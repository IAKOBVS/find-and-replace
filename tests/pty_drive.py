#!/usr/bin/env python3
"""Shared pty driver for find-and-replace interactive TUI tests.

Runs the tool under a pseudo-terminal, feeds it keystrokes, captures the
output, and records the child's exit status. Shell test functions drive it
with --phase/--tail and assert on the captured output and --rc file.

Usage:
  pty_drive.py [opts] -- [tool argv...]

Options:
  --prog PATH            executable to run (default ./find-and-replace)
  --out FILE             write captured pty output to FILE (default: discard)
  --rc FILE              write child outcome to FILE: "0", "1", "sig:<N>",
                         or "timeout"
  --winsize RxC          set the pty winsize before the child starts
  --ready TEXT           poll until TEXT appears in the output before actions
  --ready-timeout S      timeout for --ready (default 10)
  --after-ready CMD      run CMD via /bin/sh -c in the parent after --ready
  --signal SIGNAME       send SIGNAME to the child after actions
  --delay MS             default sleep before each action (default 100)
  --phase HEX[@MS]       write hex bytes after a sleep; MS overrides --delay
  --tail TEXT            write TEXT after a --delay sleep (\\\\xNN/\\\\n escapes
                         decoded); --phase and --tail run in argv order
  --env KEY=VALUE        extra child env (inherits os.environ by default)
  --timeout S            overall child run timeout (default 60)
"""

import argparse
import fcntl
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time
from typing import List, Optional, Sequence, Tuple

Action = Tuple[int, bytes]


def parse_phase(spec: str, default_delay_ms: int) -> Action:
    """Split a --phase spec into (delay_ms, hex bytes).

    A trailing @MS overrides default_delay_ms; otherwise the default is used.
    """
    if "@" in spec:
        hexpart: str
        ms: str
        hexpart, ms = spec.rsplit("@", 1)
        return int(ms), bytes.fromhex(hexpart)
    return default_delay_ms, bytes.fromhex(spec)


def decode_tail(text: str, default_delay_ms: int) -> Action:
    """Decode a --tail text into (delay_ms, bytes).

    Control escapes (\\n, \\r, \\xNN, ...) are decoded like the old inline
    drivers did, so shell tests can pass human-readable key text.
    """
    payload: bytes = text.encode("utf-8").decode("unicode_escape").encode("utf-8")
    return default_delay_ms, payload


def ordered_actions(argv: Sequence[str], default_delay_ms: int) -> List[Action]:
    """Collect --phase and --tail actions in command-line order.

    argparse does not preserve order across different flags, so the actions
    are assembled by scanning argv directly. Both "--flag value" and
    "--flag=value" forms are accepted; "@MS" only applies to --phase.
    """
    actions: List[Action] = []
    i: int = 0
    args: List[str] = list(argv)
    while i < len(args):
        arg: str = args[i]
        if arg == "--":
            break
        if arg.startswith("--phase="):
            actions.append(parse_phase(arg[len("--phase="):], default_delay_ms))
        elif arg == "--phase":
            i += 1
            if i < len(args):
                actions.append(parse_phase(args[i], default_delay_ms))
        elif arg.startswith("--tail="):
            actions.append(decode_tail(arg[len("--tail="):], default_delay_ms))
        elif arg == "--tail":
            i += 1
            if i < len(args):
                actions.append(decode_tail(args[i], default_delay_ms))
        i += 1
    return actions


def split_winsize(spec: str) -> Optional[Tuple[int, int]]:
    """Parse a "rows x cols" winsize spec into (rows, cols).

    Returns None for malformed input so callers can silently fall back to the
    pty's inherited size.
    """
    try:
        rows_str: str
        cols_str: str
        rows_str, cols_str = spec.lower().split("x")
        return int(rows_str), int(cols_str)
    except ValueError:
        return None


def write_rc(path: Optional[str], outcome: str) -> None:
    """Record the child outcome string to --rc FILE, if given."""
    if path is not None:
        with open(path, "w") as fh:
            fh.write(outcome)


def outcome_from_status(status: int) -> str:
    """Format a waitpid status as "0", "1", "sig:<N>", or "timeout"."""
    if os.WIFEXITED(status):
        return str(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        return "sig:%d" % os.WTERMSIG(status)
    return "timeout"


def drain_to_deadline(fd: int, buf: List[bytes], deadline: float) -> None:
    """Read all available pty output until EOF or the deadline passes."""
    while True:
        rlist: List[int] = select.select([fd], [], [], 0.05)[0]
        if rlist:
            try:
                data: bytes = os.read(fd, 4096)
            except OSError:
                break
            if not data:
                break
            buf.append(data)
        if time.monotonic() > deadline:
            break


def wait_for_marker(fd: int, buf: List[bytes], marker: bytes,
                    deadline: float) -> bool:
    """Poll the pty until marker appears in the accumulated output.

    Returns False if the child exits (EOF/EIO) or the deadline passes first.
    """
    while marker not in b"".join(buf):
        rlist: List[int] = select.select([fd], [], [], 0.05)[0]
        if rlist:
            try:
                data: bytes = os.read(fd, 4096)
            except OSError:
                return False
            if not data:
                return False
            buf.append(data)
        if time.monotonic() > deadline:
            return False
    return True


def spawn_child(prog: str, tool_args: List[str], env: dict,
                winsize: Optional[Tuple[int, int]]) -> Tuple[int, int]:
    """Fork and exec the child with the pty slave as its controlling tty.

    The winsize is applied to the slave BEFORE the fork so the child's first
    render cannot race the ioctl (pty.fork spawns the child immediately, which
    let an inherited size leak into the TUI and made tests flaky). Returns
    (pid, master_fd); the child gets setsid + TIOCSCTTY + dup2 of the slave.
    """
    master: int
    slave: int
    master, slave = os.openpty()
    if winsize is not None:
        rows: int
        cols: int
        rows, cols = winsize
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ,
                        struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass
    pid: int = os.fork()
    if pid == 0:
        os.close(master)
        os.setsid()
        try:
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        except OSError:
            pass
        os.dup2(slave, 0)
        os.dup2(slave, 1)
        os.dup2(slave, 2)
        if slave > 2:
            os.close(slave)
        os.execvpe(prog, [prog] + tool_args, env)
        os._exit(127)
    os.close(slave)
    return pid, master


def main(argv: Sequence[str]) -> int:
    """Parse arguments, drive the child under the pty, report the outcome."""
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("--prog", default="./find-and-replace")
    ap.add_argument("--out")
    ap.add_argument("--rc")
    ap.add_argument("--winsize")
    ap.add_argument("--ready")
    ap.add_argument("--ready-timeout", type=float, default=10.0)
    ap.add_argument("--after-ready")
    ap.add_argument("--signal")
    ap.add_argument("--delay", type=int, default=100)
    ap.add_argument("--env", action="append", default=[])
    ap.add_argument("--timeout", type=float, default=60.0)
    opts, _rest = ap.parse_known_args(list(argv))

    tool_args: List[str]
    if "--" in argv:
        tool_args = list(argv[argv.index("--") + 1:])
    else:
        tool_args = list(_rest)

    env: dict = dict(os.environ)
    for kv in opts.env:
        key: str
        _sep: str
        val: str
        key, _sep, val = kv.partition("=")
        env[key] = val

    actions: List[Action] = ordered_actions(argv, opts.delay)

    winsize: Optional[Tuple[int, int]] = None
    if opts.winsize:
        winsize = split_winsize(opts.winsize)

    pid: int
    fd: int
    pid, fd = spawn_child(opts.prog, tool_args, env, winsize)

    buf: List[bytes] = []
    deadline: float = time.monotonic() + opts.timeout
    ready_deadline: float = time.monotonic() + opts.ready_timeout

    if opts.ready:
        ok: bool = wait_for_marker(fd, buf, opts.ready.encode("utf-8"),
                                   ready_deadline)
        if not ok:
            # The marker may never appear because the child exited early (e.g.
            # a startup error). Reap it non-blockingly and report the real
            # status; only fall back to "timeout" if it is still running.
            try:
                wpid: int
                wstatus: int
                wpid, wstatus = os.waitpid(pid, os.WNOHANG)
            except OSError:
                wpid, wstatus = 0, 0
            if wpid == pid:
                if opts.out:
                    with open(opts.out, "wb") as fh:
                        fh.write(b"".join(buf))
                write_rc(opts.rc, outcome_from_status(wstatus))
                try:
                    os.close(fd)
                except OSError:
                    pass
                return 0
            write_rc(opts.rc, "timeout")
            try:
                os.close(fd)
            except OSError:
                pass
            return 1

    if opts.after_ready:
        subprocess.call(opts.after_ready, shell=True)

    try:
        for delay_ms, data in actions:
            time.sleep(delay_ms / 1000.0)
            os.write(fd, data)
        if opts.signal:
            os.kill(pid, signal.Signals["SIG" + opts.signal.upper()].value)
        drain_to_deadline(fd, buf, deadline)
    except OSError:
        pass

    try:
        _pid: int
        status: int
        _pid, status = os.waitpid(pid, 0)
    except OSError:
        status = 0

    if opts.out:
        with open(opts.out, "wb") as fh:
            fh.write(b"".join(buf))

    write_rc(opts.rc, outcome_from_status(status))

    try:
        os.close(fd)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
