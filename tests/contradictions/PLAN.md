# Contradiction reproduction plan

Purpose: create focused, isolated reproducer tests for the contradictions and
races documented in `docs/STATE_MACHINES.md`.

Location: `tests/contradictions/`.

## Status

Fixed and covered by normal regression tests:

- output mode bit leak — `tests/io/io.sh:t_backup_flag_last_wins`
- grep FILES field stale results — `tests/process/grep.sh:t_grep_files_field_rescan`
- confirm FLAGS `l` leak — `tests/ui/confirm.sh:t_confirm_l_flag_leak`

Fixed but not yet covered by a dedicated reproducer:

- grep EOS discarded by generation filter
- vim pending operator across field changes
- ESC follow-byte swallowing
- shutdown STOP wait path

Still open as latent hazards:

- B worker send-failure state leak
- `(current_root, epoch)` dual-load race
- SPMC blocking recv close leak
- raw-mode leak on alt-screen write failure
- D cache stale-size re-read
- preview scratch state caller-dependent reset

## Conventions

- Each reproducer is either:
  - `t_<name>.sh` for CLI/pty integration reproductions, or
  - `t_<name>.c` for C-level/fault-injection reproductions.
- Each shell reproducer follows the existing test conventions:
  - takes one temp-directory argument,
  - writes `PASS` or `FAIL: <reason>` to `$td/result`,
  - uses `$PROG` from `tests/lib.sh`,
  - redirects expected stderr to `/dev/null` unless checking diagnostics.
- Every pty reproducer must use `timeout` or the C pty driver’s timeout so a hung
  contradiction fails instead of hanging the suite.
- Reproducers are **not** added to `tests/run.sh` until the corresponding bug is
  fixed. They are run manually or from `tests/contradictions/run.sh`.
- A reproducer PASS means “the contradiction was observed”. After the fix, the
  reproducer should be inverted into a normal regression test and moved to the
  owning suite.

## Priority 0: high-risk control-plane contradictions

### 1. Grep EOS discarded by generation filter

Source: `src/terminal.c:1391-1397`, `1406-1410`, `1460-1474`;
`src/grep_worker.c:497-506`, `627-632`.

Test: `tests/contradictions/t_grep_stale_eos_hang.sh`

Reproduction:

1. Create a file tree with enough files to keep the live grep scan active.
2. Start `--grep -r` under the pty driver with a terminal size of 24x80.
3. During `SCANNING`, edit FIND by sending a character before the scan ends.
4. Wait for `FAR_UI_END`/scan completion and send Enter.
5. Use a 5-second timeout.

Buggy behavior:

- The EOF/EOS ack is dropped because the message generation is stale.
- `scan_active` remains 1.
- Enter or `pipeline_ui_finish()` hangs.
- The timeout kills the child and the reproducer records the hang.

Fixed behavior:

- Control EOS/DONE/ERROR are not filtered by data generation.
- TUI reaches `[INSERT]` and emits the selected match.

### 2. Shutdown joins D before C

Source: `src/pipeline.c:720-731`, `852`; `src/terminal.c:1377-1382`,
`1431-1437`.

Test: `tests/contradictions/t_shutdown_stop_during_scan.sh`

Reproduction:

1. Start live recursive grep over a slow/large fixture.
2. Send Ctrl-D while `scan_active=1`.
3. Use a 5-second timeout.

Buggy behavior:

- D is stopped before C.
- C waits for EOS that D can no longer send.
- `FAR_THREAD_JOIN(c_thread)` hangs.

Fixed behavior:

- STOP makes C break unconditionally or C is joined before D.
- Process exits promptly with `Aborted.`.

### 3. Grep FILES field does not trigger rescan

Source: `src/terminal.c:916-920`, `970-975`, `1631-1685`;
`src/grep_worker.c:167`.

Test: `tests/contradictions/t_grep_files_field_stale.sh`

Reproduction:

1. Create `a.txt` containing `hit` and `b.log` containing `hit`.
2. Start interactive grep with FIND=`hit`.
3. Move to FILES field and type `a.txt`.
4. Wait longer than the 200 ms debounce.
5. Assert Stats still reports 2 files.

Buggy behavior:

- FILES edit does not set `needs_rescan`.
- D never receives updated config.
- Match list remains stale.

Fixed behavior:

- FILES edit triggers a generation bump and rescan.
- Stats reports 1 file.

## Priority 1: state corruption without hang

### 4. Output mode bits leak

Source: `src/main.c:944`, `948`, `761`, `765`; `src/process.c:337-345`.

Test: `tests/contradictions/t_output_mode_bits_leak.sh`

Reproduction A:

1. Create `f` containing `x`.
2. Run `find-and-replace x y -ibak -i f`.
3. Check whether `f.bak` exists.

Buggy behavior:

- `f.bak` exists even though bare `-i` came last.
- `MODE_PRINT_FILE_BACKUP` was never cleared.

Fixed behavior:

- No backup is created.

Reproduction B:

1. Run `-c -ibak` interactively.
2. Clear BACKUP field.
3. Confirm.

Buggy behavior:

- Backup mode remains set and write fails because suffix is empty.

Fixed behavior:

- Plain in-place edit succeeds.

### 5. Confirm TUI `l` flag leak

Source: `src/terminal.c:457-461`, `493`.

Test: `tests/contradictions/t_confirm_l_flag_leak.sh`

Reproduction:

1. Start `-c -i` TUI on one file.
2. Edit FLAGS to include `l`.
3. Edit FLAGS again to remove `l`.
4. Confirm.

Buggy behavior:

- Changed filename is still printed to stdout.

Fixed behavior:

- No `-l` output after `l` is removed.

### 6. Runtime `-j` mutation is dead

Source: `src/main.c:516-536`, `929`, `939`; `src/pipeline.c:138-144`, `824`.

Test: `tests/contradictions/t_j_runtime_noop.c`

C-level reproduction:

1. Call `pipeline_set_workers(2)` before `pipeline_start()`.
2. Call `pipeline_start()`.
3. Call `pipeline_set_workers(8)`.
4. Assert `pipeline_worker_count() == 2`.

Buggy behavior:

- The runtime call is silently ignored; CLI documentation implies it works.

Fixed behavior:

- Either the runtime call is removed from the parser, or worker count is
  actually configurable at the intended point.

### 7. Vim pending operator survives field change

Source: `src/vim.c:187-192`, `313-327`, `350-358`; `src/terminal.c:1590`, `1910`.

Test: `tests/contradictions/t_vim_pending_field_change.sh`

Reproduction:

1. Start confirm TUI.
2. Press ESC to enter NORMAL mode.
3. Press `d` to set pending operator.
4. Press TAB/Ctrl-J to change field.
5. Press a motion key.

Buggy behavior:

- Pending `d` applies to the new field.

Fixed behavior:

- Field change cancels pending operator.

## Priority 2: latent races and fragility

### 8. B worker send-failure state leak

Source: `src/process.c:662-667`, `555-560`.

Test: `tests/contradictions/t_worker_send_fail_deadlock.c`

C-level fault injection:

1. Start pipeline with one worker.
2. Publish a root.
3. Close that worker’s `done` queue or inject a send failure.
4. Assert the root eventually reaches EOS or fails loudly.

Buggy behavior:

- `jobs_done` and `workers_done` are not advanced.
- Root waits forever.

Fixed behavior:

- Failure path still updates completion state or aborts explicitly.

### 9. `(current_root, epoch)` load buffering

Source: `src/pipeline.c:186-190`; `src/process.c:584-598`.

Test: `tests/contradictions/t_root_epoch_snapshot.c`

C-level stress/TSAN reproduction:

1. Publish roots rapidly with alternating dummy contexts.
2. Have worker threads read `current_root` then epoch repeatedly.
3. Assert they never process jobs using mismatched root state.

Buggy behavior:

- Hard to reproduce on x86; TSAN/source analysis documents the hazard.

Fixed behavior:

- Single atomic snapshot or revalidation prevents mismatch.

### 10. Key parser consumes byte after ESC

Source: `src/terminal.c:693-779`, especially `764-768`.

Test: `tests/contradictions/t_esc_char_swallow.sh`

Reproduction:

1. Start confirm TUI with FIND=`abc`.
2. Press ESC followed immediately by `x`.
3. Confirm.

Buggy behavior:

- `x` is consumed and lost; field remains unchanged.

Fixed behavior:

- ESC cancels pending vim op; `x` is processed as a normal-mode key.

### 11. Raw-mode leak on alt-screen write failure

Source: `src/terminal.c:285-292`, `41-50`.

Test: `tests/contradictions/t_raw_mode_leak.c`

Fault injection:

1. Use LD_PRELOAD to make the first `write()` of the alt-screen sequence fail.
2. Call `setup_terminal()`.
3. Check `term_initialized` and termios state.

Buggy behavior:

- Raw mode remains enabled while `term_initialized=0`.

Fixed behavior:

- `restore_terminal()` runs before the flag is cleared.

### 12. D cache stale size re-read

Source: `src/grep_worker.c:406-428`, `449-477`.

Test: `tests/contradictions/t_cache_stale_size.sh`

Reproduction:

1. Create a large file so it exceeds cache budget.
2. Start live grep.
3. Truncate or rewrite the file after initial scan but before a rescan.
4. Trigger rescan by editing FIND.

Buggy behavior:

- Rescan re-reads old `st_size`, producing stale/truncated output.

Fixed behavior:

- Rescan re-stats or reads to EOF.

### 13. Preview scratch state caller-dependent reset

Source: `src/ui.c:1087`, `1144`, `1240`; `src/main.c:768-769`;
`src/terminal.c:1822-1824`.

Test: `tests/contradictions/t_preview_scratch_reset.c`

C-level reproduction:

1. Call `ui_scan_file()` on a file with matches.
2. Without resetting `G.preview_full`/`G.matches_found`, call it on a file with
   no matches.
3. Assert state is still set.

Buggy behavior:

- `preview_full` and `matches_found` remain set.

Fixed behavior:

- `ui_scan_file()` uses an owned context that resets every scan loop.

### 14. Include/exclude cflags parse order

Source: `src/main.c:340`, `353`; `src/terminal.c:374`, `389`.

Test: `tests/contradictions/t_include_cflags_order.sh`

Reproduction:

1. Create files `a.txt`, `b.txt`.
2. Run `find-and-replace x y -E --include '\.(txt)$' -r dir`.
3. Run `find-and-replace x y --include '\.(txt)$' -E -r dir`.
4. Compare selected files.

Buggy behavior:

- Filter semantics differ by flag order.

Fixed behavior:

- Filters compile once after final cflags are known.

## Runner

Create `tests/contradictions/run.sh` after adding reproducers. It should:

- source `tests/lib.sh`,
- run only the contradiction tests,
- print `CONTRADICTION OBSERVED` for tests that still reproduce,
- print `CONTRADICTION FIXED` for tests that no longer reproduce,
- exit 0 in audit mode.

Do not add this runner to `tests/run.sh` until each reproducer is inverted into
a normal regression test.
