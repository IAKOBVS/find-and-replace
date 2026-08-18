/*
 * SPDX-License-Identifier: MIT
 * pty_drive — pty-based test driver for find-and-replace interactive TUI tests.
 *
 * Runs a program under a pseudo-terminal, feeds it keystrokes at controlled
 * delays, captures output, and records the child's exit status.
 *
 * Usage: pty_drive [opts] -- [prog argv...]
 */
/* clang-format off */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
/* clang-format on */

extern char **environ;

#define MAX_ACTIONS 128
#define MAX_ENV     64
#define BUF_INIT    4096
#define MAX_ARGV    256

typedef struct {
	int delay_ms;
	unsigned char *data;
	size_t len;
} action_t;

static int hex_val(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int parse_phase(const char *spec, int default_delay_ms, action_t *out)
{
	const char *at;
	const char *hex;
	int delay;
	size_t hexlen;
	size_t i;
	int hi, lo;
	unsigned char *data;

	at = strrchr(spec, '@');
	if (at != NULL) {
		hex = spec;
		hexlen = (size_t)(at - spec);
		delay = atoi(at + 1);
	} else {
		hex = spec;
		hexlen = strlen(spec);
		delay = default_delay_ms;
	}

	if (hexlen == 0 || hexlen % 2 != 0)
		return -1;

	data = malloc(hexlen / 2);
	if (data == NULL)
		return -1;

	for (i = 0; i < hexlen; i += 2) {
		hi = hex_val(hex[i]);
		lo = hex_val(hex[i + 1]);
		if (hi < 0 || lo < 0) {
			free(data);
			return -1;
		}
		data[i / 2] = (unsigned char)((hi << 4) | lo);
	}

	out->delay_ms = delay;
	out->data = data;
	out->len = hexlen / 2;
	return 0;
}

static int decode_tail(const char *text, int default_delay_ms, action_t *out)
{
	size_t len;
	size_t i;
	size_t j;
	unsigned char *buf;
	int hi, lo;

	len = strlen(text);
	buf = malloc(len + 1);
	if (buf == NULL)
		return -1;

	i = 0;
	j = 0;
	while (i < len) {
		if (text[i] == '\\') {
			if (i + 1 >= len) {
				free(buf);
				return -1;
			}
			i++;
			switch (text[i]) {
			case 'n':  buf[j++] = '\n'; i++; break;
			case 'r':  buf[j++] = '\r'; i++; break;
			case 't':  buf[j++] = '\t'; i++; break;
			case 'a':  buf[j++] = '\a'; i++; break;
			case 'b':  buf[j++] = '\b'; i++; break;
			case 'f':  buf[j++] = '\f'; i++; break;
			case 'v':  buf[j++] = '\v'; i++; break;
			case '0':  buf[j++] = '\0'; i++; break;
			case '\\': buf[j++] = '\\'; i++; break;
			case 'x':
				if (i + 2 < len) {
					hi = hex_val(text[i + 1]);
					lo = hex_val(text[i + 2]);
					if (hi >= 0 && lo >= 0) {
						buf[j++] = (unsigned char)((hi << 4) | lo);
						i += 3;
						break;
					}
				}
				buf[j++] = '\\';
				i++;
				break;
			default:
				buf[j++] = '\\';
				buf[j++] = (unsigned char)text[i++];
				break;
			}
		} else {
			buf[j++] = (unsigned char)text[i++];
		}
	}

	out->delay_ms = default_delay_ms;
	out->data = buf;
	out->len = j;
	return 0;
}

static int split_winsize(const char *spec, int *rows, int *cols)
{
	const char *x;
	const char *x2;
	char lower[64];
	size_t len;
	size_t i;

	len = strlen(spec);
	if (len == 0 || len >= sizeof(lower))
		return -1;

	for (i = 0; i < len; i++) {
		lower[i] = spec[i];
		if (lower[i] >= 'A' && lower[i] <= 'Z')
			lower[i] = (char)(lower[i] + ('a' - 'A'));
	}
	lower[len] = '\0';

	x = strchr(lower, 'x');
	if (x == NULL || x == lower || *(x + 1) == '\0')
		return -1;

	x2 = strchr(x + 1, 'x');
	if (x2 != NULL)
		return -1;

	*rows = atoi(lower);
	*cols = atoi(x + 1);
	return 0;
}

static const char *outcome_from_status(int status)
{
	static char buf[32];

	if (WIFEXITED(status)) {
		sprintf(buf, "%d", WEXITSTATUS(status));
		return buf;
	}
	if (WIFSIGNALED(status)) {
		sprintf(buf, "sig:%d", WTERMSIG(status));
		return buf;
	}
	return "timeout";
}

static void write_file(const char *path, const void *data, size_t len)
{
	int fd;
	if (path == NULL)
		return;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return;
	write(fd, data, len);
	close(fd);
}

static void write_rc(const char *path, const char *outcome)
{
	if (path == NULL)
		return;
	write_file(path, outcome, strlen(outcome));
}

typedef struct {
	size_t cap;
	size_t len;
	char *data;
} buf_t;

static void buf_init(buf_t *b)
{
	b->cap = BUF_INIT;
	b->len = 0;
	b->data = malloc(b->cap);
}

static void buf_append(buf_t *b, const char *data, size_t len)
{
	size_t need;
	if (len == 0)
		return;
	need = b->len + len;
	if (need > b->cap) {
		while (need > b->cap)
			b->cap *= 2;
		b->data = realloc(b->data, b->cap);
	}
	memcpy(b->data + b->len, data, len);
	b->len += len;
}

static int buf_contains(buf_t *b, const char *needle, size_t nlen)
{
	size_t i;
	if (nlen == 0 || b->len < nlen)
		return 0;
	for (i = 0; i <= b->len - nlen; i++) {
		if (memcmp(b->data + i, needle, nlen) == 0)
			return 1;
	}
	return 0;
}

static double now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1000000.0;
}

static void sleep_ms(int ms)
{
	double end;
	end = now_ms() + ms;
	while (now_ms() < end) {
		struct timeval tv;
		double rem = end - now_ms();
		if (rem <= 0)
			break;
		tv.tv_sec = (long)(rem / 1000.0);
		tv.tv_usec = (long)((rem - tv.tv_sec * 1000.0) * 1000.0);
		select(0, NULL, NULL, NULL, &tv);
	}
}

static int read_pty(int fd, buf_t *b, double deadline_ms)
{
	double remaining;
	struct timeval tv;
	fd_set rfds;
	int rc;
	char tmp[4096];
	ssize_t nr;

	remaining = deadline_ms - now_ms();
	if (remaining <= 0)
		return 0;
	tv.tv_sec = (long)(remaining / 1000.0);
	tv.tv_usec = (long)((remaining - tv.tv_sec * 1000.0) * 1000.0);
	if (tv.tv_usec < 0) tv.tv_usec = 0;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	rc = select(fd + 1, &rfds, NULL, NULL, &tv);
	if (rc <= 0)
		return rc;
	nr = read(fd, tmp, sizeof(tmp));
	if (nr <= 0)
		return -1;
	buf_append(b, tmp, (size_t)nr);
	return 1;
}

static int wait_for_marker(int fd, buf_t *b, const char *marker, size_t mlen,
			   double deadline_ms)
{
	while (!buf_contains(b, marker, mlen)) {
		if (now_ms() >= deadline_ms)
			return 0;
		if (read_pty(fd, b, deadline_ms) < 0)
			return 0;
	}
	return 1;
}

static void drain_to_deadline(int fd, buf_t *b, double deadline_ms)
{
	while (now_ms() < deadline_ms) {
		if (read_pty(fd, b, deadline_ms) < 0)
			break;
	}
}

static int spawn_child(const char *prog, char **args, char **envp,
		       int *rowsp, int *colsp, int *master_out)
{
	int master, slave;
	pid_t pid;
	struct winsize ws;

	if (openpty(&master, &slave, NULL, NULL, NULL) < 0)
		return -1;

	if (rowsp != NULL && colsp != NULL) {
		memset(&ws, 0, sizeof(ws));
		ws.ws_row = (unsigned short)*rowsp;
		ws.ws_col = (unsigned short)*colsp;
		ioctl(slave, TIOCSWINSZ, &ws);
	}

	pid = fork();
	if (pid < 0) {
		close(master);
		close(slave);
		return -1;
	}

	if (pid == 0) {
		close(master);
		setsid();
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		if (slave > 2)
			close(slave);
		execvpe(prog, args, envp);
		_exit(127);
	}

	close(slave);
	*master_out = master;
	return pid;
}

static void free_actions(action_t *actions, int count)
{
	int i;
	for (i = 0; i < count; i++)
		free(actions[i].data);
}

static int is_known_opt(const char *arg)
{
	if (strcmp(arg, "--phase") == 0 || strcmp(arg, "--tail") == 0 ||
	    strcmp(arg, "--ready") == 0 || strcmp(arg, "--out") == 0 ||
	    strcmp(arg, "--rc") == 0 || strcmp(arg, "--prog") == 0 ||
	    strcmp(arg, "--winsize") == 0 || strcmp(arg, "--signal") == 0 ||
	    strcmp(arg, "--delay") == 0 || strcmp(arg, "--env") == 0 ||
	    strcmp(arg, "--timeout") == 0 || strcmp(arg, "--after-ready") == 0 ||
	    strcmp(arg, "--ready-timeout") == 0)
		return 1;
	if (strncmp(arg, "--phase=", 8) == 0 ||
	    strncmp(arg, "--tail=", 7) == 0 ||
	    strncmp(arg, "--ready=", 8) == 0 ||
	    strncmp(arg, "--out=", 6) == 0 ||
	    strncmp(arg, "--rc=", 5) == 0 ||
	    strncmp(arg, "--prog=", 7) == 0 ||
	    strncmp(arg, "--winsize=", 10) == 0 ||
	    strncmp(arg, "--signal=", 9) == 0 ||
	    strncmp(arg, "--delay=", 8) == 0 ||
	    strncmp(arg, "--env=", 6) == 0 ||
	    strncmp(arg, "--timeout=", 10) == 0 ||
	    strncmp(arg, "--after-ready=", 14) == 0 ||
	    strncmp(arg, "--ready-timeout=", 16) == 0)
		return 1;
	return 0;
}

int main(int argc, char **argv)
{
	const char *prog = "./find-and-replace";
	const char *out_path = NULL;
	const char *rc_path = NULL;
	const char *winsize_str = NULL;
	const char *ready_marker = NULL;
	double ready_timeout_s = 10.0;
	const char *after_ready = NULL;
	const char *sig_name = NULL;
	int default_delay_ms = 100;
	double timeout_s = 60.0;
	const char *env_add[MAX_ENV];
	int env_add_count = 0;
	action_t actions[MAX_ACTIONS];
	int action_count = 0;
	int rows = -1, cols = -1;
	int i;
	int pid, master_fd;
	double deadline_ms, ready_deadline_ms;
	buf_t buf;
	int tool_argc;
	const char *tool_argv_raw[MAX_ARGV];
	int tool_start = -1;
	int tool_end = argc;

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			tool_start = i + 1;
			tool_end = argc;
			break;
		}
	}

	if (tool_start < 0) {
		for (i = 1; i < argc; i++) {
			if (!is_known_opt(argv[i])) {
				tool_start = i;
				break;
			}
			if (argv[i][0] != '-' || is_known_opt(argv[i])) {
				if (is_known_opt(argv[i])) {
					if (argv[i][1] != '=' && i + 1 < argc)
						i++;
					continue;
				}
			}
		}
	}

	for (i = 1; i < argc; i++) {
		if (tool_start >= 0 && i >= tool_start)
			break;
		if (strcmp(argv[i], "--") == 0)
			break;

		if (strcmp(argv[i], "--prog") == 0 && i + 1 < argc)
			prog = argv[++i];
		else if (strncmp(argv[i], "--prog=", 7) == 0)
			prog = argv[i] + 7;
		else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc)
			out_path = argv[++i];
		else if (strncmp(argv[i], "--out=", 6) == 0)
			out_path = argv[i] + 6;
		else if (strcmp(argv[i], "--rc") == 0 && i + 1 < argc)
			rc_path = argv[++i];
		else if (strncmp(argv[i], "--rc=", 5) == 0)
			rc_path = argv[i] + 5;
		else if (strcmp(argv[i], "--winsize") == 0 && i + 1 < argc)
			winsize_str = argv[++i];
		else if (strncmp(argv[i], "--winsize=", 10) == 0)
			winsize_str = argv[i] + 10;
		else if (strcmp(argv[i], "--ready") == 0 && i + 1 < argc)
			ready_marker = argv[++i];
		else if (strncmp(argv[i], "--ready=", 8) == 0)
			ready_marker = argv[i] + 8;
		else if (strcmp(argv[i], "--ready-timeout") == 0 && i + 1 < argc)
			ready_timeout_s = atof(argv[++i]);
		else if (strncmp(argv[i], "--ready-timeout=", 16) == 0)
			ready_timeout_s = atof(argv[i] + 16);
		else if (strcmp(argv[i], "--after-ready") == 0 && i + 1 < argc)
			after_ready = argv[++i];
		else if (strncmp(argv[i], "--after-ready=", 14) == 0)
			after_ready = argv[i] + 14;
		else if (strcmp(argv[i], "--signal") == 0 && i + 1 < argc)
			sig_name = argv[++i];
		else if (strncmp(argv[i], "--signal=", 9) == 0)
			sig_name = argv[i] + 9;
		else if (strcmp(argv[i], "--delay") == 0 && i + 1 < argc)
			default_delay_ms = atoi(argv[++i]);
		else if (strncmp(argv[i], "--delay=", 8) == 0)
			default_delay_ms = atoi(argv[i] + 8);
		else if (strcmp(argv[i], "--env") == 0 && i + 1 < argc) {
			if (env_add_count < MAX_ENV)
				env_add[env_add_count++] = argv[++i];
		} else if (strncmp(argv[i], "--env=", 6) == 0) {
			if (env_add_count < MAX_ENV)
				env_add[env_add_count++] = argv[i] + 6;
		} else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
			timeout_s = atof(argv[++i]);
		else if (strncmp(argv[i], "--timeout=", 10) == 0)
			timeout_s = atof(argv[i] + 10);
		else if (strncmp(argv[i], "--phase=", 8) == 0) {
			if (action_count < MAX_ACTIONS) {
				if (parse_phase(argv[i] + 8, default_delay_ms,
						&actions[action_count]) == 0)
					action_count++;
			}
		} else if (strcmp(argv[i], "--phase") == 0 && i + 1 < argc) {
			if (action_count < MAX_ACTIONS) {
				if (parse_phase(argv[i + 1], default_delay_ms,
						&actions[action_count]) == 0)
					action_count++;
				i++;
			}
		} else if (strncmp(argv[i], "--tail=", 7) == 0) {
			if (action_count < MAX_ACTIONS) {
				if (decode_tail(argv[i] + 7, default_delay_ms,
						&actions[action_count]) == 0)
					action_count++;
			}
		} else if (strcmp(argv[i], "--tail") == 0 && i + 1 < argc) {
			if (action_count < MAX_ACTIONS) {
				if (decode_tail(argv[i + 1], default_delay_ms,
						&actions[action_count]) == 0)
					action_count++;
				i++;
			}
		}
	}

	if (winsize_str != NULL)
		split_winsize(winsize_str, &rows, &cols);

	tool_argc = 0;
	tool_argv_raw[tool_argc++] = prog;
	if (tool_start >= 0) {
		for (i = tool_start; i < tool_end && tool_argc < MAX_ARGV - 1; i++)
			tool_argv_raw[tool_argc++] = argv[i];
	}
	tool_argv_raw[tool_argc] = NULL;

	char *child_argv[MAX_ARGV];
	char *child_env[MAX_ENV + 64];
	int env_idx = 0;

	for (i = 0; i < tool_argc; i++)
		child_argv[i] = (char *)tool_argv_raw[i];
	child_argv[tool_argc] = NULL;

	for (i = 0; environ[i] != NULL && env_idx < MAX_ENV + 63; i++)
		child_env[env_idx++] = environ[i];
	for (i = 0; i < env_add_count && env_idx < MAX_ENV + 63; i++)
		child_env[env_idx++] = (char *)env_add[i];
	child_env[env_idx] = NULL;

	pid = spawn_child(prog, child_argv, child_env,
			  rows >= 0 ? &rows : NULL,
			  cols >= 0 ? &cols : NULL,
			  &master_fd);
	if (pid < 0) {
		write_rc(rc_path, "timeout");
		return 1;
	}

	buf_init(&buf);
	deadline_ms = now_ms() + timeout_s * 1000.0;
	ready_deadline_ms = now_ms() + ready_timeout_s * 1000.0;

	if (ready_marker != NULL) {
		size_t mlen = strlen(ready_marker);
		int ok = wait_for_marker(master_fd, &buf, ready_marker, mlen,
					 ready_deadline_ms);
		if (!ok) {
			int wpid, wstatus;
			wpid = waitpid(pid, &wstatus, WNOHANG);
			if (wpid == 0) {
				kill(pid, SIGTERM);
				{
					double term_deadline = now_ms() + 2000;
					while (now_ms() < term_deadline) {
						wpid = waitpid(pid, &wstatus, WNOHANG);
						if (wpid != 0)
							break;
						sleep_ms(10);
					}
				}
				if (wpid == 0) {
					kill(pid, SIGKILL);
					waitpid(pid, &wstatus, 0);
				}
			}
			if (wpid < 0)
				wstatus = 0;
			if (out_path != NULL)
				write_file(out_path, buf.data, buf.len);
			write_rc(rc_path, outcome_from_status(wstatus));
			close(master_fd);
			free(buf.data);
			free_actions(actions, action_count);
			return 0;
		}
	}

	if (after_ready != NULL) {
		int ret = system(after_ready);
		(void)ret;
	}

	for (i = 0; i < action_count; i++) {
		sleep_ms(actions[i].delay_ms);
		write(master_fd, actions[i].data, actions[i].len);
	}

	if (sig_name != NULL) {
		int sig = 0;
		if (strcmp(sig_name, "TERM") == 0 || strcmp(sig_name, "term") == 0)
			sig = SIGTERM;
		else if (strcmp(sig_name, "HUP") == 0 || strcmp(sig_name, "hup") == 0)
			sig = SIGHUP;
		else if (strcmp(sig_name, "INT") == 0 || strcmp(sig_name, "int") == 0)
			sig = SIGINT;
		else if (strcmp(sig_name, "KILL") == 0 || strcmp(sig_name, "kill") == 0)
			sig = SIGKILL;
		else if (strcmp(sig_name, "USR1") == 0 || strcmp(sig_name, "usr1") == 0)
			sig = SIGUSR1;
		else if (strcmp(sig_name, "USR2") == 0 || strcmp(sig_name, "usr2") == 0)
			sig = SIGUSR2;
		else if (strcmp(sig_name, "QUIT") == 0 || strcmp(sig_name, "quit") == 0)
			sig = SIGQUIT;
		else if (strcmp(sig_name, "CONT") == 0 || strcmp(sig_name, "cont") == 0)
			sig = SIGCONT;
		else if (strcmp(sig_name, "STOP") == 0 || strcmp(sig_name, "stop") == 0)
			sig = SIGSTOP;
		if (sig > 0)
			kill(pid, sig);
	}

	drain_to_deadline(master_fd, &buf, deadline_ms);

	{
		int wpid, wstatus;
		wpid = waitpid(pid, &wstatus, WNOHANG);
		if (wpid == 0) {
			kill(pid, SIGTERM);
			{
				double term_deadline = now_ms() + 2000;
				while (now_ms() < term_deadline) {
					wpid = waitpid(pid, &wstatus, WNOHANG);
					if (wpid != 0)
						break;
					sleep_ms(10);
				}
			}
			if (wpid == 0) {
				kill(pid, SIGKILL);
				waitpid(pid, &wstatus, 0);
			}
		}
		if (wpid < 0)
			wstatus = 0;
		if (out_path != NULL)
			write_file(out_path, buf.data, buf.len);
		write_rc(rc_path, outcome_from_status(wstatus));
	}

	close(master_fd);
	free(buf.data);
	free_actions(actions, action_count);
	return 0;
}
