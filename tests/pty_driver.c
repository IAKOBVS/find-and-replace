#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pty.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>

typedef enum {
	OP_WAIT,
	OP_SEND_STR,
	OP_SEND_HEX,
	OP_KILL,
	OP_ACTION
} op_type_ty;

typedef struct {
	op_type_ty type;
	int val;
	char *str;
} op_ty;

static void unescape_and_send_str(int fd, const char *s) {
	size_t len = strlen(s);
	unsigned char *buf = malloc(len + 1);
	if (!buf) return;
	size_t out_len = 0;
	for (size_t i = 0; i < len; i++) {
		if (s[i] == '\\' && i + 1 < len) {
			i++;
			if (s[i] == 'n') buf[out_len++] = '\n';
			else if (s[i] == 'r') buf[out_len++] = '\r';
			else if (s[i] == 't') buf[out_len++] = '\t';
			else if (s[i] == '\\') buf[out_len++] = '\\';
			else { buf[out_len++] = '\\'; buf[out_len++] = (unsigned char)s[i]; }
		} else {
			buf[out_len++] = (unsigned char)s[i];
		}
	}
	if (out_len > 0) {
		ssize_t nw = write(fd, buf, out_len);
		(void)nw;
		usleep(50000);
	}
	free(buf);
}

static void parse_hex_and_send(int fd, const char *hex_str) {
	/* Supports "0915" or comma separated "30,64,77" or "1b5b41,1b5b42" */
	char *dup = strdup(hex_str);
	if (!dup) return;
	char *token = strtok(dup, ",");
	while (token) {
		size_t len = strlen(token);
		unsigned char buf[1024];
		size_t buf_len = 0;
		for (size_t i = 0; i < len; i += 2) {
			if (i + 1 < len) {
				char hex[3] = {token[i], token[i+1], '\0'};
				buf[buf_len++] = (unsigned char)strtol(hex, NULL, 16);
			}
		}
		if (buf_len > 0) {
			ssize_t nw = write(fd, buf, buf_len);
			(void)nw;
			usleep(150000); /* 150ms delay between keypresses, matching Python tests */
		}
		token = strtok(NULL, ",");
	}
	free(dup);
}

static void do_action(const char *action_str) {
	if (strncmp(action_str, "unlink_mkdir:", 13) == 0) {
		const char *path = action_str + 13;
		unlink(path);
		mkdir(path, 0755);
	}
}

int main(int argc, char **argv) {
	int rows = 24;
	int cols = 80;
	int print_out = 0;
	int print_exit = 0;
	const char *outfile = NULL;

	op_ty ops[128];
	int num_ops = 0;

	int i = 1;
	while (i < argc) {
		if (strcmp(argv[i], "--") == 0) {
			i++;
			break;
		}
		if (strcmp(argv[i], "-r") == 0 && i + 1 < argc) {
			rows = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
			cols = atoi(argv[++i]);
		} else if (strcmp(argv[i], "-e") == 0 && i + 1 < argc) {
			putenv(strdup(argv[++i]));
		} else if (strcmp(argv[i], "-w") == 0 && i + 1 < argc) {
			ops[num_ops].type = OP_WAIT;
			ops[num_ops].val = atoi(argv[++i]);
			num_ops++;
		} else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
			ops[num_ops].type = OP_SEND_STR;
			ops[num_ops].str = argv[++i];
			num_ops++;
		} else if (strcmp(argv[i], "-k") == 0 && i + 1 < argc) {
			ops[num_ops].type = OP_SEND_HEX;
			ops[num_ops].str = argv[++i];
			num_ops++;
		} else if (strcmp(argv[i], "-K") == 0 && i + 1 < argc) {
			ops[num_ops].type = OP_KILL;
			ops[num_ops].val = atoi(argv[++i]);
			num_ops++;
		} else if (strcmp(argv[i], "-A") == 0 && i + 1 < argc) {
			ops[num_ops].type = OP_ACTION;
			ops[num_ops].str = argv[++i];
			num_ops++;
		} else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
			outfile = argv[++i];
		} else if (strcmp(argv[i], "-p") == 0) {
			print_out = 1;
		} else if (strcmp(argv[i], "-x") == 0) {
			print_exit = 1;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			return 1;
		}
		i++;
	}

	if (i >= argc) {
		fprintf(stderr, "Usage: pty_driver [opts] -- command [args...]\n");
		return 1;
	}

	int master_fd;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = (unsigned short)rows;
	ws.ws_col = (unsigned short)cols;

	pid_t pid = forkpty(&master_fd, NULL, NULL, &ws);
	if (pid < 0) {
		perror("forkpty");
		return 1;
	}

	if (pid == 0) {
		/* Child process */
		execv(argv[i], &argv[i]);
		perror("execv");
		_exit(127);
	}

	/* Initial delay to let child process set up raw termios and draw initial frame */
	usleep(500000);

	/* Set non-blocking on master */
	int flags = fcntl(master_fd, F_GETFL, 0);
	fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);

	/* Execute ops */
	for (int op_idx = 0; op_idx < num_ops; op_idx++) {
		op_ty *op = &ops[op_idx];
		switch (op->type) {
		case OP_WAIT:
			usleep((useconds_t)op->val * 1000);
			break;
		case OP_SEND_STR:
			unescape_and_send_str(master_fd, op->str);
			break;
		case OP_SEND_HEX:
			parse_hex_and_send(master_fd, op->str);
			break;
		case OP_KILL:
			kill(pid, op->val);
			break;
		case OP_ACTION:
			do_action(op->str);
			break;
		}
	}

	/* Read output from master until EOF or child exit or timeout */
	size_t cap = 65536;
	size_t out_len = 0;
	char *out_buf = malloc(cap);
	if (!out_buf) {
		perror("malloc");
		return 1;
	}

	int idle_count = 0;
	while (1) {
		char buf[1024];
		ssize_t n = read(master_fd, buf, sizeof(buf));
		if (n > 0) {
			idle_count = 0;
			if (out_len + (size_t)n >= cap) {
				cap *= 2;
				out_buf = realloc(out_buf, cap);
				if (!out_buf) {
					perror("realloc");
					return 1;
				}
			}
			memcpy(out_buf + out_len, buf, (size_t)n);
			out_len += (size_t)n;
		} else if (n == 0) {
			break;
		} else {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				int status;
				pid_t res = waitpid(pid, &status, WNOHANG);
				if (res > 0) {
					/* Child exited. Drain any remaining output. */
					while ((n = read(master_fd, buf, sizeof(buf))) > 0) {
						if (out_len + (size_t)n >= cap) {
							cap *= 2;
							out_buf = realloc(out_buf, cap);
						}
						memcpy(out_buf + out_len, buf, (size_t)n);
						out_len += (size_t)n;
					}
					break;
				}
				idle_count++;
				if (idle_count > 100) { /* 100 * 20ms = 2.0s idle timeout */
					kill(pid, SIGKILL);
					waitpid(pid, &status, 0);
					break;
				}
				usleep(20000);
			} else {
				/* EIO or other error indicates slave closed */
				break;
			}
		}
	}

	close(master_fd);

	int status = 0;
	waitpid(pid, &status, 0);

	if (outfile) {
		int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd >= 0) {
			ssize_t nw = write(fd, out_buf, out_len);
			(void)nw;
			close(fd);
		}
	}

	if (print_out) {
		ssize_t nw = write(STDOUT_FILENO, out_buf, out_len);
		(void)nw;
	}

	if (print_exit) {
		if (WIFEXITED(status)) {
			printf("%d\n", WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			printf("%d\n", -WTERMSIG(status));
		} else {
			printf("-1\n");
		}
	}

	free(out_buf);
	return 0;
}
