#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>

static void write_file_with_x(const char *path, size_t count) {
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("open write");
		exit(1);
	}
	char buf[4096];
	memset(buf, 'x', sizeof(buf));
	size_t written = 0;
	while (written < count) {
		size_t to_write = count - written;
		if (to_write > sizeof(buf)) to_write = sizeof(buf);
		ssize_t n = write(fd, buf, to_write);
		if (n <= 0) break;
		written += (size_t)n;
	}
	char nl = '\n';
	ssize_t nw = write(fd, &nl, 1);
	(void)nw;
	close(fd);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Usage: err_helper <mode> ...\n");
		return 1;
	}

	if (strcmp(argv[1], "enospc") == 0) {
		if (argc < 7) {
			fprintf(stderr, "Usage: err_helper enospc <file_path> <file_size> <limit_bytes> <errlog_path> -- <prog> [args...]\n");
			return 1;
		}
		const char *file_path = argv[2];
		size_t file_size = (size_t)atoll(argv[3]);
		rlim_t limit_bytes = (rlim_t)atoll(argv[4]);
		const char *errlog_path = argv[5];

		int prog_idx = 6;
		if (strcmp(argv[prog_idx], "--") == 0) {
			prog_idx++;
		}

		write_file_with_x(file_path, file_size);

		signal(SIGXFSZ, SIG_IGN);

		struct rlimit rlim;
		rlim.rlim_cur = limit_bytes;
		rlim.rlim_max = limit_bytes;
		if (setrlimit(RLIMIT_FSIZE, &rlim) != 0) {
			perror("setrlimit");
			return 1;
		}

		int errlog = open(errlog_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (errlog >= 0) {
			dup2(errlog, 2);
			close(errlog);
		}

		execv(argv[prog_idx], &argv[prog_idx]);
		perror("execv");
		return 1;
	} else if (strcmp(argv[1], "closed_pipe") == 0) {
		if (argc < 5) {
			fprintf(stderr, "Usage: err_helper closed_pipe <in_path> <in_size> -- <prog> [args...]\n");
			return 1;
		}
		const char *in_path = argv[2];
		size_t in_size = (size_t)atoll(argv[3]);

		int prog_idx = 4;
		if (strcmp(argv[prog_idx], "--") == 0) {
			prog_idx++;
		}

		write_file_with_x(in_path, in_size);

		int fin = open(in_path, O_RDONLY);
		if (fin < 0) {
			perror("open in_path");
			return 1;
		}
		dup2(fin, 0);
		close(fin);

		signal(SIGPIPE, SIG_IGN);

		int p[2];
		if (pipe(p) != 0) {
			perror("pipe");
			return 1;
		}
		close(p[0]);
		dup2(p[1], 1);
		close(p[1]);

		execv(argv[prog_idx], &argv[prog_idx]);
		perror("execv");
		return 1;
	} else {
		fprintf(stderr, "Unknown mode: %s\n", argv[1]);
		return 1;
	}
}
