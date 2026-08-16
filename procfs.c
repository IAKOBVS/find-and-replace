/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "procfs.h"

/* Minimal line-based parser for /proc/meminfo-style "Key:   value" records.
 * The buffer is treated as a sequence of newline-terminated lines; each line
 * is split on the first delimiter and both sides are whitespace-trimmed. */

void
procfs_iter_init(struct procfs_iter *iter, const char *buf, unsigned int len)
{
	iter->pos = buf;
	iter->end = buf + len;
}

int
procfs_iter_next(struct procfs_iter *iter, const char **key, unsigned int *key_len, const char **val, unsigned int *val_len, int delimiter)
{
	/* Yield the next key/value pair, returning 0 once the buffer is exhausted.
	 * Lines without the delimiter are skipped, not reported as errors. */
	while (iter->pos < iter->end) {
		const char *line_start = iter->pos;
		const char *line_end = (const char *)memchr(line_start, '\n', (size_t)(iter->end - line_start));
		if (line_end == NULL) {
			line_end = iter->end;
			iter->pos = iter->end;
		} else {
			iter->pos = line_end + 1;
		}

		const char *delim_pos = (const char *)memchr(line_start, delimiter, (size_t)(line_end - line_start));
		if (delim_pos == NULL)
			continue;

		const char *k_start = line_start;
		const char *k_end = delim_pos;
		while (k_start < k_end && *k_start == ' ')
			k_start++;
		while (k_end > k_start && *(k_end - 1) == ' ')
			k_end--;

		const char *v_start = delim_pos + 1;
		const char *v_end = line_end;
		while (v_start < v_end && *v_start == ' ')
			v_start++;
		while (v_end > v_start && *(v_end - 1) == ' ')
			v_end--;

		*key = k_start;
		*key_len = (unsigned int)(k_end - k_start);
		*val = v_start;
		*val_len = (unsigned int)(v_end - v_start);
		return 1;
	}
	return 0;
}
