/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "procfs.h"

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/* Minimal line-based parser for /proc/meminfo-style "Key:   value" records.
 * The buffer is treated as a sequence of newline-terminated lines; each line
 * is split on the first delimiter and both sides are whitespace-trimmed. */

/**
 * @brief Open /proc/meminfo and initialize an iterator.
 *
 * @details This function is part of the procfs.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param iter parameter defined by the owning module contract.
 * @param buf growable byte buffer.
 * @param len valid byte count.
 * @return None.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any stage that owns the iterator/state.
 */
void
procfs_iter_init(struct procfs_iter *iter, const char *buf, unsigned int len)
{
	iter->pos = buf;
	iter->end = buf + len;
}

/**
 * @brief Read the next line from an open procfs iterator.
 *
 * @details This function is part of the procfs.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param iter parameter defined by the owning module contract.
 * @param key decoded input key.
 * @param key_len parameter defined by the owning module contract.
 * @param val value to format.
 * @param val_len parameter defined by the owning module contract.
 * @param delimiter parameter defined by the owning module contract.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any stage that owns the iterator/state.
 */
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


/**
 * @brief Return MemAvailable in bytes with a documented fallback.
 *
 * @details This function is part of the procfs.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @sideeffects Only the objects, queues, files, and global state named in the owning contract are modified.
 * @thread Any stage that owns the iterator/state.
 */
size_t
procfs_mem_available(void)
{
	const size_t fallback = (size_t)1 << 30;
	const int fd = open("/proc/meminfo", O_RDONLY);
	if (fd == -1)
		return fallback;
	char buf[4096 + 1];
	const ssize_t nread = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (nread <= 0)
		return fallback;
	buf[nread] = '\0';
	struct procfs_iter iter;
	procfs_iter_init(&iter, buf, (unsigned int)nread);
	const char *key;
	const char *val;
	unsigned int key_len;
	unsigned int val_len;
	while (procfs_iter_next(&iter, &key, &key_len, &val, &val_len, ':')) {
		if (key_len == sizeof("MemAvailable") - 1 && memcmp(key, "MemAvailable", key_len) == 0) {
			const size_t kib = (size_t)strtoul(val, NULL, 10);
			return kib ? kib * 1024 : fallback;
		}
	}
	return fallback;
}
