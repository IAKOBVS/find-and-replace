/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCFS_H
#define PROCFS_H

#include <string.h>

struct procfs_iter {
	const char *pos;
	const char *end;
};

void
procfs_iter_init(struct procfs_iter *iter, const char *buf, unsigned int len);

int
procfs_iter_next(struct procfs_iter *iter, const char **key, unsigned int *key_len, const char **val, unsigned int *val_len, int delimiter);

#endif /* PROCFS_H */
