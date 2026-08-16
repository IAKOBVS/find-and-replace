/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

/*
 * LD_PRELOAD shim that fakes /proc/meminfo for tests/unit.sh.
 *
 * Env controls:
 *   FAKE_MEMINFO          content served back for open("/proc/meminfo")
 *   FAKE_MEMINFO_OPEN_FAIL=1   open() returns -1 (ENOENT)
 *   FAKE_MEMINFO_READ_FAIL=1   read() returns -1 (EIO)
 *
 * All other opens/reads/closes pass through to the real libc.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FAKE_FD 0x4000

typedef int (*open_fn)(const char *, int, ...);
typedef int (*openat_fn)(int, const char *, int, ...);
typedef ssize_t (*read_fn)(int, void *, size_t);
typedef int (*close_fn)(int);

static open_fn real_open;
static open_fn real_open64;
static openat_fn real_openat;
static openat_fn real_openat64;
static read_fn real_read;
static close_fn real_close;

static char fake_content[4096];
static size_t fake_len;
static size_t fake_pos;

static void
resolve(void)
{
	if (real_open != NULL)
		return;
	real_open = (open_fn)dlsym(RTLD_NEXT, "open");
	real_open64 = (open_fn)dlsym(RTLD_NEXT, "open64");
	real_openat = (openat_fn)dlsym(RTLD_NEXT, "openat");
	real_openat64 = (openat_fn)dlsym(RTLD_NEXT, "openat64");
	real_read = (read_fn)dlsym(RTLD_NEXT, "read");
	real_close = (close_fn)dlsym(RTLD_NEXT, "close");
}

static int
is_meminfo(const char *path)
{
	return path != NULL && strcmp(path, "/proc/meminfo") == 0;
}

static int
fake_open_result(void)
{
	const char *fail = getenv("FAKE_MEMINFO_OPEN_FAIL");
	if (fail != NULL && *fail != '\0' && *fail != '0') {
		errno = ENOENT;
		return -1;
	}
	const char *content = getenv("FAKE_MEMINFO");
	if (content == NULL)
		content = "";
	fake_len = strlen(content);
	if (fake_len > sizeof(fake_content) - 1)
		fake_len = sizeof(fake_content) - 1;
	memcpy(fake_content, content, fake_len);
	fake_pos = 0;
	return FAKE_FD;
}

int
open(const char *path, int flags, ...)
{
	resolve();
	if (is_meminfo(path))
		return fake_open_result();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_open(path, flags, mode);
}

int
open64(const char *path, int flags, ...)
{
	resolve();
	if (is_meminfo(path))
		return fake_open_result();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_open64(path, flags, mode);
}

int
openat(int dirfd, const char *path, int flags, ...)
{
	resolve();
	if (is_meminfo(path))
		return fake_open_result();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_openat(dirfd, path, flags, mode);
}

int
openat64(int dirfd, const char *path, int flags, ...)
{
	resolve();
	if (is_meminfo(path))
		return fake_open_result();
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	return real_openat64(dirfd, path, flags, mode);
}

ssize_t
read(int fd, void *buf, size_t n)
{
	resolve();
	if (fd == FAKE_FD) {
		const char *fail = getenv("FAKE_MEMINFO_READ_FAIL");
		if (fail != NULL && *fail != '\0' && *fail != '0') {
			errno = EIO;
			return -1;
		}
		if (fake_pos >= fake_len)
			return 0;
		size_t avail = fake_len - fake_pos;
		if (n < avail)
			avail = n;
		memcpy(buf, fake_content + fake_pos, avail);
		fake_pos += avail;
		return (ssize_t)avail;
	}
	return real_read(fd, buf, n);
}

int
close(int fd)
{
	resolve();
	if (fd == FAKE_FD)
		return 0;
	return real_close(fd);
}
