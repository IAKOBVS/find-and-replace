/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef FAR_UNIT_HARNESS_H
#define FAR_UNIT_HARNESS_H

#include "../../include/common.h"

#include <stdio.h>
#include <stdlib.h>

global_ty G;

static int unit_failures;

#define CHECK(cond)                                                            \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			++unit_failures;                                       \
		}                                                              \
	} while (0)

#define SECTION(name) ((void)0)

#define SPEC_SYMBOL(fn)                                                        \
	do {                                                                   \
		CHECK((void *)(&(fn)) != NULL);                                \
	} while (0)

static unsigned long unit_rng_state = 0x9e3779b97f4a7c15UL;

static unsigned long
unit_rng_next(void)
{
	unit_rng_state ^= unit_rng_state << 13;
	unit_rng_state ^= unit_rng_state >> 7;
	unit_rng_state ^= unit_rng_state << 17;
	return unit_rng_state;
}

#define UNIT_DONE()                                                            \
	do {                                                                   \
		if (unit_failures != 0)                                        \
			return 1;                                              \
		puts("PASS");                                                  \
		return 0;                                                      \
	} while (0)

#endif
