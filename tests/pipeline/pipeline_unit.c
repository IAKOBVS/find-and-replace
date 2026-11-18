/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "../../pipeline.h"
#include "../../common.h"

#include <stdio.h>

global_ty G = { .mode = MODE_PRINT_STDOUT };

int
main(void)
{
	pipeline_shutdown();
	if (pipeline_start() != 0) {
		fprintf(stderr, "FAIL: first pipeline_start failed\n");
		return 1;
	}
	if (pipeline_start() != 0) {
		fprintf(stderr, "FAIL: second pipeline_start should be a no-op\n");
		return 1;
	}
	pipeline_shutdown();
	pipeline_shutdown();
	printf("pipeline: all checks passed\n");
	return 0;
}
