/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef THREAD_COMPAT_H
#define THREAD_COMPAT_H

#ifdef FAR_USE_PTHREAD
#include <pthread.h>
typedef pthread_t far_thread_ty;
typedef void *far_thread_ret_ty;
#define FAR_THREAD_RETURN  NULL
#define FAR_THREAD_SUCCESS 0
#define FAR_THREAD_CREATE(th, fn, arg) pthread_create((th), NULL, (fn), (arg))
#define FAR_THREAD_JOIN(th)            pthread_join((th), NULL)
#else
#include <threads.h>
typedef thrd_t far_thread_ty;
typedef int far_thread_ret_ty;
#define FAR_THREAD_RETURN  0
#define FAR_THREAD_SUCCESS thrd_success
#define FAR_THREAD_CREATE(th, fn, arg) thrd_create((th), (fn), (arg))
#define FAR_THREAD_JOIN(th)            thrd_join((th), NULL)
#endif

#endif /* THREAD_COMPAT_H */
