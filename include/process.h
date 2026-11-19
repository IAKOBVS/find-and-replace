/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PROCESS_H
#define PROCESS_H

#include "common.h"
#include "stage.h"
#include "thread_compat.h"

/**
 * @brief Process one file job from Stage A.
 * @details Reads FNAME into BUF, performs grep/replace/in-place work according
 *          to G, and returns the payload in RES. BUF ownership may transfer to
 *          RES->out; the caller must then allocate a new buffer.
 * @pre T is compiled; FNAME is readable; RES is writable.
 * @param t Compiled fixed-string matcher.
 * @param buf Per-worker reusable read buffer.
 * @param fname File path.
 * @param fname_len Byte length of FNAME.
 * @param st Stat result for FNAME.
 * @param find Find string.
 * @param find_len FIND byte length.
 * @param rplc Replacement string.
 * @param rplc_len REPLACE byte length.
 * @param confirm_phase Phase of the confirm workflow for this root.
 * @param res Result object to populate.
 * @return `JSTR_RET_SUCC` always; errors are reported in RES->err.
 * @post On success RES describes one job; BUF is valid or NULL if transferred.
 * @sideeffects May write files; does not touch stdio or Stage-C caches.
 * @thread Stage B worker.
 */
jstr_ret_ty process_job(const jstr_twoway_ty *R t, jstr_ty **R buf,
                        const char *R fname, size_t fname_len,
                        const struct stat *st, const char *R find,
                        const size_t find_len, const char *R rplc,
                        const size_t rplc_len, confirm_phase_ty confirm_phase,
                        process_result_ty *R res);

/**
 * @brief Compile or recompile the global find matcher.
 * @details Uses regex when MODE_USE_REGEX is set and fixed-string otherwise;
 *          recompiles when mode/cflags change or FORCE_RECOMPILE is set.
 * @pre FIND and RPLC are valid; ERR_BUF has ERR_SIZE bytes.
 * @param t Two-Way matcher to rebuild for fixed-string mode.
 * @param find Find string.
 * @param find_len FIND byte length.
 * @param rplc Replacement string used for backreference validation.
 * @param rplc_len REPLACE byte length.
 * @param force_recompile Force a fresh compile.
 * @param err_buf Diagnostic buffer.
 * @param err_size ERR_BUF capacity.
 * @return `JSTR_RET_SUCC` on success; `JSTR_RET_ERR` on compile/backref error.
 * @post On success G.regex/T reflect the current flags.
 * @sideeffects Mutates G regex/mode state.
 * @thread Main or Stage C only.
 */
jstr_ret_ty far_compile(jstr_twoway_ty *R t, const char *R find, size_t find_len, const char *R rplc, size_t rplc_len, int force_recompile, char *err_buf, size_t err_size);

/**
 * @brief Stage-B worker loop.
 * @details Receives SPMC work, processes each job, and publishes results to
 *          the worker's private C/D queue. Tracks root completion barriers.
 * @pre Pipeline started and root published.
 * @param arg Worker index encoded as a pointer.
 * @return `FAR_THREAD_RETURN` when shutdown is complete.
 * @post All accepted jobs have published results or errors.
 * @sideeffects Reads files, writes files, publishes queue results.
 * @thread Stage B worker only.
 */
far_thread_ret_ty process_thread(void *arg);

/**
 * @brief Collect all grep matches from a buffer into the legacy global list.
 * @details Appends owned match metadata to G.grep_lines up to SIZE_MAX.
 * @pre G.grep_lines is initialized.
 * @param t Compiled matcher.
 * @param buf Input buffer.
 * @param fname Source file name.
 * @param fname_len FNAME byte length.
 * @param find Find string.
 * @param find_len FIND byte length.
 * @return None.
 * @post G.grep_lines contains all matches from BUF.
 * @sideeffects Mutates G.grep_lines and G.grep_matched.
 * @thread Stage B worker.
 */
void grep_collect_file(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                       const char *R fname, size_t fname_len,
                       const char *R find, size_t find_len);

/**
 * @brief Collect grep matches into G.grep_lines with a limit.
 * @details Same as grep_collect_file but stops after LIMIT matches.
 * @pre LIMIT may be SIZE_MAX for unlimited collection.
 * @param t Compiled matcher.
 * @param buf Input buffer.
 * @param fname Source file name.
 * @param fname_len FNAME byte length.
 * @param find Find string.
 * @param find_len FIND byte length.
 * @param limit Maximum number of matches.
 * @return None.
 * @post At most LIMIT matches are appended.
 * @sideeffects Mutates G.grep_lines and G.grep_matched.
 * @thread Stage B worker.
 */
void grep_collect_file_n(const jstr_twoway_ty *R t, const jstr_ty *R buf,
                         const char *R fname, size_t fname_len,
                         const char *R find, size_t find_len, size_t limit);

#endif /* PROCESS_H */
