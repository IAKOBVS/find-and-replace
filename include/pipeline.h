/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef PIPELINE_H
#define PIPELINE_H

#include "stage.h"

/**
 * @brief Set the requested B worker count before startup.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param count parameter defined by the owning contract.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
void pipeline_set_workers(size_t count);
/**
 * @brief Return the active or requested B worker count.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
size_t pipeline_worker_count(void);
/**
 * @brief Publish the current root and increment its epoch.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
void pipeline_root_set(root_ctx_ty *root);
/**
 * @brief Return the currently published root.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
root_ctx_ty *pipeline_root_get(void);
/**
 * @brief Return the current root epoch.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
unsigned long pipeline_root_epoch(void);
/**
 * @brief Report whether worker shutdown was requested.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_stopping(void);
/**
 * @brief Initialize queues and start all stage threads once.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_start(void);
/**
 * @brief Stop and join all stage threads and release state.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
void pipeline_shutdown(void);
/**
 * @brief Run one target root through the persistent pipeline.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_run(root_ctx_ty *R root);

/**
 * @brief Receive the next root command from main.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
root_ctx_ty *pipeline_cmd_recv(void);
/**
 * @brief Publish one work job into the shared SPMC queue.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param job owned work item.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_work_send(far_job_ty *job);
/**
 * @brief Attempt to claim one work job.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_job_ty *pipeline_work_try_recv(void);
/**
 * @brief Publish one result to the caller’s private C queue.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @param res result object produced by Stage B.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_done_send(size_t worker, far_result_ty *res);
/**
 * @brief Attempt to consume a result from one worker queue.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_result_ty *pipeline_done_try_recv(size_t worker);
/**
 * @brief Publish one raw result to the caller’s D queue.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @param res result object produced by Stage B.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_grep_work_send(size_t worker, far_result_ty *res);
/**
 * @brief Attempt to consume a raw result from one D queue.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_result_ty *pipeline_grep_work_try_recv(size_t worker);
/**
 * @brief Publish one D match batch to C.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param msg owned message object.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_grep_msg_send(far_grep_msg_ty *msg);
/**
 * @brief Block on the next D match message.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_grep_msg_ty *pipeline_grep_msg_recv(void);
/**
 * @brief Attempt to consume a D match message.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_grep_msg_ty *pipeline_grep_msg_try_recv(void);
/**
 * @brief Publish a grep configuration snapshot to D.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param cfg configuration snapshot.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_grep_cfg_send(grep_cfg_ty *cfg);
/**
 * @brief Block on the next grep configuration snapshot.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
grep_cfg_ty *pipeline_grep_cfg_recv(void);
/**
 * @brief Attempt to consume a grep configuration snapshot.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
grep_cfg_ty *pipeline_grep_cfg_try_recv(void);
/**
 * @brief Attempt to hand a retired match list to D.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param lines match list to modify or retire.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_grep_retire_try_send(grep_lines_ty *lines);
/**
 * @brief Attempt to consume a retired match list in D.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
grep_lines_ty *pipeline_grep_retire_try_recv(void);
/**
 * @brief Block on the next UI command.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_ui_cmd_ty *pipeline_ui_cmd_recv(void);
/**
 * @brief Attempt to consume a UI command.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
far_ui_cmd_ty *pipeline_ui_cmd_try_recv(void);
/**
 * @brief Acknowledge a UI root or END command.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param status acknowledgement status.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_ui_ack_send(int status);
/**
 * @brief Wait for a UI acknowledgement.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_ui_ack_recv(void);
/**
 * @brief  Request END and wait for acknowledgement.
 *
 * @details Contract for the public declaration in pipeline.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage or main as documented in docs/ARCHITECTURE.md.
 */
int pipeline_ui_finish(void);

#endif /* PIPELINE_H */
