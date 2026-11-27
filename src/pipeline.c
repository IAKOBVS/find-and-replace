/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#include "pipeline.h"
#include "traverse.h"
#include "process.h"
#include "ui.h"
#include "terminal.h"
#include "grep_worker.h"
#include "spmc.h"
#include "spsc.h"
#include "thread_compat.h"

#include <errno.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define PIPELINE_DEPTH 256
#define PIPELINE_STATIC_WORKERS 8
#define PIPELINE_DONE_DEPTH 128
#define PIPELINE_CMD_DEPTH 16
#define PIPELINE_UI_DEPTH 16
#define PIPELINE_GREP_WORK_DEPTH 64
#define PIPELINE_GREP_MSG_DEPTH 64
#define PIPELINE_GREP_MSG_RETURN_DEPTH 64
#define PIPELINE_GREP_RETIRE_DEPTH 8
#define PIPELINE_RETIRE_NODE_RETURN_DEPTH 8
#define PIPELINE_RESULT_RETURN_DEPTH 128

typedef struct b_worker_ty {
	alignas(64) spsc_chan_ty done;
	alignas(64) void *done_slots[PIPELINE_DONE_DEPTH];
	alignas(64) spsc_chan_ty grep_work;
	alignas(64) void *grep_work_slots[PIPELINE_GREP_WORK_DEPTH];
	alignas(64) spsc_chan_ty res_return;
	alignas(64) void *res_return_slots[PIPELINE_RESULT_RETURN_DEPTH];
	alignas(64) atomic_ulong eos_epoch;
	alignas(64) spsc_chan_ty grep_cfg;
	alignas(64) void *grep_cfg_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty grep_msg;
	alignas(64) void *grep_msg_slots[PIPELINE_GREP_MSG_DEPTH];
	alignas(64) spsc_chan_ty grep_msg_return;
	alignas(64) void *grep_msg_return_slots[PIPELINE_GREP_MSG_RETURN_DEPTH];
	alignas(64) spsc_chan_ty grep_retire;
	alignas(64) void *grep_retire_slots[PIPELINE_GREP_RETIRE_DEPTH];
	alignas(64) spsc_chan_ty retire_node_return;
	alignas(64) void *retire_node_return_slots[PIPELINE_RETIRE_NODE_RETURN_DEPTH];
} b_worker_ty;

typedef struct pipeline_state_ty {
	alignas(64) spsc_chan_ty cmd;
	alignas(64) void *cmd_slots[PIPELINE_CMD_DEPTH];
	alignas(64) spmc_chan_ty work;
	spmc_slot_ty *work_slots;
	alignas(64) spsc_chan_ty ui_cmd;
	alignas(64) void *ui_cmd_slots[PIPELINE_UI_DEPTH];
	alignas(64) spsc_chan_ty ui_ack;
	alignas(64) void *ui_ack_slots[PIPELINE_UI_DEPTH];
	b_worker_ty *workers;
	far_thread_ty *process_threads;
	far_thread_ty *grep_threads;
	size_t worker_count;
	size_t grep_count;
	size_t requested_workers;
	int workers_heap_owned;
	far_thread_ty traversal_thread;
	far_thread_ty ui_thread;
} pipeline_state_ty;

typedef enum {
	PIPE_STOPPED,
	PIPE_STARTING,
	PIPE_RUNNING,
	PIPE_STOPPING
} pipeline_lifecycle_ty;

static pipeline_state_ty P;
static _Atomic(root_ctx_ty *) current_root;
static atomic_ulong root_epoch;
static atomic_int pipe_life;

static alignas(64) b_worker_ty static_workers[PIPELINE_STATIC_WORKERS];
static alignas(64) far_thread_ty static_process_threads[PIPELINE_STATIC_WORKERS];
static alignas(64) far_thread_ty static_grep_threads[PIPELINE_STATIC_WORKERS];
static alignas(64) spmc_slot_ty static_work_slots[PIPELINE_DEPTH];

/**
 * @anchor spec_parse_env_workers
 * @brief Parse the FAR_THREADS environment value.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param s input string.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
static size_t
parse_env_workers(const char *s)
{
	if (s == NULL || *s == '\0')
		return 0;
	char *end;
	errno = 0;
	const unsigned long v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v == 0)
		return 0;
	return (size_t)v;
}

/**
 * @anchor spec_default_workers
 * @brief Compute the default B worker count.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
static size_t
default_workers(void)
{
	const size_t env = parse_env_workers(getenv("FAR_THREADS"));
	if (env != 0)
		return env;
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 1)
		n = 1;
	return (size_t)n;
}

/**
 * @anchor spec_pipeline_set_workers
 * @brief Set the requested B worker count before startup.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param count parameter defined by the owning module contract.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
void
pipeline_set_workers(size_t count)
{
	if (atomic_load_explicit(&pipe_life, memory_order_acquire) != PIPE_STOPPED)
		return;
	if (count == 0)
		count = 1;
	P.requested_workers = count;
}

/**
 * @anchor spec_pipeline_worker_count
 * @brief Return the active or requested B worker count.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
size_t
pipeline_worker_count(void)
{
	if (P.worker_count != 0)
		return P.worker_count;
	if (P.requested_workers != 0)
		return P.requested_workers;
	return default_workers();
}

/**
 * @anchor spec_pipeline_uses_static_workers
 * @brief Report whether the active or last-started pipeline uses static worker storage.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Nonzero when the active or last-started B worker and work-slot arrays are static;
 *         zero when they were heap-allocated. Before any start, the default static
 *         choice is reported.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_uses_static_workers(void)
{
	return !P.workers_heap_owned;
}

/**
 * @anchor spec_pipeline_root_set
 * @brief Publish the current root and increment its epoch.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
void
pipeline_root_set(root_ctx_ty *root)
{
	atomic_store_explicit(&current_root, root, memory_order_release);
	atomic_fetch_add_explicit(&root_epoch, 1, memory_order_acq_rel);
}

/**
 * @anchor spec_pipeline_root_get
 * @brief Return the currently published root.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
root_ctx_ty *
pipeline_root_get(void)
{
	return atomic_load_explicit(&current_root, memory_order_acquire);
}

/**
 * @anchor spec_pipeline_root_epoch
 * @brief Return the current root epoch.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Computed count, width, or 1-based position; `0` when no value is available.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
unsigned long
pipeline_root_epoch(void)
{
	return atomic_load_explicit(&root_epoch, memory_order_acquire);
}

/**
 * @anchor spec_pipeline_worker_eos_mark
 * @brief Claim this worker's EOS slot for one root epoch.
 *
 * @details Atomically stores EPOCH if it is newer than the worker's last EOS
 *          epoch. Exactly one caller per worker/root epoch receives success.
 * @param worker Owning B worker index.
 * @param epoch Current root epoch.
 * @return Nonzero when this caller owns the EOS; zero when already claimed.
 * @par Threading and Reentrancy:
 *   Called by Stage B workers; one atomic per worker.
 */
int
pipeline_worker_eos_mark(size_t worker, unsigned long epoch)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return 0;
	unsigned long last = atomic_load_explicit(&P.workers[worker].eos_epoch, memory_order_relaxed);
	while (last < epoch) {
		if (atomic_compare_exchange_weak_explicit(&P.workers[worker].eos_epoch,
		                                          &last, epoch,
		                                          memory_order_acq_rel,
		                                          memory_order_relaxed))
			return 1;
	}
	return 0;
}

/**
 * @anchor spec_pipeline_stopping
 * @brief Report whether worker shutdown was requested.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Nonzero when the condition holds; zero otherwise.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_stopping(void)
{
	return atomic_load_explicit(&pipe_life, memory_order_acquire) == PIPE_STOPPING;
}

/**
 * @anchor spec_pipeline_retire_node_return_try_send
 * @brief Return a retire node to Stage C for reuse.
 * @param worker Owning Stage D worker index.
 * @param node Retire node pointer.
 * @return Zero on successful handoff; nonzero if the queue is full/invalid.
 * @par Side Effects:
 *   Publishes one pointer into the worker's retire-node return queue.
 * @par Threading and Reentrancy:
 *   Called by Stage D; consumed by Stage C.
 */
int
pipeline_retire_node_return_try_send(size_t worker, void *node)
{
	if (worker >= P.worker_count || node == NULL)
		return -1;
	return spsc_chan_try_send(&P.workers[worker].retire_node_return, node);
}

/**
 * @anchor spec_pipeline_retire_node_return_try_recv
 * @brief Try to reclaim a returned retire node.
 * @param worker Owning Stage D worker index.
 * @return Retire node pointer, or NULL if none is available.
 * @par Side Effects:
 *   Consumes one pointer from the worker's retire-node return queue.
 * @par Threading and Reentrancy:
 *   Called only by Stage C.
 */
void *
pipeline_retire_node_return_try_recv(size_t worker)
{
	if (worker >= P.worker_count)
		return NULL;
	return spsc_chan_try_recv(&P.workers[worker].retire_node_return);
}

/**
 * @anchor spec_pipeline_grep_msg_return_try_send
 * @brief Return a consumed grep message to the producer.
 * @details Non-blocking SPSC handoff. On success ownership transfers to Stage D.
 * @pre MSG is a fully processed grep message.
 * @param worker Owning Stage D worker index.
 * @param msg Message object to recycle.
 * @return Zero on successful handoff; nonzero if the queue is full/invalid.
 * @post On success the caller must not access MSG.
 * @par Side Effects:
 *   Publishes one pointer into the worker's grep-message return queue.
 * @par Threading and Reentrancy:
 *   Called by Stage C; consumed by Stage D.
 */
int
pipeline_grep_msg_return_try_send(size_t worker, far_grep_msg_ty *msg)
{
	if (worker >= P.worker_count || msg == NULL)
		return -1;
	return spsc_chan_try_send(&P.workers[worker].grep_msg_return, msg);
}

/**
 * @anchor spec_pipeline_grep_msg_return_try_recv
 * @brief Try to reclaim a recycled grep message.
 * @details Non-blocking SPSC receive. Caller owns the returned object.
 * @param worker Owning Stage D worker index.
 * @return Recycled message object, or NULL if none is available.
 * @post Caller must clear the object before reuse.
 * @par Side Effects:
 *   Consumes one pointer from the worker's grep-message return queue.
 * @par Threading and Reentrancy:
 *   Called only by Stage D.
 */
far_grep_msg_ty *
pipeline_grep_msg_return_try_recv(size_t worker)
{
	if (worker >= P.worker_count)
		return NULL;
	return (far_grep_msg_ty *)spsc_chan_try_recv(&P.workers[worker].grep_msg_return);
}

/**
 * @anchor spec_pipeline_result_return_try_send
 * @brief Return a processed result object to its owning B worker.
 * @details Non-blocking SPSC handoff. On success ownership transfers to the
 *          worker; on failure the caller keeps ownership.
 * @pre WORKER is a valid active worker index and RES is a finished result.
 * @param worker Owning B worker index.
 * @param res Result object to recycle.
 * @return Zero on successful handoff; nonzero when the queue is full/invalid.
 * @post On success RES must not be accessed by the caller.
 * @par Side Effects:
 *   Publishes one pointer into the worker return queue.
 * @par Threading and Reentrancy:
 *   Called by Stage C or D; one producer per queue.
 */
int
pipeline_result_return_try_send(size_t worker, far_result_ty *res)
{
	if (worker >= P.worker_count || res == NULL)
		return -1;
	return spsc_chan_try_send(&P.workers[worker].res_return, res);
}

/**
 * @anchor spec_pipeline_result_return_try_recv
 * @brief Try to reclaim a recycled result object for one B worker.
 * @details Non-blocking SPSC receive. Caller owns the returned object.
 * @pre WORKER is a valid active worker index.
 * @param worker Owning B worker index.
 * @return Recycled result object, or NULL if none is available.
 * @post Caller must clear the object before reuse.
 * @par Side Effects:
 *   Consumes one pointer from the worker return queue.
 * @par Threading and Reentrancy:
 *   Called only by the owning Stage B worker.
 */
far_result_ty *
pipeline_result_return_try_recv(size_t worker)
{
	if (worker >= P.worker_count)
		return NULL;
	return (far_result_ty *)spsc_chan_try_recv(&P.workers[worker].res_return);
}

/**
 * @anchor spec_pipeline_cmd_recv
 * @brief Receive the next root command from main.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
root_ctx_ty *
pipeline_cmd_recv(void)
{
	return (root_ctx_ty *)spsc_chan_recv(&P.cmd);
}

/**
 * @anchor spec_pipeline_work_send
 * @brief Publish one work job into the shared SPMC queue.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param job owned work item.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_work_send(far_job_ty *job)
{
	return spmc_chan_send(&P.work, job);
}

/**
 * @anchor spec_pipeline_work_try_recv
 * @brief Attempt to claim one work job.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
far_job_ty *
pipeline_work_try_recv(void)
{
	return (far_job_ty *)spmc_chan_try_recv(&P.work);
}

/**
 * @anchor spec_pipeline_done_send
 * @brief Publish one result to the caller’s private C queue.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @param res result object produced by Stage B.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_done_send(size_t worker, far_result_ty *res)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].done, res);
}

/**
 * @anchor spec_pipeline_done_try_recv
 * @brief Attempt to consume a result from one worker queue.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
far_result_ty *
pipeline_done_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_result_ty *)spsc_chan_try_recv(&P.workers[worker].done);
}

/**
 * @anchor spec_pipeline_grep_work_send
 * @brief Publish one raw result to the caller’s D queue.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @param res result object produced by Stage B.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_grep_work_send(size_t worker, far_result_ty *res)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].grep_work, res);
}

/**
 * @anchor spec_pipeline_grep_work_try_recv
 * @brief Attempt to consume a raw result from one D queue.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param worker zero-based B worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
far_result_ty *
pipeline_grep_work_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_result_ty *)spsc_chan_try_recv(&P.workers[worker].grep_work);
}

/**
 * @anchor spec_pipeline_grep_msg_send
 * @brief Publish one D match batch to C.
 *
 * @param worker Owning Stage D worker index.
 * @param msg owned message object.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @par Threading and Reentrancy:
 *   Called by Stage D; consumed by Stage C.
 */
int
pipeline_grep_msg_send(size_t worker, far_grep_msg_ty *msg)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].grep_msg, msg);
}

/**
 * @anchor spec_pipeline_grep_msg_recv
 * @brief Block on the next D match message from one worker.
 *
 * @param worker Owning Stage D worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @par Threading and Reentrancy:
 *   Called only by Stage C.
 */
far_grep_msg_ty *
pipeline_grep_msg_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_grep_msg_ty *)spsc_chan_recv(&P.workers[worker].grep_msg);
}

/**
 * @anchor spec_pipeline_grep_msg_try_recv
 * @brief Attempt to consume a D match message from one worker.
 *
 * @param worker Owning Stage D worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @par Threading and Reentrancy:
 *   Called only by Stage C.
 */
far_grep_msg_ty *
pipeline_grep_msg_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (far_grep_msg_ty *)spsc_chan_try_recv(&P.workers[worker].grep_msg);
}

/**
 * @anchor spec_pipeline_grep_cfg_send
 * @brief Publish a grep configuration snapshot to one D worker.
 *
 * @param worker Owning Stage D worker index.
 * @param cfg configuration snapshot.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @par Threading and Reentrancy:
 *   Called by Stage C; consumed by Stage D.
 */
int
pipeline_grep_cfg_send(size_t worker, grep_cfg_ty *cfg)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_send(&P.workers[worker].grep_cfg, cfg);
}

/**
 * @anchor spec_pipeline_grep_cfg_recv
 * @brief Block on the next grep configuration snapshot for one D worker.
 *
 * @param worker Owning Stage D worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @par Threading and Reentrancy:
 *   Called only by Stage D.
 */
grep_cfg_ty *
pipeline_grep_cfg_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (grep_cfg_ty *)spsc_chan_recv(&P.workers[worker].grep_cfg);
}

/**
 * @anchor spec_pipeline_grep_cfg_try_recv
 * @brief Attempt to consume a grep configuration snapshot for one D worker.
 *
 * @param worker Owning Stage D worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @par Threading and Reentrancy:
 *   Called only by Stage D.
 */
grep_cfg_ty *
pipeline_grep_cfg_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (grep_cfg_ty *)spsc_chan_try_recv(&P.workers[worker].grep_cfg);
}

/**
 * @anchor spec_pipeline_grep_retire_try_send
 * @brief Attempt to hand a retired match list to one D worker.
 *
 * @param worker Owning Stage D worker index.
 * @param lines match list to modify or retire.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @par Threading and Reentrancy:
 *   Called by Stage C; consumed by Stage D.
 */
int
pipeline_grep_retire_try_send(size_t worker, grep_lines_ty *lines)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return -1;
	return spsc_chan_try_send(&P.workers[worker].grep_retire, lines);
}

/**
 * @anchor spec_pipeline_grep_retire_try_recv
 * @brief Attempt to consume a retired match list in one D worker.
 *
 * @param worker Owning Stage D worker index.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @par Threading and Reentrancy:
 *   Called only by Stage D.
 */
grep_lines_ty *
pipeline_grep_retire_try_recv(size_t worker)
{
	if (jstr_unlikely(worker >= P.worker_count))
		return NULL;
	return (grep_lines_ty *)spsc_chan_try_recv(&P.workers[worker].grep_retire);
}

/**
 * @anchor spec_pipeline_ui_cmd_recv
 * @brief Block on the next UI command.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
far_ui_cmd_ty *
pipeline_ui_cmd_recv(void)
{
	return (far_ui_cmd_ty *)spsc_chan_recv(&P.ui_cmd);
}

/**
 * @anchor spec_pipeline_ui_cmd_try_recv
 * @brief Attempt to consume a UI command.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Pointer to the result object, or `NULL` on failure/end-of-stream.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
far_ui_cmd_ty *
pipeline_ui_cmd_try_recv(void)
{
	return (far_ui_cmd_ty *)spsc_chan_try_recv(&P.ui_cmd);
}

/**
 * @anchor spec_pipeline_ui_ack_send
 * @brief Acknowledge a UI root or END command.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param status acknowledgement status.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_ui_ack_send(int status)
{
	return spsc_chan_send(&P.ui_ack, (void *)(uintptr_t)(status + 1));
}

/**
 * @anchor spec_pipeline_ui_ack_recv
 * @brief Wait for a UI acknowledgement.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_ui_ack_recv(void)
{
	void *const v = spsc_chan_recv(&P.ui_ack);
	if (v == NULL)
		return -1;
	return (int)(uintptr_t)v - 1;
}

/**
 * @anchor spec_pipeline_ui_finish
 * @brief  Request END and wait for acknowledgement.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_ui_finish(void)
{
	static const far_ui_cmd_ty cmd = { .kind = FAR_UI_END, .root = NULL };
	if (jstr_unlikely(spsc_chan_send(&P.ui_cmd, (void *)&cmd) != 0))
		return -1;
	return pipeline_ui_ack_recv();
}

/**
 * @anchor spec_free_state
 * @brief Release pipeline-owned dynamic arrays.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
static void
free_state(void)
{
	if (P.workers != NULL) {
		for (size_t i = 0; i < P.worker_count; ++i) {
			far_grep_msg_ty *msg;
			void *node;
			far_result_ty *res;
			while ((msg = pipeline_grep_msg_return_try_recv(i)) != NULL)
				free(msg);
			while ((node = pipeline_retire_node_return_try_recv(i)) != NULL)
				free(node);
			while ((res = pipeline_result_return_try_recv(i)) != NULL)
				free(res);
		}
	}
	if (P.workers_heap_owned) {
		free(P.workers);
		free(P.process_threads);
		free(P.grep_threads);
		free(P.work_slots);
	}
	P.workers = NULL;
	P.process_threads = NULL;
	P.grep_threads = NULL;
	P.work_slots = NULL;
	P.worker_count = 0;
	P.grep_count = 0;
}

/**
 * @anchor spec_stop_grep
 * @brief Stop and join the started Stage D workers.
 *
 * @param count Number of D workers already started.
 * @par Threading and Reentrancy:
 *   Called by main during startup rollback and shutdown.
 */
static void
stop_grep(size_t count)
{
	grep_cfg_ty stop;
	stop.kind = GREP_CFG_STOP;
	for (size_t i = 0; i < count; ++i) {
		(void)pipeline_grep_cfg_send(i, &stop);
		FAR_THREAD_JOIN(P.grep_threads[i]);
	}
}

/**
 * @anchor spec_stop_ui_and_grep
 * @brief Stop and join C and D during startup rollback.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
static void
stop_ui_and_grep(void)
{
	far_ui_cmd_ty stop;
	stop.kind = FAR_UI_STOP;
	stop.root = NULL;
	(void)spsc_chan_send(&P.ui_cmd, &stop);
	FAR_THREAD_JOIN(P.ui_thread);
	stop_grep(P.grep_count);
}

/**
 * @anchor spec_pipeline_start
 * @brief Initialize queues and start all stage threads once.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_start(void)
{
	if (atomic_load_explicit(&pipe_life, memory_order_acquire) != PIPE_STOPPED)
		return 0;
	atomic_store_explicit(&pipe_life, PIPE_STARTING, memory_order_release);
	if (P.requested_workers == 0)
		P.requested_workers = default_workers();
	if (P.requested_workers == 0)
		P.requested_workers = 1;
	if (P.requested_workers > (size_t)-1 / sizeof(b_worker_ty))
		return -1;
	P.worker_count = P.requested_workers;
	atomic_init(&current_root, NULL);
	atomic_init(&root_epoch, 0);
	P.grep_count = P.worker_count;
	if (P.worker_count <= PIPELINE_STATIC_WORKERS) {
		P.workers = static_workers;
		P.process_threads = static_process_threads;
		P.grep_threads = static_grep_threads;
		P.work_slots = static_work_slots;
		P.workers_heap_owned = 0;
	} else {
		P.workers = (b_worker_ty *)calloc(P.worker_count, sizeof *P.workers);
		P.process_threads = (far_thread_ty *)calloc(P.worker_count, sizeof *P.process_threads);
		P.grep_threads = (far_thread_ty *)calloc(P.worker_count, sizeof *P.grep_threads);
		P.work_slots = (spmc_slot_ty *)calloc(PIPELINE_DEPTH, sizeof *P.work_slots);
		P.workers_heap_owned = 1;
		if (jstr_unlikely(!P.workers || !P.process_threads || !P.grep_threads || !P.work_slots)) {
			free_state();
			atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
			return -1;
		}
	}
	if (jstr_unlikely(spsc_chan_init(&P.cmd, P.cmd_slots, PIPELINE_CMD_DEPTH) != 0 ||
	                 spmc_chan_init(&P.work, P.work_slots, PIPELINE_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_cmd, P.ui_cmd_slots, PIPELINE_UI_DEPTH) != 0 ||
	                 spsc_chan_init(&P.ui_ack, P.ui_ack_slots, PIPELINE_UI_DEPTH) != 0)) {
		free_state();
		atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
		return -1;
	}
	for (size_t i = 0; i < P.worker_count; ++i) {
		atomic_init(&P.workers[i].eos_epoch, 0);
		if (jstr_unlikely(spsc_chan_init(&P.workers[i].done, P.workers[i].done_slots, PIPELINE_DONE_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_work, P.workers[i].grep_work_slots, PIPELINE_GREP_WORK_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].res_return, P.workers[i].res_return_slots, PIPELINE_RESULT_RETURN_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_cfg, P.workers[i].grep_cfg_slots, PIPELINE_UI_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_msg, P.workers[i].grep_msg_slots, PIPELINE_GREP_MSG_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_msg_return, P.workers[i].grep_msg_return_slots, PIPELINE_GREP_MSG_RETURN_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].grep_retire, P.workers[i].grep_retire_slots, PIPELINE_GREP_RETIRE_DEPTH) != 0 ||
		                 spsc_chan_init(&P.workers[i].retire_node_return, P.workers[i].retire_node_return_slots, PIPELINE_RETIRE_NODE_RETURN_DEPTH) != 0)) {
			free_state();
			atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
			return -1;
		}
	}
	size_t grep_started = 0;
	for (; grep_started < P.grep_count; ++grep_started) {
		if (jstr_unlikely(FAR_THREAD_CREATE(&P.grep_threads[grep_started], grep_worker_thread, (void *)(uintptr_t)grep_started) != FAR_THREAD_SUCCESS))
			break;
	}
	if (grep_started != P.grep_count) {
		stop_grep(grep_started);
		free_state();
		atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.ui_thread, terminal_ui_thread, NULL) != FAR_THREAD_SUCCESS)) {
		stop_grep(P.grep_count);
		free_state();
		atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
		return -1;
	}
	size_t started = 0;
	for (; started < P.worker_count; ++started) {
		if (jstr_unlikely(FAR_THREAD_CREATE(&P.process_threads[started], process_thread, (void *)(uintptr_t)started) != FAR_THREAD_SUCCESS))
			break;
	}
	if (started != P.worker_count) {
		atomic_store_explicit(&pipe_life, PIPE_STOPPING, memory_order_release);
		pipeline_root_set(NULL);
		spmc_chan_close(&P.work);
		for (size_t i = 0; i < started; ++i)
			FAR_THREAD_JOIN(P.process_threads[i]);
		stop_ui_and_grep();
		free_state();
		atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
		return -1;
	}
	if (jstr_unlikely(FAR_THREAD_CREATE(&P.traversal_thread, traverse_thread, NULL) != FAR_THREAD_SUCCESS)) {
		atomic_store_explicit(&pipe_life, PIPE_STOPPING, memory_order_release);
		pipeline_root_set(NULL);
		spmc_chan_close(&P.work);
		for (size_t i = 0; i < P.worker_count; ++i)
			FAR_THREAD_JOIN(P.process_threads[i]);
		stop_ui_and_grep();
		free_state();
		atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
		return -1;
	}
	atomic_store_explicit(&pipe_life, PIPE_RUNNING, memory_order_release);
	return 0;
}

/**
 * @anchor spec_pipeline_shutdown
 * @brief Stop and join all stage threads and release state.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
void
pipeline_shutdown(void)
{
	if (atomic_load_explicit(&pipe_life, memory_order_acquire) != PIPE_RUNNING)
		return;
	atomic_store_explicit(&pipe_life, PIPE_STOPPING, memory_order_release);
	(void)spsc_chan_send(&P.cmd, NULL);
	FAR_THREAD_JOIN(P.traversal_thread);
	for (size_t i = 0; i < P.worker_count; ++i)
		FAR_THREAD_JOIN(P.process_threads[i]);
	stop_ui_and_grep();
#if DO_FREE
	free_state();
#endif
	atomic_store_explicit(&pipe_life, PIPE_STOPPED, memory_order_release);
}

/**
 * @anchor spec_process_result
 * @brief Apply one Stage-B data result in Stage C.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param res result object produced by Stage B.
 * @param root per-root pipeline context.
 * @param failed parameter defined by the owning module contract.
 * @param canceled parameter defined by the owning module contract.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
static void
process_result(far_result_ty *R res, root_ctx_ty *R root, int *R failed, int *R canceled)
{
	if (!*canceled && !res->canceled) {
		if (res->pr.err) {
			if (root->a->confirm_phase == CONFIRM_SCAN) {
				*failed = 1;
				*canceled = 1;
				atomic_store_explicit(&root->cancel, true, memory_order_release);
			} else {
				++root->a->err_count;
			}
		} else if (jstr_chk(ui_result(res, root->a))) {
			if (root->a->confirm_phase == CONFIRM_SCAN) {
				*failed = 1;
				*canceled = 1;
				atomic_store_explicit(&root->cancel, true, memory_order_release);
			} else {
				++root->a->err_count;
			}
		}
	}
	ui_result_free(res);
}

/**
 * @anchor spec_pipeline_run
 * @brief Run one target root through the persistent pipeline.
 *
 * @details This function is part of the pipeline.c contract. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          All pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param root per-root pipeline context.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, all documented outputs, ownership transfers, and counters are updated;
 *       on failure, the caller retains ownership of caller-owned inputs.
 * @par Side Effects:
 *   Only the objects, queues, files, and global state named in the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Named stage/main as documented in ARCHITECTURE.md.
 */
int
pipeline_run(root_ctx_ty *R root)
{
	if (jstr_unlikely(atomic_load_explicit(&pipe_life, memory_order_acquire) != PIPE_RUNNING) && pipeline_start() != 0)
		return JSTR_RET_ERR;
	atomic_init(&root->cancel, false);
	atomic_init(&root->total, 0);
	atomic_init(&root->jobs_done, 0);
	atomic_init(&root->workers_done, 0);
	atomic_init(&root->eos_taken, false);
	atomic_init(&root->eos_sent, false);
	atomic_init(&root->phase, ROOT_STARTING);
	root->grep_live = (G.mode & MODE_GREP) && G.grep_collect &&
	                  isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
	atomic_init(&root->ftw_ret, JSTR_RET_SUCC);
	atomic_init(&root->prod_errs, 0);
	root->seq = 0;
	if (G.mode & MODE_GREP && G.grep_collect && isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) {
		far_ui_cmd_ty cmd;
		cmd.kind = FAR_UI_ROOT;
		cmd.root = root;
		if (jstr_unlikely(spsc_chan_send(&P.ui_cmd, &cmd) != 0))
			return JSTR_RET_ERR;
		if (jstr_unlikely(spsc_chan_send(&P.cmd, root) != 0))
			return JSTR_RET_ERR;
		const int status = pipeline_ui_ack_recv();
		if (status < 0)
			return JSTR_RET_ERR;
		if (status != 0)
			return JSTR_RET_ERR;
		return atomic_load_explicit(&root->ftw_ret, memory_order_acquire);
	}
	if (jstr_unlikely(spsc_chan_send(&P.cmd, root) != 0))
		return JSTR_RET_ERR;
	int failed = 0;
	int canceled = 0;
	int ret = JSTR_RET_SUCC;
	size_t eos = 0;
	size_t data_results = 0;
	unsigned int spin = 0;
	while (eos < 1 || data_results < atomic_load_explicit(&root->total, memory_order_acquire)) {
		int did = 0;
		for (size_t w = 0; w < P.worker_count; ++w) {
			far_result_ty *res;
			while ((res = pipeline_done_try_recv(w)) != NULL) {
				did = 1;
				if (res->kind == FAR_RES_EOS) {
					ui_result_free(res);
					++eos;
					continue;
				}
				++data_results;
				process_result(res, root, &failed, &canceled);
			}
		}
		if (did)
			spin = 0;
		else
			spsc_backoff(&spin);
	}
	atomic_store_explicit(&root->phase, ROOT_DONE, memory_order_release);
	root->a->err_count += atomic_load_explicit(&root->prod_errs, memory_order_acquire);
	ret = atomic_load_explicit(&root->ftw_ret, memory_order_acquire);
	if (failed)
		return JSTR_RET_ERR;
	return ret;
}
