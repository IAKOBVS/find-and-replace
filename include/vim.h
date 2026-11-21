/* SPDX-License-Identifier: MIT */
/* Copyright (c) 2023-2026 James Tirta Halim <tirtajames45 at gmail dot com> */

#ifndef VIM_H
#define VIM_H

#include "common.h"

typedef enum {
	VIM_INSERT,
	VIM_NORMAL,
	VIM_OP_D,
	VIM_OP_C
} vim_state_ty;

/**
 * @brief Return the current line-editor mode.
 *
 * @details Contract for the public declaration in vim.h. It reads only
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
 *   Stage C only.
 */
int vim_is_insert_mode(void);
/**
 * @brief Set the line-editor mode and clear any pending operator.
 *
 * @details Contract for the public declaration in vim.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param mode new editor mode.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage C only.
 */
void vim_set_insert_mode(int mode);

/** Return the current explicit vim state. */
vim_state_ty vim_state(void);

/** Set the full vim state. */
void vim_set_state(vim_state_ty state);

/** Cancel a pending vim operator without changing insert mode. */
void vim_cancel_pending(void);
/**
 * @brief Apply a vim normal-mode key to the active field.
 *
 * @details Contract for the public declaration in vim.h. It reads only
 *          the inputs named below and writes only the documented outputs.
 *          Pointer inputs must remain valid for the call duration.
 *          Failures never leave a partially published queue item, file, or result.
 * @pre The owning module is initialized and all documented preconditions hold.
 * @param c input character or channel.
 * @param active_buf parameter defined by the owning contract.
 * @param cursors per-field cursor array.
 * @param active_field zero-based active field index.
 * @param needs_redraw parameter defined by the owning contract.
 * @param needs_recompile parameter defined by the owning contract.
 * @param field_count number of fields.
 * @return Zero on success; nonzero on failure, except documented predicates.
 * @post On success, documented outputs, ownership transfers, and counters are updated;
 *       on failure, caller-owned inputs remain valid.
 * @par Side Effects:
 *   Only objects, queues, files, and global state named by the owning contract are modified.
 * @par Threading and Reentrancy:
 *   Stage C only.
 */
int vim_handle_key(char c, jstr_ty *active_buf, size_t *cursors, size_t *active_field, int *needs_redraw, int *needs_recompile, size_t field_count);

#endif /* VIM_H */
