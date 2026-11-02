// SPDX-License-Identifier: GPL-2.0-only
/* Read-only scan_call_to logic retained from upstream patch_memory.c,
 * Copyright (C) 2023 bmax121. All Rights Reserved. */
#include "hook/patch_memory.h"
#include <linux/errno.h>

int ksu_patch_text(void *dst, void *src, size_t len, int flags)
{
    return -EOPNOTSUPP;
}

void *scan_call_to(void *start, size_t size, void *target)
{
    const uint32_t *insn = (const uint32_t *)start;
    size_t count = size / sizeof(uint32_t);
    size_t i;

    for (i = 0; i < count; i++) {
        int32_t imm26;
        void *branch_target;

        /* Check BL opcode: bits[31:26] == 0b100101 */
        if ((insn[i] & 0xFC000000U) != 0x94000000U)
            continue;

        /* Sign-extend the 26-bit immediate to 32 bits */
        imm26 = (int32_t)((insn[i] & 0x03FFFFFFU) << 6) >> 6;

        /* Branch target = PC + imm26 * 4 */
        branch_target = (void *)((uintptr_t)(&insn[i]) + ((int64_t)imm26 << 2));

        if (branch_target == target)
            return (void *)&insn[i];
    }

    return NULL;
}
