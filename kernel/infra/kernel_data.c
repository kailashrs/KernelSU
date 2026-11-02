// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/proc_ns.h>
#include <linux/lsm_hooks.h>
#include "security.h"
#include "infra/kernel_data.h"
#include "infra/symbol_resolver.h"
#include "klog.h"

/* Filled before any policy, credentials, hooks or workers use these objects.
 * The module loader makes this storage read-only after successful init. */
struct ksu_kernel_data ksu_kernel_data __ro_after_init;

int __init ksu_kernel_data_init(void)
{
    struct ksu_kernel_data data = {
        .selinux = (void *)find_kernel_symbol_exact("selinux_state"),
        .blobs = (void *)find_kernel_symbol_exact("selinux_blob_sizes"),
        .mntns = (void *)find_kernel_symbol_exact("mntns_operations"),
    };
    if (!data.selinux || !data.blobs || !data.mntns) {
        pr_err("kernel_data: required built-in data symbol missing\n");
        return -ENOENT;
    }
    if (!IS_ALIGNED((unsigned long)data.selinux, __alignof__(*data.selinux)) ||
        !IS_ALIGNED((unsigned long)data.blobs, __alignof__(*data.blobs)) ||
        !IS_ALIGNED((unsigned long)data.mntns, __alignof__(*data.mntns))) {
        pr_err("kernel_data: data symbol alignment mismatch\n");
        return -EINVAL;
    }
    /* Blob offsets are initialized by the LSM core at boot. Reject absurd
     * offsets rather than publishing pointers which could corrupt objects. */
    if (data.blobs->lbs_cred < 0 || data.blobs->lbs_cred >= PAGE_SIZE ||
        data.blobs->lbs_inode < 0 || data.blobs->lbs_inode >= PAGE_SIZE) {
        pr_err("kernel_data: LSM blob offsets outside supported range\n");
        return -EINVAL;
    }
    ksu_kernel_data = data;
    pr_info("kernel_data: live typed pointers ready; no facts snapshots required\n");
    return 0;
}
