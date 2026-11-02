/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSU_KERNEL_DATA_H
#define KSU_KERNEL_DATA_H

struct selinux_state;
struct lsm_blob_sizes;
struct proc_ns_operations;

#ifdef CONFIG_KSU_SELF_RESOLVED_DATA
#ifndef CONFIG_KSU_NO_TEXT_POKE
#error "Self-resolved data requires the no-text-poke compatibility profile"
#endif
struct ksu_kernel_data {
    struct selinux_state *selinux;
    const struct lsm_blob_sizes *blobs;
    const struct proc_ns_operations *mntns;
};
extern struct ksu_kernel_data ksu_kernel_data;
int ksu_kernel_data_init(void);

static inline struct selinux_state *ksu_kernel_selinux_state(void)
{
    return ksu_kernel_data.selinux;
}
static inline const struct lsm_blob_sizes *ksu_kernel_blob_sizes(void)
{
    return ksu_kernel_data.blobs;
}
static inline const struct proc_ns_operations *ksu_kernel_mntns_ops(void)
{
    return ksu_kernel_data.mntns;
}
#else
#define ksu_kernel_selinux_state() (&selinux_state)
#define ksu_kernel_blob_sizes() (&selinux_blob_sizes)
#define ksu_kernel_mntns_ops() (&mntns_operations)
#endif
#endif
