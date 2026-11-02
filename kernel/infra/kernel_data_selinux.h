/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef KSU_KERNEL_DATA_SELINUX_H
#define KSU_KERNEL_DATA_SELINUX_H
#include "objsec.h"
#include "infra/kernel_data.h"

#ifdef CONFIG_KSU_SELF_RESOLVED_DATA
/* Preserve the kernel helpers' exact types and NULL behavior. Referencing
 * the inline helper in typeof does not emit a private kernel-data import. */
static inline __typeof__(selinux_cred((const struct cred *)0))
ksu_selinux_cred(const struct cred *cred)
{
    return cred->security + ksu_kernel_blob_sizes()->lbs_cred;
}
static inline struct inode_security_struct *ksu_selinux_inode(const struct inode *inode)
{
    if (unlikely(!inode->i_security))
        return NULL;
    return inode->i_security + ksu_kernel_blob_sizes()->lbs_inode;
}
#else
#define ksu_selinux_cred selinux_cred
#define ksu_selinux_inode selinux_inode
#endif
#endif
