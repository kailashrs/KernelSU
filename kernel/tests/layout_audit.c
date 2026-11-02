// Compile-only ABI evidence; not linked into KernelSU.
#include <linux/module.h>
#include <linux/proc_ns.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>
#include "infra/kernel_data_selinux.h"
#include "security.h"
#include "infra/seccomp_cache.c"
const unsigned long long ksu_layout_audit[] = {
 sizeof(struct module), offsetof(struct module, init), offsetof(struct module, exit),
 sizeof(struct task_struct), offsetof(struct task_struct, stack),
 offsetof(struct task_struct, real_cred), offsetof(struct task_struct, cred),
 offsetof(struct task_struct, sighand), offsetof(struct task_struct, seccomp),
 sizeof(struct mm_struct), offsetof(struct mm_struct, pgd),
 sizeof(struct pt_regs), offsetof(struct pt_regs, syscallno), offsetof(struct pt_regs, orig_x0),
 sizeof(struct kprobe), offsetof(struct kprobe, addr), offsetof(struct kprobe, pre_handler),
 sizeof(struct kretprobe), offsetof(struct kretprobe, handler),
 offsetof(struct kretprobe, entry_handler), offsetof(struct kretprobe, data_size),
 sizeof(struct kretprobe_instance), offsetof(struct kretprobe_instance, data),
 offsetof(struct pt_regs, pc), offsetof(struct pt_regs, regs),
 sizeof(struct callback_head), offsetof(struct callback_head, func),
 offsetof(struct cred, uid),
 sizeof(struct seccomp_filter), offsetof(struct seccomp_filter, cache),
 sizeof(struct action_cache), offsetof(struct action_cache, allow_native),
 offsetof(struct action_cache, allow_compat),
 sizeof(struct selinux_state), offsetof(struct selinux_state, enforcing),
 offsetof(struct selinux_state, policy), offsetof(struct selinux_state, policy_mutex),
 sizeof(struct lsm_blob_sizes), offsetof(struct lsm_blob_sizes, lbs_cred), offsetof(struct lsm_blob_sizes, lbs_inode),
 sizeof(struct task_security_struct), offsetof(struct task_security_struct, osid), offsetof(struct task_security_struct, sid),
 offsetof(struct task_security_struct, exec_sid), offsetof(struct task_security_struct, create_sid),
 offsetof(struct task_security_struct, keycreate_sid), offsetof(struct task_security_struct, sockcreate_sid),
 sizeof(struct inode_security_struct), offsetof(struct inode_security_struct, sid),
 offsetof(struct cred, security), offsetof(struct inode, i_security), sizeof(struct proc_ns_operations),
};
