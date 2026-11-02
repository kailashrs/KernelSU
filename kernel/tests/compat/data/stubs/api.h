#ifndef TEST_DATA_API_H
#define TEST_DATA_API_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#define CONFIG_KSU_SELF_RESOLVED_DATA 1
#define CONFIG_KSU_NO_TEXT_POKE 1
#define __init
#define __ro_after_init
#define PAGE_SIZE 4096
#define IS_ALIGNED(v,a) (((v)&((a)-1))==0)
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define unlikely(x) (x)
struct selinux_state { uint64_t value; };
struct lsm_blob_sizes { int lbs_cred,lbs_file,lbs_inode; };
struct proc_ns_operations { uint64_t value; };
struct cred { void *security; };
struct inode { void *i_security; };
struct task_security_struct { uint32_t sid; };
struct inode_security_struct { uint32_t sid; };
extern struct lsm_blob_sizes selinux_blob_sizes;
static inline struct task_security_struct *selinux_cred(const struct cred *c){return c->security+selinux_blob_sizes.lbs_cred;}
static inline struct inode_security_struct *selinux_inode(const struct inode *i){return i->i_security?i->i_security+selinux_blob_sizes.lbs_inode:NULL;}
#endif
