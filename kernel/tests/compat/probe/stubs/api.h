#ifndef TEST_API_H
#define TEST_API_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#define __nocfi
#define GFP_ATOMIC 0
#define THIS_MODULE ((void *)1)
#define TWA_RESUME 1
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define READ_ONCE(x) (x)
#define unlikely(x) (x)
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define pr_info(...) ((void)0)
#define __NR_setresuid 147
#define __NR_execve 221
#define __NR_execveat 281
#define __NR_newfstatat 79
#define __NR_faccessat 48
#define __NR_statx 291
#define __NR_faccessat2 439
struct pt_regs { long regs[31];long syscallno;unsigned long pc; };
struct callback_head { struct callback_head *next; void (*func)(struct callback_head *); };
struct kprobe { void *addr;int (*pre_handler)(struct kprobe *,struct pt_regs *); };
struct kretprobe_instance { char data[8]; };
struct kretprobe { struct kprobe kp;int (*entry_handler)(struct kretprobe_instance *,struct pt_regs *);int (*handler)(struct kretprobe_instance *,struct pt_regs *);size_t data_size;int maxactive; };
typedef unsigned char kprobe_opcode_t;
typedef long (*syscall_fn_t)(const struct pt_regs *);
struct kuid { uid_t val; };
extern uid_t test_uid;
extern int test_refs,test_module_live,test_alloc_fail,test_task_fail,test_fail_register,test_register_calls,test_live_probes,test_handled;
extern bool test_allowed,test_compat;
extern struct callback_head *test_work;
extern struct pt_regs test_sysregs;
extern syscall_fn_t *ksu_syscall_table;
extern int ksu_dispatcher_nr;
extern bool ksu_su_compat_enabled;
#define current ((void *)1)
static inline struct kuid current_uid(void){return (struct kuid){test_uid};}
static inline long regs_return_value(struct pt_regs *r){return r->regs[0];}
static inline bool is_compat_task(void){return test_compat;}
static inline struct pt_regs *task_pt_regs(void *p){return &test_sysregs;}
static inline void instruction_pointer_set(struct pt_regs *r,unsigned long pc){r->pc=pc;}
static inline bool try_module_get(void *m){if(!test_module_live)return false;test_refs++;return true;}
static inline void __module_get(void *m){test_refs++;}
static inline void module_put(void *m){test_refs--;}
static inline void *kzalloc(size_t n,int flags){return test_alloc_fail?NULL:calloc(1,n);}
#define kfree free
static inline int task_work_add(void *p,struct callback_head *h,int flag){if(test_task_fail)return -1;test_work=h;return 0;}
static inline int register_kprobe(struct kprobe *p){if(test_register_calls++==test_fail_register)return -EINVAL;test_live_probes++;return 0;}
static inline int register_kretprobe(struct kretprobe *p){return register_kprobe(&p->kp);}
static inline void unregister_kprobe(struct kprobe *p){test_live_probes--;}
static inline void unregister_kretprobe(struct kretprobe *p){unregister_kprobe(&p->kp);}
static inline bool ksu_is_allow_uid_for_current(uid_t uid){return test_allowed;}
static inline int ksu_handle_setresuid(uid_t a,uid_t b){test_handled++;return 0;}
long ksu_hook_execve(int,const struct pt_regs *);
long ksu_hook_execveat(int,const struct pt_regs *);
long ksu_hook_newfstatat(int,const struct pt_regs *);
long ksu_hook_faccessat(int,const struct pt_regs *);
#endif
