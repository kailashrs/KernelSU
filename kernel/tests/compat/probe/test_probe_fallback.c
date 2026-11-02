#include "api.h"
#include <assert.h>
#include <stdio.h>
uid_t test_uid;
int test_refs,test_module_live=1,test_alloc_fail,test_task_fail,test_fail_register=-1,test_register_calls,test_live_probes,test_handled;
bool test_allowed=true,test_compat;
struct callback_head *test_work;
struct pt_regs test_sysregs;
syscall_fn_t table[512];syscall_fn_t *ksu_syscall_table=table;
int ksu_dispatcher_nr=-1;
bool ksu_su_compat_enabled=true;
#include "../../../hook/arm64/probe_fallback.c"
static long nested(int nr,const struct pt_regs *r){assert(!redirect_su(nr));return 71;}
long ksu_hook_execve(int nr,const struct pt_regs *r){return nested(nr,r);}
long ksu_hook_execveat(int nr,const struct pt_regs *r){return nested(nr,r);}
long ksu_hook_newfstatat(int nr,const struct pt_regs *r){return nested(nr,r);}
long ksu_hook_faccessat(int nr,const struct pt_regs *r){return nested(nr,r);}
int main(void){
 for(int i=0;i<7;i++){
  test_register_calls=0;test_fail_register=i;
  assert(ksu_probe_fallback_init()<0);assert(test_live_probes==0);
  assert(!uid_registered && !su_registered);ksu_probe_fallback_exit();assert(test_live_probes==0);
 }
 test_fail_register=-1;test_register_calls=0;
 assert(ksu_probe_fallback_init()==0);assert(test_live_probes==7 && test_refs==1);
 ksu_probe_fallback_exit();assert(test_live_probes==0 && test_refs==1);ksu_probe_fallback_exit();
 /* Remaining cases use an independent fixture with no lifetime pin. */
 test_refs=0;
 struct kretprobe_instance ri={0};struct pt_regs regs={0};
 test_uid=0;uid_entry(&ri,&regs);test_uid=10409;
 test_module_live=0;uid_return(&ri,&regs);assert(!test_work && test_refs==0);
 test_module_live=1;test_alloc_fail=1;uid_return(&ri,&regs);assert(!test_work && test_refs==0);
 test_alloc_fail=0;test_task_fail=1;uid_return(&ri,&regs);assert(!test_work && test_refs==0);
 test_task_fail=0;uid_return(&ri,&regs);assert(test_work && test_refs==1 && !test_handled);
 test_work->func(test_work);test_work=NULL;assert(test_refs==0 && test_handled==1);
 regs.regs[0]=-1;uid_return(&ri,&regs);assert(!test_work && test_refs==0);
 regs.regs[0]=0;test_uid=0;uid_return(&ri,&regs);assert(!test_work);
 test_sysregs.syscallno=__NR_execve;assert(pre_execve(NULL,&regs)==1 && test_refs==1);
 assert(su_execve(&test_sysregs)==71);assert(test_refs==0 && test_sysregs.syscallno==__NR_execve);
 test_allowed=false;assert(pre_execve(NULL,&regs)==0 && test_refs==0);
 test_allowed=true;test_compat=true;assert(pre_execve(NULL,&regs)==0 && test_refs==0);
 test_compat=false;test_module_live=0;assert(pre_execve(NULL,&regs)==0 && test_refs==0);
 puts("PASS: all seven registration failures roll back, deferred UID work pins safely, nested calls avoid recursion, unauthorized/compat/unloading tasks bypass");
}
