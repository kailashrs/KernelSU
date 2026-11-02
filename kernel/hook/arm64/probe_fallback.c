// SPDX-License-Identifier: GPL-2.0-only
/* Explicit late-load alternative to direct syscall-table writes.
 * The setresuid/sucompat design follows the Samsung RKP adaptation in
 * Root-My-Galaxy-Payloads (GPL-2.0); no Samsung credential/DEFEX code is used.
 */
#include <linux/cred.h>
#include <linux/compat.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include "hook/arm64/probe_fallback.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "feature/sucompat.h"
#include "policy/allowlist.h"
#include "klog.h"

#define KSU_PROBE_NESTED_NR (-2)
struct uid_work {
    struct callback_head callback;
    uid_t old_uid;
    uid_t new_uid;
};

static void uid_work_run(struct callback_head *callback)
{
    struct uid_work *work = container_of(callback, struct uid_work, callback);
    ksu_handle_setresuid(work->old_uid, work->new_uid);
    kfree(work);
    module_put(THIS_MODULE);
}

static int uid_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    *(uid_t *)ri->data = current_uid().val;
    return 0;
}

static int uid_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct uid_work *work;
    uid_t old_uid = *(uid_t *)ri->data;
    uid_t new_uid = current_uid().val;
    if (regs_return_value(regs) < 0 || old_uid == new_uid)
        return 0;
    /* The handler may sleep or install an FD: defer it out of probe context.
     * A reference blocks unloading while its callback is still queued.
     * During MODULE_STATE_COMING, try_module_get fails and no work is queued.
     */
    if (!try_module_get(THIS_MODULE))
        return 0;
    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (!work) {
        module_put(THIS_MODULE);
        return 0;
    }
    work->old_uid = old_uid;
    work->new_uid = new_uid;
    work->callback.func = uid_work_run;
    if (task_work_add(current, &work->callback, TWA_RESUME)) {
        kfree(work);
        module_put(THIS_MODULE);
    }
    return 0;
}

static struct kretprobe uid_probe = {
    .entry_handler = uid_entry,
    .handler = uid_return,
    .data_size = sizeof(uid_t),
    .maxactive = 128,
};
static bool uid_registered;
static unsigned int su_registered;

static bool redirect_su(int nr)
{
    struct pt_regs *sysregs = task_pt_regs(current);
    /* Consume the marker exactly once at the nested original syscall. */
    if (unlikely(sysregs->syscallno == KSU_PROBE_NESTED_NR)) {
        sysregs->syscallno = nr;
        return false;
    }
    if (is_compat_task())
        return false;
    return ksu_su_compat_enabled &&
           ksu_is_allow_uid_for_current(current_uid().val);
}

#define SU_PROBE(name, nr, hook)                                                \
static long __nocfi su_##name(const struct pt_regs *regs)                        \
{                                                                               \
    struct pt_regs *rw = (struct pt_regs *)regs;                                 \
    int saved = rw->syscallno;                                                   \
    long ret;                                                                   \
    rw->syscallno = KSU_PROBE_NESTED_NR;                                          \
    ret = hook(nr, regs);                                                        \
    rw->syscallno = saved;                                                       \
    module_put(THIS_MODULE);                                                     \
    return ret;                                                                 \
}                                                                               \
static int pre_##name(struct kprobe *probe, struct pt_regs *regs)                \
{                                                                               \
    if (!redirect_su(nr) || !try_module_get(THIS_MODULE))                         \
        return 0;                                                               \
    instruction_pointer_set(regs, (unsigned long)su_##name);                     \
    return 1;                                                                   \
}
SU_PROBE(execve, __NR_execve, ksu_hook_execve)
SU_PROBE(execveat, __NR_execveat, ksu_hook_execveat)
SU_PROBE(newfstatat, __NR_newfstatat, ksu_hook_newfstatat)
SU_PROBE(faccessat, __NR_faccessat, ksu_hook_faccessat)
SU_PROBE(statx, __NR_statx, ksu_hook_newfstatat)
SU_PROBE(faccessat2, __NR_faccessat2, ksu_hook_faccessat)

static struct {
    int nr;
    struct kprobe probe;
} su_probes[] = {
    { .nr = __NR_execve, .probe.pre_handler = pre_execve },
    { .nr = __NR_execveat, .probe.pre_handler = pre_execveat },
    { .nr = __NR_newfstatat, .probe.pre_handler = pre_newfstatat },
    { .nr = __NR_faccessat, .probe.pre_handler = pre_faccessat },
    { .nr = __NR_statx, .probe.pre_handler = pre_statx },
    { .nr = __NR_faccessat2, .probe.pre_handler = pre_faccessat2 },
};

int ksu_probe_fallback_init(void)
{
    unsigned int i;
    int ret;
    if (!ksu_syscall_table || ksu_dispatcher_nr >= 0)
        return -EINVAL;
    uid_probe.kp.addr = (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[__NR_setresuid]);
    ret = register_kretprobe(&uid_probe);
    if (ret)
        return ret;
    uid_registered = true;
    for (i = 0; i < ARRAY_SIZE(su_probes); i++) {
        su_probes[i].probe.addr =
            (kprobe_opcode_t *)READ_ONCE(ksu_syscall_table[su_probes[i].nr]);
        ret = register_kprobe(&su_probes[i].probe);
        if (ret)
            goto rollback;
        su_registered++;
    }
    /* A pre-handler redirects execution to a wrapper after returning from
     * the kprobe machinery. Unregistering probes alone cannot synchronize
     * that wrapper's final return, or a task_work callback's final return.
     * This explicit temporary-root profile therefore remains pinned until
     * reboot; do not advertise live unloading as safe. All registration
     * failure paths above still roll back before taking this lifetime pin. */
    __module_get(THIS_MODULE);
    pr_info("probe_fallback: compatibility LKM pinned until reboot\n");
    pr_info("probe_fallback: UID return probe and %u su probes installed; no syscall-table writes\n", su_registered);
    return 0;
rollback:
    ksu_probe_fallback_exit();
    return ret;
}

void ksu_probe_fallback_exit(void)
{
    while (su_registered)
        unregister_kprobe(&su_probes[--su_registered].probe);
    if (uid_registered) {
        unregister_kretprobe(&uid_probe);
        uid_registered = false;
    }
    /* Queued UID callbacks hold module references, so normal rmmod cannot
     * reach this exit while any deferred callback is outstanding. */
}
