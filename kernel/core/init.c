#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "feature/module_blacklist.h"
#include "feature/shell_su_adb_only.h"
#include "infra/symbol_resolver.h"
#include "infra/kernel_data.h"

#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

#ifdef CONFIG_KSU_HIDE_MODULE
/*
 * Anti-fingerprinting: unlink THIS_MODULE from the kernel module list so
 * /proc/modules and module kallsyms names stop advertising it. Upstream
 * already dropped /sys/module via kobject_del above; this closes the last
 * list-visible artifact. module_mutex and modules are not exported to
 * modules, so they are resolved through the private kallsyms channel used
 * for other protected kernel data. The NO_TEXT_POKE profile pins the module
 * until reboot, so no unload path can hit a missing list node; the list
 * head is re-initialized and an extra reference is taken regardless.
 */
static void ksu_hide_module(void)
{
    static struct mutex *module_mutex_ptr;
    static struct list_head *modules_list;
    struct module *mod = THIS_MODULE;

    if (!modules_list)
        modules_list = (struct list_head *)find_kernel_symbol_exact("modules");
    if (!module_mutex_ptr)
        module_mutex_ptr = (struct mutex *)find_kernel_symbol_exact("module_mutex");

    if (!modules_list || !module_mutex_ptr) {
        pr_err("hide: module list symbols unresolved\n");
        return;
    }

    mutex_lock(module_mutex_ptr);
    if (!list_empty(&mod->list)) {
        list_del_rcu(&mod->list);
        INIT_LIST_HEAD(&mod->list);
    }
    mutex_unlock(module_mutex_ptr);

    __module_get(mod);
}
#endif

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

#ifdef MODULE
bool ksu_bundled = false;
module_param_named(bundled, ksu_bundled, bool, 0);
#endif

#ifdef CONFIG_KSU_NO_TEXT_POKE
#ifndef MODULE
#error "KSU_NO_TEXT_POKE requires an LKM"
#endif
/* LKM .exit.text is present during a failing module init. This __ref
 * rollback helper intentionally shares teardown with the unload path. */
static void __ref ksu_undo_failed_hook_init(void)
{
    /* Probe initialization rolled back its own registrations. None of the
     * observer/throne/file-wrapper hooks below it has been initialized. */
    ksu_allowlist_exit();
    ksu_supercalls_exit();
    ksu_shell_su_adb_only_exit();
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_selinux_hide_exit();
#endif
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_module_blacklist_exit();
#endif
    ksu_syscall_hook_exit();
    put_cred(ksu_cred);
}
#endif

int __init kernelsu_init(void)
{
#ifdef CONFIG_KSU_NO_TEXT_POKE
    int hook_ret;
#endif
    pr_info("welcome to KernelSU version " __stringify(KERNEL_SU_VERSION) ", package name " KSU_PACKAGE_NAME "\n");
#if defined(__x86_64__) && !defined(CONFIG_KSU_X86_PATCH_SYSCALL_DISPATCHER)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
#ifdef CONFIG_KSU_NO_TEXT_POKE
    if (!ksu_late_loaded) {
        pr_err("no_text_poke supports late-load only\n");
        return -EOPNOTSUPP;
    }
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

#ifdef CONFIG_KSU_SELF_RESOLVED_DATA
    ksu_init_symbol_resolver();
    hook_ret = ksu_kernel_data_init();
    if (hook_ret)
        return hook_ret;
#endif
    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        return -ENOSYS;
    }

#ifndef CONFIG_KSU_SELF_RESOLVED_DATA
    ksu_init_symbol_resolver();
#endif
    ksu_syscall_hook_init();

    // Block modules early, before vendor modules are loaded in second stage.
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_module_blacklist_init();
#endif

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_selinux_hide_init();
#endif
    ksu_shell_su_adb_only_init();

    ksu_supercalls_init();
    ksu_app_profile_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

#ifdef CONFIG_KSU_NO_TEXT_POKE
        hook_ret = ksu_syscall_hook_manager_init();
        if (hook_ret)
            goto fail_hook_manager;
#else
        (void)ksu_syscall_hook_manager_init();
#endif

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        track_throne(false);

        ksu_feature_apply_forced();

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }

    } else {
        (void)ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    kobject_del(&THIS_MODULE->mkobj.kobj);
#ifdef CONFIG_KSU_HIDE_MODULE
    ksu_hide_module();
#endif
#endif
#endif
    return 0;

#ifdef CONFIG_KSU_NO_TEXT_POKE
fail_hook_manager:
    ksu_undo_failed_hook_init();
    return hook_ret;
#endif
}

void __exit kernelsu_exit(void)
{
    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_shell_su_adb_only_exit();
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_selinux_hide_exit();
#endif
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();
#ifndef CONFIG_KSU_NO_TEXT_POKE
    ksu_module_blacklist_exit();
#endif

    put_cred(ksu_cred);
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif

#ifdef CONFIG_KSU_NO_TEXT_POKE
MODULE_INFO(ksu_no_text_poke, "1");
#endif

#ifdef CONFIG_KSU_SELF_RESOLVED_DATA
MODULE_INFO(ksu_self_resolved_data, "1");
#endif
