#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/ptrace.h>

#include "feature/selinux_oracle.h"
#include "klog.h" // IWYU pragma: keep
#include "selinux/selinux.h"

/*
 * selinuxfs exposes the policy to userspace through /sys/fs/selinux/context.
 * sel_write_context() resolves the written string against the live policy, so
 * an app_zygote isolated process can ask whether a root framework's SELinux
 * types exist. KernelSU adds the "ksu" and "ksu_file" types to the policy, so
 * a plain context copy answers yes and the detector reports KernelSU.
 *
 * We cannot remove check_context from app_zygote: selinux_android_setcontext()
 * calls security_check_context() on the isolated_app context while
 * specializing every useAppZygote child, and denying it aborts the child. The
 * permission is therefore kept and this kprobe hides only the KernelSU-owned
 * types. Everything else, including the legitimate isolated_app context, is
 * passed through untouched.
 *
 * Handler arguments (arm64 PCS):
 *   x0 = struct file *, x1 = char *buf, x2 = size_t size
 * The buffer comes from simple_transaction_get(), so it is kernel memory and
 * already readable. Returning non-zero from the pre-handler suppresses the
 * single-step of the probed instruction, and the return value plus PC we set
 * here make the call return -EINVAL without entering sel_write_context().
 */

#define KSU_ORACLE_APP_UID_MIN 10000

static bool context_type_is_kernelsu(const char *buf, size_t size)
{
    size_t field = 0, start = 0, i;

    for (i = 0; i <= size; i++) {
        char c = (i < size) ? buf[i] : '\0';

        if (c != ':' && c != '\0')
            continue;

        if (field == 2) {
            size_t len = i - start;

            /* "u:r:ksu:s0" */
            if (len == sizeof(KERNEL_SU_DOMAIN) - 1 &&
                !memcmp(buf + start, KERNEL_SU_DOMAIN, len))
                return true;
            /* "u:object_r:ksu_file:s0" and any other KernelSU-owned type. */
            if (len > 4 && !memcmp(buf + start, "ksu_", 4))
                return true;
        }

        if (c == '\0')
            break;
        field++;
        start = i + 1;
    }

    return false;
}

static int ksu_sel_write_context_pre(struct kprobe *probe, struct pt_regs *regs)
{
    const char *buf;
    size_t size;

    /* Root, init and system_server legitimately validate contexts. */
    if (current_uid().val < KSU_ORACLE_APP_UID_MIN)
        return 0;

    buf = (const char *)regs->regs[1];
    size = (size_t)regs->regs[2];
    if (unlikely(!buf || !size))
        return 0;

    if (!context_type_is_kernelsu(buf, size))
        return 0;

    regs_set_return_value(regs, (unsigned long)-EINVAL);
    instruction_pointer_set(regs, regs->regs[30]);
    return 1;
}

static struct kprobe sel_write_context_kp = {
    .symbol_name = "sel_write_context",
    .pre_handler = ksu_sel_write_context_pre,
};

static bool selinux_oracle_registered;

void ksu_selinux_oracle_init(void)
{
    int ret;

    if (selinux_oracle_registered)
        return;

    ret = register_kprobe(&sel_write_context_kp);
    if (ret) {
        pr_err("selinux oracle: sel_write_context kprobe failed: %d\n", ret);
        return;
    }

    selinux_oracle_registered = true;
    pr_info("selinux oracle: sel_write_context filter registered\n");
}

void ksu_selinux_oracle_exit(void)
{
    if (!selinux_oracle_registered)
        return;

    unregister_kprobe(&sel_write_context_kp);
    selinux_oracle_registered = false;
}
