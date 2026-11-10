#ifndef __KSU_H_KLOG
#define __KSU_H_KLOG

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "KernelSU: " fmt
#endif

/*
 * KSU_QUIET: anti-fingerprinting.
 *
 * dmesg is world-readable on many devices (dmesg_restrict=0), so every
 * routine "KernelSU:" line is a userspace-detectable marker. Under
 * KSU_QUIET the high-volume, unauthenticated-triggerable levels are
 * compiled out with no_printk: the call sites, their format strings and
 * the log output all disappear. pr_err survives for real failure paths.
 */
#ifdef CONFIG_KSU_QUIET
#ifdef pr_info
#undef pr_info
#endif
#define pr_info(fmt, ...) no_printk(pr_fmt(fmt), ##__VA_ARGS__)

#ifdef pr_warn
#undef pr_warn
#endif
#define pr_warn(fmt, ...) no_printk(pr_fmt(fmt), ##__VA_ARGS__)
#endif /* CONFIG_KSU_QUIET */

#endif
