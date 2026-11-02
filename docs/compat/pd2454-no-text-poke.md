# PD2454 late-load compatibility profile

This branch adds an optional ARM64 late-load profile for the Vivo X200 Ultra
(V2454A / PD2454). The validated target is:

```
6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
```

The source base is KernelSU v3.3.1, commit
`0c0fdb960178fa12d80d6cbcfdcb6ad8be6a865d`. The userspace IOCTL and app-profile
ABIs remain unchanged.

## Configuration

```
CONFIG_KSU=m
CONFIG_KSU_NO_TEXT_POKE=y
CONFIG_KSU_SELF_RESOLVED_DATA=y
```

The profile requires ARM64 kprobes/kretprobes and runtime kernel data-symbol
availability (`CONFIG_KALLSYMS_ALL=y` on the validated target). It supports
late loading only. The ordinary configuration remains separately available.

### Probe hooks

`ksu_patch_text()` refuses direct writes with `-EOPNOTSUPP`, before entering
`stop_machine`. The syscall table is resolved for reading handler addresses;
no dispatcher slot is installed.

A return probe on `setresuid` defers the existing UID-handoff work to task
work, where Manager receives its driver FD and authorized tasks receive the
usual seccomp-cache adjustment. Probes on `execve`, `execveat`, `newfstatat`,
`faccessat`, `statx` and `faccessat2` reuse the normal sucompat and allowlist
handlers. A nested-call marker prevents recursive interception.

Partial registration failures unregister the probes already installed and
abort module initialization. This mode does not change task tracepoint flags
owned by other tracing users.

A successful initialization pins this compatibility LKM until reboot.
Redirected wrappers and deferred callbacks can still be returning after a
probe callback ends; live unload is therefore deliberately unavailable.

### Typed kernel data

Before preparing credentials, updating policy or registering hooks, the
module resolves the built-in `selinux_state`, `selinux_blob_sizes` and
`mntns_operations` objects. It checks presence, alignment and supported blob
offsets before publishing the typed pointers in module-owned
`.data..ro_after_init` storage.

SELinux credential/inode accessors preserve the kernel helpers' types and
NULL behavior while using live blob offsets. The resulting module has no
undefined references to those data objects, `init_mm` or
`__tracepoint_sys_enter`.

The unused page-table walker, SELinux-hide object and module-blacklist
object are excluded. The read-only instruction scanner remains because
app-profile/seccomp compatibility uses it. The hide-only policy backup is
not allocated in this configuration.

SELinux modification hiding and module-blacklist mutation are unavailable
in this profile. Actual SELinux enforcement and KernelSU's normal root-policy
updates remain active. Registering kprobes still uses the kernel's supported
instrumentation machinery; this profile specifically avoids KernelSU's
manual fixmap/text-poke path.

## Build used for validation

The DDK image was pinned to:

```
ghcr.io/ylarod/ddk-min@sha256:51159bc935c75a282fc65bc87e02f16bd098d1cdf55dc558c4fdd0fcf7a132e2
```

It contains Android Clang 18.0.0 r510928, revision
`477610d4d0d988e69dbc3fae4fe86bff3f07f2b5`, matching the device's compiler
revision. With the checkout mounted at `/workspace`, the build was equivalent
to the following commands inside that image:

```sh
TARGET=6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
printf '%s\n' "$TARGET" > "$KDIR/include/config/kernel.release"
printf '#define UTS_RELEASE "%s"\n' "$TARGET" > "$KDIR/include/generated/utsrelease.h"
make -C "$KDIR" M=/workspace/kernel ARCH=arm64 LLVM=1 \
    CONFIG_KSU=m CONFIG_KSU_NO_TEXT_POKE=y CONFIG_KSU_SELF_RESOLVED_DATA=y \
    KSU_GIT_VERSION_VALID=1 KSU_GIT_VERSION=2680 GIT=/bin/false \
    KBUILD_MODPOST_WARN=1 KSU_NEW_DCACHE_FLUSH=1 -j2 modules
```

The explicit version settings reproduce the tested version code 32680
without a build-time history fetch. The resulting `__versions` section was
empty. The module layout and imports were checked independently against the
exact target; changing the release string alone is not an ABI validation.

## Pre-load function binding

The Linux loader resolves undefined imports before module init executes.
The module still needs pre-load binding for 50 private/protected function
imports. [The matched binder](../../tools/pd2454/README.md) validates the exact
profile and changes only those ELF symbol records using a trusted current-boot
KASLR slide. It does not rewrite instructions or kernel-data references.

Privilege acquisition and platform permissions required before insertion
belong to the external bootstrap. Once those prerequisites are established,
use the ordinary module loader with flags 0 and the matched module. The
validated runtime parameters included `allow_shell=1` for ADB diagnostics.
That option grants shell access and should be an intentional operator choice.

Bound images contain boot-specific addresses. Never reuse them after reboot,
force an incompatible module, or mix this module with an older instruction-
rewriting loader.

## Validation record

On the exact target above, one actual insertion succeeded after a prior
bootstrap reset which occurred before module insertion. Observed behavior:

- In-module data lookup completed; the kernel logged that live typed pointers
  were ready without facts snapshots.
- The driver reported version 32680, UAPI 5, LKM and late-load mode.
- Normal `su` and the debug root shell returned UID/GID 0 in `u:r:ksu:s0`.
- Manager used its original native library, received its driver handle and
  launched root shells. Its UI showed `Working [Jailbreak mode]` without a
  failed-root banner.
- SELinux remained enforcing. No temporary FD bridge or native-library
  overlay was used.
- The bound module reconstructed on the host matched the inserted image
  byte-for-byte.

Build and offline checks included:

- Clean self-data, previous no-text-poke-profile and ordinary-profile builds.
- 52 compiled structure sizes/offsets matching target BTF. The expected values
  are in [validated-layout.json](../../tools/pd2454/validated-layout.json).
- Import/address checks and verified init ordering: resolver, data binding,
  credential preparation, then hook initialization.
- Host tests for data-resolution failures, probe rollback, deferred work,
  module references and recursion prevention.
- Binder checks proving that only the intended symbol records changed, plus
  malformed-input and sanitizer mutation tests.

Run [the host tests](../../kernel/tests/compat/README.md) independently of a
phone. `kernel/tests/layout_audit.c` is a compile-only fixture; never add it
to the production module's object list.

This is one successful insertion on one exact firmware. Repeated cold-boot
reliability, other kernel versions, broader app-policy behavior and complete
external-bootstrap restoration are not established by these results. The
underlying platform text-poke hardening hypothesis was not confirmed with a
captured protected-write fault; the profile avoids that manual path.

## Attribution

The probe-fallback design follows the GPL Samsung RKP adaptation in
[Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads/blob/main/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch).
No Samsung credential/DEFEX code is included, and Samsung results are not
Vivo validation evidence. KernelSU and the retained scanner's original
copyright/license notices remain in their source files.
