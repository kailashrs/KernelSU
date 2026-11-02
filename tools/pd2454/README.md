# PD2454 function-symbol binder

`ksupatch.c` binds 50 private/protected function imports for the exact validated Vivo kernel:

```
6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
```

Build for the host or Android/AArch64 with the appropriate compiler:

```sh
clang -O2 -Wall -Wextra tools/pd2454/ksupatch.c -o ksupatch
```

Invocation:

```sh
ksupatch <current-boot-slide-hex> <unrelocated-self-data-module.ko> <output.ko>
```

It requires both `ksu_no_text_poke=1` and `ksu_self_resolved_data=1` metadata and exact target vermagic. It checks the module layout and safe initialization profile, rejects remaining private-data dependencies, and changes only function-symbol records. No instruction rewriting, facts file, section resizing, init stubbing or force-loading is performed.

The supplied slide must come from a trusted same-boot bootstrap. Output contains boot-specific addresses and must never be reused after reboot. The ordinary Linux module loader is still needed, with the required privileges and platform pre-load permissions already established.

Use the matched self-data kernel profile described in [the compatibility notes](../../docs/compat/pd2454-no-text-poke.md). The address table and ABI checks are target-specific; this is not a generic module loader.
