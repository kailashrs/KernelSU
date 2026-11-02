# PD2454 ABI reference

[validated-layout.json](validated-layout.json) contains the 52 target-BTF
layout values used to audit the compile-only `kernel/tests/layout_audit.c`
fixture for the exact validated kernel:

```
6.6.127-android15-8-g3b723d0e8507-abogki558056638-4k
```

The function-symbol binder (`ksupatch.c`), build instructions and binder
failure-path tests are maintained exclusively in the separate
[PD2454 runner repository](https://github.com/kailashrs/pd2454-kernelsu-runner).
No binder source or binder test copy is maintained in this repository.

See [the kernel compatibility notes](../../docs/compat/pd2454-no-text-poke.md)
for the matched module profile and ABI validation limits.
