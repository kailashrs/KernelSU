# Compatibility-profile host tests

Run from the repository root with Clang and ASan/UBSan available:

```sh
kernel/tests/compat/run.sh
```

The command compiles the real data resolver and probe-fallback sources against mocked kernel APIs. It covers failed resolution, alignment and offset checks, publication order, all probe-registration failure points, task-work failures, module references and nested-call handling.

The function-symbol binder and its tests live in the separate [runner repository](https://github.com/kailashrs/pd2454-kernelsu-runner). Run `tests/run.sh /path/to/unrelocated-self-data-module.ko` there for symbol-record, instruction-preservation, malformed-input and sanitizer checks. The synthetic slide is for offline tests only; never insert those generated modules.

These are host logic/parser tests. They do not establish kernel concurrency behavior, ABI compatibility or hardware reliability. The compile-only `../layout_audit.c` fixture is separate and must never be linked into the production module.
