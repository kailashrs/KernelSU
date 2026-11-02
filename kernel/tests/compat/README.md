# Compatibility-profile host tests

Run from the repository root with Clang, Python 3, and ASan/UBSan available:

```sh
kernel/tests/compat/run.sh
kernel/tests/compat/run.sh /path/to/unrelocated-self-data-module.ko
```

The first command compiles the real data resolver and probe-fallback sources against mocked kernel APIs. It covers failed resolution, alignment and offset checks, publication order, all probe-registration failure points, task-work failures, module references and nested-call handling.

The optional module argument also tests the production binder: exact symbol-record changes, unchanged instructions/sections, invalid metadata and CLI inputs, and sanitizer parser-mutation cases. The synthetic test slide is for offline checks only; the generated temporary modules must not be inserted into a kernel.

These are host logic/parser tests. They do not establish kernel concurrency behavior, ABI compatibility or hardware reliability. The compile-only `../layout_audit.c` fixture is separate and must never be linked into the production module.
