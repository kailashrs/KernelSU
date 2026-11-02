#!/bin/sh
# Host-only mocked kernel API tests. The external runner owns binder tests.
set -eu
if [ "$#" -ne 0 ]; then
    echo "usage: $0 (binder tests moved to pd2454-kernelsu-runner/tests/run.sh)" >&2
    exit 2
fi
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
compiler=${CC:-clang}
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/ksu-compat.XXXXXX")
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
for suite in data probe; do
    test_file=test_kernel_data.c
    [ "$suite" != probe ] || test_file=test_probe_fallback.c
    "$compiler" -O1 -g -fsanitize=address,undefined -Wall -Wextra -Wno-unused-parameter \
        -I"$repo_dir/kernel/tests/compat/$suite/stubs" -I"$repo_dir/kernel" \
        "$repo_dir/kernel/tests/compat/$suite/$test_file" -o "$test_dir/$suite"
    "$test_dir/$suite"
done
