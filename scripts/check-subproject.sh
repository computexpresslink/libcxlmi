#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
# Check that libcxlmi can be used as a meson subproject, the way a project
# that does not rely on an installed copy would: create a small parent
# project with strict warnings, in C and in C++, that gets libcxlmi through
# dependency('libcxlmi') and a wrap file, then build and run it.
#
# Usage: scripts/check-subproject.sh [meson setup options for the parent]

set -eu

srcdir=$(cd "$(dirname "$0")/.." && pwd)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/parent/subprojects"
ln -s "$srcdir" "$tmp/parent/subprojects/libcxlmi"

# What a parent project carries to name the subproject's dependency.
cat >"$tmp/parent/subprojects/libcxlmi.wrap" <<'WRAP'
[wrap-file]
directory = libcxlmi

[provide]
dependency_names = libcxlmi
WRAP

cat >"$tmp/parent/meson.build" <<'MESON'
project('parent', ['c', 'cpp'],
    default_options: [
        'warning_level=3',
        'werror=true',
        'c_std=gnu11',
        'cpp_std=c++20',
    ],
)

libcxlmi_dep = dependency('libcxlmi')

test('c', executable('consumer-c', 'consumer.c',
    dependencies: libcxlmi_dep))
test('cpp', executable('consumer-cpp', 'consumer.cpp',
    dependencies: libcxlmi_dep))
MESON

cat >"$tmp/parent/consumer.c" <<'C'
#include <libcxlmi.h>

int main(void)
{
	/* a payload structure that ends in a flexible array */
	struct cxlmi_cmd_get_supported_logs_rsp *logs = NULL;
	struct cxlmi_ctx *ctx;

	ctx = cxlmi_new_ctx(stderr, DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;
	cxlmi_free_ctx(ctx);
	return logs ? logs->num_supported_log_entries : 0;
}
C
cp "$tmp/parent/consumer.c" "$tmp/parent/consumer.cpp"

fail=0
check() {
	desc=$1; shift
	if "$@" >"$tmp/out" 2>&1; then
		echo "ok   $desc"
	else
		echo "FAIL $desc"
		sed 's/^/     /' "$tmp/out"
		fail=1
	fi
}

# Use the subproject even where a libcxlmi is installed.
check "configure a parent project" \
	meson setup "$tmp/build" "$tmp/parent" \
		--force-fallback-for=libcxlmi "$@"
check "build it in C and C++ with warning_level=3 and werror" \
	meson compile -C "$tmp/build"
check "run it" \
	meson test -C "$tmp/build" --print-errorlogs

# The parent gets the library, not libcxlmi's own tests and examples.
check "the library is built for the parent" \
	sh -c 'meson introspect --targets "$1" | grep -q "\"name\": \"cxlmi\""' \
	sh "$tmp/build"
check "its tests and examples are not" \
	sh -c '! meson introspect --targets "$1" |
	       grep -E "\"name\": \"(mock-tests|cxl-mctp|cxl-test-[a-z]+)\""' \
	sh "$tmp/build"

exit $fail
