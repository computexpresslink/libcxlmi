#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
# Install a configured build into a temporary DESTDIR and check that
# programs can be built against the installed headers and library:
#   - every installed header compiles on its own, as C and as C++
#   - a program using the API links via pkg-config and runs
#   - an application with its own "log.h" can include <libcxlmi.h>
#     in either order
#
# Usage: scripts/check-install.sh <builddir>

set -eu

builddir=${1:?usage: $0 <builddir>}
cc=${CC:-cc}
cxx=${CXX:-c++}

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
dest="$tmp/dest"

meson install -C "$builddir" --destdir "$dest" --quiet

pcfile=$(find "$dest" -name libcxlmi.pc | head -n 1)
if [ -z "$pcfile" ]; then
	echo "libcxlmi.pc was not installed" >&2
	exit 1
fi

# The .pc file names the real prefix; point it into DESTDIR instead.
PKG_CONFIG_PATH=$(dirname "$pcfile")${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
export PKG_CONFIG_PATH
prefix=$(pkg-config --variable=prefix libcxlmi)
pc() { pkg-config --define-variable=prefix="$dest$prefix" "$@" libcxlmi; }

cflags=$(pc --cflags)
libs=$(pc --libs)
incdir=$(pc --variable=includedir)
libdir=$(pc --variable=libdir)

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

# Each installed header must be self-contained.
for hdr in $(cd "$incdir" && find . -name '*.h' | sed 's|^\./||' | sort); do
	printf '#include <%s>\n' "$hdr" >"$tmp/hdr.c"
	check "C   header $hdr" \
		"$cc" -Wall -Werror $cflags -fsyntax-only "$tmp/hdr.c"
	if command -v "$cxx" >/dev/null 2>&1; then
		check "C++ header $hdr" \
			"$cxx" -Wall -Werror $cflags -fsyntax-only -x c++ "$tmp/hdr.c"
	fi
done

cat >"$tmp/consumer.c" <<'EOF'
#include <libcxlmi.h>

int main(void)
{
	struct cxlmi_ctx *ctx;

	ctx = cxlmi_new_ctx(stderr, DEFAULT_LOGLEVEL);
	if (!ctx)
		return 1;
	cxlmi_free_ctx(ctx);
	return 0;
}
EOF
check "link and run a program via pkg-config" \
	sh -c '"$1" -Wall -Werror $2 "$3" -o "$4" $5 &&
	       LD_LIBRARY_PATH="$6" "$4"' \
	sh "$cc" "$cflags" "$tmp/consumer.c" "$tmp/consumer" "$libs" "$libdir"

# Applications commonly have their own log.h; the library's must not
# collide with it whichever comes first.
mkdir -p "$tmp/app"
cat >"$tmp/app/log.h" <<'EOF'
#ifndef _LOG_H
#define _LOG_H
void app_log(const char *msg);
#endif
EOF
cat >"$tmp/app/first.c" <<'EOF'
#include "log.h"
#include <libcxlmi.h>
void f(void) { app_log("x"); (void)cxlmi_new_ctx(stderr, DEFAULT_LOGLEVEL); }
EOF
cat >"$tmp/app/second.c" <<'EOF'
#include <libcxlmi.h>
#include "log.h"
void f(void) { app_log("x"); (void)cxlmi_new_ctx(stderr, DEFAULT_LOGLEVEL); }
EOF
for order in first second; do
	check "app log.h included $order" \
		"$cc" -Wall -Werror -I"$tmp/app" $cflags -fsyntax-only \
		"$tmp/app/$order.c"
done

exit $fail
