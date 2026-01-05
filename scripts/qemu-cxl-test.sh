#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# QEMU CXL Unit Test Script
#
# Builds libcxlmi and a minimal initramfs, then runs unit tests
# against QEMU-emulated CXL Type3 devices using ioctl transport.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TIMEOUT=60
VERBOSE=""
SANITIZE=""
WORKDIR=""

usage() {
    cat <<EOF
Usage: $0 --kernel <bzImage> [options]

Required:
  -k, --kernel <path>     Path to kernel bzImage (with CXL support)

Options:
  -q, --qemu <path>       Path to QEMU binary (default: qemu-system-x86_64)
  -t, --timeout <secs>    Test timeout in seconds (default: 60)
  -v, --verbose           Pass verbose flag to unit tests
  -s, --sanitize          Build with AddressSanitizer (ASan)
  -h, --help              Show this help

Environment:
  QEMU_BIN                Alternative way to specify QEMU path

Example:
  $0 --kernel /boot/vmlinuz-\$(uname -r)
  QEMU_BIN=~/qemu/build/qemu-system-x86_64 $0 --kernel bzImage
EOF
    exit "${1:-1}"
}

cleanup() {
    [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ] && rm -rf "$WORKDIR"
}
trap cleanup EXIT

log() { echo "[*] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

check_requirements() {
    command -v "$QEMU_BIN" &>/dev/null || die "QEMU not found: $QEMU_BIN"
    command -v meson &>/dev/null || die "meson not found"
    [ -f "$KERNEL" ] || die "Kernel not found: $KERNEL"
    "$QEMU_BIN" -device help 2>&1 | grep -q "cxl-type3" || die "QEMU lacks CXL support"
}

build_libcxlmi() {
    log "Building libcxlmi..."
    local meson_opts="--default-library=static --prefer-static -Dlibdbus=disabled -Dtests=true"
    [ -n "$SANITIZE" ] && meson_opts="$meson_opts -Db_sanitize=address"
    meson setup "$WORKDIR/build" "$PROJECT_DIR" $meson_opts \
        > "$WORKDIR/meson.log" 2>&1 || { cat "$WORKDIR/meson.log"; die "Meson setup failed"; }
    meson compile -C "$WORKDIR/build" \
        >> "$WORKDIR/meson.log" 2>&1 || { cat "$WORKDIR/meson.log"; die "Build failed"; }
}

copy_binary_with_libs() {
    local binary="$1" destdir="$2" destbin="$3"
    cp "$binary" "$destdir/$destbin"
    chmod +x "$destdir/$destbin"
    ldd "$binary" 2>/dev/null | grep -oP '/[^ ]+' | while read -r lib; do
        [ -f "$lib" ] || continue
        mkdir -p "$destdir$(dirname "$lib")"
        [ -f "$destdir$lib" ] || cp "$lib" "$destdir$lib"
    done
}

create_initramfs() {
    log "Creating initramfs..."
    local initramfs_dir="$WORKDIR/initramfs"
    mkdir -p "$initramfs_dir"/{bin,dev,proc,sys,tmp,lib,lib64}

    # Compile and copy init
    gcc -O2 -Wall "$SCRIPT_DIR/qemu-init.c" -o "$WORKDIR/init" || die "Failed to compile init"
    copy_binary_with_libs "$WORKDIR/init" "$initramfs_dir" "init"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-generic" "$initramfs_dir" "bin/cxl-test-generic"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-memdev" "$initramfs_dir" "bin/cxl-test-memdev"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-fmapi" "$initramfs_dir" "bin/cxl-test-fmapi"

    # Minimal device nodes
    mknod -m 622 "$initramfs_dir/dev/console" c 5 1 2>/dev/null || true
    mknod -m 666 "$initramfs_dir/dev/null" c 1 3 2>/dev/null || true

    (cd "$initramfs_dir" && find . -print0 | cpio --null -o -H newc 2>/dev/null) | \
        gzip -9 > "$WORKDIR/initramfs.cpio.gz"
}

run_qemu() {
    log "Starting QEMU..."
    dd if=/dev/zero of="$WORKDIR/cxl-lsa.raw" bs=4k count=1 status=none
    dd if=/dev/zero of="$WORKDIR/cxl-pmem1.raw" bs=1M count=512 status=none

    local serial_log="$WORKDIR/serial.log"
    local append_opts="console=ttyS0 panic=-1 rdinit=/init"
    [ -n "$VERBOSE" ] && append_opts="$append_opts cxlmi_test.verbose=1"
    [ -n "$SANITIZE" ] && append_opts="$append_opts cxlmi_test.sanitize=1"

    set +e
    set -o pipefail
    timeout --foreground "$TIMEOUT" stdbuf -oL "$QEMU_BIN" \
        -machine q35,accel=kvm,cxl=on -m 2G -smp 2 -cpu host \
        -nographic -no-reboot -monitor none \
        -kernel "$KERNEL" \
        -initrd "$WORKDIR/initramfs.cpio.gz" \
        -append "$append_opts" \
        -object memory-backend-ram,id=cxl-vmem1,size=256M \
        -object "memory-backend-file,id=cxl-pmem1,share=on,mem-path=$WORKDIR/cxl-pmem1.raw,size=512M" \
        -object "memory-backend-file,id=cxl-lsa,share=on,mem-path=$WORKDIR/cxl-lsa.raw,size=4k" \
        -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1 \
        -device cxl-rp,port=0,bus=cxl.1,id=root_port0,chassis=0,slot=2 \
        -device cxl-rp,port=1,bus=cxl.1,id=root_port1,chassis=0,slot=3 \
        -device cxl-type3,bus=root_port0,volatile-memdev=cxl-vmem1,id=cxl-vmem0,sn=0xDEADBEEF \
        -device cxl-type3,bus=root_port1,persistent-memdev=cxl-pmem1,lsa=cxl-lsa,id=cxl-pmem0,sn=0xCAFEBABE \
        -M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G \
        -serial stdio 2>&1 | stdbuf -oL tee "$serial_log"
    local rc=${PIPESTATUS[0]}
    set +o pipefail
    set -e

    [ $rc -eq 124 ] && log "QEMU timed out after ${TIMEOUT}s"
    echo ""

    if grep -q "TEST_RESULT=PASS" "$serial_log" 2>/dev/null; then
        log "=== TESTS PASSED ==="; return 0
    elif grep -q "TEST_RESULT=FAIL" "$serial_log" 2>/dev/null; then
        log "=== TESTS FAILED ==="; return 1
    else
        log "=== TESTS INCONCLUSIVE ==="; return 1
    fi
}

# Parse arguments
KERNEL=""
while [ $# -gt 0 ]; do
    case "$1" in
        -k|--kernel) KERNEL="$2"; shift 2 ;;
        -q|--qemu) QEMU_BIN="$2"; shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -v|--verbose) VERBOSE="1"; shift ;;
        -s|--sanitize) SANITIZE="1"; shift ;;
        -h|--help) usage 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done
[ -z "$KERNEL" ] && usage

WORKDIR=$(mktemp -d -t libcxlmi-qemu-test.XXXXXX)
check_requirements
build_libcxlmi
create_initramfs
run_qemu
