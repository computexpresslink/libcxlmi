#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# QEMU CXL MCTP Unit Test Script
#
# Builds libcxlmi and a minimal initramfs, then runs unit tests
# against QEMU-emulated CXL devices using MCTP over I2C transport.
#
# This script creates a CXL switch topology with:
# - CXL switch with mailbox CCI exposed via i2c_mctp_cxl
# - Type3 SLD devices exposed via i2c_mctp_cxl
# - aspeed-i2c controller for MCTP I2C transport
#
# Based on cxl-fmapi-tests configuration:
# https://gitlab.com/jic23/cxl-fmapi-tests
#
# Requirements:
# - QEMU with CXL switch and i2c_mctp_cxl device support
# - Kernel with MCTP I2C transport and aspeed-i2c support
#   (may require patches for ACPI-based aspeed-i2c)
# - mctp-tools (mctp, mctpd) for MCTP network configuration
#
# Note: The aspeed-i2c driver may need modifications:
# - Comment out clock configuration
# - Make reset optional
# See: https://gitlab.com/jic23/cxl-fmapi-tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
TIMEOUT=120
VERBOSE=""
SANITIZE=""
WORKDIR=""

# MCTP configuration
# Note: EIDs are assigned dynamically by mctpd/busctl
# These are the expected EIDs after AssignEndpoint calls
MCTP_NET=11
MCTP_LOCAL_EID=50
SWITCH_I2C_ADDR=0x4     # I2C address for switch MCTP CCI
SWITCH_EID=8            # EID assigned to switch
TYPE3_1_I2C_ADDR=0x5    # I2C address for first Type3 device
TYPE3_1_EID=9           # EID assigned to first Type3
TYPE3_2_I2C_ADDR=0x6    # I2C address for second Type3 device
TYPE3_2_EID=10          # EID assigned to second Type3

usage() {
    cat <<EOF
Usage: $0 --kernel <bzImage> [options]

Required:
  -k, --kernel <path>     Path to kernel bzImage (with CXL and MCTP support)

Options:
  -q, --qemu <path>       Path to QEMU binary (default: qemu-system-x86_64)
  -t, --timeout <secs>    Test timeout in seconds (default: 120)
  -v, --verbose           Pass verbose flag to unit tests
  -s, --sanitize          Build with AddressSanitizer (ASan)
  -h, --help              Show this help

Environment:
  QEMU_BIN                Alternative way to specify QEMU path

Kernel Requirements:
  CONFIG_MCTP=y
  CONFIG_MCTP_TRANSPORT_I2C=y
  CONFIG_I2C_ASPEED=y (may require patches for ACPI support)

QEMU Requirements:
  - CXL switch support (cxl-upstream, cxl-downstream)
  - i2c_mctp_cxl device support
  - aspeed-i2c controller emulation

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
    "$QEMU_BIN" -device help 2>&1 | grep -q "cxl-upstream" || die "QEMU lacks CXL switch support"
    "$QEMU_BIN" -device help 2>&1 | grep -q "i2c_mctp_cxl" || die "QEMU lacks i2c_mctp_cxl device (required for MCTP testing)"
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
    mkdir -p "$initramfs_dir"/{bin,dev,proc,sys,lib,lib64,etc,run,var/run,tmp}

    # Compile and copy init
    gcc -O2 -Wall -DMCTP_TEST "$SCRIPT_DIR/qemu-init.c" -o "$WORKDIR/init" || die "Failed to compile init"
    copy_binary_with_libs "$WORKDIR/init" "$initramfs_dir" "init"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-generic" "$initramfs_dir" "bin/cxl-test-generic"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-memdev" "$initramfs_dir" "bin/cxl-test-memdev"
    copy_binary_with_libs "$WORKDIR/build/tests/cxl-test-fmapi" "$initramfs_dir" "bin/cxl-test-fmapi"

    # Copy mctp tools and dbus if available
    # Check standard paths and /usr/local/sbin for mctpd
    for tool in mctp mctpd busctl dbus-daemon sh dd; do
        local tool_path=""
        tool_path=$(command -v "$tool" 2>/dev/null) || true
        if [ -z "$tool_path" ]; then
            # Tool not in PATH, check common locations
            for p in /usr/local/sbin/$tool /usr/sbin/$tool /usr/local/bin/$tool; do
                if [ -x "$p" ]; then
                    tool_path="$p"
                    break
                fi
            done
        fi
        [ -z "$tool_path" ] && continue
        copy_binary_with_libs "$tool_path" "$initramfs_dir" "bin/$tool"
    done

    # Check if mctp tools were found
    if [ ! -f "$initramfs_dir/bin/mctp" ]; then
        log "Warning: mctp tool not found, MCTP tests may fail"
    else
        log "Found mctp tool"
    fi
    if [ ! -f "$initramfs_dir/bin/mctpd" ]; then
        log "Warning: mctpd not found, MCTP endpoint assignment may fail"
    else
        log "Found mctpd"
    fi
    if [ ! -f "$initramfs_dir/bin/dbus-daemon" ]; then
        log "Warning: dbus-daemon not found, mctpd may not work"
    fi

    # Copy dbus configuration if dbus-daemon is present
    if [ -f "$initramfs_dir/bin/dbus-daemon" ]; then
        mkdir -p "$initramfs_dir/etc/dbus-1"
        mkdir -p "$initramfs_dir/usr/share/dbus-1/system-services"
        mkdir -p "$initramfs_dir/usr/share/dbus-1/system.d"

        # Create minimal passwd/group files for dbus
        cat > "$initramfs_dir/etc/passwd" <<'PASSWD'
root:x:0:0:root:/root:/bin/sh
messagebus:x:106:110::/nonexistent:/usr/sbin/nologin
PASSWD
        cat > "$initramfs_dir/etc/group" <<'GROUP'
root:x:0:
messagebus:x:110:
GROUP

        # Create a minimal dbus system config that works in initramfs
        cat > "$initramfs_dir/usr/share/dbus-1/system.conf" <<'DBUSCONF'
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <fork/>
  <pidfile>/run/dbus/pid</pidfile>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="method_return"/>
    <allow send_type="error"/>
    <allow send_type="signal"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>
DBUSCONF
    fi

    # Minimal device nodes
    mknod -m 622 "$initramfs_dir/dev/console" c 5 1 2>/dev/null || true
    mknod -m 666 "$initramfs_dir/dev/null" c 1 3 2>/dev/null || true

    # Create MCTP configuration file for init
    cat > "$initramfs_dir/etc/mctp.conf" <<MCTP_CONF
# MCTP test configuration
MCTP_NET=$MCTP_NET
MCTP_LOCAL_EID=$MCTP_LOCAL_EID
SWITCH_I2C_ADDR=$SWITCH_I2C_ADDR
SWITCH_EID=$SWITCH_EID
TYPE3_1_I2C_ADDR=$TYPE3_1_I2C_ADDR
TYPE3_1_EID=$TYPE3_1_EID
TYPE3_2_I2C_ADDR=$TYPE3_2_I2C_ADDR
TYPE3_2_EID=$TYPE3_2_EID
MCTP_CONF

    (cd "$initramfs_dir" && find . -print0 | cpio --null -o -H newc 2>/dev/null) | \
        gzip -9 > "$WORKDIR/initramfs.cpio.gz"
}

run_qemu() {
    log "Starting QEMU with CXL switch topology and MCTP I2C..."

    # Create sparse memory backing files
    truncate -s 1M "$WORKDIR/cxl-lsa1.raw"
    truncate -s 1M "$WORKDIR/cxl-lsa2.raw"
    truncate -s 256M "$WORKDIR/cxl-mem1.raw"
    truncate -s 512M "$WORKDIR/cxl-mem2.raw"

    local serial_log="$WORKDIR/serial.log"
    local append_opts="console=ttyS0 panic=-1 rdinit=/init cxlmi_test.mctp=1"
    [ -n "$VERBOSE" ] && append_opts="$append_opts cxlmi_test.verbose=1"
    [ -n "$SANITIZE" ] && append_opts="$append_opts cxlmi_test.sanitize=1"

    # Add MCTP endpoint information for tests
    append_opts="$append_opts cxlmi_test.mctp_net=$MCTP_NET"
    append_opts="$append_opts cxlmi_test.switch_eid=$SWITCH_EID"
    append_opts="$append_opts cxlmi_test.type3_1_eid=$TYPE3_1_EID"
    append_opts="$append_opts cxlmi_test.type3_2_eid=$TYPE3_2_EID"
    append_opts="$append_opts cxlmi_test.switch_i2c_addr=$SWITCH_I2C_ADDR"
    append_opts="$append_opts cxlmi_test.type3_1_i2c_addr=$TYPE3_1_I2C_ADDR"
    append_opts="$append_opts cxlmi_test.type3_2_i2c_addr=$TYPE3_2_I2C_ADDR"

    set +e
    set -o pipefail

    # QEMU topology:
    # - pxb-cxl (CXL host bridge)
    #   - cxl-rp (root port)
    #     - cxl-upstream (switch upstream port)
    #       - cxl-downstream port 0 -> cxl-type3 (cxl-pmem1, Type3 SLD)
    #       - cxl-downstream port 1 -> virtio-rng (placeholder, not CXL)
    #       - cxl-downstream port 2 -> cxl-type3 (cxl-pmem2, Type3 SLD)
    # - aspeed.i2c.bus.0 (I2C bus for MCTP transport)
    #   - i2c_mctp_cxl at address 0x4 -> us0 (switch, EID 8)
    #   - i2c_mctp_cxl at address 0x5 -> cxl-pmem1 (Type3 device 1, EID 9)
    #   - i2c_mctp_cxl at address 0x6 -> cxl-pmem2 (Type3 device 2, EID 10)
    #
    # Note: This topology requires QEMU with CXL switch and i2c_mctp_cxl support.
    # The aspeed-i2c controller provides MCTP I2C transport.
    # Kernel needs CONFIG_I2C_ASPEED with ACPI support patches.

    timeout --foreground "$TIMEOUT" stdbuf -oL "$QEMU_BIN" \
        -machine q35,accel=kvm,cxl=on -m 2G -smp 4 -cpu host \
        -nographic -no-reboot -monitor none \
        -kernel "$KERNEL" \
        -initrd "$WORKDIR/initramfs.cpio.gz" \
        -append "$append_opts" \
        -object memory-backend-file,id=cxl-mem1,mem-path="$WORKDIR/cxl-mem1.raw",size=256M \
        -object memory-backend-file,id=cxl-mem2,mem-path="$WORKDIR/cxl-mem2.raw",size=512M \
        -object memory-backend-file,id=cxl-lsa1,mem-path="$WORKDIR/cxl-lsa1.raw",size=1M \
        -object memory-backend-file,id=cxl-lsa2,mem-path="$WORKDIR/cxl-lsa2.raw",size=1M \
        -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
        -device cxl-rp,port=0,bus=cxl.1,id=cxl_rp_port0,chassis=0,slot=2 \
        -device cxl-upstream,port=2,sn=1234,bus=cxl_rp_port0,id=us0,addr=0.0,multifunction=on, \
        -device cxl-switch-mailbox-cci,bus=cxl_rp_port0,addr=0.1,target=us0 \
        -device cxl-downstream,port=0,bus=us0,id=swport0,chassis=0,slot=4 \
        -device cxl-downstream,port=1,bus=us0,id=swport1,chassis=0,slot=5 \
        -device cxl-downstream,port=2,bus=us0,id=swport2,chassis=0,slot=6 \
        -device cxl-type3,bus=swport0,memdev=cxl-mem1,id=cxl-pmem1,lsa=cxl-lsa1,sn=3 \
        -device cxl-type3,bus=swport2,memdev=cxl-mem2,id=cxl-pmem2,lsa=cxl-lsa2,sn=4 \
        -device virtio-rng-pci,bus=swport1 \
        -machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=1k \
        -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=$SWITCH_I2C_ADDR,target=us0 \
        -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=$TYPE3_1_I2C_ADDR,target=cxl-pmem1 \
        -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=$TYPE3_2_I2C_ADDR,target=cxl-pmem2 \
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

WORKDIR=$(mktemp -d -t libcxlmi-mctp-test.XXXXXX)
check_requirements
build_libcxlmi
create_initramfs
run_qemu
