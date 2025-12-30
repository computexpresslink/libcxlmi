# Testing Infrastructure

libcxlmi provides a comprehensive testing infrastructure that supports multiple
testing approaches:

- **Mock Transport Tests** - Unit tests using a simulated device (no hardware required)
- **Hardware Unit Tests** - Command set tests against real CXL devices or QEMU emulation
- **QEMU Unit Tests (ioctl)** - Automated testing using QEMU CXL Type3 device emulation via kernel ioctl
- **QEMU Unit Tests (MCTP)** - Automated testing using QEMU CXL switch topology with MCTP over I2C transport

This document covers all testing approaches and how to use them effectively.

---

## Table of Contents

1. [Hardware Unit Tests](#hardware-unit-tests)
   - [Overview](#overview)
   - [Test Programs](#test-programs)
   - [Transport Options](#transport-options)
   - [Running on Bare Metal](#running-on-bare-metal)
   - [Running with QEMU (ioctl)](#running-with-qemu)
   - [Running with QEMU (MCTP)](#running-with-qemu-mctp)
2. [Mock Device Testing](#mock-device-testing-infrastructure)
3. [Code Coverage](#code-coverage)
4. [Adding New Tests](#adding-new-tests)

---

## Hardware Unit Tests

### Overview

The hardware unit tests exercise CXL commands against real devices (or QEMU-emulated
devices). These tests verify that the library correctly communicates with actual
CXL hardware using the proper command encoding, transport handling, and response
parsing.

Three test programs cover the major CXL command sets:

| Test Program | Command Set | CXL Spec Reference |
|--------------|-------------|-------------------|
| `cxl-test-generic` | Generic Component Commands | CXL r3.1 Section 8.2.9.1 |
| `cxl-test-memdev` | Memory Device Commands | CXL r3.1 Section 8.2.9.9 |
| `cxl-test-fmapi` | FM-API Commands | CXL r3.1 Section 7.6 |

### Test Programs

#### Generic Command Set Tests (`cxl-test-generic`)

Tests 27 generic CXL commands including:

- **Device Info**: identify, background operation status, response message limit
- **Events**: get/clear event records, event interrupt policy, event notification
- **Firmware**: get FW info, transfer FW, activate FW
- **Logs**: get supported logs, get log, CEL, log capabilities, clear/populate log
- **Features**: get supported features, get/set feature
- **Timestamp**: get/set timestamp

#### Memory Device Command Set Tests (`cxl-test-memdev`)

Tests 35 memory device commands including:

- **Identity/Capacity**: identify, partition info
- **Label Storage Area**: get/set LSA
- **Health**: health info, alert config, shutdown state
- **Media**: poison list, inject/clear poison, scan media
- **Sanitize**: sanitize, secure erase
- **Dynamic Capacity**: DCD config, extent list, add/release DC
- **Security**: get security state, passphrase operations, freeze security

#### FM-API Command Set Tests (`cxl-test-fmapi`)

Tests 34 Fabric Manager API commands including:

- **Physical Switch**: identify switch, physical port state/control
- **Virtual Switch**: get/bind/unbind vPPB
- **MLD Port**: tunnel management command, MLD port operations
- **Multi-headed Device**: get MHD info
- **Dynamic Capacity**: DCD info, region config, DC operations

### Transport Options

All test programs support two transport mechanisms:

#### Tunneling Options

All test programs support tunneling options for sending commands through CXL
switches to downstream devices or to specific Logical Devices (LDs) within
Multi-Logical Devices (MLDs):

| Option | Description | Tunnel Type |
|--------|-------------|-------------|
| (none) | Direct command to target device | No tunneling |
| `-p <port>` | Tunnel through switch to FM-owned LD | Level 1 (`DEFINE_CXLMI_TUNNEL_SWITCH`) |
| `-l <ld>` | Tunnel to specific LD in MLD | Level 1 (`DEFINE_CXLMI_TUNNEL_MLD`) |
| `-p <port> -l <ld>` | Tunnel through switch to LD in MLD | Level 2 (`DEFINE_CXLMI_TUNNEL_SWITCH_MLD`) |
| `-m` | Tunnel to MHD LD Pool CCI | Level 1 (`DEFINE_CXLMI_TUNNEL_MHD`) |

**Examples:**

```bash
# Direct command to switch (no tunneling)
./build/tests/cxl-test-fmapi mctp:11,8

# Tunnel through switch port 0 to downstream device (FM-owned LD)
./build/tests/cxl-test-generic mctp:11,8 -p 0

# Tunnel to LD 1 in an MLD
./build/tests/cxl-test-memdev mctp:11,9 -l 1

# Two-level tunnel: through switch port 0 to LD 1 in downstream MLD
./build/tests/cxl-test-memdev mctp:11,8 -p 0 -l 1

# Tunnel to MHD LD Pool CCI
./build/tests/cxl-test-fmapi mctp:11,8 -m
```

**Notes:**
- When no tunneling options are specified, commands are sent directly to the target
- The tunneling level is automatically determined by the combination of options
- FM-API switch commands (like `identify_sw_device`) should typically run without
  tunneling against the switch CCI directly
- MLD component commands require tunneling to reach the MLD device

#### ioctl Transport (Kernel Interface)

Uses the Linux kernel's CXL driver interface (`/dev/cxl/memX`). This is the
standard method for communicating with CXL devices on Linux.

```bash
# Run against a memory device
./build/tests/cxl-test-generic mem0
./build/tests/cxl-test-memdev mem0
```

**Requirements:**
- Linux kernel with CXL support (`CONFIG_CXL_BUS`, `CONFIG_CXL_PCI`, `CONFIG_CXL_MEM`)
- Raw commands enabled (`CONFIG_CXL_MEM_RAW_COMMANDS=y`)
- Read/write access to `/dev/cxl/memX`

#### MCTP Transport (Management Component Transport Protocol)

Uses MCTP over PCIe VDM or SMBus for out-of-band management. This enables
communication with CXL devices without kernel driver involvement.

```bash
# Run against an MCTP endpoint
./build/tests/cxl-test-generic mctp:1,0x1a
./build/tests/cxl-test-memdev mctp:1,0x50
```

**Target format:** `mctp:<network-id>,<endpoint-id>`

**Requirements:**
- MCTP infrastructure (mctp kernel module or user-space daemon)
- Network connectivity to the CXL device's management controller

### Running on Bare Metal

For testing against physical CXL hardware:

1. **Build the test programs:**

```bash
meson setup build
meson compile -C build
```

2. **Identify your CXL devices:**

```bash
ls /dev/cxl/
# Output: mem0  mem1  ...
```

3. **Run tests against a device:**

```bash
# Generic command set
sudo ./build/tests/cxl-test-generic mem0

# Memory device command set
sudo ./build/tests/cxl-test-memdev mem0

# FM-API (requires FM-capable device or switch)
sudo ./build/tests/cxl-test-fmapi mem0
```

4. **Interpret results:**

```
========================================
  libcxlmi Generic Command Set Tests
========================================
Target: mem0
  [PASS] identify
  [PASS] bg_op_status
  [SKIP] get_response_msg_limit: not supported
  [PASS] get_event_records
  ...

========================================
  Results: 15 passed, 0 failed, 12 skipped
========================================
```

- **PASS**: Command succeeded and returned valid data
- **FAIL**: Command failed unexpectedly
- **SKIP**: Command not supported by device (expected for many optional commands)

### Running with QEMU

QEMU provides CXL Type3 device emulation, enabling testing without physical
hardware. This is ideal for development, CI/CD pipelines, and testing edge cases.

The test configuration includes two CXL Type3 devices with different characteristics:
- **Volatile memory device** (`mem0`) - 256 MB RAM-backed, no LSA, serial 0xDEADBEEF
- **Persistent memory device** (`mem1`) - 512 MB file-backed, 4 KB LSA, serial 0xCAFEBABE

Tests are run against both devices automatically, allowing verification of behavior
differences between volatile and persistent memory types.

#### Prerequisites

1. **QEMU with CXL support** (version 8.0+ or built from source):

```bash
# Check QEMU version
qemu-system-x86_64 --version

# Verify CXL device support
qemu-system-x86_64 -device help | grep cxl
```

2. **Linux kernel with CXL support:**

Required kernel config options:
```
CONFIG_CXL_BUS=y
CONFIG_CXL_PCI=y
CONFIG_CXL_ACPI=y
CONFIG_CXL_MEM=y
CONFIG_CXL_MEM_RAW_COMMANDS=y
```

#### Automated QEMU Testing

The `scripts/qemu-cxl-test.sh` script automates the entire test process:

```bash
# Basic usage
./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage

# With custom QEMU binary
QEMU_BIN=~/qemu/build/qemu-system-x86_64 \
    ./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage

# With custom timeout (default: 60 seconds)
./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage --timeout 120

# With verbose output (shows detailed command responses)
./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage --verbose

# With AddressSanitizer enabled (detects memory errors)
./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage --sanitize

# Combined options
./scripts/qemu-cxl-test.sh --kernel /path/to/bzImage -v -s
```

**Script Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--kernel <path>` | `-k` | Path to kernel bzImage (required) |
| `--qemu <path>` | `-q` | Path to QEMU binary |
| `--timeout <secs>` | `-t` | Test timeout in seconds (default: 60) |
| `--verbose` | `-v` | Enable verbose output showing command response details |
| `--sanitize` | `-s` | Build with AddressSanitizer to detect memory errors |
| `--help` | `-h` | Show help message |

**What the script does:**

1. Creates a minimal initramfs with the test binaries
2. Launches QEMU with a CXL Type3 device configuration
3. Boots the kernel and runs the test suite
4. Reports results and exits with appropriate status

**Example output:**

```
[*] Building libcxlmi...
[*] Creating initramfs...
[*] Starting QEMU...

========================================
  libcxlmi Generic Command Set Tests
========================================
Target: mem0
  [PASS] identify
  [PASS] bg_op_status
  ...

========================================
  Results: 12 passed, 0 failed, 15 skipped
========================================

[*] === TESTS PASSED ===
```

**Example verbose output (`-v`):**

```
  [PASS] identify
           vendor_id: 0x1b36
           device_id: 0x0001
           serial_number: 0xdeadbeef
           total_capacity: 256 MB
           volatile_capacity: 256 MB
           persistent_capacity: 0 MB
  [PASS] bg_op_status
           status: 0x00
           opcode: 0x0000
           percent_complete: 0
```

#### AddressSanitizer Testing

The `--sanitize` option builds the test binaries with AddressSanitizer (ASan),
which detects memory errors at runtime:

- Buffer overflows (stack and heap)
- Use-after-free errors
- Double-free errors
- Memory leaks (disabled in QEMU tests due to minimal init environment)

When ASan detects an error, it prints a detailed report with stack traces:

```
==123==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...
READ of size 4 at 0x... thread T0
    #0 0x... in function_name file.c:123
    #1 0x... in caller_function file.c:456
    ...
```

This is invaluable for catching memory corruption bugs that might otherwise
go unnoticed or cause intermittent failures.

#### Manual QEMU Testing

For more control, you can run QEMU manually:

```bash
# Create backing files for CXL devices
truncate -s 4K /tmp/cxl-lsa.raw       # LSA for persistent device only
truncate -s 512M /tmp/cxl-pmem1.raw   # Persistent memory backing

# Launch QEMU with two CXL Type3 devices (volatile + persistent)
qemu-system-x86_64 \
    -machine q35,accel=kvm,cxl=on \
    -m 2G -smp 2 -cpu host \
    -kernel /path/to/bzImage \
    -append "console=ttyS0 panic=-1" \
    -initrd /path/to/initramfs.cpio.gz \
    -object memory-backend-ram,id=cxl-vmem1,size=256M \
    -object memory-backend-file,id=cxl-pmem1,share=on,mem-path=/tmp/cxl-pmem1.raw,size=512M \
    -object memory-backend-file,id=cxl-lsa,share=on,mem-path=/tmp/cxl-lsa.raw,size=4K \
    -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1 \
    -device cxl-rp,port=0,bus=cxl.1,id=root_port0,chassis=0,slot=2 \
    -device cxl-rp,port=1,bus=cxl.1,id=root_port1,chassis=0,slot=3 \
    -device cxl-type3,bus=root_port0,volatile-memdev=cxl-vmem1,id=cxl-vmem0,sn=0xDEADBEEF \
    -device cxl-type3,bus=root_port1,persistent-memdev=cxl-pmem1,lsa=cxl-lsa,id=cxl-pmem0,sn=0xCAFEBABE \
    -M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G \
    -nographic -no-reboot
```

**QEMU Device Configuration:**

| Device | Type | Size | Serial Number | LSA |
|--------|------|------|---------------|-----|
| cxl-vmem0 (mem0) | Volatile | 256 MB | 0xDEADBEEF | None |
| cxl-pmem0 (mem1) | Persistent | 512 MB | 0xCAFEBABE | 4 KB |

Then run tests inside the VM against both devices:

```bash
# Test volatile memory device
./cxl-test-generic mem0
./cxl-test-memdev mem0

# Test persistent memory device
./cxl-test-generic mem1
./cxl-test-memdev mem1
```

#### QEMU Device Capabilities

The QEMU CXL Type3 emulation supports many but not all CXL commands. Commands
that report as "not supported" are typically:

- Security commands (passphrase, secure erase)
- Advanced media operations (poison injection, scan media)
- Dynamic capacity commands (DCD)
- FM-API commands (unless using switch emulation)

This is expected behavior—the tests gracefully skip unsupported commands.

### Running with QEMU (MCTP)

QEMU also supports MCTP over I2C for out-of-band CXL management testing. This
enables testing FM-API commands against a CXL switch topology with tunneling
support, which is not possible with the ioctl-based approach.

The MCTP test configuration includes:
- **CXL Switch** with FM-API CCI (upstream port with switch mailbox)
- **Type3 Device 1** - 256 MB, connected to switch downstream port 0
- **Type3 Device 2** - 512 MB, connected to switch downstream port 3
- **MCTP over I2C** using the aspeed-i2c controller and i2c_mctp_cxl devices

#### Prerequisites

1. **QEMU with CXL and MCTP support** (built from source with aspeed-i2c and
   i2c_mctp_cxl device support):

```bash
# Verify CXL and MCTP device support
qemu-system-x86_64 -device help | grep -E "cxl|mctp"
```

2. **Linux kernel with CXL and MCTP support:**

Required kernel config options:
```
# CXL support
CONFIG_CXL_BUS=y
CONFIG_CXL_PCI=y
CONFIG_CXL_ACPI=y
CONFIG_CXL_MEM=y
CONFIG_CXL_MEM_RAW_COMMANDS=y

# MCTP support
CONFIG_MCTP=y
CONFIG_MCTP_TRANSPORT_I2C=y

# Aspeed I2C controller (for QEMU emulation)
CONFIG_I2C_ASPEED=y
```

3. **MCTP tools** (mctpd and mctp utilities from [CodeConstruct](https://github.com/CodeConstruct/mctp)):

```bash
# Build and install mctp tools
git clone https://github.com/CodeConstruct/mctp.git
cd mctp
meson setup build
meson compile -C build
sudo meson install -C build
```

4. **D-Bus** (required for mctpd endpoint assignment):

```bash
# Debian/Ubuntu
apt install dbus
```

#### Automated QEMU MCTP Testing

The `scripts/qemu-mctp-test.sh` script automates MCTP-based testing:

```bash
# Basic usage
./scripts/qemu-mctp-test.sh --kernel /path/to/bzImage

# With custom QEMU binary
QEMU_BIN=~/qemu/build/qemu-system-x86_64 \
    ./scripts/qemu-mctp-test.sh --kernel /path/to/bzImage

# With verbose output
./scripts/qemu-mctp-test.sh --kernel /path/to/bzImage -v

# With custom timeout (default: 120 seconds)
./scripts/qemu-mctp-test.sh --kernel /path/to/bzImage --timeout 180
```

**Script Options:**

| Option | Short | Description |
|--------|-------|-------------|
| `--kernel <path>` | `-k` | Path to kernel bzImage (required) |
| `--qemu <path>` | `-q` | Path to QEMU binary |
| `--timeout <secs>` | `-t` | Test timeout in seconds (default: 120) |
| `--verbose` | `-v` | Enable verbose output |
| `--sanitize` | `-s` | Build with AddressSanitizer |
| `--help` | `-h` | Show help message |

**What the script does:**

1. Builds libcxlmi with MCTP test support
2. Creates an initramfs with test binaries, mctp tools, mctpd, and dbus
3. Launches QEMU with a CXL switch topology and MCTP I2C devices
4. Inside the VM:
   - Waits for the aspeed-i2c MCTP device to appear
   - Starts dbus-daemon and mctpd
   - Assigns MCTP endpoints to the CXL devices via mctpd
   - Runs tests against the MCTP endpoints
5. Reports results and exits with appropriate status

**Example output:**

```
[*] Building libcxlmi...
[*] Creating initramfs...
[*] Found mctp tool
[*] Found mctpd
[*] Starting QEMU with CXL switch topology and MCTP I2C...

--- generic: mctp:11,8 ---
  [PASS] identify
  [PASS] get_response_msg_limit
  [PASS] get_supported_logs
  ...
[PASS] generic: mctp:11,8

--- fmapi: mctp:11,8 ---
  [PASS] identify_sw_device
  [PASS] get_phys_port_state
  [SKIP] get_ld_info: not supported
  ...
  Auto-detected tunnel port: 0 (device type 5)
  Auto-detected MLD with 3 LDs
[Tunneling Tests]
  [PASS] tunnel_switch_identify
           [via port 0] vendor_id: 0x8086
           [via port 0] device_id: 0x0d93
  [PASS] tunnel_mld_identify
           [via LD 0] vendor_id: 0x8086
  [PASS] tunnel_switch_mld_identify
           [via port 0, LD 0] vendor_id: 0x8086
[PASS] fmapi: mctp:11,8

Tunneling: switch port 0 -> FM-owned LD (level 1)
--- generic: mctp:11,8 ---
  [PASS] identify
  ...
[PASS] generic: mctp:11,8 (tunneled port 0)

--- memdev: mctp:11,9 ---
  [PASS] identify_memory_device
  [PASS] get_health_info
  ...
[PASS] memdev: mctp:11,9

TEST_RESULT=PASS
[*] === TESTS PASSED ===
```

The FM-API test includes auto-detection of tunnel targets. When a CXL switch is
detected, the test queries `identify_sw_device` and `get_phys_port_state` to find
downstream ports with connected devices, then automatically runs tunneling tests
through those ports.

#### MCTP Test Topology

The QEMU topology creates a CXL switch with downstream Type3 devices accessible
via MCTP over I2C:

```
                    ┌─────────────────────────────────────┐
                    │           Aspeed I2C Bus            │
                    └──────┬──────────┬──────────┬────────┘
                           │          │          │
                      I2C 0x4    I2C 0x5    I2C 0x6
                           │          │          │
                    ┌──────┴──────────┴──────────┴────────┐
                    │         i2c_mctp_cxl devices        │
                    └──────┬──────────┬──────────┬────────┘
                           │          │          │
                      EID 8       EID 9      EID 10
                           │          │          │
                    ┌──────┴────┐ ┌───┴───┐ ┌───┴───┐
                    │  CXL      │ │ Type3 │ │ Type3 │
                    │  Switch   │ │ Dev 1 │ │ Dev 2 │
                    │  (FM-API) │ │ 256MB │ │ 512MB │
                    └─────┬─────┘ └───────┘ └───────┘
                          │
              ┌───────────┼───────────┐
              │           │           │
           Port 0      Port 1      Port 2
              │           │           │
          ┌───┴───┐   (empty)    ┌───┴───┐
          │ Type3 │              │ Type3 │
          │ Dev 1 │              │ Dev 2 │
          └───────┘              └───────┘
```

**MCTP Configuration:**

| Device | I2C Address | MCTP EID | Description |
|--------|-------------|----------|-------------|
| Switch | 0x4 | 8 | CXL Switch with FM-API CCI |
| Type3 #1 | 0x5 | 9 | 256 MB memory device on port 0 |
| Type3 #2 | 0x6 | 10 | 512 MB memory device on port 2 |
| Local | - | 50 | Host MCTP endpoint |

**MCTP Network:** ID 11

#### Tests Executed

The MCTP test run exercises:

1. **Switch CCI (EID 8) - Direct**
   - Generic command set tests (no tunneling)
   - FM-API command set tests (no tunneling) - runs `identify_sw_device`, `get_phys_port_state`
   - Auto-detection of downstream devices for tunneling tests
   - Tunneling tests through auto-detected ports

2. **Tunneling through Switch to Downstream Devices**
   - Generic commands tunneled through switch port (`-p <port>`)
   - Memory device commands tunneled through switch port
   - The FM-API test auto-detects downstream ports and runs tunneling tests

3. **Type3 Devices (EID 9, 10) - Direct MCTP**
   - Generic command set tests
   - Memory device command set tests

**Tunneling Test Coverage:**

The FM-API test program includes built-in tunneling tests that exercise:
- `tunnel_switch_identify` - Level 1 tunnel through switch to downstream device
- `tunnel_mld_identify` - Level 1 tunnel to LD in MLD
- `tunnel_switch_mld_identify` - Level 2 tunnel through switch to LD in MLD

These tests use auto-detected tunnel targets when available, or can be manually
configured with `-p` and `-l` options.

#### Troubleshooting

**Test times out waiting for MCTP I2C device:**

- Ensure your kernel has `CONFIG_I2C_ASPEED=y` and `CONFIG_MCTP_TRANSPORT_I2C=y`
- The aspeed-i2c driver must support ACPI enumeration (requires recent kernel)
- Increase timeout with `--timeout 180` if boot is slow

**mctpd fails to start:**

- Ensure dbus is installed and dbus-daemon is available
- Check that mctpd is built and installed correctly

**Endpoint assignment fails:**

- mctpd uses D-Bus to manage endpoints; ensure dbus-daemon is running
- The script automatically handles D-Bus setup inside the VM

**All commands show "Failed to send on MCTP socket":**

- Check that MCTP endpoints were assigned correctly
- Verify `mctp route` shows routes to EIDs 8, 9, 10
- Ensure mctpd is running and has discovered the endpoints

### Test Infrastructure

All test programs share common infrastructure from `tests/test-common.h`:

```c
#include "test-common.h"

TEST_DECLARE_COUNTERS;

static void test_example(struct cxlmi_endpoint *ep)
{
    struct cxlmi_cmd_identify_rsp rsp = {0};
    int rc;

    rc = cxlmi_cmd_identify(ep, NULL, &rsp);
    if (is_unsupported(rc)) {
        TEST_SKIP("identify", "not supported");
        return;
    }
    if (rc) {
        TEST_FAIL("identify", rc_str(rc));
        return;
    }
    TEST_PASS("identify");
}

int main(int argc, char **argv)
{
    TEST_MAIN_START("Example Tests", usage);
    test_example(ep);
    TEST_MAIN_END();
}
```

**Common helpers:**

| Function/Macro | Purpose |
|----------------|---------|
| `TEST_PASS(name)` | Record a passing test |
| `TEST_FAIL(name, reason)` | Record a failing test |
| `TEST_SKIP(name, reason)` | Record a skipped test |
| `is_unsupported(rc)` | Check if command is unsupported |
| `rc_str(rc)` | Convert return code to string |
| `wait_for_bg_done(ep, timeout)` | Wait for background operation |
| `open_endpoint(ctx, target)` | Open ioctl or MCTP endpoint |

### Background Operation Handling

Some CXL commands initiate background operations. The test infrastructure
handles these appropriately:

- `CXLMI_RET_BACKGROUND` - Operation started successfully (treated as PASS)
- `CXLMI_RET_BUSY` - Device busy with existing operation (wait and retry)

```c
static void test_populate_log(struct cxlmi_endpoint *ep)
{
    int retries = 3;
    int rc;

    do {
        rc = cxlmi_cmd_populate_log(ep, NULL, &req);
        if (rc == CXLMI_RET_BUSY) {
            if (!wait_for_bg_done(ep, 5000)) {
                usleep(500000);
            }
            retries--;
            continue;
        }
        break;
    } while (retries > 0);

    if (rc == CXLMI_RET_BACKGROUND || rc == 0) {
        TEST_PASS("populate_log");
        return;
    }
    // ... handle other cases
}
```

---

## Mock Device Testing Infrastructure

libcxlmi includes a mock transport layer that enables comprehensive testing without
requiring physical CXL hardware. This section explains the architecture, benefits,
limitations, and usage of the mock testing infrastructure.

### Mock Overview

The mock transport simulates a CXL device endpoint, allowing test code to:

- Send CXL-MI commands through the library's normal API
- Configure expected responses with specific return codes and payloads
- Verify that commands are properly formatted before transmission
- Test error handling paths that are difficult to trigger with real hardware

This enables developers to validate library behavior, catch regressions, and verify
protocol correctness without access to CXL devices.

## Architecture

### How It Works

The mock transport intercepts commands at the transport layer, where the library
would normally send data over MCTP or through a mailbox interface:

```
┌─────────────────┐
│   Test Code     │
└────────┬────────┘
         │ cxlmi_cmd_*()
         ▼
┌─────────────────┐
│  libcxlmi API   │
│  (commands.c)   │
└────────┬────────┘
         │ send_cmd_cci()
         ▼
┌─────────────────┐
│ Mock Transport  │  ← Intercepts here instead of real hardware
│   (mock.c)      │
└─────────────────┘
```

When a command is sent to a mock endpoint:

1. The library builds the CCI message (command set, opcode, payload) exactly as
   it would for real hardware
2. The mock transport records the command for later verification
3. It looks up a pre-configured response matching the command set and opcode
4. It returns that response (or "unsupported" if none was configured)
5. The library processes the response and returns to the caller

This means the entire command encoding/decoding path is exercised, just as it
would be with a real device.

### Key Components

**`src/cxlmi/mock.c`** - Mock transport implementation:
- `cxlmi_open_mock()` - Creates a mock endpoint
- `cxlmi_mock_set_response()` - Queues a response for a specific command
- `cxlmi_mock_get_last_command()` - Retrieves the last command sent (for verification)
- `cxlmi_mock_get_stats()` - Returns command/response counts
- `send_mock_cmd()` - Internal function that handles mock command processing

**`src/cxlmi/test.h`** - Public test API header (separate from `libcxlmi.h` to
keep the main API clean)

**`tests/mock-tests.c`** - Comprehensive test suite using the mock infrastructure

## Benefits

### Hardware Independence

The primary benefit is the ability to test without CXL hardware. This enables:

- CI/CD pipelines that run on standard servers
- Development on laptops and workstations
- Testing of commands for devices that don't exist yet

### Complete Path Coverage

Unlike unit tests that mock at the function level, the mock transport exercises
the complete command path:

- Struct serialization to wire format
- Endianness conversion (host byte order ↔ little-endian wire format)
- Payload size calculations
- Response parsing and field extraction

### Error Path Testing

Real hardware rarely returns errors, making error handling difficult to test.
The mock transport can simulate any return code:

```c
/* Test handling of background operation status */
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BACKGROUND, NULL, 0);
rc = cxlmi_cmd_identify(ep, NULL, &id);
assert(rc == CXLMI_RET_BACKGROUND);
```

### Protocol Verification

Tests can verify that commands are encoded correctly by inspecting the raw
payload sent to the mock transport:

```c
/* Verify 64-bit field is encoded as little-endian */
cxlmi_mock_get_last_command(ep, &cmd_set, &cmd, payload, &payload_size);
assert(payload[0] == 0x78);  /* Low byte of 0x12345678 */
assert(payload[3] == 0x12);  /* High byte */
```

### Regression Testing

With 299 tests covering various commands, return codes, and edge cases, the
test suite catches regressions when modifying the library.

## Limitations

### No Device Logic

The mock transport does not simulate device behavior. It simply returns
pre-configured responses. This means:

- It cannot validate that a request makes sense for the device state
- It cannot simulate stateful operations (e.g., firmware update progress)
- It cannot test timing-dependent behavior

### Response Configuration Required

Every command needs a response configured before it's sent. Unconfigured
commands return `CXLMI_RET_UNSUPPORTED`. This is intentional—it forces tests
to be explicit about expected behavior.

### Single Response Per Command

Responses are consumed in FIFO order per command. For commands that might be
called multiple times, you must queue multiple responses:

```c
/* Queue 3 responses for retry testing */
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
```

### No MCTP/Transport Layer Testing

The mock transport bypasses the actual transport layer (MCTP, mailbox). To test
transport-level behavior, you need real hardware or a separate transport mock.

## Usage

### Basic Test Pattern

```c
#include <libcxlmi.h>
#include <cxlmi/test.h>

void test_identify(void)
{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep;
    struct cxlmi_cmd_identify_rsp wire_rsp = {0};
    struct cxlmi_cmd_identify_rsp result;
    int rc;

    /* Create context and mock endpoint */
    ctx = cxlmi_new_ctx(stderr, LOG_ERR);
    ep = cxlmi_open_mock(ctx);

    /* Configure the response the mock should return */
    wire_rsp.vendor_id = cpu_to_le16(0x1234);
    wire_rsp.device_id = cpu_to_le16(0x5678);
    cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
                            &wire_rsp, sizeof(wire_rsp));

    /* Call the library function under test */
    rc = cxlmi_cmd_identify(ep, NULL, &result);

    /* Verify results */
    assert(rc == CXLMI_RET_SUCCESS);
    assert(result.vendor_id == 0x1234);
    assert(result.device_id == 0x5678);

    /* Cleanup */
    cxlmi_close(ep);
    cxlmi_free_ctx(ctx);
}
```

### Testing Request Encoding

To verify that a request is encoded correctly on the wire:

```c
void test_request_encoding(void)
{
    struct cxlmi_cmd_set_timestamp_req req = {0};
    uint8_t cmd_set, cmd;
    uint8_t payload[64];
    size_t payload_size = sizeof(payload);

    /* ... setup mock endpoint ... */

    req.timestamp = 0x0102030405060708ULL;

    cxlmi_mock_set_response(ep, 0x03, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
    cxlmi_cmd_set_timestamp(ep, NULL, &req);

    /* Retrieve and verify the raw command payload */
    cxlmi_mock_get_last_command(ep, &cmd_set, &cmd, payload, &payload_size);

    assert(cmd_set == 0x03);  /* TIMESTAMP command set */
    assert(cmd == 0x01);      /* SET_TIMESTAMP opcode */

    /* Verify little-endian encoding */
    assert(payload[0] == 0x08);  /* LSB */
    assert(payload[7] == 0x01);  /* MSB */
}
```

### Testing Error Handling

```c
void test_error_handling(void)
{
    struct cxlmi_cmd_identify_rsp id;
    int rc;

    /* ... setup mock endpoint ... */

    /* Configure mock to return an error */
    cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_INVALID_INPUT, NULL, 0);

    rc = cxlmi_cmd_identify(ep, NULL, &id);

    assert(rc == CXLMI_RET_INVALID_INPUT);
}
```

## Test Categories

The test suite (`tests/mock-tests.c`) covers several categories:

| Category | Description |
|----------|-------------|
| Mock Infrastructure | Tests for the mock transport itself |
| Generic Component Commands | Identify, background operation status |
| Events Commands | Get/clear event records |
| Firmware Update Commands | Get FW info, transfer, activate |
| Timestamp Commands | Get/set timestamp |
| Logs Commands | Get log, supported logs, CEL |
| Features Commands | Get/set features |
| Memory Device Commands | Sanitize, secure erase |
| Health Info/Alerts Commands | Health info, alert config |
| Media and Poison Commands | Poison list, inject/clear poison |
| DCD Config Commands | Dynamic capacity configuration |
| FM-API Commands | Fabric Manager API commands |
| Error Code Handling | All CXL return codes |
| Request Payload Verification | Wire format encoding |
| Response Payload Verification | Wire format decoding |
| Endianness Verification | Multi-byte field byte order |

## Running Tests

Build and run the test suite:

```bash
meson setup build
meson compile -C build
./build/tests/mock-tests
```

Example output:

```
Mock Infrastructure:
  test_mock_create_close                                       [PASS]
  test_mock_no_response_returns_unsupported                    [PASS]
  test_mock_stats_tracking                                     [PASS]
  ...

==========================================================
Results: 299 passed, 0 failed, 299 total
==========================================================
```

## Code Coverage

The project supports code coverage reporting using gcov/lcov. This helps identify
untested code paths and measure test effectiveness.

### Prerequisites

Install the coverage tools:

```bash
# Debian/Ubuntu
apt install lcov

# Fedora/RHEL
dnf install lcov

# Or use gcovr instead
pip install gcovr
```

### Generating Coverage Reports

1. **Configure a coverage build:**

```bash
meson setup build-coverage -Db_coverage=true
```

2. **Build and run tests:**

```bash
meson compile -C build-coverage
meson test -C build-coverage
```

3. **Generate reports:**

```bash
# HTML report (recommended for detailed analysis)
ninja -C build-coverage coverage-html
# Opens: build-coverage/meson-logs/coveragereport/index.html

# Text summary
ninja -C build-coverage coverage-text

# XML report (for CI integration)
ninja -C build-coverage coverage-xml

# Sonarqube format
ninja -C build-coverage coverage-sonarqube
```

### Understanding Coverage Output

The coverage report shows three metrics:

- **Line coverage**: Percentage of executable lines that were run
- **Function coverage**: Percentage of functions that were called
- **Branch coverage**: Percentage of conditional branches taken

Example output:
```
Summary coverage rate:
  lines......: 77.9% (7681 of 9863 lines)
  functions..: 82.2% (416 of 506 functions)
  branches...: 47.9% (2138 of 4459 branches)
```

### HTML Report Navigation

The HTML report provides:

- **Directory view**: Coverage breakdown by directory
- **File view**: Line-by-line coverage highlighting
  - Green: Executed lines
  - Red: Unexecuted lines
  - Yellow: Partially covered branches
- **Summary statistics**: Overall and per-file metrics

### CI Integration

For continuous integration, use the text or XML output:

```bash
# Get a quick pass/fail based on coverage threshold
ninja -C build-coverage coverage-text 2>&1 | grep "lines"

# Generate Cobertura XML for CI tools (Jenkins, GitLab, etc.)
ninja -C build-coverage coverage-xml
# Output: build-coverage/meson-logs/coverage.xml
```

### Improving Coverage

When coverage reports show gaps:

1. **Identify uncovered functions**: Look for red functions in the HTML report
2. **Add targeted tests**: Create tests that exercise the uncovered paths
3. **Consider error paths**: Many gaps are in error handling code
4. **Check branch coverage**: Ensure both true/false paths are tested

Example of adding a test for an uncovered error path:

```c
static int test_error_resource_exhausted(void)
{
    struct cxlmi_cmd_identify_rsp id;
    int rc;

    ASSERT_EQ(setup(), 0, "setup failed");
    cxlmi_mock_set_response(test_ep, 0x00, 0x01,
                            CXLMI_RET_RESOURCES_EXHAUSTED, NULL, 0);
    rc = cxlmi_cmd_identify(test_ep, NULL, &id);
    teardown();

    ASSERT_EQ(rc, CXLMI_RET_RESOURCES_EXHAUSTED, "wrong error code");
    return 0;
}
```

## Adding New Tests

When adding support for a new command, add corresponding tests:

1. **Basic functionality test** - Configure a valid response and verify the
   library returns correct values

2. **Request encoding test** - Verify multi-byte fields are encoded as
   little-endian on the wire

3. **Response decoding test** - Provide a little-endian wire response and
   verify fields are converted to host byte order

4. **Error handling test** - Verify the command handles error return codes

See existing tests in `tests/mock-tests.c` for examples.
