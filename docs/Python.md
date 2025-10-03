# Python Bindings for libcxlmi

This document describes the Python bindings for libcxlmi, providing Python developers with access to CXL Management Interface functionality.

## Overview

The Python bindings are generated using SWIG (Simplified Wrapper and Interface Generator) and provide a Pythonic interface to the libcxlmi C library. The bindings support all major CXL command sets:

- **Generic Component Commands**: Device identification, events, firmware, logs
- **Memory Device Commands**: Capacity, health, security, dynamic capacity
- **FM-API Commands**: Fabric Manager operations, switch management, MLD operations
- **Vendor Specific Commands**: Custom vendor-defined commands

## Building with Python Support

### Prerequisites

- Python 3.6 or later
- SWIG 3.0 or later
- Python setuptools module

### Build Configuration

Python bindings are **disabled by default**. To enable them:

```bash
# Enable Python bindings
meson setup build -Dpython=enabled

# Build
meson compile -C build

# Run tests
meson test -C build
```

To disable installation of Python bindings:

```bash
meson setup build -Dpython=enabled -Dpython-install=false
```

## Installation

When Python bindings are enabled and `python-install=true` (default), the module is installed to the Python site-packages directory:

```bash
meson install -C build
```

For development, you can use the module directly from the build directory without installing:

```bash
export PYTHONPATH=/path/to/build/src/python
export LD_LIBRARY_PATH=/path/to/build/src
python3 your_script.py
```

## Python API

### Module Import

```python
import cxlmi
```

### Context Management

```python
# Create a new context
ctx = cxlmi.cxlmi_new_ctx(None, 0)  # NULL log file, log level 0

# Enable/disable automatic probing
cxlmi.cxlmi_set_probe_enabled(ctx, True)

# Scan for MCTP endpoints
cxlmi.cxlmi_scan_mctp(ctx)

# Free context when done
cxlmi.cxlmi_free_ctx(ctx)
```

### Endpoint Management

```python
# Open MCTP endpoint
ep = cxlmi.cxlmi_open_mctp(ctx, net=0, eid=8)

# Open character device endpoint
ep = cxlmi.cxlmi_open(ctx, "/dev/cxl/mem0")

# Get/set timeout
timeout = cxlmi.cxlmi_endpoint_get_timeout(ep)
cxlmi.cxlmi_endpoint_set_timeout(ep, 5000)  # 5 seconds

# Check FM-API support
if cxlmi.cxlmi_endpoint_has_fmapi(ep):
    cxlmi.cxlmi_endpoint_enable_fmapi(ep)

# Close endpoint when done
cxlmi.cxlmi_close(ep)
```

### Iterating Endpoints

```python
# Use the helper generator function
for ep in cxlmi.endpoints(ctx):
    # Work with endpoint
    pass

# Or manually iterate
ep = cxlmi.cxlmi_first_endpoint(ctx)
while ep:
    # Work with endpoint
    ep = cxlmi.cxlmi_next_endpoint(ctx, ep)
```

### Tunneling Support

For complex CXL topologies, commands can be tunneled through switches and to Multi-Logical Devices (MLDs):

```python
# Tunnel to MLD (Logical Device)
ti_mld = cxlmi.cxlmi_tunnel_mld(ld=0)

# Tunnel through switch
ti_switch = cxlmi.cxlmi_tunnel_switch(port=1)

# Tunnel through switch to MLD
ti_switch_mld = cxlmi.cxlmi_tunnel_switch_mld(port=1, ld=0)

# Tunnel to Multi-Headed Device
ti_mhd = cxlmi.cxlmi_tunnel_mhd()

# Use None for direct (non-tunneled) commands
ti = None

# Free tunnel info when done
cxlmi.cxlmi_tunnel_free(ti_mld)
```

### Executing Commands

Commands follow the C API pattern with Python-friendly argument passing:

```python
# Commands with output only
ident = cxlmi.cxlmi_cmd_identify()
cxlmi.cxlmi_cmd_identify(ep, None, ident)  # None = no tunneling
print(f"Vendor ID: 0x{ident.vendor_id:04x}")
print(f"Device ID: 0x{ident.device_id:04x}")

# Commands with input and output
req = cxlmi.cxlmi_cmd_get_event_records_req()
req.event_log = cxlmi.CXLMI_EVENT_LOG_INFO
rsp = cxlmi.cxlmi_cmd_get_event_records_rsp()
cxlmi.cxlmi_cmd_get_event_records(ep, None, req, rsp)
print(f"Event record count: {rsp.record_count}")

# Commands with input only
req = cxlmi.cxlmi_cmd_set_timestamp()
req.timestamp = 1234567890
cxlmi.cxlmi_cmd_set_timestamp(ep, None, req)

# Commands with no payload
cxlmi.cxlmi_cmd_request_bg_operation_abort(ep, None)
```

### Working with Structures

All CXL command structures are available as Python classes:

```python
# Create and populate structures
health = cxlmi.cxlmi_cmd_memdev_get_health_info()
cxlmi.cxlmi_cmd_memdev_get_health_info(ep, None, health)

# Access fields
print(f"Media status: {health.media_status}")
print(f"Dirty shutdown count: {health.dirty_shutdown_count}")
print(f"Life used: {health.life_used}%")

# Structures with flexible array members
# The flexible array field is hidden, but all fixed fields work normally
event_rsp = cxlmi.cxlmi_cmd_get_event_records_rsp()
event_rsp.overflow_err_count = 5
event_rsp.record_count = 3
print(f"Events: {event_rsp.record_count}")
```

### Error Handling

Commands raise Python exceptions on errors:

```python
try:
    ident = cxlmi.cxlmi_cmd_identify()
    cxlmi.cxlmi_cmd_identify(ep, None, ident)
except IOError as e:
    print(f"I/O error: {e}")
except RuntimeError as e:
    print(f"CXL command error: {e}")
```

Error codes can be converted to strings:

```python
msg = cxlmi.cxlmi_cmd_retcode_tostr(cxlmi.CXLMI_RET_UNSUPPORTED)
print(msg)  # "Unsupported"
```

### Return Codes

All CXL return codes are available as constants:

```python
cxlmi.CXLMI_RET_SUCCESS        # 0x0 - Success
cxlmi.CXLMI_RET_BACKGROUND     # Background operation started
cxlmi.CXLMI_RET_INPUT          # Invalid input
cxlmi.CXLMI_RET_UNSUPPORTED    # Unsupported command
cxlmi.CXLMI_RET_INTERNAL       # Internal error
# ... and 29 more return codes
```

### Constants

Key constants are exposed:

```python
cxlmi.CXLMI_MAX_SUPPORTED_EVENT_RECORDS  # 20
cxlmi.CXLMI_MAX_SUPPORTED_LOGS           # 7
cxlmi.CXL_MAILBOX_MAX_PAYLOAD_SIZE       # 2048 bytes
```

## Examples

Complete example programs are provided in the `examples/python/` directory:

- `simple.py` - Basic device identification
- `events.py` - Event log reading and management
- `health.py` - Health monitoring
- `firmware.py` - Firmware information
- `tunneling.py` - Multi-level command tunneling
- `vendor.py` - Vendor-specific commands

To run examples from the build directory:

```bash
cd examples/python
PYTHONPATH=../../build/src/python LD_LIBRARY_PATH=../../build/src python3 simple.py
```

See `examples/python/README.md` for detailed usage instructions.

## Testing

The Python bindings include comprehensive unit tests in `tests/python/test_cxlmi.py`:

- 42 test cases covering all aspects of the bindings
- Tests for context management, endpoint handling, structures, tunneling
- Tests for flexible array member handling
- Tests for error handling and constants

Run tests with:

```bash
meson test -C build python-bindings
```

Or directly:

```bash
cd tests/python
PYTHONPATH=../../build/src/python LD_LIBRARY_PATH=../../build/src python3 -m unittest test_cxlmi.py
```

## Technical Details

### SWIG Interface

The bindings are generated from `src/cxlmi.i`, which:
- Exposes all CXL command structures from `cxlmi/api-types.h`
- Provides context and endpoint management functions
- Includes helper functions for tunneling
- Handles opaque structure types (`cxlmi_ctx`, `cxlmi_endpoint`)
- Provides Python generator for endpoint iteration

### Flexible Array Members

Some CXL structures contain C99 flexible array members (e.g., `uint8_t data[]`) at the end. SWIG cannot expose these fields to Python because:

1. They have no fixed size - the actual size depends on the command/response
2. They're part of variable-length wire protocol structures
3. Python has no direct equivalent to C flexible array members

**This is not a problem** because:
- The structures themselves are fully usable from Python
- Users create and populate these structures normally
- All fixed-size fields remain accessible
- The C library functions handle the flexible arrays internally
- For reading data from flexible arrays, the C API provides dedicated getter functions
- This is the standard approach for SWIG bindings (same pattern as libnvme)

Example structures with hidden flexible arrays:
- `cxlmi_cmd_identify.component_specific_ident_data[]`
- `cxlmi_cmd_get_event_records_rsp.records[]`
- `cxlmi_cmd_get_fw_info.fw_slot_info[]`
- `cxlmi_cmd_memdev_get_poison_list_rsp.media_error_records[]`

### Memory Management

- Context and endpoint objects are opaque pointers managed by the C library
- Tunnel info structures are allocated by helper functions and must be freed with `cxlmi_tunnel_free()`
- Command structures are Python objects with automatic memory management
- The SWIG-generated code handles all marshalling between Python and C

### Thread Safety

The bindings inherit the thread safety characteristics of the C library:
- No internal locking is provided
- Users must serialize access to contexts and endpoints
- Multiple contexts can be used concurrently from different threads

### API Coverage

The Python bindings expose approximately **75+ CXL commands** across four command sets:

#### Generic Component Commands (~19 commands)
- Device identification and capabilities
- Event record management
- Firmware operations
- Log management
- Timestamp operations
- Alert configuration
- Feature negotiation

#### Memory Device Commands (~35 commands)
- Memory device identification
- Partition info and capacity management
- LSA (Label Storage Area) operations
- Health info and alerts
- Poison list management
- Security operations
- Sanitize and secure erase
- Dynamic capacity operations
- Media scan operations

#### FM-API Commands (~20 commands)
- Switch device identification
- Physical port management
- Virtual CXL Switch operations
- vPPB (virtual Point-to-Point Bridge) management
- Multi-Logical Device (MLD) operations
- QoS bandwidth management
- Multi-headed device operations

#### Vendor Specific Commands
- `cxlmi_cmd_vendor_specific()` - Execute custom vendor commands with arbitrary opcodes

## Limitations

1. **No async support**: Commands are synchronous only
2. **No background operation polling**: Background operations must be polled using additional commands
3. **Limited array support**: C arrays are not directly accessible; use provided array helper functions where available

## Compatibility

- **Python versions**: 3.6, 3.7, 3.8, 3.9, 3.10, 3.11, 3.12+
- **Platforms**: Linux (MCTP and character device endpoints)
- **CXL specifications**: CXL 2.0, 3.0, 3.1, 3.2

## License

The Python bindings are licensed under LGPL-2.1-or-later, matching the libcxlmi library.

## Contributing

When adding new commands to libcxlmi, the Python bindings automatically expose them if:
- The command structures are in `cxlmi/api-types.h`
- The command function is declared in `libcxlmi.h`
- Any flexible array members are added to the `%ignore` list in `src/cxlmi.i`

For questions or issues with the Python bindings, please open an issue at the libcxlmi repository.
