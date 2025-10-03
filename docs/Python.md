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
- SWIG 3.0 or later (for building bindings)
- Python setuptools module
- For MCTP examples: libcxlmi built with D-Bus support (`-Dlibdbus=enabled`)

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

## Installation

When Python bindings are enabled, the module is automatically installed to the Python site-packages directory:

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

### Core Library Functions

#### Context Management
- `cxlmi.cxlmi_new_ctx(fp, log_level)` - Create library context
- `cxlmi.cxlmi_free_ctx(ctx)` - Free context
- `cxlmi.cxlmi_set_probe_enabled(ctx, enabled)` - Enable/disable automatic probing

#### Endpoint Opening and Scanning
- `cxlmi.cxlmi_open(ctx, devname)` - Open CXL device (e.g., "mem0")
- `cxlmi.cxlmi_open_mctp(ctx, net, eid)` - Open MCTP endpoint
- `cxlmi.cxlmi_scan_mctp(ctx)` - Scan for MCTP endpoints (requires D-Bus)
- `cxlmi.cxlmi_close(ep)` - Close endpoint

#### Endpoint Configuration
- `cxlmi.cxlmi_endpoint_get_timeout(ep)` - Get timeout in milliseconds
- `cxlmi.cxlmi_endpoint_set_timeout(ep, timeout_ms)` - Set timeout
- `cxlmi.cxlmi_endpoint_has_fmapi(ep)` - Check FM-API support
- `cxlmi.cxlmi_endpoint_enable_fmapi(ep)` - Enable FM-API command set
- `cxlmi.cxlmi_endpoint_disable_fmapi(ep)` - Disable FM-API command set

#### Endpoint Iteration
- `cxlmi.cxlmi_first_endpoint(ctx)` - Get first endpoint
- `cxlmi.cxlmi_next_endpoint(ctx, ep)` - Get next endpoint
- `cxlmi.endpoints(ctx)` - Python generator for iteration

#### Tunneling Functions
- `cxlmi.cxlmi_tunnel_mld(ld)` - Create MLD tunnel info
- `cxlmi.cxlmi_tunnel_switch(port)` - Create switch tunnel info
- `cxlmi.cxlmi_tunnel_switch_mld(port, ld)` - Create switch→MLD tunnel info
- `cxlmi.cxlmi_tunnel_mhd()` - Create MHD tunnel info
- `cxlmi.cxlmi_tunnel_free(ti)` - Free tunnel info

#### Utility Functions
- `cxlmi.cxlmi_cmd_retcode_tostr(code)` - Convert return code to string

### Usage Examples

#### Context Management

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

#### Endpoint Management

```python
# Open MCTP endpoint
ep = cxlmi.cxlmi_open_mctp(ctx, net=0, eid=8)

# Open character device endpoint
ep = cxlmi.cxlmi_open(ctx, "mem0")

# Get/set timeout
timeout = cxlmi.cxlmi_endpoint_get_timeout(ep)
cxlmi.cxlmi_endpoint_set_timeout(ep, 5000)  # 5 seconds

# Check FM-API support
if cxlmi.cxlmi_endpoint_has_fmapi(ep):
    cxlmi.cxlmi_endpoint_enable_fmapi(ep)

# Close endpoint when done
cxlmi.cxlmi_close(ep)
```

#### Iterating Endpoints

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

#### Tunneling Support

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

Complete example programs are provided in the `examples/python/` directory demonstrating various aspects of the library.

### Running Examples

Make sure the Python module is in your PYTHONPATH:

```bash
export PYTHONPATH=/path/to/libcxlmi/build/src/python:$PYTHONPATH
export LD_LIBRARY_PATH=/path/to/libcxlmi/build/src:$LD_LIBRARY_PATH
```

Then run any example:

```bash
python3 identify_device.py mem0
python3 get_health_info.py mem0
python3 get_partition_info.py mem0
```

### Available Examples

#### identify_device.py
Basic example showing how to:
- Create a context
- Open a CXL device (mailbox) or scan for MCTP endpoints
- Send an Identify command
- Display device information and decode component type

#### get_health_info.py
Demonstrates querying memory device health information:
- Health status and media status
- Temperature monitoring
- Life used percentage
- Error counts

#### get_partition_info.py
Shows how to query and display partition information:
- Active partition sizes (volatile/persistent)
- Pending partition changes
- Human-readable capacity formatting

#### list_endpoints_mctp.py
MCTP endpoint discovery example (requires D-Bus support):
- Scanning for MCTP-connected CXL endpoints
- Iterating over discovered endpoints
- Querying basic information from each

#### tunnel_example.py
Comprehensive tunneling demonstration:
- Tunneling to Logical Devices in MLDs
- Tunneling through CXL Switches
- Multi-level tunneling (Switch → MLD)
- Multi-Headed Device (MHD) tunneling

#### fmapi_switch_info.py
FM-API example for CXL Switches:
- Checking FM-API support
- Querying switch identification
- Getting physical port states

### Writing Your Own Scripts

Here's a minimal example:

```python
#!/usr/bin/env python3
import cxlmi

# Create context
ctx = cxlmi.cxlmi_new_ctx(None, 6)  # LOG_INFO level

# Open device
ep = cxlmi.cxlmi_open(ctx, "mem0")

# Send command
ident = cxlmi.cxlmi_cmd_identify()
cxlmi.cxlmi_cmd_identify(ep, None, ident)

# Access results
print(f"Vendor ID: 0x{ident.vendor_id:04x}")

# Cleanup
cxlmi.cxlmi_close(ep)
cxlmi.cxlmi_free_ctx(ctx)
```

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

## Command Reference

The Python bindings expose all CXL commands across four command sets:

#### Generic Component Commands
- `cxlmi_cmd_identify()` - Device identification
- `cxlmi_cmd_bg_op_status()` - Background operation status
- `cxlmi_cmd_get_response_msg_limit()` - Get response message limit
- `cxlmi_cmd_set_response_msg_limit()` - Set response message limit
- `cxlmi_cmd_request_bg_op_abort()` - Request background operation abort
- `cxlmi_cmd_get_event_records()` - Get event records
- `cxlmi_cmd_clear_event_records()` - Clear event records
- `cxlmi_cmd_get_event_interrupt_policy()` - Get event interrupt policy
- `cxlmi_cmd_set_event_interrupt_policy()` - Set event interrupt policy
- `cxlmi_cmd_get_mctp_event_interrupt_policy()` - Get MCTP event interrupt policy
- `cxlmi_cmd_set_mctp_event_interrupt_policy()` - Set MCTP event interrupt policy
- `cxlmi_cmd_event_notification()` - Event notification
- `cxlmi_cmd_get_fw_info()` - Get firmware info
- `cxlmi_cmd_transfer_fw()` - Transfer firmware
- `cxlmi_cmd_activate_fw()` - Activate firmware
- `cxlmi_cmd_get_timestamp()` - Get timestamp
- `cxlmi_cmd_set_timestamp()` - Set timestamp
- `cxlmi_cmd_get_supported_logs()` - Get supported logs
- `cxlmi_cmd_get_log()` - Get log
- `cxlmi_cmd_get_log_cel()` - Get Command Effects Log (CEL)
- `cxlmi_cmd_get_log_capabilities()` - Get log capabilities
- `cxlmi_cmd_clear_log()` - Clear log
- `cxlmi_cmd_populate_log()` - Populate log
- `cxlmi_cmd_get_supported_logs_sublist()` - Get supported logs sublist
- `cxlmi_cmd_get_supported_features()` - Get supported features
- `cxlmi_cmd_get_feature()` - Get feature
- `cxlmi_cmd_set_feature()` - Set feature
- `cxlmi_cmd_vendor_specific()` - Vendor-specific command

#### Memory Device Commands
- `cxlmi_cmd_memdev_identify()` - Memory device identification
- `cxlmi_cmd_memdev_get_partition_info()` - Get partition info
- `cxlmi_cmd_memdev_set_partition_info()` - Set partition info
- `cxlmi_cmd_memdev_get_lsa()` - Get Label Storage Area
- `cxlmi_cmd_memdev_set_lsa()` - Set Label Storage Area
- `cxlmi_cmd_memdev_get_health_info()` - Get health info
- `cxlmi_cmd_memdev_get_alert_config()` - Get alert configuration
- `cxlmi_cmd_memdev_set_alert_config()` - Set alert configuration
- `cxlmi_cmd_memdev_get_shutdown_state()` - Get shutdown state
- `cxlmi_cmd_memdev_set_shutdown_state()` - Set shutdown state
- `cxlmi_cmd_get_poison_list()` - Get poison list
- `cxlmi_cmd_memdev_inject_poison()` - Inject poison
- `cxlmi_cmd_memdev_clear_poison()` - Clear poison
- `cxlmi_cmd_get_scan_media_capabilities()` - Get scan media capabilities
- `cxlmi_cmd_scan_media()` - Scan media
- `cxlmi_cmd_get_scan_media_results()` - Get scan media results
- `cxlmi_cmd_memdev_sanitize()` - Sanitize memory
- `cxlmi_cmd_memdev_secure_erase()` - Secure erase
- `cxlmi_cmd_memdev_media_operations_discovery()` - Media operations discovery
- `cxlmi_cmd_memdev_media_operations_sanitize()` - Media operations sanitize
- `cxlmi_cmd_memdev_security_send()` - Security send
- `cxlmi_cmd_memdev_security_receive()` - Security receive
- `cxlmi_cmd_memdev_get_security_state()` - Get security state
- `cxlmi_cmd_memdev_set_passphrase()` - Set passphrase
- `cxlmi_cmd_memdev_disable_passphrase()` - Disable passphrase
- `cxlmi_cmd_memdev_unlock()` - Unlock device
- `cxlmi_cmd_memdev_freeze_security_state()` - Freeze security state
- `cxlmi_cmd_memdev_passphrase_secure_erase()` - Passphrase secure erase
- `cxlmi_cmd_memdev_get_sld_qos_control()` - Get SLD QoS control
- `cxlmi_cmd_memdev_set_sld_qos_control()` - Set SLD QoS control
- `cxlmi_cmd_memdev_get_sld_qos_status()` - Get SLD QoS status
- `cxlmi_cmd_memdev_get_dc_config()` - Get Dynamic Capacity configuration
- `cxlmi_cmd_memdev_get_dc_extent_list()` - Get DC extent list
- `cxlmi_cmd_memdev_add_dc_response()` - Add DC response
- `cxlmi_cmd_memdev_release_dc()` - Release Dynamic Capacity

#### FM-API Commands
- `cxlmi_cmd_fmapi_identify_sw_device()` - Identify switch device
- `cxlmi_cmd_fmapi_get_phys_port_state()` - Get physical port state
- `cxlmi_cmd_fmapi_phys_port_control()` - Physical port control
- `cxlmi_cmd_fmapi_send_ppb_cxlio_config_request()` - Send PPB CXL.io config request
- `cxlmi_cmd_fmapi_get_domain_validation_sv_state()` - Get domain validation SV state
- `cxlmi_cmd_fmapi_set_domain_validation_sv()` - Set domain validation SV
- `cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state()` - Get VCS domain validation SV state
- `cxlmi_cmd_fmapi_get_domain_validation_sv()` - Get domain validation SV
- `cxlmi_cmd_fmapi_bind_vppb()` - Bind virtual PPB
- `cxlmi_cmd_fmapi_unbind_vppb()` - Unbind virtual PPB
- `cxlmi_cmd_fmapi_send_ld_cxlio_config_request()` - Send LD CXL.io config request
- `cxlmi_cmd_fmapi_send_ld_cxlio_mem_request()` - Send LD CXL.io mem request
- `cxlmi_cmd_fmapi_get_ld_info()` - Get Logical Device info
- `cxlmi_cmd_fmapi_get_ld_allocations()` - Get LD allocations
- `cxlmi_cmd_fmapi_set_ld_allocations()` - Set LD allocations
- `cxlmi_cmd_fmapi_get_qos_control()` - Get QoS control
- `cxlmi_cmd_fmapi_set_qos_control()` - Set QoS control
- `cxlmi_cmd_fmapi_get_qos_status()` - Get QoS status
- `cxlmi_cmd_fmapi_get_qos_allocated_bw()` - Get QoS allocated bandwidth
- `cxlmi_cmd_fmapi_set_qos_allocated_bw()` - Set QoS allocated bandwidth
- `cxlmi_cmd_fmapi_get_qos_bw_limit()` - Get QoS bandwidth limit
- `cxlmi_cmd_fmapi_set_qos_bw_limit()` - Set QoS bandwidth limit
- `cxlmi_cmd_fmapi_get_multiheaded_info()` - Get multi-headed info
- `cxlmi_cmd_fmapi_get_dcd_info()` - Get DCD info
- `cxlmi_cmd_fmapi_get_dc_reg_config()` - Get DC region config
- `cxlmi_cmd_fmapi_set_dc_region_config()` - Set DC region config
- `cxlmi_cmd_fmapi_get_dc_region_ext_list()` - Get DC region extent list
- `cxlmi_cmd_fmapi_initiate_dc_add()` - Initiate DC add
- `cxlmi_cmd_fmapi_initiate_dc_release()` - Initiate DC release
- `cxlmi_cmd_fmapi_dc_add_reference()` - DC add reference
- `cxlmi_cmd_fmapi_dc_remove_reference()` - DC remove reference
- `cxlmi_cmd_fmapi_dc_list_tags()` - DC list tags

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
