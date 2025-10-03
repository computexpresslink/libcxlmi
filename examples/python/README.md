# Python Examples for libcxlmi

This directory contains Python examples demonstrating the use of libcxlmi Python bindings.

## Prerequisites

- Python 3.6 or later
- libcxlmi built with Python bindings enabled (`-Dpython=enabled`)
- SWIG installed for building bindings
- For MCTP examples: libcxlmi built with D-Bus support (`-Dlibdbus=enabled`)

## Building Python Bindings

```bash
# Configure with Python bindings
meson setup build -Dpython=enabled

# Build
meson compile -C build

# The Python module will be in: build/src/python/
```

## Running Examples

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

## Examples

### identify_device.py
Basic example showing how to:
- Create a context
- Open a CXL device
- Send an Identify command
- Display device information

### get_health_info.py
Demonstrates querying memory device health information:
- Health status and media status
- Temperature monitoring
- Life used percentage
- Error counts

### get_partition_info.py
Shows how to query and display partition information:
- Active partition sizes (volatile/persistent)
- Pending partition changes
- Human-readable capacity formatting

### list_endpoints_mctp.py
MCTP endpoint discovery example (requires D-Bus support):
- Scanning for MCTP-connected CXL endpoints
- Iterating over discovered endpoints
- Querying basic information from each

### tunnel_example.py
Comprehensive tunneling demonstration:
- Tunneling to Logical Devices in MLDs
- Tunneling through CXL Switches
- Multi-level tunneling (Switch → MLD)
- Multi-Headed Device (MHD) tunneling

### fmapi_switch_info.py
FM-API example for CXL Switches:
- Checking FM-API support
- Querying switch identification
- Getting physical port states

## Writing Your Own Scripts

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

## Error Handling

The Python bindings automatically convert CXL return codes to Python exceptions:

```python
try:
    cxlmi.cxlmi_cmd_identify(ep, None, ident)
except RuntimeError as e:
    print(f"CXL command failed: {e}")
except IOError as e:
    print(f"Communication error: {e}")
```

## Tunneling

Create tunnel info structures for complex topologies:

```python
# Tunnel to LD 5 in an MLD
ti = cxlmi.cxlmi_tunnel_mld(5)
cxlmi.cxlmi_cmd_identify(ep, ti, ident)
cxlmi.cxlmi_tunnel_free(ti)

# Tunnel through switch port 2
ti = cxlmi.cxlmi_tunnel_switch(2)
cxlmi.cxlmi_cmd_identify(ep, ti, ident)
cxlmi.cxlmi_tunnel_free(ti)

# Two-level: Switch port 1 to LD 3
ti = cxlmi.cxlmi_tunnel_switch_mld(1, 3)
cxlmi.cxlmi_cmd_identify(ep, ti, ident)
cxlmi.cxlmi_tunnel_free(ti)
```

## Endpoint Iteration

Iterate over all endpoints in a context:

```python
for ep in cxlmi.endpoints(ctx):
    ident = cxlmi.cxlmi_cmd_identify()
    cxlmi.cxlmi_cmd_identify(ep, None, ident)
    print(f"Device: 0x{ident.vendor_id:04x}:0x{ident.device_id:04x}")
```

## Available Commands

The Python bindings provide access to all libcxlmi commands:

### Generic Component Commands
- `cxlmi_cmd_identify()`
- `cxlmi_cmd_bg_op_status()`
- `cxlmi_cmd_get_event_records()`
- `cxlmi_cmd_get_fw_info()`
- `cxlmi_cmd_get_timestamp()`
- `cxlmi_cmd_get_supported_logs()`
- And more...

### Memory Device Commands
- `cxlmi_cmd_memdev_identify()`
- `cxlmi_cmd_memdev_get_health_info()`
- `cxlmi_cmd_memdev_get_partition_info()`
- `cxlmi_cmd_get_poison_list()`
- `cxlmi_cmd_memdev_get_security_state()`
- And more...

### FM-API Commands
- `cxlmi_cmd_fmapi_identify_sw_device()`
- `cxlmi_cmd_fmapi_get_phys_port_state()`
- `cxlmi_cmd_fmapi_get_ld_info()`
- `cxlmi_cmd_fmapi_bind_vppb()`
- And more...

### Vendor Commands
```python
# Send vendor-specific command
opcode = 0xC000
input_data = b'\x00\x01\x02\x03'
output_data = cxlmi.cxlmi_cmd_vendor_specific(
    ep, None, opcode, input_data, len(input_data),
    output_buffer, output_size
)
```

## Testing

Run the comprehensive test suite:

```bash
cd /path/to/libcxlmi/build
meson test python-bindings -v
```

## Documentation

See the main libcxlmi documentation and CXL specifications for detailed information about:
- Command payloads and responses
- Return codes and error handling
- CXL topology and tunneling
- Device capabilities and features
