# Python Bindings for libcxlmi

This document describes the Python bindings for libcxlmi, providing Python developers with access to CXL Management Interface functionality.

The Python interface is a work-in-progress, provided as a preview of what can be done when integrating with Python.
It is not guaranteed to be stable, as there are dependencies for the binding generator,
which may break across versions. See, the [Limitations](#limitations) section for a list of known shortcomings/areas of improvement.

## Overview

The Python bindings are generated using clang2py and provide a ctypes-based interface to the libcxlmi C library. The bindings support all CXL command structures and functions through direct ctypes wrapping.

- **Generic Component Commands**: Device identification, events, firmware, logs
- **Memory Device Commands**: Capacity, health, security, dynamic capacity
- **FM-API Commands**: Fabric Manager operations, switch management, MLD operations
- **Vendor Specific Commands**: Custom vendor-defined commands

## Building with Python Support

### Prerequisites
We use the ctypeslib2 tool to generate python bindings, this requires the following:
- Python 3.6 or later
- clang compiler (clang llvm llvm-dev), 17 <= version < 20
- clang python bindings with the *same version* as the clang compiler that was installed
- ctypeslib2
    - only compatible with clang 17-19 as of Feb. 2025

Assuming you already have the clang compiler installed, for quick python package
installation (this is agnostic to your clang compiler version, so YMMV):
```
pip install src/python/requirements.txt
```

Otherwise, to install everything manually, follow the example below for Debian:
```
# Install clang compiler
sudo apt-get install clang-19 llvm-19 llvm-19-dev

# Check clang version
clang --version

Debian clang version 19.1.7 (7)
Target: x86_64-pc-linux-gnu
Thread model: posix
InstalledDir: /usr/lib/llvm-19/bin

# Start a Python venv to install Python dependencies
python3 -m venv venv

# Install clang Python bindings with the *same* version as your system clang
pip install clang==19.1.7

# Install ctypes
pip install ctypes

# Install ctypeslib2 -- this fork includes a bug fix that has not yet been merged
pip install "ctypeslib2 @ git+https://github.com/anisa-su993/anisa-ctypes2.git"
```

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

## Troubleshooting
ctypeslib2 is built on lib/ctypes, which part of the python standard library.
If you are using Python 3.12+: the ctypes.CDLL._filepath attribute was deprecated,
breaking upstream ctypeslib2 as of Novemeber 2025. This causes the following error:

```
 File "/root/libcxlmi/venv/lib/python3.13/site-packages/ctypeslib/codegen/codegenerator.py", line 804, in get_sharedlib
    print("_libraries[%r] =%s ctypes.CDLL(%r%s)" % (library._name, stub_comment, library._filepath, global_flag),
                                                                                 ^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/ctypes/__init__.py", line 403, in __getattr__
    func = self.__getitem__(name)
  File "/usr/lib/python3.13/ctypes/__init__.py", line 408, in __getitem__
    func = self._FuncPtr((name_or_ordinal, self))
AttributeError: /usr/local/lib/x86_64-linux-gnu/libcxlmi.so: undefined symbol: _filepath
```

To solve, please install this fork of ctypeslib2, which includes a fix:

```
pip install "ctypeslib2 @ git+https://github.com/anisa-su993/anisa-ctypes2.git"
```

## Limitations

1. "This param type is not defined" warning
Ex:
```
INFO:cursorhandler:This param type is not declared: uint8_t
```
ctypeslib2 uses the clang AST, which does not expose #define macros. Some uint types
in stdint may be defined as macros with #define instead of with typedef, which will
trigger this warning.

It should be safe to ignore, as ctypeslib2 will default to its built-in map of common
type conversion.

2. "Bad source code, bitsize == -16 on __" warning
Ex:
```
WARNING:cursorhandler:Bad source code, bitsize == -16 <0 on records
```
ctypeslib2 can trigger this warning for flex-arrays, as the clang AST internally represents
the size of flex arrays as -2. `cursorhandler` calculate sthe number of bits for each field of
a struct, which results in the -16.

The warning checks for cases such as having something like `int a[-4];` in the source code but
is not accurate for flex arrays. Thus, it can be safely ignored.

3. **No #define macros**: Constants (pre-processor macros from #define statements) are *not* exposed.
This is a limitation of ctypeslib2, which parses the clang AST to generate the bindings.
Pre-processor macros are not included in the AST, thus are not translated to Python.

    This includes all of the tunnel initialization helper macros:
        - `cxlmi_tunnel_mld(ld)` - Create MLD tunnel info
        - `cxlmi_tunnel_switch(port)` - Create switch tunnel info
        - `cxlmi_tunnel_switch_mld(port, ld)` - Create switch→MLD tunnel info
        - `cxlmi_tunnel_mhd()` - Create MHD tunnel info
        - `cxlmi_tunnel_free(ti)` - Free tunnel info

    tunnel_info structs can still be manually initialized. See `examples/python/tunnel_example.py` for examples each of the tunneling situations above.

    Unsupported constants include (non-comprehensive):

    ```
    CXLMI_MAX_SUPPORTED_EVENT_RECORDS  # 20
    CXLMI_MAX_SUPPORTED_LOGS           # 7
    CXL_MAILBOX_MAX_PAYLOAD_SIZE       # 2048 bytes
    ```

## Usage

### Module Import

```python
import cxlmi
```

### Struct Initialization
Python’s ctypes automatically creates a generated __init__ that accepts keyword arguments for all field names. Thus, you can initialize a struct/class with any
number of its defined fields, or none.

Unspecified fields default to zero / false / null.

For example:
```python
# Default initialize tunnel_info
ti = struct_cxlmi_tunnel_info()

# Initialize all fields
ti = struct_cxlmi_tunnel_info(
    port=3,
    ld=2,
    level=0,
    mhd=True
)

# Initialize some fields
ti = struct_cxlmi_tunnel_info(
    port=3,
    ld=2,
)
```

This applies to all structs.

### Opening IOCTL EPs
To open a specific device, use the built-in `.endcode()` function to convert a
string to `ctypes.c_char_p` because Python `str` cannot be automatically cast to
`char *`

Ex:
```python

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cxl_device>")
        print(f"Example: {sys.argv[0]} mem0")
        return 1

    device_name = sys.argv[1]

    ctx = cxlmi.cxlmi_new_ctx(None, 6)
    try:
        ep = cxlmi.cxlmi_open(ctx, device_name.encode())
        if not ep:
            print(f"Failed to open device: {device_name}")
            return 1
```

### Byte Strings
Fixed-size byte-strings are not automatically 0-padded. For example, take the
set_passphrase request struct:
```
/* CXL r3.1 Section 8.2.9.9.6.2: Set Passphrase (Opcode 4501h) */
struct cxlmi_cmd_memdev_set_passphrase_req {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t current_passphrase[0x20];
	uint8_t new_passphrase[0x20];
} __attribute__((packed));
```
The following Python assignment will fail because ctypes expects an array object of exactly the same type (c_ubyte * 32), not raw bytes.

Even if it did accept the bytes, ctypes never automatically pads them with zeros; it would truncate or reject them depending on context:
```
set_pass = cxlmi.struct_cxlmi_cmd_memdev_set_passphrase_req()
set_pass.current_passphrase = b'current_pass'
```

Use the built-in `ljust` or left-justify method to pad with 0s:
```
set_pass = cxlmi.struct_cxlmi_cmd_memdev_set_passphrase_req()
set_pass.current_passphrase = b'current_pass'.ljust(32, b'\0')
```

### Flexible Arrays

Some CXL structures contain C99 flexible array members (for example `uint8_t data[]`) at the end.
ctypeslib2 cannot create a Python attribute with a dynamic-length array, so the generated bindings declare
the flexible field as an array of length 0 (for example `records = struct_cxlmi_event_record * 0`).

--------------------------------------------------------------

The general pattern is:

1. Decide how many elements (N) you need in the flexible array.
2. Allocate one contiguous buffer using `create_string_buffer`:

```python
total_size = ctypes.sizeof(cxlmi.struct_cxlmi_cmd_get_event_records_rsp) + \
             N * ctypes.sizeof(cxlmi.struct_cxlmi_event_record)
buf = ctypes.create_string_buffer(total_size)
```

3. Create a typed view of the header using `.from_buffer()`:

```python
event_rsp = cxlmi.struct_cxlmi_cmd_get_event_records_rsp.from_buffer(buf)
```

4. Create an array type for the flexible element and make a typed view starting at the header size offset:

```python
records_type = cxlmi.struct_cxlmi_event_record * N
records = records_type.from_buffer(buf, ctypes.sizeof(cxlmi.struct_cxlmi_cmd_get_event_records_rsp))
```

5. Use `records[i]` to access or modify individual elements. Each element is a ctypes Structure so you can set fields
   directly (for example `records[0].handle = 0x100`).

Important notes and gotchas
--------------------------

- Keep a reference to the original `buf`. If it is garbage-collected the views (`event_rsp`, `records`) may become
  invalid and accessing them will crash. The easiest approach is to keep `buf` in scope for as long as you need the views.
- Use `ctypes.sizeof()` to compute header and element sizes — avoid hard-coding sizes.
- The structure packing (`_pack_`) and field order in the generated bindings already reflect the C layout; the views
  created with `from_buffer` will therefore map correctly onto the memory buffer.
- Endianness and ABI are governed by the platform and the compiled C library; the ctypes views assume the native
  platform layout.

--------------------------------------------------------

`examples/python/fmapi_get_dc_region_extent_list.py` demonstrates this pattern. It allocates a
buffer for five `struct_cxlmi_fmapi_dc_extent` entries, sends the command to the device
and reads the extent information out of the returned list.

```python
# Allocate one contiguous buffer: header + N extents
total_size = ctypes.sizeof(struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp) + \
            req.extent_count * ctypes.sizeof(struct_cxlmi_fmapi_dc_extent)
buf = ctypes.create_string_buffer(total_size)

# Create typed views into the buffer
rsp = struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp.from_buffer(buf)
extents = struct_cxlmi_fmapi_dc_extent * req.extent_count
rsp_extents = extents.from_buffer(buf, ctypes.sizeof(struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp))

# Create array for extents in response
ret = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, None, req, rsp)

if ret != 0:
    print(f"Bad rc {ret}")
    return ret

print(f"Total Extents: {rsp.total_extents}")
print(f"Extents Returned: {rsp.extents_returned}")
print(f"Extent Starting Index: {rsp.start_ext_index}")

# Access extents directly from the response structure
for i in range(rsp.extents_returned):
    ext = rsp_extents[i]
    print(f"Extent {i}:")
    print(f"  Start DPA: {ext.start_dpa}")
    print(f"  Length: {ext.len}")

print("Done")
```

Summary
-------

The `from_buffer` pattern is a safe, zero-copy way to work with C flexible array members using ctypes. The test-suite
includes examples (see `tests/python/test_cxlmi.py::test_event_records_response`) which you can reuse as a template.

### Core Library Functions

#### Context Management
- `cxlmi.cxlmi_new_ctx(fp, log_level)` - Create library context
- `cxlmi.cxlmi_free_ctx(ctx)` - Free context
- `cxlmi.cxlmi_set_probe_enabled(ctx, enabled)` - Enable/disable automatic probing

#### Endpoint Opening and Scanning
- `cxlmi.cxlmi_open(ctx, devname)` - Open CXL device (e.g., "mem0")
- `cxlmi.cxlmi_open_mctp(ctx, net, eid)` - Open MCTP endpoint
- `cxlmi.cxlmi_scan(ctx)` - Scan /dev/cxl/ for ioctl endpoints
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

### Usage Examples

#### Context Management

```python
# Create a new context
ctx = cxlmi.cxlmi_new_ctx(None, 0)  # NULL log file, log level 0

# Enable/disable automatic probing
cxlmi.cxlmi_set_probe_enabled(ctx, True)

# Scan for ioctl endpoints in /dev/cxl/
num_ioctl_eps = cxlmi.cxlmi_scan(ctx)
print(f"Found {num_ioctl_eps} ioctl endpoints")

# Scan for MCTP endpoints
num_mctp_eps = cxlmi.cxlmi_scan_mctp(ctx)
print(f"Found {num_mctp_eps} MCTP endpoints")

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

The bindings use ctypes error handling. Functions may raise:
- `ctypes.ArgumentError` - Invalid argument types
- `OSError` - Library loading or system call errors
- `ValueError` - Invalid parameter values

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

## Examples

Complete example programs are provided in the `examples/python/` directory demonstrating various aspects of the library.

### Running Examples

Make sure the Python module is in your PYTHONPATH or has been installed via the
`meson install` command:

```bash
export PYTHONPATH=/path/to/libcxlmi/build/src/python:$PYTHONPATH
export LD_LIBRARY_PATH=/path/to/libcxlmi/build/src:$LD_LIBRARY_PATH
```

Then run any example:

```bash
python3 identify_device.py
python3 get_partition_info.py mem0
```

### Type Definitions

The bindings include common C types mapped to Python:
- `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`
- `int8_t`, `int16_t`, `int32_t`, `int64_t`
- Custom types like `c_int128` and `c_uint128`

## Testing

The Python bindings include unit tests in `tests/python/test_cxlmi.py`:

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

### Memory Management

The bindings are ctypes-based, so memory ownership follows C semantics but is represented with ctypes types in Python. Key points:

- Context and endpoint objects are opaque C pointers exposed as ctypes POINTER types (for example the result of
  `cxlmi.cxlmi_new_ctx()` is a `ctypes.POINTER(struct_cxlmi_ctx)`). These objects are owned by the C library and
  must be released with the corresponding C free functions exposed in the bindings:

```python
ctx = cxlmi.cxlmi_new_ctx(None, 6)
...
cxlmi.cxlmi_free_ctx(ctx)

ep = cxlmi.cxlmi_open(ctx, b"mem0")
...
cxlmi.cxlmi_close(ep)
```

- Tunnel info is represented as a ctypes Structure (`struct_cxlmi_tunnel_info`). You normally create it in Python and
  pass it by reference to command functions. If the C library provides helper functions that allocate tunnel info for
  you, follow those helpers' ownership rules (and free with the corresponding C free function if provided). Example of
  the common case where Python owns the struct:

```python
ti = cxlmi.struct_cxlmi_tunnel_info()
ti.port = -1
ti.ld = 0
ti.level = 1
ti.mhd = False
# pass ctypes.byref(ti) or ti directly depending on the function signature
```

- Command request/response structures are plain `ctypes.Structure` instances allocated in Python. They are garbage
  collected by Python when no longer referenced. Pass them to C calls using `ctypes.byref()` or by passing the object
  when the binding's argtypes expect a pointer.

- Flexible-array members (C99 flexible arrays declared as `type name[]`) are represented in the generated bindings as
  a zero-length array type at the end of the structure. To use them you must allocate a contiguous buffer large enough
  for the header plus N elements and create typed views with `.from_buffer()` (see the Flexible Array Members section
  for an example). Importantly, keep the original buffer object alive for as long as you need the views to avoid
  use-after-free crashes.

- Functions that return `char *` or `const char *` (for example string helpers) will usually be declared with a
  `ctypes.POINTER(ctypes.c_char)` or `ctypes.c_char_p` restype. Convert these to Python strings using `ctypes.cast(...).value`
  or the generated helper functions such as `string_cast()` if provided:

```python
# function declared as returning POINTER(c_char)
ptr = cxlmi.cxlmi_cmd_retcode_tostr(cxlmi.CXLMI_RET_UNSUPPORTED)
msg = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
# or if the generated bindings provide a helper:
msg = cxlmi.string_cast(ptr)
```

- If a C function allocates memory that the caller must free (rare and always documented in the C API), the bindings
  will generally expose a matching free function. Only call the free function if the C API specifies the caller owns
  the memory.

Summary: Python code allocates and passes ctypes structures and buffers; release C-owned opaque pointers with the
library-provided free functions; keep manually-created buffers alive while using `.from_buffer()` views; and use the
provided string/utility helpers for safe conversions between C pointers and Python types.

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

For questions or issues with the Python bindings, please open an issue at the libcxlmi repository.