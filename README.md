# libcxlmi

CXL Management Interface library (libcxlmi).

[![Build](https://github.com/computexpresslink/libcxlmi/actions/workflows/build.yml/badge.svg)](https://github.com/computexpresslink/libcxlmi/actions/workflows/build.yml)
[![Test](https://github.com/computexpresslink/libcxlmi/actions/workflows/test.yml/badge.svg)](https://github.com/computexpresslink/libcxlmi/actions/workflows/test.yml)
[![Analysis](https://github.com/computexpresslink/libcxlmi/actions/workflows/analysis.yml/badge.svg)](https://github.com/computexpresslink/libcxlmi/actions/workflows/analysis.yml)
[![ABI](https://github.com/computexpresslink/libcxlmi/actions/workflows/abi.yml/badge.svg)](https://github.com/computexpresslink/libcxlmi/actions/workflows/abi.yml)
[![Spelling](https://github.com/computexpresslink/libcxlmi/actions/workflows/spelling.yml/badge.svg)](https://github.com/computexpresslink/libcxlmi/actions/workflows/spelling.yml)
[![Coverity](https://scan.coverity.com/projects/31615/badge.svg)](https://scan.coverity.com/projects/computexpresslink-libcxlmi)

CXL Management Interface utility library provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, send and decode CCI commands and payloads over both
in-band (Linux) and out-of-band (OoB) link, typically MCTP-based
CCIs over I2C or VDM. As such, users will mostly be BMC, firmware
and/or fabric managers, targeting: Type3 SLD, Type3 MLD
(FM owned) or a CXL Switch.

Actual management of CXL components is done through the Component Command
Interface (CCI), which represents a command, and can be either Mailbox
Registers or MCTP-based.

Keeping in mind the lack of safety provided by the in-band (OS driver)
equivalent, benefits for OoB management include:
- Single development environment (BMC).
- Works on any host OS.
- Does not require an OS (pre-boot).

Abstractions
------------

Unlike the actual CCI commands described below, the library provided
abstractions (data structures) listed here are opaque, and therefore
individual members cannot be directly referenced.

- `struct cxlmi_ctx`: library context object - holds general information
common to all opened/tracked endpoints as well as library settings. Before
component enumeration, a new context must be created via `cxlmi_new_ctx()`,
providing basic logging information. And once finished with it, the
`cxlmi_free_ctx()` counterpart must be called.

- `struct cxlmi_endpoint`: A CXL component may include different types
of CCIs, which operate independently. As such library endpoint represents
a specific type: either MCTP-based or the Linux ioctl interface for raw
primary Mailbox registers. For MCTP, an endpoint will be the component
that holds the MCTP address (EID), and receives request messages. Endpoint
creation is done by opening an MCTP endpoint through `cxlmi_open_mctp()`.
Similarly, opening a Linux CXL device is done through `cxlmi_open()`. The
respective housekeeping is done with the `cxlmi_close()` counterpart.
Given a context, all tracked endpoints in the system can be reached with
the (and related) `cxlmi_for_each_endpoint()` iterator.

While a library context can track different representations of CCIs for
the same underlying CXL component, duplicates of each type is forbidden.
This matches the component requirement of 1:1 MCTP and a primary Mailbox
(secondary is ignored in Linux). For example, if already open, the same
MCTP endpoint cannot be opened again.


Component discovery
-------------------
- Individual, MCTP-specific `nid:eid` endpoint by using `cxlmi_open_mctp()`.
  This will setup the path for CCI commands to be sent. By default, it will
  also probe the endpoint to get the CXL component this belongs to: either
  a Switch or a Type3 device. This auto-probing can be disabled with
  `cxlmi_set_probe_enabled()` or with the `$LIBCXLMI_PROBE_ENABLED` environment
  variable. Potential reasons to disable probing are wanting to avoid
  the necessary Identify command and/or disabling the FM-API.

- Enumerate all MCTP endpoints with `cxlmi_scan_mctp()`. Each found endpoint
  will be subject to the above treatment.

- Individual, Linux-specific `device` endpoint by using `cxlmi_open()`. This
  is for in-band communication through ioctl for Mailbox based raw CXL commands.

- Enumerate all Linux CXL devices with `cxlmi_scan()`. This function scans the
  `/dev/cxl/` directory for available CXL devices and opens each one found.
  Each found endpoint will be subject to the same treatment as `cxlmi_open()`.

Issuing CCI commands
--------------------
Once an endpoint is open, commands may be sent to the CXL component, for which
response timeouts are configurable through `cxlmi_endpoint_set_timeout()`,
taking into account any maximum values defined by the transport. For example,
for MCTP-based that is 2 seconds. Similarly, the `cxlmi_endpoint_get_timeout()`
counterpart may be used to obtain the timeout value.

API for sending commands is very ad-hoc to the CXL specification, such as for
payload input and output. As such, the user is expected to know what to look
for in each case, accessing particular structure members, for example.

The names of both the functions to send commands and the CXL-defined payload
data structures follow a `cxlmi_cmd_[memdev|fmapi_]<cmdname>()` format. All
payload structures use consistent naming with `_req` suffix for input
payloads and `_rsp` suffix for output payloads. Commands that return
raw data (such as Get LSA or Log commands) use a `void *ret` parameter instead
of a structured response, for which the user is expected to handle the buffer
accordingly.

Naturally, `memdev` and `fmapi` corresponds to the respective command set,
otherwise the command belongs to the Generic Component set. Vendor-specific
commands can use `cxlmi_cmd_vendor_specific()` passing the opcode, along with
any input and/or output buffers, with their respective sizes.

When sending any CXL command, the passed parameters, in addition to the
corresponding endpoint and respective payload information, must indicate the
way the command will be issued: either directly (such as the case of a SLD) or
through tunneling (such as the CXL-spec images below). For the library, this
is done by passing a `struct cxlmi_tunnel_info` armed with the necessary
information - otherwise, direct calls can simply pass NULL. The possible tunnel
targets can be armed with the respective helper: `DEFINE_CXLMI_TUNNEL_SWITCH()`,
which needs the port number to be passed, `DEFINE_CXLMI_TUNNEL_MLD()` which needs
the LD id and `DEFINE_CXLMI_TUNNEL_SWITCH_MLD()`, which needs both for the
respective inner and outer tunnels as arguments.

1. Tunneling Commands to an MLD through a CXL Switch.

<img src="http://stgolabs.net/tunnel0.png" width="650" height="260">

   ```C
   struct cxlmi_cmd_fmapi_set_ld_allocations_req *alloc_req;
   struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *alloc_rsp;
   DEFINE_CXLMI_TUNNEL_SWITCH(ti, 1);

   /* prepare payload buffers... */

   rc = cxlmi_cmd_fmapi_set_ld_allocations(ep, &ti, alloc_req, alloc_rsp);
   if (rc) {
	   /* handle error */
   }
   ```

2. Tunneling Commands to an LD in an MLD.

When sent to an MLD, the provided command is tunneled by the FM-owned LD to
the specified LD.

<img src="http://stgolabs.net/tunnel1.png" width="650" height="260">

   ```C
   struct cxlmi_cmd_memdev_set_lsa_req *lsa = arm_lsa(offset, data);
   DEFINE_CXLMI_TUNNEL_MLD(ti, 1);

   rc = cxlmi_cmd_memdev_set_lsa(ep, &ti, lsa);
   if (rc) {
	   /* handle error */
   }
   ```

3. Tunneling Commands to an LD in an MLD through a CXL Switch.

An additional layer of tunneling is needed for commands issued on LDs in an MLD
that is accessible through an MLD port of a CXL Switch.

<img src="http://stgolabs.net/tunnel2.png" width="850 " height="260">

   ```C
   struct cxlmi_cmd_memdev_set_lsa_req *lsa = arm_lsa(offset, data);
   DEFINE_CXLMI_TUNNEL_SWITCH_MLD(ti, 3, 1);

   rc = cxlmi_cmd_memdev_set_lsa(ep, &ti, lsa);
   if (rc) {
	   /* handle error */
   }
   ```

4. Tunneling Commands to the LD Pool CCI in a Multi-Headed Device.

<img src="http://stgolabs.net/tunnel3.png" width="650" height="260">

   ```C
   struct cxlmi_cmd_fmapi_get_multiheaded_info_req req = {
	  .start_ld_id = 0,
	  .ld_map_list_limit = 4,
   };
   struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp *rsp;
   DEFINE_CXLMI_TUNNEL_MHD(ti);

   /* prepare payload return buffer... */

   err = cxlmi_cmd_fmapi_get_multiheaded_info(ep, &ti, &req, rsp);
   if (!err) {
	   for (i = 0; i < rsp->ld_map_len; i++)
		   /* do something with rsp->map[i] */
   }
   ```

Commands with simple payload input/output can use stack-allocated variables,
while more complex ones require the user to already provide the respective payload
buffer. Next are a few examples for sending commands directly.

1. Input-only payload

   ```C
   struct cxlmi_cmd_set_timestamp_req ts = {
	  .timestamp = 946684800, /* Jan 1, 2000 */
   };

   err = cxlmi_cmd_set_timestamp(ep, NULL, &ts);
   if (err) {
	   /* handle error */
   }
   ```

2. Output-only payload

   ```C
   struct cxlmi_cmd_get_timestamp_rsp ts;

   err = cxlmi_cmd_get_timestamp(ep, NULL, &ts);
   if (!err) {
	   /* do something with ts.timestamp */
   }
   ```

3. Input and output payloads

   ```C
   struct cxlmi_cmd_get_log_req in = {
	   .offset = 0,
	   .length = cel_size,
   };
   struct cxlmi_cmd_get_log_cel_rsp *ret = calloc(1, cel_size);

   memcpy(in.uuid, cel_uuid, sizeof(in.uuid));
   err = cxlmi_cmd_get_log_cel(ep, NULL, &in, ret);
   if (err == 0) {
	   /* do something with ret[i].opcode */
   }
   free(ret);
   ```

4. No input, no output payload

   ```C
   err = cxlmi_cmd_request_bg_operation_abort(ep, NULL);
   if (err) {
	   /* handle error */
   }
   ```

When sending a command to a device, a return of `0` indicates success.
Otherwise `-1` is returned to indicate a problem sending the command, while
`> 0` corresponds to the CXL defined returned code `cxlmi_cmd_retcode`,
which can be translated to a string with `cxlmi_cmd_retcode_tostr()`.
Upon error, the return payload is undefined and should be considered invalid.

   ```C
   err = cxlmi_cmd_fmapi_identify_switch_device(ep, NULL, &ret);
   if (err) {
	   if (err > 0)
		   fprintf(stderr, "%s", cxlmi_cmd_retcode_tostr(err));
	   return err;
   }
   ```

The exception to this is when a background operation has been started,
which is considered a successful return value. The user must ensure to
verify, when appropriate, against the `CXLMI_RET_BACKGROUND` value.

   ```C
   err = cxlmi_cmd_memdev_sanitize(ep, NULL);
   if (err && err != CXLMI_RET_BACKGROUND) {
	   if (err > 0)
		   fprintf(stderr, "%s", cxlmi_cmd_retcode_tostr(err));
	   return err;
   }
   ```

Note that CXL does not specify background contexts, so users polling for
bg command completions can race with hardware starting a new command.

FM-API Management
-----------------
By default, an endpoint will allow FM-API commands, *if* supported by the
CXL component (or implicitly by disabling probing, see Component Discovery
section above). To check if such command set is supported, `cxlmi_endpoint_has_fmapi()`
can be called. Similarly, to control it (disable/enable) dynamically,
`cxlmi_endpoint_disable_fmapi()` and `cxlmi_endpoint_enable_fmapi()` can be used.

This will impact, for example, on whether or not tunneling is available as a
form of sending commands. Naturally, if FM-API is disabled/unsupported, any
tunneled command will fail. One distinction is that if disabled by the user,
the failure is at the library level, while unsupported is the expected hardware
return via `CXLMI_RET_UNSUPPORTED`.

Logging
-------
Library internal logging information is set upon context creation, using `stderr`
by default. Logging levels are standard `syslog`.


Considerations
--------------
A few things to consider when evaluating using this library:

- The library leaves any and all serialization up to the user - libs should not
hold locks.

- The library is endianness-aware.

- Users must provide the correct command to the correct CXL component. Similarly
device state may be altered by command semantics, and therefore users get to keep
the pieces.

- Commands initiated on MCTP-based CCIs are not tracked across any component state
change, such as Conventional Resets.

- G-FAM devices (GFD) and multiple hosts are currently unsupported.

- CXL r3.1 + DMTF binding specs are not clear on what Message type is used for the
generic command set - these can be issued to either a switch or a type 3 device.
The assumption here is that for those command either smctp_type is fine.

API References
==============

- [Generic Component Commands](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md)

- [Memory Device Commands](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md)

- [FM-API](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md)

- [Vendor Specific Commands](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Vendor-Specific-Commands.md)

FAQ
===

- How is this library different from ndctl's libcxl?
`libcxlmi` aims to be a CXL Swiss army knife to interact with CXL component(s)
through CCI command(s), both in and out of band transports. The user is given
full freedom to send any command to any device. `libcxl`, on the other hand,
is very much tied to Linux, acting as wrappers for sysfs and ioctl interfaces,
and hence provides more safety by the CXL driver itself.

- What CXL version does this library support? Similar to how qemu and the kernel
driver work, libcxlmi loosely supports all versions of the CXL specification.
While originally developed against 3.1, it also supports functionality from
earlier (2.0) and later versions of CXL.


Requirements
============
1. arm64 or x86-64 architecture.

2. Linux kernel v5.15+ for MCTP support (as well as header files).

3. Enabling use of aspeed-i2c with ACPI **out-of-tree** series
   https://lore.kernel.org/all/20230531100600.13543-1-Jonathan.Cameron@huawei.com/

4. Kernel configurations enabled (and RAW command support for ioctl):
   ```
   CONFIG_MCTP_TRANSPORT_I2C=y
   CONFIG_MCTP=y
   CONFIG_MCTP_FLOWS=y
   CONFIG_I2C_ASPEED=y
   CONFIG_CXL_MEM_RAW_COMMANDS=y
   ```

For more info, refer to https://gitlab.com/jic23/cxl-fmapi-tests


Build
=====
This project uses the `meson` build system.

1. To configure as a shared library (default):

```
meson setup build
```
Alternatively, to configure for static libraries:
```
meson setup --default-library=static build
```
Also, to configure with dbus support to enable MCTP scanning:
```
meson setup -Dlibdbus=enabled -Dmctpd=(openbmc | codeconstruct) build
```
The `mctpd` option defaults to "openbmc", but "codeconstruct" can also be specified, which refers to CodeConstruct's
[mctpd v2](https://codeconstruct.com.au/docs/mctp-utils-v2-0-release/).

To enable CXL 2.0 compatibility mode:
```
meson setup build -Dcxl2_0_mode=enabled
```
This mode adjusts payload structures and behavior to be compatible with CXL 2.0 specification requirements. By default, the library targets CXL 3.x specifications. The affected commands include Get/Set Event Interrupt Policy and related event management commands where payload structures changed between CXL versions.

To configure a build for debugging purposes (i.e. optimization turned
off and debug symbols enabled):

```bash
meson setup build --buildtype=debug
```

To enable address sanitizer (advanced debugging of memory issues):

```bash
meson setup build -Db_sanitize=address
```

This option adds `-fsanitize=address` to the gcc options.

Note that when using the sanitize feature, the library `libasan.so` must be available and must be the very first library loaded when running an executable. If experiencing linking issues, ensure that `libasan.so` gets loaded first with the `LD_PRELOAD` environment variable as follows:

It's also possible to enable the undefined behavior sanitizer with `-Db_sanitize=undefined`. To enable both, use `-Db_sanitize=address,undefined`.

2. Then compile it:
```
meson compile -C build
```
3. Optionally, to install:
```
meson install -C build
```
4. To purge everything:
```
rm -rf build
```

Testing
=======

The library includes a mock transport layer for unit testing without hardware.
To run the tests:

```
meson setup build
meson test -C build
```

The mock transport intercepts commands at the transport layer, exercising the
complete command encoding/decoding path including endianness conversion. This
enables testing of all CCI commands without CXL hardware.

Include `<cxlmi/test.h>` for the mock API:

```C
#include <libcxlmi.h>
#include <cxlmi/test.h>

struct cxlmi_ctx *ctx = cxlmi_new_ctx(stderr, LOG_ERR);
struct cxlmi_endpoint *ep = cxlmi_open_mock(ctx);

/* Configure a mock response */
struct cxlmi_cmd_identify_rsp rsp = { .vendor_id = 0x1234 };
cxlmi_mock_set_response(ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));

/* Send the command - it will receive the configured response */
struct cxlmi_cmd_identify_rsp ret;
int rc = cxlmi_cmd_identify(ep, NULL, &ret);

cxlmi_close(ep);
cxlmi_free_ctx(ctx);
```

Code Coverage
-------------
To generate code coverage reports (requires `lcov` or `gcovr`):

```bash
meson setup build-coverage -Db_coverage=true
meson compile -C build-coverage
meson test -C build-coverage
ninja -C build-coverage coverage-html
```

The HTML report will be at `build-coverage/meson-logs/coveragereport/index.html`.

For detailed documentation on the mock testing infrastructure, coverage
reporting, and fuzz testing, see [docs/Testing.md](docs/Testing.md).

Linking
=======

Programs making use of this library must include the `libcxlmi.h` header file
and link with `-lcxlmi`.


References
==========
- This library has been influenced by cxl-fmapi-tests and libnvme(-mi).
- CXL Specifications.
- CXL Type3 Device Component Command Interface over MCTP Binding Specification (DSP0281).
- CXL Fabric Manager API over MCTP Binding Specification (DSP0324).

Resources
=========
- [libcxlmi: CXL Management Interface library (LPC24)](https://lpc.events/event/18/contributions/1876/attachments/1441/3072/lpc24-dbueso-libcxlmi.pdf)

- [How To Add a Command with an FMAPI DCD Example](https://github.com/computexpresslink/libcxlmi/blob/main/docs/How-To-Add-A-Command.md)
