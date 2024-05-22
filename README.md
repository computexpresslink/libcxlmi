# libcxlmi

CXL Management Interface library (libcxlmi).

CXL Management Interface utility library provides type definitions
for CXL specification structures, enumerations and helper functions to
construct, send and decode CCI commands and payloads over both
in-band (Linux) an out-of-band (OoB) link, typically MCTP-based
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
  a Switch or a Type3 device. This auto-probing can by disabled with
  `cxlmi_set_probe_enabled()` or with the `$LIBCXLMI_PROBE_ENABLED` environment
  variable. Potential reasons to disable probing are wanting to avoid
  the necessary Identify command and/or disabling the FM-API.

- Enumerate all MCTP endpoints with `cxlmi_scan_mctp()`. Each found endpoint
  will be subject to the above treatment.

- Individual, Linux-specific `device` endpoint by using `cxlmi_open()`. This
  is for in-band communication through ioctl for Mailbox based raw CXL commands.


Issuing CCI commands
--------------------
Once an endpoint is open, commands may be sent to the CXL component, for which
response timeouts are configurable through `cxlmi_endpoint_set_timeout()`,
taking into account any maximum values defined by the transport. For example,
for MCTP-based that is 2 seconds.

API for sending commands is very ad-hoc to the CXL specification, such as for
payload input and output. As such, the user is expected to know what to look
for in each case, accessing particular structure members, for example.

The names of both the functions to send commands and the CXL-defined payload
data structures are the same, using a `cxlmi_cmd_[memdev|fmapi_]<cmdname>()`
format. When there are input *and* output payloads, the `_req` and `_rsp`
suffixes are needed, respectively, for the payload names. Naturally, `memdev`
and `fmapi` corresponds to the respective command set, otherwise the command
belongs to the Generic Component set.

When sending any CXL command, the passed parameters, in addition to the
corresponding endpoint and respective payload information, must indicate the
way the command will be issued: either directly (such as the case of a SLD) or
through tunneling (such as the CXL-spec images below). For the library, this
is done by passing a `struct cxlmi_tunnel_info` armed with the necessary
information - otherwise, direct calls can simply pass NULL.

When sent to an MLD, the provided command is tunneled by the FM-owned LD to
the specified LD.

<img src="http://stgolabs.net/tunnel1.png" width="650" height="260">

   ```C
   struct cxlmi_cmd_memdev_set_lsa *lsa = arm_lsa(offset, data);
   struct cxlmi_tunnel_info ti = {
	  .level = 1,
	  .ld = 1,
   };

   rc = cxlmi_cmd_memdev_set_lsa(ep, &ti, lsa);
   if (rc) {
	   /* handle error */
   }
   ```

An additional layer of tunneling is needed for commands issued on LDs in an MLD
that is accessible through an MLD port of a CXL Switch.

<img src="http://stgolabs.net/tunnel2.png" width="850 " height="290">

   ```C
   struct cxlmi_cmd_memdev_set_lsa *lsa = arm_lsa(offset, data);
   struct cxlmi_tunnel_info ti = {
	  .level = 2,
	  .port = 3, /* outer tunnel */
	  .ld = 1, /* inner tunnel */
   };

   rc = cxlmi_cmd_memdev_set_lsa(ep, &ti, lsa);
   if (rc) {
	   /* handle error */
   }
   ```

Note that a third level tunneling commands to the LD Pool CCI in a Multi-Headed
Device (MHD) is unsupported (CXL.io).

Commands with simple payload input/output can use  stack-allocated variables,
while more complex ones require the user to already provide the respective payload
buffer. Next are a few examples for sending commands directly.

1. Input-only payload

   ```C
   struct cxlmi_cmd_set_timestamp ts = {
	  .timestamp = 946684800, /* Jan 1, 2000 */
   };

   err = cxlmi_cmd_set_timestamp(ep, NULL, &ts);
   if (err) {
	   /* handle error */
   }
   ```

2. Output-only payload

   ```C
   struct cxlmi_cmd_get_timestamp ts;

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
which can be translated to a string with `cxlmi_cmd_retcode_to_str()`.
Upon error, the return payload is undefined and should be considered invalid.

   ```C
   err = cxlmi_cmd_fmapi_identify_switch_device(ep, NULL, &ret);
   if (err) {
	   if (err > 0)
		   fprintf(stderr, "%s", cxlmi_cmd_retcode_to_str(err));
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

FM-API Management
-----------------
By default, an endpoint will allow FM-API commands, *if* supported by the
CXL component (or implicitly by disabling probing, see Component Discovery
section above). To check if such command set is supported, `cxlmi_endpoint_has_fmapi()`
can be called. Similarly, to control it disable/enable it dynamically,
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

- G-FAM devices (GFD) and multiple hosts are beyond the scope of this library,
and therefore, unsupported.

- CXL r3.1 + DMTF binding specs are not clear on what Message type is used for the
generic command set - these can be issued to either a switch or a type 3 device.
The assumption here is that for those command either smctp_type is fine.


FAQ
===

- How is this library different from ndctl's libcxl?
`libcxlmi` aims to be a CXL swiss army knife to interact with CXL component(s)
through CCI command(s), both in and out of band transports. The user is given
full freedom to send any command to any device. `libcxl`, on the other hand,
is very much tied to Linux, acting as wrappers for sysfs and ioctl interfaces,
and hence provides more safety by the CXL driver itself.

- What CXL version does this library support? Latest 3.1 version.


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
To `configure` the project as a shared library (default):

```
meson setup build;
```
Alternatively, to configure for static libraries:
```
meson setup --default-library=static build
```
Also, to configure with dbus support  to enable MCTP scanning:
```
meson setup -Dlibdbus=enabled build
```

Then compile it:
```
meson compile -C build;
```
Optionally, to install:
```
meson install -C build
```


Linking
=======

Programs making use of this library must include the `libcxlmi.h` header file
and link with `-lcxlmi`.


References
==========
- This library has been influenced by cxl-fmapi-tests and libnvme(-mi).
- CXL 3.1 Specification.
- CXL Type3 Device Component Command Interface over MCTP Binding Specification (DSP0281).
- CXL Fabric Manager API over MCTP Binding Specification (DSP0324).
