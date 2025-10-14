// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */

%module cxlmi

%{
#define SWIG_FILE_WITH_INIT
#include "libcxlmi.h"
#include "cxlmi/api-types.h"
%}

/* Tell SWIG to ignore GCC attributes */
#define __attribute__(x)

/* Ignore flexible array members that SWIG can't handle
 *
 * These are C99 flexible array members (e.g., uint8_t data[]) at the end of structs.
 * SWIG cannot expose these to Python because:
 * 1. They have no fixed size - the actual size depends on the command/response
 * 2. They're part of variable-length wire protocol structures
 * 3. Python has no direct equivalent to C flexible array members
 *
 * This is NOT a problem for users because:
 * - The structures themselves are fully usable from Python
 * - Users create and populate these structures normally
 * - The C library functions handle the flexible arrays internally
 * - For reading data from flexible arrays, the C API provides dedicated getter functions
 * - This is the standard approach for SWIG bindings (same pattern as libnvme)
 *
 * Example: cxlmi_cmd_get_event_records_rsp has a 'records[]' flexible array.
 * Users call cxlmi_cmd_get_event_records() which returns the struct, and the
 * records are accessed through the struct's fixed-size fields and length counters.
 */
%ignore cxlmi_cmd_identify_rsp::component_specific_ident_data;
%ignore cxlmi_cmd_get_event_records_rsp::records;
%ignore cxlmi_cmd_clear_event_records::handles;
%ignore cxlmi_cmd_get_fw_info::fw_slot_info;
%ignore cxlmi_cmd_get_supported_logs::entries;
%ignore cxlmi_cmd_get_log_cel_rsp::entries;
%ignore cxlmi_cmd_memdev_identify::reserved;
%ignore cxlmi_cmd_memdev_get_lsa::lsa_data;
%ignore cxlmi_cmd_memdev_get_poison_list_rsp::media_error_records;
%ignore cxlmi_cmd_get_scan_media_results::media_error_list;
%ignore cxlmi_cmd_memdev_media_operations_discovery_rsp::supported_list;
%ignore cxlmi_cmd_memdev_media_operations_sanitize::dpa_range_list;
%ignore cxlmi_cmd_memdev_security_send::security_payload;
%ignore cxlmi_cmd_fmapi_identify_sw_device::reserved;
%ignore cxlmi_cmd_fmapi_get_phys_port_state_rsp::port_info_list;
%ignore cxlmi_cmd_fmapi_get_ld_allocations_req::range1_ld_list;
%ignore cxlmi_cmd_fmapi_get_ld_allocations_req::range2_ld_list;
%ignore cxlmi_cmd_fmapi_get_ld_allocations_rsp::range1_ld_list;
%ignore cxlmi_cmd_fmapi_get_ld_allocations_rsp::range2_ld_list;
%ignore cxlmi_cmd_fmapi_set_ld_allocations_req::range1_ld_list;
%ignore cxlmi_cmd_fmapi_set_ld_allocations_rsp::range1_ld_list;
%ignore cxlmi_cmd_fmapi_get_qos_allocated_bw_req::num_ports;
%ignore cxlmi_cmd_fmapi_set_qos_allocated_bw::allocated_bw;
%ignore cxlmi_cmd_fmapi_get_qos_bw_limit_req::num_ports;
%ignore cxlmi_cmd_fmapi_set_qos_bw_limit::bw_limit;
%ignore cxlmi_cmd_fmapi_get_multiheaded_info_rsp::head_info_list;
%ignore cxlmi_cmd_fmapi_get_multiheaded_info_blkfmt::reserved;

%include "stdint.i"
%include "cstring.i"
%include "carrays.i"

/* Exception handling for C library error codes
 *
 * These %exception directives convert C-style error return codes into Python exceptions,
 * providing idiomatic Python error handling instead of requiring manual return code checks.
 *
 * WITHOUT exception handlers:
 *   ret = cxlmi.cxlmi_scan(ctx)
 *   if ret < 0:
 *       # Handle error - users might forget to check!
 *
 * WITH exception handlers:
 *   try:
 *       num = cxlmi.cxlmi_scan(ctx)  # Raises exception automatically on error
 *   except IOError as e:
 *       print(f"Error: {e}")
 *
 * Benefits:
 * 1. Pythonic error handling - uses try/except instead of checking return codes
 * 2. Better error messages - converts numeric codes to descriptive strings
 * 3. Type safety - different exception types (IOError vs RuntimeError) for different errors
 * 4. Prevents silent failures - errors can't be accidentally ignored
 *
 * The $action macro executes the wrapped C function, and 'result' contains its return value.
 */

/* Exception handler for all CXL Management Interface commands
 *
 * Applies to all functions starting with "cxlmi_cmd_" (wildcard match).
 *
 * C API return semantics:
 *   return 0  = Success
 *   return <0 = I/O or system error (e.g., device not responding, permission denied)
 *   return >0 = CXL protocol error code (e.g., UNSUPPORTED, INVALID_INPUT, etc.)
 *
 * Python exception mapping:
 *   result < 0  -> IOError("CXLMI command failed")
 *   result > 0  -> RuntimeError("CXLMI error: <description> (code N)")
 *
 * The error code is converted to a human-readable string using cxlmi_cmd_retcode_tostr().
 */
%exception cxlmi_cmd_ %{
    $action
    if (result < 0) {
        PyErr_SetString(PyExc_IOError, "CXLMI command failed");
        SWIG_fail;
    } else if (result > 0) {
        char buf[256];
        const char *msg = cxlmi_cmd_retcode_tostr((enum cxlmi_cmd_retcode)result);
        if (msg) {
            snprintf(buf, sizeof(buf), "CXLMI error: %s (code %d)", msg, result);
        } else {
            snprintf(buf, sizeof(buf), "CXLMI error: Unknown error code %d", result);
        }
        PyErr_SetString(PyExc_RuntimeError, buf);
        SWIG_fail;
    }
%}

%exception cxlmi_scan_mctp %{
    $action
    if (result < 0) {
        PyErr_SetString(PyExc_IOError, "MCTP scan failed");
        SWIG_fail;
    }
%}

%exception cxlmi_scan %{
    $action
    if (result < 0) {
        PyErr_SetString(PyExc_IOError, "CXL device scan failed");
        SWIG_fail;
    }
%}

%exception cxlmi_endpoint_set_timeout %{
    $action
    if (result < 0) {
        PyErr_SetString(PyExc_IOError, "Failed to set timeout");
        SWIG_fail;
    }
%}

/* Opaque structure handling */
%nodefaultctor cxlmi_ctx;
%nodefaultdtor cxlmi_ctx;
%nodefaultctor cxlmi_endpoint;
%nodefaultdtor cxlmi_endpoint;

/* Custom typemaps for FILE* - Python 3 compatible */
%typemap(in) FILE* {
    if ($input == Py_None) {
        $1 = NULL;
    } else {
        int fd = PyObject_AsFileDescriptor($input);
        if (fd < 0) {
            PyErr_SetString(PyExc_TypeError, "Expected file object or file descriptor");
            SWIG_fail;
        }
        $1 = fdopen(dup(fd), "w");
    }
}

/* Tunnel info helpers - convert None to NULL */
%typemap(in) struct cxlmi_tunnel_info * (struct cxlmi_tunnel_info temp) {
    if ($input == Py_None) {
        $1 = NULL;
    } else {
        /* SWIG will handle the conversion */
        void* argp = 0;
        int res = SWIG_ConvertPtr($input, &argp, $descriptor, 0);
        if (!SWIG_IsOK(res)) {
            SWIG_exception_fail(SWIG_ArgError(res), "in method '$symname', argument $argnum of type '$type'");
        }
        $1 = (struct cxlmi_tunnel_info *)argp;
    }
}

/* Handle output buffers for commands */
%typemap(in, numinputs=0) void *ret (char temp[CXL_MAILBOX_MAX_PAYLOAD_SIZE]) {
    $1 = (void*)temp;
}

%typemap(argout) void *ret {
    /* Return the output buffer as bytes */
    PyObject *bytes = PyBytes_FromStringAndSize((char*)$1, CXL_MAILBOX_MAX_PAYLOAD_SIZE);
    $result = SWIG_AppendOutput($result, bytes);
}

/* Handle variable-length input/output buffers for vendor commands */
%apply (char *STRING, size_t LENGTH) { (void *in, ssize_t in_size) };
%typemap(in, numinputs=0) (void *ret, ssize_t ret_size) (char temp[CXL_MAILBOX_MAX_PAYLOAD_SIZE], ssize_t size) {
    size = sizeof(temp);
    $1 = (void*)temp;
    $2 = size;
}

%typemap(argout) (void *ret, ssize_t ret_size) {
    PyObject *bytes = PyBytes_FromStringAndSize((char*)$1, $2);
    $result = SWIG_AppendOutput($result, bytes);
}

/* Arrays for event records and other variable-length structures */
%array_functions(struct cxlmi_event_record, EventRecordArray);
%array_functions(struct cxlmi_supported_log_entry, SupportedLogEntryArray);
%array_functions(struct cxlmi_memdev_media_err_record, MediaErrRecordArray);
%array_functions(struct cxlmi_cmd_fmapi_port_state_info_block, PortStateInfoArray);
%array_functions(struct cxlmi_dc_region_config, DCRegionConfigArray);
%array_functions(struct cxlmi_fmapi_dc_region_config, FMAPIDCRegionConfigArray);

/* Generic helpers for accessing fixed-size byte/char arrays in structures
 *
 * Since SWIG wraps fixed-size arrays (uint8_t foo[32]) as opaque pointers,
 * these helpers provide a way to read/write them from Python.
 *
 * Example Python usage:
 *   req = cxlmi.cxlmi_cmd_memdev_set_passphrase_req()
 *
 *   # Set passphrase fields (32 bytes each)
 *   cxlmi.array_set(req.current_passphrase, b'oldpass' + b'\x00' * 25, 32)
 *   cxlmi.array_set(req.new_passphrase, b'newpass' + b'\x00' * 25, 32)
 *
 *   # Get passphrase as bytes
 *   old_pass = cxlmi.array_get(req.current_passphrase, 32)
 *
 *   # Access struct arrays using generated array functions
 *   rsp = cxlmi.cxlmi_cmd_memdev_get_dc_config_rsp()
 *   region = cxlmi.DCRegionConfigArray_getitem(rsp.region_configs, 0)
 *   print(region.base, region.decode_len)
 */

/* Exception handler for array_set - properly propagate Python exceptions */
%exception cxlmi_array_set %{
    $action
    if (PyErr_Occurred()) {
        SWIG_fail;
    }
%}

%inline %{
#include <string.h>

/* Get array data as Python bytes object */
PyObject* cxlmi_array_get(void *array_ptr, size_t size) {
    if (!array_ptr) {
        PyErr_SetString(PyExc_ValueError, "NULL pointer");
        return NULL;
    }
    return PyBytes_FromStringAndSize((char*)array_ptr, size);
}

/* Set array data from Python bytes, with automatic zero-padding if needed
 * Raises Python exception on error (checked by %exception handler above) */
void cxlmi_array_set(void *array_ptr, PyObject *data, size_t array_size) {
    if (!array_ptr) {
        PyErr_SetString(PyExc_ValueError, "NULL array pointer");
        return;
    }
    if (!PyBytes_Check(data)) {
        PyErr_SetString(PyExc_TypeError, "Expected bytes object");
        return;
    }
    Py_ssize_t data_len = PyBytes_Size(data);
    if (data_len > (Py_ssize_t)array_size) {
        PyErr_Format(PyExc_ValueError, "Data too large: %zd bytes for array of size %zu", data_len, array_size);
        return;
    }
    memcpy(array_ptr, PyBytes_AsString(data), data_len);
    /* Zero-pad remaining space if data is shorter than array */
    if (data_len < (Py_ssize_t)array_size) {
        memset((uint8_t*)array_ptr + data_len, 0, array_size - data_len);
    }
}
%}

/* Rename helper functions for tunnel definitions */
%inline %{
struct cxlmi_tunnel_info *cxlmi_tunnel_mld(int ld) {
    struct cxlmi_tunnel_info *ti = malloc(sizeof(struct cxlmi_tunnel_info));
    if (ti) {
        ti->port = -1;
        ti->ld = ld;
        ti->level = 1;
        ti->mhd = 0;
    }
    return ti;
}

struct cxlmi_tunnel_info *cxlmi_tunnel_switch(int port) {
    struct cxlmi_tunnel_info *ti = malloc(sizeof(struct cxlmi_tunnel_info));
    if (ti) {
        ti->port = port;
        ti->ld = -1;
        ti->level = 1;
        ti->mhd = 0;
    }
    return ti;
}

struct cxlmi_tunnel_info *cxlmi_tunnel_switch_mld(int port, int ld) {
    struct cxlmi_tunnel_info *ti = malloc(sizeof(struct cxlmi_tunnel_info));
    if (ti) {
        ti->port = port;
        ti->ld = ld;
        ti->level = 2;
        ti->mhd = 0;
    }
    return ti;
}

struct cxlmi_tunnel_info *cxlmi_tunnel_mhd(void) {
    struct cxlmi_tunnel_info *ti = malloc(sizeof(struct cxlmi_tunnel_info));
    if (ti) {
        ti->port = -1;
        ti->ld = -1;
        ti->level = 1;
        ti->mhd = 1;
    }
    return ti;
}

void cxlmi_tunnel_free(struct cxlmi_tunnel_info *ti) {
    free(ti);
}
%}

/* Python generator for iterating endpoints */
%pythoncode %{
def endpoints(ctx):
    """Generator to iterate over all endpoints in a context"""
    ep = cxlmi_first_endpoint(ctx)
    while ep:
        yield ep
        ep = cxlmi_next_endpoint(ctx, ep)

def for_each_endpoint_safe(ctx):
    e = cxlmi_first_endpoint(ctx)
    if e is None:
        return
    _e = cxlmi_next_endpoint(ctx, e)
    while e:
        yield e
        e, _e = _e, cxlmi_next_endpoint(ctx, _e)
%}

/* Include structure definitions from api-types.h */
%include "cxlmi/api-types.h"

%include "libcxlmi.h"
