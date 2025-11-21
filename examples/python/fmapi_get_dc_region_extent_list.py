#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Test FMAPI functionality using ctypes bindings

This example demonstrates how to:
1. Create a context
2. Open an MCTP endpoint
3. Send FMAPI DC Region Extent List
4. Display the results
"""

import sys
import ctypes
from cxlmi import *

def send_fmapi_commands(ep):
    try:
        # Create the request and response structures
        req = struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_req()

        # Set request parameters
        req.host_id = 0
        req.extent_count = 5
        req.start_ext_index = 0

        # Allocate one contiguous buffer: header + N extents
        total_size = ctypes.sizeof(struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp) + \
                    req.extent_count * ctypes.sizeof(struct_cxlmi_fmapi_dc_extent)
        buf = ctypes.create_string_buffer(total_size)

        # Create typed views into the buffer
        rsp = struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp.from_buffer(buf)
        extents = struct_cxlmi_fmapi_dc_extent * req.extent_count
        rsp_extents = extents.from_buffer(buf, ctypes.sizeof(struct_cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp))

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
            print(f"  Start DPA: {hex(ext.start_dpa)}")
            print(f"  Length: {hex(ext.len)}")

        print("Done")

    finally:
        return 0

def for_each_endpoint_safe(ctx):
    """Generator to safely iterate over endpoints"""
    e = cxlmi_first_endpoint(ctx)
    if not e:
        return
    _e = cxlmi_next_endpoint(ctx, e)
    while e:
        yield e
        e, _e = _e, cxlmi_next_endpoint(ctx, _e)

def main():
    # Create a new context with INFO log level
    ctx = cxlmi_new_ctx(None, 6)
    if not ctx:
        print("Failed to create context")
        return 1
    num_ep, nid, eid = 0, 0, 0

    if len(sys.argv) == 1:
        print("Scanning dbus....")

        num_ep = cxlmi_scan_mctp(ctx)

        if (num_ep < 0):
            print("dbus scan error")
        elif num_ep == 0:
            print("no endpoints found")
        else:
            print(f"found {num_ep} endpoint(s)")
            try:
                # Open MCTP EP
                for ep in for_each_endpoint_safe(ctx):
                    send_fmapi_commands(ep)
                    cxlmi_close(ep)
            finally:
                cxlmi_free_ctx(ctx)
    elif len(sys.argv) == 3:
        nid = int(sys.argv[1])
        eid = int(sys.argv[2])

        try:
            # Open MCTP EP
            ep = cxlmi_open_mctp(ctx, nid, eid)
            if not ep:
                print(f"Failed to open MCTP ep: {nid}:{eid}")
                return 1
            send_fmapi_commands(ep)
            cxlmi_close(ep)
        finally:
            cxlmi_free_ctx(ctx)
    else:
        print(f"Usage: {sys.argv[0]} <nid> <eid>")
        print(f"Example: {sys.argv[0]} 12 8")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())