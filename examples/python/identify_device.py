#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Identify a CXL device using ctypes bindings

This example demonstrates how to:
1. Create a context
2. Open an MCTP endpoint
3. Send an Identify command
4. Display the results
"""

import sys
from cxlmi import *

def send_identify(ep):
    ret = 0
    try:
        # Create the identify response structure
        ident = struct_cxlmi_cmd_identify_rsp()

        # Send the identify command (no tunneling)
        ret = cxlmi_cmd_identify(ep, None, ident)

        # Display the results
        print("CXL Device Identification:")
        print(f"  Vendor ID:          0x{ident.vendor_id:04x}")
        print(f"  Device ID:          0x{ident.device_id:04x}")
        print(f"  Subsystem Vendor:   0x{ident.subsys_vendor_id:04x}")
        print(f"  Subsystem ID:       0x{ident.subsys_id:04x}")
        print(f"  Serial Number:      0x{ident.serial_num:016x}")
        print(f"  Max Message Size:   {ident.max_msg_size}")
        print(f"  Component Type:     0x{ident.component_type:02x}")

        # Decode component type
        comp_types = {
            0x00: "Type 3 Device",
            0x01: "Type 2 Device",
            0x02: "Type 1 Device",
            0x03: "Logical Device",
            0x04: "FM-Owned LD in MLD",
            0x05: "Switch",
        }
        comp_type_str = comp_types.get(ident.component_type, "Unknown")
        print(f"                      ({comp_type_str})")

    finally:
        if ret != 0:
            print(f"Error: rc = {ret}")

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
                    send_identify(ep)
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
            send_identify(ep)
            cxlmi_close(ep)
        finally:
            cxlmi_free_ctx(ctx)
    else:
        print(f"Usage: {sys.argv[0]} | {sys.argv[0]} <nid> <eid>")
        print(f"Example: {sys.argv[0]} 12 8")
        return 1

    return 0

if __name__ == '__main__':
    sys.exit(main())