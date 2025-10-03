#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Identify a CXL device using Python bindings

This example demonstrates how to:
1. Create a context
2. Open a CXL endpoint (mailbox interface)
3. Send an Identify command
4. Display the results
"""

import sys
import cxlmi


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cxl_device>")
        print(f"Example: {sys.argv[0]} mem0")
        return 1

    device_name = sys.argv[1]

    # Create a new context with INFO log level
    ctx = cxlmi.cxlmi_new_ctx(None, 6)
    if not ctx:
        print("Failed to create context")
        return 1

    try:
        # Open the CXL device
        ep = cxlmi.cxlmi_open(ctx, device_name)
        if not ep:
            print(f"Failed to open device: {device_name}")
            return 1

        try:
            # Create the identify response structure
            ident = cxlmi.cxlmi_cmd_identify()

            # Send the identify command (no tunneling)
            ret = cxlmi.cxlmi_cmd_identify(ep, None, ident)

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
            cxlmi.cxlmi_close(ep)

    finally:
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
