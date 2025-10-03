#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Scan and list MCTP-connected CXL endpoints

This example demonstrates how to:
1. Scan for MCTP endpoints via D-Bus
2. Iterate over discovered endpoints
3. Query basic information from each endpoint

Note: Requires libcxlmi built with D-Bus support
"""

import sys
import cxlmi


def main():
    # Create context with DEBUG log level to see discovery process
    ctx = cxlmi.cxlmi_new_ctx(None, 7)
    if not ctx:
        print("Failed to create context")
        return 1

    try:
        # Scan for MCTP endpoints
        print("Scanning for MCTP-connected CXL endpoints...")
        num_endpoints = cxlmi.cxlmi_scan_mctp(ctx)

        if num_endpoints < 0:
            print("Failed to scan MCTP endpoints")
            print("Note: This requires libcxlmi built with D-Bus support")
            return 1

        print(f"Found {num_endpoints} endpoint(s)\n")

        if num_endpoints == 0:
            print("No MCTP endpoints found")
            return 0

        # Iterate over all endpoints
        ep_num = 0
        for ep in cxlmi.endpoints(ctx):
            ep_num += 1
            print(f"Endpoint {ep_num}:")

            try:
                # Try to identify the endpoint
                ident = cxlmi.cxlmi_cmd_identify()
                ret = cxlmi.cxlmi_cmd_identify(ep, None, ident)

                print(f"  Vendor ID:        0x{ident.vendor_id:04x}")
                print(f"  Device ID:        0x{ident.device_id:04x}")
                print(f"  Serial Number:    0x{ident.serial_num:016x}")
                print(f"  Component Type:   0x{ident.component_type:02x}")

                # Check if FM-API is supported
                if cxlmi.cxlmi_endpoint_has_fmapi(ep):
                    print(f"  FM-API:           Supported")
                else:
                    print(f"  FM-API:           Not Supported")

                # Get timeout
                timeout = cxlmi.cxlmi_endpoint_get_timeout(ep)
                print(f"  Timeout:          {timeout}ms")

            except Exception as e:
                print(f"  Error querying endpoint: {e}")

            print()

    finally:
        # Note: Endpoints are closed automatically when context is freed
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
