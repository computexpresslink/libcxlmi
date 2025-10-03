#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Get FM-API switch information

This example demonstrates how to:
1. Check if FM-API is supported
2. Query switch device information
3. Get physical port states
"""

import sys
import cxlmi


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cxl_device>")
        print(f"Example: {sys.argv[0]} mem0")
        print()
        print("Note: Device must be a CXL Switch with FM-API support")
        return 1

    device_name = sys.argv[1]

    ctx = cxlmi.cxlmi_new_ctx(None, 6)
    if not ctx:
        print("Failed to create context")
        return 1

    try:
        ep = cxlmi.cxlmi_open(ctx, device_name)
        if not ep:
            print(f"Failed to open device: {device_name}")
            return 1

        try:
            # Check FM-API support
            if not cxlmi.cxlmi_endpoint_has_fmapi(ep):
                print("Device does not support FM-API")
                print("FM-API is required for switch management commands")
                return 1

            print("FM-API is supported")
            print()

            # Identify switch device
            sw_ident = cxlmi.cxlmi_cmd_fmapi_identify_sw_device()
            ret = cxlmi.cxlmi_cmd_fmapi_identify_sw_device(ep, None, sw_ident)

            print("CXL Switch Information:")
            print(f"  Ingress Port ID:         {sw_ident.ingres_port_id}")
            print(f"  Physical Ports:          {sw_ident.num_physical_ports}")
            print(f"  Virtual Channels:        {sw_ident.num_vcs}")
            print(f"  Total vPPBs:             {sw_ident.num_total_vppb}")
            print(f"  Active vPPBs:            {sw_ident.num_active_vppb}")
            print(f"  HDM Decoders per USP:    {sw_ident.num_hdm_decoder_per_usp}")
            print()

            # Query first few port states
            print("Physical Port States:")
            num_ports_to_query = min(4, sw_ident.num_physical_ports)

            for port_id in range(num_ports_to_query):
                port_req = cxlmi.cxlmi_cmd_fmapi_get_phys_port_state_req()
                port_rsp = cxlmi.cxlmi_cmd_fmapi_get_phys_port_state_rsp()

                # Note: In a real implementation, you'd properly set up the
                # request with port IDs. This is simplified for the example.
                try:
                    ret = cxlmi.cxlmi_cmd_fmapi_get_phys_port_state(ep, None, port_req, port_rsp)

                    print(f"  Port {port_id}:")
                    print(f"    Num Ports in Response: {port_rsp.num_ports}")
                    # Additional port state decoding would go here

                except RuntimeError as e:
                    print(f"  Port {port_id}: Error - {e}")

        finally:
            cxlmi.cxlmi_close(ep)

    finally:
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
