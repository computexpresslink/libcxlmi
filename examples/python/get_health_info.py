#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Get health information from a CXL memory device

This example demonstrates how to:
1. Open a CXL memory device
2. Get health information
3. Display health status, temperature, and error counts
"""

import sys
import cxlmi


def decode_health_status(status):
    """Decode health status byte"""
    statuses = []
    if status & 0x01:
        statuses.append("Maintenance Needed")
    if status & 0x02:
        statuses.append("Performance Degraded")
    if status & 0x04:
        statuses.append("Hardware Replacement Needed")

    return ", ".join(statuses) if statuses else "Normal"


def decode_media_status(status):
    """Decode media status byte"""
    media_states = {
        0x00: "Normal",
        0x01: "Not Ready",
        0x02: "Write Persistency Lost",
        0x03: "All Data Lost",
        0x04: "Write Persistency Lost, Data Restore Failed",
        0x05: "All Data Lost, Data Restore Failed",
        0x06: "Write Persistency Lost, Data Restore Failed, All Data Lost",
    }
    return media_states.get(status & 0x07, f"Unknown (0x{status:02x})")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cxl_device>")
        print(f"Example: {sys.argv[0]} mem0")
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
            # Get health information
            health = cxlmi.cxlmi_cmd_memdev_get_health_info()
            ret = cxlmi.cxlmi_cmd_memdev_get_health_info(ep, None, health)

            print("CXL Memory Device Health Information:")
            print(f"  Health Status:                  {decode_health_status(health.health_status)}")
            print(f"  Media Status:                   {decode_media_status(health.media_status)}")
            print(f"  Life Used:                      {health.life_used}%")

            # Temperature is in units of 1/10 degree Celsius
            temp_c = health.device_temperature / 10.0
            print(f"  Device Temperature:             {temp_c:.1f}°C")

            print(f"  Dirty Shutdown Count:           {health.dirty_shutdown_count}")
            print(f"  Corrected Volatile Errors:      {health.corrected_volatile_error_count}")
            print(f"  Corrected Persistent Errors:    {health.corrected_persistent_error_count}")

            # Check for additional status flags
            if health.additional_status:
                print(f"  Additional Status:              0x{health.additional_status:02x}")

        finally:
            cxlmi.cxlmi_close(ep)

    finally:
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
