#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Get and display partition information

This example demonstrates how to:
1. Query partition information from a CXL memory device
2. Display active and next partition sizes
3. Format capacities in human-readable units
"""

import sys
import cxlmi

MiB = 1 << 20
CXL_CAPACITY_MULTIPLIER = 256 * MiB

def format_capacity(bytes_val):
    """Format byte capacity in human-readable format"""
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    unit_idx = 0
    value = float(bytes_val)

    while value >= 1024 and unit_idx < len(units) - 1:
        value /= 1024
        unit_idx += 1

    return f"{value:.2f} {units[unit_idx]}"


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
            # Get partition information
            part_info = cxlmi.cxlmi_cmd_memdev_get_partition_info_rsp()
            ret = cxlmi.cxlmi_cmd_memdev_get_partition_info(ep, None, part_info)

            print("CXL Memory Device Partition Information:")
            print()
            print("Active Partition:")
            print(f"  Volatile Memory:    {format_capacity(part_info.active_vmem * CXL_CAPACITY_MULTIPLIER)}")
            print(f"                      ({part_info.active_vmem * CXL_CAPACITY_MULTIPLIER} bytes)")
            print(f"  Persistent Memory:  {format_capacity(part_info.active_pmem * CXL_CAPACITY_MULTIPLIER)}")
            print(f"                      ({part_info.active_pmem * CXL_CAPACITY_MULTIPLIER} bytes)")
            print()

            # Check if next partition is different
            if (part_info.next_vmem != part_info.active_vmem or
                part_info.next_pmem != part_info.active_pmem):
                print("Next Partition (pending change):")
                print(f"  Volatile Memory:    {format_capacity(part_info.next_vmem * CXL_CAPACITY_MULTIPLIER)}")
                print(f"                      ({part_info.next_vmem * CXL_CAPACITY_MULTIPLIER} bytes)")
                print(f"  Persistent Memory:  {format_capacity(part_info.next_pmem * CXL_CAPACITY_MULTIPLIER)}")
                print(f"                      ({part_info.next_pmem * CXL_CAPACITY_MULTIPLIER} bytes)")
                print()
                print("Note: A device reset is required to activate the new partition")
            else:
                print("Next Partition: Same as active (no pending changes)")

        finally:
            cxlmi.cxlmi_close(ep)

    finally:
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
