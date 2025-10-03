#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Example: Commands with input payloads

This example demonstrates how to:
1. Use commands with input-only payloads (set operations)
2. Use commands with both input and output payloads
3. Properly populate input structures with data
4. Support both MCTP (out-of-band) and ioctl (in-band) endpoints
"""

import sys
import time
import cxlmi


def example_set_timestamp(ep):
    """Example: Set timestamp (input-only command)"""
    print("\n1. Setting Device Timestamp (Input-only command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_set_timestamp_req()

    # Populate the input fields
    current_time = int(time.time() * 1000)  # Convert to milliseconds
    req.timestamp = current_time

    print(f"Setting timestamp to: {current_time} ms")

    try:
        # Send command (no response structure needed)
        ret = cxlmi.cxlmi_cmd_set_timestamp(ep, None, req)
        print("SUCCESS: Timestamp set successfully")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_get_event_records(ep):
    """Example: Get event records (input + output command)"""
    print("\n2. Getting Event Records (Input + Output command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_get_event_records_req()

    # Populate input fields
    req.event_log = 0x00  # Informational event log

    print(f"Requesting events from log: {req.event_log}")

    # Create output response structure
    rsp = cxlmi.cxlmi_cmd_get_event_records_rsp()

    try:
        # Send command with both input and output
        ret = cxlmi.cxlmi_cmd_get_event_records(ep, None, req, rsp)

        print(f"SUCCESS: Event Records Retrieved:")
        print(f"  Record Count:              {rsp.record_count}")
        print(f"  Overflow Error Count:      {rsp.overflow_err_count}")
        if rsp.overflow_err_count > 0:
            print(f"  First Overflow Timestamp:  {rsp.first_overflow_timestamp}")
            print(f"  Last Overflow Timestamp:   {rsp.last_overflow_timestamp}")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_get_log(ep):
    """Example: Get log with offset and length (input + output command)"""
    print("\n3. Getting Log with Offset/Length (Input + Output command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_get_log_req()

    # Populate input fields
    req.log_identifier = 0x00  # CEL (Command Effects Log)
    req.offset = 0             # Start from beginning
    req.length = 512           # Read 512 bytes

    print(f"Requesting log:")
    print(f"  Log ID:     0x{req.log_identifier:02x}")
    print(f"  Offset:     {req.offset}")
    print(f"  Length:     {req.length} bytes")

    # Create output response structure
    rsp = cxlmi.cxlmi_cmd_get_log_rsp()

    try:
        # Send command
        ret = cxlmi.cxlmi_cmd_get_log(ep, None, req, rsp)
        print(f"SUCCESS: Log data retrieved successfully")
        # Note: The actual log data is in a flexible array member
        # that's not directly accessible from Python
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_clear_event_records(ep):
    """Example: Clear event records with flags (input-only command)"""
    print("\n4. Clearing Event Records with Flags (Input-only command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_clear_event_records_req()

    # Populate input fields
    req.event_log = 0x01        # Warning event log
    req.clear_flags = 0x01      # Clear all events flag
    req.nr_recs = 0             # Number of records (0 = all when clear_flags is set)

    print(f"Clearing events:")
    print(f"  Event Log:    {req.event_log}")
    print(f"  Clear Flags:  0x{req.clear_flags:02x}")
    print(f"  Records:      {req.nr_recs if req.nr_recs > 0 else 'all'}")

    try:
        # Send command
        ret = cxlmi.cxlmi_cmd_clear_event_records(ep, None, req)
        print("SUCCESS: Event records cleared successfully")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_set_partition_info(ep):
    """Example: Set partition info (input-only command)"""
    print("\n5. Setting Partition Info (Input-only command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_memdev_set_partition_info_req()

    # Populate input fields
    # Note: Capacity is in multiples of 256 MiB
    req.volatile_capacity = 16   # 16 * 256 MiB = 4 GiB
    req.flags = 0x01             # Immediate flag

    print(f"Setting partition:")
    print(f"  Volatile Capacity:  {req.volatile_capacity} (x256 MiB)")
    print(f"  Flags:              0x{req.flags:02x}")

    try:
        # Send command
        ret = cxlmi.cxlmi_cmd_memdev_set_partition_info(ep, None, req)
        if ret == cxlmi.CXLMI_RET_BACKGROUND:
            print("SUCCESS: Background operation started")
            print("  Note: Check background operation status")
        else:
            print("SUCCESS: Partition info set successfully")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_get_poison_list(ep):
    """Example: Get poison list with address range (input + output command)"""
    print("\n6. Getting Poison List for Address Range (Input + Output command)")
    print("-" * 50)

    # Create input request structure
    req = cxlmi.cxlmi_cmd_memdev_get_poison_list_req()

    # Populate input fields
    req.get_poison_list_phy_addr = 0x1000       # Start physical address
    req.get_poison_list_phy_addr_len = 0x10000  # Length: 64 KB

    print(f"Requesting poison list:")
    print(f"  Physical Address:  0x{req.get_poison_list_phy_addr:x}")
    print(f"  Length:            0x{req.get_poison_list_phy_addr_len:x} ({req.get_poison_list_phy_addr_len} bytes)")

    # Create output response structure
    rsp = cxlmi.cxlmi_cmd_memdev_get_poison_list_rsp()

    try:
        # Send command
        ret = cxlmi.cxlmi_cmd_memdev_get_poison_list(ep, None, req, rsp)

        print(f"SUCCESS: Poison list retrieved:")
        print(f"  Flags:                0x{rsp.flags:02x}")
        print(f"  Overflow Timestamp:   {rsp.overflow_timestamp}")
        print(f"  Record Count:         {rsp.record_count}")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def example_fmapi_get_ld_allocations(ep):
    """Example: FM-API Get LD Allocations (input + output command)"""
    print("\n7. FM-API: Getting LD Allocations (Input + Output command)")
    print("-" * 50)

    # Check FM-API support
    if not cxlmi.cxlmi_endpoint_has_fmapi(ep):
        print("SKIP: FM-API not supported on this device")
        return

    # Create input request structure
    req = cxlmi.cxlmi_cmd_fmapi_get_ld_allocations_req()

    # Populate input fields
    req.start_ld_id = 0                # Start with LD 0
    req.ld_allocation_list_limit = 8   # Get up to 8 LDs

    print(f"Requesting LD allocations:")
    print(f"  Start LD ID:  {req.start_ld_id}")
    print(f"  Limit:        {req.ld_allocation_list_limit}")

    # Create output response structure
    rsp = cxlmi.cxlmi_cmd_fmapi_get_ld_allocations_rsp()

    try:
        # Send command
        ret = cxlmi.cxlmi_cmd_fmapi_get_ld_allocations(ep, None, req, rsp)

        print(f"SUCCESS: LD allocations retrieved:")
        print(f"  Number of LDs:  {rsp.num_lds}")
        print(f"  Start LD ID:    {rsp.start_ld_id}")
    except RuntimeError as e:
        print(f"ERROR: {e}")


def run_examples(ep):
    """Run all command examples"""
    print("=" * 60)
    print("CXL Commands with Input Payloads - Examples")
    print("=" * 60)

    # Run all examples
    example_set_timestamp(ep)
    example_get_event_records(ep)
    example_get_log(ep)
    example_clear_event_records(ep)
    example_set_partition_info(ep)
    example_get_poison_list(ep)
    example_fmapi_get_ld_allocations(ep)

    print("\n" + "=" * 60)
    print("Note: Some commands may fail if not supported by the device")
    print("=" * 60)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <cxl_device>")
        print(f"   or: {sys.argv[0]} <net_id> <eid>")
        print()
        print("This example demonstrates commands with input payloads:")
        print("  - Input-only commands (set operations)")
        print("  - Input + output commands (parametrized get operations)")
        print("  - Populating request structures with data")
        print()
        print("Examples:")
        print(f"  {sys.argv[0]} mem0           # Use ioctl (in-band via kernel)")
        print(f"  {sys.argv[0]} 12 8           # Use MCTP (out-of-band, net=12, eid=8)")
        return 1

    ctx = cxlmi.cxlmi_new_ctx(None, 6)  # LOG_INFO level
    if not ctx:
        print("Failed to create context")
        return 1

    try:
        # Determine endpoint type based on arguments
        if len(sys.argv) == 2:
            # Single argument: ioctl endpoint (e.g., mem0)
            device_name = sys.argv[1]
            print(f"Opening ioctl endpoint: {device_name}")
            ep = cxlmi.cxlmi_open(ctx, device_name)
            if not ep:
                print(f"Failed to open device: {device_name}")
                return 1
        elif len(sys.argv) == 3:
            # Two arguments: MCTP endpoint (net_id, eid)
            net_id = int(sys.argv[1])
            eid = int(sys.argv[2])
            print(f"Opening MCTP endpoint: net={net_id}, eid={eid}")
            ep = cxlmi.cxlmi_open_mctp(ctx, net_id, eid)
            if not ep:
                print(f"Failed to open MCTP endpoint: net={net_id}, eid={eid}")
                return 1
        else:
            print("Invalid number of arguments")
            return 1

        try:
            run_examples(ep)
        finally:
            cxlmi.cxlmi_close(ep)

    finally:
        cxlmi.cxlmi_free_ctx(ctx)

    return 0


if __name__ == '__main__':
    sys.exit(main())
