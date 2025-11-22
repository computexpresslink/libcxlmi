#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Comprehensive test suite for libcxlmi Python bindings
"""

import unittest
import sys
import cxlmi
import ctypes

class TestContext(unittest.TestCase):
    """Test context management functions"""

    def test_create_context(self):
        """Test creating a new context"""
        ctx = cxlmi.cxlmi_new_ctx(None, 6)  # LOG_INFO level
        self.assertIsNotNone(ctx)
        cxlmi.cxlmi_free_ctx(ctx)

    def test_context_probe_control(self):
        """Test probe enable/disable"""
        ctx = cxlmi.cxlmi_new_ctx(None, 6)
        self.assertIsNotNone(ctx)

        # Test probe control
        cxlmi.cxlmi_set_probe_enabled(ctx, False)
        cxlmi.cxlmi_set_probe_enabled(ctx, True)

        cxlmi.cxlmi_free_ctx(ctx)

class TestTunneling(unittest.TestCase):
    """Test tunneling helper functions"""

    def test_tunnel_mld(self):
        """Test MLD tunnel creation"""
        # The generated bindings expose the tunnel struct directly.
        ti = cxlmi.struct_cxlmi_tunnel_info()
        ti.ld = 5
        ti.port = -1
        ti.level = 1
        ti.mhd = False
        self.assertEqual(ti.ld, 5)
        self.assertEqual(ti.port, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, False)

    def test_tunnel_switch(self):
        """Test Switch tunnel creation"""
        ti = cxlmi.struct_cxlmi_tunnel_info()
        ti.port = 3
        ti.ld = -1
        ti.level = 1
        ti.mhd = False
        self.assertEqual(ti.port, 3)
        self.assertEqual(ti.ld, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, False)

    def test_tunnel_switch_mld(self):
        """Test Switch+MLD tunnel creation"""
        ti = cxlmi.struct_cxlmi_tunnel_info()
        ti.port = 2
        ti.ld = 4
        ti.level = 2
        ti.mhd = False
        self.assertEqual(ti.port, 2)
        self.assertEqual(ti.ld, 4)
        self.assertEqual(ti.level, 2)
        self.assertEqual(ti.mhd, False)

    def test_tunnel_mhd(self):
        """Test MHD tunnel creation"""
        ti = cxlmi.struct_cxlmi_tunnel_info()
        ti.port = -1
        ti.ld = -1
        ti.level = 1
        ti.mhd = True
        self.assertEqual(ti.port, -1)
        self.assertEqual(ti.ld, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, True)

class TestEndpointIteration(unittest.TestCase):
    """Test endpoint iteration functionality"""

    def test_empty_iteration(self):
        """Test iterating over context with no endpoints"""
        ctx = cxlmi.cxlmi_new_ctx(None, 6)
        self.assertIsNotNone(ctx)

        # Iterate using the C functions
        ep = cxlmi.cxlmi_first_endpoint(ctx)
        ep_list = []
        while ep:
            ep_list.append(ep)
            ep = cxlmi.cxlmi_next_endpoint(ctx, ep)

        self.assertIsInstance(ep_list, list)
        cxlmi.cxlmi_free_ctx(ctx)


class TestReturnCodes(unittest.TestCase):
    """Test that constants are properly exposed"""

    def test_return_code_constants(self):
        """Test return code enum values are accessible"""
        self.assertEqual(cxlmi.CXLMI_RET_SUCCESS, 0)
        self.assertEqual(cxlmi.CXLMI_RET_BACKGROUND, 1)
        self.assertEqual(cxlmi.CXLMI_RET_INPUT, 2)
        self.assertEqual(cxlmi.CXLMI_RET_UNSUPPORTED, 3)
        self.assertEqual(cxlmi.CXLMI_RET_INTERNAL, 4)
        self.assertEqual(cxlmi.CXLMI_RET_RETRY, 5)
        self.assertEqual(cxlmi.CXLMI_RET_BUSY, 6)

class TestFlexibleArrayStructures(unittest.TestCase):
    """Test that structures with flexible array members work correctly

    These structures have C99 flexible array members (e.g., uint8_t data[])
    at the end.
    """

    def test_event_records_response(self):
        """Test cxlmi_cmd_get_event_records_rsp with variable size records array"""
        num_records = 5
        # Allocate one contiguous buffer: rsp + N event records
        total_size = ctypes.sizeof(cxlmi.struct_cxlmi_cmd_get_event_records_rsp) + \
                    num_records * ctypes.sizeof(cxlmi.struct_cxlmi_event_record)
        buf = ctypes.create_string_buffer(total_size)

        # Test regular fields first
        rsp = cxlmi.struct_cxlmi_cmd_get_event_records_rsp.from_buffer(buf)
        rsp.record_count = num_records

        self.assertEqual(rsp.record_count, num_records)

        # Create array of event records, then use from_buffer to create typed view of records
        records = cxlmi.struct_cxlmi_event_record * num_records
        rsp_records = records.from_buffer(buf, ctypes.sizeof(cxlmi.struct_cxlmi_cmd_get_event_records_rsp))

        # Set fields for the 4th record (index 3) to some arbitrary test values
        idx = 3
        rsp_records[idx].length = 0x10
        rsp_records[idx].handle = 0x1111
        rsp_records[idx].related_handle = 0x2222
        rsp_records[idx].timestamp = 0xCAFEBABE12345678
        rsp_records[idx].maint_op_class = 7
        rsp_records[idx].maint_op_subclass = 8
        rsp_records[idx].ld_id = 0x0010
        rsp_records[idx].head_id = 0x04

        # Verify that the fields were set correctly
        self.assertEqual(rsp_records[idx].length, 0x10)
        self.assertEqual(rsp_records[idx].handle, 0x1111)
        self.assertEqual(rsp_records[idx].related_handle, 0x2222)
        self.assertEqual(rsp_records[idx].timestamp, 0xCAFEBABE12345678)
        self.assertEqual(rsp_records[idx].maint_op_class, 7)
        self.assertEqual(rsp_records[idx].maint_op_subclass, 8)
        self.assertEqual(rsp_records[idx].ld_id, 0x0010)
        self.assertEqual(rsp_records[idx].head_id, 0x04)

class TestNestedStructs(unittest.TestCase):
    """Test more complex nested structures"""

    def test_get_memdev_dc_config_rsp(self):
        """Test memdev get dc config response, which contains a fixed-size array
        of region_config structs"""
        rsp = cxlmi.struct_cxlmi_cmd_memdev_get_dc_config_rsp()

        config = rsp.region_configs[4]
        config.base = 0x1000
        config.decode_len = 0x10
        config.region_len = 0x2000
        config.block_size = 0x500
        config.dsmadhandle = 0x10
        config.flags = 0x16

        self.assertEqual(config.base, 0x1000)
        self.assertEqual(config.decode_len, 0x10)
        self.assertEqual(config.region_len, 0x2000)
        self.assertEqual(config.block_size, 0x500)
        self.assertEqual(config.dsmadhandle, 0x10)
        self.assertEqual(config.flags, 0x16)

class TestGenericComponentCommands(unittest.TestCase):
    """Test structure creation and field access"""

    def test_identify_structure(self):
        """Test cxlmi_cmd_identify structure"""
        ident = cxlmi.struct_cxlmi_cmd_identify_rsp()
        # Test that we can access fields
        ident.vendor_id = 0x1234
        ident.device_id = 0x5678
        ident.max_msg_size = 9
        ident.component_type = 0x03

        self.assertEqual(ident.vendor_id, 0x1234)
        self.assertEqual(ident.device_id, 0x5678)
        self.assertEqual(ident.max_msg_size, 9)
        self.assertEqual(ident.component_type, 0x03)

    def test_timestamp_structure(self):
        """Test timestamp structures"""
        ts_get = cxlmi.struct_cxlmi_cmd_get_timestamp_rsp()
        ts_set = cxlmi.struct_cxlmi_cmd_set_timestamp_req()

        # Test field access
        ts_set.timestamp = 1234567890
        self.assertEqual(ts_set.timestamp, 1234567890)

    def test_event_record_structure(self):
        """Test event record structure"""
        event = cxlmi.struct_cxlmi_event_record()

        event.length = 0x80
        event.handle = 0x1234
        event.related_handle = 0x5678
        event.timestamp = 0x123456789ABCDEF0
        event.maint_op_class = 0x01
        event.maint_op_subclass = 0x02
        event.ld_id = 0x0005  # CXL 3.2: Logical Device ID
        event.head_id = 0x03   # CXL 3.2: Head ID for MHD

        self.assertEqual(event.length, 0x80)
        self.assertEqual(event.handle, 0x1234)
        self.assertEqual(event.related_handle, 0x5678)
        self.assertEqual(event.timestamp, 0x123456789ABCDEF0)
        self.assertEqual(event.maint_op_class, 0x01)
        self.assertEqual(event.maint_op_subclass, 0x02)
        self.assertEqual(event.ld_id, 0x0005)
        self.assertEqual(event.head_id, 0x03)

    def test_fw_info_structure(self):
        """Test firmware info structure"""
        fw_info = cxlmi.struct_cxlmi_cmd_get_fw_info_rsp()

        fw_info.slots_supported = 4
        fw_info.slot_info = 0x01
        fw_info.caps = 0x03

        self.assertEqual(fw_info.slots_supported, 4)
        self.assertEqual(fw_info.slot_info, 0x01)
        self.assertEqual(fw_info.caps, 0x03)

    def test_get_log_request(self):
        """Test get log request structure"""
        req = cxlmi.struct_cxlmi_cmd_get_log_req()
        req.offset = 0
        req.length = 1024

        self.assertEqual(req.offset, 0)
        self.assertEqual(req.length, 1024)

    def test_event_records_request(self):
        """Test get event records request"""
        req = cxlmi.struct_cxlmi_cmd_get_event_records_req()
        req.event_log = 0x00  # Informational event log

        self.assertEqual(req.event_log, 0x00)

    def test_clear_event_records(self):
        """Test clear event records structure"""
        req = cxlmi.struct_cxlmi_cmd_clear_event_records_req()
        req.event_log = 0x00
        req.clear_flags = 0x01
        req.nr_recs = 5

        self.assertEqual(req.event_log, 0x00)
        self.assertEqual(req.clear_flags, 0x01)
        self.assertEqual(req.nr_recs, 5)


class TestMemdevCommands(unittest.TestCase):
    def test_memdev_identify_structure(self):
        """Test memory device identify structure"""
        memdev = cxlmi.struct_cxlmi_cmd_memdev_identify_rsp()

        # Test field access
        memdev.total_capacity = 0x1000000000
        memdev.volatile_capacity = 0x800000000
        memdev.persistent_capacity = 0x800000000

        self.assertEqual(memdev.total_capacity, 0x1000000000)
        self.assertEqual(memdev.volatile_capacity, 0x800000000)
        self.assertEqual(memdev.persistent_capacity, 0x800000000)

    def test_health_info_structure(self):
        """Test health info structure"""
        health = cxlmi.struct_cxlmi_cmd_memdev_get_health_info_rsp()

        health.health_status = 0x00
        health.media_status = 0x00
        health.life_used = 50
        health.device_temperature = 300  # 30.0°C

        self.assertEqual(health.health_status, 0x00)
        self.assertEqual(health.media_status, 0x00)
        self.assertEqual(health.life_used, 50)
        self.assertEqual(health.device_temperature, 300)

    def test_partition_info_structure(self):
        """Test partition info structures"""
        get_part = cxlmi.struct_cxlmi_cmd_memdev_get_partition_info_rsp()
        set_part = cxlmi.struct_cxlmi_cmd_memdev_set_partition_info_req()

        set_part.volatile_capacity = 0x400000000
        set_part.flags = 0x01

        self.assertEqual(set_part.volatile_capacity, 0x400000000)
        self.assertEqual(set_part.flags, 0x01)

    def test_dc_extent_list_request(self):
        """Test DC extent list request"""
        req = cxlmi.struct_cxlmi_cmd_memdev_get_dc_extent_list_req()
        req.extent_cnt = 10
        req.start_extent_idx = 0

        self.assertEqual(req.extent_cnt, 10)
        self.assertEqual(req.start_extent_idx, 0)

    def test_poison_structures(self):
        """Test poison list structures"""
        poison_req = cxlmi.struct_cxlmi_cmd_memdev_get_poison_list_req()
        poison_inject = cxlmi.struct_cxlmi_cmd_memdev_inject_poison_req()
        poison_clear = cxlmi.struct_cxlmi_cmd_memdev_clear_poison_req()

        poison_req.get_poison_list_phy_addr = 0x1000
        poison_req.get_poison_list_phy_addr_len = 0x1000

        poison_inject.inject_poison_phy_addr = 0x2000
        poison_clear.clear_poison_phy_addr = 0x2000

        self.assertEqual(poison_req.get_poison_list_phy_addr, 0x1000)
        self.assertEqual(poison_inject.inject_poison_phy_addr, 0x2000)
        self.assertEqual(poison_clear.clear_poison_phy_addr, 0x2000)

    def test_passphrase_commands(self):
        """
        Test passphrase structures:
            - Set Passphrase (Opcode 4501h)
            - Disable Passphrase (Opcode 4502h)
        """
        set_pass = cxlmi.struct_cxlmi_cmd_memdev_set_passphrase_req()
        set_pass.current_passphrase[:] = b'current_pass'.ljust(32, b'\0')
        set_pass.new_passphrase[:] = b'new_pass'.ljust(32, b'\0')

        self.assertEqual(bytes(set_pass.current_passphrase), b'current_pass'.ljust(32, b'\0'))
        self.assertEqual(bytes(set_pass.new_passphrase), b'new_pass'.ljust(32, b'\0'))


    def test_qos_commands(self):
        """
        Test QoS structures:
            - Get SLD QoS Control (Opcode 4700h)
            - Set SLD QoS Control (Opcode 4701h)
            - Get SLD QoS Status (Opcode 4702h)
        """
        qos_get = cxlmi.struct_cxlmi_cmd_memdev_get_sld_qos_control_rsp()
        qos_set = cxlmi.struct_cxlmi_cmd_memdev_set_sld_qos_control_req()
        qos_status = cxlmi.struct_cxlmi_cmd_memdev_get_sld_qos_status_rsp()

        qos_set.qos_telemetry_control = 0x01
        qos_set.egress_moderate_percentage = 50
        qos_set.egress_severe_percentage = 75
        qos_set.backpressure_sample_interval = 10

        self.assertEqual(qos_set.qos_telemetry_control, 0x01)
        self.assertEqual(qos_set.egress_moderate_percentage, 50)
        self.assertEqual(qos_set.egress_severe_percentage, 75)
        self.assertEqual(qos_set.backpressure_sample_interval, 10)

    def test_scan_media(self):
        """Test Scan Media (Opcode 4304h)"""
        req = cxlmi.struct_cxlmi_cmd_scan_media_req()
        req.scan_media_physaddr = 0x1000
        req.scan_media_physaddr_length = 0x10000
        req.scan_media_flags = 0x00

        self.assertEqual(req.scan_media_physaddr, 0x1000)
        self.assertEqual(req.scan_media_physaddr_length, 0x10000)
        self.assertEqual(req.scan_media_flags, 0x00)

    def test_get_dc_config(self):
        """Test Get Dynamic Capacity Configuration (Opcode 4800h)"""
        dc_config_req = cxlmi.struct_cxlmi_cmd_memdev_get_dc_config_req()
        dc_config_rsp = cxlmi.struct_cxlmi_cmd_memdev_get_dc_config_rsp()

        dc_config_req.region_cnt = 2
        dc_config_req.start_region_id = 0

        self.assertEqual(dc_config_req.region_cnt, 2)
        self.assertEqual(dc_config_req.start_region_id, 0)

    def test_dc_extent_list(self):
        """Test Get Dynamic Capacity Extent List (Opcode 4801h)"""
        req = cxlmi.struct_cxlmi_cmd_memdev_get_dc_extent_list_req()
        req.extent_cnt = 10
        req.start_extent_idx = 0

        self.assertEqual(req.extent_cnt, 10)
        self.assertEqual(req.start_extent_idx, 0)


class TestFMAPICommands(unittest.TestCase):
    def test_fmapi_identify_structure(self):
        """Test FM-API identify switch device structure"""
        sw_ident = cxlmi.struct_cxlmi_cmd_fmapi_identify_sw_device_rsp()

        sw_ident.ingress_port_id = 0
        sw_ident.num_physical_ports = 8
        sw_ident.num_vcs = 2
        sw_ident.num_total_vppb = 16
        sw_ident.num_active_vppb = 8

        self.assertEqual(sw_ident.ingress_port_id, 0)
        self.assertEqual(sw_ident.num_physical_ports, 8)
        self.assertEqual(sw_ident.num_vcs, 2)
        self.assertEqual(sw_ident.num_total_vppb, 16)
        self.assertEqual(sw_ident.num_active_vppb, 8)

    def test_fmapi_get_ld_allocations_request(self):
        """Test FM-API get LD allocations request"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_get_ld_allocations_req()
        req.start_ld_id = 0
        req.ld_allocation_list_limit = 16

        self.assertEqual(req.start_ld_id, 0)
        self.assertEqual(req.ld_allocation_list_limit, 16)

    def test_fmapi_bind_vppb(self):
        """Test FM-API bind vPPB structure"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_bind_vppb_req()
        req.vcs_id = 1
        req.vppb_id = 5
        req.port_id = 3
        req.ld_id = 10

        self.assertEqual(req.vcs_id, 1)
        self.assertEqual(req.vppb_id, 5)
        self.assertEqual(req.port_id, 3)
        self.assertEqual(req.ld_id, 10)

    def test_fmapi_unbind_vppb(self):
        """Test FM-API unbind vPPB structure"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_unbind_vppb_req()
        req.vcs_id = 1
        req.vppb_id = 5
        req.option = 0

        self.assertEqual(req.vcs_id, 1)
        self.assertEqual(req.vppb_id, 5)
        self.assertEqual(req.option, 0)

    def test_fmapi_phys_port_control(self):
        """Test FM-API physical port control"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_phys_port_control_req()
        req.ppb_id = 2
        req.port_opcode = 0x01  # Example opcode

        self.assertEqual(req.ppb_id, 2)
        self.assertEqual(req.port_opcode, 0x01)

    def test_fmapi_get_ld_allocations_request(self):
        """Test FM-API get LD allocations request"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_get_ld_allocations_req()
        req.start_ld_id = 0
        req.ld_allocation_list_limit = 16

        self.assertEqual(req.start_ld_id, 0)
        self.assertEqual(req.ld_allocation_list_limit, 16)

    def test_fmapi_bind_vppb(self):
        """Test FM-API bind vPPB structure"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_bind_vppb_req()
        req.vcs_id = 1
        req.vppb_id = 5
        req.port_id = 3
        req.ld_id = 10

        self.assertEqual(req.vcs_id, 1)
        self.assertEqual(req.vppb_id, 5)
        self.assertEqual(req.port_id, 3)
        self.assertEqual(req.ld_id, 10)

    def test_fmapi_unbind_vppb(self):
        """Test FM-API unbind vPPB structure"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_unbind_vppb_req()
        req.vcs_id = 1
        req.vppb_id = 5
        req.option = 0

        self.assertEqual(req.vcs_id, 1)
        self.assertEqual(req.vppb_id, 5)
        self.assertEqual(req.option, 0)

    def test_fmapi_phys_port_control(self):
        """Test FM-API physical port control"""
        req = cxlmi.struct_cxlmi_cmd_fmapi_phys_port_control_req()
        req.ppb_id = 2
        req.port_opcode = 0x01  # Example opcode

        self.assertEqual(req.ppb_id, 2)
        self.assertEqual(req.port_opcode, 0x01)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestContext))
    suite.addTests(loader.loadTestsFromTestCase(TestTunneling))
    suite.addTests(loader.loadTestsFromTestCase(TestReturnCodes))
    suite.addTests(loader.loadTestsFromTestCase(TestEndpointIteration))
    suite.addTests(loader.loadTestsFromTestCase(TestReturnCodes))
    suite.addTests(loader.loadTestsFromTestCase(TestGenericComponentCommands))
    suite.addTests(loader.loadTestsFromTestCase(TestMemdevCommands))
    suite.addTests(loader.loadTestsFromTestCase(TestFMAPICommands))
    suite.addTests(loader.loadTestsFromTestCase(TestFlexibleArrayStructures))
    suite.addTests(loader.loadTestsFromTestCase(TestNestedStructs))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
