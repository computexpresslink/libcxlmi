#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Comprehensive test suite for libcxlmi Python bindings
"""

import unittest
import sys
import os

# Add the build directory to the path for testing
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../build/src/python'))

import cxlmi


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
        ti = cxlmi.cxlmi_tunnel_mld(5)
        self.assertIsNotNone(ti)
        self.assertEqual(ti.ld, 5)
        self.assertEqual(ti.port, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, False)
        cxlmi.cxlmi_tunnel_free(ti)

    def test_tunnel_switch(self):
        """Test Switch tunnel creation"""
        ti = cxlmi.cxlmi_tunnel_switch(3)
        self.assertIsNotNone(ti)
        self.assertEqual(ti.port, 3)
        self.assertEqual(ti.ld, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, False)
        cxlmi.cxlmi_tunnel_free(ti)

    def test_tunnel_switch_mld(self):
        """Test Switch+MLD tunnel creation"""
        ti = cxlmi.cxlmi_tunnel_switch_mld(2, 4)
        self.assertIsNotNone(ti)
        self.assertEqual(ti.port, 2)
        self.assertEqual(ti.ld, 4)
        self.assertEqual(ti.level, 2)
        self.assertEqual(ti.mhd, False)
        cxlmi.cxlmi_tunnel_free(ti)

    def test_tunnel_mhd(self):
        """Test MHD tunnel creation"""
        ti = cxlmi.cxlmi_tunnel_mhd()
        self.assertIsNotNone(ti)
        self.assertEqual(ti.port, -1)
        self.assertEqual(ti.ld, -1)
        self.assertEqual(ti.level, 1)
        self.assertEqual(ti.mhd, True)
        cxlmi.cxlmi_tunnel_free(ti)


class TestReturnCodes(unittest.TestCase):
    """Test return code enumeration and string conversion"""

    def test_retcode_to_string(self):
        """Test converting return codes to strings"""
        # Test known return codes - check they return strings (actual strings may vary)
        result = cxlmi.cxlmi_cmd_retcode_tostr(cxlmi.CXLMI_RET_SUCCESS)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)
        self.assertIn("success", result.lower())

        result = cxlmi.cxlmi_cmd_retcode_tostr(cxlmi.CXLMI_RET_UNSUPPORTED)
        self.assertIsNotNone(result)
        self.assertIsInstance(result, str)


class TestStructures(unittest.TestCase):
    """Test structure creation and field access"""

    def test_identify_structure(self):
        """Test cxlmi_cmd_identify structure"""
        ident = cxlmi.cxlmi_cmd_identify_rsp()
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
        ts_get = cxlmi.cxlmi_cmd_get_timestamp_rsp()
        ts_set = cxlmi.cxlmi_cmd_set_timestamp_req()

        # Test field access
        ts_set.timestamp = 1234567890
        self.assertEqual(ts_set.timestamp, 1234567890)

    def test_memdev_identify_structure(self):
        """Test memory device identify structure"""
        memdev = cxlmi.cxlmi_cmd_memdev_identify_rsp()

        # Test field access
        memdev.total_capacity = 0x1000000000
        memdev.volatile_capacity = 0x800000000
        memdev.persistent_capacity = 0x800000000

        self.assertEqual(memdev.total_capacity, 0x1000000000)
        self.assertEqual(memdev.volatile_capacity, 0x800000000)
        self.assertEqual(memdev.persistent_capacity, 0x800000000)

    def test_health_info_structure(self):
        """Test health info structure"""
        health = cxlmi.cxlmi_cmd_memdev_get_health_info_rsp()

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
        get_part = cxlmi.cxlmi_cmd_memdev_get_partition_info_rsp()
        set_part = cxlmi.cxlmi_cmd_memdev_set_partition_info_req()

        set_part.volatile_capacity = 0x400000000
        set_part.flags = 0x01

        self.assertEqual(set_part.volatile_capacity, 0x400000000)
        self.assertEqual(set_part.flags, 0x01)

    def test_event_record_structure(self):
        """Test event record structure"""
        event = cxlmi.cxlmi_event_record()

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
        fw_info = cxlmi.cxlmi_cmd_get_fw_info_rsp()

        fw_info.slots_supported = 4
        fw_info.slot_info = 0x01
        fw_info.caps = 0x03

        self.assertEqual(fw_info.slots_supported, 4)
        self.assertEqual(fw_info.slot_info, 0x01)
        self.assertEqual(fw_info.caps, 0x03)

    def test_fmapi_identify_structure(self):
        """Test FM-API identify switch device structure"""
        sw_ident = cxlmi.cxlmi_cmd_fmapi_identify_sw_device_rsp()

        sw_ident.ingres_port_id = 0
        sw_ident.num_physical_ports = 8
        sw_ident.num_vcs = 2
        sw_ident.num_total_vppb = 16
        sw_ident.num_active_vppb = 8

        self.assertEqual(sw_ident.ingres_port_id, 0)
        self.assertEqual(sw_ident.num_physical_ports, 8)
        self.assertEqual(sw_ident.num_vcs, 2)
        self.assertEqual(sw_ident.num_total_vppb, 16)
        self.assertEqual(sw_ident.num_active_vppb, 8)

    def test_dc_config_structure(self):
        """Test dynamic capacity config structures"""
        dc_config_req = cxlmi.cxlmi_cmd_memdev_get_dc_config_req()
        dc_config_rsp = cxlmi.cxlmi_cmd_memdev_get_dc_config_rsp()

        dc_config_req.region_cnt = 2
        dc_config_req.start_region_id = 0

        self.assertEqual(dc_config_req.region_cnt, 2)
        self.assertEqual(dc_config_req.start_region_id, 0)

    def test_poison_structures(self):
        """Test poison list structures"""
        poison_req = cxlmi.cxlmi_cmd_memdev_get_poison_list_req()
        poison_inject = cxlmi.cxlmi_cmd_memdev_inject_poison_req()
        poison_clear = cxlmi.cxlmi_cmd_memdev_clear_poison_req()

        poison_req.get_poison_list_phy_addr = 0x1000
        poison_req.get_poison_list_phy_addr_len = 0x1000

        poison_inject.inject_poison_phy_addr = 0x2000
        poison_clear.clear_poison_phy_addr = 0x2000

        self.assertEqual(poison_req.get_poison_list_phy_addr, 0x1000)
        self.assertEqual(poison_inject.inject_poison_phy_addr, 0x2000)
        self.assertEqual(poison_clear.clear_poison_phy_addr, 0x2000)

    def test_security_structures(self):
        """Test security structures"""
        sec_state = cxlmi.cxlmi_cmd_memdev_get_security_state_rsp()
        set_pass = cxlmi.cxlmi_cmd_memdev_set_passphrase_req()
        unlock = cxlmi.cxlmi_cmd_memdev_unlock_req()

        set_pass.passphrase_type = 0  # User passphrase

        self.assertEqual(set_pass.passphrase_type, 0)

    def test_qos_structures(self):
        """Test QoS structures"""
        qos_get = cxlmi.cxlmi_cmd_memdev_get_sld_qos_control_rsp()
        qos_set = cxlmi.cxlmi_cmd_memdev_set_sld_qos_control_req()
        qos_status = cxlmi.cxlmi_cmd_memdev_get_sld_qos_status_rsp()

        qos_set.qos_telemetry_control = 0x01
        qos_set.egress_moderate_percentage = 50
        qos_set.egress_severe_percentage = 75
        qos_set.backpressure_sample_interval = 10

        self.assertEqual(qos_set.qos_telemetry_control, 0x01)
        self.assertEqual(qos_set.egress_moderate_percentage, 50)
        self.assertEqual(qos_set.egress_severe_percentage, 75)
        self.assertEqual(qos_set.backpressure_sample_interval, 10)


class TestEndpointIteration(unittest.TestCase):
    """Test endpoint iteration functionality"""

    def test_empty_iteration(self):
        """Test iterating over context with no endpoints"""
        ctx = cxlmi.cxlmi_new_ctx(None, 6)
        self.assertIsNotNone(ctx)

        # Should have no endpoints
        ep_list = list(cxlmi.endpoints(ctx))
        self.assertEqual(len(ep_list), 0)

        cxlmi.cxlmi_free_ctx(ctx)


class TestConstants(unittest.TestCase):
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

    def test_max_event_records_constant(self):
        """Test max event records constant"""
        self.assertEqual(cxlmi.CXLMI_MAX_SUPPORTED_EVENT_RECORDS, 20)

    def test_max_logs_constant(self):
        """Test max supported logs constant"""
        self.assertEqual(cxlmi.CXLMI_MAX_SUPPORTED_LOGS, 7)

    def test_mailbox_max_payload_size(self):
        """Test mailbox max payload size constant"""
        self.assertEqual(cxlmi.CXL_MAILBOX_MAX_PAYLOAD_SIZE, 2048)


class TestCommandRequestStructures(unittest.TestCase):
    """Test command request structures for all command types"""

    def test_get_log_request(self):
        """Test get log request structure"""
        req = cxlmi.cxlmi_cmd_get_log_req()
        req.offset = 0
        req.length = 1024

        self.assertEqual(req.offset, 0)
        self.assertEqual(req.length, 1024)

    def test_event_records_request(self):
        """Test get event records request"""
        req = cxlmi.cxlmi_cmd_get_event_records_req()
        req.event_log = 0x00  # Informational event log

        self.assertEqual(req.event_log, 0x00)

    def test_clear_event_records(self):
        """Test clear event records structure"""
        req = cxlmi.cxlmi_cmd_clear_event_records_req()
        req.event_log = 0x00
        req.clear_flags = 0x01
        req.nr_recs = 5

        self.assertEqual(req.event_log, 0x00)
        self.assertEqual(req.clear_flags, 0x01)
        self.assertEqual(req.nr_recs, 5)

    def test_scan_media_request(self):
        """Test scan media request structure"""
        req = cxlmi.cxlmi_cmd_scan_media_req()
        req.scan_media_physaddr = 0x1000
        req.scan_media_physaddr_length = 0x10000
        req.scan_media_flags = 0x00

        self.assertEqual(req.scan_media_physaddr, 0x1000)
        self.assertEqual(req.scan_media_physaddr_length, 0x10000)
        self.assertEqual(req.scan_media_flags, 0x00)

    def test_fmapi_get_ld_allocations_request(self):
        """Test FM-API get LD allocations request"""
        req = cxlmi.cxlmi_cmd_fmapi_get_ld_allocations_req()
        req.start_ld_id = 0
        req.ld_allocation_list_limit = 16

        self.assertEqual(req.start_ld_id, 0)
        self.assertEqual(req.ld_allocation_list_limit, 16)

    def test_fmapi_bind_vppb(self):
        """Test FM-API bind vPPB structure"""
        req = cxlmi.cxlmi_cmd_fmapi_bind_vppb_req()
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
        req = cxlmi.cxlmi_cmd_fmapi_unbind_vppb_req()
        req.vcs_id = 1
        req.vppb_id = 5
        req.option = 0

        self.assertEqual(req.vcs_id, 1)
        self.assertEqual(req.vppb_id, 5)
        self.assertEqual(req.option, 0)

    def test_fmapi_phys_port_control(self):
        """Test FM-API physical port control"""
        req = cxlmi.cxlmi_cmd_fmapi_phys_port_control_req()
        req.ppb_id = 2
        req.port_opcode = 0x01  # Example opcode

        self.assertEqual(req.ppb_id, 2)
        self.assertEqual(req.port_opcode, 0x01)

    def test_dc_extent_list_request(self):
        """Test DC extent list request"""
        req = cxlmi.cxlmi_cmd_memdev_get_dc_extent_list_req()
        req.extent_cnt = 10
        req.start_extent_idx = 0

        self.assertEqual(req.extent_cnt, 10)
        self.assertEqual(req.start_extent_idx, 0)


class TestFlexibleArrayStructures(unittest.TestCase):
    """Test that structures with flexible array members work correctly

    These structures have C99 flexible array members (e.g., uint8_t data[])
    at the end. SWIG cannot expose these fields to Python, but the structures
    themselves are fully functional - all fixed-size fields work normally.
    """

    def test_event_records_response(self):
        """Test cxlmi_cmd_get_event_records_rsp with hidden records[] field"""
        # This structure has 'struct cxlmi_event_record records[]' flex array
        event_rsp = cxlmi.cxlmi_cmd_get_event_records_rsp()

        # All fixed fields should be accessible
        event_rsp.overflow_err_count = 5
        event_rsp.first_overflow_timestamp = 1234567890
        event_rsp.last_overflow_timestamp = 9876543210
        event_rsp.record_count = 3

        self.assertEqual(event_rsp.overflow_err_count, 5)
        self.assertEqual(event_rsp.first_overflow_timestamp, 1234567890)
        self.assertEqual(event_rsp.last_overflow_timestamp, 9876543210)
        self.assertEqual(event_rsp.record_count, 3)

    def test_supported_logs(self):
        """Test cxlmi_cmd_get_supported_logs with hidden entries[] field"""
        # This structure has 'struct cxlmi_supported_log_entry entries[]' flex array
        logs = cxlmi.cxlmi_cmd_get_supported_logs_rsp()

        # Fixed fields should work
        logs.num_supported_log_entries = 7

        self.assertEqual(logs.num_supported_log_entries, 7)

    def test_firmware_info(self):
        """Test cxlmi_cmd_get_fw_info with hidden fw_slot_info[] field"""
        # This structure has 'uint8_t fw_slot_info[]' flex array
        fw = cxlmi.cxlmi_cmd_get_fw_info_rsp()

        fw.num_slots = 4
        fw.active_slot = 1
        fw.staged_slot = 2

        self.assertEqual(fw.num_slots, 4)
        self.assertEqual(fw.active_slot, 1)
        self.assertEqual(fw.staged_slot, 2)

    def test_poison_list_response(self):
        """Test cxlmi_cmd_memdev_get_poison_list_rsp with hidden media_error_records[]"""
        # This structure has 'struct cxlmi_memdev_media_err_record media_error_records[]'
        poison = cxlmi.cxlmi_cmd_memdev_get_poison_list_rsp()

        poison.flags = 0x03
        poison.overflow_timestamp = 555666777
        poison.record_count = 10

        self.assertEqual(poison.flags, 0x03)
        self.assertEqual(poison.overflow_timestamp, 555666777)
        self.assertEqual(poison.record_count, 10)

    def test_get_log_cel_response(self):
        """Test cxlmi_cmd_get_log_cel_rsp with hidden entries[] field"""
        # This structure has 'struct cxlmi_supported_log_entry entries[]' flex array
        cel_rsp = cxlmi.cxlmi_cmd_get_log_cel_rsp()

        # Can access fixed fields
        cel_rsp.num_entries = 15

        self.assertEqual(cel_rsp.num_entries, 15)

    def test_identify_with_hidden_component_data(self):
        """Test cxlmi_cmd_identify with hidden component_specific_ident_data[]"""
        # This structure has 'uint8_t component_specific_ident_data[]' flex array
        ident = cxlmi.cxlmi_cmd_identify_rsp()

        # All other fields should be accessible
        ident.vendor_id = 0x8086
        ident.device_id = 0x5678
        ident.subsystem_vendor_id = 0x1234
        ident.subsystem_id = 0xABCD
        ident.serial_number = 0x123456789ABCDEF0
        ident.max_msg_size = 9
        ident.component_type = 0x03

        self.assertEqual(ident.vendor_id, 0x8086)
        self.assertEqual(ident.device_id, 0x5678)
        self.assertEqual(ident.subsystem_vendor_id, 0x1234)
        self.assertEqual(ident.subsystem_id, 0xABCD)
        self.assertEqual(ident.serial_number, 0x123456789ABCDEF0)
        self.assertEqual(ident.max_msg_size, 9)
        self.assertEqual(ident.component_type, 0x03)


class TestComplexStructures(unittest.TestCase):
    """Test more complex nested structures"""

    def test_get_supported_features_request(self):
        """Test get supported features request"""
        req = cxlmi.cxlmi_cmd_get_supported_features_req()
        req.count = 10
        req.starting_feature_index = 0

        self.assertEqual(req.count, 10)
        self.assertEqual(req.starting_feature_index, 0)

    def test_get_feature_request(self):
        """Test get feature request"""
        req = cxlmi.cxlmi_cmd_get_feature_req()
        req.offset = 0
        req.count = 256
        req.selection = 0x01

        self.assertEqual(req.offset, 0)
        self.assertEqual(req.count, 256)
        self.assertEqual(req.selection, 0x01)

    def test_media_operations_discovery_request(self):
        """Test media operations discovery request"""
        req = cxlmi.cxlmi_cmd_memdev_media_operations_discovery_req()
        req.media_operation_class = 0x01
        req.media_operation_subclass = 0x00
        req.dpa_range_count = 1

        self.assertEqual(req.media_operation_class, 0x01)
        self.assertEqual(req.media_operation_subclass, 0x00)
        self.assertEqual(req.dpa_range_count, 1)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestContext))
    suite.addTests(loader.loadTestsFromTestCase(TestTunneling))
    suite.addTests(loader.loadTestsFromTestCase(TestReturnCodes))
    suite.addTests(loader.loadTestsFromTestCase(TestStructures))
    suite.addTests(loader.loadTestsFromTestCase(TestEndpointIteration))
    suite.addTests(loader.loadTestsFromTestCase(TestConstants))
    suite.addTests(loader.loadTestsFromTestCase(TestCommandRequestStructures))
    suite.addTests(loader.loadTestsFromTestCase(TestFlexibleArrayStructures))
    suite.addTests(loader.loadTestsFromTestCase(TestComplexStructures))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
