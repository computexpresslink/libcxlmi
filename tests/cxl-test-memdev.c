// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * CXL Memory Device Command Set unit tests for libcxlmi
 *
 * Tests memdev commands (CXL r3.1 Section 8.2.9.9) against a CXL device.
 * Supports tunneling through a CXL switch with -p <port> option.
 */

#include "test-common.h"

TEST_DECLARE_COUNTERS;
TEST_DECLARE_TUNNEL_CONFIG;

/*
 * Identify and Capacity Commands
 */

static void test_identify(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_identify_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_identify(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("identify", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("identify", rc_str(rc));
		return;
	}

	/* Basic sanity checks */
	if (rsp.total_capacity == 0) {
		TEST_FAIL("identify", "zero total capacity");
		return;
	}

	TEST_PASS("identify");
	if (verbose) {
		printf("           total_capacity: %lu MB\n",
		       (unsigned long)(rsp.total_capacity * 256));
		printf("           volatile_capacity: %lu MB\n",
		       (unsigned long)(rsp.volatile_capacity * 256));
		printf("           persistent_capacity: %lu MB\n",
		       (unsigned long)(rsp.persistent_capacity * 256));
		printf("           lsa_size: %u bytes\n", rsp.lsa_size);
		printf("           inject_poison_limit: %u\n", rsp.inject_poison_limit);
	}
}

static void test_get_partition_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_partition_info_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_partition_info(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_partition_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_partition_info", rc_str(rc));
		return;
	}

	TEST_PASS("get_partition_info");
	if (verbose) {
		printf("           active_vmem: %lu MB\n",
		       (unsigned long)(rsp.active_vmem * 256));
		printf("           active_pmem: %lu MB\n",
		       (unsigned long)(rsp.active_pmem * 256));
		printf("           next_vmem: %lu MB\n",
		       (unsigned long)(rsp.next_vmem * 256));
		printf("           next_pmem: %lu MB\n",
		       (unsigned long)(rsp.next_pmem * 256));
	}
}

/*
 * Label Storage Area Commands
 */

static void test_get_lsa(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_identify_rsp id = {0};
	struct cxlmi_cmd_memdev_get_lsa_req req = {0};
	uint8_t *lsa_data;
	size_t lsa_size;
	int rc;

	/* First get LSA size from identify */
	rc = cxlmi_cmd_memdev_identify(ep, get_tunnel_info(), &id);
	if (rc) {
		TEST_SKIP("get_lsa", "failed to get LSA size");
		return;
	}

	lsa_size = id.lsa_size;
	if (lsa_size == 0) {
		TEST_SKIP("get_lsa", "no LSA available");
		return;
	}

	/* Read first 256 bytes or full LSA if smaller */
	if (lsa_size > 256)
		lsa_size = 256;

	lsa_data = calloc(1, lsa_size);
	if (!lsa_data) {
		TEST_FAIL("get_lsa", "allocation failed");
		return;
	}

	req.offset = 0;
	req.length = lsa_size;

	rc = cxlmi_cmd_memdev_get_lsa(ep, get_tunnel_info(), &req, lsa_data);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_lsa", "not supported");
		free(lsa_data);
		return;
	}
	if (rc) {
		TEST_FAIL("get_lsa", rc_str(rc));
		free(lsa_data);
		return;
	}

	TEST_PASS("get_lsa");
	if (verbose) {
		printf("           total_lsa_size: %u\n", id.lsa_size);
		printf("           read_offset: %u\n", req.offset);
		printf("           read_length: %zu\n", lsa_size);
	}
	free(lsa_data);
}

/*
 * Health and Alert Commands
 */

static void test_get_health_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_health_info_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_health_info(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_health_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_health_info", rc_str(rc));
		return;
	}

	TEST_PASS("get_health_info");
	if (verbose) {
		printf("           health_status: 0x%02x\n", rsp.health_status);
		printf("           media_status: 0x%02x\n", rsp.media_status);
		printf("           additional_status: 0x%02x\n", rsp.additional_status);
		printf("           life_used: %u%%\n", rsp.life_used);
		printf("           device_temperature: %d C\n", (int16_t)rsp.device_temperature);
		printf("           dirty_shutdown_count: %u\n", rsp.dirty_shutdown_count);
		printf("           corrected_volatile_error_count: %u\n",
		       rsp.corrected_volatile_error_count);
		printf("           corrected_persistent_error_count: %u\n",
		       rsp.corrected_persistent_error_count);
	}
}

static void test_get_alert_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_alert_config_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_alert_config(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_alert_config", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_alert_config", rc_str(rc));
		return;
	}

	TEST_PASS("get_alert_config");
	if (verbose) {
		printf("           valid_alerts: 0x%02x\n", rsp.valid_alerts);
		printf("           programmable_alerts: 0x%02x\n", rsp.programmable_alerts);
		printf("           life_used_critical_threshold: %u%%\n",
		       rsp.life_used_critical_alert_threshold);
		printf("           life_used_warning_threshold: %u%%\n",
		       rsp.life_used_programmable_warning_threshold);
		printf("           over_temp_critical_threshold: %u\n",
		       rsp.device_over_temperature_critical_alert_threshold);
		printf("           under_temp_critical_threshold: %u\n",
		       rsp.device_under_temperature_critical_alert_threshold);
	}
}

static void test_set_alert_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_alert_config_rsp get_rsp = {0};
	struct cxlmi_cmd_memdev_set_alert_config_req set_req = {0};
	int rc;

	/* Get current config */
	rc = cxlmi_cmd_memdev_get_alert_config(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_alert_config", "get not supported");
		return;
	}

	/* Set same warning thresholds (safe operation) */
	set_req.life_used_programmable_warning_threshold =
		get_rsp.life_used_programmable_warning_threshold;
	set_req.device_over_temperature_programmable_warning_threshold =
		get_rsp.device_over_temperature_programmable_warning_threshold;
	set_req.device_under_temperature_programmable_warning_threshold =
		get_rsp.device_under_temperature_programmable_warning_threshold;
	set_req.corrected_volatile_mem_error_programmable_warning_threshold =
		get_rsp.corrected_volatile_mem_error_programmable_warning_threshold;
	set_req.corrected_persistent_mem_error_programmable_warning_threshold =
		get_rsp.corrected_persistent_mem_error_programmable_warning_threshold;

	rc = cxlmi_cmd_memdev_set_alert_config(ep, get_tunnel_info(), &set_req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_alert_config", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_alert_config", rc_str(rc));
		return;
	}

	TEST_PASS("set_alert_config");
}

static void test_get_shutdown_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_shutdown_state_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_shutdown_state(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_shutdown_state", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_shutdown_state", rc_str(rc));
		return;
	}

	TEST_PASS("get_shutdown_state");
	if (verbose)
		printf("           state: 0x%02x\n", rsp.state);
}

/*
 * Poison Commands
 */

static void test_get_poison_list(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp rsp = {0};
	int rc;

	req.get_poison_list_phy_addr = 0;
	req.get_poison_list_phy_addr_len = 0x10000; /* 64KB */

	rc = cxlmi_cmd_get_poison_list(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_poison_list", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_poison_list", rc_str(rc));
		return;
	}

	TEST_PASS("get_poison_list");
	if (verbose) {
		printf("           poison_list_flags: 0x%02x\n",
		       rsp.poison_list_flags);
		printf("           more_err_media_record_cnt: %u\n",
		       rsp.more_err_media_record_cnt);
	}
}

static void test_inject_clear_poison(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_identify_rsp id = {0};
	struct cxlmi_cmd_memdev_inject_poison_req inject = {0};
	struct cxlmi_cmd_memdev_clear_poison_req clear = {0};
	int rc;

	/* Check if poison injection is supported */
	rc = cxlmi_cmd_memdev_identify(ep, get_tunnel_info(), &id);
	if (rc) {
		TEST_SKIP("inject_poison", "failed to check caps");
		return;
	}

	if (id.inject_poison_limit == 0) {
		TEST_SKIP("inject_poison", "poison injection not supported");
		return;
	}

	/* Inject poison at a test address */
	inject.inject_poison_phy_addr = 0x1000;
	rc = cxlmi_cmd_memdev_inject_poison(ep, get_tunnel_info(), &inject);
	if (is_unsupported(rc)) {
		TEST_SKIP("inject_poison", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("inject_poison", rc_str(rc));
		return;
	}

	/* Clear the poison */
	clear.clear_poison_phy_addr = 0x1000;
	memset(clear.clear_poison_write_data, 0, 64);

	rc = cxlmi_cmd_memdev_clear_poison(ep, get_tunnel_info(), &clear);
	if (rc) {
		TEST_FAIL("clear_poison", rc_str(rc));
		return;
	}

	TEST_PASS("inject_poison");
	TEST_PASS("clear_poison");
}

/*
 * Media Scan Commands
 */

static void test_get_scan_media_caps(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp rsp = {0};
	int rc;

	req.get_scan_media_capabilities_start_physaddr = 0;
	req.get_scan_media_capabilities_physaddr_length = 0x10000;

	rc = cxlmi_cmd_get_scan_media_capabilities(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_scan_media_caps", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_scan_media_caps", rc_str(rc));
		return;
	}

	TEST_PASS("get_scan_media_caps");
	if (verbose)
		printf("           estimated_scan_media_time: %u ms\n",
		       rsp.estimated_scan_media_time);
}

/*
 * QoS Commands
 */

static void test_get_sld_qos_control(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_sld_qos_control_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_sld_qos_control(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_sld_qos_control", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_sld_qos_control", rc_str(rc));
		return;
	}

	TEST_PASS("get_sld_qos_control");
	if (verbose) {
		printf("           qos_telemetry_control: 0x%02x\n",
		       rsp.qos_telemetry_control);
		printf("           egress_moderate_percentage: %u%%\n",
		       rsp.egress_moderate_percentage);
		printf("           egress_severe_percentage: %u%%\n",
		       rsp.egress_severe_percentage);
		printf("           backpressure_sample_interval: %u\n",
		       rsp.backpressure_sample_interval);
	}
}

static void test_set_sld_qos_control(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_sld_qos_control_rsp get_rsp = {0};
	struct cxlmi_cmd_memdev_set_sld_qos_control_req set_req = {0};
	int rc;

	/* Get current config */
	rc = cxlmi_cmd_memdev_get_sld_qos_control(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_sld_qos_control", "get not supported");
		return;
	}

	/* Set same config (safe operation) */
	set_req.qos_telemetry_control = get_rsp.qos_telemetry_control;
	set_req.egress_moderate_percentage = get_rsp.egress_moderate_percentage;
	set_req.egress_severe_percentage = get_rsp.egress_severe_percentage;
	set_req.backpressure_sample_interval = get_rsp.backpressure_sample_interval;

	rc = cxlmi_cmd_memdev_set_sld_qos_control(ep, get_tunnel_info(), &set_req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_sld_qos_control", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_sld_qos_control", rc_str(rc));
		return;
	}

	TEST_PASS("set_sld_qos_control");
}

static void test_get_sld_qos_status(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_sld_qos_status_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_sld_qos_status(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_sld_qos_status", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_sld_qos_status", rc_str(rc));
		return;
	}

	TEST_PASS("get_sld_qos_status");
	if (verbose)
		printf("           backpressure_avg_percentage: %u%%\n",
		       rsp.backpressure_avg_percentage);
}

/*
 * Security Commands
 */

static void test_get_security_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_security_state_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_security_state(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_security_state", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_security_state", rc_str(rc));
		return;
	}

	TEST_PASS("get_security_state");
	if (verbose)
		printf("           security_state: 0x%08x\n", rsp.security_state);
}

/*
 * Dynamic Capacity Commands
 */

static void test_get_dc_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp));
	if (!rsp) {
		TEST_FAIL("get_dc_config", "allocation failed");
		return;
	}

	req.region_cnt = 8;
	req.start_region_id = 0;

	rc = cxlmi_cmd_memdev_get_dc_config(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_dc_config", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_dc_config", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_dc_config");
	if (verbose) {
		printf("           num_regions: %u\n", rsp->num_regions);
		printf("           regions_returned: %u\n", rsp->regions_returned);
		printf("           num_extents_supported: %u\n", rsp->num_extents_supported);
		printf("           num_extents_available: %u\n", rsp->num_extents_available);
		printf("           num_tags_supported: %u\n", rsp->num_tags_supported);
		printf("           num_tags_available: %u\n", rsp->num_tags_available);
	}
	free(rsp);
}

static void test_get_dc_extent_list(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 8 * sizeof(rsp->extents[0]));
	if (!rsp) {
		TEST_FAIL("get_dc_extent_list", "allocation failed");
		return;
	}

	req.extent_cnt = 8;
	req.start_extent_idx = 0;

	rc = cxlmi_cmd_memdev_get_dc_extent_list(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_dc_extent_list", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_dc_extent_list", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_dc_extent_list");
	if (verbose) {
		printf("           num_extents_returned: %u\n",
		       rsp->num_extents_returned);
		printf("           total_num_extents: %u\n",
		       rsp->total_num_extents);
		printf("           generation_num: %u\n",
		       rsp->generation_num);
	}
	free(rsp);
}

/*
 * Destructive Commands
 */

static void test_set_partition_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_partition_info_rsp get_rsp = {0};
	struct cxlmi_cmd_memdev_set_partition_info_req req = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_partition_info(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_partition_info", "get not supported");
		return;
	}

	/* Set same volatile capacity (safe operation) */
	req.volatile_capacity = get_rsp.active_vmem;
	req.flags = 0;

	rc = cxlmi_cmd_memdev_set_partition_info(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_partition_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_partition_info", rc_str(rc));
		return;
	}

	TEST_PASS("set_partition_info");
}

static void test_set_lsa(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_identify_rsp id = {0};
	struct cxlmi_cmd_memdev_get_lsa_req get_req = {0};
	struct cxlmi_cmd_memdev_set_lsa_req *set_req;
	uint8_t *lsa_data;
	size_t lsa_size;
	int rc;

	/* First get LSA size from identify */
	rc = cxlmi_cmd_memdev_identify(ep, get_tunnel_info(), &id);
	if (rc) {
		TEST_SKIP("set_lsa", "failed to get LSA size");
		return;
	}

	lsa_size = id.lsa_size;
	if (lsa_size == 0) {
		TEST_SKIP("set_lsa", "no LSA available");
		return;
	}

	/* Read first 256 bytes or full LSA if smaller */
	if (lsa_size > 256)
		lsa_size = 256;

	lsa_data = calloc(1, lsa_size);
	if (!lsa_data) {
		TEST_FAIL("set_lsa", "allocation failed");
		return;
	}

	get_req.offset = 0;
	get_req.length = lsa_size;

	rc = cxlmi_cmd_memdev_get_lsa(ep, get_tunnel_info(), &get_req, lsa_data);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_lsa", "get not supported");
		free(lsa_data);
		return;
	}
	if (rc) {
		TEST_SKIP("set_lsa", "failed to read LSA");
		free(lsa_data);
		return;
	}

	/* Write back the same data (safe operation) */
	set_req = calloc(1, sizeof(*set_req) + lsa_size);
	if (!set_req) {
		TEST_FAIL("set_lsa", "allocation failed");
		free(lsa_data);
		return;
	}

	set_req->offset = 0;
	memcpy(set_req->data, lsa_data, lsa_size);

	rc = cxlmi_cmd_memdev_set_lsa(ep, get_tunnel_info(), set_req, lsa_size);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_lsa", "not supported");
		free(set_req);
		free(lsa_data);
		return;
	}
	if (rc) {
		TEST_FAIL("set_lsa", rc_str(rc));
		free(set_req);
		free(lsa_data);
		return;
	}

	TEST_PASS("set_lsa");
	free(set_req);
	free(lsa_data);
}

static void test_set_shutdown_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_shutdown_state_rsp get_rsp = {0};
	struct cxlmi_cmd_memdev_set_shutdown_state_req req = {0};
	int rc;

	rc = cxlmi_cmd_memdev_get_shutdown_state(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_shutdown_state", "get not supported");
		return;
	}

	/* Set same state (safe operation) */
	req.state = get_rsp.state;

	rc = cxlmi_cmd_memdev_set_shutdown_state(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_shutdown_state", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_shutdown_state", rc_str(rc));
		return;
	}

	TEST_PASS("set_shutdown_state");
}

static void test_scan_media(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_scan_media_req req = {0};
	int retries = 3;
	int rc;

	req.scan_media_physaddr = 0;
	req.scan_media_physaddr_length = 0x10000; /* 64KB */
	req.scan_media_flags = 0;

	do {
		rc = cxlmi_cmd_scan_media(ep, get_tunnel_info(), &req);
		if (rc == CXLMI_RET_BUSY) {
			if (!wait_for_bg_done(ep, 5000))
				usleep(500000);
			retries--;
			continue;
		}
		break;
	} while (retries > 0);

	if (is_unsupported(rc)) {
		TEST_SKIP("scan_media", "not supported");
		return;
	}
	if (rc == CXLMI_RET_BUSY) {
		TEST_SKIP("scan_media", "device busy timeout");
		return;
	}
	if (is_bg_success(rc)) {
		TEST_PASS("scan_media");
		return;
	}
	TEST_FAIL("scan_media", rc_str(rc));
}

static void test_get_scan_media_results(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_scan_media_results_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->record[0]));
	if (!rsp) {
		TEST_FAIL("get_scan_media_results", "allocation failed");
		return;
	}

	rc = cxlmi_cmd_get_scan_media_results(ep, get_tunnel_info(), rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_scan_media_results", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_scan_media_results", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_scan_media_results");
	if (verbose) {
		printf("           scan_media_flags: 0x%02x\n",
		       rsp->scan_media_flags);
		printf("           media_error_count: %u\n",
		       rsp->media_error_count);
	}
	free(rsp);
}

static void test_sanitize(struct cxlmi_endpoint *ep)
{
	int retries = 3;
	int rc;

	do {
		rc = cxlmi_cmd_memdev_sanitize(ep, get_tunnel_info());
		if (rc == CXLMI_RET_BUSY) {
			if (!wait_for_bg_done(ep, 5000))
				usleep(500000);
			retries--;
			continue;
		}
		break;
	} while (retries > 0);

	if (is_unsupported(rc)) {
		TEST_SKIP("sanitize", "not supported");
		return;
	}
	if (rc == CXLMI_RET_BUSY) {
		TEST_SKIP("sanitize", "device busy timeout");
		return;
	}
	if (is_bg_success(rc)) {
		TEST_PASS("sanitize");
		return;
	}
	TEST_FAIL("sanitize", rc_str(rc));
}

static void test_secure_erase(struct cxlmi_endpoint *ep)
{
	int retries = 3;
	int rc;

	do {
		rc = cxlmi_cmd_memdev_secure_erase(ep, get_tunnel_info());
		if (rc == CXLMI_RET_BUSY) {
			if (!wait_for_bg_done(ep, 5000))
				usleep(500000);
			retries--;
			continue;
		}
		break;
	} while (retries > 0);

	if (is_unsupported(rc)) {
		TEST_SKIP("secure_erase", "not supported");
		return;
	}
	if (rc == CXLMI_RET_BUSY) {
		TEST_SKIP("secure_erase", "device busy timeout");
		return;
	}
	if (is_bg_success(rc)) {
		TEST_PASS("secure_erase");
		return;
	}
	TEST_FAIL("secure_erase", rc_str(rc));
}

static void test_media_operations_discovery(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_media_operations_discovery_req req = {0};
	struct cxlmi_cmd_memdev_media_operations_discovery_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->entry[0]));
	if (!rsp) {
		TEST_FAIL("media_operations_discovery", "allocation failed");
		return;
	}

	req.media_operation_class = 0;
	req.media_operation_subclass = 0;
	req.dpa_range_count = 0;
	req.discovery_osa.start_index = 0;
	req.discovery_osa.num_ops = 16;

	rc = cxlmi_cmd_memdev_media_operations_discovery(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("media_operations_discovery", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("media_operations_discovery", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("media_operations_discovery");
	if (verbose) {
		printf("           dpa_range_granularity: %lu\n",
		       (unsigned long)rsp->dpa_range_granularity);
		printf("           total_supported_ops: %u\n",
		       rsp->total_supported_ops);
		printf("           num_supported_ops: %u\n",
		       rsp->num_supported_ops);
	}
	free(rsp);
}

static void test_media_operations_sanitize(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_media_operations_sanitize_req *req;
	int retries = 3;
	int rc;

	req = calloc(1, sizeof(*req) + sizeof(req->dpa_range_list[0]));
	if (!req) {
		TEST_FAIL("media_operations_sanitize", "allocation failed");
		return;
	}

	req->media_operation_class = 0; /* Sanitize class */
	req->media_operation_subclass = 0;
	req->dpa_range_count = 1;
	req->dpa_range_list[0].starting_dpa = 0;
	req->dpa_range_list[0].length = 0x10000;

	do {
		rc = cxlmi_cmd_memdev_media_operations_sanitize(ep, get_tunnel_info(), req);
		if (rc == CXLMI_RET_BUSY) {
			if (!wait_for_bg_done(ep, 5000))
				usleep(500000);
			retries--;
			continue;
		}
		break;
	} while (retries > 0);

	if (is_unsupported(rc)) {
		TEST_SKIP("media_operations_sanitize", "not supported");
		free(req);
		return;
	}
	if (rc == CXLMI_RET_BUSY) {
		TEST_SKIP("media_operations_sanitize", "device busy timeout");
		free(req);
		return;
	}
	if (is_bg_success(rc)) {
		TEST_PASS("media_operations_sanitize");
		free(req);
		return;
	}
	TEST_FAIL("media_operations_sanitize", rc_str(rc));
	free(req);
}

static void test_freeze_security_state(struct cxlmi_endpoint *ep)
{
	int rc;

	rc = cxlmi_cmd_memdev_freeze_security_state(ep, get_tunnel_info());
	if (is_unsupported(rc)) {
		TEST_SKIP("freeze_security_state", "not supported");
		return;
	}
	if (rc == CXLMI_RET_SECURITY) {
		TEST_SKIP("freeze_security_state", "invalid security state");
		return;
	}
	if (rc) {
		TEST_FAIL("freeze_security_state", rc_str(rc));
		return;
	}

	TEST_PASS("freeze_security_state");
}

static void test_add_dc_response(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_add_dc_response_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("add_dc_response", "allocation failed");
		return;
	}

	req->updated_extent_list_size = 0;
	req->flags = 0;

	rc = cxlmi_cmd_memdev_add_dc_response(ep, get_tunnel_info(), req);
	if (is_unsupported(rc)) {
		TEST_SKIP("add_dc_response", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("add_dc_response", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("add_dc_response");
	free(req);
}

static void test_release_dc(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_release_dc_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("release_dc", "allocation failed");
		return;
	}

	req->updated_extent_list_size = 0;
	req->flags = 0;

	rc = cxlmi_cmd_memdev_release_dc(ep, get_tunnel_info(), req);
	if (is_unsupported(rc)) {
		TEST_SKIP("release_dc", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("release_dc", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("release_dc");
	free(req);
}

static void test_set_passphrase(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_set_passphrase_req req = {0};
	int rc;

	/* Try to set user passphrase with null values - typically requires existing passphrase */
	req.passphrase_type = 0; /* User passphrase */

	rc = cxlmi_cmd_memdev_set_passphrase(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_passphrase", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_passphrase", rc_str(rc));
		return;
	}

	TEST_PASS("set_passphrase");
}

static void test_disable_passphrase(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_disable_passphrase_req req = {0};
	int rc;

	req.passphrase_type = 0; /* User passphrase */

	rc = cxlmi_cmd_memdev_disable_passphrase(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("disable_passphrase", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("disable_passphrase", rc_str(rc));
		return;
	}

	TEST_PASS("disable_passphrase");
}

static void test_unlock(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_unlock_req req = {0};
	int rc;

	/* Try unlock with null passphrase */
	rc = cxlmi_cmd_memdev_unlock(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("unlock", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("unlock", rc_str(rc));
		return;
	}

	TEST_PASS("unlock");
}

static void test_passphrase_secure_erase(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_passphrase_secure_erase_req req = {0};
	int rc;

	req.passphrase_type = 0; /* User passphrase */

	rc = cxlmi_cmd_memdev_passphrase_secure_erase(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("passphrase_secure_erase", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("passphrase_secure_erase", rc_str(rc));
		return;
	}

	TEST_PASS("passphrase_secure_erase");
}

static void test_security_send(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_security_send_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("security_send", "allocation failed");
		return;
	}

	req->security_protocol = 0;
	req->sp_specific = 0;

	rc = cxlmi_cmd_memdev_security_send(ep, get_tunnel_info(), req, 0);
	if (is_unsupported(rc)) {
		TEST_SKIP("security_send", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("security_send", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("security_send");
	free(req);
}

static void test_security_receive(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_security_receive_req req = {0};
	uint8_t rsp_buf[256] = {0};
	int rc;

	req.security_protocol = 0;
	req.sp_specific = 0;

	rc = cxlmi_cmd_memdev_security_receive(ep, get_tunnel_info(), &req, rsp_buf);
	if (is_unsupported(rc)) {
		TEST_SKIP("security_receive", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("security_receive", rc_str(rc));
		return;
	}

	TEST_PASS("security_receive");
}

static void run_tests(struct cxlmi_endpoint *ep)
{
	printf("\n[Memory Device Command Set]\n");

	/* Identify and Capacity */
	test_identify(ep);
	test_get_partition_info(ep);

	/* Label Storage Area */
	test_get_lsa(ep);

	/* Health and Alert */
	test_get_health_info(ep);
	test_get_alert_config(ep);
	test_set_alert_config(ep);
	test_get_shutdown_state(ep);

	/* Poison */
	test_get_poison_list(ep);
	test_inject_clear_poison(ep);

	/* Media Scan */
	test_get_scan_media_caps(ep);

	/* QoS */
	test_get_sld_qos_control(ep);
	test_set_sld_qos_control(ep);
	test_get_sld_qos_status(ep);

	/* Security */
	test_get_security_state(ep);

	/* Dynamic Capacity */
	test_get_dc_config(ep);
	test_get_dc_extent_list(ep);

	/* Destructive Commands */
	test_set_partition_info(ep);
	test_set_lsa(ep);
	test_set_shutdown_state(ep);
	test_scan_media(ep);
	test_get_scan_media_results(ep);
	test_sanitize(ep);
	test_secure_erase(ep);
	test_media_operations_discovery(ep);
	test_media_operations_sanitize(ep);
	test_freeze_security_state(ep);
	test_add_dc_response(ep);
	test_release_dc(ep);

	/* Security Commands (destructive) */
	test_set_passphrase(ep);
	test_disable_passphrase(ep);
	test_unlock(ep);
	test_passphrase_secure_erase(ep);
	test_security_send(ep);
	test_security_receive(ep);
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options] <target>\n", progname);
	print_target_usage();
	print_tunnel_usage();
	fprintf(stderr, "\nGeneral Options:\n");
	fprintf(stderr, "  -v, --verbose         Show detailed response data\n");
	fprintf(stderr, "  -h, --help            Show this help\n");
	fprintf(stderr, "\nExamples:\n");
	fprintf(stderr, "  %s mctp:50              Direct to device at MCTP addr 50\n", progname);
	fprintf(stderr, "  %s -p 2 mctp:50         Via switch port 2 to Type3 device\n", progname);
	fprintf(stderr, "  %s -p 2 -l 0 mctp:50     Via switch port 2 to MLD LD0 (level 2)\n", progname);
}

int main(int argc, char **argv)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep;
	const char *target = NULL;
	int rc = 1;
	int argidx;

	for (argidx = 1; argidx < argc; argidx++) {
		int consumed;

		if (strcmp(argv[argidx], "-h") == 0 ||
		    strcmp(argv[argidx], "--help") == 0) {
			usage(argv[0]);
			return 0;
		}
		if (strcmp(argv[argidx], "-v") == 0 ||
		    strcmp(argv[argidx], "--verbose") == 0) {
			verbose = true;
			continue;
		}
		consumed = parse_tunnel_arg(argc, argv, argidx);
		if (consumed) {
			argidx += consumed - 1;
			continue;
		}
		if (argv[argidx][0] == '-') {
			fprintf(stderr, "Unknown option: %s\n", argv[argidx]);
			usage(argv[0]);
			return 1;
		}
		target = argv[argidx];
	}

	if (!target) {
		usage(argv[0]);
		return 1;
	}

	printf("========================================\n");
	printf("  libcxlmi Memory Device Command Tests\n");
	printf("========================================\n");
	printf("Target: %s\n", target);
	print_tunnel_config();

	ctx = cxlmi_new_ctx(stdout, LOG_WARNING);
	if (!ctx) {
		fprintf(stderr, "Failed to create context\n");
		return 1;
	}

	ep = open_endpoint(ctx, target);
	if (!ep) {
		fprintf(stderr, "Failed to open endpoint: %s\n", target);
		cxlmi_free_ctx(ctx);
		return 1;
	}

	run_tests(ep);

	TEST_PRINT_RESULTS();
	rc = TEST_EXIT_CODE();
	cxlmi_close(ep);
	cxlmi_free_ctx(ctx);
	return rc;
}
