// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * CXL Generic Command Set unit tests for libcxlmi
 *
 * Tests generic commands (CXL r3.1 Section 8.2.9.1) against a CXL device.
 * Supports tunneling through a CXL switch with -p <port> option.
 */

#include "test-common.h"

TEST_DECLARE_COUNTERS;
TEST_DECLARE_TUNNEL_CONFIG;

/*
 * Device Info and Status Commands
 */

static void test_identify(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_identify(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("identify", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("identify", rc_str(rc));
		return;
	}

	TEST_PASS("identify");
	if (verbose) {
		printf("           vendor_id: 0x%04x\n", rsp.vendor_id);
		printf("           device_id: 0x%04x\n", rsp.device_id);
		printf("           subsys_vendor_id: 0x%04x\n", rsp.subsys_vendor_id);
		printf("           subsys_id: 0x%04x\n", rsp.subsys_id);
		printf("           serial_num: 0x%016lx\n", (unsigned long)rsp.serial_num);
		printf("           component_type: %u\n", rsp.component_type);
	}
}

static void test_bg_op_status(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_bg_op_status_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_bg_op_status(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("bg_op_status", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("bg_op_status", rc_str(rc));
		return;
	}

	TEST_PASS("bg_op_status");
	if (verbose) {
		printf("           status: %u\n", rsp.status);
		printf("           opcode: 0x%04x\n", rsp.opcode);
		printf("           returncode: %u\n", rsp.returncode);
		printf("           vendor_ext_status: 0x%04x\n", rsp.vendor_ext_status);
	}
}

static void test_get_response_msg_limit(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_response_msg_limit_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_response_msg_limit(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_response_msg_limit", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_response_msg_limit", rc_str(rc));
		return;
	}

	TEST_PASS("get_response_msg_limit");
	if (verbose)
		printf("           limit: %u bytes\n", rsp.limit);
}

static void test_set_response_msg_limit(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_response_msg_limit_rsp get_rsp = {0};
	struct cxlmi_cmd_set_response_msg_limit_req set_req = {0};
	struct cxlmi_cmd_set_response_msg_limit_rsp set_rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_response_msg_limit(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_response_msg_limit", "get not supported");
		return;
	}

	set_req.limit = get_rsp.limit;
	rc = cxlmi_cmd_set_response_msg_limit(ep, get_tunnel_info(), &set_req, &set_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_response_msg_limit", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_response_msg_limit", rc_str(rc));
		return;
	}

	TEST_PASS("set_response_msg_limit");
}

static void test_request_bg_op_abort(struct cxlmi_endpoint *ep)
{
	int rc;

	rc = cxlmi_cmd_request_bg_op_abort(ep, get_tunnel_info());
	if (is_unsupported(rc)) {
		TEST_SKIP("request_bg_op_abort", "not supported");
		return;
	}
	if (rc && rc != CXLMI_RET_NO_BGABORT) {
		TEST_FAIL("request_bg_op_abort", rc_str(rc));
		return;
	}

	TEST_PASS("request_bg_op_abort");
}

/*
 * Timestamp Commands
 */

static void test_get_timestamp(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_timestamp_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_timestamp(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_timestamp", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_timestamp", rc_str(rc));
		return;
	}

	TEST_PASS("get_timestamp");
	if (verbose)
		printf("           timestamp: %lu\n", (unsigned long)rsp.timestamp);
}

static void test_set_timestamp(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_timestamp_rsp get_rsp = {0};
	struct cxlmi_cmd_set_timestamp_req set_req = {0};
	int rc;

	rc = cxlmi_cmd_get_timestamp(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_timestamp", "not supported");
		return;
	}

	set_req.timestamp = get_rsp.timestamp;
	rc = cxlmi_cmd_set_timestamp(ep, get_tunnel_info(), &set_req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_timestamp", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_timestamp", rc_str(rc));
		return;
	}

	TEST_PASS("set_timestamp");
}

/*
 * Event Commands
 */

static void test_get_event_records(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->records[0]));
	if (!rsp) {
		TEST_FAIL("get_event_records", "allocation failed");
		return;
	}

	req.event_log = 0;
	rc = cxlmi_cmd_get_event_records(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_event_records", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_event_records", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_event_records");
	if (verbose) {
		printf("           flags: 0x%02x\n", rsp->flags);
		printf("           overflow_err_count: %u\n", rsp->overflow_err_count);
		printf("           record_count: %u\n", rsp->record_count);
	}
	free(rsp);
}

static void test_clear_event_records(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_clear_event_records_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("clear_event_records", "allocation failed");
		return;
	}

	req->event_log = 0;
	req->clear_flags = 1; /* Clear all */
	req->nr_recs = 0;

	rc = cxlmi_cmd_clear_event_records(ep, get_tunnel_info(), req);
	if (is_unsupported(rc)) {
		TEST_SKIP("clear_event_records", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("clear_event_records", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("clear_event_records");
	free(req);
}

static void test_get_event_interrupt_policy(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_event_interrupt_policy_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_event_interrupt_policy(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_event_interrupt_policy", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_event_interrupt_policy", rc_str(rc));
		return;
	}

	TEST_PASS("get_event_interrupt_policy");
	if (verbose) {
		printf("           informational_settings: 0x%02x\n",
		       rsp.informational_settings);
		printf("           warning_settings: 0x%02x\n",
		       rsp.warning_settings);
		printf("           failure_settings: 0x%02x\n",
		       rsp.failure_settings);
		printf("           fatal_settings: 0x%02x\n",
		       rsp.fatal_settings);
#ifndef SUPPORT_CXL_2_0
		printf("           dcd_settings: 0x%02x\n",
		       rsp.dcd_settings);
#endif
	}
}

static void test_set_event_interrupt_policy(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_event_interrupt_policy_rsp get_rsp = {0};
	struct cxlmi_cmd_set_event_interrupt_policy_req set_req = {0};
	int rc;

	rc = cxlmi_cmd_get_event_interrupt_policy(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_event_interrupt_policy", "get not supported");
		return;
	}

	set_req.informational_settings = get_rsp.informational_settings;
	set_req.warning_settings = get_rsp.warning_settings;
	set_req.failure_settings = get_rsp.failure_settings;
	set_req.fatal_settings = get_rsp.fatal_settings;
#ifndef SUPPORT_CXL_2_0
	set_req.dcd_settings = get_rsp.dcd_settings;
#endif

	rc = cxlmi_cmd_set_event_interrupt_policy(ep, get_tunnel_info(), &set_req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_event_interrupt_policy", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_event_interrupt_policy", rc_str(rc));
		return;
	}

	TEST_PASS("set_event_interrupt_policy");
}

/*
 * Firmware Commands
 */

static void test_get_fw_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_fw_info_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_fw_info(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_fw_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_fw_info", rc_str(rc));
		return;
	}

	TEST_PASS("get_fw_info");
	if (verbose) {
		printf("           slots_supported: %u\n", rsp.slots_supported);
		printf("           slot_info: 0x%02x (active=%u, staged=%u)\n",
		       rsp.slot_info, rsp.slot_info & 0x7, (rsp.slot_info >> 3) & 0x7);
		printf("           caps: 0x%02x\n", rsp.caps);
		if (rsp.slots_supported >= 1)
			printf("           slot1_fw_rev: %.16s\n", rsp.fw_rev1);
		if (rsp.slots_supported >= 2)
			printf("           slot2_fw_rev: %.16s\n", rsp.fw_rev2);
		if (rsp.slots_supported >= 3)
			printf("           slot3_fw_rev: %.16s\n", rsp.fw_rev3);
		if (rsp.slots_supported >= 4)
			printf("           slot4_fw_rev: %.16s\n", rsp.fw_rev4);
	}
}

static void test_transfer_fw(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_fw_info_rsp fw_info = {0};
	struct cxlmi_cmd_transfer_fw_req *req;
	uint8_t slot;
	int rc;

	/* Get FW info to find a valid slot */
	rc = cxlmi_cmd_get_fw_info(ep, get_tunnel_info(), &fw_info);
	if (is_unsupported(rc)) {
		TEST_SKIP("transfer_fw", "get_fw_info not supported");
		return;
	}

	/* Use the next available slot, or slot 1 if only one slot */
	if (fw_info.slots_supported > 1)
		slot = ((fw_info.slot_info & 0x7) % fw_info.slots_supported) + 1;
	else
		slot = 1;

	req = calloc(1, sizeof(*req) + 128);
	if (!req) {
		TEST_FAIL("transfer_fw", "allocation failed");
		return;
	}

	req->action = 0; /* Full transfer */
	req->slot = slot;
	req->offset = 0;

	rc = cxlmi_cmd_transfer_fw(ep, get_tunnel_info(), req, 128);
	if (is_unsupported(rc)) {
		TEST_SKIP("transfer_fw", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("transfer_fw", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("transfer_fw");
	free(req);
}

static void test_activate_fw(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_fw_info_rsp fw_info = {0};
	struct cxlmi_cmd_activate_fw_req req = {0};
	int rc;

	rc = cxlmi_cmd_get_fw_info(ep, get_tunnel_info(), &fw_info);
	if (is_unsupported(rc)) {
		TEST_SKIP("activate_fw", "get_fw_info not supported");
		return;
	}

	/* Activate the currently active slot (no-op) */
	req.action = 0; /* Online activation */
	req.slot = (fw_info.slot_info & 0x7);

	rc = cxlmi_cmd_activate_fw(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("activate_fw", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("activate_fw", rc_str(rc));
		return;
	}

	TEST_PASS("activate_fw");
}

/*
 * Log Commands
 */

static void test_get_supported_logs(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_logs_rsp *rsp;
	int rc, i;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->entries[0]));
	if (!rsp) {
		TEST_FAIL("get_supported_logs", "allocation failed");
		return;
	}

	rc = cxlmi_cmd_get_supported_logs(ep, get_tunnel_info(), rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_supported_logs", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_supported_logs", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_supported_logs");
	if (verbose) {
		printf("           num_supported_log_entries: %u\n",
		       rsp->num_supported_log_entries);
		for (i = 0; i < rsp->num_supported_log_entries; i++) {
			printf("             [%d] uuid: ", i);
			for (int j = 0; j < 16; j++)
				printf("%02x", rsp->entries[i].uuid[j]);
			printf(", size: %u\n", rsp->entries[i].log_size);
		}
	}
	free(rsp);
}

static void test_get_supported_logs_sublist(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req req = {0};
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->entries[0]));
	if (!rsp) {
		TEST_FAIL("get_supported_logs_sublist", "allocation failed");
		return;
	}

	req.max_supported_log_entries = 16;
	req.start_log_entry_index = 0;

	rc = cxlmi_cmd_get_supported_logs_sublist(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_supported_logs_sublist", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_supported_logs_sublist", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_supported_logs_sublist");
	if (verbose) {
		printf("           num_supported_log_entries: %u\n",
		       rsp->num_supported_log_entries);
		printf("           total_num_supported_log_entries: %u\n",
		       rsp->total_num_supported_log_entries);
	}
	free(rsp);
}

static void test_get_log_cel(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_logs_rsp *gsl;
	struct cxlmi_cmd_get_log_req req = {0};
	struct cxlmi_cmd_get_log_cel_rsp *cel;
	size_t cel_size = 0;
	int rc, i;

	gsl = calloc(1, sizeof(*gsl) + 16 * sizeof(gsl->entries[0]));
	if (!gsl) {
		TEST_FAIL("get_log_cel", "allocation failed");
		return;
	}

	rc = cxlmi_cmd_get_supported_logs(ep, get_tunnel_info(), gsl);
	if (rc) {
		TEST_SKIP("get_log_cel", "failed to get supported logs");
		free(gsl);
		return;
	}

	for (i = 0; i < gsl->num_supported_log_entries; i++) {
		if (memcmp(gsl->entries[i].uuid, CEL_UUID, 16) == 0) {
			cel_size = gsl->entries[i].log_size;
			break;
		}
	}
	free(gsl);

	if (cel_size == 0) {
		TEST_SKIP("get_log_cel", "CEL not available");
		return;
	}

	cel = calloc(1, sizeof(*cel) + cel_size);
	if (!cel) {
		TEST_FAIL("get_log_cel", "allocation failed");
		return;
	}

	memcpy(req.uuid, CEL_UUID, 16);
	req.offset = 0;
	req.length = cel_size;

	rc = cxlmi_cmd_get_log_cel(ep, get_tunnel_info(), &req, cel);
	if (rc) {
		TEST_FAIL("get_log_cel", rc_str(rc));
		free(cel);
		return;
	}

	TEST_PASS("get_log_cel");
	if (verbose) {
		int num_cmds = cel_size / sizeof(*cel);
		printf("           cel_entries: %d\n", num_cmds);
		for (i = 0; i < num_cmds; i++) {
			printf("             [%3d] opcode: 0x%04x, effect: 0x%04x\n",
			       i, cel[i].opcode, cel[i].command_effect);
		}
	}
	free(cel);
}

static void test_get_log_capabilities(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_log_capabilities_req req = {0};
	struct cxlmi_cmd_get_log_capabilities_rsp rsp = {0};
	int rc;

	memcpy(req.uuid, CEL_UUID, 16);

	rc = cxlmi_cmd_get_log_capabilities(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_log_capabilities", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_log_capabilities", rc_str(rc));
		return;
	}

	TEST_PASS("get_log_capabilities");
	if (verbose)
		printf("           parameter_flags: 0x%08x\n", rsp.parameter_flags);
}

static void test_clear_log(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_clear_log_req req = {0};
	int rc;

	memcpy(req.uuid, VENDOR_DEBUG_UUID, 16);

	rc = cxlmi_cmd_clear_log(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("clear_log", "not supported");
		return;
	}
	if (rc == CXLMI_RET_LOG) {
		TEST_SKIP("clear_log", "log not available");
		return;
	}
	if (rc) {
		TEST_FAIL("clear_log", rc_str(rc));
		return;
	}

	TEST_PASS("clear_log");
}

static void test_populate_log(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_populate_log_req req = {0};
	int retries = 3;
	int rc;

	memcpy(req.uuid, VENDOR_DEBUG_UUID, 16);

	do {
		rc = cxlmi_cmd_populate_log(ep, get_tunnel_info(), &req);

		/* If device is busy with another bg op, wait and retry */
		if (rc == CXLMI_RET_BUSY) {
			if (!wait_for_bg_done(ep, 5000)) {
				/* If bg_op_status not supported, just sleep */
				usleep(500000);
			}
			retries--;
			continue;
		}
		break;
	} while (retries > 0);

	if (is_unsupported(rc)) {
		TEST_SKIP("populate_log", "not supported");
		return;
	}
	if (rc == CXLMI_RET_LOG) {
		TEST_SKIP("populate_log", "log not available");
		return;
	}
	if (rc == CXLMI_RET_BUSY) {
		TEST_SKIP("populate_log", "device busy timeout");
		return;
	}
	if (is_bg_success(rc)) {
		TEST_PASS("populate_log");
		return;
	}
	TEST_FAIL("populate_log", rc_str(rc));
}

/*
 * Feature Commands
 */

static void test_get_supported_features(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	struct cxlmi_cmd_get_supported_features_rsp *rsp;
	int rc, i;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->supported_feature_entries[0]));
	if (!rsp) {
		TEST_FAIL("get_supported_features", "allocation failed");
		return;
	}

	req.count = 16;
	req.starting_feature_index = 0;

	rc = cxlmi_cmd_get_supported_features(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_supported_features", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_supported_features", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_supported_features");
	if (verbose) {
		printf("           num_supported_feature_entries: %u\n",
		       rsp->num_supported_feature_entries);
		printf("           device_supported_features: 0x%04x\n",
		       rsp->device_supported_features);
		for (i = 0; i < rsp->num_supported_feature_entries; i++) {
			printf("             [%d] uuid: ", i);
			for (int j = 0; j < 16; j++)
				printf("%02x", rsp->supported_feature_entries[i].feature_id[j]);
			printf("\n                  get_size: %u, set_size: %u, flags: 0x%08x\n",
			       rsp->supported_feature_entries[i].get_feature_size,
			       rsp->supported_feature_entries[i].set_feature_size,
			       rsp->supported_feature_entries[i].attribute_flags);
		}
	}
	free(rsp);
}

static void test_get_feature(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_features_req sf_req = {0};
	struct cxlmi_cmd_get_supported_features_rsp *sf_rsp;
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp *rsp;
	int rc;

	sf_rsp = calloc(1, sizeof(*sf_rsp) + 16 * sizeof(sf_rsp->supported_feature_entries[0]));
	if (!sf_rsp) {
		TEST_FAIL("get_feature", "allocation failed");
		return;
	}

	sf_req.count = 16;
	sf_req.starting_feature_index = 0;

	rc = cxlmi_cmd_get_supported_features(ep, get_tunnel_info(), &sf_req, sf_rsp);
	if (is_unsupported(rc) || sf_rsp->num_supported_feature_entries == 0) {
		TEST_SKIP("get_feature", "no features supported");
		free(sf_rsp);
		return;
	}

	rsp = calloc(1, sizeof(*rsp) + sf_rsp->supported_feature_entries[0].get_feature_size);
	if (!rsp) {
		TEST_FAIL("get_feature", "allocation failed");
		free(sf_rsp);
		return;
	}

	memcpy(req.feature_id, sf_rsp->supported_feature_entries[0].feature_id, 16);
	req.offset = 0;
	req.count = sf_rsp->supported_feature_entries[0].get_feature_size;
	req.selection = 0;

	rc = cxlmi_cmd_get_feature(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_feature", "not supported");
		free(rsp);
		free(sf_rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_feature", rc_str(rc));
		free(rsp);
		free(sf_rsp);
		return;
	}

	TEST_PASS("get_feature");
	if (verbose) {
		printf("           feature_uuid: "
		       "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		       "%02x%02x-%02x%02x%02x%02x%02x%02x\n",
		       req.feature_id[0], req.feature_id[1],
		       req.feature_id[2], req.feature_id[3],
		       req.feature_id[4], req.feature_id[5],
		       req.feature_id[6], req.feature_id[7],
		       req.feature_id[8], req.feature_id[9],
		       req.feature_id[10], req.feature_id[11],
		       req.feature_id[12], req.feature_id[13],
		       req.feature_id[14], req.feature_id[15]);
		printf("           data_size: %u bytes\n", req.count);
	}
	free(rsp);
	free(sf_rsp);
}

static void test_set_feature(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_features_req sf_req = {0};
	struct cxlmi_cmd_get_supported_features_rsp *sf_rsp;
	struct cxlmi_cmd_get_feature_req get_req = {0};
	struct cxlmi_cmd_get_feature_rsp *get_rsp;
	struct cxlmi_cmd_set_feature_req *set_req;
	size_t feature_size;
	int rc, i;

	sf_rsp = calloc(1, sizeof(*sf_rsp) + 16 * sizeof(sf_rsp->supported_feature_entries[0]));
	if (!sf_rsp) {
		TEST_FAIL("set_feature", "allocation failed");
		return;
	}

	sf_req.count = 16;
	sf_req.starting_feature_index = 0;

	rc = cxlmi_cmd_get_supported_features(ep, get_tunnel_info(), &sf_req, sf_rsp);
	if (is_unsupported(rc) || sf_rsp->num_supported_feature_entries == 0) {
		TEST_SKIP("set_feature", "no features supported");
		free(sf_rsp);
		return;
	}

	/* Find a writable feature */
	for (i = 0; i < sf_rsp->num_supported_feature_entries; i++) {
		if (sf_rsp->supported_feature_entries[i].set_feature_size > 0)
			break;
	}
	if (i >= sf_rsp->num_supported_feature_entries) {
		TEST_SKIP("set_feature", "no writable features");
		free(sf_rsp);
		return;
	}

	feature_size = sf_rsp->supported_feature_entries[i].get_feature_size;

	get_rsp = calloc(1, sizeof(*get_rsp) + feature_size);
	if (!get_rsp) {
		TEST_FAIL("set_feature", "allocation failed");
		free(sf_rsp);
		return;
	}

	memcpy(get_req.feature_id, sf_rsp->supported_feature_entries[i].feature_id, 16);
	get_req.offset = 0;
	get_req.count = feature_size;
	get_req.selection = 0;

	rc = cxlmi_cmd_get_feature(ep, get_tunnel_info(), &get_req, get_rsp);
	if (rc) {
		TEST_SKIP("set_feature", "failed to get current value");
		free(get_rsp);
		free(sf_rsp);
		return;
	}

	set_req = calloc(1, sizeof(*set_req) + feature_size);
	if (!set_req) {
		TEST_FAIL("set_feature", "allocation failed");
		free(get_rsp);
		free(sf_rsp);
		return;
	}

	memcpy(set_req->feature_id, sf_rsp->supported_feature_entries[i].feature_id, 16);
	set_req->set_feature_flags = 0;
	set_req->offset = 0;
	set_req->version = sf_rsp->supported_feature_entries[i].set_feature_version;
	memcpy(set_req->feature_data, get_rsp->feature_data, feature_size);

	rc = cxlmi_cmd_set_feature(ep, get_tunnel_info(), set_req, feature_size);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_feature", "not supported");
		free(set_req);
		free(get_rsp);
		free(sf_rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("set_feature", rc_str(rc));
		free(set_req);
		free(get_rsp);
		free(sf_rsp);
		return;
	}

	TEST_PASS("set_feature");
	free(set_req);
	free(get_rsp);
	free(sf_rsp);
}

static void test_get_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_mctp_event_interrupt_policy_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_get_mctp_event_interrupt_policy(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_mctp_event_interrupt_policy", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_mctp_event_interrupt_policy", rc_str(rc));
		return;
	}

	TEST_PASS("get_mctp_event_interrupt_policy");
	if (verbose)
		printf("           event_interrupt_settings: 0x%04x\n",
		       rsp.event_interrupt_settings);
}

static void test_set_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_mctp_event_interrupt_policy_rsp get_rsp = {0};
	struct cxlmi_cmd_set_mctp_event_interrupt_policy_req set_req = {0};
	int rc;

	rc = cxlmi_cmd_get_mctp_event_interrupt_policy(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_mctp_event_interrupt_policy", "get not supported");
		return;
	}

	/* Set same policy (safe operation) */
	set_req.event_interrupt_settings = get_rsp.event_interrupt_settings;

	rc = cxlmi_cmd_set_mctp_event_interrupt_policy(ep, get_tunnel_info(), &set_req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_mctp_event_interrupt_policy", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_mctp_event_interrupt_policy", rc_str(rc));
		return;
	}

	TEST_PASS("set_mctp_event_interrupt_policy");
}

static void test_event_notification(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_event_notification_req req = {0};
	int rc;

	/* Send a no-op event notification */
	req.event = 0;

	rc = cxlmi_cmd_event_notification(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("event_notification", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("event_notification", rc_str(rc));
		return;
	}

	TEST_PASS("event_notification");
}

static void test_get_log(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_get_supported_logs_rsp *gsl;
	struct cxlmi_cmd_get_log_req req = {0};
	uint8_t *log_data;
	int rc;

	gsl = calloc(1, sizeof(*gsl) + 16 * sizeof(gsl->entries[0]));
	if (!gsl) {
		TEST_FAIL("get_log", "allocation failed");
		return;
	}

	rc = cxlmi_cmd_get_supported_logs(ep, get_tunnel_info(), gsl);
	if (is_unsupported(rc) || gsl->num_supported_log_entries == 0) {
		TEST_SKIP("get_log", "no logs available");
		free(gsl);
		return;
	}

	/* Try to read first available log */
	log_data = calloc(1, gsl->entries[0].log_size);
	if (!log_data) {
		TEST_FAIL("get_log", "allocation failed");
		free(gsl);
		return;
	}

	memcpy(req.uuid, gsl->entries[0].uuid, 16);
	req.offset = 0;
	req.length = gsl->entries[0].log_size;

	rc = cxlmi_cmd_get_log(ep, get_tunnel_info(), &req, log_data);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_log", "not supported");
		free(log_data);
		free(gsl);
		return;
	}
	if (rc) {
		TEST_FAIL("get_log", rc_str(rc));
		free(log_data);
		free(gsl);
		return;
	}

	TEST_PASS("get_log");
	if (verbose) {
		printf("           log_uuid: "
		       "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		       "%02x%02x-%02x%02x%02x%02x%02x%02x\n",
		       req.uuid[0], req.uuid[1], req.uuid[2], req.uuid[3],
		       req.uuid[4], req.uuid[5], req.uuid[6], req.uuid[7],
		       req.uuid[8], req.uuid[9], req.uuid[10], req.uuid[11],
		       req.uuid[12], req.uuid[13], req.uuid[14], req.uuid[15]);
		printf("           log_size: %u bytes\n", req.length);
	}
	free(log_data);
	free(gsl);
}

static void run_tests(struct cxlmi_endpoint *ep)
{
	printf("\n[Generic Command Set]\n");

	/* Device Info and Status */
	test_identify(ep);
	test_bg_op_status(ep);
	test_get_response_msg_limit(ep);
	test_set_response_msg_limit(ep);
	test_request_bg_op_abort(ep);

	/* Timestamp */
	test_get_timestamp(ep);
	test_set_timestamp(ep);

	/* Events */
	test_get_event_records(ep);
	test_clear_event_records(ep);
	test_get_event_interrupt_policy(ep);
	test_set_event_interrupt_policy(ep);
	test_get_mctp_event_interrupt_policy(ep);
	test_set_mctp_event_interrupt_policy(ep);
	test_event_notification(ep);

	/* Firmware */
	test_get_fw_info(ep);
	test_transfer_fw(ep);
	test_activate_fw(ep);

	/* Logs */
	test_get_supported_logs(ep);
	test_get_supported_logs_sublist(ep);
	test_get_log(ep);
	test_get_log_cel(ep);
	test_get_log_capabilities(ep);
	test_clear_log(ep);
	test_populate_log(ep);

	/* Features */
	test_get_supported_features(ep);
	test_get_feature(ep);
	test_set_feature(ep);
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
	printf("  libcxlmi Generic Command Set Tests\n");
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
