// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * CXL FM-API Command Set unit tests for libcxlmi
 *
 * Tests FM-API commands (CXL r3.1 Section 8.2.9.9) against a CXL FM device.
 * Supports tunneling through a CXL switch with -p <port> option.
 */

#include "test-common.h"

TEST_DECLARE_COUNTERS;
TEST_DECLARE_TUNNEL_CONFIG;

/*
 * Physical Switch Commands
 */

static void test_identify_sw_device(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("identify_sw_device", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("identify_sw_device", rc_str(rc));
		return;
	}

	TEST_PASS("identify_sw_device");
	if (verbose) {
		printf("           ingress_port_id: %u\n", rsp.ingress_port_id);
		printf("           num_physical_ports: %u\n", rsp.num_physical_ports);
		printf("           num_vcs: %u\n", rsp.num_vcs);
		printf("           num_total_vppb: %u\n", rsp.num_total_vppb);
		printf("           num_active_vppb: %u\n", rsp.num_active_vppb);
		printf("           num_hdm_decoder_per_usp: %u\n", rsp.num_hdm_decoder_per_usp);
	}
}

static void test_get_phys_port_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp id = {0};
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp;
	int rc, num_active_ports, port_idx;

	/* First get number of ports from identify */
	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, get_tunnel_info(), &id);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_phys_port_state", "identify not supported");
		return;
	}

	/* Count active ports from bitmask */
	num_active_ports = 0;
	for (int i = 0; i < 256; i++) {
		if (id.active_port_bitmask[i / 8] & (1 << (i % 8)))
			num_active_ports++;
	}

	if (num_active_ports == 0) {
		TEST_SKIP("get_phys_port_state", "no active ports");
		return;
	}

	req = calloc(1, sizeof(*req) + num_active_ports);
	rsp = calloc(1, sizeof(*rsp) + num_active_ports * sizeof(rsp->ports[0]));
	if (!req || !rsp) {
		TEST_FAIL("get_phys_port_state", "allocation failed");
		free(req);
		free(rsp);
		return;
	}

	/* Request only active ports based on bitmask */
	req->num_ports = num_active_ports;
	port_idx = 0;
	for (int i = 0; i < 256 && port_idx < num_active_ports; i++) {
		if (id.active_port_bitmask[i / 8] & (1 << (i % 8)))
			req->ports[port_idx++] = i;
	}

	rc = cxlmi_cmd_fmapi_get_phys_port_state(ep, get_tunnel_info(), req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_phys_port_state", "not supported");
		free(req);
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_phys_port_state", rc_str(rc));
		free(req);
		free(rsp);
		return;
	}

	TEST_PASS("get_phys_port_state");
	if (verbose) {
		printf("           num_ports: %u\n", rsp->num_ports);
		for (int i = 0; i < rsp->num_ports; i++) {
			printf("             [%d] port_id: %u, state: %u, type: %u\n",
			       i, rsp->ports[i].port_id,
			       rsp->ports[i].config_state,
			       rsp->ports[i].conn_dev_type);
			printf("                  link: width=%u/%u, speed=%u/%u, ltssm=0x%02x\n",
			       rsp->ports[i].negotiated_link_width,
			       rsp->ports[i].max_link_width,
			       rsp->ports[i].current_link_speed,
			       rsp->ports[i].max_link_speed,
			       rsp->ports[i].ltssm_state);
		}
	}
	free(req);
	free(rsp);
}

static void test_phys_port_control(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_phys_port_control_req req = {0};
	int rc;

	/* Try a no-op control operation on port 0 */
	req.ppb_id = 0;
	req.port_opcode = 0; /* No operation / query */

	rc = cxlmi_cmd_fmapi_phys_port_control(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("phys_port_control", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("phys_port_control", rc_str(rc));
		return;
	}

	TEST_PASS("phys_port_control");
}

static void test_send_ppb_cxlio_config_request(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp rsp = {0};
	int rc;

	/* Read config space offset 0 (vendor ID) */
	req.ppb_id = 0;
	/* field_1[0x3] contains destination_type/opcode/address_offset packed */
	req.transaction_data = 0;

	rc = cxlmi_cmd_fmapi_send_ppb_cxlio_config_request(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("send_ppb_cxlio_config_request", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("send_ppb_cxlio_config_request", rc_str(rc));
		return;
	}

	TEST_PASS("send_ppb_cxlio_config_request");
	if (verbose)
		printf("           return_data: 0x%08x\n", rsp.return_data);
}

/*
 * Domain Validation Commands
 */

static void test_get_domain_validation_sv_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_state_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_domain_validation_sv_state(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_domain_validation_sv_state", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_domain_validation_sv_state", rc_str(rc));
		return;
	}

	TEST_PASS("get_domain_validation_sv_state");
	if (verbose)
		printf("           secret_value_state: 0x%02x\n",
		       rsp.secret_value_state);
}

static void test_set_domain_validation_sv(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_set_domain_validation_sv_req req = {0};
	int rc;

	/* Set a test secret value UUID (safe operation - zeros) */
	memset(req.secret_value_uuid, 0, sizeof(req.secret_value_uuid));

	rc = cxlmi_cmd_fmapi_set_domain_validation_sv(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_domain_validation_sv", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_domain_validation_sv", rc_str(rc));
		return;
	}

	TEST_PASS("set_domain_validation_sv");
}

static void test_get_vcs_domain_validation_sv_state(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req req = {0};
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp rsp = {0};
	int rc;

	req.vcs_id = 0;

	rc = cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_vcs_domain_validation_sv_state", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_vcs_domain_validation_sv_state", rc_str(rc));
		return;
	}

	TEST_PASS("get_vcs_domain_validation_sv_state");
	if (verbose)
		printf("           secret_value_state: 0x%02x\n",
		       rsp.secret_value_state);
}

static void test_get_domain_validation_sv(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_req req = {0};
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp rsp = {0};
	int rc;

	req.vcs_id = 0;

	rc = cxlmi_cmd_fmapi_get_domain_validation_sv(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_domain_validation_sv", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_domain_validation_sv", rc_str(rc));
		return;
	}

	TEST_PASS("get_domain_validation_sv");
	if (verbose) {
		printf("           secret_value_uuid: "
		       "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
		       "%02x%02x-%02x%02x%02x%02x%02x%02x\n",
		       rsp.secret_value_uuid[0], rsp.secret_value_uuid[1],
		       rsp.secret_value_uuid[2], rsp.secret_value_uuid[3],
		       rsp.secret_value_uuid[4], rsp.secret_value_uuid[5],
		       rsp.secret_value_uuid[6], rsp.secret_value_uuid[7],
		       rsp.secret_value_uuid[8], rsp.secret_value_uuid[9],
		       rsp.secret_value_uuid[10], rsp.secret_value_uuid[11],
		       rsp.secret_value_uuid[12], rsp.secret_value_uuid[13],
		       rsp.secret_value_uuid[14], rsp.secret_value_uuid[15]);
	}
}

/*
 * Virtual Switch Commands
 */

static void test_bind_vppb(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_bind_vppb_req req = {0};
	int rc;

	req.vcs_id = 0;
	req.vppb_id = 0;
	req.port_id = 0;
	req.ld_id = 0;

	rc = cxlmi_cmd_fmapi_bind_vppb(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("bind_vppb", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("bind_vppb", rc_str(rc));
		return;
	}

	TEST_PASS("bind_vppb");
}

static void test_unbind_vppb(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_unbind_vppb_req req = {0};
	int rc;

	req.vcs_id = 0;
	req.vppb_id = 0;
	req.option = 0; /* Wait for clean unbind */

	rc = cxlmi_cmd_fmapi_unbind_vppb(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("unbind_vppb", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("unbind_vppb", rc_str(rc));
		return;
	}

	TEST_PASS("unbind_vppb");
}

/*
 * MLD Port Commands
 */

static void test_send_ld_cxlio_config_request(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp rsp = {0};
	int rc;

	req.ppb_id = 0;
	req.ld_id = 0;
	/* field_1[0x3] and transaction_data contain packed config info */
	req.transaction_data = 0;

	rc = cxlmi_cmd_fmapi_send_ld_cxlio_config_request(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("send_ld_cxlio_config_request", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("send_ld_cxlio_config_request", rc_str(rc));
		return;
	}

	TEST_PASS("send_ld_cxlio_config_request");
	if (verbose)
		printf("           return_data: 0x%08x\n", rsp.return_data);
}

static void test_send_ld_cxlio_mem_request(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp rsp = {0};
	int rc;

	req.port_id = 0;
	req.ld_id = 0;
	req.transaction_len = 0;
	req.transaction_addr = 0;

	rc = cxlmi_cmd_fmapi_send_ld_cxlio_mem_request(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("send_ld_cxlio_mem_request", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("send_ld_cxlio_mem_request", rc_str(rc));
		return;
	}

	TEST_PASS("send_ld_cxlio_mem_request");
	if (verbose)
		printf("           return_size: %u\n", rsp.return_size);
}

/*
 * MLD Component Commands
 */

static void test_get_ld_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_ld_info_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_ld_info(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_ld_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_ld_info", rc_str(rc));
		return;
	}

	TEST_PASS("get_ld_info");
	if (verbose) {
		printf("           memory_size: %lu MB\n",
		       (unsigned long)(rsp.memory_size * 256));
		printf("           ld_count: %u\n", rsp.ld_count);
	}
}

static void test_get_ld_allocations(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->ld_allocation_list[0]));
	if (!rsp) {
		TEST_FAIL("get_ld_allocations", "allocation failed");
		return;
	}

	req.start_ld_id = 0;
	req.ld_allocation_list_limit = 16;

	rc = cxlmi_cmd_fmapi_get_ld_allocations(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_ld_allocations", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_ld_allocations", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_ld_allocations");
	if (verbose) {
		printf("           number_ld: %u\n", rsp->number_ld);
		printf("           memory_granularity: %u\n", rsp->memory_granularity);
		printf("           ld_allocation_list_len: %u\n",
		       rsp->ld_allocation_list_len);
	}
	free(rsp);
}

static void test_set_ld_allocations(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req get_req = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *get_rsp;
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *set_req;
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *set_rsp;
	int rc;

	get_rsp = calloc(1, sizeof(*get_rsp) + 16 * sizeof(get_rsp->ld_allocation_list[0]));
	if (!get_rsp) {
		TEST_FAIL("set_ld_allocations", "allocation failed");
		return;
	}

	get_req.start_ld_id = 0;
	get_req.ld_allocation_list_limit = 16;

	rc = cxlmi_cmd_fmapi_get_ld_allocations(ep, get_tunnel_info(), &get_req, get_rsp);
	if (is_unsupported(rc) || get_rsp->number_ld == 0) {
		TEST_SKIP("set_ld_allocations", "get not supported or no LDs");
		free(get_rsp);
		return;
	}

	/* Set same allocations (safe operation) */
	set_req = calloc(1, sizeof(*set_req) + get_rsp->number_ld * sizeof(set_req->ld_allocation_list[0]));
	set_rsp = calloc(1, sizeof(*set_rsp) + get_rsp->number_ld * sizeof(set_rsp->ld_allocation_list[0]));
	if (!set_req || !set_rsp) {
		TEST_FAIL("set_ld_allocations", "allocation failed");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	set_req->number_ld = get_rsp->number_ld;
	set_req->start_ld_id = 0;
	memcpy(set_req->ld_allocation_list, get_rsp->ld_allocation_list,
	       get_rsp->number_ld * sizeof(get_rsp->ld_allocation_list[0]));

	rc = cxlmi_cmd_fmapi_set_ld_allocations(ep, get_tunnel_info(), set_req, set_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_ld_allocations", "not supported");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("set_ld_allocations", rc_str(rc));
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	TEST_PASS("set_ld_allocations");
	free(get_rsp);
	free(set_req);
	free(set_rsp);
}

/*
 * QoS Commands
 */

static void test_get_qos_control(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_control_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_qos_control(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_qos_control", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_qos_control", rc_str(rc));
		return;
	}

	TEST_PASS("get_qos_control");
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

static void test_set_qos_control(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_control_rsp get_rsp = {0};
	struct cxlmi_cmd_fmapi_set_qos_control_req req = {0};
	struct cxlmi_cmd_fmapi_set_qos_control_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_qos_control(ep, get_tunnel_info(), &get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_control", "get not supported");
		return;
	}

	/* Set same values (safe operation) */
	req.qos_telemetry_control = get_rsp.qos_telemetry_control;
	req.egress_moderate_percentage = get_rsp.egress_moderate_percentage;
	req.egress_severe_percentage = get_rsp.egress_severe_percentage;
	req.backpressure_sample_interval = get_rsp.backpressure_sample_interval;
	req.completion_collection_interval = get_rsp.completion_collection_interval;

	rc = cxlmi_cmd_fmapi_set_qos_control(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_control", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_qos_control", rc_str(rc));
		return;
	}

	TEST_PASS("set_qos_control");
	if (verbose) {
		printf("           qos_telemetry_control: 0x%02x\n",
		       rsp.qos_telemetry_control);
		printf("           egress_moderate_percentage: %u\n",
		       rsp.egress_moderate_percentage);
		printf("           egress_severe_percentage: %u\n",
		       rsp.egress_severe_percentage);
		printf("           backpressure_sample_interval: %u\n",
		       rsp.backpressure_sample_interval);
		printf("           completion_collection_interval: %u\n",
		       rsp.completion_collection_interval);
	}
}

static void test_get_qos_status(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_status_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_qos_status(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_qos_status", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_qos_status", rc_str(rc));
		return;
	}

	TEST_PASS("get_qos_status");
	if (verbose)
		printf("           backpressure_avg_percentage: %u%%\n",
		       rsp.backpressure_avg_percentage);
}

static void test_get_qos_allocated_bw(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req req = {0};
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->qos_allocation_fraction[0]));
	if (!rsp) {
		TEST_FAIL("get_qos_allocated_bw", "allocation failed");
		return;
	}

	req.number_ld = 16;
	req.start_ld_id = 0;

	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_qos_allocated_bw", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_qos_allocated_bw", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_qos_allocated_bw");
	if (verbose) {
		printf("           number_ld: %u\n", rsp->number_ld);
		printf("           start_ld_id: %u\n", rsp->start_ld_id);
	}
	free(rsp);
}

static void test_set_qos_allocated_bw(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req get_req = {0};
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *get_rsp;
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *set_req;
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *set_rsp;
	int rc;

	get_rsp = calloc(1, sizeof(*get_rsp) + 16 * sizeof(get_rsp->qos_allocation_fraction[0]));
	if (!get_rsp) {
		TEST_FAIL("set_qos_allocated_bw", "allocation failed");
		return;
	}

	get_req.number_ld = 16;
	get_req.start_ld_id = 0;

	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(ep, get_tunnel_info(), &get_req, get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_allocated_bw", "get not supported");
		free(get_rsp);
		return;
	}

	set_req = calloc(1, sizeof(*set_req) + get_rsp->number_ld * sizeof(set_req->qos_allocation_fraction[0]));
	set_rsp = calloc(1, sizeof(*set_rsp) + get_rsp->number_ld * sizeof(set_rsp->qos_allocation_fraction[0]));
	if (!set_req || !set_rsp) {
		TEST_FAIL("set_qos_allocated_bw", "allocation failed");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	set_req->number_ld = get_rsp->number_ld;
	set_req->start_ld_id = 0;
	memcpy(set_req->qos_allocation_fraction, get_rsp->qos_allocation_fraction,
	       get_rsp->number_ld * sizeof(get_rsp->qos_allocation_fraction[0]));

	rc = cxlmi_cmd_fmapi_set_qos_allocated_bw(ep, get_tunnel_info(), set_req, set_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_allocated_bw", "not supported");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("set_qos_allocated_bw", rc_str(rc));
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	TEST_PASS("set_qos_allocated_bw");
	if (verbose) {
		printf("           number_ld: %u\n", set_rsp->number_ld);
		printf("           start_ld_id: %u\n", set_rsp->start_ld_id);
	}
	free(get_rsp);
	free(set_req);
	free(set_rsp);
}

static void test_get_qos_bw_limit(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req req = {0};
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->qos_limit_fraction[0]));
	if (!rsp) {
		TEST_FAIL("get_qos_bw_limit", "allocation failed");
		return;
	}

	req.number_ld = 16;
	req.start_ld_id = 0;

	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_qos_bw_limit", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_qos_bw_limit", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_qos_bw_limit");
	if (verbose) {
		printf("           number_ld: %u\n", rsp->number_ld);
		printf("           start_ld_id: %u\n", rsp->start_ld_id);
	}
	free(rsp);
}

static void test_set_qos_bw_limit(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req get_req = {0};
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *get_rsp;
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *set_req;
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *set_rsp;
	int rc;

	get_rsp = calloc(1, sizeof(*get_rsp) + 16 * sizeof(get_rsp->qos_limit_fraction[0]));
	if (!get_rsp) {
		TEST_FAIL("set_qos_bw_limit", "allocation failed");
		return;
	}

	get_req.number_ld = 16;
	get_req.start_ld_id = 0;

	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(ep, get_tunnel_info(), &get_req, get_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_bw_limit", "get not supported");
		free(get_rsp);
		return;
	}

	set_req = calloc(1, sizeof(*set_req) + get_rsp->number_ld * sizeof(set_req->qos_limit_fraction[0]));
	set_rsp = calloc(1, sizeof(*set_rsp) + get_rsp->number_ld * sizeof(set_rsp->qos_limit_fraction[0]));
	if (!set_req || !set_rsp) {
		TEST_FAIL("set_qos_bw_limit", "allocation failed");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	set_req->number_ld = get_rsp->number_ld;
	set_req->start_ld_id = 0;
	memcpy(set_req->qos_limit_fraction, get_rsp->qos_limit_fraction,
	       get_rsp->number_ld * sizeof(get_rsp->qos_limit_fraction[0]));

	rc = cxlmi_cmd_fmapi_set_qos_bw_limit(ep, get_tunnel_info(), set_req, set_rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_qos_bw_limit", "not supported");
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("set_qos_bw_limit", rc_str(rc));
		free(get_rsp);
		free(set_req);
		free(set_rsp);
		return;
	}

	TEST_PASS("set_qos_bw_limit");
	if (verbose) {
		printf("           number_ld: %u\n", set_rsp->number_ld);
		printf("           start_ld_id: %u\n", set_rsp->start_ld_id);
	}
	free(get_rsp);
	free(set_req);
	free(set_rsp);
}

/*
 * Multi-Headed Device Commands
 */

static void test_get_multiheaded_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_multiheaded_info_req req = {0};
	struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16); /* Allow for ld_map array */
	if (!rsp) {
		TEST_FAIL("get_multiheaded_info", "allocation failed");
		return;
	}

	req.start_ld_id = 0;
	req.ld_map_list_limit = 8;

	rc = cxlmi_cmd_fmapi_get_multiheaded_info(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_multiheaded_info", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_multiheaded_info", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_multiheaded_info");
	if (verbose) {
		printf("           num_heads: %u\n", rsp->num_heads);
		printf("           num_lds: %u\n", rsp->num_lds);
	}
	free(rsp);
}

static void test_get_head_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_head_info_req req = {0};
	struct cxlmi_cmd_fmapi_get_head_info_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 8 * sizeof(rsp->head_info_list[0]));
	if (!rsp) {
		TEST_FAIL("get_head_info", "allocation failed");
		return;
	}

	req.start_head = 0;
	req.num_heads = 8;

	rc = cxlmi_cmd_fmapi_get_head_info(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_head_info", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_head_info", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_head_info");
	if (verbose)
		printf("           num_heads: %u\n", rsp->num_heads);
	free(rsp);
}

/*
 * Dynamic Capacity Commands
 */

static void test_get_dcd_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_dcd_info_rsp rsp = {0};
	int rc;

	rc = cxlmi_cmd_fmapi_get_dcd_info(ep, get_tunnel_info(), &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_dcd_info", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_dcd_info", rc_str(rc));
		return;
	}

	TEST_PASS("get_dcd_info");
	if (verbose) {
		printf("           num_hosts: %u\n", rsp.num_hosts);
		printf("           num_supported_dc_regions: %u\n",
		       rsp.num_supported_dc_regions);
		printf("           total_dynamic_capacity: %lu MB\n",
		       (unsigned long)(rsp.total_dynamic_capacity * 256));
	}
}

static void test_get_dc_reg_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp rsp = {0};
	int rc;

	req.host_id = 0;
	req.region_cnt = 8;
	req.start_region_id = 0;

	rc = cxlmi_cmd_fmapi_get_dc_reg_config(ep, get_tunnel_info(), &req, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_dc_reg_config", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("get_dc_reg_config", rc_str(rc));
		return;
	}

	TEST_PASS("get_dc_reg_config");
	if (verbose) {
		printf("           host_id: %u\n", rsp.host_id);
		printf("           num_regions: %u\n", rsp.num_regions);
		printf("           regions_returned: %u\n", rsp.regions_returned);
	}
}

static void test_set_dc_region_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_set_dc_region_config_req req = {0};
	int rc;

	req.region_id = 0;
	req.block_sz = 0; /* Use default block size */
	req.sanitize_on_release = 0;

	rc = cxlmi_cmd_fmapi_set_dc_region_config(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("set_dc_region_config", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("set_dc_region_config", rc_str(rc));
		return;
	}

	TEST_PASS("set_dc_region_config");
}

static void test_get_dc_region_ext_list(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 8 * sizeof(rsp->extents[0]));
	if (!rsp) {
		TEST_FAIL("get_dc_region_ext_list", "allocation failed");
		return;
	}

	req.host_id = 0;
	req.extent_count = 8;
	req.start_ext_index = 0;

	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("get_dc_region_ext_list", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("get_dc_region_ext_list", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("get_dc_region_ext_list");
	if (verbose) {
		printf("           host_id: %u\n", rsp->host_id);
		printf("           extents_returned: %u\n", rsp->extents_returned);
		printf("           total_extents: %u\n", rsp->total_extents);
	}
	free(rsp);
}

static void test_initiate_dc_add(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_initiate_dc_add_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("initiate_dc_add", "allocation failed");
		return;
	}

	req->host_id = 0;
	req->selection_policy = 0;
	req->region_num = 0;
	req->length = 0;
	req->ext_count = 0;

	rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, get_tunnel_info(), req);
	if (is_unsupported(rc)) {
		TEST_SKIP("initiate_dc_add", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("initiate_dc_add", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("initiate_dc_add");
	free(req);
}

static void test_initiate_dc_release(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_initiate_dc_release_req *req;
	int rc;

	req = calloc(1, sizeof(*req));
	if (!req) {
		TEST_FAIL("initiate_dc_release", "allocation failed");
		return;
	}

	req->host_id = 0;
	req->flags = 0;
	req->length = 0;
	req->ext_count = 0;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, get_tunnel_info(), req);
	if (is_unsupported(rc)) {
		TEST_SKIP("initiate_dc_release", "not supported");
		free(req);
		return;
	}
	if (rc) {
		TEST_FAIL("initiate_dc_release", rc_str(rc));
		free(req);
		return;
	}

	TEST_PASS("initiate_dc_release");
	free(req);
}

static void test_dc_add_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_add_ref_req req = {0};
	int rc;

	/* tag[0x10] is the only field - zeroed by default */
	memset(req.tag, 0, sizeof(req.tag));

	rc = cxlmi_cmd_fmapi_dc_add_reference(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("dc_add_reference", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("dc_add_reference", rc_str(rc));
		return;
	}

	TEST_PASS("dc_add_reference");
}

static void test_dc_remove_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_remove_ref_req req = {0};
	int rc;

	/* tag[0x10] is the only field - zeroed by default */
	memset(req.tag, 0, sizeof(req.tag));

	rc = cxlmi_cmd_fmapi_dc_remove_reference(ep, get_tunnel_info(), &req);
	if (is_unsupported(rc)) {
		TEST_SKIP("dc_remove_reference", "not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("dc_remove_reference", rc_str(rc));
		return;
	}

	TEST_PASS("dc_remove_reference");
}

static void test_dc_list_tags(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp) + 16 * sizeof(rsp->tags_list[0]));
	if (!rsp) {
		TEST_FAIL("dc_list_tags", "allocation failed");
		return;
	}

	req.start_idx = 0;
	req.tags_count = 16;

	rc = cxlmi_cmd_fmapi_dc_list_tags(ep, get_tunnel_info(), &req, rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("dc_list_tags", "not supported");
		free(rsp);
		return;
	}
	if (rc) {
		TEST_FAIL("dc_list_tags", rc_str(rc));
		free(rsp);
		return;
	}

	TEST_PASS("dc_list_tags");
	if (verbose) {
		printf("           generation_num: %u\n", rsp->generation_num);
		printf("           total_num_tags: %u\n", rsp->total_num_tags);
		printf("           num_tags_returned: %u\n", rsp->num_tags_returned);
	}
	free(rsp);
}

/*
 * Tunneling Tests - Exercise commands through switch/MLD tunneling
 *
 * These tests verify that commands can be properly tunneled:
 * - Through a CXL Switch to downstream devices (DEFINE_CXLMI_TUNNEL_SWITCH)
 * - To an LD within an MLD (DEFINE_CXLMI_TUNNEL_MLD)
 * - Two-level: through switch to an LD in an MLD (DEFINE_CXLMI_TUNNEL_SWITCH_MLD)
 */

static void test_tunnel_switch_identify(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify_rsp rsp = {0};
	DEFINE_CXLMI_TUNNEL_SWITCH(ti, tunnel_port);
	int rc;

	if (tunnel_port < 0) {
		TEST_SKIP("tunnel_switch_identify", "no tunnel port configured");
		return;
	}

	rc = cxlmi_cmd_identify(ep, &ti, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("tunnel_switch_identify", "tunneling not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("tunnel_switch_identify", rc_str(rc));
		return;
	}

	TEST_PASS("tunnel_switch_identify");
	if (verbose) {
		printf("           [via port %d] vendor_id: 0x%04x\n",
		       tunnel_port, rsp.vendor_id);
		printf("           [via port %d] device_id: 0x%04x\n",
		       tunnel_port, rsp.device_id);
		printf("           [via port %d] component_type: %u\n",
		       tunnel_port, rsp.component_type);
	}
}

static void test_tunnel_switch_get_health_info(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_memdev_get_health_info_rsp rsp = {0};
	DEFINE_CXLMI_TUNNEL_SWITCH(ti, tunnel_port);
	int rc;

	if (tunnel_port < 0) {
		TEST_SKIP("tunnel_switch_get_health_info", "no tunnel port configured");
		return;
	}

	rc = cxlmi_cmd_memdev_get_health_info(ep, &ti, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("tunnel_switch_get_health_info", "not supported via tunnel");
		return;
	}
	if (rc) {
		TEST_FAIL("tunnel_switch_get_health_info", rc_str(rc));
		return;
	}

	TEST_PASS("tunnel_switch_get_health_info");
	if (verbose) {
		printf("           [via port %d] health_status: 0x%02x\n",
		       tunnel_port, rsp.health_status);
		printf("           [via port %d] device_temperature: %d C\n",
		       tunnel_port, rsp.device_temperature);
	}
}

static void test_tunnel_mld_identify(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify_rsp rsp = {0};
	DEFINE_CXLMI_TUNNEL_MLD(ti, tunnel_ld);
	int rc;

	if (tunnel_ld < 0) {
		TEST_SKIP("tunnel_mld_identify", "no tunnel LD configured");
		return;
	}

	rc = cxlmi_cmd_identify(ep, &ti, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("tunnel_mld_identify", "MLD tunneling not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("tunnel_mld_identify", rc_str(rc));
		return;
	}

	TEST_PASS("tunnel_mld_identify");
	if (verbose) {
		printf("           [via LD %d] vendor_id: 0x%04x\n",
		       tunnel_ld, rsp.vendor_id);
		printf("           [via LD %d] device_id: 0x%04x\n",
		       tunnel_ld, rsp.device_id);
	}
}

static void test_tunnel_switch_mld_identify(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify_rsp rsp = {0};
	DEFINE_CXLMI_TUNNEL_SWITCH_MLD(ti, tunnel_port, tunnel_ld);
	int rc;

	if (tunnel_port < 0 || tunnel_ld < 0) {
		TEST_SKIP("tunnel_switch_mld_identify", "tunnel port/LD not configured");
		return;
	}

	rc = cxlmi_cmd_identify(ep, &ti, &rsp);
	if (is_unsupported(rc)) {
		TEST_SKIP("tunnel_switch_mld_identify", "two-level tunneling not supported");
		return;
	}
	if (rc) {
		TEST_FAIL("tunnel_switch_mld_identify", rc_str(rc));
		return;
	}

	TEST_PASS("tunnel_switch_mld_identify");
	if (verbose) {
		printf("           [via port %d, LD %d] vendor_id: 0x%04x\n",
		       tunnel_port, tunnel_ld, rsp.vendor_id);
		printf("           [via port %d, LD %d] device_id: 0x%04x\n",
		       tunnel_port, tunnel_ld, rsp.device_id);
	}
}

static void run_tunnel_tests(struct cxlmi_endpoint *ep)
{
	printf("\n[Tunneling Tests]\n");

	/* Test tunneling through switch to downstream device */
	test_tunnel_switch_identify(ep);
	test_tunnel_switch_get_health_info(ep);

	/* Test tunneling to LD within MLD */
	test_tunnel_mld_identify(ep);

	/* Test two-level tunneling: switch -> MLD -> LD */
	test_tunnel_switch_mld_identify(ep);
}

/*
 * Auto-detect tunnel targets by querying the switch
 *
 * This function queries the switch to find:
 * - A DSP port with a connected device (for switch tunnel tests)
 * - An MLD with multiple LDs (for MLD tunnel tests)
 */
static void auto_detect_tunnel_targets(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp id = {0};
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp;
	int rc, num_active_ports, port_idx;

	/* Skip auto-detection if already configured */
	if (tunnel_port >= 0)
		return;

	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, get_tunnel_info(), &id);
	if (rc)
		return;

	/* Count active ports from bitmask */
	num_active_ports = 0;
	for (int i = 0; i < 256; i++) {
		if (id.active_port_bitmask[i / 8] & (1 << (i % 8)))
			num_active_ports++;
	}

	if (num_active_ports == 0)
		return;

	req = calloc(1, sizeof(*req) + num_active_ports);
	rsp = calloc(1, sizeof(*rsp) + num_active_ports * sizeof(rsp->ports[0]));
	if (!req || !rsp) {
		free(req);
		free(rsp);
		return;
	}

	/* Request only active ports based on bitmask */
	req->num_ports = num_active_ports;
	port_idx = 0;
	for (int i = 0; i < 256 && port_idx < num_active_ports; i++) {
		if (id.active_port_bitmask[i / 8] & (1 << (i % 8)))
			req->ports[port_idx++] = i;
	}

	rc = cxlmi_cmd_fmapi_get_phys_port_state(ep, get_tunnel_info(), req, rsp);
	if (rc) {
		free(req);
		free(rsp);
		return;
	}

	/* Find first DSP with a CXL device attached */
	for (int i = 0; i < rsp->num_ports; i++) {
		/* config_state == 3 means DSP (Downstream Port) */
		if (rsp->ports[i].config_state == 3 &&
		    rsp->ports[i].conn_dev_type >= 2) {  /* CXL Type 1/2/3 */
			tunnel_port = rsp->ports[i].port_id;
			if (verbose)
				printf("  Auto-detected tunnel port: %d (device type %u)\n",
				       tunnel_port, rsp->ports[i].conn_dev_type);

			/* If it's an MLD (Type 5), also set tunnel_ld */
			if (rsp->ports[i].conn_dev_type == 5 &&
			    rsp->ports[i].supported_ld_count > 1) {
				tunnel_ld = 0;  /* Start with LD 0 */
				if (verbose)
					printf("  Auto-detected MLD with %u LDs\n",
					       rsp->ports[i].supported_ld_count);
			}
			break;
		}
	}

	free(req);
	free(rsp);
}

static void run_tests(struct cxlmi_endpoint *ep)
{
	printf("\n[FM-API Command Set]\n");

	/* Physical Switch Commands */
	test_identify_sw_device(ep);
	test_get_phys_port_state(ep);
	test_phys_port_control(ep);
	test_send_ppb_cxlio_config_request(ep);

	/* Domain Validation Commands */
	test_get_domain_validation_sv_state(ep);
	test_set_domain_validation_sv(ep);
	test_get_vcs_domain_validation_sv_state(ep);
	test_get_domain_validation_sv(ep);

	/* Virtual Switch Commands */
	test_bind_vppb(ep);
	test_unbind_vppb(ep);

	/* MLD Port Commands */
	test_send_ld_cxlio_config_request(ep);
	test_send_ld_cxlio_mem_request(ep);

	/* MLD Component Commands */
	test_get_ld_info(ep);
	test_get_ld_allocations(ep);
	test_set_ld_allocations(ep);

	/* QoS Commands */
	test_get_qos_control(ep);
	test_set_qos_control(ep);
	test_get_qos_status(ep);
	test_get_qos_allocated_bw(ep);
	test_set_qos_allocated_bw(ep);
	test_get_qos_bw_limit(ep);
	test_set_qos_bw_limit(ep);

	/* Multi-Headed Device Commands */
	test_get_multiheaded_info(ep);
	test_get_head_info(ep);

	/* Dynamic Capacity Commands */
	test_get_dcd_info(ep);
	test_get_dc_reg_config(ep);
	test_set_dc_region_config(ep);
	test_get_dc_region_ext_list(ep);
	test_initiate_dc_add(ep);
	test_initiate_dc_release(ep);
	test_dc_add_reference(ep);
	test_dc_remove_reference(ep);
	test_dc_list_tags(ep);

	/* Auto-detect tunnel targets and run tunneling tests */
	auto_detect_tunnel_targets(ep);
	run_tunnel_tests(ep);
}

static void usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [options] <target>\n", progname);
	print_target_usage();
	print_tunnel_usage();
	fprintf(stderr, "\nGeneral Options:\n");
	fprintf(stderr, "  -v, --verbose         Show detailed response data\n");
	fprintf(stderr, "  -h, --help            Show this help\n");
	fprintf(stderr, "\nNotes:\n");
	fprintf(stderr, "  If no tunneling options specified, auto-detection is attempted.\n");
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
	printf("  libcxlmi FM-API Command Set Tests\n");
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
