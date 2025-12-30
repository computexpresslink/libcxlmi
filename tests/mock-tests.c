// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Comprehensive unit tests using the mock transport layer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ccan/endian/endian.h>

#include <libcxlmi.h>
#include <cxlmi/test.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static const char *current_suite = NULL;

#define RUN_TEST(test_func) do { \
	tests_run++; \
	printf("  %-60s ", #test_func); \
	fflush(stdout); \
	if (test_func() == 0) { \
		printf("[PASS]\n"); \
		tests_passed++; \
	} else { \
		printf("[FAIL]\n"); \
		tests_failed++; \
	} \
} while (0)

#define TEST_SUITE(name) do { \
	current_suite = name; \
	printf("\n%s:\n", name); \
} while (0)

#define ASSERT_EQ(actual, expected, msg) do { \
	if ((actual) != (expected)) { \
		fprintf(stderr, "\n    ASSERT FAILED: %s (got %d, expected %d)\n", \
			msg, (int)(actual), (int)(expected)); \
		return 1; \
	} \
} while (0)

#define ASSERT_TRUE(cond, msg) do { \
	if (!(cond)) { \
		fprintf(stderr, "\n    ASSERT FAILED: %s\n", msg); \
		return 1; \
	} \
} while (0)

/* Helper: create mock context and endpoint */
static struct cxlmi_ctx *test_ctx;
static struct cxlmi_endpoint *test_ep;

/* Helper: set multiple identical responses for retry testing */
static int mock_set_response_n(struct cxlmi_endpoint *ep,
			       uint8_t command_set, uint8_t command,
			       uint16_t return_code,
			       void *payload, size_t payload_size,
			       unsigned int count)
{
	unsigned int i;
	int rc;

	for (i = 0; i < count; i++) {
		rc = cxlmi_mock_set_response(ep, command_set, command,
					     return_code, payload, payload_size);
		if (rc)
			return rc;
	}
	return 0;
}

static int setup(void)
{
	test_ctx = cxlmi_new_ctx(stderr, LOG_ERR);
	if (!test_ctx)
		return -1;
	test_ep = cxlmi_open_mock(test_ctx);
	if (!test_ep) {
		cxlmi_free_ctx(test_ctx);
		return -1;
	}
	return 0;
}

static void teardown(void)
{
	if (test_ep)
		cxlmi_close(test_ep);
	if (test_ctx)
		cxlmi_free_ctx(test_ctx);
	test_ep = NULL;
	test_ctx = NULL;
}

/* ============================================================
 * Mock Infrastructure Tests
 * ============================================================ */

static int test_mock_create_close(void)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep;

	ctx = cxlmi_new_ctx(stderr, LOG_ERR);
	ASSERT_TRUE(ctx != NULL, "failed to create context");

	ep = cxlmi_open_mock(ctx);
	ASSERT_TRUE(ep != NULL, "failed to create mock endpoint");

	cxlmi_close(ep);
	cxlmi_free_ctx(ctx);
	return 0;
}

static int test_mock_no_response_returns_unsupported(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_UNSUPPORTED, "expected UNSUPPORTED");
	return 0;
}

static int test_mock_stats_tracking(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	unsigned int sent, returned;

	ASSERT_EQ(setup(), 0, "setup failed");

	cxlmi_mock_get_stats(test_ep, &sent, &returned);
	ASSERT_EQ(sent, 0, "initial sent should be 0");

	cxlmi_cmd_identify(test_ep, NULL, &id);
	cxlmi_mock_get_stats(test_ep, &sent, &returned);
	ASSERT_EQ(sent, 1, "sent should be 1");

	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	cxlmi_cmd_identify(test_ep, NULL, &id);
	cxlmi_mock_get_stats(test_ep, &sent, &returned);
	ASSERT_EQ(sent, 2, "sent should be 2");
	ASSERT_EQ(returned, 1, "returned should be 1");

	teardown();
	return 0;
}

static int test_mock_clear_responses(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");

	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	cxlmi_mock_clear_responses(test_ep);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);

	teardown();
	ASSERT_EQ(rc, CXLMI_RET_UNSUPPORTED, "expected UNSUPPORTED after clear");
	return 0;
}

static int test_mock_payload_size_zero_when_no_payload(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	uint8_t payload[16];
	size_t payload_size;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* identify has no request payload */
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	payload_size = sizeof(payload);
	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);

	teardown();
	ASSERT_EQ(payload_size, 0, "payload_size should be 0 for no-payload commands");
	return 0;
}

static int test_mock_response_sequence(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* Queue: BUSY, BUSY, SUCCESS - simulates retry scenario */
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_BUSY, &rsp, sizeof(rsp));
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_BUSY, &rsp, sizeof(rsp));
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));

	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_BUSY, "first call should return BUSY");

	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_BUSY, "second call should return BUSY");

	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "third call should return SUCCESS");

	/* Fourth call should return UNSUPPORTED (no more responses) */
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_UNSUPPORTED, "fourth call should return UNSUPPORTED");

	teardown();
	return 0;
}

static int test_mock_response_sequence_helper(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	unsigned int sent, returned;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* Use helper to queue 3 identical responses */
	rc = mock_set_response_n(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
				 &rsp, sizeof(rsp), 3);
	ASSERT_EQ(rc, 0, "failed to queue responses");

	cxlmi_cmd_identify(test_ep, NULL, &id);
	cxlmi_cmd_identify(test_ep, NULL, &id);
	cxlmi_cmd_identify(test_ep, NULL, &id);

	cxlmi_mock_get_stats(test_ep, &sent, &returned);
	ASSERT_EQ(sent, 3, "sent should be 3");
	ASSERT_EQ(returned, 3, "returned should be 3");

	/* Fourth call exhausts responses */
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_UNSUPPORTED, "should be UNSUPPORTED after exhausting responses");

	teardown();
	return 0;
}

/* ============================================================
 * Generic Component Commands (Info/Status - 0x00)
 * ============================================================ */

static int test_cmd_identify(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, ret;
	int rc;

	rsp.vendor_id = 0x1234;
	rsp.device_id = 0x5678;
	rsp.serial_num = 0xDEADBEEFCAFEBABE;
	rsp.component_type = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.vendor_id, 0x1234, "vendor_id mismatch");
	ASSERT_EQ(ret.device_id, 0x5678, "device_id mismatch");
	ASSERT_EQ(ret.component_type, 0x03, "component_type mismatch");
	return 0;
}

static int test_cmd_bg_op_status(void)
{
	struct cxlmi_cmd_bg_op_status_rsp rsp = {0}, ret;
	int rc;

	rsp.status = 0x01;
	rsp.opcode = 0x4304;
	rsp.returncode = 0x0000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x02, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_bg_op_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.status, 0x01, "status mismatch");
	return 0;
}

static int test_cmd_get_response_msg_limit(void)
{
	struct cxlmi_cmd_get_response_msg_limit_rsp rsp = {0}, ret;
	int rc;

	rsp.limit = 10;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_response_msg_limit(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.limit, 10, "limit mismatch");
	return 0;
}

static int test_cmd_set_response_msg_limit(void)
{
	struct cxlmi_cmd_set_response_msg_limit_req req = {0};
	struct cxlmi_cmd_set_response_msg_limit_rsp rsp = {0}, ret;
	int rc;

	req.limit = 8;
	rsp.limit = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x04, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_set_response_msg_limit(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.limit, 8, "limit mismatch");
	return 0;
}

static int test_cmd_request_bg_op_abort(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_request_bg_op_abort(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Events Commands (0x01)
 * ============================================================ */

static int test_cmd_get_event_records(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp rsp = {0}, ret = {0};
	int rc;

	req.event_log = 0; /* Info log */
	rsp.flags = 0;
	rsp.record_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.record_count, 0, "record_count mismatch");
	return 0;
}

static int test_cmd_get_event_interrupt_policy(void)
{
	struct cxlmi_cmd_get_event_interrupt_policy_rsp rsp = {0}, ret;
	int rc;

	rsp.informational_settings = 0x01;
	rsp.warning_settings = 0x02;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x02, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_interrupt_policy(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.informational_settings, 0x01, "info settings mismatch");
	return 0;
}

static int test_cmd_set_event_interrupt_policy(void)
{
	struct cxlmi_cmd_set_event_interrupt_policy_req req = {0};
	int rc;

	req.informational_settings = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_event_interrupt_policy(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Firmware Update Commands (0x02)
 * ============================================================ */

static int test_cmd_get_fw_info(void)
{
	struct cxlmi_cmd_get_fw_info_rsp rsp = {0}, ret;
	int rc;

	rsp.slots_supported = 2;
	rsp.slot_info = 0x01;
	memcpy(rsp.fw_rev1, "1.0.0", 5);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_fw_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.slots_supported, 2, "slots_supported mismatch");
	return 0;
}

static int test_cmd_activate_fw(void)
{
	struct cxlmi_cmd_activate_fw_req req = {0};
	int rc;

	req.action = 0x01;
	req.slot = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Timestamp Commands (0x03)
 * ============================================================ */

static int test_cmd_get_timestamp(void)
{
	struct cxlmi_cmd_get_timestamp_rsp rsp = {0}, ret;
	int rc;

	rsp.timestamp = 0x123456789ABCDEF0ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_timestamp(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.timestamp == 0x123456789ABCDEF0ULL, "timestamp mismatch");
	return 0;
}

static int test_cmd_set_timestamp(void)
{
	struct cxlmi_cmd_set_timestamp_req req = {0};
	int rc;

	req.timestamp = 0x123456789ABCDEF0ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_timestamp(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Logs Commands (0x04)
 * ============================================================ */

static int test_cmd_get_supported_logs(void)
{
	struct cxlmi_cmd_get_supported_logs_rsp *rsp, *ret;
	size_t struct_sz;
	int rc, result = 1;

	/* Allocate space for header + 2 entries (flexible array member) */
	struct_sz = sizeof(*rsp) + 2 * sizeof(rsp->entries[0]);
	rsp = calloc(1, struct_sz);
	ret = calloc(1, struct_sz);
	if (!rsp || !ret)
		goto cleanup;

	rsp->num_supported_log_entries = 2;
	/* Fill in some test UUIDs */
	memset(rsp->entries[0].uuid, 0xAA, sizeof(rsp->entries[0].uuid));
	rsp->entries[0].log_size = 0x100;
	memset(rsp->entries[1].uuid, 0xBB, sizeof(rsp->entries[1].uuid));
	rsp->entries[1].log_size = 0x200;

	if (setup() != 0) {
		fprintf(stderr, "\n    ASSERT FAILED: setup failed\n");
		goto cleanup;
	}
	cxlmi_mock_set_response(test_ep, 0x04, 0x00, CXLMI_RET_SUCCESS, rsp, struct_sz);
	rc = cxlmi_cmd_get_supported_logs(test_ep, NULL, ret);
	teardown();

	if (rc != CXLMI_RET_SUCCESS) {
		fprintf(stderr, "\n    ASSERT FAILED: command failed (got %d, expected %d)\n",
			rc, CXLMI_RET_SUCCESS);
		goto cleanup;
	}
	if (ret->num_supported_log_entries != 2) {
		fprintf(stderr, "\n    ASSERT FAILED: num entries mismatch\n");
		goto cleanup;
	}
	if (ret->entries[0].log_size != 0x100) {
		fprintf(stderr, "\n    ASSERT FAILED: entry 0 log_size mismatch\n");
		goto cleanup;
	}
	if (ret->entries[1].log_size != 0x200) {
		fprintf(stderr, "\n    ASSERT FAILED: entry 1 log_size mismatch\n");
		goto cleanup;
	}

	result = 0;
cleanup:
	free(rsp);
	free(ret);
	return result;
}

static int test_cmd_get_log_capabilities(void)
{
	struct cxlmi_cmd_get_log_capabilities_req req = {0};
	struct cxlmi_cmd_get_log_capabilities_rsp rsp = {0}, ret;
	int rc;

	rsp.parameter_flags = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x02, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_log_capabilities(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.parameter_flags, 0x01, "flags mismatch");
	return 0;
}

static int test_cmd_clear_log(void)
{
	struct cxlmi_cmd_clear_log_req req = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_clear_log(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_populate_log(void)
{
	struct cxlmi_cmd_populate_log_req req = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_populate_log(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Memory Device Identify (0x40)
 * ============================================================ */

static int test_cmd_memdev_identify(void)
{
	struct cxlmi_cmd_memdev_identify_rsp rsp = {0}, ret;
	int rc;

	rsp.total_capacity = 0x1000;
	rsp.volatile_capacity = 0x800;
	rsp.persistent_capacity = 0x800;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x40, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.total_capacity == 0x1000, "total_capacity mismatch");
	return 0;
}

/* ============================================================
 * CCLS Commands (0x41)
 * ============================================================ */

static int test_cmd_memdev_get_partition_info(void)
{
	struct cxlmi_cmd_memdev_get_partition_info_rsp rsp = {0}, ret;
	int rc;

	rsp.active_vmem = 0x100;
	rsp.active_pmem = 0x200;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_partition_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.active_vmem == 0x100, "active_vmem mismatch");
	return 0;
}

static int test_cmd_memdev_set_partition_info(void)
{
	struct cxlmi_cmd_memdev_set_partition_info_req req = {0};
	int rc;

	req.volatile_capacity = 0x100;
	req.flags = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_partition_info(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Health Info/Alerts Commands (0x42)
 * ============================================================ */

static int test_cmd_memdev_get_health_info(void)
{
	struct cxlmi_cmd_memdev_get_health_info_rsp rsp = {0}, ret;
	int rc;

	rsp.health_status = 0x01;
	rsp.media_status = 0x00;
	rsp.life_used = 10;
	rsp.device_temperature = 350; /* 35.0 C */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_health_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.health_status, 0x01, "health_status mismatch");
	ASSERT_EQ(ret.life_used, 10, "life_used mismatch");
	return 0;
}

static int test_cmd_memdev_get_alert_config(void)
{
	struct cxlmi_cmd_memdev_get_alert_config_rsp rsp = {0}, ret;
	int rc;

	rsp.valid_alerts = 0xFF;
	rsp.life_used_critical_alert_threshold = 90;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_alert_config(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.valid_alerts, 0xFF, "valid_alerts mismatch");
	return 0;
}

static int test_cmd_memdev_set_alert_config(void)
{
	struct cxlmi_cmd_memdev_set_alert_config_req req = {0};
	int rc;

	req.valid_alert_actions = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_alert_config(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_get_shutdown_state(void)
{
	struct cxlmi_cmd_memdev_get_shutdown_state_rsp rsp = {0}, ret;
	int rc;

	rsp.state = 0x00;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_shutdown_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.state, 0x00, "state mismatch");
	return 0;
}

static int test_cmd_memdev_set_shutdown_state(void)
{
	struct cxlmi_cmd_memdev_set_shutdown_state_req req = {0};
	int rc;

	req.state = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_shutdown_state(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Media and Poison Commands (0x43)
 * ============================================================ */

static int test_cmd_memdev_inject_poison(void)
{
	struct cxlmi_cmd_memdev_inject_poison_req req = {0};
	int rc;

	req.inject_poison_phy_addr = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_inject_poison(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_clear_poison(void)
{
	struct cxlmi_cmd_memdev_clear_poison_req req = {0};
	int rc;

	req.clear_poison_phy_addr = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_clear_poison(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_get_scan_media_capabilities(void)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp rsp = {0}, ret;
	int rc;

	req.get_scan_media_capabilities_start_physaddr = 0x0;
	req.get_scan_media_capabilities_physaddr_length = 0x10000;
	rsp.estimated_scan_media_time = 1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_scan_media_capabilities(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.estimated_scan_media_time, 1000, "time mismatch");
	return 0;
}

static int test_cmd_scan_media(void)
{
	struct cxlmi_cmd_scan_media_req req = {0};
	int rc;

	req.scan_media_physaddr = 0x0;
	req.scan_media_physaddr_length = 0x10000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x04, CXLMI_RET_BACKGROUND, NULL, 0);
	rc = cxlmi_cmd_scan_media(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_BACKGROUND, "expected background op");
	return 0;
}

/* ============================================================
 * Sanitize Commands (0x44)
 * ============================================================ */

static int test_cmd_memdev_sanitize(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x00, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_sanitize(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_secure_erase(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_secure_erase(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Security Commands (0x45)
 * ============================================================ */

static int test_cmd_memdev_get_security_state(void)
{
	struct cxlmi_cmd_memdev_get_security_state_rsp rsp = {0}, ret;
	int rc;

	rsp.security_state = 0x00;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_security_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.security_state, 0x00, "security_state mismatch");
	return 0;
}

static int test_cmd_memdev_freeze_security_state(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_freeze_security_state(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * SLD QoS Commands (0x47)
 * ============================================================ */

static int test_cmd_memdev_get_sld_qos_control(void)
{
	struct cxlmi_cmd_memdev_get_sld_qos_control_rsp rsp = {0}, ret;
	int rc;

	rsp.qos_telemetry_control = 0x01;
	rsp.egress_moderate_percentage = 50;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_sld_qos_control(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x01, "qos_telemetry_control mismatch");
	return 0;
}

static int test_cmd_memdev_set_sld_qos_control(void)
{
	struct cxlmi_cmd_memdev_set_sld_qos_control_req req = {0};
	int rc;

	req.qos_telemetry_control = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_sld_qos_control(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_get_sld_qos_status(void)
{
	struct cxlmi_cmd_memdev_get_sld_qos_status_rsp rsp = {0}, ret;
	int rc;

	rsp.backpressure_avg_percentage = 25;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x02, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_sld_qos_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.backpressure_avg_percentage, 25, "percentage mismatch");
	return 0;
}

/* ============================================================
 * DCD Config Commands (0x48)
 * ============================================================ */

static int test_cmd_memdev_get_dc_config(void)
{
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp rsp = {0}, ret;
	int rc;

	req.region_cnt = 8;
	req.start_region_id = 0;
	rsp.num_regions = 2;
	rsp.regions_returned = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_regions, 2, "num_regions mismatch");
	return 0;
}

/* ============================================================
 * FM-API Physical Switch Commands (0x51)
 * ============================================================ */

static int test_cmd_fmapi_identify_sw_device(void)
{
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp rsp = {0}, ret;
	int rc;

	rsp.ingress_port_id = 0;
	rsp.num_physical_ports = 8;
	rsp.num_vcs = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_identify_sw_device(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_physical_ports, 8, "num_physical_ports mismatch");
	return 0;
}

static int test_cmd_fmapi_phys_port_control(void)
{
	struct cxlmi_cmd_fmapi_phys_port_control_req req = {0};
	int rc;

	req.ppb_id = 0;
	req.port_opcode = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_phys_port_control(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * FM-API Virtual Switch Commands (0x52)
 * ============================================================ */

static int test_cmd_fmapi_bind_vppb(void)
{
	struct cxlmi_cmd_fmapi_bind_vppb_req req = {0};
	int rc;

	req.vcs_id = 0;
	req.vppb_id = 0;
	req.port_id = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x52, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_bind_vppb(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_unbind_vppb(void)
{
	struct cxlmi_cmd_fmapi_unbind_vppb_req req = {0};
	int rc;

	req.vcs_id = 0;
	req.vppb_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x52, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_unbind_vppb(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * FM-API MLD Components Commands (0x54)
 * ============================================================ */

static int test_cmd_fmapi_get_ld_info(void)
{
	struct cxlmi_cmd_fmapi_get_ld_info_rsp rsp = {0}, ret;
	int rc;

	rsp.memory_size = 0x100000000ULL;
	rsp.ld_count = 16;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_ld_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.ld_count, 16, "ld_count mismatch");
	return 0;
}

static int test_cmd_fmapi_get_qos_control(void)
{
	struct cxlmi_cmd_fmapi_get_qos_control_rsp rsp = {0}, ret;
	int rc;

	rsp.qos_telemetry_control = 0x01;
	rsp.egress_moderate_percentage = 50;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_control(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x01, "qos_telemetry_control mismatch");
	return 0;
}

static int test_cmd_fmapi_get_qos_status(void)
{
	struct cxlmi_cmd_fmapi_get_qos_status_rsp rsp = {0}, ret;
	int rc;

	rsp.backpressure_avg_percentage = 10;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x05, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.backpressure_avg_percentage, 10, "percentage mismatch");
	return 0;
}

/* ============================================================
 * FM-API DCD Management Commands (0x56)
 * ============================================================ */

static int test_cmd_fmapi_get_dcd_info(void)
{
	struct cxlmi_cmd_fmapi_get_dcd_info_rsp rsp = {0}, ret;
	int rc;

	rsp.num_hosts = 4;
	rsp.num_supported_dc_regions = 8;
	rsp.total_dynamic_capacity = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dcd_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_hosts, 4, "num_hosts mismatch");
	return 0;
}

/* ============================================================
 * Additional Logs Commands (0x04)
 * ============================================================ */

static int test_cmd_get_log(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	uint8_t ret_buf[64] = {0};
	uint8_t rsp_data[32];
	int rc;

	/* Fill response with pattern */
	for (int i = 0; i < 32; i++)
		rsp_data[i] = i;

	memset(req.uuid, 0xAA, sizeof(req.uuid));
	req.offset = 0;
	req.length = 32;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				rsp_data, sizeof(rsp_data));
	rc = cxlmi_cmd_get_log(test_ep, NULL, &req, ret_buf);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret_buf[0], 0, "ret_buf[0] mismatch");
	ASSERT_EQ(ret_buf[31], 31, "ret_buf[31] mismatch");
	return 0;
}

static int test_cmd_get_log_cel(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	struct cxlmi_cmd_get_log_cel_rsp rsp = {0};
	struct cxlmi_cmd_get_log_cel_rsp *ret;
	int rc, result = 1;

	rsp.opcode = 0x0001; /* Identify */
	rsp.command_effect = 0x0000;

	req.offset = 0;
	req.length = sizeof(rsp);

	ret = calloc(1, sizeof(*ret) + req.length);
	if (!ret) {
		fprintf(stderr, "\n    ASSERT FAILED: allocation failed\n");
		return 1;
	}

	if (setup() != 0) {
		fprintf(stderr, "\n    ASSERT FAILED: setup failed\n");
		goto cleanup;
	}
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_log_cel(test_ep, NULL, &req, ret);
	teardown();

	if (rc != CXLMI_RET_SUCCESS) {
		fprintf(stderr, "\n    ASSERT FAILED: command failed (got %d, expected %d)\n",
			rc, CXLMI_RET_SUCCESS);
		goto cleanup;
	}

	result = 0;
cleanup:
	free(ret);
	return result;
}

static int test_cmd_get_supported_logs_sublist(void)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req req = {0};
	struct cxlmi_cmd_get_supported_logs_sublist_rsp rsp = {0};
	/* Allocate storage for entries - lib will copy entries into ret */
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_logs_sublist_rsp) +
			8 * sizeof(struct cxlmi_supported_log_entry)];
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret =
		(struct cxlmi_cmd_get_supported_logs_sublist_rsp *)ret_buf;
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));
	req.max_supported_log_entries = 8;
	req.start_log_entry_index = 0;

	rsp.num_supported_log_entries = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_supported_logs_sublist(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_log_entries, 2, "num entries mismatch");
	return 0;
}

/* ============================================================
 * Features Commands (0x05)
 * ============================================================ */

static int test_cmd_get_supported_features(void)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	/* Response buffer with storage for 3 entries (each 48 bytes) */
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_get_supported_features_rsp) + 3 * 48];
	struct cxlmi_cmd_get_supported_features_rsp *rsp =
		(struct cxlmi_cmd_get_supported_features_rsp *)rsp_buf;
	/* Return buffer with storage for entries */
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_features_rsp) + 3 * 48];
	struct cxlmi_cmd_get_supported_features_rsp *ret =
		(struct cxlmi_cmd_get_supported_features_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.count = 3 * 48;
	req.starting_feature_index = 0;

	rsp->num_supported_feature_entries = 3;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS,
				&rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_feature_entries, 3, "num features mismatch");
	return 0;
}

static int test_cmd_get_feature(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0}, ret;
	int rc;

	memset(req.feature_id, 0xBB, sizeof(req.feature_id));
	req.offset = 0;
	req.count = 32;
	req.selection = 0; /* Current value */

	rsp.feature_data[0] = 0x12;
	rsp.feature_data[1] = 0x34;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.feature_data[0], 0x12, "feature data mismatch");
	return 0;
}

static int test_cmd_set_feature(void)
{
	struct cxlmi_cmd_set_feature_req req = {0};
	int rc;

	memset(req.feature_id, 0xCC, sizeof(req.feature_id));
	req.set_feature_flags = 0x01;
	req.offset = 0;
	req.version = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_feature(test_ep, NULL, &req, 0);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional CCLS Commands (0x41)
 * ============================================================ */

static int test_cmd_memdev_get_lsa(void)
{
	struct cxlmi_cmd_memdev_get_lsa_req req = {0};
	uint8_t ret_buf[64] = {0};
	uint8_t rsp_data[32];
	int rc;

	for (int i = 0; i < 32; i++)
		rsp_data[i] = 0xA0 + i;

	req.offset = 0;
	req.length = 32;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x02, CXLMI_RET_SUCCESS,
				rsp_data, sizeof(rsp_data));
	rc = cxlmi_cmd_memdev_get_lsa(test_ep, NULL, &req, ret_buf);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret_buf[0], 0xA0, "lsa data mismatch");
	return 0;
}

static int test_cmd_memdev_set_lsa(void)
{
	/* req struct has flexible array member for data */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_set_lsa_req) + 32];
	struct cxlmi_cmd_memdev_set_lsa_req *req =
		(struct cxlmi_cmd_memdev_set_lsa_req *)req_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->offset = 0;
	memset(req->data, 0xAA, 32);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_lsa(test_ep, NULL, req, 32);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional Media/Poison Commands (0x43)
 * ============================================================ */

static int test_cmd_get_poison_list(void)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp rsp = {0}, ret;
	int rc;

	req.get_poison_list_phy_addr = 0x0;
	req.get_poison_list_phy_addr_len = 0x100000;

	rsp.poison_list_flags = 0x01;
	rsp.overflow_timestamp = 0x123456789ABCDEF0ULL;
	rsp.more_err_media_record_cnt = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.poison_list_flags, 0x01, "flags mismatch");
	return 0;
}

static int test_cmd_get_scan_media_results(void)
{
	struct cxlmi_cmd_get_scan_media_results_rsp rsp = {0}, ret;
	int rc;

	rsp.scan_media_restart_physaddr = 0x1000;
	rsp.scan_media_restart_physaddr_length = 0x500;
	rsp.scan_media_flags = 0x01;
	rsp.media_error_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_scan_media_results(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.scan_media_flags, 0x01, "flags mismatch");
	return 0;
}

/* ============================================================
 * Additional DCD Commands (0x48)
 * ============================================================ */

static int test_cmd_memdev_get_dc_extent_list(void)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp rsp = {0}, ret;
	int rc;

	req.extent_cnt = 8;
	req.start_extent_idx = 0;

	/* Return 0 extents to avoid accessing flexible array member */
	rsp.num_extents_returned = 0;
	rsp.total_num_extents = 5;
	rsp.generation_num = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.total_num_extents, 5, "total extents mismatch");
	return 0;
}

static int test_cmd_memdev_add_dc_response(void)
{
	struct cxlmi_cmd_memdev_add_dc_response_req req = {0};
	int rc;

	req.updated_extent_list_size = 0;
	req.flags = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_add_dc_response(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_release_dc(void)
{
	struct cxlmi_cmd_memdev_release_dc_req req = {0};
	int rc;

	req.updated_extent_list_size = 0;
	req.flags = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_release_dc(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional FM-API Physical Switch Commands (0x51)
 * ============================================================ */

static int test_cmd_fmapi_get_phys_port_state(void)
{
	/* Request struct has flexible array for ports */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_req) + 1];
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_req *)req_buf;
	/* Response struct has flexible array for port_info_list */
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) + 64];
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) + 64];
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->num_ports = 1;
	req->ports[0] = 0;

	rsp->num_ports = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_phys_port_state(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_ports, 1, "num_ports mismatch");
	return 0;
}

/* ============================================================
 * Additional FM-API MLD Components Commands (0x54)
 * ============================================================ */

static int test_cmd_fmapi_get_ld_allocations(void)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	/* Response has flexible array for ld_allocation_list */
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			4 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			4 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.start_ld_id = 0;
	req.ld_allocation_list_limit = 4;

	rsp->number_ld = 2;
	rsp->ld_allocation_list_len = 2;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_ld_allocations(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld mismatch");
	return 0;
}

static int test_cmd_fmapi_set_qos_control(void)
{
	struct cxlmi_cmd_fmapi_set_qos_control_req req = {0};
	struct cxlmi_cmd_fmapi_set_qos_control_rsp rsp = {0}, ret;
	int rc;

	req.qos_telemetry_control = 0x01;
	req.egress_moderate_percentage = 50;
	req.egress_severe_percentage = 80;

	rsp.qos_telemetry_control = 0x01;
	rsp.egress_moderate_percentage = 50;
	rsp.egress_severe_percentage = 80;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_set_qos_control(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x01, "telemetry control mismatch");
	return 0;
}

static int test_cmd_fmapi_get_qos_allocated_bw(void)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req req = {0};
	/* Response has flexible array for qos_allocation_fraction */
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.number_ld = 2;
	req.start_ld_id = 0;

	rsp->number_ld = 2;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x06, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld mismatch");
	return 0;
}

static int test_cmd_fmapi_set_qos_allocated_bw(void)
{
	/* Both req and rsp have flexible arrays for qos_allocation_fraction */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 1;
	req->start_ld_id = 0;

	rsp->number_ld = 1;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x07, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_allocated_bw(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 1, "number_ld mismatch");
	return 0;
}

static int test_cmd_fmapi_get_qos_bw_limit(void)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req req = {0};
	/* Response has flexible array for qos_bw_limit_fraction */
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.number_ld = 2;
	req.start_ld_id = 0;

	rsp->number_ld = 2;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x08, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld mismatch");
	return 0;
}

static int test_cmd_fmapi_set_qos_bw_limit(void)
{
	/* Both req and rsp have flexible arrays for qos_bw_limit_fraction */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req) + 4];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 1;
	req->start_ld_id = 0;

	rsp->number_ld = 1;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x09, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_bw_limit(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 1, "number_ld mismatch");
	return 0;
}

/* ============================================================
 * FM-API Multi-Headed Commands (0x55)
 * ============================================================ */

static int test_cmd_fmapi_get_multiheaded_info(void)
{
	struct cxlmi_cmd_fmapi_get_multiheaded_info_req req = {0};
	struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp rsp = {0}, ret;
	int rc;

	req.start_ld_id = 0;
	req.ld_map_list_limit = 4;

	rsp.num_lds = 2;
	rsp.num_heads = 2;
	rsp.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_multiheaded_info(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_heads, 2, "num_heads mismatch");
	return 0;
}

static int test_cmd_fmapi_get_head_info(void)
{
	struct cxlmi_cmd_fmapi_get_head_info_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_head_info_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_get_head_info_blkfmt)];
	struct cxlmi_cmd_fmapi_get_head_info_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_head_info_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_head_info_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_get_head_info_blkfmt)];
	struct cxlmi_cmd_fmapi_get_head_info_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_head_info_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.start_head = 0;
	req.num_heads = 2;

	rsp->num_heads = 2;
	rsp->head_info_list[0].port_num = 1;
	rsp->head_info_list[0].ltssm_state = 0x10;
	rsp->head_info_list[1].port_num = 2;
	rsp->head_info_list[1].ltssm_state = 0x10;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_head_info(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_heads, 2, "num_heads mismatch");
	ASSERT_EQ(ret->head_info_list[0].port_num, 1, "head[0].port_num mismatch");
	ASSERT_EQ(ret->head_info_list[1].port_num, 2, "head[1].port_num mismatch");
	return 0;
}

/* ============================================================
 * FM-API DCD Management Commands (0x56)
 * ============================================================ */

static int test_cmd_fmapi_get_dc_reg_config(void)
{
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp rsp = {0}, ret;
	int rc;

	req.host_id = 0;
	req.region_cnt = 4;
	req.start_region_id = 0;

	rsp.num_regions = 2;
	rsp.regions_returned = 2;
	rsp.num_extents_available = 10;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dc_reg_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_regions, 2, "num_regions mismatch");
	return 0;
}

static int test_cmd_fmapi_set_dc_region_config(void)
{
	struct cxlmi_cmd_fmapi_set_dc_region_config_req req = {0};
	int rc;

	req.region_id = 0;
	req.block_sz = 0x10000;
	req.sanitize_on_release = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_set_dc_region_config(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_get_dc_region_ext_list(void)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp rsp = {0}, ret;
	int rc;

	req.host_id = 0;
	req.extent_count = 8;
	req.start_ext_index = 0;

	/* Return 0 extents to avoid accessing flexible array member */
	rsp.extents_returned = 0;
	rsp.total_extents = 5;
	rsp.list_generation_num = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.total_extents, 5, "total extents mismatch");
	return 0;
}

static int test_cmd_fmapi_initiate_dc_add(void)
{
	struct cxlmi_cmd_fmapi_initiate_dc_add_req req = {0};
	int rc;

	req.host_id = 0;
	req.selection_policy = 0;
	req.region_num = 0;
	req.length = 0x10000;
	req.ext_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_initiate_dc_add(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_initiate_dc_release(void)
{
	struct cxlmi_cmd_fmapi_initiate_dc_release_req req = {0};
	int rc;

	req.host_id = 0;
	req.flags = 0;
	req.ext_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_initiate_dc_release(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional Events Commands (0x01)
 * ============================================================ */

static int test_cmd_clear_event_records(void)
{
	struct cxlmi_cmd_clear_event_records_req req = {0};
	int rc;

	req.event_log = 0x01; /* Informational log */
	req.clear_flags = 0x01; /* Clear all */
	req.nr_recs = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_clear_event_records(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_get_mctp_event_interrupt_policy(void)
{
	struct cxlmi_cmd_get_mctp_event_interrupt_policy_rsp rsp = {0}, ret;
	int rc;

	rsp.event_interrupt_settings = 0x1234;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_mctp_event_interrupt_policy(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.event_interrupt_settings, 0x1234, "settings mismatch");
	return 0;
}

static int test_cmd_set_mctp_event_interrupt_policy(void)
{
	struct cxlmi_cmd_set_mctp_event_interrupt_policy_req req = {0};
	int rc;

	req.event_interrupt_settings = 0x5678;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_mctp_event_interrupt_policy(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_event_notification(void)
{
	struct cxlmi_cmd_event_notification_req req = {0};
	int rc;

	req.event = 0x0001; /* Event notification */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x06, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_event_notification(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional Firmware Commands (0x02)
 * ============================================================ */

static int test_cmd_transfer_fw(void)
{
	/* transfer_fw req has flexible array for data */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_transfer_fw_req) + 64];
	struct cxlmi_cmd_transfer_fw_req *req =
		(struct cxlmi_cmd_transfer_fw_req *)req_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->action = 0x01; /* Full transfer */
	req->slot = 0x01;
	req->offset = 0;
	memset(req->data, 0xAA, 64);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_transfer_fw(test_ep, NULL, req, 64);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional Security Commands (0x45)
 * ============================================================ */

static int test_cmd_memdev_set_passphrase(void)
{
	struct cxlmi_cmd_memdev_set_passphrase_req req = {0};
	int rc;

	req.passphrase_type = 0x01; /* User passphrase */
	memset(req.current_passphrase, 0x11, sizeof(req.current_passphrase));
	memset(req.new_passphrase, 0x22, sizeof(req.new_passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_passphrase(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_disable_passphrase(void)
{
	struct cxlmi_cmd_memdev_disable_passphrase_req req = {0};
	int rc;

	req.passphrase_type = 0x01;
	memset(req.passphrase, 0x33, sizeof(req.passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_disable_passphrase(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_unlock(void)
{
	struct cxlmi_cmd_memdev_unlock_req req = {0};
	int rc;

	memset(req.current_passphrase, 0x44, sizeof(req.current_passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_unlock(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_passphrase_secure_erase(void)
{
	struct cxlmi_cmd_memdev_passphrase_secure_erase_req req = {0};
	int rc;

	req.passphrase_type = 0x01;
	memset(req.passphrase, 0x55, sizeof(req.passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_passphrase_secure_erase(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_memdev_security_send(void)
{
	/* req struct has flexible array member for data */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_security_send_req) + 32];
	struct cxlmi_cmd_memdev_security_send_req *req =
		(struct cxlmi_cmd_memdev_security_send_req *)req_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->security_protocol = 0x01;
	req->sp_specific = 0x1234;
	memset(req->data, 0xAA, 32);

	ASSERT_EQ(setup(), 0, "setup failed");
	/* Security command set 0x46, Security Send opcode 0x00 */
	cxlmi_mock_set_response(test_ep, 0x46, 0x00, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_security_send(test_ep, NULL, req, 32);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional Media Operations Commands (0x44)
 * ============================================================ */

static int test_cmd_memdev_media_operations_discovery(void)
{
	struct cxlmi_cmd_memdev_media_operations_discovery_req req = {0};
	struct cxlmi_cmd_memdev_media_operations_discovery_rsp rsp = {0}, ret;
	int rc;

	req.media_operation_class = 0x00;
	req.media_operation_subclass = 0x00;
	req.dpa_range_count = 0;
	req.discovery_osa.start_index = 0;
	req.discovery_osa.num_ops = 4;

	rsp.dpa_range_granularity = 0x1000;
	rsp.total_supported_ops = 2;
	rsp.num_supported_ops = 0; /* Return 0 to avoid flexible array */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_media_operations_discovery(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.total_supported_ops, 2, "total_supported_ops mismatch");
	return 0;
}

static int test_cmd_memdev_media_operations_sanitize(void)
{
	struct cxlmi_cmd_memdev_media_operations_sanitize_req req = {0};
	int rc;

	req.media_operation_class = 0x00;
	req.media_operation_subclass = 0x00;
	req.dpa_range_count = 0; /* No DPA ranges */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_media_operations_sanitize(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional FM-API Physical Switch Commands (0x51)
 * ============================================================ */

static int test_cmd_fmapi_send_ppb_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp rsp = {0}, ret;
	int rc;

	req.ppb_id = 0x01;
	req.transaction_data = 0x12345678;

	rsp.return_data = 0xABCDEF01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ppb_cxlio_config_request(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.return_data, 0xABCDEF01, "return_data mismatch");
	return 0;
}

static int test_cmd_fmapi_get_domain_validation_sv_state(void)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_state_rsp rsp = {0}, ret;
	int rc;

	rsp.secret_value_state = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_domain_validation_sv_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_state, 0x01, "state mismatch");
	return 0;
}

static int test_cmd_fmapi_set_domain_validation_sv(void)
{
	struct cxlmi_cmd_fmapi_set_domain_validation_sv_req req = {0};
	int rc;

	memset(req.secret_value_uuid, 0xAA, sizeof(req.secret_value_uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_set_domain_validation_sv(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_get_vcs_domain_validation_sv_state(void)
{
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req req = {0};
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp rsp = {0}, ret;
	int rc;

	req.vcs_id = 0x01;
	rsp.secret_value_state = 0x02;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x06, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_state, 0x02, "state mismatch");
	return 0;
}

static int test_cmd_fmapi_get_domain_validation_sv(void)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_req req = {0};
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp rsp = {0}, ret;
	int rc;

	req.vcs_id = 0x01;
	memset(rsp.secret_value_uuid, 0xBB, sizeof(rsp.secret_value_uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x07, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_domain_validation_sv(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_uuid[0], 0xBB, "uuid mismatch");
	return 0;
}

/* ============================================================
 * Additional FM-API MLD Port Commands (0x53)
 * ============================================================ */

static int test_cmd_fmapi_send_ld_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp rsp = {0}, ret;
	int rc;

	req.ppb_id = 0x01;
	req.ld_id = 0x0002;
	req.transaction_data = 0x12345678;

	rsp.return_data = 0xABCDEF01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_config_request(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.return_data, 0xABCDEF01, "return_data mismatch");
	return 0;
}

static int test_cmd_fmapi_send_ld_cxlio_mem_request(void)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp rsp = {0}, ret;
	int rc;

	req.port_id = 0x01;
	req.ld_id = 0x0002;
	req.transaction_len = 0;
	req.transaction_addr = 0x1000;

	rsp.return_size = 0; /* No return data to avoid flexible array */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_mem_request(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional FM-API MLD Components Commands (0x54)
 * ============================================================ */

static int test_cmd_fmapi_set_ld_allocations(void)
{
	struct cxlmi_cmd_fmapi_set_ld_allocations_req req = {0};
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp rsp = {0}, ret;
	int rc;

	req.number_ld = 0; /* No LD allocations to avoid flexible array */
	req.start_ld_id = 0;

	rsp.number_ld = 0;
	rsp.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_set_ld_allocations(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* ============================================================
 * Additional FM-API DCD Commands (0x56)
 * ============================================================ */

static int test_cmd_fmapi_dc_add_reference(void)
{
	struct cxlmi_cmd_fmapi_dc_add_ref_req req = {0};
	int rc;

	memset(req.tag, 0xAA, sizeof(req.tag));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x06, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_dc_add_reference(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_dc_remove_reference(void)
{
	struct cxlmi_cmd_fmapi_dc_remove_ref_req req = {0};
	int rc;

	memset(req.tag, 0xBB, sizeof(req.tag));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x07, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_dc_remove_reference(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_fmapi_dc_list_tags(void)
{
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp rsp = {0}, ret;
	int rc;

	req.start_idx = 0;
	req.tags_count = 4;

	rsp.generation_num = 1;
	rsp.total_num_tags = 5;
	rsp.num_tags_returned = 0; /* Avoid flexible array */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x08, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_dc_list_tags(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.total_num_tags, 5, "total_num_tags mismatch");
	return 0;
}

static int test_cmd_memdev_security_receive(void)
{
	struct cxlmi_cmd_memdev_security_receive_req req = {0};
	uint8_t ret[264]; /* 6 rsvd + 2 len + 256 protos */
	int rc;

	/* Use security protocol 0x00 (Security protocol information) */
	req.security_protocol = 0x00;
	req.sp_specific = 0x0000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x46, 0x01, CXLMI_RET_SUCCESS,
				ret, sizeof(ret));
	rc = cxlmi_cmd_memdev_security_receive(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

static int test_cmd_vendor_specific(void)
{
	uint8_t in_data[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	uint8_t out_data[16] = {0};
	uint8_t expected[16] = {0xAA, 0xBB, 0xCC, 0xDD};
	int rc;

	/* Vendor-specific opcode must be >= 0xC000 */
	uint16_t opcode = 0xC001;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, opcode >> 8, opcode & 0xFF,
				CXLMI_RET_SUCCESS, expected, sizeof(expected));
	rc = cxlmi_cmd_vendor_specific(test_ep, NULL, opcode,
				       in_data, sizeof(in_data),
				       out_data, sizeof(out_data));
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(out_data[0], 0xAA, "out_data[0] mismatch");
	ASSERT_EQ(out_data[1], 0xBB, "out_data[1] mismatch");
	return 0;
}

/* ============================================================
 * Error Code Tests
 * ============================================================ */

static int test_error_code_busy(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_BUSY, "expected BUSY");
	return 0;
}

static int test_error_code_invalid_input(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_INPUT, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_INPUT, "expected INPUT error");
	return 0;
}

static int test_error_code_internal(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_INTERNAL, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_INTERNAL, "expected INTERNAL error");
	return 0;
}

static int test_error_code_retry(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_RETRY, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_RETRY, "expected RETRY error");
	return 0;
}

static int test_error_code_media_disabled(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_MEDIADISABLED, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_MEDIADISABLED, "expected MEDIADISABLED error");
	return 0;
}

static int test_error_code_abort(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_ABORT, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_ABORT, "expected ABORT error");
	return 0;
}

static int test_error_code_security(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SECURITY, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SECURITY, "expected SECURITY error");
	return 0;
}

static int test_error_code_passphrase(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_PASSPHRASE, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_PASSPHRASE, "expected PASSPHRASE error");
	return 0;
}

static int test_error_code_mailbox_unsupported(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_MBUNSUPPORTED, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_MBUNSUPPORTED, "expected MBUNSUPPORTED error");
	return 0;
}

static int test_error_code_payload_length(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_PAYLOADLEN, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_PAYLOADLEN, "expected PAYLOADLEN error");
	return 0;
}

static int test_error_code_log(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_LOG, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_LOG, "expected LOG error");
	return 0;
}

static int test_error_code_interrupted(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_INTERRUPTED, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_INTERRUPTED, "expected INTERRUPTED error");
	return 0;
}

/* Firmware-specific error codes */
static int test_error_code_fw_in_progress(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 1 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWINPROGRESS, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWINPROGRESS, "expected FWINPROGRESS error");
	return 0;
}

static int test_error_code_fw_out_of_order(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 1 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWOOO, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWOOO, "expected FWOOO error");
	return 0;
}

static int test_error_code_fw_auth(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 1 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWAUTH, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWAUTH, "expected FWAUTH error");
	return 0;
}

static int test_error_code_fw_slot(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 99 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWSLOT, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWSLOT, "expected FWSLOT error");
	return 0;
}

static int test_error_code_fw_rollback(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 1 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWROLLBACK, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWROLLBACK, "expected FWROLLBACK error");
	return 0;
}

static int test_error_code_fw_reset(void)
{
	struct cxlmi_cmd_activate_fw_req req = { .action = 1, .slot = 1 };
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_FWRESET, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FWRESET, "expected FWRESET error");
	return 0;
}

/* Memory/media error codes */
static int test_error_code_invalid_handle(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_HANDLE, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_HANDLE, "expected HANDLE error");
	return 0;
}

static int test_error_code_physical_address(void)
{
	struct cxlmi_cmd_memdev_inject_poison_req req = {0};
	int rc;

	req.inject_poison_phy_addr = 0xFFFFFFFFFFFFFFFFULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* MEDIA_AND_POISON=0x43, INJECT_POISON=0x01 */
	cxlmi_mock_set_response(test_ep, 0x43, 0x01, CXLMI_RET_PADDR, NULL, 0);
	rc = cxlmi_cmd_memdev_inject_poison(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_PADDR, "expected PADDR error");
	return 0;
}

static int test_error_code_poison_limit(void)
{
	struct cxlmi_cmd_memdev_inject_poison_req req = {0};
	int rc;

	req.inject_poison_phy_addr = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* MEDIA_AND_POISON=0x43, INJECT_POISON=0x01 */
	cxlmi_mock_set_response(test_ep, 0x43, 0x01, CXLMI_RET_POISONLMT, NULL, 0);
	rc = cxlmi_cmd_memdev_inject_poison(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_POISONLMT, "expected POISONLMT error");
	return 0;
}

static int test_error_code_media_failure(void)
{
	struct cxlmi_cmd_memdev_clear_poison_req req = {0};
	int rc;

	req.clear_poison_phy_addr = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* MEDIA_AND_POISON=0x43, CLEAR_POISON=0x02 */
	cxlmi_mock_set_response(test_ep, 0x43, 0x02, CXLMI_RET_MEDIAFAILURE, NULL, 0);
	rc = cxlmi_cmd_memdev_clear_poison(test_ep, NULL, &req);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_MEDIAFAILURE, "expected MEDIAFAILURE error");
	return 0;
}

/* Feature-specific error codes */
static int test_error_code_feature_version(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* FEATURES=0x05, GET_FEATURE=0x01 */
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_FEATUREVERSION, NULL, 0);
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &rsp);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FEATUREVERSION, "expected FEATUREVERSION error");
	return 0;
}

static int test_error_code_feature_selection(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* FEATURES=0x05, GET_FEATURE=0x01 */
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_FEATURESELVALUE, NULL, 0);
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &rsp);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FEATURESELVALUE, "expected FEATURESELVALUE error");
	return 0;
}

static int test_error_code_feature_transfer_in_progress(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* FEATURES=0x05, GET_FEATURE=0x01 */
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_FEATURETRANSFERIP, NULL, 0);
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &rsp);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FEATURETRANSFERIP, "expected FEATURETRANSFERIP error");
	return 0;
}

static int test_error_code_feature_transfer_out_of_order(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* FEATURES=0x05, GET_FEATURE=0x01 */
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_FEATURETRANSFEROOO, NULL, 0);
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &rsp);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_FEATURETRANSFEROOO, "expected FEATURETRANSFEROOO error");
	return 0;
}

/* Resource and DCD error codes */
static int test_error_code_resource_exhausted(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_RESOURCEEXHAUSTED, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_RESOURCEEXHAUSTED, "expected RESOURCEEXHAUSTED error");
	return 0;
}

static int test_error_code_extent_list(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_EXTLIST, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_EXTLIST, "expected EXTLIST error");
	return 0;
}

static int test_error_code_transfer_out_of_order(void)
{
	struct cxlmi_cmd_identify_rsp id;
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_TRANSFEROOO, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_TRANSFEROOO, "expected TRANSFEROOO error");
	return 0;
}

static int test_error_code_no_bg_abort(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x05, CXLMI_RET_NO_BGABORT, NULL, 0);
	rc = cxlmi_cmd_request_bg_op_abort(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_NO_BGABORT, "expected NO_BGABORT error");
	return 0;
}

static int test_error_code_background(void)
{
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x00, CXLMI_RET_BACKGROUND, NULL, 0);
	rc = cxlmi_cmd_memdev_sanitize(test_ep, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_BACKGROUND, "expected BACKGROUND (success, bg started)");
	return 0;
}

/* Error sequence tests - simulating real-world scenarios */
static int test_error_retry_then_success(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	int rc;

	rsp.vendor_id = 0x1234;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* First attempt returns RETRY */
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_RETRY, NULL, 0);
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_RETRY, "first call should return RETRY");

	/* Second attempt succeeds */
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "second call should succeed");
	ASSERT_EQ(id.vendor_id, 0x1234, "vendor_id should match");

	teardown();
	return 0;
}

static int test_error_busy_multiple_retries(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	unsigned int sent, returned;
	int rc;

	rsp.vendor_id = 0xABCD;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* Queue: BUSY, BUSY, BUSY, SUCCESS */
	mock_set_response_n(test_ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0, 3);
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));

	/* Simulate polling loop */
	do {
		rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	} while (rc == CXLMI_RET_BUSY);

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "should eventually succeed");
	ASSERT_EQ(id.vendor_id, 0xABCD, "vendor_id should match");

	cxlmi_mock_get_stats(test_ep, &sent, &returned);
	ASSERT_EQ(sent, 4, "should have sent 4 commands");
	ASSERT_EQ(returned, 4, "should have returned 4 responses");

	teardown();
	return 0;
}

static int test_error_with_partial_response(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, id;
	int rc;

	/* Set only some fields - simulates partial/corrupt response */
	rsp.vendor_id = 0x5678;
	/* Other fields remain zero */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &id);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command should succeed");
	ASSERT_EQ(id.vendor_id, 0x5678, "vendor_id should match");
	ASSERT_EQ(id.device_id, 0, "unset fields should be zero");
	return 0;
}

static int test_error_different_commands_different_errors(void)
{
	struct cxlmi_cmd_identify_rsp id;
	struct cxlmi_cmd_get_timestamp_rsp ts;
	int rc1, rc2;

	ASSERT_EQ(setup(), 0, "setup failed");

	/* Queue different errors for different commands */
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_BUSY, NULL, 0);
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_INTERNAL, NULL, 0);

	rc1 = cxlmi_cmd_identify(test_ep, NULL, &id);
	rc2 = cxlmi_cmd_get_timestamp(test_ep, NULL, &ts);

	teardown();

	ASSERT_EQ(rc1, CXLMI_RET_BUSY, "identify should return BUSY");
	ASSERT_EQ(rc2, CXLMI_RET_INTERNAL, "get_timestamp should return INTERNAL");
	return 0;
}

/* ============================================================
 * Edge Case Tests - Variable-Length Responses
 * ============================================================ */

/* Test get_supported_logs with zero entries */
static int test_edge_get_supported_logs_empty(void)
{
	struct cxlmi_cmd_get_supported_logs_rsp rsp = {0}, ret;
	int rc;

	rsp.num_supported_log_entries = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_supported_logs(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_supported_log_entries, 0, "should be 0 entries");
	return 0;
}

/* Test get_supported_logs with multiple entries */
static int test_edge_get_supported_logs_multiple(void)
{
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_get_supported_logs_rsp) +
			3 * sizeof(struct cxlmi_supported_log_entry)] = {0};
	struct cxlmi_cmd_get_supported_logs_rsp *rsp =
		(struct cxlmi_cmd_get_supported_logs_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_logs_rsp) +
			3 * sizeof(struct cxlmi_supported_log_entry)] = {0};
	struct cxlmi_cmd_get_supported_logs_rsp *ret =
		(struct cxlmi_cmd_get_supported_logs_rsp *)ret_buf;
	int rc;

	rsp->num_supported_log_entries = cpu_to_le16(3);
	/* Entry 0 */
	rsp->entries[0].log_size = cpu_to_le32(0x1000);
	/* Entry 1 */
	rsp->entries[1].log_size = cpu_to_le32(0x2000);
	/* Entry 2 */
	rsp->entries[2].log_size = cpu_to_le32(0x3000);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x00, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_supported_logs(test_ep, NULL, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_log_entries, 3, "should be 3 entries");
	return 0;
}

/* Test get_event_records with zero records */
static int test_edge_get_event_records_empty(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp rsp = {0}, ret = {0};
	int rc;

	req.event_log = 0;
	rsp.flags = 0;
	rsp.overflow_err_count = 0;
	rsp.first_overflow_timestamp = 0;
	rsp.last_overflow_timestamp = 0;
	rsp.record_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.record_count, 0, "should be 0 records");
	return 0;
}

/* Test get_poison_list with zero records */
static int test_edge_get_poison_list_empty(void)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp rsp = {0}, ret;
	int rc;

	req.get_poison_list_phy_addr = 0;
	req.get_poison_list_phy_addr_len = 0x100000;

	rsp.poison_list_flags = 0;
	rsp.overflow_timestamp = 0;
	rsp.more_err_media_record_cnt = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.more_err_media_record_cnt, 0, "should be 0 records");
	return 0;
}

/* Test get_poison_list with multiple records */
static int test_edge_get_poison_list_multiple(void)
{
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			2 * sizeof(struct cxlmi_memdev_media_err_record)] = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp *rsp =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			2 * sizeof(struct cxlmi_memdev_media_err_record)] = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp *ret =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)ret_buf;
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	int rc;

	req.get_poison_list_phy_addr = 0;
	req.get_poison_list_phy_addr_len = 0x100000;

	rsp->poison_list_flags = 0;
	rsp->more_err_media_record_cnt = cpu_to_le16(2);
	/* Record 0 */
	rsp->records[0].media_err_addr = cpu_to_le64(0x1000);
	rsp->records[0].media_err_len = cpu_to_le32(64);
	/* Record 1 */
	rsp->records[1].media_err_addr = cpu_to_le64(0x2000);
	rsp->records[1].media_err_len = cpu_to_le32(128);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->more_err_media_record_cnt, 2, "should be 2 records");
	return 0;
}

/* Test get_dc_extent_list with zero extents */
static int test_edge_get_dc_extent_list_empty(void)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp rsp = {0}, ret;
	int rc;

	req.extent_cnt = 8;
	req.start_extent_idx = 0;

	rsp.num_extents_returned = 0;
	rsp.total_num_extents = 0;
	rsp.generation_num = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_extents_returned, 0, "should be 0 extents returned");
	ASSERT_EQ(ret.total_num_extents, 0, "should be 0 total extents");
	return 0;
}

/* Test fmapi_get_ld_allocations with zero allocations */
static int test_edge_fmapi_get_ld_allocations_empty(void)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp rsp = {0}, ret;
	int rc;

	req.start_ld_id = 0;
	req.ld_allocation_list_limit = 8;

	rsp.number_ld = 0;
	rsp.memory_granularity = 0;
	rsp.start_ld_id = 0;
	rsp.ld_allocation_list_len = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_ld_allocations(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.ld_allocation_list_len, 0, "should be 0 allocations");
	return 0;
}

/* Test fmapi_get_ld_allocations with multiple allocations */
static int test_edge_fmapi_get_ld_allocations_multiple(void)
{
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			3 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)] = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			3 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)] = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)ret_buf;
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	int rc;

	req.start_ld_id = 0;
	req.ld_allocation_list_limit = 8;

	rsp->number_ld = 3;
	rsp->memory_granularity = 8;
	rsp->start_ld_id = 0;
	rsp->ld_allocation_list_len = 3;
	/* Allocation entries */
	rsp->ld_allocation_list[0].range_1_allocation_mult = cpu_to_le64(0x1000);
	rsp->ld_allocation_list[1].range_1_allocation_mult = cpu_to_le64(0x2000);
	rsp->ld_allocation_list[2].range_1_allocation_mult = cpu_to_le64(0x3000);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_ld_allocations(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->ld_allocation_list_len, 3, "should be 3 allocations");
	return 0;
}

/* Test fmapi_get_phys_port_state with zero ports */
static int test_edge_fmapi_get_phys_port_state_empty(void)
{
	struct cxlmi_cmd_fmapi_get_phys_port_state_req req = {0};
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp rsp = {0}, ret;
	int rc;

	req.num_ports = 0;

	rsp.num_ports = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_phys_port_state(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_ports, 0, "should be 0 ports");
	return 0;
}

/* Test fmapi_get_qos_allocated_bw with zero LDs */
static int test_edge_fmapi_get_qos_allocated_bw_empty(void)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req req = {0};
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp rsp = {0}, ret;
	int rc;

	req.number_ld = 0;
	req.start_ld_id = 0;

	rsp.number_ld = 0;
	rsp.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x06, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.number_ld, 0, "should be 0 LDs");
	return 0;
}

/* Test fmapi_get_qos_bw_limit with zero LDs */
static int test_edge_fmapi_get_qos_bw_limit_empty(void)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req req = {0};
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp rsp = {0}, ret;
	int rc;

	req.number_ld = 0;
	req.start_ld_id = 0;

	rsp.number_ld = 0;
	rsp.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x08, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.number_ld, 0, "should be 0 LDs");
	return 0;
}

/* Test get_supported_features with zero features */
static int test_edge_get_supported_features_empty(void)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	struct cxlmi_cmd_get_supported_features_rsp rsp = {0}, ret;
	int rc;

	req.count = 8;
	req.starting_feature_index = 0;

	rsp.num_supported_feature_entries = 0;
	rsp.device_supported_features = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_supported_feature_entries, 0, "should be 0 features");
	return 0;
}

/* Test get_log_cel with zero entries */
static int test_edge_get_log_cel_empty(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	struct cxlmi_cmd_get_log_cel_rsp rsp = {0}, ret;
	int rc;

	req.offset = 0;
	req.length = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				&rsp, 0);
	rc = cxlmi_cmd_get_log_cel(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	return 0;
}

/* Test get_scan_media_results with zero errors */
static int test_edge_get_scan_media_results_empty(void)
{
	struct cxlmi_cmd_get_scan_media_results_rsp rsp = {0}, ret;
	int rc;

	rsp.scan_media_restart_physaddr = 0;
	rsp.scan_media_restart_physaddr_length = 0;
	rsp.scan_media_flags = 0;
	rsp.media_error_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_scan_media_results(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.media_error_count, 0, "should be 0 errors");
	return 0;
}

/* ============================================================
 * Edge Case Tests - Boundary Values
 * ============================================================ */

/* Test identify with maximum values */
static int test_edge_identify_max_values(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, ret;
	int rc;

	rsp.vendor_id = cpu_to_le16(0xFFFF);
	rsp.device_id = cpu_to_le16(0xFFFF);
	rsp.subsys_vendor_id = cpu_to_le16(0xFFFF);
	rsp.subsys_id = cpu_to_le16(0xFFFF);
	rsp.serial_num = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.max_msg_size = 0xFF;
	rsp.component_type = 0xFF;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.vendor_id, 0xFFFF, "vendor_id mismatch");
	ASSERT_EQ(ret.device_id, 0xFFFF, "device_id mismatch");
	ASSERT_TRUE(ret.serial_num == 0xFFFFFFFFFFFFFFFFULL, "serial_num mismatch");
	return 0;
}

/* Test timestamp with max value */
static int test_edge_timestamp_max_value(void)
{
	struct cxlmi_cmd_get_timestamp_rsp rsp = {0}, ret;
	int rc;

	rsp.timestamp = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_timestamp(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.timestamp == 0xFFFFFFFFFFFFFFFFULL, "timestamp mismatch");
	return 0;
}

/* Test timestamp with zero value */
static int test_edge_timestamp_zero_value(void)
{
	struct cxlmi_cmd_get_timestamp_rsp rsp = {0}, ret;
	int rc;

	rsp.timestamp = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_timestamp(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.timestamp == 0, "timestamp should be 0");
	return 0;
}

/* Test health info with critical thresholds */
static int test_edge_health_info_critical(void)
{
	struct cxlmi_cmd_memdev_get_health_info_rsp rsp = {0}, ret;
	int rc;

	rsp.health_status = 0xFF; /* All flags set */
	rsp.media_status = 0xFF;
	rsp.additional_status = 0xFF;
	rsp.life_used = 100; /* 100% life used */
	rsp.device_temperature = cpu_to_le16(0x7FFF); /* Max positive temp */
	rsp.dirty_shutdown_count = cpu_to_le32(0xFFFFFFFF);
	rsp.corrected_volatile_error_count = cpu_to_le32(0xFFFFFFFF);
	rsp.corrected_persistent_error_count = cpu_to_le32(0xFFFFFFFF);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_health_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.health_status, 0xFF, "health_status mismatch");
	ASSERT_EQ(ret.life_used, 100, "life_used mismatch");
	return 0;
}

/* Test memdev identify with max capacity */
static int test_edge_memdev_identify_max_capacity(void)
{
	struct cxlmi_cmd_memdev_identify_rsp rsp = {0}, ret;
	int rc;

	rsp.total_capacity = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.volatile_capacity = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.persistent_capacity = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.partition_align = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.lsa_size = cpu_to_le32(0xFFFFFFFF);
	/* poison_list_max_mer is a 3-byte field */
	rsp.poison_list_max_mer[0] = 0xFF;
	rsp.poison_list_max_mer[1] = 0xFF;
	rsp.poison_list_max_mer[2] = 0xFF;
	rsp.inject_poison_limit = cpu_to_le16(0xFFFF);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x40, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.total_capacity == 0xFFFFFFFFFFFFFFFFULL,
		    "total_capacity mismatch");
	return 0;
}

/* Test DC config with max regions */
static int test_edge_dc_config_max_regions(void)
{
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp rsp = {0}, ret;
	int rc;

	req.region_cnt = 8;
	req.start_region_id = 0;

	rsp.num_regions = 8;
	rsp.regions_returned = 8;
	rsp.num_extents_supported = cpu_to_le32(0xFFFFFFFF);
	rsp.num_extents_available = cpu_to_le32(0xFFFFFFFF);
	rsp.num_tags_supported = cpu_to_le32(0xFFFFFFFF);
	rsp.num_tags_available = cpu_to_le32(0xFFFFFFFF);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_regions, 8, "num_regions mismatch");
	ASSERT_EQ(ret.num_extents_supported, 0xFFFFFFFF, "num_extents mismatch");
	return 0;
}

/* Test QoS status with max values */
static int test_edge_qos_status_max_values(void)
{
	struct cxlmi_cmd_fmapi_get_qos_status_rsp rsp = {0}, ret;
	int rc;

	rsp.backpressure_avg_percentage = 0xFF;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.backpressure_avg_percentage, 0xFF, "backpressure mismatch");
	return 0;
}

/* Test FW info with all slots used */
static int test_edge_fw_info_all_slots(void)
{
	struct cxlmi_cmd_get_fw_info_rsp rsp = {0}, ret;
	int rc;

	rsp.slots_supported = 4;
	rsp.slot_info = 0x04; /* Slot 4 active */
	rsp.caps = 0xFF;
	memset(rsp.fw_rev1, 'A', sizeof(rsp.fw_rev1));
	memset(rsp.fw_rev2, 'B', sizeof(rsp.fw_rev2));
	memset(rsp.fw_rev3, 'C', sizeof(rsp.fw_rev3));
	memset(rsp.fw_rev4, 'D', sizeof(rsp.fw_rev4));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_fw_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.slots_supported, 4, "slots_supported mismatch");
	return 0;
}

/* Test bg_op_status with max values */
static int test_edge_bg_op_status_max_values(void)
{
	struct cxlmi_cmd_bg_op_status_rsp rsp = {0}, ret;
	int rc;

	rsp.status = 0xFF;
	rsp.opcode = cpu_to_le16(0xFFFF);
	rsp.returncode = cpu_to_le16(0xFFFF);
	rsp.vendor_ext_status = cpu_to_le16(0xFFFF);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_bg_op_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.status, 0xFF, "status mismatch");
	ASSERT_EQ(ret.opcode, 0xFFFF, "opcode mismatch");
	return 0;
}

/* Test event records with overflow flags */
static int test_edge_event_records_overflow(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp rsp = {0}, ret = {0};
	int rc;

	req.event_log = 0;

	rsp.flags = 0x03; /* More records + overflow */
	rsp.overflow_err_count = cpu_to_le16(0xFFFF);
	rsp.first_overflow_timestamp = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.last_overflow_timestamp = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.record_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.flags, 0x03, "flags mismatch");
	ASSERT_EQ(ret.overflow_err_count, 0xFFFF, "overflow_err_count mismatch");
	return 0;
}

/* Test poison list with overflow */
static int test_edge_poison_list_overflow(void)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp rsp = {0}, ret;
	int rc;

	req.get_poison_list_phy_addr = 0;
	req.get_poison_list_phy_addr_len = 0x100000;

	rsp.poison_list_flags = 0x03; /* More data + overflow */
	rsp.overflow_timestamp = cpu_to_le64(0xFFFFFFFFFFFFFFFFULL);
	rsp.more_err_media_record_cnt = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.poison_list_flags, 0x03, "flags mismatch");
	return 0;
}

/* Test response message limit at boundaries */
static int test_edge_response_msg_limit_boundaries(void)
{
	struct cxlmi_cmd_get_response_msg_limit_rsp rsp = {0}, ret;
	int rc;

	/* Test minimum limit (256 bytes = 0x08) */
	rsp.limit = 0x08;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_response_msg_limit(test_ep, NULL, &ret);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.limit, 0x08, "min limit mismatch");

	/* Test maximum limit */
	rsp.limit = 0xFF;
	cxlmi_mock_set_response(test_ep, 0x00, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_response_msg_limit(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.limit, 0xFF, "max limit mismatch");
	return 0;
}

/* ============================================================
 * Request Payload Verification Tests
 * ============================================================ */

/* --- Generic Component Commands (0x00) --- */

static int test_payload_set_response_msg_limit(void)
{
	struct cxlmi_cmd_set_response_msg_limit_req req = {0};
	struct cxlmi_cmd_set_response_msg_limit_rsp ret;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.limit = 0x0A;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x04, CXLMI_RET_SUCCESS, &req, sizeof(req));
	rc = cxlmi_cmd_set_response_msg_limit(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 1, "payload size should be 1 byte");
	ASSERT_EQ(payload[0], 0x0A, "limit mismatch");

	return 0;
}

/* --- Events Commands (0x01) --- */

static int test_payload_get_event_records(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.event_log = 0x02; /* Warning log */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 1, "payload size should be 1 byte");
	ASSERT_EQ(payload[0], 0x02, "event_log mismatch");

	return 0;
}

static int test_payload_set_event_interrupt_policy(void)
{
	struct cxlmi_cmd_set_event_interrupt_policy_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.informational_settings = 0x01;
	req.warning_settings = 0x02;
	req.failure_settings = 0x03;
	req.fatal_settings = 0x04;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_event_interrupt_policy(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload[0], 0x01, "informational_settings mismatch");
	ASSERT_EQ(payload[1], 0x02, "warning_settings mismatch");
	ASSERT_EQ(payload[2], 0x03, "failure_settings mismatch");
	ASSERT_EQ(payload[3], 0x04, "fatal_settings mismatch");

	return 0;
}

/* --- Firmware Commands (0x02) --- */

static int test_payload_set_timestamp(void)
{
	struct cxlmi_cmd_set_timestamp_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t sent_timestamp;
	int rc;

	req.timestamp = 0x123456789ABCDEF0ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_timestamp(test_ep, NULL, &req);

	/* Verify the payload that was sent */
	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size should be 8 bytes");

	/* Verify little-endian encoding */
	sent_timestamp = le64_to_cpu(*(leint64_t *)payload);
	ASSERT_TRUE(sent_timestamp == 0x123456789ABCDEF0ULL, "timestamp not encoded correctly");

	return 0;
}

static int test_payload_activate_fw(void)
{
	struct cxlmi_cmd_activate_fw_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.action = 0x02;
	req.slot = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_activate_fw(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size should be 2 bytes");
	ASSERT_EQ(payload[0], 0x02, "action byte mismatch");
	ASSERT_EQ(payload[1], 0x03, "slot byte mismatch");

	return 0;
}

static int test_payload_set_partition_info(void)
{
	struct cxlmi_cmd_memdev_set_partition_info_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t sent_capacity;
	int rc;

	req.volatile_capacity = 0x0000000100000000ULL; /* 256MB units */
	req.flags = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_partition_info(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 9, "payload size should be 9 bytes");

	/* Verify little-endian encoding of 64-bit capacity */
	sent_capacity = le64_to_cpu(*(leint64_t *)payload);
	ASSERT_TRUE(sent_capacity == 0x0000000100000000ULL, "capacity not encoded correctly");
	ASSERT_EQ(payload[8], 0x01, "flags byte mismatch");

	return 0;
}

static int test_payload_inject_poison(void)
{
	struct cxlmi_cmd_memdev_inject_poison_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t sent_addr;
	int rc;

	req.inject_poison_phy_addr = 0xDEADBEEF00001000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_inject_poison(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size should be 8 bytes");

	sent_addr = le64_to_cpu(*(leint64_t *)payload);
	ASSERT_TRUE(sent_addr == 0xDEADBEEF00001000ULL, "address not encoded correctly");

	return 0;
}

static int test_payload_command_opcode(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, ret;
	uint8_t cmd_set, cmd;
	int rc;

	rsp.vendor_id = 0x1234;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);

	/* Verify the command set and opcode that were sent */
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, NULL, NULL);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x00, "command set should be 0x00 (INFOSTAT)");
	ASSERT_EQ(cmd, 0x01, "command should be 0x01 (IDENTIFY)");

	return 0;
}

static int test_payload_fmapi_bind_vppb(void)
{
	struct cxlmi_cmd_fmapi_bind_vppb_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.vcs_id = 0x02;
	req.vppb_id = 0x05;
	req.port_id = 0x07;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x52, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_bind_vppb(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x52, "command set should be 0x52 (FMAPI VS)");
	ASSERT_EQ(cmd, 0x01, "command should be 0x01 (BIND_VPPB)");
	ASSERT_EQ(payload[0], 0x02, "vcs_id mismatch");
	ASSERT_EQ(payload[1], 0x05, "vppb_id mismatch");
	ASSERT_EQ(payload[2], 0x07, "port_id mismatch");

	return 0;
}

/* --- Logs Commands (0x04) --- */

static int test_payload_get_log(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	uint8_t ret_buf[512];
	uint8_t rsp_data[256] = {0}; /* Mock response payload */
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint32_t offset, length;
	int rc;

	/* CEL UUID */
	memset(req.uuid, 0xAA, sizeof(req.uuid));
	req.offset = 0x00001000;
	req.length = 256;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				rsp_data, sizeof(rsp_data));
	rc = cxlmi_cmd_get_log(test_ep, NULL, &req, ret_buf);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 24, "payload size should be 24 bytes");
	ASSERT_EQ(payload[0], 0xAA, "uuid[0] mismatch");

	offset = le32_to_cpu(*(leint32_t *)&payload[16]);
	length = le32_to_cpu(*(leint32_t *)&payload[20]);
	ASSERT_EQ(offset, 0x00001000, "offset mismatch");
	ASSERT_EQ(length, 256, "length mismatch");

	return 0;
}

static int test_payload_clear_log(void)
{
	struct cxlmi_cmd_clear_log_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req.uuid, 0xBB, sizeof(req.uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_clear_log(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size should be 16 bytes");
	ASSERT_EQ(payload[0], 0xBB, "uuid[0] mismatch");
	ASSERT_EQ(payload[15], 0xBB, "uuid[15] mismatch");

	return 0;
}

/* --- Memory Device Commands (0x40-0x48) --- */

static int test_payload_get_poison_list(void)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t addr, len;
	int rc;

	req.get_poison_list_phy_addr = 0x0000100000000000ULL;
	req.get_poison_list_phy_addr_len = 0x0000000010000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size should be 16 bytes");

	addr = le64_to_cpu(*(leint64_t *)&payload[0]);
	len = le64_to_cpu(*(leint64_t *)&payload[8]);
	ASSERT_TRUE(addr == 0x0000100000000000ULL, "phy_addr mismatch");
	ASSERT_TRUE(len == 0x0000000010000000ULL, "phy_addr_len mismatch");

	return 0;
}

static int test_payload_clear_poison(void)
{
	struct cxlmi_cmd_memdev_clear_poison_req req = {0};
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint64_t addr;
	int rc;

	req.clear_poison_phy_addr = 0xDEADBEEF12345678ULL;
	memset(req.clear_poison_write_data, 0x55, 64);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_clear_poison(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 72, "payload size should be 72 bytes");

	addr = le64_to_cpu(*(leint64_t *)&payload[0]);
	ASSERT_TRUE(addr == 0xDEADBEEF12345678ULL, "phy_addr mismatch");
	ASSERT_EQ(payload[8], 0x55, "write_data[0] mismatch");
	ASSERT_EQ(payload[71], 0x55, "write_data[63] mismatch");

	return 0;
}

static int test_payload_scan_media(void)
{
	struct cxlmi_cmd_scan_media_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t addr, len;
	int rc;

	req.scan_media_physaddr = 0x0000200000000000ULL;
	req.scan_media_physaddr_length = 0x0000000020000000ULL;
	req.scan_media_flags = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_scan_media(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 17, "payload size should be 17 bytes");

	addr = le64_to_cpu(*(leint64_t *)&payload[0]);
	len = le64_to_cpu(*(leint64_t *)&payload[8]);
	ASSERT_TRUE(addr == 0x0000200000000000ULL, "physaddr mismatch");
	ASSERT_TRUE(len == 0x0000000020000000ULL, "physaddr_length mismatch");
	ASSERT_EQ(payload[16], 0x01, "flags mismatch");

	return 0;
}

static int test_payload_set_alert_config(void)
{
	struct cxlmi_cmd_memdev_set_alert_config_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint16_t temp;
	int rc;

	req.valid_alert_actions = 0xFF;
	req.enable_alert_actions = 0x0F;
	req.life_used_programmable_warning_threshold = 80;
	req.device_over_temperature_programmable_warning_threshold = 850; /* 85.0 C */
	req.device_under_temperature_programmable_warning_threshold = 50;  /* 5.0 C */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_alert_config(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload[0], 0xFF, "valid_alert_actions mismatch");
	ASSERT_EQ(payload[1], 0x0F, "enable_alert_actions mismatch");
	ASSERT_EQ(payload[2], 80, "life_used threshold mismatch");

	temp = le16_to_cpu(*(leint16_t *)&payload[4]);
	ASSERT_EQ(temp, 850, "over_temp threshold mismatch");

	return 0;
}

static int test_payload_set_shutdown_state(void)
{
	struct cxlmi_cmd_memdev_set_shutdown_state_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.state = 0x01;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_shutdown_state(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 1, "payload size should be 1 byte");
	ASSERT_EQ(payload[0], 0x01, "state mismatch");

	return 0;
}

static int test_payload_get_dc_config(void)
{
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.region_cnt = 8;
	req.start_region_id = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x00, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_memdev_get_dc_config(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size should be 2 bytes");
	ASSERT_EQ(payload[0], 8, "region_cnt mismatch");
	ASSERT_EQ(payload[1], 2, "start_region_id mismatch");

	return 0;
}

static int test_payload_set_sld_qos_control(void)
{
	struct cxlmi_cmd_memdev_set_sld_qos_control_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.qos_telemetry_control = 0x01;
	req.egress_moderate_percentage = 50;
	req.egress_severe_percentage = 80;
	req.backpressure_sample_interval = 100;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_sld_qos_control(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 4, "payload size should be 4 bytes");
	ASSERT_EQ(payload[0], 0x01, "qos_telemetry_control mismatch");
	ASSERT_EQ(payload[1], 50, "egress_moderate_percentage mismatch");
	ASSERT_EQ(payload[2], 80, "egress_severe_percentage mismatch");
	ASSERT_EQ(payload[3], 100, "backpressure_sample_interval mismatch");

	return 0;
}

/* --- FM-API Commands (0x51-0x56) --- */

static int test_payload_fmapi_phys_port_control(void)
{
	struct cxlmi_cmd_fmapi_phys_port_control_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.ppb_id = 0x03;
	req.port_opcode = 0x02; /* Disable port */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_phys_port_control(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x51, "command set should be 0x51");
	ASSERT_EQ(cmd, 0x02, "command should be 0x02");
	ASSERT_EQ(payload_size, 2, "payload size should be 2 bytes");
	ASSERT_EQ(payload[0], 0x03, "ppb_id mismatch");
	ASSERT_EQ(payload[1], 0x02, "port_opcode mismatch");

	return 0;
}

static int test_payload_fmapi_unbind_vppb(void)
{
	struct cxlmi_cmd_fmapi_unbind_vppb_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.vcs_id = 0x01;
	req.vppb_id = 0x04;
	req.option = 0x01; /* Wait for clean unbind */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x52, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_unbind_vppb(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x52, "command set should be 0x52");
	ASSERT_EQ(cmd, 0x02, "command should be 0x02");
	ASSERT_EQ(payload[0], 0x01, "vcs_id mismatch");
	ASSERT_EQ(payload[1], 0x04, "vppb_id mismatch");
	ASSERT_EQ(payload[2], 0x01, "option mismatch");

	return 0;
}

static int test_payload_clear_event_records(void)
{
	/* Use a buffer to hold the request with flexible array member */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_clear_event_records_req) +
			2 * sizeof(uint16_t)];
	struct cxlmi_cmd_clear_event_records_req *req =
		(struct cxlmi_cmd_clear_event_records_req *)req_buf;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->event_log = 0x03; /* Failure log */
	req->clear_flags = 0x01;
	req->nr_recs = 2;
	req->handles[0] = 0x1234;
	req->handles[1] = 0x5678;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_clear_event_records(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload[0], 0x03, "event_log mismatch");
	ASSERT_EQ(payload[1], 0x01, "clear_flags mismatch");
	ASSERT_EQ(payload[2], 2, "nr_recs mismatch");

	return 0;
}

static int test_payload_get_log_capabilities(void)
{
	struct cxlmi_cmd_get_log_capabilities_req req = {0};
	struct cxlmi_cmd_get_log_capabilities_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/* Set UUID to specific pattern */
	memset(req.uuid, 0xCC, sizeof(req.uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x02, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_log_capabilities(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size should be 16 bytes");
	ASSERT_EQ(payload[0], 0xCC, "uuid[0] mismatch");
	ASSERT_EQ(payload[15], 0xCC, "uuid[15] mismatch");

	return 0;
}

static int test_payload_populate_log(void)
{
	struct cxlmi_cmd_populate_log_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/* Set UUID to specific pattern */
	memset(req.uuid, 0xDD, sizeof(req.uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_populate_log(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size should be 16 bytes");
	ASSERT_EQ(payload[0], 0xDD, "uuid[0] mismatch");
	ASSERT_EQ(payload[15], 0xDD, "uuid[15] mismatch");

	return 0;
}

static int test_payload_get_supported_logs_sublist(void)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req req = {0};
	struct cxlmi_cmd_get_supported_logs_sublist_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.max_supported_log_entries = 16;
	req.start_log_entry_index = 4;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x05, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_supported_logs_sublist(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size should be 2 bytes");
	ASSERT_EQ(payload[0], 16, "max_supported_log_entries mismatch");
	ASSERT_EQ(payload[1], 4, "start_log_entry_index mismatch");

	return 0;
}

static int test_payload_fmapi_get_ld_allocations(void)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.start_ld_id = 4;
	req.ld_allocation_list_limit = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x01, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_fmapi_get_ld_allocations(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size should be 2 bytes");
	ASSERT_EQ(payload[0], 4, "start_ld_id mismatch");
	ASSERT_EQ(payload[1], 8, "ld_allocation_list_limit mismatch");

	return 0;
}

static int test_payload_fmapi_set_qos_control(void)
{
	struct cxlmi_cmd_fmapi_set_qos_control_req req = {0};
	struct cxlmi_cmd_fmapi_set_qos_control_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint16_t recmpbasis;
	int rc;

	req.qos_telemetry_control = 0x03;
	req.egress_moderate_percentage = 45;
	req.egress_severe_percentage = 75;
	req.backpressure_sample_interval = 200;
	req.recmpbasis = 300;
	req.completion_collection_interval = 50;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x04, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_fmapi_set_qos_control(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 7, "payload size should be 7 bytes");
	ASSERT_EQ(payload[0], 0x03, "qos_telemetry_control mismatch");
	ASSERT_EQ(payload[1], 45, "egress_moderate_percentage mismatch");
	ASSERT_EQ(payload[2], 75, "egress_severe_percentage mismatch");
	ASSERT_EQ(payload[3], 200, "backpressure_sample_interval mismatch");

	recmpbasis = le16_to_cpu(*(leint16_t *)&payload[4]);
	ASSERT_EQ(recmpbasis, 300, "recmpbasis mismatch");
	ASSERT_EQ(payload[6], 50, "completion_collection_interval mismatch");

	return 0;
}

static int test_payload_memdev_get_lsa(void)
{
	struct cxlmi_cmd_memdev_get_lsa_req req = {0};
	uint8_t ret_buf[64] = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint32_t offset, length;
	int rc;

	req.offset = 0x00001234;
	req.length = 0x00000040;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x02, CXLMI_RET_SUCCESS, ret_buf, 64);
	rc = cxlmi_cmd_memdev_get_lsa(test_ep, NULL, &req, ret_buf);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size should be 8 bytes");

	offset = le32_to_cpu(*(leint32_t *)&payload[0]);
	length = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(offset, 0x00001234, "offset mismatch");
	ASSERT_EQ(length, 0x00000040, "length mismatch");

	return 0;
}

static int test_payload_get_scan_media_capabilities(void)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint64_t addr, len;
	int rc;

	req.get_scan_media_capabilities_start_physaddr = 0x0000300000000000ULL;
	req.get_scan_media_capabilities_physaddr_length = 0x0000000040000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x03, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_scan_media_capabilities(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size should be 16 bytes");

	addr = le64_to_cpu(*(leint64_t *)&payload[0]);
	len = le64_to_cpu(*(leint64_t *)&payload[8]);
	ASSERT_TRUE(addr == 0x0000300000000000ULL, "start_physaddr mismatch");
	ASSERT_TRUE(len == 0x0000000040000000ULL, "physaddr_length mismatch");

	return 0;
}

static int test_payload_transfer_fw(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_transfer_fw_req) + 16];
	struct cxlmi_cmd_transfer_fw_req *req =
		(struct cxlmi_cmd_transfer_fw_req *)req_buf;
	uint8_t payload[256];
	size_t payload_size = sizeof(payload);
	uint32_t offset;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->action = 0x02;
	req->slot = 0x01;
	req->offset = 0x00001000;
	memset(req->data, 0x55, 16);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_transfer_fw(test_ep, NULL, req, 16);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (0x80 bytes) + data (16 bytes) */
	ASSERT_EQ(payload_size, 0x80 + 16, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x02, "action mismatch");
	ASSERT_EQ(payload[1], 0x01, "slot mismatch");
	offset = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(offset, 0x00001000, "offset mismatch");
	/* Check data starts at offset 0x80 */
	ASSERT_EQ(payload[0x80], 0x55, "data[0] mismatch");
	ASSERT_EQ(payload[0x80 + 15], 0x55, "data[15] mismatch");

	return 0;
}

static int test_payload_memdev_set_lsa(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_set_lsa_req) + 32];
	struct cxlmi_cmd_memdev_set_lsa_req *req =
		(struct cxlmi_cmd_memdev_set_lsa_req *)req_buf;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint32_t offset;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->offset = 0x00000100;
	memset(req->data, 0xAA, 32);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_lsa(test_ep, NULL, req, 32);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (8 bytes: offset + rsvd) + data (32 bytes) */
	ASSERT_EQ(payload_size, 8 + 32, "payload size mismatch");
	offset = le32_to_cpu(*(leint32_t *)&payload[0]);
	ASSERT_EQ(offset, 0x00000100, "offset mismatch");
	/* Check data starts at offset 8 */
	ASSERT_EQ(payload[8], 0xAA, "data[0] mismatch");
	ASSERT_EQ(payload[8 + 31], 0xAA, "data[31] mismatch");

	return 0;
}

static int test_payload_memdev_add_dc_response(void)
{
	/* Extent size is 24 bytes (8 + 8 + 8) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_add_dc_response_req) + 2 * 24];
	struct cxlmi_cmd_memdev_add_dc_response_req *req =
		(struct cxlmi_cmd_memdev_add_dc_response_req *)req_buf;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint32_t extent_count;
	uint64_t dpa, len;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->updated_extent_list_size = 2;
	req->flags = 0x01;
	req->extents[0].start_dpa = 0x0000100000000000ULL;
	req->extents[0].len = 0x0000000010000000ULL;
	req->extents[1].start_dpa = 0x0000200000000000ULL;
	req->extents[1].len = 0x0000000020000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_add_dc_response(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (8 bytes) + 2 extents (24 bytes each) */
	ASSERT_EQ(payload_size, 8 + 2 * 24, "payload size mismatch");

	extent_count = le32_to_cpu(*(leint32_t *)&payload[0]);
	ASSERT_EQ(extent_count, 2, "extent count mismatch");
	ASSERT_EQ(payload[4], 0x01, "flags mismatch");

	/* Check first extent at offset 8 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[8]);
	len = le64_to_cpu(*(leint64_t *)&payload[16]);
	ASSERT_TRUE(dpa == 0x0000100000000000ULL, "extent[0] dpa mismatch");
	ASSERT_TRUE(len == 0x0000000010000000ULL, "extent[0] len mismatch");

	/* Check second extent at offset 8 + 24 = 32 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[32]);
	len = le64_to_cpu(*(leint64_t *)&payload[40]);
	ASSERT_TRUE(dpa == 0x0000200000000000ULL, "extent[1] dpa mismatch");
	ASSERT_TRUE(len == 0x0000000020000000ULL, "extent[1] len mismatch");

	return 0;
}

static int test_payload_memdev_release_dc(void)
{
	/* Extent size is 24 bytes (8 + 8 + 8) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_release_dc_req) + 24];
	struct cxlmi_cmd_memdev_release_dc_req *req =
		(struct cxlmi_cmd_memdev_release_dc_req *)req_buf;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint32_t extent_count;
	uint64_t dpa, len;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->updated_extent_list_size = 1;
	req->flags = 0x02;
	req->extents[0].start_dpa = 0x0000300000000000ULL;
	req->extents[0].len = 0x0000000030000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_release_dc(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (8 bytes) + 1 extent (24 bytes) */
	ASSERT_EQ(payload_size, 8 + 24, "payload size mismatch");

	extent_count = le32_to_cpu(*(leint32_t *)&payload[0]);
	ASSERT_EQ(extent_count, 1, "extent count mismatch");
	ASSERT_EQ(payload[4], 0x02, "flags mismatch");

	dpa = le64_to_cpu(*(leint64_t *)&payload[8]);
	len = le64_to_cpu(*(leint64_t *)&payload[16]);
	ASSERT_TRUE(dpa == 0x0000300000000000ULL, "extent[0] dpa mismatch");
	ASSERT_TRUE(len == 0x0000000030000000ULL, "extent[0] len mismatch");

	return 0;
}

static int test_payload_fmapi_set_ld_allocations(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_req) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *req =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)ret_buf;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint64_t r1, r2;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 2;
	req->start_ld_id = 0;
	req->ld_allocation_list[0].range_1_allocation_mult = 0x100;
	req->ld_allocation_list[0].range_2_allocation_mult = 0x200;
	req->ld_allocation_list[1].range_1_allocation_mult = 0x300;
	req->ld_allocation_list[1].range_2_allocation_mult = 0x400;

	rsp->number_ld = 2;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x02, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_ld_allocations(test_ep, NULL, req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (4 bytes) + 2 allocations (16 bytes each) */
	ASSERT_EQ(payload_size, 4 + 2 * 16, "payload size mismatch");

	ASSERT_EQ(payload[0], 2, "number_ld mismatch");
	ASSERT_EQ(payload[1], 0, "start_ld_id mismatch");

	/* Check first allocation at offset 4 */
	r1 = le64_to_cpu(*(leint64_t *)&payload[4]);
	r2 = le64_to_cpu(*(leint64_t *)&payload[12]);
	ASSERT_EQ(r1, 0x100, "alloc[0] range_1 mismatch");
	ASSERT_EQ(r2, 0x200, "alloc[0] range_2 mismatch");

	/* Check second allocation at offset 4 + 16 = 20 */
	r1 = le64_to_cpu(*(leint64_t *)&payload[20]);
	r2 = le64_to_cpu(*(leint64_t *)&payload[28]);
	ASSERT_EQ(r1, 0x300, "alloc[1] range_1 mismatch");
	ASSERT_EQ(r2, 0x400, "alloc[1] range_2 mismatch");

	return 0;
}

static int test_payload_fmapi_set_qos_allocated_bw(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)ret_buf;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 4;
	req->start_ld_id = 0;
	req->qos_allocation_fraction[0] = 0x10;
	req->qos_allocation_fraction[1] = 0x20;
	req->qos_allocation_fraction[2] = 0x30;
	req->qos_allocation_fraction[3] = 0x40;

	rsp->number_ld = 4;
	rsp->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x07, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_allocated_bw(test_ep, NULL, req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (2 bytes) + 4 fractions (1 byte each) */
	ASSERT_EQ(payload_size, 2 + 4, "payload size mismatch");

	ASSERT_EQ(payload[0], 4, "number_ld mismatch");
	ASSERT_EQ(payload[1], 0, "start_ld_id mismatch");
	ASSERT_EQ(payload[2], 0x10, "fraction[0] mismatch");
	ASSERT_EQ(payload[3], 0x20, "fraction[1] mismatch");
	ASSERT_EQ(payload[4], 0x30, "fraction[2] mismatch");
	ASSERT_EQ(payload[5], 0x40, "fraction[3] mismatch");

	return 0;
}

static int test_payload_fmapi_set_qos_bw_limit(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req) + 3];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 3];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 3];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)ret_buf;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 3;
	req->start_ld_id = 1;
	req->qos_limit_fraction[0] = 0xAA;
	req->qos_limit_fraction[1] = 0xBB;
	req->qos_limit_fraction[2] = 0xCC;

	rsp->number_ld = 3;
	rsp->start_ld_id = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x09, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_bw_limit(test_ep, NULL, req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (2 bytes) + 3 fractions (1 byte each) */
	ASSERT_EQ(payload_size, 2 + 3, "payload size mismatch");

	ASSERT_EQ(payload[0], 3, "number_ld mismatch");
	ASSERT_EQ(payload[1], 1, "start_ld_id mismatch");
	ASSERT_EQ(payload[2], 0xAA, "fraction[0] mismatch");
	ASSERT_EQ(payload[3], 0xBB, "fraction[1] mismatch");
	ASSERT_EQ(payload[4], 0xCC, "fraction[2] mismatch");

	return 0;
}

static int test_payload_security_send(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_security_send_req) + 16];
	struct cxlmi_cmd_memdev_security_send_req *req =
		(struct cxlmi_cmd_memdev_security_send_req *)req_buf;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint16_t sp_specific;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->security_protocol = 0xEC;
	req->sp_specific = 0x1234;
	memset(req->data, 0x77, 16);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x46, 0x00, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_security_send(test_ep, NULL, req, 16);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (8 bytes) + data (16 bytes) */
	ASSERT_EQ(payload_size, 8 + 16, "payload size mismatch");

	ASSERT_EQ(payload[0], 0xEC, "security_protocol mismatch");
	sp_specific = le16_to_cpu(*(leint16_t *)&payload[1]);
	ASSERT_EQ(sp_specific, 0x1234, "sp_specific mismatch");
	/* Data starts at offset 8 */
	ASSERT_EQ(payload[8], 0x77, "data[0] mismatch");
	ASSERT_EQ(payload[8 + 15], 0x77, "data[15] mismatch");

	return 0;
}

static int test_payload_media_operations_sanitize(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_memdev_media_operations_sanitize_req) +
			2 * sizeof(struct cxlmi_cmd_memdev_media_ops_dpa_range_list_entry)];
	struct cxlmi_cmd_memdev_media_operations_sanitize_req *req =
		(struct cxlmi_cmd_memdev_media_operations_sanitize_req *)req_buf;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint32_t count;
	uint64_t dpa, len;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->media_operation_class = 0x00;
	req->media_operation_subclass = 0x00;
	req->dpa_range_count = 2;
	req->dpa_range_list[0].starting_dpa = 0x0000400000000000ULL;
	req->dpa_range_list[0].length = 0x0000000010000000ULL;
	req->dpa_range_list[1].starting_dpa = 0x0000500000000000ULL;
	req->dpa_range_list[1].length = 0x0000000020000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_media_operations_sanitize(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (8 bytes) + 2 ranges (16 bytes each) */
	ASSERT_EQ(payload_size, 8 + 2 * 16, "payload size mismatch");

	ASSERT_EQ(payload[0], 0x00, "media_operation_class mismatch");
	ASSERT_EQ(payload[1], 0x00, "media_operation_subclass mismatch");
	count = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(count, 2, "dpa_range_count mismatch");

	/* First range at offset 8 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[8]);
	len = le64_to_cpu(*(leint64_t *)&payload[16]);
	ASSERT_TRUE(dpa == 0x0000400000000000ULL, "range[0] dpa mismatch");
	ASSERT_TRUE(len == 0x0000000010000000ULL, "range[0] len mismatch");

	/* Second range at offset 8 + 16 = 24 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[24]);
	len = le64_to_cpu(*(leint64_t *)&payload[32]);
	ASSERT_TRUE(dpa == 0x0000500000000000ULL, "range[1] dpa mismatch");
	ASSERT_TRUE(len == 0x0000000020000000ULL, "range[1] len mismatch");

	return 0;
}

static int test_payload_fmapi_get_phys_port_state(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_req) + 3];
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) +
			3 * sizeof(struct cxlmi_cmd_fmapi_port_state_info_block)];
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) +
			3 * sizeof(struct cxlmi_cmd_fmapi_port_state_info_block)];
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)ret_buf;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->num_ports = 3;
	req->ports[0] = 0x01;
	req->ports[1] = 0x02;
	req->ports[2] = 0x05;

	rsp->num_ports = 3;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_phys_port_state(test_ep, NULL, req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (1 byte) + 3 port IDs (1 byte each) */
	ASSERT_EQ(payload_size, 1 + 3, "payload size mismatch");

	ASSERT_EQ(payload[0], 3, "num_ports mismatch");
	ASSERT_EQ(payload[1], 0x01, "port[0] mismatch");
	ASSERT_EQ(payload[2], 0x02, "port[1] mismatch");
	ASSERT_EQ(payload[3], 0x05, "port[2] mismatch");

	return 0;
}

static int test_payload_set_feature(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_set_feature_req) + 8];
	struct cxlmi_cmd_set_feature_req *req =
		(struct cxlmi_cmd_set_feature_req *)req_buf;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint32_t flags;
	uint16_t offset;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	/* Set a test UUID */
	memset(req->feature_id, 0xAB, sizeof(req->feature_id));
	req->set_feature_flags = 0x00000003;
	req->offset = 0x0100;
	req->version = 0x01;
	memset(req->feature_data, 0x55, 8);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_feature(test_ep, NULL, req, 8);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* feature_id(16) + flags(4) + offset(2) + version(1) + rsvd(9) + feature_data(8) = 40 */
	ASSERT_EQ(payload_size, 32 + 8, "payload size mismatch");
	ASSERT_EQ(payload[0], 0xAB, "feature_id[0] mismatch");
	flags = le32_to_cpu(*(leint32_t *)&payload[16]);
	ASSERT_EQ(flags, 0x00000003, "flags mismatch");
	offset = le16_to_cpu(*(leint16_t *)&payload[20]);
	ASSERT_EQ(offset, 0x0100, "offset mismatch");
	ASSERT_EQ(payload[22], 0x01, "version mismatch");
	/* feature_data starts at offset 32 (after 16+4+2+1+9 = 32 bytes) */
	ASSERT_EQ(payload[32], 0x55, "feature_data[0] mismatch");

	return 0;
}

static int test_payload_get_feature(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp ret = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	uint16_t offset, count;
	int rc;

	memset(req.feature_id, 0xCD, sizeof(req.feature_id));
	req.offset = 0x0200;
	req.count = 0x0040;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 21, "payload size mismatch");
	ASSERT_EQ(payload[0], 0xCD, "feature_id[0] mismatch");
	offset = le16_to_cpu(*(leint16_t *)&payload[16]);
	ASSERT_EQ(offset, 0x0200, "offset mismatch");
	count = le16_to_cpu(*(leint16_t *)&payload[18]);
	ASSERT_EQ(count, 0x0040, "count mismatch");

	return 0;
}

static int test_payload_memdev_set_passphrase(void)
{
	struct cxlmi_cmd_memdev_set_passphrase_req req = {0};
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	int rc;

	req.passphrase_type = 0x01;
	memset(req.current_passphrase, 0x11, sizeof(req.current_passphrase));
	memset(req.new_passphrase, 0x22, sizeof(req.new_passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_passphrase(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* passphrase_type(1) + rsvd(31) + current(32) + new(32) = 96 bytes */
	ASSERT_EQ(payload_size, 96, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x01, "passphrase_type mismatch");
	/* current_passphrase at offset 32 (after type + rsvd) */
	ASSERT_EQ(payload[32], 0x11, "current_passphrase[0] mismatch");
	ASSERT_EQ(payload[63], 0x11, "current_passphrase[31] mismatch");
	/* new_passphrase at offset 64 */
	ASSERT_EQ(payload[64], 0x22, "new_passphrase[0] mismatch");
	ASSERT_EQ(payload[95], 0x22, "new_passphrase[31] mismatch");

	return 0;
}

static int test_payload_memdev_disable_passphrase(void)
{
	struct cxlmi_cmd_memdev_disable_passphrase_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.passphrase_type = 0x01;
	memset(req.passphrase, 0x33, sizeof(req.passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_disable_passphrase(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* passphrase_type(1) + rsvd(31) + passphrase(32) = 64 bytes */
	ASSERT_EQ(payload_size, 64, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x01, "passphrase_type mismatch");
	/* passphrase at offset 32 (after type + rsvd) */
	ASSERT_EQ(payload[32], 0x33, "passphrase[0] mismatch");
	ASSERT_EQ(payload[63], 0x33, "passphrase[31] mismatch");

	return 0;
}

static int test_payload_memdev_unlock(void)
{
	struct cxlmi_cmd_memdev_unlock_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req.current_passphrase, 0x44, sizeof(req.current_passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x03, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_unlock(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* current_passphrase(32) = 32 bytes */
	ASSERT_EQ(payload_size, 32, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x44, "current_passphrase[0] mismatch");
	ASSERT_EQ(payload[31], 0x44, "current_passphrase[31] mismatch");

	return 0;
}

static int test_payload_memdev_passphrase_secure_erase(void)
{
	struct cxlmi_cmd_memdev_passphrase_secure_erase_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	req.passphrase_type = 0x01;
	memset(req.passphrase, 0x55, sizeof(req.passphrase));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_passphrase_secure_erase(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* passphrase_type(1) + rsvd(31) + passphrase(32) = 64 bytes */
	ASSERT_EQ(payload_size, 64, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x01, "passphrase_type mismatch");
	/* passphrase at offset 32 (after type + rsvd) */
	ASSERT_EQ(payload[32], 0x55, "passphrase[0] mismatch");
	ASSERT_EQ(payload[63], 0x55, "passphrase[31] mismatch");

	return 0;
}

static int test_payload_memdev_get_dc_extent_list(void)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp rsp = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	uint32_t cnt, start;
	int rc;

	/* Note: library clamps extent_cnt > 8 to 8, so use a value <= 8 */
	req.extent_cnt = 6;
	req.start_extent_idx = 5;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, &rsp);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	cnt = le32_to_cpu(*(leint32_t *)&payload[0]);
	start = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(cnt, 6, "extent_cnt mismatch");
	ASSERT_EQ(start, 5, "start_extent_idx mismatch");

	return 0;
}

static int test_payload_fmapi_get_qos_allocated_bw(void)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)ret_buf;
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.number_ld = 4;
	req.start_ld_id = 2;

	rsp->number_ld = 4;
	rsp->start_ld_id = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x06, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(test_ep, NULL, &req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	ASSERT_EQ(payload[0], 4, "number_ld mismatch");
	ASSERT_EQ(payload[1], 2, "start_ld_id mismatch");

	return 0;
}

static int test_payload_fmapi_get_qos_bw_limit(void)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 3];
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 3];
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)ret_buf;
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.number_ld = 3;
	req.start_ld_id = 1;

	rsp->number_ld = 3;
	rsp->start_ld_id = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x08, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(test_ep, NULL, &req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	ASSERT_EQ(payload[0], 3, "number_ld mismatch");
	ASSERT_EQ(payload[1], 1, "start_ld_id mismatch");

	return 0;
}

static int test_payload_fmapi_initiate_dc_add(void)
{
	/* Extent size is 40 bytes (8 + 8 + 0x10 + 2 + 6) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_initiate_dc_add_req) + 40];
	struct cxlmi_cmd_fmapi_initiate_dc_add_req *req =
		(struct cxlmi_cmd_fmapi_initiate_dc_add_req *)req_buf;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint16_t host_id;
	uint64_t length, dpa, len;
	uint32_t ext_count;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->host_id = 0x1234;
	req->selection_policy = 0x01;
	req->region_num = 0x02;
	req->length = 0x0000000100000000ULL;
	memset(req->tag, 0xEE, sizeof(req->tag));
	req->ext_count = 1;
	req->extents[0].start_dpa = 0x0000600000000000ULL;
	req->extents[0].len = 0x0000000040000000ULL;
	memset(req->extents[0].tag, 0xFF, sizeof(req->extents[0].tag));
	req->extents[0].shared_seq = 0xABCD;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_initiate_dc_add(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (32 bytes) + 1 extent (40 bytes) */
	ASSERT_EQ(payload_size, 32 + 40, "payload size mismatch");

	host_id = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(host_id, 0x1234, "host_id mismatch");
	ASSERT_EQ(payload[2], 0x01, "selection_policy mismatch");
	ASSERT_EQ(payload[3], 0x02, "region_num mismatch");
	length = le64_to_cpu(*(leint64_t *)&payload[4]);
	ASSERT_TRUE(length == 0x0000000100000000ULL, "length mismatch");
	ASSERT_EQ(payload[12], 0xEE, "tag[0] mismatch");
	ext_count = le32_to_cpu(*(leint32_t *)&payload[28]);
	ASSERT_EQ(ext_count, 1, "ext_count mismatch");

	/* Check extent at offset 32 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[32]);
	len = le64_to_cpu(*(leint64_t *)&payload[40]);
	ASSERT_TRUE(dpa == 0x0000600000000000ULL, "extent dpa mismatch");
	ASSERT_TRUE(len == 0x0000000040000000ULL, "extent len mismatch");

	return 0;
}

static int test_payload_fmapi_initiate_dc_release(void)
{
	/* Extent size is 40 bytes (8 + 8 + 0x10 + 2 + 6) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_initiate_dc_release_req) + 40];
	struct cxlmi_cmd_fmapi_initiate_dc_release_req *req =
		(struct cxlmi_cmd_fmapi_initiate_dc_release_req *)req_buf;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);
	uint16_t host_id;
	uint64_t length, dpa, len;
	uint32_t ext_count;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	req->host_id = 0x5678;
	req->flags = 0x03;
	req->length = 0x0000000200000000ULL;
	memset(req->tag, 0xDD, sizeof(req->tag));
	req->ext_count = 1;
	req->extents[0].start_dpa = 0x0000700000000000ULL;
	req->extents[0].len = 0x0000000080000000ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_initiate_dc_release(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (32 bytes) + 1 extent (40 bytes) */
	ASSERT_EQ(payload_size, 32 + 40, "payload size mismatch");

	host_id = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(host_id, 0x5678, "host_id mismatch");
	ASSERT_EQ(payload[2], 0x03, "flags mismatch");
	length = le64_to_cpu(*(leint64_t *)&payload[4]);
	ASSERT_TRUE(length == 0x0000000200000000ULL, "length mismatch");
	ASSERT_EQ(payload[12], 0xDD, "tag[0] mismatch");
	ext_count = le32_to_cpu(*(leint32_t *)&payload[28]);
	ASSERT_EQ(ext_count, 1, "ext_count mismatch");

	/* Check extent at offset 32 */
	dpa = le64_to_cpu(*(leint64_t *)&payload[32]);
	len = le64_to_cpu(*(leint64_t *)&payload[40]);
	ASSERT_TRUE(dpa == 0x0000700000000000ULL, "extent dpa mismatch");
	ASSERT_TRUE(len == 0x0000000080000000ULL, "extent len mismatch");

	return 0;
}

static int test_payload_fmapi_send_ld_cxlio_mem_request(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req) + 8];
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req *req =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req *)req_buf;
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp) + 8];
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *rsp =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp) + 8];
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *ret =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *)ret_buf;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	uint16_t ld_id, trans_len, trans_addr;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->port_id = 0x03;
	req->ld_id = 0x0102;
	req->transaction_len = 8;
	req->transaction_addr = 0x1000;
	memset(req->transaction_data, 0x99, 8);

	rsp->return_size = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x02, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_mem_request(test_ep, NULL, req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Header (9 bytes) + data (8 bytes) */
	ASSERT_EQ(payload_size, 9 + 8, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x03, "port_id mismatch");
	ld_id = le16_to_cpu(*(leint16_t *)&payload[3]);
	ASSERT_EQ(ld_id, 0x0102, "ld_id mismatch");
	trans_len = le16_to_cpu(*(leint16_t *)&payload[5]);
	ASSERT_EQ(trans_len, 8, "transaction_len mismatch");
	trans_addr = le16_to_cpu(*(leint16_t *)&payload[7]);
	ASSERT_EQ(trans_addr, 0x1000, "transaction_addr mismatch");
	ASSERT_EQ(payload[9], 0x99, "data[0] mismatch");

	return 0;
}

static int test_payload_event_notification(void)
{
	struct cxlmi_cmd_event_notification_req req = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t event;
	int rc;

	req.event = 0x0003;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x06, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_event_notification(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	event = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(event, 0x0003, "event mismatch");

	return 0;
}

static int test_payload_set_mctp_event_interrupt_policy(void)
{
	struct cxlmi_cmd_set_mctp_event_interrupt_policy_req req = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t settings;
	int rc;

	req.event_interrupt_settings = 0x1234;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_mctp_event_interrupt_policy(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	settings = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(settings, 0x1234, "event_interrupt_settings mismatch");

	return 0;
}

static int test_payload_get_log_cel(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	struct cxlmi_cmd_get_log_cel_rsp ret[2] = {0};
	uint8_t rsp_buf[8] = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	uint32_t offset, length;
	int rc;

	memset(req.uuid, 0x00, sizeof(req.uuid));
	req.offset = 0;
	req.length = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS, rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_log_cel(test_ep, NULL, &req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 24, "payload size mismatch");
	offset = le32_to_cpu(*(leint32_t *)&payload[16]);
	length = le32_to_cpu(*(leint32_t *)&payload[20]);
	ASSERT_EQ(offset, 0, "offset mismatch");
	ASSERT_EQ(length, 8, "length mismatch");

	return 0;
}

static int test_payload_get_supported_features(void)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	/* Response includes header + variable entries (use raw bytes for simplicity) */
	uint8_t rsp_buf[64] = {0};
	struct cxlmi_cmd_get_supported_features_rsp *ret;
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint32_t count;
	uint16_t start_idx;
	int rc;

	ret = (struct cxlmi_cmd_get_supported_features_rsp *)rsp_buf;
	req.count = 4;
	req.starting_feature_index = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS, rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	count = le32_to_cpu(*(leint32_t *)&payload[0]);
	start_idx = le16_to_cpu(*(leint16_t *)&payload[4]);
	ASSERT_EQ(count, 4, "count mismatch");
	ASSERT_EQ(start_idx, 0, "starting_feature_index mismatch");

	return 0;
}

static int test_payload_memdev_media_operations_discovery(void)
{
	struct cxlmi_cmd_memdev_media_operations_discovery_req req = {0};
	struct cxlmi_cmd_memdev_media_operations_discovery_rsp ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint32_t dpa_range_count;
	uint16_t start_index, num_ops;
	int rc;

	req.media_operation_class = 0x01;
	req.media_operation_subclass = 0x02;
	req.dpa_range_count = 0;
	req.discovery_osa.start_index = 0;
	req.discovery_osa.num_ops = 4;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x02, CXLMI_RET_SUCCESS, &ret, sizeof(ret));
	rc = cxlmi_cmd_memdev_media_operations_discovery(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 12, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x01, "media_operation_class mismatch");
	ASSERT_EQ(payload[1], 0x02, "media_operation_subclass mismatch");
	dpa_range_count = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(dpa_range_count, 0, "dpa_range_count mismatch");
	start_index = le16_to_cpu(*(leint16_t *)&payload[8]);
	num_ops = le16_to_cpu(*(leint16_t *)&payload[10]);
	ASSERT_EQ(start_index, 0, "start_index mismatch");
	ASSERT_EQ(num_ops, 4, "num_ops mismatch");

	return 0;
}

static int test_payload_memdev_security_receive(void)
{
	struct cxlmi_cmd_memdev_security_receive_req req = {0};
	/* Response size for protocol 0x00 is 6 + 2 + 256 = 264 bytes */
	uint8_t rsp_buf[264] = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t sp_specific;
	int rc;

	req.security_protocol = 0x00; /* Use supported protocol */
	req.sp_specific = 0x0001;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x46, 0x01, CXLMI_RET_SUCCESS, rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_memdev_security_receive(test_ep, NULL, &req, rsp_buf);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x00, "security_protocol mismatch");
	sp_specific = le16_to_cpu(*(leint16_t *)&payload[1]);
	ASSERT_EQ(sp_specific, 0x0001, "sp_specific mismatch");

	return 0;
}

static int test_payload_fmapi_get_multiheaded_info(void)
{
	struct cxlmi_cmd_fmapi_get_multiheaded_info_req req = {0};
	struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	req.start_ld_id = 2;
	req.ld_map_list_limit = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x00, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_multiheaded_info(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	ASSERT_EQ(payload[0], 2, "start_ld_id mismatch");
	ASSERT_EQ(payload[1], 8, "ld_map_list_limit mismatch");

	return 0;
}

static int test_payload_fmapi_get_head_info(void)
{
	struct cxlmi_cmd_fmapi_get_head_info_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_head_info_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_get_head_info_blkfmt)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_head_info_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_get_head_info_blkfmt)];
	struct cxlmi_cmd_fmapi_get_head_info_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_head_info_rsp *)ret_buf;
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req.start_head = 1;
	req.num_heads = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x01, CXLMI_RET_SUCCESS, rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_head_info(test_ep, NULL, &req, ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 2, "payload size mismatch");
	ASSERT_EQ(payload[0], 1, "start_head mismatch");
	ASSERT_EQ(payload[1], 2, "num_heads mismatch");

	return 0;
}

static int test_payload_fmapi_send_ppb_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint32_t trans_data;
	int rc;

	req.ppb_id = 0x05;
	req.transaction_data = 0x12345678;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ppb_cxlio_config_request(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x05, "ppb_id mismatch");
	trans_data = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(trans_data, 0x12345678, "transaction_data mismatch");

	return 0;
}

static int test_payload_fmapi_send_ld_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t ld_id;
	uint32_t trans_data;
	int rc;

	req.ppb_id = 0x03;
	req.ld_id = 0x0102;
	req.transaction_data = 0xAABBCCDD;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x01, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_config_request(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 12, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x03, "ppb_id mismatch");
	ld_id = le16_to_cpu(*(leint16_t *)&payload[4]);
	ASSERT_EQ(ld_id, 0x0102, "ld_id mismatch");
	trans_data = le32_to_cpu(*(leint32_t *)&payload[8]);
	ASSERT_EQ(trans_data, 0xAABBCCDD, "transaction_data mismatch");

	return 0;
}

static int test_payload_fmapi_get_domain_validation_sv(void)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_req req = {0};
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	req.vcs_id = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x07, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_domain_validation_sv(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 1, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x03, "vcs_id mismatch");

	return 0;
}

static int test_payload_fmapi_set_domain_validation_sv(void)
{
	struct cxlmi_cmd_fmapi_set_domain_validation_sv_req req = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req.secret_value_uuid, 0xAB, sizeof(req.secret_value_uuid));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x05, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_set_domain_validation_sv(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size mismatch");
	ASSERT_EQ(payload[0], 0xAB, "secret_value_uuid[0] mismatch");
	ASSERT_EQ(payload[15], 0xAB, "secret_value_uuid[15] mismatch");

	return 0;
}

static int test_payload_fmapi_get_vcs_domain_validation_sv_state(void)
{
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req req = {0};
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	req.vcs_id = 0x05;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x06, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 1, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x05, "vcs_id mismatch");

	return 0;
}

static int test_payload_fmapi_get_dc_reg_config(void)
{
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp ret = {0};
	uint8_t rsp_buf[100] = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t host_id;
	int rc;

	req.host_id = 0x0102;
	req.region_cnt = 4;
	req.start_region_id = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x01, CXLMI_RET_SUCCESS, rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_dc_reg_config(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 4, "payload size mismatch");
	host_id = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(host_id, 0x0102, "host_id mismatch");
	ASSERT_EQ(payload[2], 4, "region_cnt mismatch");
	ASSERT_EQ(payload[3], 1, "start_region_id mismatch");

	return 0;
}

static int test_payload_fmapi_set_dc_region_config(void)
{
	struct cxlmi_cmd_fmapi_set_dc_region_config_req req = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	uint64_t block_sz;
	int rc;

	req.region_id = 2;
	req.block_sz = 0x100000;
	req.sanitize_on_release = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_set_dc_region_config(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size mismatch");
	ASSERT_EQ(payload[0], 2, "region_id mismatch");
	block_sz = le64_to_cpu(*(leint64_t *)&payload[4]);
	ASSERT_EQ(block_sz, 0x100000, "block_sz mismatch");
	ASSERT_EQ(payload[12], 1, "sanitize_on_release mismatch");

	return 0;
}

static int test_payload_fmapi_get_dc_region_ext_list(void)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint16_t host_id;
	uint32_t extent_count, start_ext_index;
	int rc;

	req.host_id = 0x0203;
	req.extent_count = 8;
	req.start_ext_index = 4;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x03, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 12, "payload size mismatch");
	host_id = le16_to_cpu(*(leint16_t *)&payload[0]);
	ASSERT_EQ(host_id, 0x0203, "host_id mismatch");
	extent_count = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(extent_count, 8, "extent_count mismatch");
	start_ext_index = le32_to_cpu(*(leint32_t *)&payload[8]);
	ASSERT_EQ(start_ext_index, 4, "start_ext_index mismatch");

	return 0;
}

static int test_payload_fmapi_dc_add_reference(void)
{
	struct cxlmi_cmd_fmapi_dc_add_ref_req req = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req.tag, 0xCD, sizeof(req.tag));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x06, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_dc_add_reference(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size mismatch");
	ASSERT_EQ(payload[0], 0xCD, "tag[0] mismatch");
	ASSERT_EQ(payload[15], 0xCD, "tag[15] mismatch");

	return 0;
}

static int test_payload_fmapi_dc_remove_reference(void)
{
	struct cxlmi_cmd_fmapi_dc_remove_ref_req req = {0};
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req.tag, 0xEF, sizeof(req.tag));

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x07, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_fmapi_dc_remove_reference(test_ep, NULL, &req);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 16, "payload size mismatch");
	ASSERT_EQ(payload[0], 0xEF, "tag[0] mismatch");
	ASSERT_EQ(payload[15], 0xEF, "tag[15] mismatch");

	return 0;
}

static int test_payload_fmapi_dc_list_tags(void)
{
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp rsp = {0}, ret = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	uint32_t start_idx, tags_count;
	int rc;

	req.start_idx = 5;
	req.tags_count = 10;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x08, CXLMI_RET_SUCCESS, &rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_dc_list_tags(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	start_idx = le32_to_cpu(*(leint32_t *)&payload[0]);
	tags_count = le32_to_cpu(*(leint32_t *)&payload[4]);
	ASSERT_EQ(start_idx, 5, "start_idx mismatch");
	ASSERT_EQ(tags_count, 10, "tags_count mismatch");

	return 0;
}

static int test_payload_vendor_specific(void)
{
	uint8_t cmd_data[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	uint8_t rsp_data[8] = {0};
	uint8_t payload[16];
	size_t payload_size = sizeof(payload);
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0xC0, 0x00, CXLMI_RET_SUCCESS, rsp_data, sizeof(rsp_data));
	rc = cxlmi_cmd_vendor_specific(test_ep, NULL, 0xC000, cmd_data, sizeof(cmd_data),
				       rsp_data, sizeof(rsp_data));

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(payload_size, 8, "payload size mismatch");
	ASSERT_EQ(payload[0], 0x11, "cmd_data[0] mismatch");
	ASSERT_EQ(payload[7], 0x88, "cmd_data[7] mismatch");

	return 0;
}

/* ============================================================
 * Response Payload Verification Tests
 * These tests verify that the library correctly decodes
 * little-endian response data from the device.
 * ============================================================ */

static int test_response_identify(void)
{
	struct cxlmi_cmd_identify_rsp rsp = {0}, ret = {0};
	int rc;

	/* Set up response in little-endian wire format */
	rsp.vendor_id = cpu_to_le16(0x1234);
	rsp.device_id = cpu_to_le16(0x5678);
	rsp.subsys_vendor_id = cpu_to_le16(0xABCD);
	rsp.subsys_id = cpu_to_le16(0xEF01);
	rsp.serial_num = cpu_to_le64(0x123456789ABCDEF0ULL);
	rsp.max_msg_size = 9; /* 512 bytes */
	rsp.component_type = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.vendor_id, 0x1234, "vendor_id mismatch");
	ASSERT_EQ(ret.device_id, 0x5678, "device_id mismatch");
	ASSERT_EQ(ret.subsys_vendor_id, 0xABCD, "subsys_vendor_id mismatch");
	ASSERT_EQ(ret.subsys_id, 0xEF01, "subsys_id mismatch");
	ASSERT_EQ(ret.serial_num, 0x123456789ABCDEF0ULL, "serial_num mismatch");
	ASSERT_EQ(ret.max_msg_size, 9, "max_msg_size mismatch");
	ASSERT_EQ(ret.component_type, 0x03, "component_type mismatch");

	return 0;
}

static int test_response_bg_op_status(void)
{
	struct cxlmi_cmd_bg_op_status_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.status = 0x02; /* In progress */
	rsp.opcode = cpu_to_le16(0x4400); /* Sanitize */
	rsp.returncode = cpu_to_le16(0x0000);
	rsp.vendor_ext_status = cpu_to_le16(0x1234);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_bg_op_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.status, 0x02, "status mismatch");
	ASSERT_EQ(ret.opcode, 0x4400, "opcode mismatch");
	ASSERT_EQ(ret.vendor_ext_status, 0x1234, "vendor_ext_status mismatch");

	return 0;
}

static int test_response_get_timestamp(void)
{
	struct cxlmi_cmd_get_timestamp_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.timestamp = cpu_to_le64(0xFEDCBA9876543210ULL);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_timestamp(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.timestamp, 0xFEDCBA9876543210ULL, "timestamp mismatch");

	return 0;
}

static int test_response_memdev_identify(void)
{
	struct cxlmi_cmd_memdev_identify_rsp rsp = {0}, ret = {0};
	int rc;

	memcpy(rsp.fw_revision, "TestFW-1.2.3    ", 16);
	rsp.total_capacity = cpu_to_le64(0x100000000ULL); /* 4GB in 256MB units */
	rsp.volatile_capacity = cpu_to_le64(0x80000000ULL);
	rsp.persistent_capacity = cpu_to_le64(0x80000000ULL);
	rsp.partition_align = cpu_to_le64(0x10000000ULL);
	rsp.info_event_log_size = cpu_to_le16(1024);
	rsp.warning_event_log_size = cpu_to_le16(512);
	rsp.failure_event_log_size = cpu_to_le16(256);
	rsp.fatal_event_log_size = cpu_to_le16(128);
	rsp.lsa_size = cpu_to_le32(65536);
	rsp.inject_poison_limit = cpu_to_le16(256);
	rsp.poison_caps = 0x07;
	rsp.qos_telemetry_caps = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x40, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.total_capacity, 0x100000000ULL, "total_capacity mismatch");
	ASSERT_EQ(ret.volatile_capacity, 0x80000000ULL, "volatile_capacity mismatch");
	ASSERT_EQ(ret.persistent_capacity, 0x80000000ULL, "persistent_capacity mismatch");
	ASSERT_EQ(ret.partition_align, 0x10000000ULL, "partition_align mismatch");
	ASSERT_EQ(ret.info_event_log_size, 1024, "info_event_log_size mismatch");
	ASSERT_EQ(ret.warning_event_log_size, 512, "warning_event_log_size mismatch");
	ASSERT_EQ(ret.lsa_size, 65536, "lsa_size mismatch");
	ASSERT_EQ(ret.inject_poison_limit, 256, "inject_poison_limit mismatch");

	return 0;
}

static int test_response_memdev_get_partition_info(void)
{
	struct cxlmi_cmd_memdev_get_partition_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.active_vmem = cpu_to_le64(0x200000000ULL);
	rsp.active_pmem = cpu_to_le64(0x300000000ULL);
	rsp.next_vmem = cpu_to_le64(0x180000000ULL);
	rsp.next_pmem = cpu_to_le64(0x380000000ULL);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_partition_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.active_vmem, 0x200000000ULL, "active_vmem mismatch");
	ASSERT_EQ(ret.active_pmem, 0x300000000ULL, "active_pmem mismatch");
	ASSERT_EQ(ret.next_vmem, 0x180000000ULL, "next_vmem mismatch");
	ASSERT_EQ(ret.next_pmem, 0x380000000ULL, "next_pmem mismatch");

	return 0;
}

static int test_response_memdev_get_health_info(void)
{
	struct cxlmi_cmd_memdev_get_health_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.health_status = 0x01;
	rsp.media_status = 0x02;
	rsp.additional_status = 0x03;
	rsp.life_used = 25; /* 25% */
	rsp.device_temperature = cpu_to_le16(325); /* 32.5C */
	rsp.dirty_shutdown_count = cpu_to_le32(5);
	rsp.corrected_volatile_error_count = cpu_to_le32(100);
	rsp.corrected_persistent_error_count = cpu_to_le32(50);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_health_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.health_status, 0x01, "health_status mismatch");
	ASSERT_EQ(ret.media_status, 0x02, "media_status mismatch");
	ASSERT_EQ(ret.life_used, 25, "life_used mismatch");
	ASSERT_EQ(ret.device_temperature, 325, "device_temperature mismatch");
	ASSERT_EQ(ret.dirty_shutdown_count, 5, "dirty_shutdown_count mismatch");
	ASSERT_EQ(ret.corrected_volatile_error_count, 100, "corrected_volatile_error_count mismatch");
	ASSERT_EQ(ret.corrected_persistent_error_count, 50, "corrected_persistent_error_count mismatch");

	return 0;
}

static int test_response_memdev_get_alert_config(void)
{
	struct cxlmi_cmd_memdev_get_alert_config_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.valid_alerts = 0xFF;
	rsp.programmable_alerts = 0x0F;
	rsp.life_used_critical_alert_threshold = 90;
	rsp.life_used_programmable_warning_threshold = 80;
	rsp.device_over_temperature_critical_alert_threshold = cpu_to_le16(850);
	rsp.device_under_temperature_critical_alert_threshold = cpu_to_le16(100);
	rsp.device_over_temperature_programmable_warning_threshold = cpu_to_le16(750);
	rsp.device_under_temperature_programmable_warning_threshold = cpu_to_le16(150);
	rsp.corrected_volatile_mem_error_programmable_warning_threshold = cpu_to_le16(1000);
	rsp.corrected_persistent_mem_error_programmable_warning_threshold = cpu_to_le16(500);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_alert_config(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.valid_alerts, 0xFF, "valid_alerts mismatch");
	ASSERT_EQ(ret.life_used_critical_alert_threshold, 90, "life_used_critical mismatch");
	ASSERT_EQ(ret.device_over_temperature_critical_alert_threshold, 850, "over_temp_critical mismatch");
	ASSERT_EQ(ret.device_over_temperature_programmable_warning_threshold, 750, "over_temp_warning mismatch");
	ASSERT_EQ(ret.corrected_volatile_mem_error_programmable_warning_threshold, 1000, "volatile_error_warning mismatch");

	return 0;
}

static int test_response_fmapi_identify_sw_device(void)
{
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.ingress_port_id = 0x05;
	rsp.num_physical_ports = 16;
	rsp.num_vcs = 4;
	rsp.active_port_bitmask[0] = 0xFF;
	rsp.active_port_bitmask[1] = 0x0F;
	rsp.active_vcs_bitmask[0] = 0x0F;
	rsp.num_total_vppb = cpu_to_le16(64);
	rsp.num_active_vppb = cpu_to_le16(32);
	rsp.num_hdm_decoder_per_usp = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_identify_sw_device(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.ingress_port_id, 0x05, "ingress_port_id mismatch");
	ASSERT_EQ(ret.num_physical_ports, 16, "num_physical_ports mismatch");
	ASSERT_EQ(ret.num_vcs, 4, "num_vcs mismatch");
	ASSERT_EQ(ret.num_total_vppb, 64, "num_total_vppb mismatch");
	ASSERT_EQ(ret.num_active_vppb, 32, "num_active_vppb mismatch");
	ASSERT_EQ(ret.num_hdm_decoder_per_usp, 8, "num_hdm_decoder_per_usp mismatch");

	return 0;
}

static int test_response_fmapi_get_ld_info(void)
{
	struct cxlmi_cmd_fmapi_get_ld_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.memory_size = cpu_to_le64(0x400000000ULL); /* 16GB */
	rsp.ld_count = cpu_to_le16(8);
	rsp.qos_telemetry_capability = 0x07;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_ld_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.memory_size, 0x400000000ULL, "memory_size mismatch");
	ASSERT_EQ(ret.ld_count, 8, "ld_count mismatch");
	ASSERT_EQ(ret.qos_telemetry_capability, 0x07, "qos_telemetry_capability mismatch");

	return 0;
}

static int test_response_fmapi_get_qos_status(void)
{
	struct cxlmi_cmd_fmapi_get_qos_status_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.backpressure_avg_percentage = 45;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.backpressure_avg_percentage, 45, "backpressure mismatch");

	return 0;
}

static int test_response_get_fw_info(void)
{
	struct cxlmi_cmd_get_fw_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.slots_supported = 4;
	rsp.slot_info = 0x12; /* Active slot 2, staged slot 1 */
	rsp.caps = 0x03;
	memcpy(rsp.fw_rev1, "FW-Slot1-v1.0   ", 16);
	memcpy(rsp.fw_rev2, "FW-Slot2-v2.0   ", 16);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x02, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_fw_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.slots_supported, 4, "slots_supported mismatch");
	ASSERT_EQ(ret.slot_info, 0x12, "slot_info mismatch");
	ASSERT_EQ(ret.caps, 0x03, "caps mismatch");
	ASSERT_EQ(memcmp(ret.fw_rev1, "FW-Slot1-v1.0   ", 16), 0, "fw_rev1 mismatch");

	return 0;
}

static int test_response_memdev_get_poison_list(void)
{
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			2 * sizeof(struct cxlmi_memdev_media_err_record)];
	struct cxlmi_cmd_memdev_get_poison_list_rsp *rsp =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			2 * sizeof(struct cxlmi_memdev_media_err_record)];
	struct cxlmi_cmd_memdev_get_poison_list_rsp *ret =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)ret_buf;
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->poison_list_flags = 0x01;
	rsp->overflow_timestamp = cpu_to_le64(0x123456789ABCDEF0ULL);
	rsp->more_err_media_record_cnt = cpu_to_le16(2);
	rsp->records[0].media_err_addr = cpu_to_le64(0x1000);
	rsp->records[0].media_err_len = cpu_to_le32(0x100);
	rsp->records[1].media_err_addr = cpu_to_le64(0x2000);
	rsp->records[1].media_err_len = cpu_to_le32(0x200);

	req.get_poison_list_phy_addr = 0;
	req.get_poison_list_phy_addr_len = 0x10000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->poison_list_flags, 0x01, "poison_list_flags mismatch");
	ASSERT_EQ(ret->overflow_timestamp, 0x123456789ABCDEF0ULL, "overflow_timestamp mismatch");
	ASSERT_EQ(ret->more_err_media_record_cnt, 2, "more_err_media_record_cnt mismatch");
	ASSERT_EQ(ret->records[0].media_err_addr, 0x1000, "record[0].media_err_addr mismatch");
	ASSERT_EQ(ret->records[0].media_err_len, 0x100, "record[0].media_err_len mismatch");
	ASSERT_EQ(ret->records[1].media_err_addr, 0x2000, "record[1].media_err_addr mismatch");

	return 0;
}

static int test_response_get_event_records(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	struct cxlmi_cmd_get_event_records_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.flags = 0x03;
	rsp.overflow_err_count = cpu_to_le16(5);
	rsp.first_overflow_timestamp = cpu_to_le64(0x1111222233334444ULL);
	rsp.last_overflow_timestamp = cpu_to_le64(0x5555666677778888ULL);
	rsp.record_count = cpu_to_le16(0); /* No records to avoid flexible array */

	req.event_log = 0x00; /* Information log */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.flags, 0x03, "flags mismatch");
	ASSERT_EQ(ret.overflow_err_count, 5, "overflow_err_count mismatch");
	ASSERT_EQ(ret.first_overflow_timestamp, 0x1111222233334444ULL, "first_overflow_timestamp mismatch");
	ASSERT_EQ(ret.last_overflow_timestamp, 0x5555666677778888ULL, "last_overflow_timestamp mismatch");
	ASSERT_EQ(ret.record_count, 0, "record_count mismatch");

	return 0;
}

static int test_response_get_supported_logs(void)
{
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_get_supported_logs_rsp) +
			3 * sizeof(struct cxlmi_supported_log_entry)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_logs_rsp) +
			3 * sizeof(struct cxlmi_supported_log_entry)];
	struct cxlmi_cmd_get_supported_logs_rsp *rsp =
		(struct cxlmi_cmd_get_supported_logs_rsp *)rsp_buf;
	struct cxlmi_cmd_get_supported_logs_rsp *ret =
		(struct cxlmi_cmd_get_supported_logs_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->num_supported_log_entries = cpu_to_le16(3);
	/* Set some test data in entries */
	memset(rsp->entries[0].uuid, 0xAA, sizeof(rsp->entries[0].uuid));
	rsp->entries[0].log_size = cpu_to_le32(0x1000);
	memset(rsp->entries[1].uuid, 0xBB, sizeof(rsp->entries[1].uuid));
	rsp->entries[1].log_size = cpu_to_le32(0x2000);
	memset(rsp->entries[2].uuid, 0xCC, sizeof(rsp->entries[2].uuid));
	rsp->entries[2].log_size = cpu_to_le32(0x3000);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x00, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_supported_logs(test_ep, NULL, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_log_entries, 3, "num_supported_log_entries mismatch");
	ASSERT_EQ(ret->entries[0].uuid[0], 0xAA, "entry[0].uuid wrong");
	ASSERT_EQ(ret->entries[0].log_size, 0x1000, "entry[0].log_size wrong");
	ASSERT_EQ(ret->entries[1].uuid[0], 0xBB, "entry[1].uuid wrong");
	ASSERT_EQ(ret->entries[1].log_size, 0x2000, "entry[1].log_size wrong");
	ASSERT_EQ(ret->entries[2].uuid[0], 0xCC, "entry[2].uuid wrong");
	ASSERT_EQ(ret->entries[2].log_size, 0x3000, "entry[2].log_size wrong");

	return 0;
}

static int test_response_get_response_msg_limit(void)
{
	struct cxlmi_cmd_get_response_msg_limit_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.limit = 10; /* 1KB */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_response_msg_limit(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.limit, 10, "limit mismatch");

	return 0;
}

static int test_response_memdev_get_shutdown_state(void)
{
	struct cxlmi_cmd_memdev_get_shutdown_state_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.state = 0x01; /* Clean shutdown */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_shutdown_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.state, 0x01, "state mismatch");

	return 0;
}

static int test_response_memdev_get_security_state(void)
{
	struct cxlmi_cmd_memdev_get_security_state_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.security_state = cpu_to_le32(0x0000001F);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x45, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_security_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.security_state, 0x0000001F, "security_state mismatch");

	return 0;
}

static int test_response_memdev_get_sld_qos_control(void)
{
	struct cxlmi_cmd_memdev_get_sld_qos_control_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.qos_telemetry_control = 0x03;
	rsp.egress_moderate_percentage = 50;
	rsp.egress_severe_percentage = 80;
	rsp.backpressure_sample_interval = 100;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_sld_qos_control(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x03, "qos_telemetry_control mismatch");
	ASSERT_EQ(ret.egress_moderate_percentage, 50, "egress_moderate_percentage mismatch");
	ASSERT_EQ(ret.egress_severe_percentage, 80, "egress_severe_percentage mismatch");
	ASSERT_EQ(ret.backpressure_sample_interval, 100, "backpressure_sample_interval mismatch");

	return 0;
}

static int test_response_memdev_get_sld_qos_status(void)
{
	struct cxlmi_cmd_memdev_get_sld_qos_status_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.backpressure_avg_percentage = 42;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x47, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_sld_qos_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.backpressure_avg_percentage, 42, "backpressure_avg_percentage mismatch");

	return 0;
}

static int test_response_fmapi_get_qos_control(void)
{
	struct cxlmi_cmd_fmapi_get_qos_control_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.qos_telemetry_control = 0x07;
	rsp.egress_moderate_percentage = 40;
	rsp.egress_severe_percentage = 70;
	rsp.backpressure_sample_interval = 50;
	rsp.recmpbasis = cpu_to_le16(1000);
	rsp.completion_collection_interval = 5;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_qos_control(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x07, "qos_telemetry_control mismatch");
	ASSERT_EQ(ret.egress_moderate_percentage, 40, "egress_moderate_percentage mismatch");
	ASSERT_EQ(ret.recmpbasis, 1000, "recmpbasis mismatch");
	ASSERT_EQ(ret.completion_collection_interval, 5, "completion_collection_interval mismatch");

	return 0;
}

static int test_response_get_scan_media_capabilities(void)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.estimated_scan_media_time = cpu_to_le32(3600);

	req.get_scan_media_capabilities_start_physaddr = 0x1000;
	req.get_scan_media_capabilities_physaddr_length = 0x10000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_scan_media_capabilities(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.estimated_scan_media_time, 3600, "estimated_scan_media_time mismatch");

	return 0;
}

static int test_response_get_scan_media_results(void)
{
	struct cxlmi_cmd_get_scan_media_results_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.scan_media_restart_physaddr = cpu_to_le64(0x2000);
	rsp.scan_media_restart_physaddr_length = cpu_to_le64(0x8000);
	rsp.scan_media_flags = 0x01;
	rsp.media_error_count = cpu_to_le16(0); /* No records to avoid flexible array */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x05, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_scan_media_results(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.scan_media_restart_physaddr, 0x2000, "scan_media_restart_physaddr mismatch");
	ASSERT_EQ(ret.scan_media_restart_physaddr_length, 0x8000, "scan_media_restart_physaddr_length mismatch");
	ASSERT_EQ(ret.scan_media_flags, 0x01, "scan_media_flags mismatch");

	return 0;
}

static int test_response_memdev_get_dc_config(void)
{
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp ret = {0};
	/*
	 * The wire format has the extents/tags fields immediately after the
	 * returned region_configs, not at a fixed offset. Build a buffer with
	 * 2 regions followed by the 4 uint32 fields.
	 */
	uint8_t rsp_buf[8 + 2*40 + 16] = {0}; /* hdr + 2 regions + 4 u32s */
	uint8_t *p = rsp_buf;
	int rc;

	/* Header: num_regions, regions_returned, rsvd[6] */
	p[0] = 2; /* num_regions */
	p[1] = 2; /* regions_returned */
	p += 8;   /* skip rsvd */

	/* Region config 0 */
	*(leint64_t *)p = cpu_to_le64(0x100000000ULL); p += 8; /* base */
	*(leint64_t *)p = cpu_to_le64(0x80000000ULL); p += 8;  /* decode_len */
	*(leint64_t *)p = cpu_to_le64(0x80000000ULL); p += 8;  /* region_len */
	*(leint64_t *)p = cpu_to_le64(0x40); p += 8;           /* block_size */
	*(leint32_t *)p = cpu_to_le32(0); p += 4;              /* dsmadhandle */
	*p++ = 0; p += 3;                                       /* flags + rsvd */

	/* Region config 1 */
	*(leint64_t *)p = cpu_to_le64(0x200000000ULL); p += 8; /* base */
	*(leint64_t *)p = cpu_to_le64(0x40000000ULL); p += 8;  /* decode_len */
	*(leint64_t *)p = cpu_to_le64(0x40000000ULL); p += 8;  /* region_len */
	*(leint64_t *)p = cpu_to_le64(0x80); p += 8;           /* block_size */
	*(leint32_t *)p = cpu_to_le32(0); p += 4;              /* dsmadhandle */
	*p++ = 0; p += 3;                                       /* flags + rsvd */

	/* Extents/tags fields immediately after 2 regions */
	*(leint32_t *)p = cpu_to_le32(1024); p += 4; /* num_extents_supported */
	*(leint32_t *)p = cpu_to_le32(512); p += 4;  /* num_extents_available */
	*(leint32_t *)p = cpu_to_le32(256); p += 4;  /* num_tags_supported */
	*(leint32_t *)p = cpu_to_le32(128);          /* num_tags_available */

	req.region_cnt = 8;
	req.start_region_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x00, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_memdev_get_dc_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_regions, 2, "num_regions mismatch");
	ASSERT_EQ(ret.regions_returned, 2, "regions_returned mismatch");
	ASSERT_EQ(ret.region_configs[0].base, 0x100000000ULL, "region_configs[0].base mismatch");
	ASSERT_EQ(ret.num_extents_supported, 1024, "num_extents_supported mismatch");
	ASSERT_EQ(ret.num_extents_available, 512, "num_extents_available mismatch");
	ASSERT_EQ(ret.num_tags_supported, 256, "num_tags_supported mismatch");
	ASSERT_EQ(ret.num_tags_available, 128, "num_tags_available mismatch");

	return 0;
}

static int test_response_fmapi_get_ld_allocations(void)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 2;
	rsp->memory_granularity = 8;
	rsp->start_ld_id = 0;
	rsp->ld_allocation_list_len = 2;
	rsp->ld_allocation_list[0].range_1_allocation_mult = cpu_to_le64(0x100);
	rsp->ld_allocation_list[0].range_2_allocation_mult = cpu_to_le64(0x200);
	rsp->ld_allocation_list[1].range_1_allocation_mult = cpu_to_le64(0x150);
	rsp->ld_allocation_list[1].range_2_allocation_mult = cpu_to_le64(0x250);

	req.start_ld_id = 0;
	req.ld_allocation_list_limit = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_ld_allocations(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld mismatch");
	ASSERT_EQ(ret->memory_granularity, 8, "memory_granularity mismatch");
	ASSERT_EQ(ret->ld_allocation_list[0].range_1_allocation_mult, 0x100, "entries[0].range1 mismatch");
	ASSERT_EQ(ret->ld_allocation_list[1].range_1_allocation_mult, 0x150, "entries[1].range1 mismatch");

	return 0;
}

static int test_response_fmapi_get_qos_allocated_bw(void)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 4;
	rsp->start_ld_id = 0;
	rsp->qos_allocation_fraction[0] = 64;
	rsp->qos_allocation_fraction[1] = 64;
	rsp->qos_allocation_fraction[2] = 64;
	rsp->qos_allocation_fraction[3] = 64;

	req.number_ld = 4;
	req.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x06, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_allocated_bw(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 4, "number_ld mismatch");
	ASSERT_EQ(ret->qos_allocation_fraction[0], 64, "fractions[0] mismatch");
	ASSERT_EQ(ret->qos_allocation_fraction[3], 64, "fractions[3] mismatch");

	return 0;
}

static int test_response_fmapi_get_qos_bw_limit(void)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 4];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 4;
	rsp->start_ld_id = 0;
	rsp->qos_limit_fraction[0] = 128;
	rsp->qos_limit_fraction[1] = 128;
	rsp->qos_limit_fraction[2] = 255;
	rsp->qos_limit_fraction[3] = 255;

	req.number_ld = 4;
	req.start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x08, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_qos_bw_limit(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 4, "number_ld mismatch");
	ASSERT_EQ(ret->qos_limit_fraction[0], 128, "limits[0] mismatch");
	ASSERT_EQ(ret->qos_limit_fraction[2], 255, "limits[2] mismatch");

	return 0;
}

static int test_response_get_event_interrupt_policy(void)
{
	struct cxlmi_cmd_get_event_interrupt_policy_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.informational_settings = 0x01;
	rsp.warning_settings = 0x02;
	rsp.failure_settings = 0x04;
	rsp.fatal_settings = 0x08;
#ifndef SUPPORT_CXL_2_0
	rsp.dcd_settings = 0x10;
#endif

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_event_interrupt_policy(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.informational_settings, 0x01, "informational_settings mismatch");
	ASSERT_EQ(ret.warning_settings, 0x02, "warning_settings mismatch");
	ASSERT_EQ(ret.failure_settings, 0x04, "failure_settings mismatch");
	ASSERT_EQ(ret.fatal_settings, 0x08, "fatal_settings mismatch");

	return 0;
}

static int test_response_get_mctp_event_interrupt_policy(void)
{
	struct cxlmi_cmd_get_mctp_event_interrupt_policy_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.event_interrupt_settings = cpu_to_le16(0x1234);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_mctp_event_interrupt_policy(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.event_interrupt_settings, 0x1234, "event_interrupt_settings mismatch");

	return 0;
}

static int test_response_get_log_capabilities(void)
{
	struct cxlmi_cmd_get_log_capabilities_req req = {0};
	struct cxlmi_cmd_get_log_capabilities_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.parameter_flags = cpu_to_le32(0x00000007);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x02, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_log_capabilities(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.parameter_flags, 0x00000007, "parameter_flags mismatch");

	return 0;
}

static int test_response_get_supported_logs_sublist(void)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req req = {0};
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_get_supported_logs_sublist_rsp) +
			2 * sizeof(struct cxlmi_supported_log_entry)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_logs_sublist_rsp) +
			2 * sizeof(struct cxlmi_supported_log_entry)];
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *rsp =
		(struct cxlmi_cmd_get_supported_logs_sublist_rsp *)rsp_buf;
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret =
		(struct cxlmi_cmd_get_supported_logs_sublist_rsp *)ret_buf;
	int rc;

	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->num_supported_log_entries = 2;
	rsp->total_num_supported_log_entries = cpu_to_le16(10);
	rsp->start_log_entry_index = 2;
	/* Set UUIDs for the entries */
	memset(rsp->entries[0].uuid, 0xAA, sizeof(rsp->entries[0].uuid));
	rsp->entries[0].log_size = cpu_to_le32(0x1000);
	memset(rsp->entries[1].uuid, 0xBB, sizeof(rsp->entries[1].uuid));
	rsp->entries[1].log_size = cpu_to_le32(0x2000);

	req.max_supported_log_entries = 5;
	req.start_log_entry_index = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x05, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_supported_logs_sublist(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_log_entries, 2, "num_supported_log_entries mismatch");
	ASSERT_EQ(ret->total_num_supported_log_entries, 10, "total_num_supported_log_entries mismatch");
	ASSERT_EQ(ret->start_log_entry_index, 2, "start_log_entry_index mismatch");
	ASSERT_EQ(ret->entries[0].uuid[0], 0xAA, "entries[0].uuid[0] mismatch");
	ASSERT_EQ(ret->entries[0].log_size, 0x1000, "entries[0].log_size mismatch");
	ASSERT_EQ(ret->entries[1].uuid[0], 0xBB, "entries[1].uuid[0] mismatch");
	ASSERT_EQ(ret->entries[1].log_size, 0x2000, "entries[1].log_size mismatch");

	return 0;
}

static int test_response_get_supported_features(void)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	/* Entry struct is 48 bytes: 16 (feature_id) + 2+2+2+4+1+1+2+18 */
	struct {
		uint16_t num_supported_feature_entries;
		uint16_t device_supported_features;
		uint8_t rsvd[4];
		struct {
			uint8_t feature_id[0x10];
			uint16_t feature_index;
			uint16_t get_feature_size;
			uint16_t set_feature_size;
			uint32_t attribute_flags;
			uint8_t get_feature_version;
			uint8_t set_feature_version;
			uint16_t set_feature_effects;
			uint8_t rsvd[18];
		} __attribute__((packed)) entries[2];
	} __attribute__((packed)) rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_features_rsp) + 96];
	struct cxlmi_cmd_get_supported_features_rsp *ret =
		(struct cxlmi_cmd_get_supported_features_rsp *)ret_buf;
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	rsp.num_supported_feature_entries = cpu_to_le16(2);
	rsp.device_supported_features = cpu_to_le16(8);
	memset(rsp.entries[0].feature_id, 0xAA, sizeof(rsp.entries[0].feature_id));
	rsp.entries[0].feature_index = cpu_to_le16(0);
	rsp.entries[0].get_feature_size = cpu_to_le16(64);
	memset(rsp.entries[1].feature_id, 0xBB, sizeof(rsp.entries[1].feature_id));
	rsp.entries[1].feature_index = cpu_to_le16(1);
	rsp.entries[1].get_feature_size = cpu_to_le16(128);

	req.count = sizeof(rsp);
	req.starting_feature_index = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_feature_entries, 2, "num_supported_feature_entries mismatch");
	ASSERT_EQ(ret->device_supported_features, 8, "device_supported_features mismatch");
	ASSERT_EQ(ret->supported_feature_entries[0].feature_id[0], 0xAA, "entries[0].feature_id mismatch");
	ASSERT_EQ(ret->supported_feature_entries[0].get_feature_size, 64, "entries[0].get_feature_size mismatch");
	ASSERT_EQ(ret->supported_feature_entries[1].feature_id[0], 0xBB, "entries[1].feature_id mismatch");

	return 0;
}

static int test_response_get_feature(void)
{
	struct cxlmi_cmd_get_feature_req req = {0};
	struct cxlmi_cmd_get_feature_rsp rsp = {0}, ret = {0};
	int rc;

	/* Set some feature data */
	rsp.feature_data[0] = 0xAA;
	rsp.feature_data[1] = 0xBB;
	rsp.feature_data[2] = 0xCC;

	req.count = 64;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_get_feature(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.feature_data[0], 0xAA, "feature_data[0] mismatch");
	ASSERT_EQ(ret.feature_data[1], 0xBB, "feature_data[1] mismatch");
	ASSERT_EQ(ret.feature_data[2], 0xCC, "feature_data[2] mismatch");

	return 0;
}

static int test_response_memdev_get_dc_extent_list(void)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.num_extents_returned = cpu_to_le32(0);
	rsp.total_num_extents = cpu_to_le32(10);
	rsp.generation_num = cpu_to_le32(5);

	req.extent_cnt = 8;
	req.start_extent_idx = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_extents_returned, 0, "num_extents_returned mismatch");
	ASSERT_EQ(ret.total_num_extents, 10, "total_num_extents mismatch");
	ASSERT_EQ(ret.generation_num, 5, "generation_num mismatch");

	return 0;
}

static int test_response_fmapi_get_phys_port_state(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_req) + 2];
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_port_state_info_block)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_port_state_info_block)];
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_req *)req_buf;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->num_ports = 2;
	rsp->ports[0].port_id = 1;
	rsp->ports[0].config_state = 0x04;
	rsp->ports[0].current_link_speed = 5;
	rsp->ports[1].port_id = 2;
	rsp->ports[1].config_state = 0x04;
	rsp->ports[1].current_link_speed = 4;

	req->num_ports = 2;
	req->ports[0] = 1;
	req->ports[1] = 2;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_phys_port_state(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_ports, 2, "num_ports mismatch");
	ASSERT_EQ(ret->ports[0].port_id, 1, "ports[0].port_id mismatch");
	ASSERT_EQ(ret->ports[0].current_link_speed, 5, "ports[0].current_link_speed mismatch");
	ASSERT_EQ(ret->ports[1].port_id, 2, "ports[1].port_id mismatch");

	return 0;
}

static int test_response_fmapi_get_dcd_info(void)
{
	struct cxlmi_cmd_fmapi_get_dcd_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.num_hosts = 4;
	rsp.num_supported_dc_regions = 8;
	rsp.capacity_selection_policies = cpu_to_le16(0x0007);
	rsp.capacity_removal_policies = cpu_to_le16(0x0003);
	/* Library multiplies by 256MB, so set raw value as 4 -> 4*256MB = 1GB */
	rsp.total_dynamic_capacity = cpu_to_le64(4);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dcd_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_hosts, 4, "num_hosts mismatch");
	ASSERT_EQ(ret.num_supported_dc_regions, 8, "num_supported_dc_regions mismatch");
	ASSERT_EQ(ret.capacity_selection_policies, 0x0007, "capacity_selection_policies mismatch");
	/* 4 * 256MB = 1GB = 0x40000000 */
	ASSERT_TRUE(ret.total_dynamic_capacity == 0x40000000ULL, "total_dynamic_capacity mismatch");

	return 0;
}

static int test_response_fmapi_get_multiheaded_info(void)
{
	struct cxlmi_cmd_fmapi_get_multiheaded_info_req req = {0};
	struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.num_lds = 4;
	rsp.num_heads = 2;
	rsp.start_ld_id = 0;
	rsp.ld_map_len = 0;

	req.start_ld_id = 0;
	req.ld_map_list_limit = 4;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x00, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_multiheaded_info(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_lds, 4, "num_lds mismatch");
	ASSERT_EQ(ret.num_heads, 2, "num_heads mismatch");

	return 0;
}

static int test_response_fmapi_get_head_info(void)
{
	struct cxlmi_cmd_fmapi_get_head_info_req req = {0};
	/*
	 * Wire format: 4-byte header + 9 bytes per head entry.
	 * Request 2 heads.
	 */
	uint8_t rsp_buf[4 + 2 * 9] = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_head_info_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_get_head_info_blkfmt)];
	struct cxlmi_cmd_fmapi_get_head_info_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_head_info_rsp *)ret_buf;
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	req.start_head = 0;
	req.num_heads = 2;

	/* Header: num_heads(1) + rsvd(3) */
	rsp_buf[0] = 2; /* num_heads */

	/* Head 0 at offset 4 */
	rsp_buf[4] = 1;    /* port_num */
	rsp_buf[5] = 0x10; /* field_1 (max link width) */
	rsp_buf[6] = 0x08; /* field_2 (negotiated link width) */
	rsp_buf[7] = 0x1F; /* field_3 (supported link speed vector) */
	rsp_buf[8] = 0x04; /* field_4 (max link speed) */
	rsp_buf[9] = 0x03; /* field_5 (current link speed) */
	rsp_buf[10] = 0x10; /* ltssm_state */
	rsp_buf[11] = 0;   /* first_negotiated_lane_num */
	rsp_buf[12] = 0x01; /* link_state_flags */

	/* Head 1 at offset 13 */
	rsp_buf[13] = 2;    /* port_num */
	rsp_buf[14] = 0x10; /* field_1 */
	rsp_buf[15] = 0x08; /* field_2 */
	rsp_buf[16] = 0x1F; /* field_3 */
	rsp_buf[17] = 0x04; /* field_4 */
	rsp_buf[18] = 0x03; /* field_5 */
	rsp_buf[19] = 0x10; /* ltssm_state */
	rsp_buf[20] = 0;    /* first_negotiated_lane_num */
	rsp_buf[21] = 0x01; /* link_state_flags */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x55, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_head_info(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_heads, 2, "num_heads mismatch");
	ASSERT_EQ(ret->head_info_list[0].port_num, 1, "head[0].port_num mismatch");
	ASSERT_EQ(ret->head_info_list[0].ltssm_state, 0x10, "head[0].ltssm_state mismatch");
	ASSERT_EQ(ret->head_info_list[0].link_state_flags, 0x01, "head[0].link_state_flags mismatch");
	ASSERT_EQ(ret->head_info_list[1].port_num, 2, "head[1].port_num mismatch");
	ASSERT_EQ(ret->head_info_list[1].field_5, 0x03, "head[1].field_5 mismatch");

	return 0;
}

/* Helper to write little-endian values to potentially unaligned buffer */
static void write_le16(uint8_t *p, uint16_t v)
{
	leint16_t le = cpu_to_le16(v);
	memcpy(p, &le, sizeof(le));
}

static void write_le32(uint8_t *p, uint32_t v)
{
	leint32_t le = cpu_to_le32(v);
	memcpy(p, &le, sizeof(le));
}

static void write_le64(uint8_t *p, uint64_t v)
{
	leint64_t le = cpu_to_le64(v);
	memcpy(p, &le, sizeof(le));
}

static int test_response_fmapi_get_dc_reg_config(void)
{
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp ret = {0};
	/*
	 * The wire format has the extents/tags fields immediately after the
	 * returned region_configs, not at a fixed offset. Build a buffer with
	 * 2 regions followed by the 4 uint32 fields.
	 * Region config: base(8) + decode_len(8) + region_len(8) + block_size(8) +
	 *                flags(1) + rsvd(3) + sanitize(1) + rsvd2(3) = 40 bytes
	 */
	uint8_t rsp_buf[4 + 2*40 + 16] = {0}; /* hdr + 2 regions + 4 u32s */
	uint8_t *p = rsp_buf;
	int rc;

	/* Header: host_id(2), num_regions(1), regions_returned(1) */
	write_le16(p, 1); p += 2; /* host_id */
	*p++ = 2; /* num_regions */
	*p++ = 2; /* regions_returned */

	/* Region config 0 */
	write_le64(p, 0x100000000ULL); p += 8; /* base */
	write_le64(p, 0x80000000ULL); p += 8;  /* decode_len */
	write_le64(p, 0x80000000ULL); p += 8;  /* region_len */
	write_le64(p, 0x40); p += 8;           /* block_size */
	*p++ = 0; p += 3;                       /* flags + rsvd */
	*p++ = 0; p += 3;                       /* sanitize + rsvd2 */

	/* Region config 1 */
	write_le64(p, 0x200000000ULL); p += 8; /* base */
	write_le64(p, 0x40000000ULL); p += 8;  /* decode_len */
	write_le64(p, 0x40000000ULL); p += 8;  /* region_len */
	write_le64(p, 0x80); p += 8;           /* block_size */
	*p++ = 0; p += 3;                       /* flags + rsvd */
	*p++ = 0; p += 3;                       /* sanitize + rsvd2 */

	/* Extents/tags fields immediately after 2 regions */
	write_le32(p, 512); p += 4;  /* num_extents_supported */
	write_le32(p, 256); p += 4;  /* num_extents_available */
	write_le32(p, 128); p += 4;  /* num_tags_supported */
	write_le32(p, 64);           /* num_tags_available */

	req.host_id = 1;
	req.region_cnt = 8;
	req.start_region_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_get_dc_reg_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.host_id, 1, "host_id mismatch");
	ASSERT_EQ(ret.num_regions, 2, "num_regions mismatch");
	ASSERT_EQ(ret.num_extents_supported, 512, "num_extents_supported mismatch");
	ASSERT_EQ(ret.num_extents_available, 256, "num_extents_available mismatch");

	return 0;
}

static int test_response_fmapi_get_dc_region_ext_list(void)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.host_id = cpu_to_le16(1);
	rsp.start_ext_index = cpu_to_le32(0);
	rsp.extents_returned = cpu_to_le32(0);
	rsp.total_extents = cpu_to_le32(10);
	rsp.list_generation_num = cpu_to_le32(5);

	req.host_id = 1;
	req.extent_count = 8;
	req.start_ext_index = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.host_id, 1, "host_id mismatch");
	ASSERT_EQ(ret.total_extents, 10, "total_extents mismatch");
	ASSERT_EQ(ret.list_generation_num, 5, "list_generation_num mismatch");

	return 0;
}

static int test_response_fmapi_dc_list_tags(void)
{
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.generation_num = cpu_to_le32(10);
	rsp.total_num_tags = cpu_to_le32(5);
	rsp.num_tags_returned = cpu_to_le32(0);
	rsp.validity_bitmap = 0x1F;

	req.start_idx = 0;
	req.tags_count = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x08, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_dc_list_tags(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.generation_num, 10, "generation_num mismatch");
	ASSERT_EQ(ret.total_num_tags, 5, "total_num_tags mismatch");
	ASSERT_EQ(ret.validity_bitmap, 0x1F, "validity_bitmap mismatch");

	return 0;
}

static int test_response_memdev_media_operations_discovery(void)
{
	struct cxlmi_cmd_memdev_media_operations_discovery_req req = {0};
	/*
	 * Wire format buffer: header (12 bytes) + 2 entries (2 bytes each).
	 * The flexible array member entry[] starts at offset 12.
	 */
	uint8_t rsp_buf[12 + 4] = {0};
	uint8_t *p = rsp_buf;
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_memdev_media_operations_discovery_rsp) +
			2 * sizeof(struct cxlmi_cmd_memdev_media_ops_supported_list_entry)];
	struct cxlmi_cmd_memdev_media_operations_discovery_rsp *ret =
		(struct cxlmi_cmd_memdev_media_operations_discovery_rsp *)ret_buf;
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	/* Request 2 entries */
	req.discovery_osa.num_ops = 2;

	/* Header */
	*(leint64_t *)p = cpu_to_le64(0x10000); p += 8; /* dpa_range_granularity */
	*(leint16_t *)p = cpu_to_le16(4); p += 2;       /* total_supported_ops */
	*(leint16_t *)p = cpu_to_le16(2); p += 2;       /* num_supported_ops */

	/* Entries immediately after header */
	*p++ = 0x01; /* entry[0].media_op_class */
	*p++ = 0x02; /* entry[0].media_op_subclass */
	*p++ = 0x03; /* entry[1].media_op_class */
	*p++ = 0x04; /* entry[1].media_op_subclass */

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x44, 0x02, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_memdev_media_operations_discovery(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->dpa_range_granularity, 0x10000, "dpa_range_granularity mismatch");
	ASSERT_EQ(ret->total_supported_ops, 4, "total_supported_ops mismatch");
	ASSERT_EQ(ret->num_supported_ops, 2, "num_supported_ops mismatch");
	ASSERT_EQ(ret->entry[0].media_op_class, 0x01, "entry[0].media_op_class mismatch");
	ASSERT_EQ(ret->entry[1].media_op_subclass, 0x04, "entry[1].media_op_subclass mismatch");

	return 0;
}

static int test_response_fmapi_get_domain_validation_sv_state(void)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_state_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.secret_value_state = 0x02;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_domain_validation_sv_state(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_state, 0x02, "secret_value_state mismatch");

	return 0;
}

static int test_response_fmapi_get_vcs_domain_validation_sv_state(void)
{
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req req = {0};
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.secret_value_state = 0x01;
	req.vcs_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x06, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_state, 0x01, "secret_value_state mismatch");

	return 0;
}

static int test_response_fmapi_get_domain_validation_sv(void)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_req req = {0};
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp rsp = {0}, ret = {0};
	int rc;

	memset(rsp.secret_value_uuid, 0xAB, sizeof(rsp.secret_value_uuid));
	req.vcs_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x07, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_get_domain_validation_sv(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.secret_value_uuid[0], 0xAB, "secret_value_uuid[0] mismatch");
	ASSERT_EQ(ret.secret_value_uuid[15], 0xAB, "secret_value_uuid[15] mismatch");

	return 0;
}

static int test_response_fmapi_send_ppb_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.return_data = cpu_to_le32(0x12345678);
	req.ppb_id = 1;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x51, 0x03, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ppb_cxlio_config_request(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.return_data, 0x12345678, "return_data mismatch");

	return 0;
}

static int test_response_fmapi_send_ld_cxlio_config_request(void)
{
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req req = {0};
	struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.return_data = cpu_to_le32(0xDEADBEEF);
	req.ppb_id = 1;
	req.ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x01, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_config_request(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.return_data, 0xDEADBEEF, "return_data mismatch");

	return 0;
}

static int test_response_fmapi_send_ld_cxlio_mem_request(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req) + 8];
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp) + 8];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp) + 8];
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req *req =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req *)req_buf;
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *rsp =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *ret =
		(struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->return_size = cpu_to_le16(8);
	memset(rsp->return_data, 0x55, 8);

	req->port_id = 1;
	req->ld_id = 0;
	req->transaction_len = 8;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x53, 0x02, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_send_ld_cxlio_mem_request(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->return_size, 8, "return_size mismatch");
	ASSERT_EQ(ret->return_data[0], 0x55, "return_data[0] mismatch");

	return 0;
}

static int test_response_fmapi_set_ld_allocations(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_req) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *req =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_req *)req_buf;
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 2;
	rsp->start_ld_id = 0;
	rsp->ld_allocation_list[0].range_1_allocation_mult = cpu_to_le64(0x100);

	req->number_ld = 2;
	req->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x02, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_ld_allocations(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld mismatch");
	ASSERT_EQ(ret->ld_allocation_list[0].range_1_allocation_mult, 0x100, "entries[0].range_1 mismatch");

	return 0;
}

static int test_response_fmapi_set_qos_control(void)
{
	struct cxlmi_cmd_fmapi_set_qos_control_req req = {0};
	struct cxlmi_cmd_fmapi_set_qos_control_rsp rsp = {0}, ret = {0};
	int rc;

	rsp.qos_telemetry_control = 0x03;
	rsp.egress_moderate_percentage = 45;
	rsp.egress_severe_percentage = 75;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x04, CXLMI_RET_SUCCESS,
				&rsp, sizeof(rsp));
	rc = cxlmi_cmd_fmapi_set_qos_control(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.qos_telemetry_control, 0x03, "qos_telemetry_control mismatch");
	ASSERT_EQ(ret.egress_moderate_percentage, 45, "egress_moderate_percentage mismatch");
	ASSERT_EQ(ret.egress_severe_percentage, 75, "egress_severe_percentage mismatch");

	return 0;
}

static int test_response_fmapi_set_qos_allocated_bw(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req) + 4];
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_req *)req_buf;
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_allocated_bw_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 4;
	rsp->start_ld_id = 0;
	rsp->qos_allocation_fraction[0] = 64;
	rsp->qos_allocation_fraction[1] = 64;

	req->number_ld = 4;
	req->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x07, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_allocated_bw(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 4, "number_ld mismatch");
	ASSERT_EQ(ret->qos_allocation_fraction[0], 64, "fractions[0] mismatch");

	return 0;
}

static int test_response_fmapi_set_qos_bw_limit(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req) + 4];
	uint8_t rsp_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 4];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp) + 4];
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *req =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_req *)req_buf;
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *rsp =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)rsp_buf;
	struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_qos_bw_limit_rsp *)ret_buf;
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(rsp_buf, 0, sizeof(rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	rsp->number_ld = 4;
	rsp->start_ld_id = 0;
	rsp->qos_limit_fraction[0] = 128;
	rsp->qos_limit_fraction[1] = 255;

	req->number_ld = 4;
	req->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x09, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_fmapi_set_qos_bw_limit(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 4, "number_ld mismatch");
	ASSERT_EQ(ret->qos_limit_fraction[0], 128, "limits[0] mismatch");
	ASSERT_EQ(ret->qos_limit_fraction[1], 255, "limits[1] mismatch");

	return 0;
}

static int test_response_get_log_cel(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	/*
	 * Wire format: array of 4-byte entries (opcode le16, command_effect le16).
	 * Request 2 entries.
	 */
	uint8_t rsp_buf[8] = {0};
	struct cxlmi_cmd_get_log_cel_rsp ret[2] = {0};
	int rc;

	/* Entry 0: opcode=0x0001 (Identify), command_effect=0x0010 */
	rsp_buf[0] = 0x01; rsp_buf[1] = 0x00; /* opcode LE */
	rsp_buf[2] = 0x10; rsp_buf[3] = 0x00; /* command_effect LE */
	/* Entry 1: opcode=0x0401 (Get Log), command_effect=0x0020 */
	rsp_buf[4] = 0x01; rsp_buf[5] = 0x04; /* opcode LE */
	rsp_buf[6] = 0x20; rsp_buf[7] = 0x00; /* command_effect LE */

	req.length = sizeof(rsp_buf);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_log_cel(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret[0].opcode, 0x0001, "entry[0].opcode mismatch");
	ASSERT_EQ(ret[0].command_effect, 0x0010, "entry[0].command_effect mismatch");
	ASSERT_EQ(ret[1].opcode, 0x0401, "entry[1].opcode mismatch");
	ASSERT_EQ(ret[1].command_effect, 0x0020, "entry[1].command_effect mismatch");

	return 0;
}

/* ============================================================
 * Endianness Verification Tests
 *
 * These tests use byte patterns where byte order matters (high byte != low byte).
 * Values like 0xAABB will become 0xBBAA if endianness is wrong.
 * ============================================================ */

/*
 * Test 16-bit response field endianness using identify command.
 * Wire format uses little-endian; library converts to host.
 */
static int test_endian_identify_16bit(void)
{
	/*
	 * Build wire-format response with explicit LE byte order.
	 * vendor_id: 0xBEEF -> wire bytes: EF BE
	 * device_id: 0xCAFE -> wire bytes: FE CA
	 * subsys_vendor_id: 0xDEAD -> wire bytes: AD DE
	 * subsys_id: 0xF00D -> wire bytes: 0D F0
	 */
	uint8_t wire_rsp[18] = {
		0xEF, 0xBE,             /* vendor_id LE */
		0xFE, 0xCA,             /* device_id LE */
		0xAD, 0xDE,             /* subsys_vendor_id LE */
		0x0D, 0xF0,             /* subsys_id LE */
		0x78, 0x56, 0x34, 0x12, /* serial_num LE (low 32) */
		0xF0, 0xDE, 0xBC, 0x9A, /* serial_num LE (high 32) */
		0x09,                   /* max_msg_size */
		0x03,                   /* component_type */
	};
	struct cxlmi_cmd_identify_rsp ret = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.vendor_id, 0xBEEF, "vendor_id endianness wrong");
	ASSERT_EQ(ret.device_id, 0xCAFE, "device_id endianness wrong");
	ASSERT_EQ(ret.subsys_vendor_id, 0xDEAD, "subsys_vendor_id endianness wrong");
	ASSERT_EQ(ret.subsys_id, 0xF00D, "subsys_id endianness wrong");

	return 0;
}

/*
 * Test 64-bit response field endianness using identify command.
 * serial_num should be 0x9ABCDEF012345678 (host order).
 */
static int test_endian_identify_64bit(void)
{
	uint8_t wire_rsp[18] = {
		0x00, 0x00,             /* vendor_id */
		0x00, 0x00,             /* device_id */
		0x00, 0x00,             /* subsys_vendor_id */
		0x00, 0x00,             /* subsys_id */
		/* serial_num: 0x9ABCDEF012345678 in LE wire format */
		0x78, 0x56, 0x34, 0x12, /* low 32 bits */
		0xF0, 0xDE, 0xBC, 0x9A, /* high 32 bits */
		0x00,                   /* max_msg_size */
		0x00,                   /* component_type */
	};
	struct cxlmi_cmd_identify_rsp ret = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x01, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.serial_num == 0x9ABCDEF012345678ULL,
		    "serial_num endianness wrong");

	return 0;
}

/*
 * Test 64-bit request field endianness using set_timestamp command.
 * Verify the wire format has correct LE byte order.
 */
static int test_endian_set_timestamp_request(void)
{
	struct cxlmi_cmd_set_timestamp_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/* Host value: 0xFEDCBA9876543210 */
	req.timestamp = 0xFEDCBA9876543210ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_set_timestamp(test_ep, NULL, &req);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(payload_size, 8, "payload size wrong");
	/* Verify LE wire format: LSB first */
	ASSERT_EQ(payload[0], 0x10, "timestamp byte 0 wrong");
	ASSERT_EQ(payload[1], 0x32, "timestamp byte 1 wrong");
	ASSERT_EQ(payload[2], 0x54, "timestamp byte 2 wrong");
	ASSERT_EQ(payload[3], 0x76, "timestamp byte 3 wrong");
	ASSERT_EQ(payload[4], 0x98, "timestamp byte 4 wrong");
	ASSERT_EQ(payload[5], 0xBA, "timestamp byte 5 wrong");
	ASSERT_EQ(payload[6], 0xDC, "timestamp byte 6 wrong");
	ASSERT_EQ(payload[7], 0xFE, "timestamp byte 7 wrong");

	return 0;
}

/*
 * Test 64-bit response field endianness using get_timestamp command.
 */
static int test_endian_get_timestamp_response(void)
{
	/* Wire format: 0x0102030405060708 in LE */
	uint8_t wire_rsp[8] = {
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
	};
	struct cxlmi_cmd_get_timestamp_rsp ret = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x03, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_timestamp(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret.timestamp == 0x0102030405060708ULL,
		    "timestamp endianness wrong");

	return 0;
}

/*
 * Test 32-bit request field endianness using get_log command.
 */
static int test_endian_get_log_request(void)
{
	struct cxlmi_cmd_get_log_req req = {0};
	uint8_t rsp_buf[32] = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/*
	 * Use values with distinct bytes to detect swapping.
	 * Keep length small (32) since library allocates that many bytes.
	 * offset: 0xAABBCCDD (verifies 32-bit LE encoding)
	 * length: 32 (0x00000020) - small but functional
	 */
	req.offset = 0xAABBCCDD;
	req.length = 32;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				rsp_buf, sizeof(rsp_buf));
	rc = cxlmi_cmd_get_log(test_ep, NULL, &req, rsp_buf);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	/* Request payload: uuid[16] + offset[4] + length[4] */
	ASSERT_TRUE(payload_size >= 24, "payload too small");
	/* offset at byte 16, LE format: 0xAABBCCDD -> DD CC BB AA */
	ASSERT_EQ(payload[16], 0xDD, "offset byte 0 wrong");
	ASSERT_EQ(payload[17], 0xCC, "offset byte 1 wrong");
	ASSERT_EQ(payload[18], 0xBB, "offset byte 2 wrong");
	ASSERT_EQ(payload[19], 0xAA, "offset byte 3 wrong");
	/* length at byte 20, LE format: 32 = 0x00000020 -> 20 00 00 00 */
	ASSERT_EQ(payload[20], 0x20, "length byte 0 wrong");
	ASSERT_EQ(payload[21], 0x00, "length byte 1 wrong");
	ASSERT_EQ(payload[22], 0x00, "length byte 2 wrong");
	ASSERT_EQ(payload[23], 0x00, "length byte 3 wrong");

	return 0;
}

/*
 * Test memdev_identify 64-bit capacity fields.
 * Library does le64_to_cpu conversion (no multiplier applied).
 */
static int test_endian_memdev_identify_capacity(void)
{
	/*
	 * Build wire response for memdev_identify.
	 * Struct layout:
	 *   char fw_revision[16]   - offset 0
	 *   uint64_t total_capacity - offset 16
	 *   uint64_t volatile_capacity - offset 24
	 */
	uint8_t wire_rsp[80] = {0};
	struct cxlmi_cmd_memdev_identify_rsp ret = {0};
	int rc;

	/* total_capacity at offset 16: 0x123456789ABCDEF0 in LE */
	wire_rsp[16] = 0xF0; wire_rsp[17] = 0xDE;
	wire_rsp[18] = 0xBC; wire_rsp[19] = 0x9A;
	wire_rsp[20] = 0x78; wire_rsp[21] = 0x56;
	wire_rsp[22] = 0x34; wire_rsp[23] = 0x12;

	/* volatile_capacity at offset 24: 0xFEDCBA9876543210 in LE */
	wire_rsp[24] = 0x10; wire_rsp[25] = 0x32;
	wire_rsp[26] = 0x54; wire_rsp[27] = 0x76;
	wire_rsp[28] = 0x98; wire_rsp[29] = 0xBA;
	wire_rsp[30] = 0xDC; wire_rsp[31] = 0xFE;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x40, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_identify(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Library does le64_to_cpu, no multiplier */
	ASSERT_TRUE(ret.total_capacity == 0x123456789ABCDEF0ULL,
		    "total_capacity endianness/multiplier wrong");
	ASSERT_TRUE(ret.volatile_capacity == 0xFEDCBA9876543210ULL,
		    "volatile_capacity endianness/multiplier wrong");

	return 0;
}

/*
 * Test bg_op_status 16-bit fields.
 */
static int test_endian_bg_op_status(void)
{
	/* Wire format for bg_op_status response */
	uint8_t wire_rsp[8] = {
		0x01,             /* status */
		0x00,             /* rsvd */
		0xCD, 0xAB,       /* opcode: 0xABCD in LE */
		0x34, 0x12,       /* returncode: 0x1234 in LE */
		0x78, 0x56,       /* vendor_ext_status: 0x5678 in LE */
	};
	struct cxlmi_cmd_bg_op_status_rsp ret = {0};
	int rc;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x00, 0x02, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_bg_op_status(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.status, 0x01, "status mismatch");
	ASSERT_EQ(ret.opcode, 0xABCD, "opcode endianness wrong");
	ASSERT_EQ(ret.returncode, 0x1234, "returncode endianness wrong");
	ASSERT_EQ(ret.vendor_ext_status, 0x5678, "vendor_ext_status endianness wrong");

	return 0;
}

/*
 * Test event_records response with overflow timestamps (64-bit).
 */
static int test_endian_event_records_timestamps(void)
{
	struct cxlmi_cmd_get_event_records_req req = {0};
	/*
	 * Wire format: flags, rsvd, overflow_err_count, timestamps, record_count
	 * Minimal header without records.
	 */
	uint8_t wire_rsp[32] = {0};
	struct cxlmi_cmd_get_event_records_rsp ret = {0};
	int rc;

	/* overflow_err_count at offset 2: 0xBEEF in LE */
	wire_rsp[2] = 0xEF; wire_rsp[3] = 0xBE;

	/* first_overflow_timestamp at offset 4: 0x0102030405060708 in LE */
	wire_rsp[4] = 0x08; wire_rsp[5] = 0x07;
	wire_rsp[6] = 0x06; wire_rsp[7] = 0x05;
	wire_rsp[8] = 0x04; wire_rsp[9] = 0x03;
	wire_rsp[10] = 0x02; wire_rsp[11] = 0x01;

	/* last_overflow_timestamp at offset 12: 0xFEDCBA9876543210 in LE */
	wire_rsp[12] = 0x10; wire_rsp[13] = 0x32;
	wire_rsp[14] = 0x54; wire_rsp[15] = 0x76;
	wire_rsp[16] = 0x98; wire_rsp[17] = 0xBA;
	wire_rsp[18] = 0xDC; wire_rsp[19] = 0xFE;

	/* record_count at offset 20: 0 (no records) */
	wire_rsp[20] = 0x00; wire_rsp[21] = 0x00;

	req.event_log = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.overflow_err_count, 0xBEEF, "overflow_err_count endianness wrong");
	ASSERT_TRUE(ret.first_overflow_timestamp == 0x0102030405060708ULL,
		    "first_overflow_timestamp endianness wrong");
	ASSERT_TRUE(ret.last_overflow_timestamp == 0xFEDCBA9876543210ULL,
		    "last_overflow_timestamp endianness wrong");

	return 0;
}

/*
 * Test inject_poison request (64-bit address field).
 */
static int test_endian_inject_poison_request(void)
{
	struct cxlmi_cmd_memdev_inject_poison_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/* Physical address with distinct bytes */
	req.inject_poison_phy_addr = 0xFEDCBA9876543210ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x01, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_inject_poison(test_ep, NULL, &req);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	ASSERT_EQ(payload_size, 8, "payload size wrong");
	/* Verify LE wire format */
	ASSERT_EQ(payload[0], 0x10, "addr byte 0 wrong");
	ASSERT_EQ(payload[1], 0x32, "addr byte 1 wrong");
	ASSERT_EQ(payload[2], 0x54, "addr byte 2 wrong");
	ASSERT_EQ(payload[3], 0x76, "addr byte 3 wrong");
	ASSERT_EQ(payload[4], 0x98, "addr byte 4 wrong");
	ASSERT_EQ(payload[5], 0xBA, "addr byte 5 wrong");
	ASSERT_EQ(payload[6], 0xDC, "addr byte 6 wrong");
	ASSERT_EQ(payload[7], 0xFE, "addr byte 7 wrong");

	return 0;
}

/*
 * Test get_supported_logs response (32-bit log_size fields).
 */
static int test_endian_supported_logs_size(void)
{
	/*
	 * Wire format: num_supported_log_entries (le16), rsvd[6], entries[]
	 * Each entry: uuid[16], log_size (le32)
	 */
	uint8_t wire_rsp[8 + 20] = {0}; /* header + 1 entry */
	struct cxlmi_cmd_get_supported_logs_rsp *ret;
	size_t ret_sz;
	int rc, result = 1;

	/* num_supported_log_entries: 1 */
	wire_rsp[0] = 0x01; wire_rsp[1] = 0x00;
	/* entry 0: uuid (all zeros) + log_size: 0xAABBCCDD in LE */
	wire_rsp[8 + 16] = 0xDD;
	wire_rsp[8 + 17] = 0xCC;
	wire_rsp[8 + 18] = 0xBB;
	wire_rsp[8 + 19] = 0xAA;

	ret_sz = sizeof(*ret) + sizeof(ret->entries[0]);
	ret = calloc(1, ret_sz);
	if (!ret) {
		fprintf(stderr, "\n    ASSERT FAILED: alloc failed\n");
		return 1;
	}

	if (setup() != 0) {
		fprintf(stderr, "\n    ASSERT FAILED: setup failed\n");
		goto cleanup;
	}
	cxlmi_mock_set_response(test_ep, 0x04, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_supported_logs(test_ep, NULL, ret);
	teardown();

	if (rc != CXLMI_RET_SUCCESS) {
		fprintf(stderr, "\n    ASSERT FAILED: command failed (got %d, expected %d)\n",
			rc, CXLMI_RET_SUCCESS);
		goto cleanup;
	}
	if (ret->num_supported_log_entries != 1) {
		fprintf(stderr, "\n    ASSERT FAILED: num entries wrong\n");
		goto cleanup;
	}
	if (ret->entries[0].log_size != 0xAABBCCDD) {
		fprintf(stderr, "\n    ASSERT FAILED: log_size endianness wrong\n");
		goto cleanup;
	}

	result = 0;
cleanup:
	free(ret);
	return result;
}

/*
 * Test round-trip: host -> wire -> host for 16/32/64 bit values.
 * Uses set_feature request and verifies wire format.
 */
static int test_endian_set_feature_request(void)
{
	struct cxlmi_cmd_set_feature_req req = {0};
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	/* set_feature_flags: 0xAABBCCDD (32-bit) */
	req.set_feature_flags = 0xAABBCCDD;
	/* offset: 0x1234 (16-bit) */
	req.offset = 0x1234;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	/* set_feature takes feature_data_sz as 4th param */
	rc = cxlmi_cmd_set_feature(test_ep, NULL, &req, 0);
	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	cxlmi_mock_get_last_command(test_ep, NULL, NULL, payload, &payload_size);
	teardown();

	/*
	 * set_feature request layout:
	 * uuid[16] + set_feature_flags[4] + offset[2] + ...
	 */
	ASSERT_TRUE(payload_size >= 22, "payload too small");

	/* set_feature_flags at offset 16, LE format */
	ASSERT_EQ(payload[16], 0xDD, "flags byte 0 wrong");
	ASSERT_EQ(payload[17], 0xCC, "flags byte 1 wrong");
	ASSERT_EQ(payload[18], 0xBB, "flags byte 2 wrong");
	ASSERT_EQ(payload[19], 0xAA, "flags byte 3 wrong");

	/* offset at offset 20, LE format */
	ASSERT_EQ(payload[20], 0x34, "offset byte 0 wrong");
	ASSERT_EQ(payload[21], 0x12, "offset byte 1 wrong");

	return 0;
}

/*
 * Test get_partition_info response (64-bit fields).
 */
static int test_endian_partition_info(void)
{
	/*
	 * Wire format: active_vmem[8], active_pmem[8], next_vmem[8], next_pmem[8]
	 * Library does le64_to_cpu conversion (no multiplier applied).
	 */
	uint8_t wire_rsp[32] = {0};
	struct cxlmi_cmd_memdev_get_partition_info_rsp ret = {0};
	int rc;

	/* active_vmem: 0x123456789ABCDEF0 in LE */
	wire_rsp[0] = 0xF0; wire_rsp[1] = 0xDE;
	wire_rsp[2] = 0xBC; wire_rsp[3] = 0x9A;
	wire_rsp[4] = 0x78; wire_rsp[5] = 0x56;
	wire_rsp[6] = 0x34; wire_rsp[7] = 0x12;

	/* active_pmem: 0xFEDCBA9876543210 in LE */
	wire_rsp[8] = 0x10; wire_rsp[9] = 0x32;
	wire_rsp[10] = 0x54; wire_rsp[11] = 0x76;
	wire_rsp[12] = 0x98; wire_rsp[13] = 0xBA;
	wire_rsp[14] = 0xDC; wire_rsp[15] = 0xFE;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x41, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_partition_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	/* Library does le64_to_cpu, no multiplier */
	ASSERT_TRUE(ret.active_vmem == 0x123456789ABCDEF0ULL,
		    "active_vmem endianness/multiplier wrong");
	ASSERT_TRUE(ret.active_pmem == 0xFEDCBA9876543210ULL,
		    "active_pmem endianness/multiplier wrong");

	return 0;
}

/*
 * Test health_info response with mixed field sizes.
 */
static int test_endian_health_info(void)
{
	/*
	 * health_info has various field sizes:
	 * - health_status: 1 byte
	 * - media_status: 1 byte
	 * - additional_status: 1 byte
	 * - life_used: 1 byte
	 * - device_temperature: 2 bytes (offset 4)
	 * - dirty_shutdown_count: 4 bytes (offset 6)
	 * - corrected_volatile_error_count: 4 bytes (offset 10)
	 * - corrected_persistent_error_count: 4 bytes (offset 14)
	 */
	uint8_t wire_rsp[18] = {0};
	struct cxlmi_cmd_memdev_get_health_info_rsp ret = {0};
	int rc;

	wire_rsp[0] = 0x01; /* health_status */
	wire_rsp[1] = 0x02; /* media_status */
	wire_rsp[2] = 0x03; /* additional_status */
	wire_rsp[3] = 0x50; /* life_used */

	/* device_temperature: 0xBEEF in LE */
	wire_rsp[4] = 0xEF; wire_rsp[5] = 0xBE;

	/* dirty_shutdown_count: 0xCAFEBABE in LE */
	wire_rsp[6] = 0xBE; wire_rsp[7] = 0xBA;
	wire_rsp[8] = 0xFE; wire_rsp[9] = 0xCA;

	/* corrected_volatile_error_count: 0xDEADBEEF in LE */
	wire_rsp[10] = 0xEF; wire_rsp[11] = 0xBE;
	wire_rsp[12] = 0xAD; wire_rsp[13] = 0xDE;

	/* corrected_persistent_error_count: 0x12345678 in LE */
	wire_rsp[14] = 0x78; wire_rsp[15] = 0x56;
	wire_rsp[16] = 0x34; wire_rsp[17] = 0x12;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_health_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.health_status, 0x01, "health_status wrong");
	ASSERT_EQ(ret.device_temperature, 0xBEEF, "device_temperature endianness wrong");
	ASSERT_EQ(ret.dirty_shutdown_count, 0xCAFEBABE, "dirty_shutdown_count endianness wrong");
	ASSERT_EQ(ret.corrected_volatile_error_count, 0xDEADBEEF, "corrected_volatile_error_count endianness wrong");
	ASSERT_EQ(ret.corrected_persistent_error_count, 0x12345678, "corrected_persistent_error_count endianness wrong");

	return 0;
}

/*
 * Test get_alert_config response (16-bit temperature thresholds).
 * Struct layout:
 *   uint8_t valid_alerts                                       - offset 0
 *   uint8_t programmable_alerts                                - offset 1
 *   uint8_t life_used_critical_alert_threshold                 - offset 2
 *   uint8_t life_used_programmable_warning_threshold           - offset 3
 *   uint16_t device_over_temperature_critical_alert_threshold  - offset 4
 *   uint16_t device_under_temperature_critical_alert_threshold - offset 6
 *   uint16_t device_over_temperature_programmable_warning_threshold  - offset 8
 *   uint16_t device_under_temperature_programmable_warning_threshold - offset 10
 *   uint16_t corrected_volatile_mem_error_programmable_warning_threshold   - offset 12
 *   uint16_t corrected_persistent_mem_error_programmable_warning_threshold - offset 14
 */
static int test_endian_get_alert_config(void)
{
	uint8_t wire_rsp[16] = {0};
	struct cxlmi_cmd_memdev_get_alert_config_rsp ret = {0};
	int rc;

	wire_rsp[0] = 0xFF; /* valid_alerts */
	wire_rsp[1] = 0x0F; /* programmable_alerts */
	wire_rsp[2] = 0x50; /* life_used_critical_alert_threshold */
	wire_rsp[3] = 0x40; /* life_used_programmable_warning_threshold */

	/* device_over_temperature_critical_alert_threshold: 0xBEEF in LE */
	wire_rsp[4] = 0xEF; wire_rsp[5] = 0xBE;

	/* device_under_temperature_critical_alert_threshold: 0xCAFE in LE */
	wire_rsp[6] = 0xFE; wire_rsp[7] = 0xCA;

	/* device_over_temperature_programmable_warning_threshold: 0xDEAD in LE */
	wire_rsp[8] = 0xAD; wire_rsp[9] = 0xDE;

	/* device_under_temperature_programmable_warning_threshold: 0xF00D in LE */
	wire_rsp[10] = 0x0D; wire_rsp[11] = 0xF0;

	/* corrected_volatile_mem_error_programmable_warning_threshold: 0x1234 in LE */
	wire_rsp[12] = 0x34; wire_rsp[13] = 0x12;

	/* corrected_persistent_mem_error_programmable_warning_threshold: 0x5678 in LE */
	wire_rsp[14] = 0x78; wire_rsp[15] = 0x56;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x01, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_alert_config(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.valid_alerts, 0xFF, "valid_alerts wrong");
	ASSERT_EQ(ret.programmable_alerts, 0x0F, "programmable_alerts wrong");
	ASSERT_EQ(ret.device_over_temperature_critical_alert_threshold, 0xBEEF,
		  "device_over_temperature_critical endianness wrong");
	ASSERT_EQ(ret.device_under_temperature_critical_alert_threshold, 0xCAFE,
		  "device_under_temperature_critical endianness wrong");
	ASSERT_EQ(ret.device_over_temperature_programmable_warning_threshold, 0xDEAD,
		  "device_over_temperature_programmable endianness wrong");
	ASSERT_EQ(ret.device_under_temperature_programmable_warning_threshold, 0xF00D,
		  "device_under_temperature_programmable endianness wrong");
	ASSERT_EQ(ret.corrected_volatile_mem_error_programmable_warning_threshold, 0x1234,
		  "corrected_volatile_mem_error endianness wrong");
	ASSERT_EQ(ret.corrected_persistent_mem_error_programmable_warning_threshold, 0x5678,
		  "corrected_persistent_mem_error endianness wrong");

	return 0;
}

/*
 * Test set_alert_config request encoding (16-bit temperature thresholds).
 */
static int test_endian_set_alert_config_request(void)
{
	struct cxlmi_cmd_memdev_set_alert_config_req req = {0};
	uint8_t cmd_payload[256];
	size_t cmd_payload_size = sizeof(cmd_payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.valid_alert_actions = 0xFF;
	req.enable_alert_actions = 0x0F;
	req.life_used_programmable_warning_threshold = 0x40;
	req.device_over_temperature_programmable_warning_threshold = 0xBEEF;
	req.device_under_temperature_programmable_warning_threshold = 0xCAFE;
	req.corrected_volatile_mem_error_programmable_warning_threshold = 0xDEAD;
	req.corrected_persistent_mem_error_programmable_warning_threshold = 0xF00D;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x42, 0x02, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_memdev_set_alert_config(test_ep, NULL, &req);
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, cmd_payload, &cmd_payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x42, "wrong command set");
	ASSERT_EQ(cmd, 0x02, "wrong command");

	/*
	 * Wire layout:
	 *   valid_alert_actions: 1 byte (offset 0)
	 *   enable_alert_actions: 1 byte (offset 1)
	 *   life_used_programmable_warning_threshold: 1 byte (offset 2)
	 *   rsvd1: 1 byte (offset 3)
	 *   device_over_temperature_programmable_warning_threshold: 2 bytes LE (offset 4)
	 *   device_under_temperature_programmable_warning_threshold: 2 bytes LE (offset 6)
	 *   corrected_volatile_mem_error_programmable_warning_threshold: 2 bytes LE (offset 8)
	 *   corrected_persistent_mem_error_programmable_warning_threshold: 2 bytes LE (offset 10)
	 */
	ASSERT_EQ(cmd_payload[0], 0xFF, "valid_alert_actions wrong");
	ASSERT_EQ(cmd_payload[1], 0x0F, "enable_alert_actions wrong");
	ASSERT_EQ(cmd_payload[2], 0x40, "life_used threshold wrong");

	/* device_over_temperature: 0xBEEF -> EF BE */
	ASSERT_EQ(cmd_payload[4], 0xEF, "device_over_temp low byte wrong");
	ASSERT_EQ(cmd_payload[5], 0xBE, "device_over_temp high byte wrong");

	/* device_under_temperature: 0xCAFE -> FE CA */
	ASSERT_EQ(cmd_payload[6], 0xFE, "device_under_temp low byte wrong");
	ASSERT_EQ(cmd_payload[7], 0xCA, "device_under_temp high byte wrong");

	/* corrected_volatile: 0xDEAD -> AD DE */
	ASSERT_EQ(cmd_payload[8], 0xAD, "corrected_volatile low byte wrong");
	ASSERT_EQ(cmd_payload[9], 0xDE, "corrected_volatile high byte wrong");

	/* corrected_persistent: 0xF00D -> 0D F0 */
	ASSERT_EQ(cmd_payload[10], 0x0D, "corrected_persistent low byte wrong");
	ASSERT_EQ(cmd_payload[11], 0xF0, "corrected_persistent high byte wrong");

	return 0;
}

/*
 * Test fmapi_get_dcd_info response (16-bit policies, 64-bit capacity and masks).
 * Struct layout:
 *   uint8_t num_hosts                      - offset 0
 *   uint8_t num_supported_dc_regions       - offset 1
 *   uint8_t rsvd1[2]                       - offset 2
 *   uint16_t capacity_selection_policies   - offset 4
 *   uint8_t rsvd2[2]                       - offset 6
 *   uint16_t capacity_removal_policies     - offset 8
 *   uint8_t sanitize_on_release_config_mask - offset 10
 *   uint8_t rsvd3                          - offset 11
 *   uint64_t total_dynamic_capacity        - offset 12 (multiplied by 256MB)
 *   uint64_t region_0_supported_blk_sz_mask - offset 20
 *   ... (regions 1-7 follow)
 */
static int test_endian_fmapi_get_dcd_info(void)
{
	uint8_t wire_rsp[84] = {0};
	struct cxlmi_cmd_fmapi_get_dcd_info_rsp ret = {0};
	int rc;

	wire_rsp[0] = 0x04; /* num_hosts */
	wire_rsp[1] = 0x02; /* num_supported_dc_regions */

	/* capacity_selection_policies: 0xBEEF in LE at offset 4 */
	wire_rsp[4] = 0xEF; wire_rsp[5] = 0xBE;

	/* capacity_removal_policies: 0xCAFE in LE at offset 8 */
	wire_rsp[8] = 0xFE; wire_rsp[9] = 0xCA;

	wire_rsp[10] = 0x0F; /* sanitize_on_release_config_mask */

	/*
	 * total_dynamic_capacity: 0x12345678 in LE at offset 12
	 * Library multiplies by CXL_CAPACITY_MULTIPLIER (256MB = 0x10000000)
	 */
	wire_rsp[12] = 0x78; wire_rsp[13] = 0x56;
	wire_rsp[14] = 0x34; wire_rsp[15] = 0x12;
	wire_rsp[16] = 0x00; wire_rsp[17] = 0x00;
	wire_rsp[18] = 0x00; wire_rsp[19] = 0x00;

	/* region_0_supported_blk_sz_mask: 0xFEDCBA9876543210 in LE at offset 20 */
	wire_rsp[20] = 0x10; wire_rsp[21] = 0x32;
	wire_rsp[22] = 0x54; wire_rsp[23] = 0x76;
	wire_rsp[24] = 0x98; wire_rsp[25] = 0xBA;
	wire_rsp[26] = 0xDC; wire_rsp[27] = 0xFE;

	/* region_1_supported_blk_sz_mask: 0x123456789ABCDEF0 in LE at offset 28 */
	wire_rsp[28] = 0xF0; wire_rsp[29] = 0xDE;
	wire_rsp[30] = 0xBC; wire_rsp[31] = 0x9A;
	wire_rsp[32] = 0x78; wire_rsp[33] = 0x56;
	wire_rsp[34] = 0x34; wire_rsp[35] = 0x12;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_fmapi_get_dcd_info(test_ep, NULL, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_hosts, 0x04, "num_hosts wrong");
	ASSERT_EQ(ret.num_supported_dc_regions, 0x02, "num_supported_dc_regions wrong");
	ASSERT_EQ(ret.capacity_selection_policies, 0xBEEF,
		  "capacity_selection_policies endianness wrong");
	ASSERT_EQ(ret.capacity_removal_policies, 0xCAFE,
		  "capacity_removal_policies endianness wrong");
	ASSERT_EQ(ret.sanitize_on_release_config_mask, 0x0F,
		  "sanitize_on_release_config_mask wrong");

	/* total_dynamic_capacity: 0x12345678 * 256MB = 0x1234567800000000 */
	ASSERT_TRUE(ret.total_dynamic_capacity == (0x12345678ULL * 256ULL * 1024ULL * 1024ULL),
		    "total_dynamic_capacity endianness/multiplier wrong");

	ASSERT_TRUE(ret.region_0_supported_blk_sz_mask == 0xFEDCBA9876543210ULL,
		    "region_0_supported_blk_sz_mask endianness wrong");
	ASSERT_TRUE(ret.region_1_supported_blk_sz_mask == 0x123456789ABCDEF0ULL,
		    "region_1_supported_blk_sz_mask endianness wrong");

	return 0;
}

/*
 * Test get_poison_list request encoding (64-bit addresses).
 */
static int test_endian_get_poison_list_request(void)
{
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	struct cxlmi_cmd_memdev_get_poison_list_rsp ret = {0};
	uint8_t cmd_payload[256];
	size_t cmd_payload_size = sizeof(cmd_payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.get_poison_list_phy_addr = 0x123456789ABCDEF0ULL;
	req.get_poison_list_phy_addr_len = 0xFEDCBA9876543210ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* Provide minimal response */
	uint8_t wire_rsp[32] = {0};
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, &ret);
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, cmd_payload, &cmd_payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x43, "wrong command set");
	ASSERT_EQ(cmd, 0x00, "wrong command");

	/* get_poison_list_phy_addr: 0x123456789ABCDEF0 -> F0 DE BC 9A 78 56 34 12 */
	ASSERT_EQ(cmd_payload[0], 0xF0, "phy_addr byte 0 wrong");
	ASSERT_EQ(cmd_payload[1], 0xDE, "phy_addr byte 1 wrong");
	ASSERT_EQ(cmd_payload[2], 0xBC, "phy_addr byte 2 wrong");
	ASSERT_EQ(cmd_payload[3], 0x9A, "phy_addr byte 3 wrong");
	ASSERT_EQ(cmd_payload[4], 0x78, "phy_addr byte 4 wrong");
	ASSERT_EQ(cmd_payload[5], 0x56, "phy_addr byte 5 wrong");
	ASSERT_EQ(cmd_payload[6], 0x34, "phy_addr byte 6 wrong");
	ASSERT_EQ(cmd_payload[7], 0x12, "phy_addr byte 7 wrong");

	/* get_poison_list_phy_addr_len: 0xFEDCBA9876543210 -> 10 32 54 76 98 BA DC FE */
	ASSERT_EQ(cmd_payload[8], 0x10, "phy_addr_len byte 0 wrong");
	ASSERT_EQ(cmd_payload[9], 0x32, "phy_addr_len byte 1 wrong");
	ASSERT_EQ(cmd_payload[10], 0x54, "phy_addr_len byte 2 wrong");
	ASSERT_EQ(cmd_payload[11], 0x76, "phy_addr_len byte 3 wrong");
	ASSERT_EQ(cmd_payload[12], 0x98, "phy_addr_len byte 4 wrong");
	ASSERT_EQ(cmd_payload[13], 0xBA, "phy_addr_len byte 5 wrong");
	ASSERT_EQ(cmd_payload[14], 0xDC, "phy_addr_len byte 6 wrong");
	ASSERT_EQ(cmd_payload[15], 0xFE, "phy_addr_len byte 7 wrong");

	return 0;
}

/*
 * Test get_poison_list response (64-bit timestamp, 16-bit count, record fields).
 * Uses compound struct with explicit LE encoding to test endianness conversion.
 */
static int test_endian_get_poison_list_response(void)
{
	uint8_t wire_rsp_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			    2 * sizeof(struct cxlmi_memdev_media_err_record)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_memdev_get_poison_list_rsp) +
			2 * sizeof(struct cxlmi_memdev_media_err_record)];
	struct cxlmi_cmd_memdev_get_poison_list_rsp *wire_rsp =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)wire_rsp_buf;
	struct cxlmi_cmd_memdev_get_poison_list_rsp *ret =
		(struct cxlmi_cmd_memdev_get_poison_list_rsp *)ret_buf;
	struct cxlmi_cmd_memdev_get_poison_list_req req = {0};
	int rc;

	memset(wire_rsp_buf, 0, sizeof(wire_rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	/* Encode wire data in LE - library should decode correctly */
	wire_rsp->poison_list_flags = 0x03;
	wire_rsp->overflow_timestamp = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp->more_err_media_record_cnt = cpu_to_le16(2);

	/* Records with distinct byte patterns */
	wire_rsp->records[0].media_err_addr = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp->records[0].media_err_len = cpu_to_le32(0xCAFEBABE);
	wire_rsp->records[1].media_err_addr = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp->records[1].media_err_len = cpu_to_le32(0xDEADBEEF);

	req.get_poison_list_phy_addr = 0x1000;
	req.get_poison_list_phy_addr_len = 0x10000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp_buf, sizeof(wire_rsp_buf));
	rc = cxlmi_cmd_get_poison_list(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->poison_list_flags, 0x03, "poison_list_flags wrong");
	ASSERT_TRUE(ret->overflow_timestamp == 0x123456789ABCDEF0ULL,
		    "overflow_timestamp endianness wrong");
	ASSERT_EQ(ret->more_err_media_record_cnt, 2, "more_err_media_record_cnt wrong");

	ASSERT_TRUE(ret->records[0].media_err_addr == 0xFEDCBA9876543210ULL,
		    "record[0].media_err_addr endianness wrong");
	ASSERT_EQ(ret->records[0].media_err_len, 0xCAFEBABE,
		  "record[0].media_err_len endianness wrong");

	ASSERT_TRUE(ret->records[1].media_err_addr == 0x1122334455667788ULL,
		    "record[1].media_err_addr endianness wrong");
	ASSERT_EQ(ret->records[1].media_err_len, 0xDEADBEEF,
		  "record[1].media_err_len endianness wrong");

	return 0;
}

/*
 * Test scan_media request encoding (64-bit addresses).
 * Note: scan_media_flags is 8-bit in struct but library writes 16-bit LE.
 */
static int test_endian_scan_media_request(void)
{
	struct cxlmi_cmd_scan_media_req req = {0};
	uint8_t cmd_payload[256];
	size_t cmd_payload_size = sizeof(cmd_payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.scan_media_physaddr = 0x123456789ABCDEF0ULL;
	req.scan_media_physaddr_length = 0xFEDCBA9876543210ULL;
	req.scan_media_flags = 0x03;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x04, CXLMI_RET_SUCCESS, NULL, 0);
	rc = cxlmi_cmd_scan_media(test_ep, NULL, &req);
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, cmd_payload, &cmd_payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x43, "wrong command set");
	ASSERT_EQ(cmd, 0x04, "wrong command");

	/* scan_media_physaddr: 0x123456789ABCDEF0 -> F0 DE BC 9A 78 56 34 12 */
	ASSERT_EQ(cmd_payload[0], 0xF0, "physaddr byte 0 wrong");
	ASSERT_EQ(cmd_payload[1], 0xDE, "physaddr byte 1 wrong");
	ASSERT_EQ(cmd_payload[2], 0xBC, "physaddr byte 2 wrong");
	ASSERT_EQ(cmd_payload[3], 0x9A, "physaddr byte 3 wrong");
	ASSERT_EQ(cmd_payload[4], 0x78, "physaddr byte 4 wrong");
	ASSERT_EQ(cmd_payload[5], 0x56, "physaddr byte 5 wrong");
	ASSERT_EQ(cmd_payload[6], 0x34, "physaddr byte 6 wrong");
	ASSERT_EQ(cmd_payload[7], 0x12, "physaddr byte 7 wrong");

	/* scan_media_physaddr_length: 0xFEDCBA9876543210 -> 10 32 54 76 98 BA DC FE */
	ASSERT_EQ(cmd_payload[8], 0x10, "physaddr_length byte 0 wrong");
	ASSERT_EQ(cmd_payload[9], 0x32, "physaddr_length byte 1 wrong");
	ASSERT_EQ(cmd_payload[10], 0x54, "physaddr_length byte 2 wrong");
	ASSERT_EQ(cmd_payload[11], 0x76, "physaddr_length byte 3 wrong");
	ASSERT_EQ(cmd_payload[12], 0x98, "physaddr_length byte 4 wrong");
	ASSERT_EQ(cmd_payload[13], 0xBA, "physaddr_length byte 5 wrong");
	ASSERT_EQ(cmd_payload[14], 0xDC, "physaddr_length byte 6 wrong");
	ASSERT_EQ(cmd_payload[15], 0xFE, "physaddr_length byte 7 wrong");

	/* scan_media_flags: low byte should be 0x03 (library writes 16-bit LE) */
	ASSERT_EQ(cmd_payload[16], 0x03, "flags low byte wrong");

	return 0;
}

/*
 * Test get_scan_media_results response (64-bit addresses, 16-bit count, records).
 * Uses compound struct with explicit LE encoding to test endianness conversion.
 */
static int test_endian_get_scan_media_results(void)
{
	uint8_t wire_rsp_buf[sizeof(struct cxlmi_cmd_get_scan_media_results_rsp) +
			    2 * sizeof(struct cxlmi_media_error_record)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_scan_media_results_rsp) +
			2 * sizeof(struct cxlmi_media_error_record)];
	struct cxlmi_cmd_get_scan_media_results_rsp *wire_rsp =
		(struct cxlmi_cmd_get_scan_media_results_rsp *)wire_rsp_buf;
	struct cxlmi_cmd_get_scan_media_results_rsp *ret =
		(struct cxlmi_cmd_get_scan_media_results_rsp *)ret_buf;
	int rc;

	memset(wire_rsp_buf, 0, sizeof(wire_rsp_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	/* Encode wire data in LE - library should decode correctly */
	wire_rsp->scan_media_restart_physaddr = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp->scan_media_restart_physaddr_length = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp->scan_media_flags = 0x05;
	wire_rsp->media_error_count = cpu_to_le16(2);

	/* Records with distinct byte patterns */
	wire_rsp->record[0].media_error_address = cpu_to_le64(0xAABBCCDDEEFF0011ULL);
	wire_rsp->record[0].media_error_length = cpu_to_le32(0x12345678);
	wire_rsp->record[1].media_error_address = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp->record[1].media_error_length = cpu_to_le32(0xABCDEF01);

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x05, CXLMI_RET_SUCCESS,
				wire_rsp_buf, sizeof(wire_rsp_buf));
	rc = cxlmi_cmd_get_scan_media_results(test_ep, NULL, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_TRUE(ret->scan_media_restart_physaddr == 0x123456789ABCDEF0ULL,
		    "scan_media_restart_physaddr endianness wrong");
	ASSERT_TRUE(ret->scan_media_restart_physaddr_length == 0xFEDCBA9876543210ULL,
		    "scan_media_restart_physaddr_length endianness wrong");
	ASSERT_EQ(ret->scan_media_flags, 0x05, "scan_media_flags wrong");
	ASSERT_EQ(ret->media_error_count, 2, "media_error_count wrong");

	ASSERT_TRUE(ret->record[0].media_error_address == 0xAABBCCDDEEFF0011ULL,
		    "record[0].media_error_address endianness wrong");
	ASSERT_EQ(ret->record[0].media_error_length, 0x12345678,
		  "record[0].media_error_length endianness wrong");

	ASSERT_TRUE(ret->record[1].media_error_address == 0x1122334455667788ULL,
		    "record[1].media_error_address endianness wrong");
	ASSERT_EQ(ret->record[1].media_error_length, 0xABCDEF01,
		  "record[1].media_error_length endianness wrong");

	return 0;
}

/*
 * Test get_supported_features request encoding (32-bit count, 16-bit index).
 */
static int test_endian_get_supported_features_request(void)
{
	struct cxlmi_cmd_get_supported_features_req req = {0};
	struct cxlmi_cmd_get_supported_features_rsp ret = {0};
	uint8_t cmd_payload[256];
	size_t cmd_payload_size = sizeof(cmd_payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.count = 0x12345678;
	req.starting_feature_index = 0xBEEF;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* Provide minimal response */
	uint8_t wire_rsp[8] = {0};
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, &ret);
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, cmd_payload, &cmd_payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x05, "wrong command set");
	ASSERT_EQ(cmd, 0x00, "wrong command");

	/* count: 0x12345678 -> 78 56 34 12 (32-bit LE at offset 0) */
	ASSERT_EQ(cmd_payload[0], 0x78, "count byte 0 wrong");
	ASSERT_EQ(cmd_payload[1], 0x56, "count byte 1 wrong");
	ASSERT_EQ(cmd_payload[2], 0x34, "count byte 2 wrong");
	ASSERT_EQ(cmd_payload[3], 0x12, "count byte 3 wrong");

	/* starting_feature_index: 0xBEEF -> EF BE (16-bit LE at offset 4) */
	ASSERT_EQ(cmd_payload[4], 0xEF, "starting_feature_index byte 0 wrong");
	ASSERT_EQ(cmd_payload[5], 0xBE, "starting_feature_index byte 1 wrong");

	return 0;
}

/*
 * Test get_supported_features response (16/32-bit header, per-entry fields).
 * Uses compound struct with explicit LE encoding.
 */
static int test_endian_get_supported_features_response(void)
{
	struct wire_entry {
		uint8_t feature_id[0x10];
		uint16_t feature_index;
		uint16_t get_feature_size;
		uint16_t set_feature_size;
		uint32_t attribute_flags;
		uint8_t get_feature_version;
		uint8_t set_feature_version;
		uint16_t set_feature_effects;
		uint8_t rsvd[18];
	} __attribute__((packed));
	struct {
		uint16_t num_supported_feature_entries;
		uint16_t device_supported_features;
		uint8_t rsvd[4];
		struct wire_entry entries[2];
	} __attribute__((packed)) wire_rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_supported_features_rsp) +
			2 * sizeof(struct wire_entry)];
	struct cxlmi_cmd_get_supported_features_rsp *ret =
		(struct cxlmi_cmd_get_supported_features_rsp *)ret_buf;
	struct cxlmi_cmd_get_supported_features_req req = {0};
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	/* Header fields */
	wire_rsp.num_supported_feature_entries = cpu_to_le16(2);
	wire_rsp.device_supported_features = cpu_to_le16(0xCAFE);

	/* Entry 0 with distinct byte patterns */
	wire_rsp.entries[0].feature_index = cpu_to_le16(0xBEEF);
	wire_rsp.entries[0].get_feature_size = cpu_to_le16(0xDEAD);
	wire_rsp.entries[0].set_feature_size = cpu_to_le16(0xF00D);
	wire_rsp.entries[0].attribute_flags = cpu_to_le32(0x12345678);
	wire_rsp.entries[0].set_feature_effects = cpu_to_le16(0xABCD);

	/* Entry 1 */
	wire_rsp.entries[1].feature_index = cpu_to_le16(0x1234);
	wire_rsp.entries[1].get_feature_size = cpu_to_le16(0x5678);
	wire_rsp.entries[1].set_feature_size = cpu_to_le16(0x9ABC);
	wire_rsp.entries[1].attribute_flags = cpu_to_le32(0xFEDCBA98);
	wire_rsp.entries[1].set_feature_effects = cpu_to_le16(0xEF01);

	req.count = sizeof(wire_rsp.entries);
	req.starting_feature_index = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x05, 0x00, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_supported_features(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_supported_feature_entries, 2, "num_entries wrong");
	ASSERT_EQ(ret->device_supported_features, 0xCAFE, "device_supported_features endianness wrong");

	/* Entry 0 */
	ASSERT_EQ(ret->supported_feature_entries[0].feature_index, 0xBEEF,
		  "entry[0].feature_index endianness wrong");
	ASSERT_EQ(ret->supported_feature_entries[0].get_feature_size, 0xDEAD,
		  "entry[0].get_feature_size endianness wrong");
	ASSERT_EQ(ret->supported_feature_entries[0].set_feature_size, 0xF00D,
		  "entry[0].set_feature_size endianness wrong");
	ASSERT_EQ(ret->supported_feature_entries[0].attribute_flags, 0x12345678,
		  "entry[0].attribute_flags endianness wrong");
	ASSERT_EQ(ret->supported_feature_entries[0].set_feature_effects, 0xABCD,
		  "entry[0].set_feature_effects endianness wrong");

	/* Entry 1 */
	ASSERT_EQ(ret->supported_feature_entries[1].feature_index, 0x1234,
		  "entry[1].feature_index endianness wrong");
	ASSERT_EQ(ret->supported_feature_entries[1].attribute_flags, 0xFEDCBA98,
		  "entry[1].attribute_flags endianness wrong");

	return 0;
}

/*
 * Test memdev_get_dc_config response (64-bit region fields, 32-bit counts).
 * Struct has region_configs[8] array with base, decode_len, region_len, block_size.
 * decode_len is multiplied by CXL_CAPACITY_MULTIPLIER (256MB).
 */
static int test_endian_memdev_get_dc_config(void)
{
	/*
	 * The response has variable layout: header + N regions + trailing fields.
	 * Trailing fields immediately follow the returned regions (not at fixed offset).
	 * Header: 8 bytes (num_regions, regions_returned, rsvd[6])
	 * Per-region: 40 bytes (base, decode_len, region_len, block_size, dsmadhandle, flags, rsvd[3])
	 * Trailing: 16 bytes (num_extents_supported/available, num_tags_supported/available)
	 */
	struct __attribute__((packed)) {
		uint8_t num_regions;
		uint8_t regions_returned;
		uint8_t rsvd1[6];
		struct __attribute__((packed)) {
			uint64_t base;
			uint64_t decode_len;
			uint64_t region_len;
			uint64_t block_size;
			uint32_t dsmadhandle;
			uint8_t flags;
			uint8_t rsvd2[3];
		} region_configs[2]; /* Only 2 regions */
		uint32_t num_extents_supported;
		uint32_t num_extents_available;
		uint32_t num_tags_supported;
		uint32_t num_tags_available;
	} wire_rsp = {0};
	struct cxlmi_cmd_memdev_get_dc_config_rsp ret = {0};
	struct cxlmi_cmd_memdev_get_dc_config_req req = {0};
	int rc;

	wire_rsp.num_regions = 2;
	wire_rsp.regions_returned = 2;

	/* Region 0 */
	wire_rsp.region_configs[0].base = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.region_configs[0].decode_len = cpu_to_le64(0x00000010); /* 16 * 256MB = 4GB */
	wire_rsp.region_configs[0].region_len = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp.region_configs[0].block_size = cpu_to_le64(0xAABBCCDDEEFF0011ULL);
	wire_rsp.region_configs[0].dsmadhandle = cpu_to_le32(0xDEADBEEF);

	/* Region 1 */
	wire_rsp.region_configs[1].base = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.region_configs[1].decode_len = cpu_to_le64(0x00000020); /* 32 * 256MB = 8GB */
	wire_rsp.region_configs[1].region_len = cpu_to_le64(0x8877665544332211ULL);
	wire_rsp.region_configs[1].block_size = cpu_to_le64(0x0102030405060708ULL);
	wire_rsp.region_configs[1].dsmadhandle = cpu_to_le32(0xCAFEBABE);

	/* Trailing 32-bit fields immediately after region[1] */
	wire_rsp.num_extents_supported = cpu_to_le32(0x11223344);
	wire_rsp.num_extents_available = cpu_to_le32(0x55667788);
	wire_rsp.num_tags_supported = cpu_to_le32(0x99AABBCC);
	wire_rsp.num_tags_available = cpu_to_le32(0xDDEEFF00);

	req.region_cnt = 2;
	req.start_region_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x00, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_dc_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.num_regions, 2, "num_regions wrong");
	ASSERT_EQ(ret.regions_returned, 2, "regions_returned wrong");

	/* Region 0 */
	ASSERT_TRUE(ret.region_configs[0].base == 0x123456789ABCDEF0ULL,
		    "region[0].base endianness wrong");
	/* decode_len is multiplied by 256MB */
	ASSERT_TRUE(ret.region_configs[0].decode_len == (0x10ULL * 256ULL * 1024ULL * 1024ULL),
		    "region[0].decode_len endianness/multiplier wrong");
	ASSERT_TRUE(ret.region_configs[0].region_len == 0xFEDCBA9876543210ULL,
		    "region[0].region_len endianness wrong");
	ASSERT_TRUE(ret.region_configs[0].block_size == 0xAABBCCDDEEFF0011ULL,
		    "region[0].block_size endianness wrong");
	ASSERT_EQ(ret.region_configs[0].dsmadhandle, 0xDEADBEEF,
		  "region[0].dsmadhandle endianness wrong");

	/* Region 1 */
	ASSERT_TRUE(ret.region_configs[1].base == 0x1122334455667788ULL,
		    "region[1].base endianness wrong");
	ASSERT_TRUE(ret.region_configs[1].decode_len == (0x20ULL * 256ULL * 1024ULL * 1024ULL),
		    "region[1].decode_len endianness/multiplier wrong");
	ASSERT_EQ(ret.region_configs[1].dsmadhandle, 0xCAFEBABE,
		  "region[1].dsmadhandle endianness wrong");

	/* Trailing 32-bit fields */
	ASSERT_EQ(ret.num_extents_supported, 0x11223344,
		  "num_extents_supported endianness wrong");
	ASSERT_EQ(ret.num_extents_available, 0x55667788,
		  "num_extents_available endianness wrong");
	ASSERT_EQ(ret.num_tags_supported, 0x99AABBCC,
		  "num_tags_supported endianness wrong");
	ASSERT_EQ(ret.num_tags_available, 0xDDEEFF00,
		  "num_tags_available endianness wrong");

	return 0;
}

/*
 * Test memdev_get_dc_extent_list request encoding (32-bit fields).
 */
static int test_endian_get_dc_extent_list_request(void)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp ret = {0};
	uint8_t cmd_payload[256];
	size_t cmd_payload_size = sizeof(cmd_payload);
	uint8_t cmd_set, cmd;
	int rc;

	req.extent_cnt = 0x12345678;
	req.start_extent_idx = 0xDEADBEEF;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* Provide minimal response */
	uint8_t wire_rsp[16] = {0};
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS,
				wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, &ret);
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, cmd_payload, &cmd_payload_size);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(cmd_set, 0x48, "wrong command set");
	ASSERT_EQ(cmd, 0x01, "wrong command");

	/*
	 * Note: Library clamps extent_cnt to 8 if > 8 or 0, so we check
	 * that at least start_extent_idx is encoded correctly.
	 * start_extent_idx: 0xDEADBEEF -> EF BE AD DE (32-bit LE at offset 4)
	 */
	ASSERT_EQ(cmd_payload[4], 0xEF, "start_extent_idx byte 0 wrong");
	ASSERT_EQ(cmd_payload[5], 0xBE, "start_extent_idx byte 1 wrong");
	ASSERT_EQ(cmd_payload[6], 0xAD, "start_extent_idx byte 2 wrong");
	ASSERT_EQ(cmd_payload[7], 0xDE, "start_extent_idx byte 3 wrong");

	return 0;
}

/*
 * Test memdev_get_dc_extent_list response (32-bit header, 64-bit/16-bit extent fields).
 */
static int test_endian_get_dc_extent_list_response(void)
{
	struct wire_extent {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t tag[0x10];
		uint16_t shared_seq;
		uint8_t rsvd[0x6];
	} __attribute__((packed));
	struct {
		uint32_t num_extents_returned;
		uint32_t total_num_extents;
		uint32_t generation_num;
		uint8_t rsvd[4];
		struct wire_extent extents[2];
	} __attribute__((packed)) wire_rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_memdev_get_dc_extent_list_rsp) +
			2 * sizeof(struct wire_extent)];
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *ret =
		(struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *)ret_buf;
	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {0};
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	/* Header fields */
	wire_rsp.num_extents_returned = cpu_to_le32(2);
	wire_rsp.total_num_extents = cpu_to_le32(0xDEADBEEF);
	wire_rsp.generation_num = cpu_to_le32(0xCAFEBABE);

	/* Extent 0 */
	wire_rsp.extents[0].start_dpa = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.extents[0].len = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp.extents[0].shared_seq = cpu_to_le16(0xBEEF);

	/* Extent 1 */
	wire_rsp.extents[1].start_dpa = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.extents[1].len = cpu_to_le64(0x8877665544332211ULL);
	wire_rsp.extents[1].shared_seq = cpu_to_le16(0xF00D);

	req.extent_cnt = 2;
	req.start_extent_idx = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x48, 0x01, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_memdev_get_dc_extent_list(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->num_extents_returned, 2, "num_extents_returned wrong");
	ASSERT_EQ(ret->total_num_extents, 0xDEADBEEF,
		  "total_num_extents endianness wrong");
	ASSERT_EQ(ret->generation_num, 0xCAFEBABE,
		  "generation_num endianness wrong");

	/* Extent 0 */
	ASSERT_TRUE(ret->extents[0].start_dpa == 0x123456789ABCDEF0ULL,
		    "extent[0].start_dpa endianness wrong");
	ASSERT_TRUE(ret->extents[0].len == 0xFEDCBA9876543210ULL,
		    "extent[0].len endianness wrong");
	ASSERT_EQ(ret->extents[0].shared_seq, 0xBEEF,
		  "extent[0].shared_seq endianness wrong");

	/* Extent 1 */
	ASSERT_TRUE(ret->extents[1].start_dpa == 0x1122334455667788ULL,
		    "extent[1].start_dpa endianness wrong");
	ASSERT_TRUE(ret->extents[1].len == 0x8877665544332211ULL,
		    "extent[1].len endianness wrong");
	ASSERT_EQ(ret->extents[1].shared_seq, 0xF00D,
		  "extent[1].shared_seq endianness wrong");

	return 0;
}

/*
 * Test get_event_records response (16/64-bit header and per-record fields).
 * Header has overflow timestamps (64-bit) and counts (16-bit).
 * Each record has handle, related_handle, ld_id (16-bit) and timestamp (64-bit).
 */
static int test_endian_get_event_records(void)
{
	/*
	 * Variable-length response: header + N records.
	 * Need to construct wire format with proper endianness.
	 */
	struct __attribute__((packed)) {
		uint8_t flags;
		uint8_t reserved1;
		uint16_t overflow_err_count;
		uint64_t first_overflow_timestamp;
		uint64_t last_overflow_timestamp;
		uint16_t record_count;
		uint8_t reserved2[0xa];
		struct cxlmi_event_record records[2];
	} wire_rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_get_event_records_rsp) +
			2 * sizeof(struct cxlmi_event_record)];
	struct cxlmi_cmd_get_event_records_rsp *ret =
		(struct cxlmi_cmd_get_event_records_rsp *)ret_buf;
	struct cxlmi_cmd_get_event_records_req req = {0};
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	/* Header fields */
	wire_rsp.flags = 0x01;
	wire_rsp.overflow_err_count = cpu_to_le16(0xABCD);
	wire_rsp.first_overflow_timestamp = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.last_overflow_timestamp = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp.record_count = cpu_to_le16(2);

	/* Record 0 */
	wire_rsp.records[0].length = 0x80;
	wire_rsp.records[0].handle = cpu_to_le16(0x1234);
	wire_rsp.records[0].related_handle = cpu_to_le16(0x5678);
	wire_rsp.records[0].timestamp = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.records[0].ld_id = cpu_to_le16(0xBEEF);

	/* Record 1 */
	wire_rsp.records[1].length = 0x80;
	wire_rsp.records[1].handle = cpu_to_le16(0xDEAD);
	wire_rsp.records[1].related_handle = cpu_to_le16(0xBEEF);
	wire_rsp.records[1].timestamp = cpu_to_le64(0x8877665544332211ULL);
	wire_rsp.records[1].ld_id = cpu_to_le16(0xCAFE);

	req.event_log = 0; /* Info log */

	ASSERT_EQ(setup(), 0, "setup failed");
	/* EVENTS=0x01, GET_RECORDS=0x00 */
	cxlmi_mock_set_response(test_ep, 0x01, 0x00, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_event_records(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	/* Header field checks */
	ASSERT_EQ(ret->flags, 0x01, "flags wrong");
	ASSERT_EQ(ret->overflow_err_count, 0xABCD,
		  "overflow_err_count endianness wrong");
	ASSERT_TRUE(ret->first_overflow_timestamp == 0x123456789ABCDEF0ULL,
		    "first_overflow_timestamp endianness wrong");
	ASSERT_TRUE(ret->last_overflow_timestamp == 0xFEDCBA9876543210ULL,
		    "last_overflow_timestamp endianness wrong");
	ASSERT_EQ(ret->record_count, 2, "record_count endianness wrong");

	/* Record 0 checks */
	ASSERT_EQ(ret->records[0].handle, 0x1234,
		  "record[0].handle endianness wrong");
	ASSERT_EQ(ret->records[0].related_handle, 0x5678,
		  "record[0].related_handle endianness wrong");
	ASSERT_TRUE(ret->records[0].timestamp == 0x1122334455667788ULL,
		    "record[0].timestamp endianness wrong");
	ASSERT_EQ(ret->records[0].ld_id, 0xBEEF,
		  "record[0].ld_id endianness wrong");

	/* Record 1 checks */
	ASSERT_EQ(ret->records[1].handle, 0xDEAD,
		  "record[1].handle endianness wrong");
	ASSERT_EQ(ret->records[1].related_handle, 0xBEEF,
		  "record[1].related_handle endianness wrong");
	ASSERT_TRUE(ret->records[1].timestamp == 0x8877665544332211ULL,
		    "record[1].timestamp endianness wrong");
	ASSERT_EQ(ret->records[1].ld_id, 0xCAFE,
		  "record[1].ld_id endianness wrong");

	return 0;
}

/*
 * Test fmapi_get_dc_region_ext_list request encoding (16/32-bit fields).
 */
static int test_endian_fmapi_get_dc_region_ext_list_request(void)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp ret = {0};
	uint8_t cmd_set, cmd;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	req.host_id = 0x1234;
	/* Use small extent_count - cmd allocates extent_count * sizeof(extent) bytes */
	req.extent_count = 0x0201;  /* 513 - small enough to allocate, distinct bytes */
	req.start_ext_index = 0x04030201; /* Distinct bytes for endianness check */

	ASSERT_EQ(setup(), 0, "setup failed");
	/* DCD_MANAGEMENT=0x56, GET_DC_REGION_EXTENT_LIST=0x03 */
	cxlmi_mock_set_response(test_ep, 0x56, 0x03, CXLMI_RET_SUCCESS,
				NULL, 0);
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(test_ep, NULL, &req, &ret);
	(void)rc; /* May fail due to minimal response, we only care about request encoding */

	/* Check what was sent */
	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x56, "wrong command set");
	ASSERT_EQ(cmd, 0x03, "wrong command");

	/* Check host_id encoding (16-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0x34, "host_id low byte wrong");
	ASSERT_EQ(payload[1], 0x12, "host_id high byte wrong");

	/* Check extent_count encoding (32-bit LE at offset 4) */
	ASSERT_EQ(payload[4], 0x01, "extent_count byte 0 wrong");
	ASSERT_EQ(payload[5], 0x02, "extent_count byte 1 wrong");
	ASSERT_EQ(payload[6], 0x00, "extent_count byte 2 wrong");
	ASSERT_EQ(payload[7], 0x00, "extent_count byte 3 wrong");

	/* Check start_ext_index encoding (32-bit LE at offset 8) */
	ASSERT_EQ(payload[8], 0x01, "start_ext_index byte 0 wrong");
	ASSERT_EQ(payload[9], 0x02, "start_ext_index byte 1 wrong");
	ASSERT_EQ(payload[10], 0x03, "start_ext_index byte 2 wrong");
	ASSERT_EQ(payload[11], 0x04, "start_ext_index byte 3 wrong");

	return 0;
}

/*
 * Test fmapi_get_dc_region_ext_list response (16/32/64-bit fields with extents).
 */
static int test_endian_fmapi_get_dc_region_ext_list_response(void)
{
	struct wire_extent {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t tag[0x10];
		uint16_t shared_seq;
		uint8_t rsvd[6];
	} __attribute__((packed));
	struct __attribute__((packed)) {
		uint16_t host_id;
		uint8_t rsvd1[2];
		uint32_t start_ext_index;
		uint32_t extents_returned;
		uint32_t total_extents;
		uint32_t list_generation_num;
		uint8_t rsvd2[4];
		struct wire_extent extents[2];
	} wire_rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp) +
			2 * sizeof(struct wire_extent)];
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *ret =
		(struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *)ret_buf;
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {0};
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));

	/* Header fields */
	wire_rsp.host_id = cpu_to_le16(0xABCD);
	wire_rsp.start_ext_index = cpu_to_le32(0x11223344);
	wire_rsp.extents_returned = cpu_to_le32(2);
	wire_rsp.total_extents = cpu_to_le32(0xDEADBEEF);
	wire_rsp.list_generation_num = cpu_to_le32(0xCAFEBABE);

	/* Extent 0 */
	wire_rsp.extents[0].start_dpa = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.extents[0].len = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp.extents[0].shared_seq = cpu_to_le16(0xBEEF);

	/* Extent 1 */
	wire_rsp.extents[1].start_dpa = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.extents[1].len = cpu_to_le64(0x8877665544332211ULL);
	wire_rsp.extents[1].shared_seq = cpu_to_le16(0xF00D);

	req.host_id = 0;
	req.extent_count = 2;
	req.start_ext_index = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x03, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	/* Header checks */
	ASSERT_EQ(ret->host_id, 0xABCD, "host_id endianness wrong");
	ASSERT_EQ(ret->start_ext_index, 0x11223344,
		  "start_ext_index endianness wrong");
	ASSERT_EQ(ret->extents_returned, 2, "extents_returned wrong");
	ASSERT_EQ(ret->total_extents, 0xDEADBEEF,
		  "total_extents endianness wrong");
	ASSERT_EQ(ret->list_generation_num, 0xCAFEBABE,
		  "list_generation_num endianness wrong");

	/* Extent 0 checks */
	ASSERT_TRUE(ret->extents[0].start_dpa == 0x123456789ABCDEF0ULL,
		    "extent[0].start_dpa endianness wrong");
	ASSERT_TRUE(ret->extents[0].len == 0xFEDCBA9876543210ULL,
		    "extent[0].len endianness wrong");
	ASSERT_EQ(ret->extents[0].shared_seq, 0xBEEF,
		  "extent[0].shared_seq endianness wrong");

	/* Extent 1 checks */
	ASSERT_TRUE(ret->extents[1].start_dpa == 0x1122334455667788ULL,
		    "extent[1].start_dpa endianness wrong");
	ASSERT_TRUE(ret->extents[1].len == 0x8877665544332211ULL,
		    "extent[1].len endianness wrong");
	ASSERT_EQ(ret->extents[1].shared_seq, 0xF00D,
		  "extent[1].shared_seq endianness wrong");

	return 0;
}

/*
 * Test fmapi_get_dc_reg_config request encoding (16-bit host_id).
 */
static int test_endian_fmapi_get_dc_reg_config_request(void)
{
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp ret = {0};
	uint8_t cmd_set, cmd;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);

	req.host_id = 0xABCD;
	req.region_cnt = 2;
	req.start_region_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* DCD_MANAGEMENT=0x56, GET_HOST_DC_REGION_CONFIG=0x01 */
	cxlmi_mock_set_response(test_ep, 0x56, 0x01, CXLMI_RET_SUCCESS,
				NULL, 0);
	cxlmi_cmd_fmapi_get_dc_reg_config(test_ep, NULL, &req, &ret);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x56, "wrong command set");
	ASSERT_EQ(cmd, 0x01, "wrong command");

	/* Check host_id encoding (16-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0xCD, "host_id low byte wrong");
	ASSERT_EQ(payload[1], 0xAB, "host_id high byte wrong");

	return 0;
}

/*
 * Test fmapi_get_dc_reg_config response (16-bit host_id, 64-bit region fields, 32-bit trailing).
 * Similar to memdev_get_dc_config but with host_id field.
 */
static int test_endian_fmapi_get_dc_reg_config_response(void)
{
	/*
	 * Variable-length response like memdev_get_dc_config.
	 * Trailing fields follow returned regions.
	 */
	struct __attribute__((packed)) {
		uint16_t host_id;
		uint8_t num_regions;
		uint8_t regions_returned;
		struct __attribute__((packed)) {
			uint64_t base;
			uint64_t decode_len;
			uint64_t region_len;
			uint64_t block_size;
			uint8_t flags;
			uint8_t rsvd[3];
			uint8_t sanitize_on_release;
			uint8_t rsvd2[3];
		} region_configs[2];
		uint32_t num_extents_supported;
		uint32_t num_extents_available;
		uint32_t num_tags_supported;
		uint32_t num_tags_available;
	} wire_rsp = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp ret = {0};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req req = {0};
	int rc;

	wire_rsp.host_id = cpu_to_le16(0xABCD);
	wire_rsp.num_regions = 2;
	wire_rsp.regions_returned = 2;

	/* Region 0 */
	wire_rsp.region_configs[0].base = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.region_configs[0].decode_len = cpu_to_le64(0x10); /* 16 * 256MB */
	wire_rsp.region_configs[0].region_len = cpu_to_le64(0xFEDCBA9876543210ULL);
	wire_rsp.region_configs[0].block_size = cpu_to_le64(0xAABBCCDDEEFF0011ULL);

	/* Region 1 */
	wire_rsp.region_configs[1].base = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.region_configs[1].decode_len = cpu_to_le64(0x20); /* 32 * 256MB */
	wire_rsp.region_configs[1].region_len = cpu_to_le64(0x8877665544332211ULL);
	wire_rsp.region_configs[1].block_size = cpu_to_le64(0x0102030405060708ULL);

	/* Trailing fields */
	wire_rsp.num_extents_supported = cpu_to_le32(0x11223344);
	wire_rsp.num_extents_available = cpu_to_le32(0x55667788);
	wire_rsp.num_tags_supported = cpu_to_le32(0x99AABBCC);
	wire_rsp.num_tags_available = cpu_to_le32(0xDDEEFF00);

	req.host_id = 0;
	req.region_cnt = 2;
	req.start_region_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x01, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_fmapi_get_dc_reg_config(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	/* Header checks */
	ASSERT_EQ(ret.host_id, 0xABCD, "host_id endianness wrong");
	ASSERT_EQ(ret.num_regions, 2, "num_regions wrong");
	ASSERT_EQ(ret.regions_returned, 2, "regions_returned wrong");

	/* Region 0 */
	ASSERT_TRUE(ret.region_configs[0].base == 0x123456789ABCDEF0ULL,
		    "region[0].base endianness wrong");
	ASSERT_TRUE(ret.region_configs[0].decode_len == (0x10ULL * 256ULL * 1024ULL * 1024ULL),
		    "region[0].decode_len endianness/multiplier wrong");
	ASSERT_TRUE(ret.region_configs[0].region_len == 0xFEDCBA9876543210ULL,
		    "region[0].region_len endianness wrong");
	ASSERT_TRUE(ret.region_configs[0].block_size == 0xAABBCCDDEEFF0011ULL,
		    "region[0].block_size endianness wrong");

	/* Region 1 */
	ASSERT_TRUE(ret.region_configs[1].base == 0x1122334455667788ULL,
		    "region[1].base endianness wrong");
	ASSERT_TRUE(ret.region_configs[1].decode_len == (0x20ULL * 256ULL * 1024ULL * 1024ULL),
		    "region[1].decode_len endianness/multiplier wrong");

	/* Trailing fields */
	ASSERT_EQ(ret.num_extents_supported, 0x11223344,
		  "num_extents_supported endianness wrong");
	ASSERT_EQ(ret.num_extents_available, 0x55667788,
		  "num_extents_available endianness wrong");
	ASSERT_EQ(ret.num_tags_supported, 0x99AABBCC,
		  "num_tags_supported endianness wrong");
	ASSERT_EQ(ret.num_tags_available, 0xDDEEFF00,
		  "num_tags_available endianness wrong");

	return 0;
}

/*
 * Test fmapi_initiate_dc_add request encoding (16/32/64-bit fields with extents).
 */
static int test_endian_fmapi_initiate_dc_add_request(void)
{
	/* Extent size is 40 bytes (8 + 8 + 0x10 + 2 + 6) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_initiate_dc_add_req) + 40];
	struct cxlmi_cmd_fmapi_initiate_dc_add_req *req =
		(struct cxlmi_cmd_fmapi_initiate_dc_add_req *)req_buf;
	uint8_t cmd_set, cmd;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);

	memset(req_buf, 0, sizeof(req_buf));
	req->host_id = 0xABCD;
	req->selection_policy = 0x01;
	req->region_num = 0x02;
	req->length = 0x123456789ABCDEF0ULL;
	req->ext_count = 1;

	req->extents[0].start_dpa = 0xFEDCBA9876543210ULL;
	req->extents[0].len = 0x1122334455667788ULL;
	req->extents[0].shared_seq = 0xBEEF;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* DCD_MANAGEMENT=0x56, INITIATE_DC_ADD=0x04 */
	cxlmi_mock_set_response(test_ep, 0x56, 0x04, CXLMI_RET_SUCCESS,
				NULL, 0);
	cxlmi_cmd_fmapi_initiate_dc_add(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x56, "wrong command set");
	ASSERT_EQ(cmd, 0x04, "wrong command");

	/* Check host_id encoding (16-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0xCD, "host_id low byte wrong");
	ASSERT_EQ(payload[1], 0xAB, "host_id high byte wrong");

	/* Check length encoding (64-bit LE at offset 4) */
	ASSERT_EQ(payload[4], 0xF0, "length byte 0 wrong");
	ASSERT_EQ(payload[5], 0xDE, "length byte 1 wrong");
	ASSERT_EQ(payload[6], 0xBC, "length byte 2 wrong");
	ASSERT_EQ(payload[7], 0x9A, "length byte 3 wrong");
	ASSERT_EQ(payload[8], 0x78, "length byte 4 wrong");
	ASSERT_EQ(payload[9], 0x56, "length byte 5 wrong");
	ASSERT_EQ(payload[10], 0x34, "length byte 6 wrong");
	ASSERT_EQ(payload[11], 0x12, "length byte 7 wrong");

	/* Check ext_count encoding (32-bit LE at offset 28: after 4+8+16=28) */
	ASSERT_EQ(payload[28], 0x01, "ext_count byte 0 wrong");
	ASSERT_EQ(payload[29], 0x00, "ext_count byte 1 wrong");
	ASSERT_EQ(payload[30], 0x00, "ext_count byte 2 wrong");
	ASSERT_EQ(payload[31], 0x00, "ext_count byte 3 wrong");

	/* Check extent[0].start_dpa (64-bit LE at offset 32) */
	ASSERT_EQ(payload[32], 0x10, "extent[0].start_dpa byte 0 wrong");
	ASSERT_EQ(payload[33], 0x32, "extent[0].start_dpa byte 1 wrong");
	ASSERT_EQ(payload[34], 0x54, "extent[0].start_dpa byte 2 wrong");
	ASSERT_EQ(payload[35], 0x76, "extent[0].start_dpa byte 3 wrong");
	ASSERT_EQ(payload[36], 0x98, "extent[0].start_dpa byte 4 wrong");
	ASSERT_EQ(payload[37], 0xBA, "extent[0].start_dpa byte 5 wrong");
	ASSERT_EQ(payload[38], 0xDC, "extent[0].start_dpa byte 6 wrong");
	ASSERT_EQ(payload[39], 0xFE, "extent[0].start_dpa byte 7 wrong");

	/* Check extent[0].len (64-bit LE at offset 40) */
	ASSERT_EQ(payload[40], 0x88, "extent[0].len byte 0 wrong");
	ASSERT_EQ(payload[41], 0x77, "extent[0].len byte 1 wrong");
	ASSERT_EQ(payload[42], 0x66, "extent[0].len byte 2 wrong");
	ASSERT_EQ(payload[43], 0x55, "extent[0].len byte 3 wrong");
	ASSERT_EQ(payload[44], 0x44, "extent[0].len byte 4 wrong");
	ASSERT_EQ(payload[45], 0x33, "extent[0].len byte 5 wrong");
	ASSERT_EQ(payload[46], 0x22, "extent[0].len byte 6 wrong");
	ASSERT_EQ(payload[47], 0x11, "extent[0].len byte 7 wrong");

	/* Check extent[0].shared_seq (16-bit LE at offset 64: 40+8+16=64) */
	ASSERT_EQ(payload[64], 0xEF, "extent[0].shared_seq low byte wrong");
	ASSERT_EQ(payload[65], 0xBE, "extent[0].shared_seq high byte wrong");

	return 0;
}

/*
 * Test fmapi_initiate_dc_release request encoding (16/32/64-bit fields with extents).
 */
static int test_endian_fmapi_initiate_dc_release_request(void)
{
	/* Extent size is 40 bytes (8 + 8 + 0x10 + 2 + 6) */
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_initiate_dc_release_req) + 40];
	struct cxlmi_cmd_fmapi_initiate_dc_release_req *req =
		(struct cxlmi_cmd_fmapi_initiate_dc_release_req *)req_buf;
	uint8_t cmd_set, cmd;
	uint8_t payload[128];
	size_t payload_size = sizeof(payload);

	memset(req_buf, 0, sizeof(req_buf));
	req->host_id = 0xDEAD;
	req->flags = 0x01;
	req->length = 0xCAFEBABE12345678ULL;
	req->ext_count = 1;

	req->extents[0].start_dpa = 0xABCDEF0123456789ULL;
	req->extents[0].len = 0x9876543210FEDCBAULL;
	req->extents[0].shared_seq = 0xF00D;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* DCD_MANAGEMENT=0x56, INITIATE_DC_RELEASE=0x05 */
	cxlmi_mock_set_response(test_ep, 0x56, 0x05, CXLMI_RET_SUCCESS,
				NULL, 0);
	cxlmi_cmd_fmapi_initiate_dc_release(test_ep, NULL, req);

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x56, "wrong command set");
	ASSERT_EQ(cmd, 0x05, "wrong command");

	/* Check host_id encoding (16-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0xAD, "host_id low byte wrong");
	ASSERT_EQ(payload[1], 0xDE, "host_id high byte wrong");

	/* Check length encoding (64-bit LE at offset 4) */
	ASSERT_EQ(payload[4], 0x78, "length byte 0 wrong");
	ASSERT_EQ(payload[5], 0x56, "length byte 1 wrong");
	ASSERT_EQ(payload[6], 0x34, "length byte 2 wrong");
	ASSERT_EQ(payload[7], 0x12, "length byte 3 wrong");
	ASSERT_EQ(payload[8], 0xBE, "length byte 4 wrong");
	ASSERT_EQ(payload[9], 0xBA, "length byte 5 wrong");
	ASSERT_EQ(payload[10], 0xFE, "length byte 6 wrong");
	ASSERT_EQ(payload[11], 0xCA, "length byte 7 wrong");

	/* Check ext_count encoding (32-bit LE at offset 28) */
	ASSERT_EQ(payload[28], 0x01, "ext_count byte 0 wrong");
	ASSERT_EQ(payload[29], 0x00, "ext_count byte 1 wrong");

	/* Check extent[0].start_dpa (64-bit LE at offset 32) */
	ASSERT_EQ(payload[32], 0x89, "extent[0].start_dpa byte 0 wrong");
	ASSERT_EQ(payload[33], 0x67, "extent[0].start_dpa byte 1 wrong");
	ASSERT_EQ(payload[34], 0x45, "extent[0].start_dpa byte 2 wrong");
	ASSERT_EQ(payload[35], 0x23, "extent[0].start_dpa byte 3 wrong");
	ASSERT_EQ(payload[36], 0x01, "extent[0].start_dpa byte 4 wrong");
	ASSERT_EQ(payload[37], 0xEF, "extent[0].start_dpa byte 5 wrong");
	ASSERT_EQ(payload[38], 0xCD, "extent[0].start_dpa byte 6 wrong");
	ASSERT_EQ(payload[39], 0xAB, "extent[0].start_dpa byte 7 wrong");

	/* Check extent[0].shared_seq (16-bit LE at offset 64) */
	ASSERT_EQ(payload[64], 0x0D, "extent[0].shared_seq low byte wrong");
	ASSERT_EQ(payload[65], 0xF0, "extent[0].shared_seq high byte wrong");

	return 0;
}

/*
 * Test get_log_cel response (16-bit opcode and command_effect per entry).
 */
static int test_endian_get_log_cel(void)
{
	struct __attribute__((packed)) {
		uint16_t opcode;
		uint16_t command_effect;
	} wire_rsp[3] = {0};
	struct cxlmi_cmd_get_log_cel_rsp ret[3] = {0};
	struct cxlmi_cmd_get_log_req req = {0};
	int rc;

	/* Entry 0 */
	wire_rsp[0].opcode = cpu_to_le16(0x1234);
	wire_rsp[0].command_effect = cpu_to_le16(0x5678);

	/* Entry 1 */
	wire_rsp[1].opcode = cpu_to_le16(0xABCD);
	wire_rsp[1].command_effect = cpu_to_le16(0xEF01);

	/* Entry 2 */
	wire_rsp[2].opcode = cpu_to_le16(0xDEAD);
	wire_rsp[2].command_effect = cpu_to_le16(0xBEEF);

	/* CEL log UUID */
	req.uuid[0] = 0xda;
	req.uuid[1] = 0x9c;
	req.uuid[2] = 0x6b;
	req.uuid[3] = 0x0b;
	req.offset = 0;
	req.length = sizeof(wire_rsp); /* 12 bytes = 3 entries */

	ASSERT_EQ(setup(), 0, "setup failed");
	/* LOGS=0x04, GET_LOG=0x01 */
	cxlmi_mock_set_response(test_ep, 0x04, 0x01, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_log_cel(test_ep, NULL, &req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");

	/* Entry 0 */
	ASSERT_EQ(ret[0].opcode, 0x1234, "entry[0].opcode endianness wrong");
	ASSERT_EQ(ret[0].command_effect, 0x5678,
		  "entry[0].command_effect endianness wrong");

	/* Entry 1 */
	ASSERT_EQ(ret[1].opcode, 0xABCD, "entry[1].opcode endianness wrong");
	ASSERT_EQ(ret[1].command_effect, 0xEF01,
		  "entry[1].command_effect endianness wrong");

	/* Entry 2 */
	ASSERT_EQ(ret[2].opcode, 0xDEAD, "entry[2].opcode endianness wrong");
	ASSERT_EQ(ret[2].command_effect, 0xBEEF,
		  "entry[2].command_effect endianness wrong");

	return 0;
}

/*
 * Test fmapi_dc_list_tags request encoding (32-bit fields).
 */
static int test_endian_fmapi_dc_list_tags_request(void)
{
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp ret = {0};
	uint8_t cmd_set, cmd;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	req.start_idx = 0x11223344;
	req.tags_count = 0x01020304;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* DCD_MANAGEMENT=0x56, DC_LIST_TAGS=0x08 */
	cxlmi_mock_set_response(test_ep, 0x56, 0x08, CXLMI_RET_SUCCESS,
				NULL, 0);
	rc = cxlmi_cmd_fmapi_dc_list_tags(test_ep, NULL, &req, &ret);
	(void)rc;

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x56, "wrong command set");
	ASSERT_EQ(cmd, 0x08, "wrong command");

	/* Check start_idx encoding (32-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0x44, "start_idx byte 0 wrong");
	ASSERT_EQ(payload[1], 0x33, "start_idx byte 1 wrong");
	ASSERT_EQ(payload[2], 0x22, "start_idx byte 2 wrong");
	ASSERT_EQ(payload[3], 0x11, "start_idx byte 3 wrong");

	/* Check tags_count encoding (32-bit LE at offset 4) */
	ASSERT_EQ(payload[4], 0x04, "tags_count byte 0 wrong");
	ASSERT_EQ(payload[5], 0x03, "tags_count byte 1 wrong");
	ASSERT_EQ(payload[6], 0x02, "tags_count byte 2 wrong");
	ASSERT_EQ(payload[7], 0x01, "tags_count byte 3 wrong");

	return 0;
}

/*
 * Test fmapi_dc_list_tags response (32-bit header fields).
 */
static int test_endian_fmapi_dc_list_tags_response(void)
{
	struct __attribute__((packed)) {
		uint32_t generation_num;
		uint32_t total_num_tags;
		uint32_t num_tags_returned;
		uint8_t validity_bitmap;
		uint8_t rsvd[3];
	} wire_rsp = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp ret = {0};
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {0};
	int rc;

	wire_rsp.generation_num = cpu_to_le32(0x11223344);
	wire_rsp.total_num_tags = cpu_to_le32(0x55667788);
	wire_rsp.num_tags_returned = cpu_to_le32(0); /* No tags to avoid flex array */
	wire_rsp.validity_bitmap = 0xAB;

	req.start_idx = 0;
	req.tags_count = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x56, 0x08, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_fmapi_dc_list_tags(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.generation_num, 0x11223344,
		  "generation_num endianness wrong");
	ASSERT_EQ(ret.total_num_tags, 0x55667788,
		  "total_num_tags endianness wrong");
	ASSERT_EQ(ret.num_tags_returned, 0, "num_tags_returned wrong");
	ASSERT_EQ(ret.validity_bitmap, 0xAB, "validity_bitmap wrong");

	return 0;
}

/*
 * Test get_scan_media_capabilities request encoding (64-bit fields).
 */
static int test_endian_get_scan_media_capabilities_request(void)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp ret = {0};
	uint8_t cmd_set, cmd;
	uint8_t payload[32];
	size_t payload_size = sizeof(payload);
	int rc;

	req.get_scan_media_capabilities_start_physaddr = 0x123456789ABCDEF0ULL;
	req.get_scan_media_capabilities_physaddr_length = 0xFEDCBA9876543210ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* MEDIA_AND_POISON=0x43, GET_SCAN_MEDIA_CAPABILITIES=0x03 */
	cxlmi_mock_set_response(test_ep, 0x43, 0x03, CXLMI_RET_SUCCESS,
				NULL, 0);
	rc = cxlmi_cmd_get_scan_media_capabilities(test_ep, NULL, &req, &ret);
	(void)rc;

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x43, "wrong command set");
	ASSERT_EQ(cmd, 0x03, "wrong command");

	/* Check start_physaddr encoding (64-bit LE at offset 0) */
	ASSERT_EQ(payload[0], 0xF0, "start_physaddr byte 0 wrong");
	ASSERT_EQ(payload[1], 0xDE, "start_physaddr byte 1 wrong");
	ASSERT_EQ(payload[2], 0xBC, "start_physaddr byte 2 wrong");
	ASSERT_EQ(payload[3], 0x9A, "start_physaddr byte 3 wrong");
	ASSERT_EQ(payload[4], 0x78, "start_physaddr byte 4 wrong");
	ASSERT_EQ(payload[5], 0x56, "start_physaddr byte 5 wrong");
	ASSERT_EQ(payload[6], 0x34, "start_physaddr byte 6 wrong");
	ASSERT_EQ(payload[7], 0x12, "start_physaddr byte 7 wrong");

	/* Check physaddr_length encoding (64-bit LE at offset 8) */
	ASSERT_EQ(payload[8], 0x10, "physaddr_length byte 0 wrong");
	ASSERT_EQ(payload[9], 0x32, "physaddr_length byte 1 wrong");
	ASSERT_EQ(payload[10], 0x54, "physaddr_length byte 2 wrong");
	ASSERT_EQ(payload[11], 0x76, "physaddr_length byte 3 wrong");
	ASSERT_EQ(payload[12], 0x98, "physaddr_length byte 4 wrong");
	ASSERT_EQ(payload[13], 0xBA, "physaddr_length byte 5 wrong");
	ASSERT_EQ(payload[14], 0xDC, "physaddr_length byte 6 wrong");
	ASSERT_EQ(payload[15], 0xFE, "physaddr_length byte 7 wrong");

	return 0;
}

/*
 * Test get_scan_media_capabilities response (32-bit field).
 */
static int test_endian_get_scan_media_capabilities_response(void)
{
	struct cxlmi_cmd_get_scan_media_capabilities_rsp wire_rsp = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp ret = {0};
	struct cxlmi_cmd_get_scan_media_capabilities_req req = {0};
	int rc;

	wire_rsp.estimated_scan_media_time = cpu_to_le32(0xDEADBEEF);

	req.get_scan_media_capabilities_start_physaddr = 0;
	req.get_scan_media_capabilities_physaddr_length = 0x1000;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x43, 0x03, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_get_scan_media_capabilities(test_ep, NULL, &req, &ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret.estimated_scan_media_time, 0xDEADBEEF,
		  "estimated_scan_media_time endianness wrong");

	return 0;
}

/*
 * Test fmapi_set_ld_allocations request encoding (64-bit allocation fields).
 */
static int test_endian_fmapi_set_ld_allocations_request(void)
{
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_req) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *req =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_req *)req_buf;
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)ret_buf;
	uint8_t cmd_set, cmd;
	uint8_t payload[64];
	size_t payload_size = sizeof(payload);
	int rc;

	memset(req_buf, 0, sizeof(req_buf));
	memset(ret_buf, 0, sizeof(ret_buf));

	req->number_ld = 2;
	req->start_ld_id = 0;

	req->ld_allocation_list[0].range_1_allocation_mult = 0x123456789ABCDEF0ULL;
	req->ld_allocation_list[0].range_2_allocation_mult = 0xFEDCBA9876543210ULL;

	req->ld_allocation_list[1].range_1_allocation_mult = 0x1122334455667788ULL;
	req->ld_allocation_list[1].range_2_allocation_mult = 0x8877665544332211ULL;

	ASSERT_EQ(setup(), 0, "setup failed");
	/* MLD_COMPONENTS=0x54, SET_LD_ALLOCATIONS=0x02 */
	cxlmi_mock_set_response(test_ep, 0x54, 0x02, CXLMI_RET_SUCCESS,
				NULL, 0);
	rc = cxlmi_cmd_fmapi_set_ld_allocations(test_ep, NULL, req, ret);
	(void)rc;

	cxlmi_mock_get_last_command(test_ep, &cmd_set, &cmd, payload, &payload_size);
	teardown();

	ASSERT_EQ(cmd_set, 0x54, "wrong command set");
	ASSERT_EQ(cmd, 0x02, "wrong command");

	/* Header: number_ld at 0, start_ld_id at 1, rsvd[2] at 2-3 */
	ASSERT_EQ(payload[0], 2, "number_ld wrong");
	ASSERT_EQ(payload[1], 0, "start_ld_id wrong");

	/* LD[0].range_1_allocation_mult (64-bit LE at offset 4) */
	ASSERT_EQ(payload[4], 0xF0, "ld[0].range_1 byte 0 wrong");
	ASSERT_EQ(payload[5], 0xDE, "ld[0].range_1 byte 1 wrong");
	ASSERT_EQ(payload[6], 0xBC, "ld[0].range_1 byte 2 wrong");
	ASSERT_EQ(payload[7], 0x9A, "ld[0].range_1 byte 3 wrong");
	ASSERT_EQ(payload[8], 0x78, "ld[0].range_1 byte 4 wrong");
	ASSERT_EQ(payload[9], 0x56, "ld[0].range_1 byte 5 wrong");
	ASSERT_EQ(payload[10], 0x34, "ld[0].range_1 byte 6 wrong");
	ASSERT_EQ(payload[11], 0x12, "ld[0].range_1 byte 7 wrong");

	/* LD[0].range_2_allocation_mult (64-bit LE at offset 12) */
	ASSERT_EQ(payload[12], 0x10, "ld[0].range_2 byte 0 wrong");
	ASSERT_EQ(payload[13], 0x32, "ld[0].range_2 byte 1 wrong");
	ASSERT_EQ(payload[14], 0x54, "ld[0].range_2 byte 2 wrong");
	ASSERT_EQ(payload[15], 0x76, "ld[0].range_2 byte 3 wrong");
	ASSERT_EQ(payload[16], 0x98, "ld[0].range_2 byte 4 wrong");
	ASSERT_EQ(payload[17], 0xBA, "ld[0].range_2 byte 5 wrong");
	ASSERT_EQ(payload[18], 0xDC, "ld[0].range_2 byte 6 wrong");
	ASSERT_EQ(payload[19], 0xFE, "ld[0].range_2 byte 7 wrong");

	/* LD[1].range_1_allocation_mult (64-bit LE at offset 20) */
	ASSERT_EQ(payload[20], 0x88, "ld[1].range_1 byte 0 wrong");
	ASSERT_EQ(payload[21], 0x77, "ld[1].range_1 byte 1 wrong");
	ASSERT_EQ(payload[22], 0x66, "ld[1].range_1 byte 2 wrong");
	ASSERT_EQ(payload[23], 0x55, "ld[1].range_1 byte 3 wrong");
	ASSERT_EQ(payload[24], 0x44, "ld[1].range_1 byte 4 wrong");
	ASSERT_EQ(payload[25], 0x33, "ld[1].range_1 byte 5 wrong");
	ASSERT_EQ(payload[26], 0x22, "ld[1].range_1 byte 6 wrong");
	ASSERT_EQ(payload[27], 0x11, "ld[1].range_1 byte 7 wrong");

	return 0;
}

/*
 * Test fmapi_set_ld_allocations response (64-bit allocation fields).
 */
static int test_endian_fmapi_set_ld_allocations_response(void)
{
	struct __attribute__((packed)) {
		uint8_t number_ld;
		uint8_t start_ld_id;
		uint8_t rsvd[2];
		struct {
			uint64_t range_1_allocation_mult;
			uint64_t range_2_allocation_mult;
		} ld_list[2];
	} wire_rsp = {0};
	uint8_t ret_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	uint8_t req_buf[sizeof(struct cxlmi_cmd_fmapi_set_ld_allocations_req) +
			2 * sizeof(struct cxlmi_cmd_fmapi_ld_allocations_list)];
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)ret_buf;
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *req =
		(struct cxlmi_cmd_fmapi_set_ld_allocations_req *)req_buf;
	int rc;

	memset(ret_buf, 0, sizeof(ret_buf));
	memset(req_buf, 0, sizeof(req_buf));

	wire_rsp.number_ld = 2;
	wire_rsp.start_ld_id = 0;

	wire_rsp.ld_list[0].range_1_allocation_mult = cpu_to_le64(0x123456789ABCDEF0ULL);
	wire_rsp.ld_list[0].range_2_allocation_mult = cpu_to_le64(0xFEDCBA9876543210ULL);

	wire_rsp.ld_list[1].range_1_allocation_mult = cpu_to_le64(0x1122334455667788ULL);
	wire_rsp.ld_list[1].range_2_allocation_mult = cpu_to_le64(0x8877665544332211ULL);

	req->number_ld = 2;
	req->start_ld_id = 0;

	ASSERT_EQ(setup(), 0, "setup failed");
	cxlmi_mock_set_response(test_ep, 0x54, 0x02, CXLMI_RET_SUCCESS,
				&wire_rsp, sizeof(wire_rsp));
	rc = cxlmi_cmd_fmapi_set_ld_allocations(test_ep, NULL, req, ret);
	teardown();

	ASSERT_EQ(rc, CXLMI_RET_SUCCESS, "command failed");
	ASSERT_EQ(ret->number_ld, 2, "number_ld wrong");
	ASSERT_EQ(ret->start_ld_id, 0, "start_ld_id wrong");

	/* LD[0] */
	ASSERT_TRUE(ret->ld_allocation_list[0].range_1_allocation_mult == 0x123456789ABCDEF0ULL,
		    "ld[0].range_1 endianness wrong");
	ASSERT_TRUE(ret->ld_allocation_list[0].range_2_allocation_mult == 0xFEDCBA9876543210ULL,
		    "ld[0].range_2 endianness wrong");

	/* LD[1] */
	ASSERT_TRUE(ret->ld_allocation_list[1].range_1_allocation_mult == 0x1122334455667788ULL,
		    "ld[1].range_1 endianness wrong");
	ASSERT_TRUE(ret->ld_allocation_list[1].range_2_allocation_mult == 0x8877665544332211ULL,
		    "ld[1].range_2 endianness wrong");

	return 0;
}

/* ============================================================
 * Main
 * ============================================================ */

int main(void)
{
	printf("==========================================================\n");
	printf("libcxlmi Mock Transport Unit Tests\n");
	printf("==========================================================\n");

	TEST_SUITE("Mock Infrastructure");
	RUN_TEST(test_mock_create_close);
	RUN_TEST(test_mock_no_response_returns_unsupported);
	RUN_TEST(test_mock_stats_tracking);
	RUN_TEST(test_mock_clear_responses);
	RUN_TEST(test_mock_payload_size_zero_when_no_payload);
	RUN_TEST(test_mock_response_sequence);
	RUN_TEST(test_mock_response_sequence_helper);

	TEST_SUITE("Generic Component Commands (Info/Status)");
	RUN_TEST(test_cmd_identify);
	RUN_TEST(test_cmd_bg_op_status);
	RUN_TEST(test_cmd_get_response_msg_limit);
	RUN_TEST(test_cmd_set_response_msg_limit);
	RUN_TEST(test_cmd_request_bg_op_abort);

	TEST_SUITE("Events Commands");
	RUN_TEST(test_cmd_get_event_records);
	RUN_TEST(test_cmd_clear_event_records);
	RUN_TEST(test_cmd_get_event_interrupt_policy);
	RUN_TEST(test_cmd_set_event_interrupt_policy);
	RUN_TEST(test_cmd_get_mctp_event_interrupt_policy);
	RUN_TEST(test_cmd_set_mctp_event_interrupt_policy);
	RUN_TEST(test_cmd_event_notification);

	TEST_SUITE("Firmware Update Commands");
	RUN_TEST(test_cmd_get_fw_info);
	RUN_TEST(test_cmd_transfer_fw);
	RUN_TEST(test_cmd_activate_fw);

	TEST_SUITE("Timestamp Commands");
	RUN_TEST(test_cmd_get_timestamp);
	RUN_TEST(test_cmd_set_timestamp);

	TEST_SUITE("Logs Commands");
	RUN_TEST(test_cmd_get_supported_logs);
	RUN_TEST(test_cmd_get_log);
	RUN_TEST(test_cmd_get_log_cel);
	RUN_TEST(test_cmd_get_log_capabilities);
	RUN_TEST(test_cmd_clear_log);
	RUN_TEST(test_cmd_populate_log);
	RUN_TEST(test_cmd_get_supported_logs_sublist);

	TEST_SUITE("Features Commands");
	RUN_TEST(test_cmd_get_supported_features);
	RUN_TEST(test_cmd_get_feature);
	RUN_TEST(test_cmd_set_feature);

	TEST_SUITE("Memory Device Commands");
	RUN_TEST(test_cmd_memdev_identify);
	RUN_TEST(test_cmd_memdev_get_partition_info);
	RUN_TEST(test_cmd_memdev_set_partition_info);
	RUN_TEST(test_cmd_memdev_get_lsa);
	RUN_TEST(test_cmd_memdev_set_lsa);

	TEST_SUITE("Health Info/Alerts Commands");
	RUN_TEST(test_cmd_memdev_get_health_info);
	RUN_TEST(test_cmd_memdev_get_alert_config);
	RUN_TEST(test_cmd_memdev_set_alert_config);
	RUN_TEST(test_cmd_memdev_get_shutdown_state);
	RUN_TEST(test_cmd_memdev_set_shutdown_state);

	TEST_SUITE("Media and Poison Commands");
	RUN_TEST(test_cmd_get_poison_list);
	RUN_TEST(test_cmd_memdev_inject_poison);
	RUN_TEST(test_cmd_memdev_clear_poison);
	RUN_TEST(test_cmd_get_scan_media_capabilities);
	RUN_TEST(test_cmd_scan_media);
	RUN_TEST(test_cmd_get_scan_media_results);

	TEST_SUITE("Sanitize Commands");
	RUN_TEST(test_cmd_memdev_sanitize);
	RUN_TEST(test_cmd_memdev_secure_erase);
	RUN_TEST(test_cmd_memdev_media_operations_discovery);
	RUN_TEST(test_cmd_memdev_media_operations_sanitize);

	TEST_SUITE("Security Commands");
	RUN_TEST(test_cmd_memdev_get_security_state);
	RUN_TEST(test_cmd_memdev_set_passphrase);
	RUN_TEST(test_cmd_memdev_disable_passphrase);
	RUN_TEST(test_cmd_memdev_unlock);
	RUN_TEST(test_cmd_memdev_freeze_security_state);
	RUN_TEST(test_cmd_memdev_passphrase_secure_erase);
	RUN_TEST(test_cmd_memdev_security_send);

	TEST_SUITE("SLD QoS Commands");
	RUN_TEST(test_cmd_memdev_get_sld_qos_control);
	RUN_TEST(test_cmd_memdev_set_sld_qos_control);
	RUN_TEST(test_cmd_memdev_get_sld_qos_status);

	TEST_SUITE("DCD Config Commands");
	RUN_TEST(test_cmd_memdev_get_dc_config);
	RUN_TEST(test_cmd_memdev_get_dc_extent_list);
	RUN_TEST(test_cmd_memdev_add_dc_response);
	RUN_TEST(test_cmd_memdev_release_dc);

	TEST_SUITE("FM-API Physical Switch Commands");
	RUN_TEST(test_cmd_fmapi_identify_sw_device);
	RUN_TEST(test_cmd_fmapi_get_phys_port_state);
	RUN_TEST(test_cmd_fmapi_phys_port_control);
	RUN_TEST(test_cmd_fmapi_send_ppb_cxlio_config_request);
	RUN_TEST(test_cmd_fmapi_get_domain_validation_sv_state);
	RUN_TEST(test_cmd_fmapi_set_domain_validation_sv);
	RUN_TEST(test_cmd_fmapi_get_vcs_domain_validation_sv_state);
	RUN_TEST(test_cmd_fmapi_get_domain_validation_sv);

	TEST_SUITE("FM-API Virtual Switch Commands");
	RUN_TEST(test_cmd_fmapi_bind_vppb);
	RUN_TEST(test_cmd_fmapi_unbind_vppb);

	TEST_SUITE("FM-API MLD Port Commands");
	RUN_TEST(test_cmd_fmapi_send_ld_cxlio_config_request);
	RUN_TEST(test_cmd_fmapi_send_ld_cxlio_mem_request);

	TEST_SUITE("FM-API MLD Components Commands");
	RUN_TEST(test_cmd_fmapi_get_ld_info);
	RUN_TEST(test_cmd_fmapi_get_ld_allocations);
	RUN_TEST(test_cmd_fmapi_set_ld_allocations);
	RUN_TEST(test_cmd_fmapi_get_qos_control);
	RUN_TEST(test_cmd_fmapi_set_qos_control);
	RUN_TEST(test_cmd_fmapi_get_qos_status);
	RUN_TEST(test_cmd_fmapi_get_qos_allocated_bw);
	RUN_TEST(test_cmd_fmapi_set_qos_allocated_bw);
	RUN_TEST(test_cmd_fmapi_get_qos_bw_limit);
	RUN_TEST(test_cmd_fmapi_set_qos_bw_limit);

	TEST_SUITE("FM-API Multi-Headed Commands");
	RUN_TEST(test_cmd_fmapi_get_multiheaded_info);
	RUN_TEST(test_cmd_fmapi_get_head_info);

	TEST_SUITE("FM-API DCD Management Commands");
	RUN_TEST(test_cmd_fmapi_get_dcd_info);
	RUN_TEST(test_cmd_fmapi_get_dc_reg_config);
	RUN_TEST(test_cmd_fmapi_set_dc_region_config);
	RUN_TEST(test_cmd_fmapi_get_dc_region_ext_list);
	RUN_TEST(test_cmd_fmapi_initiate_dc_add);
	RUN_TEST(test_cmd_fmapi_initiate_dc_release);
	RUN_TEST(test_cmd_fmapi_dc_add_reference);
	RUN_TEST(test_cmd_fmapi_dc_remove_reference);
	RUN_TEST(test_cmd_fmapi_dc_list_tags);
	RUN_TEST(test_cmd_memdev_security_receive);
	RUN_TEST(test_cmd_vendor_specific);

	TEST_SUITE("Error Code Handling");
	RUN_TEST(test_error_code_busy);
	RUN_TEST(test_error_code_invalid_input);
	RUN_TEST(test_error_code_internal);
	RUN_TEST(test_error_code_retry);
	RUN_TEST(test_error_code_media_disabled);
	RUN_TEST(test_error_code_abort);
	RUN_TEST(test_error_code_security);
	RUN_TEST(test_error_code_passphrase);
	RUN_TEST(test_error_code_mailbox_unsupported);
	RUN_TEST(test_error_code_payload_length);
	RUN_TEST(test_error_code_log);
	RUN_TEST(test_error_code_interrupted);
	RUN_TEST(test_error_code_fw_in_progress);
	RUN_TEST(test_error_code_fw_out_of_order);
	RUN_TEST(test_error_code_fw_auth);
	RUN_TEST(test_error_code_fw_slot);
	RUN_TEST(test_error_code_fw_rollback);
	RUN_TEST(test_error_code_fw_reset);
	RUN_TEST(test_error_code_invalid_handle);
	RUN_TEST(test_error_code_physical_address);
	RUN_TEST(test_error_code_poison_limit);
	RUN_TEST(test_error_code_media_failure);
	RUN_TEST(test_error_code_feature_version);
	RUN_TEST(test_error_code_feature_selection);
	RUN_TEST(test_error_code_feature_transfer_in_progress);
	RUN_TEST(test_error_code_feature_transfer_out_of_order);
	RUN_TEST(test_error_code_resource_exhausted);
	RUN_TEST(test_error_code_extent_list);
	RUN_TEST(test_error_code_transfer_out_of_order);
	RUN_TEST(test_error_code_no_bg_abort);
	RUN_TEST(test_error_code_background);

	TEST_SUITE("Error Sequence Handling");
	RUN_TEST(test_error_retry_then_success);
	RUN_TEST(test_error_busy_multiple_retries);
	RUN_TEST(test_error_with_partial_response);
	RUN_TEST(test_error_different_commands_different_errors);

	TEST_SUITE("Edge Cases - Variable-Length Responses");
	RUN_TEST(test_edge_get_supported_logs_empty);
	RUN_TEST(test_edge_get_supported_logs_multiple);
	RUN_TEST(test_edge_get_event_records_empty);
	RUN_TEST(test_edge_get_poison_list_empty);
	RUN_TEST(test_edge_get_poison_list_multiple);
	RUN_TEST(test_edge_get_dc_extent_list_empty);
	RUN_TEST(test_edge_fmapi_get_ld_allocations_empty);
	RUN_TEST(test_edge_fmapi_get_ld_allocations_multiple);
	RUN_TEST(test_edge_fmapi_get_phys_port_state_empty);
	RUN_TEST(test_edge_fmapi_get_qos_allocated_bw_empty);
	RUN_TEST(test_edge_fmapi_get_qos_bw_limit_empty);
	RUN_TEST(test_edge_get_supported_features_empty);
	RUN_TEST(test_edge_get_log_cel_empty);
	RUN_TEST(test_edge_get_scan_media_results_empty);

	TEST_SUITE("Edge Cases - Boundary Values");
	RUN_TEST(test_edge_identify_max_values);
	RUN_TEST(test_edge_timestamp_max_value);
	RUN_TEST(test_edge_timestamp_zero_value);
	RUN_TEST(test_edge_health_info_critical);
	RUN_TEST(test_edge_memdev_identify_max_capacity);
	RUN_TEST(test_edge_dc_config_max_regions);
	RUN_TEST(test_edge_qos_status_max_values);
	RUN_TEST(test_edge_fw_info_all_slots);
	RUN_TEST(test_edge_bg_op_status_max_values);
	RUN_TEST(test_edge_event_records_overflow);
	RUN_TEST(test_edge_poison_list_overflow);
	RUN_TEST(test_edge_response_msg_limit_boundaries);

	TEST_SUITE("Request Payload Verification");
	RUN_TEST(test_payload_set_response_msg_limit);
	RUN_TEST(test_payload_get_event_records);
	RUN_TEST(test_payload_set_event_interrupt_policy);
	RUN_TEST(test_payload_clear_event_records);
	RUN_TEST(test_payload_set_timestamp);
	RUN_TEST(test_payload_activate_fw);
	RUN_TEST(test_payload_get_log);
	RUN_TEST(test_payload_clear_log);
	RUN_TEST(test_payload_get_log_capabilities);
	RUN_TEST(test_payload_populate_log);
	RUN_TEST(test_payload_get_supported_logs_sublist);
	RUN_TEST(test_payload_set_partition_info);
	RUN_TEST(test_payload_memdev_get_lsa);
	RUN_TEST(test_payload_get_poison_list);
	RUN_TEST(test_payload_inject_poison);
	RUN_TEST(test_payload_clear_poison);
	RUN_TEST(test_payload_get_scan_media_capabilities);
	RUN_TEST(test_payload_scan_media);
	RUN_TEST(test_payload_set_alert_config);
	RUN_TEST(test_payload_set_shutdown_state);
	RUN_TEST(test_payload_get_dc_config);
	RUN_TEST(test_payload_set_sld_qos_control);
	RUN_TEST(test_payload_command_opcode);
	RUN_TEST(test_payload_fmapi_phys_port_control);
	RUN_TEST(test_payload_fmapi_bind_vppb);
	RUN_TEST(test_payload_fmapi_unbind_vppb);
	RUN_TEST(test_payload_fmapi_get_ld_allocations);
	RUN_TEST(test_payload_fmapi_set_qos_control);
	RUN_TEST(test_payload_transfer_fw);
	RUN_TEST(test_payload_memdev_set_lsa);
	RUN_TEST(test_payload_memdev_add_dc_response);
	RUN_TEST(test_payload_memdev_release_dc);
	RUN_TEST(test_payload_fmapi_set_ld_allocations);
	RUN_TEST(test_payload_fmapi_set_qos_allocated_bw);
	RUN_TEST(test_payload_fmapi_set_qos_bw_limit);
	RUN_TEST(test_payload_security_send);
	RUN_TEST(test_payload_media_operations_sanitize);
	RUN_TEST(test_payload_fmapi_get_phys_port_state);
	RUN_TEST(test_payload_set_feature);
	RUN_TEST(test_payload_get_feature);
	RUN_TEST(test_payload_memdev_set_passphrase);
	RUN_TEST(test_payload_memdev_disable_passphrase);
	RUN_TEST(test_payload_memdev_unlock);
	RUN_TEST(test_payload_memdev_passphrase_secure_erase);
	RUN_TEST(test_payload_memdev_get_dc_extent_list);
	RUN_TEST(test_payload_fmapi_get_qos_allocated_bw);
	RUN_TEST(test_payload_fmapi_get_qos_bw_limit);
	RUN_TEST(test_payload_fmapi_initiate_dc_add);
	RUN_TEST(test_payload_fmapi_initiate_dc_release);
	RUN_TEST(test_payload_fmapi_send_ld_cxlio_mem_request);
	RUN_TEST(test_payload_event_notification);
	RUN_TEST(test_payload_set_mctp_event_interrupt_policy);
	RUN_TEST(test_payload_get_log_cel);
	RUN_TEST(test_payload_get_supported_features);
	RUN_TEST(test_payload_memdev_media_operations_discovery);
	RUN_TEST(test_payload_memdev_security_receive);
	RUN_TEST(test_payload_fmapi_get_multiheaded_info);
	RUN_TEST(test_payload_fmapi_get_head_info);
	RUN_TEST(test_payload_fmapi_send_ppb_cxlio_config_request);
	RUN_TEST(test_payload_fmapi_send_ld_cxlio_config_request);
	RUN_TEST(test_payload_fmapi_get_domain_validation_sv);
	RUN_TEST(test_payload_fmapi_set_domain_validation_sv);
	RUN_TEST(test_payload_fmapi_get_vcs_domain_validation_sv_state);
	RUN_TEST(test_payload_fmapi_get_dc_reg_config);
	RUN_TEST(test_payload_fmapi_set_dc_region_config);
	RUN_TEST(test_payload_fmapi_get_dc_region_ext_list);
	RUN_TEST(test_payload_fmapi_dc_add_reference);
	RUN_TEST(test_payload_fmapi_dc_remove_reference);
	RUN_TEST(test_payload_fmapi_dc_list_tags);
	RUN_TEST(test_payload_vendor_specific);

	TEST_SUITE("Response Payload Verification");
	RUN_TEST(test_response_identify);
	RUN_TEST(test_response_bg_op_status);
	RUN_TEST(test_response_get_timestamp);
	RUN_TEST(test_response_memdev_identify);
	RUN_TEST(test_response_memdev_get_partition_info);
	RUN_TEST(test_response_memdev_get_health_info);
	RUN_TEST(test_response_memdev_get_alert_config);
	RUN_TEST(test_response_fmapi_identify_sw_device);
	RUN_TEST(test_response_fmapi_get_ld_info);
	RUN_TEST(test_response_fmapi_get_qos_status);
	RUN_TEST(test_response_get_fw_info);
	RUN_TEST(test_response_memdev_get_poison_list);
	RUN_TEST(test_response_get_event_records);
	RUN_TEST(test_response_get_supported_logs);
	RUN_TEST(test_response_get_response_msg_limit);
	RUN_TEST(test_response_memdev_get_shutdown_state);
	RUN_TEST(test_response_memdev_get_security_state);
	RUN_TEST(test_response_memdev_get_sld_qos_control);
	RUN_TEST(test_response_memdev_get_sld_qos_status);
	RUN_TEST(test_response_fmapi_get_qos_control);
	RUN_TEST(test_response_get_scan_media_capabilities);
	RUN_TEST(test_response_get_scan_media_results);
	RUN_TEST(test_response_memdev_get_dc_config);
	RUN_TEST(test_response_fmapi_get_ld_allocations);
	RUN_TEST(test_response_fmapi_get_qos_allocated_bw);
	RUN_TEST(test_response_fmapi_get_qos_bw_limit);
	RUN_TEST(test_response_get_event_interrupt_policy);
	RUN_TEST(test_response_get_mctp_event_interrupt_policy);
	RUN_TEST(test_response_get_log_capabilities);
	RUN_TEST(test_response_get_supported_logs_sublist);
	RUN_TEST(test_response_get_supported_features);
	RUN_TEST(test_response_get_feature);
	RUN_TEST(test_response_memdev_get_dc_extent_list);
	RUN_TEST(test_response_fmapi_get_phys_port_state);
	RUN_TEST(test_response_fmapi_get_dcd_info);
	RUN_TEST(test_response_fmapi_get_multiheaded_info);
	RUN_TEST(test_response_fmapi_get_head_info);
	RUN_TEST(test_response_fmapi_get_dc_reg_config);
	RUN_TEST(test_response_fmapi_get_dc_region_ext_list);
	RUN_TEST(test_response_fmapi_dc_list_tags);
	RUN_TEST(test_response_memdev_media_operations_discovery);
	RUN_TEST(test_response_fmapi_get_domain_validation_sv_state);
	RUN_TEST(test_response_fmapi_get_vcs_domain_validation_sv_state);
	RUN_TEST(test_response_fmapi_get_domain_validation_sv);
	RUN_TEST(test_response_fmapi_send_ppb_cxlio_config_request);
	RUN_TEST(test_response_fmapi_send_ld_cxlio_config_request);
	RUN_TEST(test_response_fmapi_send_ld_cxlio_mem_request);
	RUN_TEST(test_response_fmapi_set_ld_allocations);
	RUN_TEST(test_response_fmapi_set_qos_control);
	RUN_TEST(test_response_fmapi_set_qos_allocated_bw);
	RUN_TEST(test_response_fmapi_set_qos_bw_limit);
	RUN_TEST(test_response_get_log_cel);

	TEST_SUITE("Endianness Verification");
	RUN_TEST(test_endian_identify_16bit);
	RUN_TEST(test_endian_identify_64bit);
	RUN_TEST(test_endian_set_timestamp_request);
	RUN_TEST(test_endian_get_timestamp_response);
	RUN_TEST(test_endian_get_log_request);
	RUN_TEST(test_endian_memdev_identify_capacity);
	RUN_TEST(test_endian_bg_op_status);
	RUN_TEST(test_endian_event_records_timestamps);
	RUN_TEST(test_endian_inject_poison_request);
	RUN_TEST(test_endian_supported_logs_size);
	RUN_TEST(test_endian_set_feature_request);
	RUN_TEST(test_endian_partition_info);
	RUN_TEST(test_endian_health_info);
	RUN_TEST(test_endian_get_alert_config);
	RUN_TEST(test_endian_set_alert_config_request);
	RUN_TEST(test_endian_fmapi_get_dcd_info);
	RUN_TEST(test_endian_get_poison_list_request);
	RUN_TEST(test_endian_get_poison_list_response);
	RUN_TEST(test_endian_scan_media_request);
	RUN_TEST(test_endian_get_scan_media_results);
	RUN_TEST(test_endian_get_supported_features_request);
	RUN_TEST(test_endian_get_supported_features_response);
	RUN_TEST(test_endian_memdev_get_dc_config);
	RUN_TEST(test_endian_get_dc_extent_list_request);
	RUN_TEST(test_endian_get_dc_extent_list_response);
	RUN_TEST(test_endian_get_event_records);
	RUN_TEST(test_endian_fmapi_get_dc_region_ext_list_request);
	RUN_TEST(test_endian_fmapi_get_dc_region_ext_list_response);
	RUN_TEST(test_endian_fmapi_get_dc_reg_config_request);
	RUN_TEST(test_endian_fmapi_get_dc_reg_config_response);
	RUN_TEST(test_endian_fmapi_initiate_dc_add_request);
	RUN_TEST(test_endian_fmapi_initiate_dc_release_request);
	RUN_TEST(test_endian_get_log_cel);
	RUN_TEST(test_endian_fmapi_dc_list_tags_request);
	RUN_TEST(test_endian_fmapi_dc_list_tags_response);
	RUN_TEST(test_endian_get_scan_media_capabilities_request);
	RUN_TEST(test_endian_get_scan_media_capabilities_response);
	RUN_TEST(test_endian_fmapi_set_ld_allocations_request);
	RUN_TEST(test_endian_fmapi_set_ld_allocations_response);

	printf("\n==========================================================\n");
	printf("Results: %d passed, %d failed, %d total\n",
	       tests_passed, tests_failed, tests_run);
	printf("==========================================================\n");

	return tests_failed > 0 ? 1 : 0;
}
