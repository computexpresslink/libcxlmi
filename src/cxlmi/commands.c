// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <stdlib.h>

#include <ccan/endian/endian.h>

#include <libcxlmi.h>

#include "private.h"

CXLMI_EXPORT int cxlmi_cmd_identify(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_identify *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_identify *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 18);

	arm_cci_request(ep, &req, 0, INFOSTAT, IS_IDENTIFY);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_identify *)rsp->payload;

	ret->vendor_id = le16_to_cpu(rsp_pl->vendor_id);
	ret->device_id = le16_to_cpu(rsp_pl->device_id);
	ret->subsys_vendor_id = le16_to_cpu(rsp_pl->subsys_vendor_id);
	ret->subsys_id = le16_to_cpu(rsp_pl->subsys_id);
	ret->serial_num = le64_to_cpu(rsp_pl->serial_num);
	ret->max_msg_size = rsp_pl->max_msg_size;
	ret->component_type = rsp_pl->component_type;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_bg_op_status *ret)
{
	struct cxlmi_cmd_bg_op_status *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_STATUS);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_bg_op_status *)rsp->payload;
	ret->status = rsp_pl->status;
	ret->opcode = le16_to_cpu(rsp_pl->opcode);
	ret->returncode = le16_to_cpu(rsp_pl->returncode);
	ret->vendor_ext_status = le16_to_cpu(rsp_pl->vendor_ext_status);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_response_msg_limit(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_get_response_msg_limit *ret)
{
	struct cxlmi_cmd_get_response_msg_limit *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	arm_cci_request(ep, &req, 0, INFOSTAT, GET_RESP_MSG_LIMIT);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_response_msg_limit *)rsp->payload;
	ret->limit = rsp_pl->limit;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_set_response_msg_limit *in)
{
	struct cxlmi_cmd_get_response_msg_limit *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 1);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), INFOSTAT, SET_RESP_MSG_LIMIT);

	req_pl = (struct cxlmi_cmd_get_response_msg_limit *)req->payload;
	req_pl->limit = in->limit;

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep,
					       struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, INFOSTAT, BACKGROUND_OPERATION_ABORT);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_event_records(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_get_event_records_req *in,
				     struct cxlmi_cmd_get_event_records_rsp *ret)
{
	struct cxlmi_cmd_get_event_records_rsp *rsp_pl;
	struct cxlmi_cmd_get_event_records_req *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz, req_sz;
	int i, rc;

	req_sz = sizeof(*req) + sizeof(*req_pl);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), EVENTS, GET_RECORDS);
	req_pl = (struct cxlmi_cmd_get_event_records_req *)req->payload;
	req_pl->event_log = in->event_log;

	/*
	 * This command shall retrieve as many event records from the
	 * event log that fit into the mailbox output payload (1mb).
	 */
	rsp_sz = sizeof(*rsp) + (CXLMI_MAX_SUPPORTED_EVENT_RECORDS * sizeof(*rsp_pl->records));
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_event_records_rsp *)rsp->payload;
	ret->flags = rsp_pl->flags;
	ret->overflow_err_count = le16_to_cpu(rsp_pl->overflow_err_count);
	ret->first_overflow_timestamp =
		le64_to_cpu(rsp_pl->first_overflow_timestamp);
	ret->last_overflow_timestamp =
		le64_to_cpu(rsp_pl->last_overflow_timestamp);
	ret->record_count = le16_to_cpu(rsp_pl->record_count);

	for (i = 0; i < ret->record_count; i++) {
		memcpy(ret->records[i].uuid, rsp_pl->records[i].uuid, 0x10);
		ret->records[i].length = rsp_pl->records[i].length;
		ret->records[i].handle = le16_to_cpu(rsp_pl->records[i].handle);
		ret->records[i].timestamp =
			le64_to_cpu(rsp_pl->records[i].timestamp);
		ret->records[i].maint_op_class =
			rsp_pl->records[i].maint_op_class;
		ret->records[i].maint_op_subclass =
			rsp_pl->records[i].maint_op_subclass;
		memcpy(ret->records[i].data, rsp_pl->records[i].data,
		       sizeof(rsp_pl->records[i].data));
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_clear_event_records(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_clear_event_records *in)
{
	struct cxlmi_cmd_clear_event_records *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	ssize_t req_sz, handles_sz = (in->nr_recs) * sizeof(*(in->handles));
	int rc = -1;

	req_sz = sizeof(*req_pl) + handles_sz + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), EVENTS, CLEAR_RECORDS);
	req_pl = (struct cxlmi_cmd_clear_event_records *)req->payload;

	req_pl->event_log = in->event_log;
	req_pl->clear_flags = in->clear_flags;
	req_pl->nr_recs = in->nr_recs;
	memcpy(req_pl->handles, in->handles, handles_sz);

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_get_event_interrupt_policy(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_event_interrupt_policy *ret)
{
	struct cxlmi_cmd_get_event_interrupt_policy *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 5);

	arm_cci_request(ep, &req, 0, EVENTS, GET_EVENT_IRQ_POL);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_event_interrupt_policy *)rsp->payload;
	ret->informational_settings = rsp_pl->informational_settings;
	ret->warning_settings = rsp_pl->warning_settings;
	ret->failure_settings = rsp_pl->failure_settings;
	ret->fatal_settings = rsp_pl->fatal_settings;
	ret->dcd_settings = rsp_pl->dcd_settings;

	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_set_event_interrupt_policy(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_set_event_interrupt_policy *in)
{
	struct cxlmi_cmd_set_event_interrupt_policy *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 5);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), EVENTS, SET_EVENT_IRQ_POL);

	req_pl = (struct cxlmi_cmd_set_event_interrupt_policy *)req->payload;
	req_pl->informational_settings = in->informational_settings;
	req_pl->warning_settings = in->warning_settings;
	req_pl->failure_settings = in->failure_settings;
	req_pl->fatal_settings = in->fatal_settings;
	req_pl->dcd_settings = in->dcd_settings;

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_get_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_mctp_event_interrupt_policy *ret)
{
	struct cxlmi_cmd_get_mctp_event_interrupt_policy *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 2);

	arm_cci_request(ep, &req, 0, EVENTS, GET_MCTP_EVENT_IRQ_POL);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_mctp_event_interrupt_policy *)rsp->payload;
	ret->event_interrupt_settings = le16_to_cpu(rsp_pl->event_interrupt_settings);

	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_set_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_set_mctp_event_interrupt_policy *in)
{
	struct cxlmi_cmd_set_mctp_event_interrupt_policy *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), EVENTS, SET_MCTP_EVENT_IRQ_POL);

	req_pl = (struct cxlmi_cmd_set_mctp_event_interrupt_policy *)req->payload;
	req_pl->event_interrupt_settings =
		cpu_to_le16(in->event_interrupt_settings);

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_event_notification(struct cxlmi_endpoint *ep,
				      struct cxlmi_tunnel_info *ti,
				      struct cxlmi_cmd_event_notification *in)
{
	struct cxlmi_cmd_event_notification *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), EVENTS, NOTIFICATION);

	req_pl = (struct cxlmi_cmd_event_notification *)req->payload;
	req_pl->event = cpu_to_le16(in->event);

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_fw_info(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_get_fw_info *ret)
{
	struct cxlmi_cmd_get_fw_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x50);

	arm_cci_request(ep, &req, 0, FIRMWARE_UPDATE, GET_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_fw_info *)rsp->payload;
	ret->slots_supported = rsp_pl->slots_supported;
	ret->slot_info = rsp_pl->slot_info;
	ret->caps = rsp_pl->caps;
	pstrcpy(ret->fw_rev1, sizeof(rsp_pl->fw_rev1), rsp_pl->fw_rev1);
	pstrcpy(ret->fw_rev2, sizeof(rsp_pl->fw_rev2), rsp_pl->fw_rev2);
	pstrcpy(ret->fw_rev3, sizeof(rsp_pl->fw_rev3), rsp_pl->fw_rev3);
	pstrcpy(ret->fw_rev4, sizeof(rsp_pl->fw_rev4), rsp_pl->fw_rev4);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_transfer_fw(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_transfer_fw *in)
{
	struct cxlmi_cmd_transfer_fw *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	ssize_t req_sz, data_sz = struct_size(in, data, 0);
	int rc = -1;

	req_sz = sizeof(*req_pl) + data_sz + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), FIRMWARE_UPDATE, TRANSFER);
	req_pl = (struct cxlmi_cmd_transfer_fw *)req->payload;

	req_pl->action = in->action;
	req_pl->slot = in->slot;
	req_pl->offset = cpu_to_le32(in->offset);
	memcpy(req_pl->data, in->data, data_sz);

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_activate_fw(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_activate_fw *in)
{
	struct cxlmi_cmd_activate_fw *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	int rc = 0;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), FIRMWARE_UPDATE, ACTIVATE);

	req_pl = (struct cxlmi_cmd_activate_fw *)req->payload;
	req_pl->action = in->slot;
	req_pl->slot = in->slot;

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_get_timestamp *ret)
{
	struct cxlmi_cmd_get_timestamp *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, TIMESTAMP, GET);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_timestamp *)rsp->payload;
	ret->timestamp = le64_to_cpu(rsp_pl->timestamp);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_set_timestamp *in)
{
	struct cxlmi_cmd_set_timestamp *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 8);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), TIMESTAMP, SET);

	req_pl = (struct cxlmi_cmd_set_timestamp *)req->payload;
	req_pl->timestamp = cpu_to_le64(in->timestamp);

	return send_cmd_cci(ep, ti, req, req_sz,
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				      struct cxlmi_tunnel_info *ti,
				      struct cxlmi_cmd_get_supported_logs *ret)
{
	struct cxlmi_cmd_get_supported_logs *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp;
	int rc, i;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, LOGS, GET_SUPPORTED);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) +
		CXLMI_MAX_SUPPORTED_LOGS * sizeof(*rsp_pl->entries);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz,
			  sizeof(*rsp) + sizeof(*rsp_pl));
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_supported_logs *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_supported_log_entries =
		le16_to_cpu(rsp_pl->num_supported_log_entries);

	for (i = 0; i < rsp_pl->num_supported_log_entries; i++) {
		memcpy(ret->entries[i].uuid, rsp_pl->entries[i].uuid,
		       sizeof(rsp_pl->entries[i].uuid));
		ret->entries[i].log_size =
			le32_to_cpu(rsp_pl->entries[i].log_size);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_log(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_get_log_req *in,
				   void *ret)
{
	struct cxlmi_cmd_get_log_req *req_pl;
	struct cxlmi_cmd_get_log_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg  *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_LOG);
	req_pl = (struct cxlmi_cmd_get_log_req *)req->payload;

	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));
	req_pl->offset = cpu_to_le32(in->offset);
	req_pl->length = cpu_to_le32(in->length);

	rsp_sz = sizeof(*rsp) + in->length;
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return rc;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (void *)rsp->payload;
	memcpy(ret, rsp_pl, in->length * sizeof(*rsp_pl));

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_get_log_cel(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_get_log_req *in,
				       struct cxlmi_cmd_get_log_cel_rsp *ret)
{
	struct cxlmi_cmd_get_log_req *req_pl;
	struct cxlmi_cmd_get_log_cel_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg  *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_LOG);
	req_pl = (struct cxlmi_cmd_get_log_req *)req->payload;

	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));
	req_pl->offset = cpu_to_le32(in->offset);
	req_pl->length = cpu_to_le32(in->length);

	rsp_sz = sizeof(*rsp) + in->length;
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return rc;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_log_cel_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	for (i = 0; i < in->length / sizeof(*rsp_pl); i++) {
		ret[i].opcode = le16_to_cpu(rsp_pl[i].opcode);
		ret[i].command_effect =
			le16_to_cpu(rsp_pl[i].command_effect);
	}

	return rc;
}

CXLMI_EXPORT
int cxlmi_cmd_get_log_capabilities(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_get_log_capabilities_req *in,
			   struct cxlmi_cmd_get_log_capabilities_rsp *ret)
{
	struct cxlmi_cmd_get_log_capabilities_req *req_pl;
	struct cxlmi_cmd_get_log_capabilities_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x10);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 4);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_LOG_CAPS);
	req_pl = (struct cxlmi_cmd_get_log_capabilities_req *)req->payload;

	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_log_capabilities_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->parameter_flags = le32_to_cpu(rsp_pl->parameter_flags);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_clear_log(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_clear_log *in)
{
	struct cxlmi_cmd_clear_log *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), LOGS, CLEAR_LOG);

	req_pl = (struct cxlmi_cmd_clear_log *)req->payload;
	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	return send_cmd_cci(ep, ti, req, req_sz,
			  &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_populate_log(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_populate_log *in)
{
	struct cxlmi_cmd_populate_log *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), LOGS, POPULATE_LOG);

	req_pl = (struct cxlmi_cmd_populate_log *)req->payload;
	memcpy(req_pl->uuid, in->uuid, sizeof(in->uuid));

	return send_cmd_cci(ep, ti, req, req_sz,
			  &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_get_supported_logs_sublist(struct cxlmi_endpoint *ep,
		     struct cxlmi_tunnel_info *ti,
		     struct cxlmi_cmd_get_supported_logs_sublist_req *in,
		     struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret)
{
	struct cxlmi_cmd_get_supported_logs_sublist_req *req_pl;
	struct cxlmi_cmd_get_supported_logs_sublist_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), LOGS, GET_SUPPORTED_SUBLIST);
	req_pl = (struct cxlmi_cmd_get_supported_logs_sublist_req *)req->payload;

	req_pl->max_supported_log_entries = in->max_supported_log_entries;
	req_pl->start_log_entry_index = in->start_log_entry_index;

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) +
		CXLMI_MAX_SUPPORTED_LOGS * sizeof(*rsp_pl->entries);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_supported_logs_sublist_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_supported_log_entries = rsp_pl->num_supported_log_entries;
	ret->total_num_supported_log_entries =
		le16_to_cpu(rsp_pl->total_num_supported_log_entries);
	ret->start_log_entry_index = rsp_pl->start_log_entry_index;

	for (i = 0; i < rsp_pl->num_supported_log_entries; i++) {
		memcpy(ret->entries[i].uuid, rsp_pl->entries[i].uuid,
		       sizeof(rsp_pl->entries[i].uuid));
		ret->entries[i].log_size =
			le32_to_cpu(rsp_pl->entries[i].log_size);
	}

	return rc;
}


CXLMI_EXPORT int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_identify *ret)
{
	struct cxlmi_cmd_memdev_identify *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x45);

	arm_cci_request(ep, &req, 0, IDENTIFY, MEMORY_DEVICE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_identify *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	memcpy(ret->fw_revision, rsp_pl->fw_revision,
	       sizeof(rsp_pl->fw_revision));
	ret->total_capacity = le64_to_cpu(rsp_pl->total_capacity);
	ret->volatile_capacity = le64_to_cpu(rsp_pl->volatile_capacity);
	ret->persistent_capacity = le64_to_cpu(rsp_pl->persistent_capacity);
	ret->partition_align = le64_to_cpu(rsp_pl->partition_align);
	ret->info_event_log_size = le16_to_cpu(rsp_pl->info_event_log_size);
	ret->warning_event_log_size = le16_to_cpu(rsp_pl->warning_event_log_size);
	ret->failure_event_log_size = le16_to_cpu(rsp_pl->failure_event_log_size);
	ret->fatal_event_log_size = le16_to_cpu(rsp_pl->fatal_event_log_size);
	ret->lsa_size = le32_to_cpu(rsp_pl->lsa_size);
	/* TODO unaligned ie: get_unaligned_le24(rsp_pl->poison_list_max_mer); */
	memcpy(ret->poison_list_max_mer, rsp_pl->poison_list_max_mer,
	       sizeof(rsp_pl->poison_list_max_mer));
	ret->inject_poison_limit = le16_to_cpu(rsp_pl->inject_poison_limit);
	ret->poison_caps = rsp_pl->poison_caps;
	ret->qos_telemetry_caps = rsp_pl->qos_telemetry_caps;
	ret->dc_event_log_size = le16_to_cpu(rsp_pl->dc_event_log_size);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_partition_info(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_get_partition_info *ret)
{
	struct cxlmi_cmd_memdev_get_partition_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 32);

	arm_cci_request(ep, &req, 0, CCLS, GET_PARTITION_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_partition_info *)rsp->payload;
	ret->active_vmem = le64_to_cpu(rsp_pl->active_vmem);
	ret->active_pmem = le64_to_cpu(rsp_pl->active_pmem);
	ret->next_vmem = le64_to_cpu(rsp_pl->next_vmem);
	ret->next_pmem = le64_to_cpu(rsp_pl->next_pmem);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_partition_info(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_set_partition_info *in)
{
	struct cxlmi_cmd_memdev_set_partition_info  *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 9);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), CCLS, SET_PARTITION_INFO);

	req_pl = (struct cxlmi_cmd_memdev_set_partition_info *)req->payload;
	req_pl->volatile_capacity = cpu_to_le64(in->volatile_capacity);
	req_pl->flags = in->flags;

	return send_cmd_cci(ep, ti, req, req_sz,
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_memdev_get_lsa *ret)
{
	struct cxlmi_cmd_memdev_get_lsa *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 8);

	arm_cci_request(ep, &req, 0, CCLS, GET_LSA);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_lsa *)rsp->payload;
	ret->offset = le32_to_cpu(rsp_pl->offset);
	ret->length = le32_to_cpu(rsp_pl->length);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_memdev_set_lsa *in)
{
	struct cxlmi_cmd_memdev_set_lsa  *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz, data_sz = struct_size(in, data, 0);

	req_sz = sizeof(*req) + data_sz + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), CCLS, SET_LSA);

	req_pl = (struct cxlmi_cmd_memdev_set_lsa *)req->payload;
	req_pl->offset = cpu_to_le32(in->offset);

	return send_cmd_cci(ep, ti, req, req_sz,
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_health_info(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_get_health_info *ret)
{
	struct cxlmi_cmd_memdev_get_health_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, HEALTH_INFO_ALERTS, GET_HEALTH_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_health_info *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->health_status = rsp_pl->health_status;
	ret->media_status = rsp_pl->media_status;
	ret->additional_status = rsp_pl->additional_status;
	ret->life_used = rsp_pl->life_used;
	ret->device_temperature = le16_to_cpu(rsp_pl->device_temperature);
	ret->dirty_shutdown_count = le32_to_cpu(rsp_pl->dirty_shutdown_count);
	ret->corrected_volatile_error_count =
		le32_to_cpu(rsp_pl->corrected_volatile_error_count);
	ret->corrected_persistent_error_count =
		le32_to_cpu(rsp_pl->corrected_persistent_error_count);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_get_alert_config *ret)
{
	struct cxlmi_cmd_memdev_get_alert_config *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, HEALTH_INFO_ALERTS, GET_ALERT_CONFIG);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_alert_config *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->valid_alerts = rsp_pl->valid_alerts;
	ret->programmable_alerts = rsp_pl->programmable_alerts;
	ret->life_used_critical_alert_threshold =
		rsp_pl->life_used_critical_alert_threshold;
	ret->life_used_programmable_warning_threshold =
		rsp_pl->life_used_programmable_warning_threshold;
	ret->device_over_temperature_critical_alert_threshold =
		le16_to_cpu(rsp_pl->device_over_temperature_critical_alert_threshold);
	ret->device_under_temperature_critical_alert_threshold =
		le16_to_cpu(rsp_pl->device_under_temperature_critical_alert_threshold);
	ret->device_over_temperature_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->device_over_temperature_programmable_warning_threshold);
	ret->device_under_temperature_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->device_under_temperature_programmable_warning_threshold);
	ret->corrected_volatile_mem_error_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->corrected_volatile_mem_error_programmable_warning_threshold);
	ret->corrected_persistent_mem_error_programmable_warning_threshold =
		le16_to_cpu(rsp_pl->corrected_persistent_mem_error_programmable_warning_threshold);

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_alert_config(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_set_alert_config *in)
{
	struct cxlmi_cmd_memdev_set_alert_config *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), HEALTH_INFO_ALERTS, SET_ALERT_CONFIG);

	req_pl = (struct cxlmi_cmd_memdev_set_alert_config *)req->payload;

	req_pl->valid_alert_actions = in->valid_alert_actions;
	req_pl->enable_alert_actions = in->enable_alert_actions;
	req_pl->life_used_programmable_warning_threshold =
		in->life_used_programmable_warning_threshold;
	req_pl->device_over_temperature_programmable_warning_threshold =
		cpu_to_le16(in->device_over_temperature_programmable_warning_threshold);
	req_pl->device_under_temperature_programmable_warning_threshold =
		cpu_to_le16(in->device_under_temperature_programmable_warning_threshold);
	req_pl->corrected_volatile_mem_error_programmable_warning_threshold =
		cpu_to_le16(in->corrected_volatile_mem_error_programmable_warning_threshold);
	req_pl->corrected_persistent_mem_error_programmable_warning_threshold =
		cpu_to_le16(in->corrected_persistent_mem_error_programmable_warning_threshold);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_shutdown_state(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_get_shutdown_state *ret)
{
	struct cxlmi_cmd_memdev_get_shutdown_state *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, HEALTH_INFO_ALERTS, GET_SHUTDOWN_STATE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_shutdown_state *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->state = rsp_pl->state;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_shutdown_state(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_set_shutdown_state *in)
{
	struct cxlmi_cmd_memdev_set_shutdown_state *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), HEALTH_INFO_ALERTS, SET_SHUTDOWN_STATE);

	req_pl = (struct cxlmi_cmd_memdev_set_shutdown_state *)req->payload;

	req_pl->state = in->state;

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_get_poison_list(struct cxlmi_endpoint *ep,
		     struct cxlmi_tunnel_info *ti,
		     struct cxlmi_cmd_memdev_get_poison_list_req *in,
		     struct cxlmi_cmd_memdev_get_poison_list_rsp *ret)
{
	struct cxlmi_cmd_memdev_get_poison_list_req *req_pl;
	struct cxlmi_cmd_memdev_get_poison_list_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), MEDIA_AND_POISON, GET_POISON_LIST);
	req_pl = (struct cxlmi_cmd_memdev_get_poison_list_req *)req->payload;

	req_pl->get_poison_list_phy_addr = cpu_to_le64(in->get_poison_list_phy_addr);
	req_pl->get_poison_list_phy_addr_len = cpu_to_le64(in->get_poison_list_phy_addr_len);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_poison_list_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->poison_list_flags = rsp_pl->poison_list_flags;
	ret->overflow_timestamp =
		le64_to_cpu(rsp_pl->overflow_timestamp);
	ret->more_err_media_record_cnt = le16_to_cpu(rsp_pl->more_err_media_record_cnt);

	for (i = 0; i < rsp_pl->more_err_media_record_cnt; i++) {
		ret->records[i].media_err_addr =
			le64_to_cpu(rsp_pl->records[i].media_err_addr);
		ret->records[i].media_err_len =
			le32_to_cpu(rsp_pl->records[i].media_err_len);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_inject_poison(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_inject_poison *in)
{
	struct cxlmi_cmd_memdev_inject_poison *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), MEDIA_AND_POISON, INJECT_POISON);

	req_pl = (struct cxlmi_cmd_memdev_inject_poison *)req->payload;

	req_pl->inject_poison_phy_addr = cpu_to_le64(in->inject_poison_phy_addr);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_clear_poison(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_clear_poison *in)
{
	struct cxlmi_cmd_memdev_clear_poison *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), MEDIA_AND_POISON, CLEAR_POISON);

	req_pl = (struct cxlmi_cmd_memdev_clear_poison *)req->payload;

	req_pl->clear_poison_phy_addr = cpu_to_le64(in->clear_poison_phy_addr);
	memcpy(req_pl->clear_poison_write_data, in->clear_poison_write_data,
	       sizeof(in->clear_poison_write_data));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_scan_media_capabilities(struct cxlmi_endpoint *ep,
				       struct cxlmi_tunnel_info *ti,
				       struct cxlmi_cmd_get_scan_media_capabilities_req *in,
				       struct cxlmi_cmd_get_scan_media_capabilities_rsp *ret)
{
	struct cxlmi_cmd_get_scan_media_capabilities_req *req_pl;
	struct cxlmi_cmd_get_scan_media_capabilities_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc = -1;
	ssize_t req_sz, rsp_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x10);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 4);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), MEDIA_AND_POISON, GET_SCAN_MEDIA_CAPABILITIES);

	req_pl = (struct cxlmi_cmd_get_scan_media_capabilities_req *)req->payload;
	req_pl->get_scan_media_capabilities_start_physaddr =
		cpu_to_le64(in->get_scan_media_capabilities_start_physaddr);
	req_pl->get_scan_media_capabilities_physaddr_length =
		cpu_to_le64(in->get_scan_media_capabilities_physaddr_length);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;
	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_scan_media_capabilities_rsp *)rsp->payload;

	memset(ret, 0, sizeof(*ret));
	ret->estimated_scan_media_time = le32_to_cpu(rsp_pl->estimated_scan_media_time);
	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_scan_media(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_scan_media *in)
{
	struct cxlmi_cmd_scan_media *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 17);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), MEDIA_AND_POISON, SCAN_MEDIA);

	req_pl = (struct cxlmi_cmd_scan_media *)req->payload;
	req_pl->scan_media_physaddr = cpu_to_le64(in->scan_media_physaddr);
	req_pl->scan_media_physaddr_length = cpu_to_le64(in->scan_media_physaddr_length);
	req_pl->scan_media_flags = cpu_to_le16(in->scan_media_flags);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_get_scan_media_results(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_get_scan_media_results *ret)
{
	struct cxlmi_cmd_get_scan_media_results *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int i, rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, MEDIA_AND_POISON, GET_SCAN_MEDIA_RESULTS);
	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_get_scan_media_results *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->scan_media_restart_physaddr =
		le64_to_cpu(rsp_pl->scan_media_restart_physaddr);
	ret->scan_media_restart_physaddr_length =
		le64_to_cpu(rsp_pl->scan_media_restart_physaddr_length);
	ret->scan_media_flags = rsp_pl->scan_media_flags;
	ret->media_error_count = le16_to_cpu(rsp_pl->media_error_count);
	for (i = 0; i < ret->media_error_count; i++) {
		ret->record[i].media_error_address =
			le64_to_cpu(rsp_pl->record[i].media_error_address);
		ret->record[i].media_error_length =
			le32_to_cpu(rsp_pl->record[i].media_error_length);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep,
					   struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, SANITIZE, SANITIZE);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_secure_erase(struct cxlmi_endpoint *ep,
					       struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, SANITIZE, SECURE_ERASE);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_security_state(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_get_security_state *ret)
{
	struct cxlmi_cmd_memdev_get_security_state *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	int rc;
	ssize_t rsp_sz;

	arm_cci_request(ep, &req, 0, PERSISTENT_MEM, GET_SECURITY_STATE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_security_state *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->security_state = le32_to_cpu(rsp_pl->security_state);

	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_memdev_set_passphrase(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_set_passphrase *in)
{
	struct cxlmi_cmd_memdev_set_passphrase *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x60);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), PERSISTENT_MEM, SET_PASSPHRASE);

	req_pl = (struct cxlmi_cmd_memdev_set_passphrase *)req->payload;
	req_pl->passphrase_type = in->passphrase_type;
	memcpy(req_pl->current_passphrase,
	       in->current_passphrase, sizeof(in->current_passphrase));
	memcpy(req_pl->new_passphrase,
	       in->new_passphrase, sizeof(in->new_passphrase));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_memdev_disable_passphrase(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_memdev_disable_passphrase *in)
{
	struct cxlmi_cmd_memdev_disable_passphrase *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x40);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), PERSISTENT_MEM, DISABLE_PASSPHRASE);

	req_pl = (struct cxlmi_cmd_memdev_disable_passphrase *)req->payload;
	req_pl->passphrase_type = in->passphrase_type;
	memcpy(req_pl->passphrase, in->passphrase, sizeof(in->passphrase));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_unlock(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_memdev_unlock *in)
{
	struct cxlmi_cmd_memdev_unlock *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x20);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), PERSISTENT_MEM, UNLOCK);

	req_pl = (struct cxlmi_cmd_memdev_unlock *)req->payload;
	memcpy(req_pl->current_passphrase,
	       in->current_passphrase, sizeof(in->current_passphrase));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_freeze_security_state(struct cxlmi_endpoint *ep,
							struct cxlmi_tunnel_info *ti)
{
	struct cxlmi_cci_msg req, rsp;

	arm_cci_request(ep, &req, 0, PERSISTENT_MEM, FREEZE_SECURITY_STATE);

	return send_cmd_cci(ep, ti, &req, sizeof(req),
			    &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_memdev_passphrase_secure_erase(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_memdev_passphrase_secure_erase *in)
{
	struct cxlmi_cmd_memdev_passphrase_secure_erase *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x40);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in), PERSISTENT_MEM,
			PASSPHRASE_SECURE_ERASE);

	req_pl = (struct cxlmi_cmd_memdev_passphrase_secure_erase *)req->payload;
	req_pl->passphrase_type = in->passphrase_type;
	memcpy(req_pl->passphrase, in->passphrase, sizeof(in->passphrase));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_sld_qos_control(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_get_sld_qos_control *ret)
{
	struct cxlmi_cmd_memdev_get_sld_qos_control *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 4);

	arm_cci_request(ep, &req, 0, SLD_QOS_TELEMETRY, GET_SLD_QOS_CONTROL);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_sld_qos_control *)rsp->payload;

	ret->qos_telemetry_control = rsp_pl->qos_telemetry_control;
	ret->egress_moderate_percentage = rsp_pl->egress_moderate_percentage;
	ret->egress_severe_percentage = rsp_pl->egress_severe_percentage;
	ret->backpressure_sample_interval = rsp_pl->backpressure_sample_interval;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_set_sld_qos_control(struct cxlmi_endpoint *ep,
				      struct cxlmi_tunnel_info *ti,
				      struct cxlmi_cmd_memdev_set_sld_qos_control *in,
				      struct cxlmi_cmd_memdev_set_sld_qos_control *ret)
{
	struct cxlmi_cmd_memdev_set_sld_qos_control *req_pl;
	struct cxlmi_cmd_memdev_set_sld_qos_control *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 4);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 4);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			SLD_QOS_TELEMETRY, SET_SLD_QOS_CONTROL);
	req_pl = (struct cxlmi_cmd_memdev_set_sld_qos_control *)req->payload;

	req_pl->qos_telemetry_control = in->qos_telemetry_control;
	req_pl->egress_moderate_percentage = in->egress_moderate_percentage;
	req_pl->egress_severe_percentage = in->egress_severe_percentage;
	req_pl->backpressure_sample_interval = in->backpressure_sample_interval;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_set_sld_qos_control *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->qos_telemetry_control = rsp_pl->qos_telemetry_control;
	ret->egress_moderate_percentage = rsp_pl->egress_moderate_percentage;
	ret->egress_severe_percentage = rsp_pl->egress_severe_percentage;
	ret->backpressure_sample_interval = rsp_pl->backpressure_sample_interval;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_sld_qos_status(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_memdev_get_sld_qos_status *ret)
{
	struct cxlmi_cmd_memdev_get_sld_qos_status *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	arm_cci_request(ep, &req, 0, SLD_QOS_TELEMETRY, GET_SLD_QOS_STATUS);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_sld_qos_status *)rsp->payload;

	ret->backpressure_avg_percentage = rsp_pl->backpressure_avg_percentage;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_get_dc_extent_list(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_memdev_get_dc_extent_list_req *in,
				     struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *ret)
{
	struct cxlmi_cmd_memdev_get_dc_extent_list_req *req_pl;
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz, rsp_sz_min;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), DCD_CONFIG, GET_DYN_CAP_EXT_LIST);
	req_pl = (struct cxlmi_cmd_memdev_get_dc_extent_list_req *)req->payload;
	req_pl->extent_cnt = cpu_to_le32(in->extent_cnt);
	req_pl->start_extent_idx = cpu_to_le32(in->start_extent_idx);

	/*
	 * Assume we retrieve at most 8 extents at one time, the software is
	 * responsible to retrieve all the extents based on the total extent
	 * count and the number of extents returned till now.
	 */
	if (req_pl->extent_cnt  == 0 || req_pl->extent_cnt > 8)
		req_pl->extent_cnt = cpu_to_le32(8);
	rsp_sz = sizeof(rsp) + sizeof(rsp_pl) + 8 * sizeof(rsp_pl->extents[0]);
	rsp_sz_min = sizeof(rsp) + sizeof(rsp_pl);

	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz_min);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_extents_returned = le32_to_cpu(rsp_pl->num_extents_returned);
	ret->total_num_extents = le32_to_cpu(rsp_pl->total_num_extents);
	ret->generation_num = le32_to_cpu(rsp_pl->generation_num);

	for (i = 0; i < ret->num_extents_returned; i++) {
		ret->extents[i].start_dpa = le64_to_cpu(rsp_pl->extents[i].start_dpa);
		ret->extents[i].len = le64_to_cpu(rsp_pl->extents[i].len);
		memcpy(ret->extents[i].tag, rsp_pl->extents[i].tag, 0x10);
		ret->extents[i].shared_seq = le16_to_cpu(rsp_pl->extents[i].shared_seq);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_memdev_add_dc_response(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_add_dc_response *in)
{
       struct cxlmi_cmd_memdev_add_dc_response *req_pl;
       _cleanup_free_ struct cxlmi_cci_msg *req = NULL;
       struct cxlmi_cci_msg rsp;
       ssize_t req_sz;
       int i;

       req_sz = sizeof(*req_pl) + sizeof(*req) +
	       in->updated_extent_list_size * sizeof(in->extents[0]);
       req = calloc(1, req_sz);
       if (!req)
	       return -1;

       arm_cci_request(ep, req, sizeof(*req_pl), DCD_CONFIG, ADD_DYN_CAP_RSP);
       req_pl = (struct cxlmi_cmd_memdev_add_dc_response *)req->payload;
       req_pl->updated_extent_list_size = cpu_to_le32(in->updated_extent_list_size);
       req_pl->flags = in->flags;

       for (i = 0; i < in->updated_extent_list_size; i++) {
	       req_pl->extents[i].start_dpa = cpu_to_le64(in->extents[i].start_dpa);
	       req_pl->extents[i].len = cpu_to_le64(in->extents[i].len);
       }

       return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_memdev_release_dc(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_memdev_release_dc *in)
{
	struct cxlmi_cmd_memdev_release_dc *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	ssize_t req_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + sizeof(*req) +
		in->updated_extent_list_size * sizeof(in->extents[0]);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), DCD_CONFIG, RELEASE_DYN_CAP);
	req_pl = (struct cxlmi_cmd_memdev_release_dc *)req->payload;
	req_pl->updated_extent_list_size = cpu_to_le32(in->updated_extent_list_size);
	req_pl->flags = in->flags;

	for (i = 0; i < in->updated_extent_list_size; i++) {
		req_pl->extents[i].start_dpa = cpu_to_le64(in->extents[i].start_dpa);
		req_pl->extents[i].len = cpu_to_le64(in->extents[i].len);
	}

	rc = send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
						    struct cxlmi_tunnel_info *ti,
						    struct cxlmi_cmd_fmapi_identify_sw_device *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_fmapi_identify_sw_device *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x49);

	arm_cci_request(ep, &req, 0, PHYSICAL_SWITCH, IDENTIFY_SWITCH_DEVICE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return -1;

	rsp_pl = (struct cxlmi_cmd_fmapi_identify_sw_device *)rsp->payload;

	ret->ingres_port_id = rsp_pl->ingres_port_id;
	ret->num_physical_ports = rsp_pl->num_physical_ports;
	ret->num_vcs = rsp_pl->num_vcs;
	memcpy(ret->active_port_bitmask, rsp_pl->active_port_bitmask,
	       sizeof(rsp_pl->active_port_bitmask));
	memcpy(ret->active_vcs_bitmask, rsp_pl->active_vcs_bitmask,
	       sizeof(rsp_pl->active_vcs_bitmask));
	ret->num_total_vppb = le16_to_cpu(rsp_pl->num_total_vppb);
	ret->num_active_vppb = le16_to_cpu(rsp_pl->num_active_vppb);
	ret->num_hdm_decoder_per_usp = rsp_pl->num_hdm_decoder_per_usp;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_phys_port_state(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_fmapi_get_phys_port_state_req *in,
				     struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req_pl;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + in->num_ports + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl) + in->num_ports,
			PHYSICAL_SWITCH, GET_PHYSICAL_PORT_STATE);
	req_pl = (struct cxlmi_cmd_fmapi_get_phys_port_state_req *)req->payload;

	req_pl->num_ports = in->num_ports;
	for (i = 0; i < in->num_ports; i++)
		req_pl->ports[i] = in->ports[i];

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl) +
		in->num_ports * sizeof(*rsp_pl->ports);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_ports = rsp_pl->num_ports;
	for (i = 0; i < rsp_pl->num_ports; i++) {
		ret->ports[i].port_id = rsp_pl->ports[i].port_id;
		ret->ports[i].config_state = rsp_pl->ports[i].config_state;
		ret->ports[i].conn_dev_cxl_ver = rsp_pl->ports[i].conn_dev_cxl_ver;
		ret->ports[i].conn_dev_type = rsp_pl->ports[i].conn_dev_type;
		ret->ports[i].port_cxl_ver_bitmask =
			rsp_pl->ports[i].port_cxl_ver_bitmask;
		ret->ports[i].max_link_width = rsp_pl->ports[i].max_link_width;
		ret->ports[i].negotiated_link_width =
			rsp_pl->ports[i].negotiated_link_width;
		ret->ports[i].supported_link_speeds_vector =
			rsp_pl->ports[i].supported_link_speeds_vector;
		ret->ports[i].max_link_speed = rsp_pl->ports[i].max_link_speed;
		ret->ports[i].current_link_speed =
			rsp_pl->ports[i].current_link_speed;
		ret->ports[i].ltssm_state = rsp_pl->ports[i].ltssm_state;
		ret->ports[i].first_lane_num = rsp_pl->ports[i].first_lane_num;
		ret->ports[i].link_state = le16_to_cpu(rsp_pl->ports[i].link_state);
		ret->ports[i].supported_ld_count = rsp_pl->ports[i].supported_ld_count;
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_phys_port_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_fmapi_phys_port_control *in)
{
	struct cxlmi_cmd_fmapi_phys_port_control *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in),
			PHYSICAL_SWITCH, PHYSICAL_PORT_CONTROL);

	req_pl = (struct cxlmi_cmd_fmapi_phys_port_control *)req->payload;

	req_pl->ppb_id = in->ppb_id;
	req_pl->port_opcode = in->port_opcode;

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_fmapi_get_domain_validation_sv_state(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_get_domain_validation_sv_state *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_state *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	arm_cci_request(ep, &req, 0,
			PHYSICAL_SWITCH, GET_DOMAIN_VALIDATION_SV_STATE);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_domain_validation_sv_state *)rsp->payload;

	ret->secret_value_state = rsp_pl->secret_value_state;

	return rc;
}

CXLMI_EXPORT int
cxlmi_cmd_fmapi_set_domain_validation_sv(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_set_domain_validation_sv *in)
{
	struct cxlmi_cmd_fmapi_set_domain_validation_sv *req_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	struct cxlmi_cci_msg rsp;
	size_t req_sz;
	CXLMI_BUILD_BUG_ON(sizeof(*in) != 0x10);

	req_sz = sizeof(*req) + sizeof(*in);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*in),
			PHYSICAL_SWITCH, SET_DOMAIN_VALIDATION_SV);

	req_pl = (struct cxlmi_cmd_fmapi_set_domain_validation_sv *)req->payload;

	memcpy(req_pl->secret_value_uuid, in->secret_value_uuid,
	       sizeof(req_pl->secret_value_uuid));

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int
cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req *in,
			    struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req *req_pl;
	struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 1);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			PHYSICAL_SWITCH, GET_VCS_DOMAIN_VALIDATION_SV_STATE);
	req_pl = (struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req *)req->payload;

	req_pl->vcs_id = in->vcs_id;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->secret_value_state = rsp_pl->secret_value_state;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_domain_validation_sv(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_get_domain_validation_sv_req *in,
			    struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_req *req_pl;
	struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 1);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 0x10);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			PHYSICAL_SWITCH, GET_DOMAIN_VALIDATION_SV);
	req_pl = (struct cxlmi_cmd_fmapi_get_domain_validation_sv_req *)req->payload;

	req_pl->vcs_id = in->vcs_id;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	memcpy(ret->secret_value_uuid, rsp_pl->secret_value_uuid,
	       sizeof(rsp_pl->secret_value_uuid));

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_bind_vppb(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_bind_vppb *in)
{

	struct cxlmi_cmd_fmapi_bind_vppb req_pl;
	struct cxlmi_cci_msg rsp;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	ssize_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 5);

	req_sz = sizeof(req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	memcpy(&req_pl, in, sizeof(req_pl));
	arm_cci_request(ep, req, sizeof(req_pl), VIRTUAL_SWITCH, BIND_VPPB);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_unbind_vppb(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_unbind_vppb *in)
{

	struct cxlmi_cmd_fmapi_unbind_vppb req_pl;
	struct cxlmi_cci_msg rsp;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	ssize_t req_sz;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 3);

	req_sz = sizeof(req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	memcpy(&req_pl, in, sizeof(req_pl));
	arm_cci_request(ep, req, sizeof(req_pl), VIRTUAL_SWITCH, UNBIND_VPPB);

	return send_cmd_cci(ep, ti, req, req_sz, &rsp, sizeof(rsp), sizeof(rsp));
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_ld_info(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_get_ld_info *ret)
{
	int rc;
	ssize_t rsp_sz;
	struct cxlmi_cmd_fmapi_get_ld_info *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 11);

	arm_cci_request(ep, &req, 0, MLD_COMPONENTS, GET_LD_INFO);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_ld_info *)rsp->payload;

	ret->memory_size = le64_to_cpu(rsp_pl->memory_size);
	ret->ld_count = le16_to_cpu(rsp_pl->ld_count);
	ret->qos_telemetry_capability = rsp_pl->qos_telemetry_capability;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_ld_allocations(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_get_ld_allocations_req *in,
			    struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_ld_allocations_req *req_pl;
	struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, GET_LD_ALLOCATIONS);
	req_pl = (struct cxlmi_cmd_fmapi_get_ld_allocations_req *)req->payload;

	req_pl->start_ld_id = in->start_ld_id;
	req_pl->ld_allocation_list_limit = in->ld_allocation_list_limit;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->memory_granularity = rsp_pl->memory_granularity;
	ret->start_ld_id = rsp_pl->start_ld_id;
	ret->ld_allocation_list_len = rsp_pl->ld_allocation_list_len;

	for (i = 0; i < ret->ld_allocation_list_len; i++) {
		ret->ld_allocation_list[i].range_1_allocation_mult =
			le64_to_cpu(rsp_pl->ld_allocation_list[i].range_1_allocation_mult);
		ret->ld_allocation_list[i].range_2_allocation_mult =
			le64_to_cpu(rsp_pl->ld_allocation_list[i].range_2_allocation_mult);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_set_ld_allocations(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_set_ld_allocations_req *in,
			    struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret)
{
	struct cxlmi_cmd_fmapi_set_ld_allocations_req *req_pl;
	struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + sizeof(*req) +
		in->number_ld * sizeof(*in->ld_allocation_list);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, SET_LD_ALLOCATIONS);
	req_pl = (struct cxlmi_cmd_fmapi_set_ld_allocations_req *)req->payload;

	req_pl->number_ld = in->number_ld;
	req_pl->start_ld_id = in->start_ld_id;

	for (i = 0; i < ret->number_ld; i++) {
		req_pl->ld_allocation_list[i].range_1_allocation_mult =
			cpu_to_le64(in->ld_allocation_list[i].range_1_allocation_mult);
		req_pl->ld_allocation_list[i].range_2_allocation_mult =
			cpu_to_le64(in->ld_allocation_list[i].range_2_allocation_mult);
	}

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp) +
		in->number_ld * sizeof(*in->ld_allocation_list);;
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->start_ld_id = rsp_pl->start_ld_id;

	for (i = 0; i < ret->number_ld; i++) {
		ret->ld_allocation_list[i].range_1_allocation_mult =
			le64_to_cpu(rsp_pl->ld_allocation_list[i].range_1_allocation_mult);
		ret->ld_allocation_list[i].range_2_allocation_mult =
			le64_to_cpu(rsp_pl->ld_allocation_list[i].range_2_allocation_mult);
	}

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_qos_control(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_fmapi_get_qos_control *ret)
{
	struct  cxlmi_cmd_fmapi_get_qos_control *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 7);

	arm_cci_request(ep, &req, 0, MLD_COMPONENTS, GET_QOS_CONTROL);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_qos_control *)rsp->payload;

	ret->qos_telemetry_control = rsp_pl->qos_telemetry_control;
	ret->egress_moderate_percentage = rsp_pl->egress_moderate_percentage;
	ret->egress_severe_percentage = rsp_pl->egress_severe_percentage;
	ret->backpressure_sample_interval = rsp_pl->backpressure_sample_interval;
	ret->recmpbasis = le16_to_cpu(rsp_pl->backpressure_sample_interval);
	ret->completion_collection_interval = rsp_pl->completion_collection_interval;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_set_qos_control(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_set_qos_control *in,
					  struct cxlmi_cmd_fmapi_set_qos_control *ret)
{
	struct cxlmi_cmd_fmapi_set_qos_control *req_pl;
	struct cxlmi_cmd_fmapi_set_qos_control *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 7);
	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 7);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, SET_QOS_CONTROL);
	req_pl = (struct cxlmi_cmd_fmapi_set_qos_control *)req->payload;

	req_pl->qos_telemetry_control = in->qos_telemetry_control;
	req_pl->egress_moderate_percentage = in->egress_moderate_percentage;
	req_pl->egress_severe_percentage = in->egress_severe_percentage;
	req_pl->backpressure_sample_interval = in->backpressure_sample_interval;
	req_pl->recmpbasis = cpu_to_le16(in->backpressure_sample_interval);
	req_pl->completion_collection_interval = in->completion_collection_interval;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_set_qos_control *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->qos_telemetry_control = rsp_pl->qos_telemetry_control;
	ret->egress_moderate_percentage = rsp_pl->egress_moderate_percentage;
	ret->egress_severe_percentage = rsp_pl->egress_severe_percentage;
	ret->backpressure_sample_interval = rsp_pl->backpressure_sample_interval;
	ret->recmpbasis = le16_to_cpu(rsp_pl->backpressure_sample_interval);
	ret->completion_collection_interval = rsp_pl->completion_collection_interval;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_qos_status(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_fmapi_get_qos_status *ret)
{
	struct  cxlmi_cmd_fmapi_get_qos_status *rsp_pl;
	struct cxlmi_cci_msg req;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t rsp_sz;
	int rc;

	CXLMI_BUILD_BUG_ON(sizeof(*ret) != 1);

	arm_cci_request(ep, &req, 0, MLD_COMPONENTS, GET_QOS_STATUS);

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, &req, sizeof(req), rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_qos_status *)rsp->payload;

	ret->backpressure_avg_percentage = rsp_pl->backpressure_avg_percentage;

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_qos_allocated_bw(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req *in,
					  struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req *req_pl;
	struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, GET_QOS_ALLOCATED_BW);
	req_pl = (struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req *)req->payload;

	req_pl->number_ld = in->number_ld;
	req_pl->start_ld_id = in->start_ld_id;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp) +
		in->number_ld * sizeof(*ret->qos_allocation_fraction);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->start_ld_id = rsp_pl->start_ld_id;

	for (i = 0; i < ret->number_ld; i++)
		ret->qos_allocation_fraction[i] = rsp_pl->qos_allocation_fraction[i];

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_set_qos_allocated_bw(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_set_qos_allocated_bw *in,
					  struct cxlmi_cmd_fmapi_set_qos_allocated_bw *ret)
{
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw *req_pl;
	struct cxlmi_cmd_fmapi_set_qos_allocated_bw *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + sizeof(*req) +
		in->number_ld * sizeof(*ret->qos_allocation_fraction);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, SET_QOS_ALLOCATED_BW);
	req_pl = (struct cxlmi_cmd_fmapi_set_qos_allocated_bw *)req->payload;

	req_pl->number_ld = in->number_ld;
	req_pl->start_ld_id = in->start_ld_id;
	for (i = 0; i < in->number_ld; i++)
		req_pl->qos_allocation_fraction[i] = in->qos_allocation_fraction[i];

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp) +
		in->number_ld * sizeof(*ret->qos_allocation_fraction);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_set_qos_allocated_bw *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->start_ld_id = rsp_pl->start_ld_id;

	for (i = 0; i < ret->number_ld; i++)
		ret->qos_allocation_fraction[i] = rsp_pl->qos_allocation_fraction[i];

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_get_qos_bw_limit(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_get_qos_bw_limit_req *in,
					  struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret)
{
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_req *req_pl;
	struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	CXLMI_BUILD_BUG_ON(sizeof(*in) != 2);

	req_sz = sizeof(*req_pl) + sizeof(*req);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, GET_QOS_BW_LIMIT);
	req_pl = (struct cxlmi_cmd_fmapi_get_qos_bw_limit_req *)req->payload;

	req_pl->number_ld = in->number_ld;
	req_pl->start_ld_id = in->start_ld_id;

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp) +
		in->number_ld * sizeof(*ret->qos_limit_fraction);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->start_ld_id = rsp_pl->start_ld_id;

	for (i = 0; i < ret->number_ld; i++)
		ret->qos_limit_fraction[i] = rsp_pl->qos_limit_fraction[i];

	return rc;
}

CXLMI_EXPORT int cxlmi_cmd_fmapi_set_qos_bw_limit(struct cxlmi_endpoint *ep,
					  struct cxlmi_tunnel_info *ti,
					  struct cxlmi_cmd_fmapi_set_qos_bw_limit *in,
					  struct cxlmi_cmd_fmapi_set_qos_bw_limit *ret)
{
	struct cxlmi_cmd_fmapi_set_qos_bw_limit *req_pl;
	struct cxlmi_cmd_fmapi_set_qos_bw_limit *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz;
	int i, rc = -1;

	req_sz = sizeof(*req_pl) + sizeof(*req) +
		in->number_ld * sizeof(*ret->qos_limit_fraction);
	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl),
			MLD_COMPONENTS, SET_QOS_BW_LIMIT);
	req_pl = (struct cxlmi_cmd_fmapi_set_qos_bw_limit *)req->payload;

	req_pl->number_ld = in->number_ld;
	req_pl->start_ld_id = in->start_ld_id;
	for (i = 0; i < in->number_ld; i++)
		req_pl->qos_limit_fraction[i] = in->qos_limit_fraction[i];

	rsp_sz = sizeof(*rsp_pl) + sizeof(*rsp) +
		in->number_ld * sizeof(*ret->qos_limit_fraction);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_fmapi_set_qos_bw_limit *)rsp->payload;

	ret->number_ld = rsp_pl->number_ld;
	ret->start_ld_id = rsp_pl->start_ld_id;

	for (i = 0; i < ret->number_ld; i++)
		ret->qos_limit_fraction[i] = rsp_pl->qos_limit_fraction[i];

	return rc;
}

#define CXL_CAPACITY_MULTIPLIER   (256 * 1024 * 1024)
CXLMI_EXPORT int cxlmi_cmd_memdev_get_dc_config(struct cxlmi_endpoint *ep,
		struct cxlmi_tunnel_info *ti,
		struct cxlmi_cmd_memdev_get_dc_config_req *in,
		struct cxlmi_cmd_memdev_get_dc_config_rsp *ret)
{
	struct cxlmi_cmd_memdev_get_dc_config_req *req_pl;
	struct cxlmi_cmd_memdev_get_dc_config_rsp *rsp_pl;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz, rsp_sz, rsp_sz_min;
	int i, rc = -1;
	void *p;

	req_sz = sizeof(*req) + sizeof(*req_pl);

	req = calloc(1, req_sz);
	if (!req)
		return -1;

	arm_cci_request(ep, req, sizeof(*req_pl), DCD_CONFIG, GET_DC_CONFIG);
	req_pl = (struct cxlmi_cmd_memdev_get_dc_config_req *)req->payload;
	req_pl->region_cnt = in->region_cnt;
	req_pl->start_region_id = in->start_region_id;

	rsp_sz = sizeof(*rsp) + sizeof(*rsp_pl);
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rsp_sz_min = rsp_sz - sizeof(rsp_pl->region_configs[0]) * 8;
	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz_min);
	if (rc)
		return rc;

	rsp_pl = (struct cxlmi_cmd_memdev_get_dc_config_rsp *)rsp->payload;
	memset(ret, 0, sizeof(*ret));

	ret->num_regions = rsp_pl->num_regions;
	ret->regions_returned = rsp_pl->regions_returned;
	for (i = 0; i < ret->regions_returned; i++) {
		ret->region_configs[i].base = le64_to_cpu(rsp_pl->region_configs[i].base);
		ret->region_configs[i].decode_len =
			le64_to_cpu(rsp_pl->region_configs[i].decode_len) * CXL_CAPACITY_MULTIPLIER;
		ret->region_configs[i].region_len = le64_to_cpu(rsp_pl->region_configs[i].region_len);
		ret->region_configs[i].block_size = le64_to_cpu(rsp_pl->region_configs[i].block_size);
		ret->region_configs[i].dsmadhandle = le32_to_cpu(rsp_pl->region_configs[i].dsmadhandle);
	}
	p = (void *)&rsp_pl->region_configs[i];
	ret->num_extents_supported = le32_to_cpu(*(uint32_t *)p);
	p += sizeof(uint32_t);
	ret->num_extents_available = le32_to_cpu(*(uint32_t *)p);
	p += sizeof(uint32_t);
	ret->num_tags_supported = le32_to_cpu(*(uint32_t *)p);
	p += sizeof(uint32_t);
	ret->num_tags_available = le32_to_cpu(*(uint32_t *)p);

	return rc;
}

/* Vendor-specific commands */

CXLMI_EXPORT int cxlmi_cmd_vendor_specific(struct cxlmi_endpoint *ep,
					   struct cxlmi_tunnel_info *ti,
					   uint16_t opcode,
					   void *in, ssize_t in_size,
					   void *ret, ssize_t ret_size)
{

	int rc = -1;
	_cleanup_free_ struct cxlmi_cci_msg *req = NULL;
	_cleanup_free_ struct cxlmi_cci_msg *rsp = NULL;
	ssize_t req_sz = sizeof(*req);
	ssize_t rsp_sz = sizeof(*rsp);

	/* C000h-FFFFh describe vendor-specific commands */
	if (opcode < 0xC000)
		return rc;

	if ((in && !in_size) || (ret && !ret_size))
		return rc;
	if ((!in && in_size) || (!ret && ret_size))
		return rc;

	if (in)
		req_sz += in_size;
	req = calloc(1, req_sz);
	if (!req)
		return -1;
	arm_cci_request(ep, req, in ? 0 : in_size, opcode >> 8, opcode & 0xFF);
	if (in)
		memcpy(req->payload, in, in_size);

	if (ret)
		rsp_sz += ret_size;
	rsp = calloc(1, rsp_sz);
	if (!rsp)
		return -1;

	rc = send_cmd_cci(ep, ti, req, req_sz, rsp, rsp_sz, rsp_sz);
	if (rc)
		return rc;

	if (ret)
		memcpy(ret, rsp->payload, ret_size);

	return rc;
}
