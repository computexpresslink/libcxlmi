// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Mock transport layer for testing without hardware.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ccan/list/list.h>

#include <libcxlmi.h>

#include "private.h"
#include "mock.h"

/* Magic value to identify mock transport */
#define CXLMI_MOCK_TRANSPORT_MAGIC 0x4D4F434B /* "MOCK" */

struct cxlmi_mock_response {
	struct list_node entry;
	uint8_t command_set;
	uint8_t command;
	uint16_t return_code;
	void *payload;
	size_t payload_size;
};

struct cxlmi_transport_mock {
	uint32_t magic;
	struct list_head responses;
	/* Stats for testing */
	unsigned int commands_sent;
	unsigned int responses_returned;
	/* Last command received (for verification) */
	uint8_t last_command_set;
	uint8_t last_command;
	void *last_payload;
	size_t last_payload_size;
};

bool cxlmi_is_mock_endpoint(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mock *mock;

	if (!ep || !ep->transport_data)
		return false;

	mock = ep->transport_data;
	return mock->magic == CXLMI_MOCK_TRANSPORT_MAGIC;
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open_mock(struct cxlmi_ctx *ctx)
{
	struct cxlmi_endpoint *ep;
	struct cxlmi_transport_mock *mock;

	if (!ctx) {
		errno = EINVAL;
		return NULL;
	}

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return NULL;

	mock = calloc(1, sizeof(*mock));
	if (!mock) {
		free(ep);
		return NULL;
	}

	mock->magic = CXLMI_MOCK_TRANSPORT_MAGIC;
	list_head_init(&mock->responses);

	list_node_init(&ep->entry);
	ep->ctx = ctx;
	ep->transport_data = mock;
	ep->timeout_ms = 5000;
	ep->has_fmapi = true; /* Mock supports everything */
	ep->fd = -1;

	list_add(&ctx->endpoints, &ep->entry);

	return ep;
}

CXLMI_EXPORT int cxlmi_mock_set_response(struct cxlmi_endpoint *ep,
					 uint8_t command_set,
					 uint8_t command,
					 uint16_t return_code,
					 void *payload,
					 size_t payload_size)
{
	struct cxlmi_transport_mock *mock;
	struct cxlmi_mock_response *resp;

	if (!ep || !cxlmi_is_mock_endpoint(ep)) {
		errno = EINVAL;
		return -1;
	}

	mock = ep->transport_data;

	resp = calloc(1, sizeof(*resp));
	if (!resp)
		return -1;

	resp->command_set = command_set;
	resp->command = command;
	resp->return_code = return_code;

	if (payload && payload_size > 0) {
		resp->payload = malloc(payload_size);
		if (!resp->payload) {
			free(resp);
			return -1;
		}
		memcpy(resp->payload, payload, payload_size);
		resp->payload_size = payload_size;
	}

	list_add_tail(&mock->responses, &resp->entry);

	return 0;
}

CXLMI_EXPORT void cxlmi_mock_clear_responses(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mock *mock;
	struct cxlmi_mock_response *resp, *next;

	if (!ep || !cxlmi_is_mock_endpoint(ep))
		return;

	mock = ep->transport_data;

	list_for_each_safe(&mock->responses, resp, next, entry) {
		list_del(&resp->entry);
		free(resp->payload);
		free(resp);
	}
}

CXLMI_EXPORT int cxlmi_mock_get_stats(struct cxlmi_endpoint *ep,
				      unsigned int *commands_sent,
				      unsigned int *responses_returned)
{
	struct cxlmi_transport_mock *mock;

	if (!ep || !cxlmi_is_mock_endpoint(ep)) {
		errno = EINVAL;
		return -1;
	}

	mock = ep->transport_data;

	if (commands_sent)
		*commands_sent = mock->commands_sent;
	if (responses_returned)
		*responses_returned = mock->responses_returned;

	return 0;
}

CXLMI_EXPORT int cxlmi_mock_get_last_command(struct cxlmi_endpoint *ep,
					     uint8_t *command_set,
					     uint8_t *command,
					     void *payload,
					     size_t *payload_size)
{
	struct cxlmi_transport_mock *mock;

	if (!ep || !cxlmi_is_mock_endpoint(ep)) {
		errno = EINVAL;
		return -1;
	}

	mock = ep->transport_data;

	if (command_set)
		*command_set = mock->last_command_set;
	if (command)
		*command = mock->last_command;
	if (payload_size) {
		if (payload && mock->last_payload) {
			size_t copy_size = *payload_size < mock->last_payload_size ?
					   *payload_size : mock->last_payload_size;
			memcpy(payload, mock->last_payload, copy_size);
		}
		*payload_size = mock->last_payload_size;
	}

	return 0;
}

/* Internal: find and consume a matching response */
static struct cxlmi_mock_response *
mock_find_response(struct cxlmi_transport_mock *mock,
		   uint8_t command_set, uint8_t command)
{
	struct cxlmi_mock_response *resp;

	list_for_each(&mock->responses, resp, entry) {
		if (resp->command_set == command_set &&
		    resp->command == command) {
			list_del(&resp->entry);
			return resp;
		}
	}

	return NULL;
}

/* Internal: called by send_cmd_cci for mock transport */
int send_mock_cmd(struct cxlmi_endpoint *ep,
		  struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		  struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		  size_t rsp_msg_sz_min)
{
	struct cxlmi_transport_mock *mock = ep->transport_data;
	struct cxlmi_mock_response *resp;
	size_t req_pl_size;

	mock->commands_sent++;

	/* Store last command for verification */
	mock->last_command_set = req_msg->command_set;
	mock->last_command = req_msg->command;

	req_pl_size = req_msg->pl_length[0] |
		      (req_msg->pl_length[1] << 8) |
		      ((req_msg->pl_length[2] & 0xf) << 16);

	free(mock->last_payload);
	mock->last_payload = NULL;
	mock->last_payload_size = 0;

	if (req_pl_size > 0) {
		mock->last_payload = malloc(req_pl_size);
		if (mock->last_payload) {
			memcpy(mock->last_payload, req_msg->payload, req_pl_size);
			mock->last_payload_size = req_pl_size;
		}
	}

	/* Find matching response */
	resp = mock_find_response(mock, req_msg->command_set, req_msg->command);
	if (!resp) {
		/* No response configured - return unsupported */
		cxlmi_msg(ep->ctx, LOG_DEBUG,
			  "mock: no response for cmd %02x:%02x\n",
			  req_msg->command_set, req_msg->command);
		if (rsp_msg && rsp_msg_sz > 0) {
			memset(rsp_msg, 0, rsp_msg_sz);
			rsp_msg->command_set = req_msg->command_set;
			rsp_msg->command = req_msg->command;
			rsp_msg->return_code = CXLMI_RET_UNSUPPORTED;
		}
		return CXLMI_RET_UNSUPPORTED;
	}

	mock->responses_returned++;

	/* Build response message */
	if (rsp_msg && rsp_msg_sz > 0) {
		memset(rsp_msg, 0, rsp_msg_sz);
		rsp_msg->category = 1; /* Response */
		rsp_msg->tag = req_msg->tag;
		rsp_msg->command = req_msg->command;
		rsp_msg->command_set = req_msg->command_set;
		rsp_msg->return_code = resp->return_code;

		if (resp->payload && resp->payload_size > 0) {
			size_t copy_size = resp->payload_size;
			if (copy_size > rsp_msg_sz - sizeof(*rsp_msg))
				copy_size = rsp_msg_sz - sizeof(*rsp_msg);

			memcpy(rsp_msg->payload, resp->payload, copy_size);
			rsp_msg->pl_length[0] = copy_size & 0xff;
			rsp_msg->pl_length[1] = (copy_size >> 8) & 0xff;
			rsp_msg->pl_length[2] = (copy_size >> 16) & 0xf;
		}
	}

	int rc = resp->return_code;
	free(resp->payload);
	free(resp);

	return rc;
}

void mock_close(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mock *mock = ep->transport_data;

	if (!mock)
		return;

	cxlmi_mock_clear_responses(ep);
	free(mock->last_payload);
	free(mock);
	ep->transport_data = NULL;
}
