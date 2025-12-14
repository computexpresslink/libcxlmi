// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Mock transport API for testing without hardware.
 * This header is separate from libcxlmi.h to keep the public API clean.
 */
#ifndef _LIBCXLMI_TEST_H
#define _LIBCXLMI_TEST_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cxlmi_ctx;
struct cxlmi_endpoint;

/**
 * cxlmi_open_mock() - Create a mock endpoint for testing.
 * @ctx: library context object to create under
 *
 * Creates a mock endpoint that doesn't require hardware. Use
 * cxlmi_mock_set_response() to configure expected responses.
 *
 * Return: New mock endpoint object, or NULL on failure.
 *
 * See &cxlmi_mock_set_response, &cxlmi_close
 */
struct cxlmi_endpoint *cxlmi_open_mock(struct cxlmi_ctx *ctx);

/**
 * cxlmi_mock_set_response() - Configure a response for the mock endpoint.
 * @ep: Mock endpoint object
 * @command_set: Command set (opcode high byte)
 * @command: Command (opcode low byte)
 * @return_code: CXL return code to return
 * @payload: Response payload data (copied, may be NULL)
 * @payload_size: Size of payload in bytes
 *
 * Queues a response to be returned when a matching command is sent.
 * Responses are consumed in FIFO order per command.
 *
 * Return: 0 on success, -1 on failure.
 */
int cxlmi_mock_set_response(struct cxlmi_endpoint *ep,
			    uint8_t command_set,
			    uint8_t command,
			    uint16_t return_code,
			    void *payload,
			    size_t payload_size);

/**
 * cxlmi_mock_clear_responses() - Clear all queued mock responses.
 * @ep: Mock endpoint object
 */
void cxlmi_mock_clear_responses(struct cxlmi_endpoint *ep);

/**
 * cxlmi_mock_get_stats() - Get mock endpoint statistics.
 * @ep: Mock endpoint object
 * @commands_sent: Output for number of commands sent (may be NULL)
 * @responses_returned: Output for number of responses returned (may be NULL)
 *
 * Return: 0 on success, -1 on failure.
 */
int cxlmi_mock_get_stats(struct cxlmi_endpoint *ep,
			 unsigned int *commands_sent,
			 unsigned int *responses_returned);

/**
 * cxlmi_mock_get_last_command() - Get the last command sent to mock endpoint.
 * @ep: Mock endpoint object
 * @command_set: Output for command set (may be NULL)
 * @command: Output for command (may be NULL)
 * @payload: Buffer for payload copy (may be NULL)
 * @payload_size: In/out size of payload buffer. On input, the buffer size.
 *                On output, the actual payload size (0 if no payload).
 *
 * Return: 0 on success, -1 on failure.
 */
int cxlmi_mock_get_last_command(struct cxlmi_endpoint *ep,
				uint8_t *command_set,
				uint8_t *command,
				void *payload,
				size_t *payload_size);

#ifdef __cplusplus
}
#endif

#endif /* _LIBCXLMI_TEST_H */
