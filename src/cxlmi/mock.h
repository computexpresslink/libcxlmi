// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Internal mock transport declarations.
 */
#ifndef _LIBCXLMI_MOCK_H
#define _LIBCXLMI_MOCK_H

#include <stdbool.h>
#include <stddef.h>

struct cxlmi_endpoint;
struct cxlmi_cci_msg;

/* Check if endpoint is a mock endpoint */
bool cxlmi_is_mock_endpoint(struct cxlmi_endpoint *ep);

/* Internal send function for mock transport */
int send_mock_cmd(struct cxlmi_endpoint *ep,
		  struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		  struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		  size_t rsp_msg_sz_min);

/* Internal close function for mock transport */
void mock_close(struct cxlmi_endpoint *ep);

#endif /* _LIBCXLMI_MOCK_H */
