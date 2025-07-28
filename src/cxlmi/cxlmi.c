// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <poll.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/types.h>
#if HAVE_LINUX_MCTP_H
#include <linux/mctp.h>
#endif
#if HAVE_LINUX_CXL_MEM_H
#include <linux/cxl_mem.h>
#endif

#ifdef CONFIG_DBUS
#include <dbus/dbus.h>
#endif

#include <ccan/array_size/array_size.h>
#include <ccan/minmax/minmax.h>
#include <ccan/list/list.h>

#include <libcxlmi.h>

#include "private.h"

#if !defined(AF_MCTP)
#define AF_MCTP 45
#endif /* !AF_MCTP */

#if !HAVE_LINUX_MCTP_H
/* As of kernel v5.15, these AF_MCTP-related definitions are provided by
 * linux/mctp.h. Keep this fallback to fail gracefully upon older standard
 * includes.
 * These were all introduced in the same version as AF_MCTP was defined,
 * so we can key off the presence of that.
 */

typedef __u8			mctp_eid_t;

struct mctp_addr {
	mctp_eid_t		s_addr;
};

struct sockaddr_mctp {
	unsigned short int	smctp_family;
	__u16			__smctp_pad0;
	unsigned int		smctp_network;
	struct mctp_addr	smctp_addr;
	__u8			smctp_type;
	__u8			smctp_tag;
	__u8			__smctp_pad1;
};

#define MCTP_NET_ANY		0x0

#define MCTP_ADDR_NULL		0x00
#define MCTP_ADDR_ANY		0xff

#define MCTP_TAG_MASK		0x07
#define MCTP_TAG_OWNER		0x08

#endif /* !HAVE_LINUX_MCTP_H */

#define CXL_MCTP_CATEGORY_REQ 0
#define CXL_MCTP_CATEGORY_RSP 1

struct cxlmi_transport_mctp {
	int	nid;
	uint8_t	eid;
	int	sd;
	int	fmapi_sd;
	struct sockaddr_mctp addr;
	struct sockaddr_mctp fmapi_addr;
	int tag;
};

/* 2 secs, see CXL r3.1 Section 9.20.2 */
#define MCTP_MAX_TIMEOUT 2000

#define MCTP_TYPE_CXL_FMAPI 0x7
#define MCTP_TYPE_CXL_CCI   0x8

static bool cxlmi_probe_enabled_default(void)
{
	char *val;

	val = getenv("LIBCXLMI_PROBE_ENABLED");
	if (!val)
		return true;

	return strcmp(val, "0") &&
		strcasecmp(val, "false") &&
		strncasecmp(val, "disable", 7);
}

CXLMI_EXPORT struct cxlmi_ctx *cxlmi_new_ctx(FILE *fp, int log_level)
{
	struct cxlmi_ctx *ctx;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->fp = fp ? fp : stderr;
	ctx->log_level = log_level;
	ctx->probe_enabled = cxlmi_probe_enabled_default();
	list_head_init(&ctx->endpoints);

	return ctx;
}

CXLMI_EXPORT void cxlmi_free_ctx(struct cxlmi_ctx *ctx)
{
	free(ctx);
}

static const int nsec_per_sec = 1000 * 1000 * 1000;
/* timercmp and timersub, but for struct timespec */
#define timespec_cmp(a, b, CMP)						\
	(((a)->tv_sec == (b)->tv_sec)					\
		? ((a)->tv_nsec CMP (b)->tv_nsec)			\
		: ((a)->tv_sec CMP (b)->tv_sec))

#define timespec_sub(a, b, result)					\
	do {								\
		(result)->tv_sec = (a)->tv_sec - (b)->tv_sec;		\
		(result)->tv_nsec = (a)->tv_nsec - (b)->tv_nsec;	\
		if ((result)->tv_nsec < 0) {				\
			--(result)->tv_sec;				\
			(result)->tv_nsec += nsec_per_sec;		\
		}							\
	} while (0)

static void cxlmi_insert_delay(struct cxlmi_endpoint *ep)
{
	struct timespec now, next, delay;
	int rc;

	if (!ep->last_resp_time_valid)
		return;

	/* calculate earliest next command time */
	next.tv_nsec = ep->last_resp_time.tv_nsec + ep->inter_command_us * 1000;
	next.tv_sec = ep->last_resp_time.tv_sec;
	if (next.tv_nsec > nsec_per_sec) {
		next.tv_nsec -= nsec_per_sec;
		next.tv_sec += 1;
	}

	rc = clock_gettime(CLOCK_MONOTONIC, &now);
	if (rc) {
		/* not much we can do; continue immediately */
		return;
	}

	if (timespec_cmp(&now, &next, >=))
		return;

	timespec_sub(&next, &now, &delay);

	nanosleep(&delay, NULL);
}

static struct cxlmi_endpoint *init_endpoint(struct cxlmi_ctx *ctx)
{
	struct cxlmi_endpoint *ep;

	ep = calloc(1, sizeof(*ep));
	if (!ep)
		return NULL;

	list_node_init(&ep->entry);
	ep->ctx = ctx;
	ep->timeout_ms = 5000;
	list_add(&ctx->endpoints, &ep->entry);

	return ep;
}

static int mctp_check_timeout(struct cxlmi_endpoint *ep,
			      int timeout_ms)
{
	return timeout_ms > MCTP_MAX_TIMEOUT;
}

CXLMI_EXPORT int cxlmi_endpoint_set_timeout(struct cxlmi_endpoint *ep,
					    int timeout_ms)
{
	if (ep->transport_data) {
		int rc;

		rc = mctp_check_timeout(ep, timeout_ms);
		if (rc)
			return rc;
	}
	ep->timeout_ms = timeout_ms;
	return 0;
}

CXLMI_EXPORT unsigned int cxlmi_endpoint_get_timeout(struct cxlmi_endpoint *ep)
{
	return ep->timeout_ms;
}

static bool cxlmi_ep_has_quirk(struct cxlmi_endpoint *ep, unsigned long quirk)
{
	return ep->quirks & quirk;
}

CXLMI_EXPORT bool cxlmi_endpoint_has_fmapi(struct cxlmi_endpoint *ep)
{
	return ep->has_fmapi;
}

CXLMI_EXPORT bool cxlmi_endpoint_enable_fmapi(struct cxlmi_endpoint *ep)
{
	if (cxlmi_endpoint_has_fmapi(ep)) /* nop */
		return true;

	if (ep->transport_data) {
		struct cxlmi_transport_mctp *mctp = ep->transport_data;
		struct sockaddr_mctp fmapi_addr = {
			.smctp_family = AF_MCTP,
			.smctp_network = mctp->nid,
			.smctp_addr.s_addr = mctp->eid,
			.smctp_type = MCTP_TYPE_CXL_FMAPI,
			.smctp_tag = MCTP_TAG_OWNER,
		};

		mctp->fmapi_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
		if (mctp->fmapi_sd < 0)
			goto err;
		if (bind(mctp->fmapi_sd, (struct sockaddr *)&fmapi_addr,
			 sizeof(fmapi_addr)))
			goto err;

		mctp->fmapi_addr = fmapi_addr;
	}

	ep->has_fmapi = true;
	return true;
err:
	cxlmi_msg(ep->ctx, LOG_INFO, "FM-API unsupported\n");
	return false;
}

CXLMI_EXPORT bool cxlmi_endpoint_disable_fmapi(struct cxlmi_endpoint *ep)
{
	if (!cxlmi_endpoint_has_fmapi(ep)) /* nop */
		return true;

	if (ep->transport_data) {
		struct cxlmi_transport_mctp *mctp = ep->transport_data;

		close(mctp->fmapi_sd);
		memset(&mctp->fmapi_addr, 0, sizeof(mctp->fmapi_addr));
	}

	ep->has_fmapi = false;
	return true;
}

static void mctp_close(struct cxlmi_endpoint *ep)
{
	struct cxlmi_transport_mctp *mctp = ep->transport_data;

	if (cxlmi_endpoint_has_fmapi(ep))
		close(mctp->fmapi_sd);

	close(mctp->sd);
}

CXLMI_EXPORT void cxlmi_close(struct cxlmi_endpoint *ep)
{
	if (ep->transport_data) {
		mctp_close(ep);
		free(ep->transport_data);
	} else {
		if (ep->fd > 0)
			close(ep->fd);
		if (ep->devname)
			free(ep->devname);
	}

	list_del(&ep->entry);
	free(ep);
}

static int sanity_check_mctp_rsp(struct cxlmi_endpoint *ep,
			 struct cxlmi_cci_msg *req, struct cxlmi_cci_msg *rsp,
			 size_t len, bool fixed_length, size_t min_length)
{
	uint32_t pl_length;
	struct cxlmi_ctx *ctx = ep->ctx;

	if (len < sizeof(rsp)) {
		cxlmi_msg(ctx, LOG_ERR, "Too short to read error code\n");
		return -1;
	}

	if (rsp->category != CXL_MCTP_CATEGORY_RSP) {
		cxlmi_msg(ctx, LOG_ERR, "Message not a response\n");
		return -1;
	}
	if (rsp->tag != req->tag) {
		cxlmi_msg(ctx, LOG_ERR, "Reply has wrong tag %d %d\n",
			  rsp->tag, req->tag);
		return -1;
	}
	if ((rsp->command != req->command) ||
	    (rsp->command_set != req->command_set)) {
		cxlmi_msg(ctx, LOG_ERR, "Response to wrong command\n");
		return -1;
	}

	if (rsp->return_code != 0) {
		if (rsp->return_code != CXLMI_RET_BACKGROUND)
			cxlmi_msg(ctx, LOG_ERR, "Error code in response: %d\n",
				  rsp->return_code);
		return rsp->return_code;
	}

	if (fixed_length) {
		if (len != min_length) {
			cxlmi_msg(ctx, LOG_ERR,
				  "Unexpected fixed length of response. %ld %ld\n",
				  len, min_length);
			return -1;
		}
	} else {
		if (len < min_length) {
			cxlmi_msg(ctx, LOG_ERR,
				  "Unexpected minimum length of response\n");
			return -1;
		}
	}
	pl_length = rsp->pl_length[0] | (rsp->pl_length[1] << 8) |
		((rsp->pl_length[2] & 0xf) << 16);
	if (len - sizeof(*rsp) != pl_length) {
		cxlmi_msg(ctx, LOG_ERR,
			"Payload length not matching expected part of full message %ld %d\n",
			  len - sizeof(*rsp), pl_length);
		return -1;
	}

	return 0;
}

static int send_mctp_direct(struct cxlmi_endpoint *ep, bool fmapi,
			    struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			    struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			    size_t rsp_msg_sz_min)
{
	int rc, errno_save, len;
	struct sockaddr_mctp addrrx;
	socklen_t addrlen = sizeof(addrrx);
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct pollfd pollfds[1];
	int timeout = ep->timeout_ms ? ep->timeout_ms : -1;
	int sd = !fmapi ? mctp->sd : mctp->fmapi_sd;
	struct sockaddr_mctp addr = !fmapi ? mctp->addr : mctp->fmapi_addr;

	memset(rsp_msg, 0, rsp_msg_sz);

	len = sendto(sd, req_msg, req_msg_sz, 0,
		     (struct sockaddr *)&addr, sizeof(addr));

	pollfds[0].fd = sd;
	pollfds[0].events = POLLIN;
	while (1) {
		rc = poll(pollfds, 1, timeout);
		if (rc > 0)
			break;
		else if (rc == 0) {
			cxlmi_msg(ep->ctx, LOG_DEBUG, "Timeout on MCTP socket");
			errno = ETIMEDOUT;
			return -1;
		} else if (errno != EINTR) {
			errno_save = errno;
			cxlmi_msg(ep->ctx, LOG_ERR,
				  "Failed polling on MCTP socket");
			errno = errno_save;
			return -1;
		}
	}

	len = recvfrom(sd, rsp_msg, rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);

	return sanity_check_mctp_rsp(ep, req_msg, rsp_msg, len,
				rsp_msg_sz == rsp_msg_sz_min, rsp_msg_sz_min);
}

/* CXL r3.1 Section 7.6.7.3.2: Tunnel Management Command (Opcode 5300h) */
struct cxlmi_cmd_fmapi_tunnel_command_req {
	uint8_t id; /* Port or LD ID as appropriate */
	uint8_t target_type;
	uint16_t command_size;
	struct cxlmi_cci_msg message[];
} __attribute__((packed));

struct cxlmi_cmd_fmapi_tunnel_command_rsp {
	uint16_t length;
	uint16_t resv;
	struct cxlmi_cci_msg message[]; /* only one but lets closs over that */
} __attribute__((packed));

static void extract_rsp_msg_from_tunnel(struct cxlmi_cci_msg *tunnel_msg,
					struct cxlmi_cci_msg *extracted_msg,
					size_t extracted_msg_size)
{
	struct cxlmi_cmd_fmapi_tunnel_command_rsp *rsp =
		(struct cxlmi_cmd_fmapi_tunnel_command_rsp *)tunnel_msg->payload;

	memcpy(extracted_msg, &rsp->message, extracted_msg_size);
}


#define TUNNEL_TARGET_TYPE_PORT_OR_LD  0
#define TUNNEL_TARGET_TYPE_LD_POOL_CCI 1

static int build_tunnel_req(struct cxlmi_endpoint *ep, int port_or_ld,
		    struct cxlmi_cci_msg *payload_in, size_t payload_in_sz,
		    struct cxlmi_cci_msg **payload_out, size_t *payload_out_sz)
{
	struct cxlmi_cmd_fmapi_tunnel_command_req *t_req;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct cxlmi_cci_msg *req;
	size_t t_req_sz = sizeof(*t_req) + payload_in_sz;
	size_t req_sz = sizeof(*req) + t_req_sz;
	int tag = 0x10; /* can start anywhere when not tracking */

	req = calloc(1, req_sz);
	if (!req)
		return -1;

	*req = (struct cxlmi_cci_msg) {
		.category = CXL_MCTP_CATEGORY_REQ,
		.tag = mctp ? mctp->tag++ : tag,
		.command = TUNNEL_MANAGEMENT_COMMAND,
		.command_set = MLD_PORT,
		.vendor_ext_status = 0xabcd,
		.pl_length = {
			t_req_sz & 0xff,
			(t_req_sz >> 8) & 0xff,
			(t_req_sz >> 16) & 0xff,
		}
	};

	t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req *)req->payload;
	*t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req) {
		.target_type = port_or_ld == -1 ?
		TUNNEL_TARGET_TYPE_LD_POOL_CCI : TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = port_or_ld, /* ignored if type=1 */
		.command_size = payload_in_sz,
	};
	if (payload_in_sz)
		memcpy(t_req->message, payload_in, payload_in_sz);
	*payload_out = req;
	*payload_out_sz = req_sz;

	return 0;
}

static int send_mctp_tunnel1(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			     struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			     size_t rsp_msg_sz_min)
{
	struct cxlmi_cmd_fmapi_tunnel_command_req *t_req;
	struct cxlmi_cmd_fmapi_tunnel_command_rsp *t_rsp;
	struct cxlmi_cci_msg *t_req_msg, *t_rsp_msg;
	struct sockaddr_mctp addrrx;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct pollfd pollfds[1];
	int timeout = ep->timeout_ms ? ep->timeout_ms : -1;
	size_t t_req_msg_sz, t_rsp_msg_sz, len_max, len_min;
	int len, rc, errno_save;
	socklen_t addrlen = sizeof(addrrx);

	cxlmi_msg(ep->ctx, LOG_DEBUG, "1 Level tunnel of opcode %02x%02x\n",
		  req_msg->command_set, req_msg->command);

	rc = build_tunnel_req(ep, ti->ld == -1 ? ti->port : ti->ld,
			      req_msg, req_msg_sz, &t_req_msg, &t_req_msg_sz);
	if (rc)
		return rc;

	/* Outer CCI message + tunnel header + inner message */
	t_rsp_msg_sz = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
	/* These length will be update as tunnel unwound */
	len_min = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz_min;
	len_max = sizeof(*t_rsp_msg) + sizeof(*t_rsp) + rsp_msg_sz;
	t_rsp_msg = calloc(1, t_rsp_msg_sz);
	if (!t_rsp_msg) {
		rc = -1;
		goto free_req;
	}

	len = sendto(mctp->fmapi_sd, t_req_msg, t_req_msg_sz, 0,
		     (struct sockaddr *)&mctp->fmapi_addr,
		     sizeof(mctp->fmapi_addr));
	if (len != t_req_msg_sz) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Failed to send whole request\n");
		rc = -1;
		goto free_rsp;
	}

	pollfds[0].fd = mctp->fmapi_sd;
	pollfds[0].events = POLLIN;
	while (1) {
		rc = poll(pollfds, 1, timeout);
		if (rc > 0)
			break;
		else if (rc == 0) {
			cxlmi_msg(ep->ctx, LOG_DEBUG, "Timeout on MCTP socket");
			errno = ETIMEDOUT;
			rc = -1;
			goto free_rsp;
		} else if (errno != EINTR) {
			errno_save = errno;
			cxlmi_msg(ep->ctx, LOG_ERR,
				  "Failed polling on MCTP socket");
			errno = errno_save;
			rc = -1;
			goto free_rsp;
		}
	}

	len = recvfrom(mctp->fmapi_sd, t_rsp_msg, t_rsp_msg_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);

	rc = sanity_check_mctp_rsp(ep, t_req_msg, t_rsp_msg, len,
				   len_min == len_max, len_min);
	if (rc)
		goto free_rsp;

	/* Update lengths to unwind the outer tunnel */
	len -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
	len_max -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);
	len_min -= sizeof(*t_rsp_msg) + sizeof(*t_rsp);

	/* Unwind one level of tunnel */
	t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req *)t_req_msg->payload;
	t_rsp = (struct cxlmi_cmd_fmapi_tunnel_command_rsp *)t_rsp_msg->payload;

	if (t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel length is not consistent with received length\n");
		rc = -1;
		goto free_rsp;
	}

	/* Need to exclude the tunneled command header from sizes as used for PL check */
	rc = sanity_check_mctp_rsp(ep, t_req->message, t_rsp->message, len,
			      len_min == len_max, len_min);
	if (rc)
		goto free_rsp;

	extract_rsp_msg_from_tunnel(t_rsp_msg, rsp_msg, rsp_msg_sz);

free_rsp:
	free(t_rsp_msg);
free_req:
	free(t_req_msg);
	return rc;
}

static int send_mctp_tunnel2(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
			     struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
			     size_t rsp_msg_sz_min)
{
	struct cxlmi_cci_msg *inner_req, *outer_req, *inner_rsp, *outer_rsp;
	size_t inner_req_sz, outer_req_sz, outer_rsp_sz, len_min, len_max;
	struct cxlmi_cmd_fmapi_tunnel_command_req *inner_t_req, *outer_t_req;
	struct cxlmi_cmd_fmapi_tunnel_command_rsp *inner_t_rsp, *outer_t_rsp;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct pollfd pollfds[1];
	struct sockaddr_mctp addrrx;
	int timeout = ep->timeout_ms ? ep->timeout_ms : -1;
	int errno_save, len, rc;
	socklen_t addrlen = sizeof(addrrx);

	cxlmi_msg(ep->ctx, LOG_DEBUG, "2 Level tunnel of opcode %02x%02x\n",
		  req_msg->command_set, req_msg->command);

	rc = build_tunnel_req(ep, ti->ld, req_msg, req_msg_sz,
			      &inner_req, &inner_req_sz);
	if (rc)
		return rc;

	rc = build_tunnel_req(ep, ti->port, inner_req, inner_req_sz,
			      &outer_req, &outer_req_sz);
	if (rc)
		goto free_inner_req;

	/*
	 * Outer tunnel message + outer tunnel header +
	 * inner tunnel message + inner tunnel header +
	 * inner message
	 */
	outer_rsp_sz = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) +
		sizeof(*inner_rsp) + sizeof(*inner_t_rsp) + rsp_msg_sz;
	len_min = sizeof(*outer_rsp) + sizeof(*outer_t_rsp) +
		sizeof(*inner_rsp) + sizeof(*inner_t_rsp) + rsp_msg_sz_min;
	len_max = outer_rsp_sz;
	outer_rsp = calloc(1, outer_rsp_sz);
	if (!outer_rsp) {
		rc = -1;
		goto free_outer_req;
	}

	len = sendto(mctp->fmapi_sd, outer_req, outer_req_sz, 0,
		     (struct sockaddr *)&mctp->fmapi_addr,
		     sizeof(mctp->fmapi_addr));
	if (len != outer_req_sz) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Failed to send whole request\n");
		rc = -1;
		goto free_outer_rsp;
	}

	pollfds[0].fd = mctp->fmapi_sd;
	pollfds[0].events = POLLIN;
	while (1) {
		rc = poll(pollfds, 1, timeout);
		if (rc > 0)
			break;
		else if (rc == 0) {
			cxlmi_msg(ep->ctx, LOG_DEBUG, "Timeout on MCTP socket");
			errno = ETIMEDOUT;
			rc = -1;
			goto free_outer_rsp;
		} else if (errno != EINTR) {
			errno_save = errno;
			cxlmi_msg(ep->ctx, LOG_ERR,
				  "Failed polling on MCTP socket");
			errno = errno_save;
			rc = -1;
			goto free_outer_rsp;
		}
	}

	len = recvfrom(mctp->fmapi_sd, outer_rsp, outer_rsp_sz, 0,
		       (struct sockaddr *)&addrrx, &addrlen);
	if (len < len_min) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Not enough data in reply\n");
		rc = -1 ;
		goto free_outer_rsp;
	}

	rc = sanity_check_mctp_rsp(ep, outer_req, outer_rsp, len,
				   len_min == len_max, len_min);
	if (rc)
		goto free_outer_rsp;

	len -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
	len_min -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);
	len_max -= sizeof(*outer_rsp) + sizeof(*outer_t_rsp);

	outer_t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req *)outer_req->payload;
	outer_t_rsp = (struct cxlmi_cmd_fmapi_tunnel_command_rsp *)outer_rsp->payload;

	if (outer_t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel length not consistent with received length\n");
		rc = -1;
		goto free_outer_rsp;
	}

	rc = sanity_check_mctp_rsp(ep, outer_t_req->message,
				   outer_t_rsp->message, len,
				   len_min == len_max, len_min);
	if (rc)
		goto free_outer_rsp;

	/*
	 * TODO: Consider doing the extra copies so that
	 * extract_rsp_msg_from_tunnel() could be used
	 */
	inner_rsp = outer_t_rsp->message;
	inner_t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req *)inner_req->payload;
	inner_t_rsp = (struct cxlmi_cmd_fmapi_tunnel_command_rsp *)inner_rsp->payload;

	len -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
	len_min -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);
	len_max -= sizeof(*inner_rsp) + sizeof(*inner_t_rsp);

	if (inner_t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel lenght not consistent with received length\n");
		rc = -1;
		goto free_outer_rsp;
	}
	rc = sanity_check_mctp_rsp(ep, inner_t_req->message,
				   inner_t_rsp->message, len,
				   len_min == len_max, len_min);
	if (rc)
		goto free_outer_rsp;

	extract_rsp_msg_from_tunnel(inner_rsp, rsp_msg, rsp_msg_sz);

 free_outer_rsp:
	free(outer_rsp);
 free_outer_req:
	free(outer_req);
 free_inner_req:
	free(inner_req);

	return rc;
}

static int send_ioctl_direct(struct cxlmi_endpoint *ep,
		      struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		      struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		      size_t rsp_msg_sz_min)
{
	int rc, errno_save;
	struct cxlmi_ctx *ctx = ep->ctx;
	struct cxl_send_command cmd = {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = req_msg->command | (req_msg->command_set << 8),
		/* The payload is the same, but take off the CCI message header */
		.in.size = req_msg_sz - sizeof(*req_msg),
		.in.payload = (__u64)req_msg->payload,
		.out.size = rsp_msg_sz - sizeof(*rsp_msg),
		.out.payload = (__u64)rsp_msg->payload,
	};

	rc = ioctl(ep->fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR, "ioctl failed %d\n", rc);
		goto err;
	}

	if (cmd.retval != 0) {
		if (cmd.retval != CXLMI_RET_BACKGROUND)
			cxlmi_msg(ctx, LOG_ERR,
				  "ioctl returned non zero retval %d\n",
				  cmd.retval);
		return cmd.retval;
	}
	/* To make it compatible with CXL2.0, do not impose size check */
	if (cmd.out.size < rsp_msg_sz_min - sizeof(*rsp_msg)) {
		cxlmi_msg(ctx, LOG_WARNING, "ioctl returned too little data\n");
	}

	return 0;
err:
	errno = errno_save;
	return -1;
}

static int
send_ioctl_tunnel1(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti,
		   struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		   struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		   size_t rsp_msg_sz_min)
{
	struct cxlmi_cmd_fmapi_tunnel_command_req *t_req;
	struct cxlmi_cmd_fmapi_tunnel_command_rsp *t_rsp;
	size_t t_req_sz, t_rsp_sz, len_min, len_max;
	struct cxl_send_command cmd;
	int rc, len;

	cxlmi_msg(ep->ctx, LOG_DEBUG,
		  "Tunneling over switch CCI mailbox by IOCTL\n");

	/*
	 * Step 1. Wrap the CCI message in a tunnel command
	 * that we will send via ioctl.
	 */
	t_req_sz = sizeof(*t_req) + req_msg_sz;
	t_req = calloc(1, t_req_sz);
	if (!t_req)
		return -1;

	*t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req) {
		.target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = ti->ld == -1 ? ti->port : ti->ld,
		.command_size = req_msg_sz,
	};
	memcpy(t_req->message, req_msg, req_msg_sz);
	/* These will be updated to reflect current parsing state */
	len_min = sizeof(*t_req) + rsp_msg_sz_min;
	len_max = sizeof(*t_req) + rsp_msg_sz;

	t_rsp_sz = sizeof(*t_rsp) + rsp_msg_sz;
	t_rsp = calloc(t_rsp_sz, 1);
	if (!t_rsp) {
		rc = -1;
		goto free_tunnel_req;
	}

	cmd = (struct cxl_send_command) {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = 0 | (0x53 << 8),
		.in.payload = (__u64)t_req,
		.in.size = t_req_sz,
		.out.payload = (__u64)t_rsp,
		.out.size = t_rsp_sz,
	};
	rc = ioctl(ep->fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0)
		goto free_tunnel_rsp;

	if (cmd.retval) {
		cxlmi_msg(ep->ctx, LOG_ERR, "bad return value\n");
		rc = -cmd.retval;
		goto free_tunnel_rsp;
	}
	len = cmd.out.size;

	if (len < len_min) {
		cxlmi_msg(ep->ctx, LOG_ERR, "IOCTL output too small %d < %ld\n",
			  len, len_min);
		rc = -1;
		goto free_tunnel_rsp;
	}

	len -= sizeof(*t_rsp);
	len_min -= sizeof(*t_rsp);
	len_max -= sizeof(*t_rsp);
	if (t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	if (t_rsp->length < len_min) {
		cxlmi_msg(ep->ctx, LOG_ERR,
			  "Got back too little data ain the tunnel\n");
		rc = -1;
		goto free_tunnel_rsp;
	};
	rc = sanity_check_mctp_rsp(ep, t_req->message, t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Inner tunnel repsonse failed\n");
		goto free_tunnel_rsp;
	}

	memcpy(rsp_msg, t_rsp->message, rsp_msg_sz);

	if (rsp_msg->return_code) {
		rc = -rsp_msg->return_code;
		goto free_tunnel_rsp;
	}

 free_tunnel_rsp:
	free(t_rsp);
 free_tunnel_req:
	free(t_req);
	return rc;
}


/*
 * 2 level tunnel - so there are two tunnel_command_req, tunnel_comamnd_rsp
 * burried in an ioctl message
 */
static int
send_ioctl_tunnel2(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti,
		   struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		   struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		   size_t rsp_msg_sz_min)
{
	struct cxlmi_cci_msg *inner_req, *inner_rsp;
	size_t inner_req_sz;
	struct cxlmi_cmd_fmapi_tunnel_command_req *outer_t_req, *inner_t_req;
	struct cxlmi_cmd_fmapi_tunnel_command_rsp *outer_t_rsp, *inner_t_rsp;
	size_t outer_t_req_sz, outer_t_rsp_sz, len_min, len_max;
	struct cxl_send_command cmd;
	int rc, len;

	cxlmi_msg(ep->ctx, LOG_DEBUG,
		  "Tunneling 2 levels over switch CCI mailbox by IOCTL\n");

	/*
	 * Step 1. Wrap to be the tunneled CCI message including payload in a
	 * CCI message that is a Tunneled request.
	 *      12             4            req_msg_sz
	 * | CCIMessage | TunnelHdr | req_msg (CCIMessage +PL) |
	 */
	rc = build_tunnel_req(ep, ti->ld, req_msg, req_msg_sz, &inner_req,
			      &inner_req_sz);
	if (rc)
		return rc;

	/*
	 * Step 2. Wrap the now already inner wrapped CCI message in
	 * tunnel command that we will send via ioctl.
	 * |      4        12 + 4 + req_msg_sz
	 * | Tunnel Hdr | Inner Req as above   |
	 */
	outer_t_req_sz = sizeof(*outer_t_req) + inner_req_sz;
	outer_t_req = calloc(1, outer_t_req_sz);
	if (!outer_t_req) {
		rc = -1;
		goto free_inner_req;
	}
	*outer_t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req) {
		.target_type = TUNNEL_TARGET_TYPE_PORT_OR_LD,
		.id = ti->port,
		.command_size = inner_req_sz,
	};
	memcpy(outer_t_req->message, inner_req, inner_req_sz);

	/*
	 * Allocate the whole response in one go
	 *       4           12           4             resp_msg_sz
	 * | TunnelHdr | CCIMessage | TunnelHdr | rsp_msg (CCIMessage + PL) |
	 */
	outer_t_rsp_sz = sizeof(*outer_t_rsp) + sizeof(*outer_t_rsp->message) +
		sizeof(*inner_t_rsp) + rsp_msg_sz;
	/*
	 * Also compute the max/min good response size - this will be updated as
	 * the tunnelling is unwound.
	 */
	len_min = sizeof(*outer_t_rsp) + sizeof(*outer_t_rsp->message) +
		sizeof(*inner_t_rsp) + rsp_msg_sz_min;
	len_max = outer_t_rsp_sz;

	outer_t_rsp = calloc(outer_t_rsp_sz, 1);
	if (!outer_t_rsp) {
		rc = -1;
		goto free_tunnel_req;
	}

	cmd = (struct cxl_send_command) {
		.id = CXL_MEM_COMMAND_ID_RAW,
		.raw.opcode = 0 | (0x53 << 8),
		.in.payload = (__u64)outer_t_req,
		.in.size = outer_t_req_sz,
		.out.payload = (__u64)outer_t_rsp,
		.out.size = outer_t_rsp_sz,
	};
	rc = ioctl(ep->fd, CXL_MEM_SEND_COMMAND, &cmd);
	if (rc < 0)
		goto free_tunnel_rsp;

	if (cmd.retval) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Bad return value\n");
		rc = -cmd.retval;
		goto free_tunnel_rsp;
	}
	len = cmd.out.size;

	/* Check overal message size */
	if (len < len_min) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		       "IOCTL output too small %d < %ld\n", len, len_min);
		rc = -1;
		goto free_tunnel_rsp;
	}

	/* Check the length in the tunnel header */
	len -= sizeof(*outer_t_rsp);
	len_min -= sizeof(*outer_t_rsp);
	len_max -= sizeof(*outer_t_rsp);

	if (outer_t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	if (outer_t_rsp->length < len_min) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Got back to little data in the tunnel overall %d %ld %d\n",
		       outer_t_rsp->length, len_min, cmd.out.size);
		rc = -1;
		goto free_tunnel_rsp;
	}

	/* Check the outer tunnel */
	rc = sanity_check_mctp_rsp(ep, outer_t_req->message, outer_t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Outer tunnel response failed\n");
		goto free_tunnel_rsp;
	}

	len -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);
	len_min -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);
	len_max -= sizeof(*inner_t_rsp) + sizeof(*inner_t_rsp->message);

	inner_t_req = (struct cxlmi_cmd_fmapi_tunnel_command_req *)inner_req->payload;
	inner_rsp = outer_t_rsp->message;
	inner_t_rsp = (struct cxlmi_cmd_fmapi_tunnel_command_rsp *)inner_rsp->payload;
	if (inner_t_rsp->length != len) {
		cxlmi_msg(ep->ctx, LOG_ERR,
		  "Tunnel length not consistent with ioctl data returned\n");
		rc = -1;
		goto free_tunnel_rsp;
	}
	rc = sanity_check_mctp_rsp(ep, inner_t_req->message, inner_t_rsp->message, len,
			      len_max == len_min, len_min);
	if (rc) {
		cxlmi_msg(ep->ctx, LOG_ERR, "Inner tunnel repsonse failed\n");
		goto free_tunnel_rsp;
	}
	extract_rsp_msg_from_tunnel(inner_rsp, rsp_msg, rsp_msg_sz);
 free_tunnel_rsp:
	free(outer_t_rsp);

 free_tunnel_req:
	free(outer_t_req);

 free_inner_req:
	free(inner_req);
	return rc;
}

static void cxlmi_record_resp_time(struct cxlmi_endpoint *ep)
{
	int rc;

	rc = clock_gettime(CLOCK_MONOTONIC, &ep->last_resp_time);
	ep->last_resp_time_valid = !rc;
}

static bool cxlmi_cmd_is_fmapi(int cmdset)
{
	switch(cmdset) {
	case PHYSICAL_SWITCH:
	case MLD_PORT:
	case MHD:
	case DCD_MANAGEMENT:
		return true;
	default:
		return false;
	}
}

int send_cmd_cci(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti,
		 struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		 struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		 size_t rsp_msg_sz_min)
{
	int rc = -1;
	bool fmapi_cmd = cxlmi_cmd_is_fmapi(req_msg->command_set);

	if (fmapi_cmd && !cxlmi_endpoint_has_fmapi(ep))
		return -1;

	/* ensure valid tunnel info before anything else */
	if (ti) {
		if (ti->level > 2)
			return -1;
	}

	if (cxlmi_ep_has_quirk(ep, CXLMI_QUIRK_MIN_INTER_COMMAND_TIME))
		cxlmi_insert_delay(ep);

	if (ep->transport_data) {
		if (!ti || ti->level == 0)
			rc = send_mctp_direct(ep, fmapi_cmd, req_msg, req_msg_sz,
				      rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
		else if (ti->level == 1)
			rc = send_mctp_tunnel1(ep, ti, req_msg, req_msg_sz,
				       rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
		else if (ti->level == 2)
			rc = send_mctp_tunnel2(ep, ti, req_msg, req_msg_sz,
				       rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
	} else {
		if (!ti || ti->level == 0)
			rc = send_ioctl_direct(ep, req_msg, req_msg_sz,
				       rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
		else if (ti->level == 1)
			rc = send_ioctl_tunnel1(ep, ti, req_msg, req_msg_sz,
				       rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
		else if (ti->level == 2)
			rc = send_ioctl_tunnel2(ep, ti, req_msg, req_msg_sz,
					rsp_msg, rsp_msg_sz, rsp_msg_sz_min);
	}

	if (cxlmi_ep_has_quirk(ep, CXLMI_QUIRK_MIN_INTER_COMMAND_TIME))
		cxlmi_record_resp_time(ep);

	return rc;
}

CXLMI_EXPORT void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled)
{
	ctx->probe_enabled = enabled;
}

/* probe cxl component for basic device info */
static void endpoint_probe_mctp(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_identify id;
	struct cxlmi_transport_mctp *mctp = ep->transport_data;
	struct sockaddr_mctp fmapi_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = mctp->nid,
		.smctp_addr.s_addr = mctp->eid,
		.smctp_type = MCTP_TYPE_CXL_FMAPI,
		.smctp_tag = MCTP_TAG_OWNER,
	};

	if (cxlmi_cmd_identify(ep, NULL, &id))
		return;

	/*
	 * Probing topology is not cached as it may change dynamically.
	 * It is up to the user to have an updated view of what underlying
	 * CXL component this endpoint corresponds to.
	 */
	switch (id.component_type) {
	case 0x00:
		cxlmi_msg(ep->ctx, LOG_INFO, "detected a CXL Switch device\n");
		break;
	case 0x03:
		cxlmi_msg(ep->ctx, LOG_INFO,
			  "detected a CXL Type3 device (SLD or MLD FM-owned LD\n");
		break;
	default:
		cxlmi_msg(ep->ctx, LOG_WARNING,
			  "mctp probe found unsupported CXL component\n");
		return;
	}

	/* FM-API errors are ignored and the CCI will only be available */
	mctp->fmapi_sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (bind(mctp->fmapi_sd, (struct sockaddr *)&fmapi_addr,
		 sizeof(fmapi_addr))) {
		cxlmi_msg(ep->ctx, LOG_INFO, "FM-API unsupported\n");
		return;
	}

	mctp->fmapi_addr = fmapi_addr;
	ep->has_fmapi = true;
}

static void endpoint_probe(struct cxlmi_endpoint *ep)
{
	if (!ep->ctx->probe_enabled)
		return;

	/* XXX: quirk machinery is there, but no currently known quirks */
	ep->quirks = 0;

	/*
	 * If we're quirking for the inter-command time, record the last
	 * command time now, so we don't conflict with the just-sent identify.
	 */
	if (ep->quirks & CXLMI_QUIRK_MIN_INTER_COMMAND_TIME)
		cxlmi_record_resp_time(ep);

	if (ep->quirks) {
		cxlmi_msg(ep->ctx, LOG_DEBUG,
			  "endpoint: applying quirks 0x%08lx\n", ep->quirks);
	}

	if (ep->transport_data)
		endpoint_probe_mctp(ep);
	else
		ep->has_fmapi = true;
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
					    unsigned int netid, uint8_t eid)
{
	struct cxlmi_endpoint *ep, *tmp;
	struct cxlmi_transport_mctp *mctp;
	int rc, errno_save;
	struct sockaddr_mctp cci_addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = netid,
		.smctp_addr.s_addr = eid,
		.smctp_type = MCTP_TYPE_CXL_CCI,
		.smctp_tag = MCTP_TAG_OWNER,
	};

	/* ensure no duplicates */
	cxlmi_for_each_endpoint(ctx, tmp) {
		if (tmp->transport_data) {
			struct cxlmi_transport_mctp *mctp = tmp->transport_data;

			if (mctp->nid == netid && mctp->eid == eid) {
				cxlmi_msg(ctx, LOG_ERR,
					  "mctp endpoint %d:%d already opened\n",
					  netid, eid);
				return NULL;
			}
		}
	}

	ep = init_endpoint(ctx);
	if (!ep)
		return NULL;

	mctp = calloc(1, sizeof(*mctp));
	if (!mctp) {
		errno_save = errno;
		goto err_close_ep;
	}

	mctp->sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (mctp->sd < 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot open socket for mctp endpoint %d:%d\n",
			  netid, eid);
		goto err_free_mctp;
	}
	rc = bind(mctp->sd, (struct sockaddr *)&cci_addr, sizeof(cci_addr));
	if (rc) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR,
			  "cannot bind for mctp endpoint %d:%d\n", netid, eid);
		goto err_free_mctp;
	}

	mctp->nid = netid;
	mctp->eid = eid;
	mctp->addr = cci_addr;

	ep->transport_data = mctp;
	ep->timeout_ms = MCTP_MAX_TIMEOUT;
	endpoint_probe(ep);

	return ep;

err_free_mctp:
	free(mctp);
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

#ifdef CONFIG_DBUS

static int cxlmi_mctp_add(struct cxlmi_ctx *ctx, unsigned int netid, __u8 eid)
{
	struct cxlmi_endpoint *ep = NULL;

	ep = cxlmi_open_mctp(ctx, netid, eid);
	if (!ep)
		return -1;

	return 0;
}

static bool dbus_object_is_type(DBusMessageIter *obj, int type)
{
	return dbus_message_iter_get_arg_type(obj) == type;
}

static bool dbus_object_is_dict(DBusMessageIter *obj)
{
	return dbus_object_is_type(obj, DBUS_TYPE_ARRAY) &&
		dbus_message_iter_get_element_type(obj) == DBUS_TYPE_DICT_ENTRY;
}

static int read_variant_basic(DBusMessageIter *var, int type, void *val)
{
	if (!dbus_object_is_type(var, type))
		return -1;

	dbus_message_iter_get_basic(var, val);

	return 0;
}

static bool has_message_type(DBusMessageIter *prop, uint8_t type)
{
	DBusMessageIter inner;
	uint8_t *types;
	int i, n;

	if (!dbus_object_is_type(prop, DBUS_TYPE_ARRAY) ||
	    dbus_message_iter_get_element_type(prop) != DBUS_TYPE_BYTE)
		return false;

	dbus_message_iter_recurse(prop, &inner);

	dbus_message_iter_get_fixed_array(&inner, &types, &n);

	for (i = 0; i < n; i++) {
		if (types[i] == type)
			return true;
	}

	return false;
}

static int handle_mctp_endpoint(struct cxlmi_ctx *ctx, const char* objpath,
				DBusMessageIter *props, int *opened)
{
	bool have_eid = false, have_net = false, have_cxlmi = false;
	mctp_eid_t eid;
	int net, rc = 0;

	/* for each property */
	for (;;) {
		DBusMessageIter prop, val;
		const char *propname;

		dbus_message_iter_recurse(props, &prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_STRING)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (propname)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&prop, &propname);
		dbus_message_iter_next(&prop);

		if (!dbus_object_is_type(&prop, DBUS_TYPE_VARIANT)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (propval)\n");
			return -1;
		}

		dbus_message_iter_recurse(&prop, &val);

		if (!strcmp(propname, "EID")) {
			rc = read_variant_basic(&val, DBUS_TYPE_BYTE, &eid);
			have_eid = true;
		} else if (!strcmp(propname, "NetworkId")) {
			rc = read_variant_basic(&val, DBUS_TYPE_UINT32, &net);
			have_net = true;
		} else if (!strcmp(propname, "SupportedMessageTypes")) {
			have_cxlmi = has_message_type(&val, MCTP_TYPE_CXL_CCI);
		}

		if (rc)
			return rc;

		if (!dbus_message_iter_next(props))
			break;
	}

	if (have_cxlmi) {
		if (!(have_eid && have_net)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "Missing property for %s\n", objpath);
			errno = ENOENT;
			return -1;
		}
		rc = cxlmi_mctp_add(ctx, net, eid);
		if (rc < 0) {
			int errno_save = errno;
			cxlmi_msg(ctx, LOG_ERR,
				 "Error adding net %d eid %d: %m\n", net, eid);
			errno = errno_save;
		} else
			*opened = 1;
	} else {
		/* Ignore other endpoints */
		rc = 0;
	}
	return rc;
}

/* obj is an array of (object path, interfaces) dict entries - ie., dbus type
 *   a{oa{sa{sv}}}
 */
static int handle_mctp_obj(struct cxlmi_ctx *ctx, DBusMessageIter *obj,
			   int *opened)
{
	const char *objpath = NULL;
	DBusMessageIter intfs;

	*opened = 0;

	if (!dbus_object_is_type(obj, DBUS_TYPE_OBJECT_PATH)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling object (path)\n");
		return -1;
	}

	dbus_message_iter_get_basic(obj, &objpath);
	dbus_message_iter_next(obj);

	if (!dbus_object_is_dict(obj)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling object (intfs)\n");
		return -1;
	}

	dbus_message_iter_recurse(obj, &intfs);

	/* for each interface */
	for (;;) {
		DBusMessageIter props, intf;
		const char *intfname;

		dbus_message_iter_recurse(&intfs, &intf);

		if (!dbus_object_is_type(&intf, DBUS_TYPE_STRING)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmashalling object (intf)\n");
			return -1;
		}

		dbus_message_iter_get_basic(&intf, &intfname);

		if (strcmp(intfname, MCTP_DBUS_IFACE_ENDPOINT)) {
			if (!dbus_message_iter_next(&intfs))
				break;
			continue;
		}

		dbus_message_iter_next(&intf);

		if (!dbus_object_is_dict(&intf)) {
			cxlmi_msg(ctx, LOG_ERR,
				 "error unmarshalling object (props)\n");
			return -1;
		}

		dbus_message_iter_recurse(&intf, &props);
		return handle_mctp_endpoint(ctx, objpath, &props, opened);
	}

	return 0;
}

int cxlmi_scan_mctp(struct cxlmi_ctx *ctx)
{
	DBusMessage *msg, *resp = NULL;
	DBusConnection *bus = NULL;
	DBusMessageIter args, objs;
	dbus_bool_t drc;
	DBusError berr;
	int errno_save, nopen = 0, rc = -1;

	dbus_error_init(&berr);

	bus = dbus_bus_get(DBUS_BUS_SYSTEM, &berr);
	if (!bus) {
		cxlmi_msg(ctx, LOG_ERR, "Failed connecting to D-Bus: %s (%s)\n",
			  berr.message, berr.name);
		return -1;
	}

	msg = dbus_message_new_method_call(MCTP_DBUS_IFACE,
					   MCTP_DBUS_PATH,
					   "org.freedesktop.DBus.ObjectManager",
					   "GetManagedObjects");
	if (!msg) {
		cxlmi_msg(ctx, LOG_ERR, "Failed creating call message\n");
		return -1;
	}

	resp = dbus_connection_send_with_reply_and_block(bus, msg,
							 DBUS_TIMEOUT_USE_DEFAULT,
							 &berr);
	dbus_message_unref(msg);
	if (!resp) {
		cxlmi_msg(ctx, LOG_ERR, "Failed querying MCTP D-Bus: %s (%s)\n",
			  berr.message, berr.name);
		goto out;
	}

	/* argument container */
	drc = dbus_message_iter_init(resp, &args);
	if (!drc) {
		cxlmi_msg(ctx, LOG_ERR, "can't read dbus reply args\n");
		goto out;
	}

	if (!dbus_object_is_dict(&args)) {
		cxlmi_msg(ctx, LOG_ERR, "error unmashalling args\n");
		goto out;
	}

	/* objects container */
	dbus_message_iter_recurse(&args, &objs);

	rc = 0;

	do {
		DBusMessageIter ent;
		int opened;

		dbus_message_iter_recurse(&objs, &ent);

		rc = handle_mctp_obj(ctx, &ent, &opened);
		if (rc)
			break;

		nopen += opened;
	} while (dbus_message_iter_next(&objs));
out:
	errno_save = errno;
	if (resp)
		dbus_message_unref(resp);
	if (bus)
		dbus_connection_unref(bus);
	dbus_error_free(&berr);

	if (rc < 0)
		errno = errno_save;
	else
		rc = nopen;

	return rc;
}

#else /* CONFIG_DBUS */

int cxlmi_scan_mctp(struct cxlmi_ctx *ctx)
{
	return -1;
}

#endif /* CONFIG_DBUS */

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_open(struct cxlmi_ctx *ctx,
					       const char *devname)
{
	struct cxlmi_endpoint *ep, *tmp;
	int errno_save;
	char filename[40];

	/* ensure no duplicates */
	cxlmi_for_each_endpoint(ctx, tmp) {
		if (tmp->devname && !strcmp(tmp->devname, devname)) {
			cxlmi_msg(ctx, LOG_ERR,
				  "endpoint '%s' already open\n",
				  devname);
			return NULL;
		}
	}

	ep = init_endpoint(ctx);
	if (!ep)
		return NULL;

	snprintf(filename, sizeof(filename), "/dev/cxl/%s", devname);

	ep->fd = open(filename, O_RDWR);
	if (ep->fd <= 0) {
		errno_save = errno;
		cxlmi_msg(ctx, LOG_ERR, "could not open %s\n", filename);
		goto err_close_ep;
	}

	ep->devname = strdup(devname);
	if (!ep->devname) {
		errno_save = errno;
		goto err_close_ep;
	}

	endpoint_probe(ep);

	return ep;
err_close_ep:
	cxlmi_close(ep);
	errno = errno_save;
	return NULL;
}

static const char *const cxlmi_cmd_retcode_tbl[] = {
	[CXLMI_RET_SUCCESS] = "success",
	[CXLMI_RET_BACKGROUND] = "background cmd started successfully",
	[CXLMI_RET_INPUT] = "cmd input was invalid",
	[CXLMI_RET_UNSUPPORTED] = "cmd is not supported",
	[CXLMI_RET_INTERNAL] = "internal device error",
	[CXLMI_RET_RETRY] = "temporary error, retry once",
	[CXLMI_RET_BUSY] = "ongoing background operation",
	[CXLMI_RET_MEDIADISABLED] = "media access is disabled",
	[CXLMI_RET_FWINPROGRESS] = "one FW package can be transferred at a time",
	[CXLMI_RET_FWOOO] = "FW package content was transferred out of order",
	[CXLMI_RET_FWAUTH] = "FW package authentication failed",
	[CXLMI_RET_FWSLOT] = "FW slot is not supported for requested operation",
	[CXLMI_RET_FWROLLBACK] = "rolled back to the previous active FW",
	[CXLMI_RET_FWRESET] = "FW failed to activate, needs cold reset",
	[CXLMI_RET_HANDLE] = "one or more Event Record Handles were invalid",
	[CXLMI_RET_PADDR] = "physical address specified is invalid",
	[CXLMI_RET_POISONLMT] = "poison injection limit has been reached",
	[CXLMI_RET_MEDIAFAILURE] = "permanent issue with the media",
	[CXLMI_RET_ABORT] = "background cmd was aborted by device",
	[CXLMI_RET_SECURITY] = "not valid in the current security state",
	[CXLMI_RET_PASSPHRASE] = "phrase doesn't match current set passphrase",
	[CXLMI_RET_MBUNSUPPORTED] = "unsupported on the mailbox it was issued on",
	[CXLMI_RET_PAYLOADLEN] = "invalid payload length",
	[CXLMI_RET_LOG] = "invalid or unsupported log page",
	[CXLMI_RET_INTERRUPTED] = "asynchronous event occured",
	[CXLMI_RET_FEATUREVERSION] = "unsupported feature version",
	[CXLMI_RET_FEATURESELVALUE] = "unsupported feature selection value",
	[CXLMI_RET_FEATURETRANSFERIP] = "feature transfer in progress",
	[CXLMI_RET_FEATURETRANSFEROOO] = "feature transfer out of order",
	[CXLMI_RET_RESOURCEEXHAUSTED] = "resources are exhausted",
	[CXLMI_RET_EXTLIST] = "invalid Extent List",
	[CXLMI_RET_TRANSFEROOO] = "transfer out of order",
	[CXLMI_RET_NO_BGABORT] = "on-going background cmd is not abortable",
};

CXLMI_EXPORT const char *cxlmi_cmd_retcode_tostr(enum cxlmi_cmd_retcode code)
{
	if (code > ARRAY_SIZE(cxlmi_cmd_retcode_tbl) - 1)
		return NULL;

	return cxlmi_cmd_retcode_tbl[code];
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_first_endpoint(struct cxlmi_ctx *ctx)
{
	return list_top(&ctx->endpoints, struct cxlmi_endpoint, entry);
}

CXLMI_EXPORT struct cxlmi_endpoint *cxlmi_next_endpoint(struct cxlmi_ctx *ctx,
						struct cxlmi_endpoint *ep)
{
	return ep ? list_next(&ctx->endpoints, ep, entry) : NULL;
}

void arm_cci_request(struct cxlmi_endpoint *ep, struct cxlmi_cci_msg *req,
		     size_t req_pl_sz, uint8_t cmdset, uint8_t cmd)
{
	if (ep->transport_data) {
		struct cxlmi_transport_mctp *mctp = ep->transport_data;

		*req = (struct cxlmi_cci_msg) {
			.category = CXL_MCTP_CATEGORY_REQ,
			.tag = mctp->tag++,
			.command = cmd,
			.command_set = cmdset,
			.vendor_ext_status = 0xabcd,
		};

		if (req_pl_sz) {
			req->pl_length[0] = req_pl_sz & 0xff;
			req->pl_length[1] = (req_pl_sz >> 8) & 0xff;
			req->pl_length[2] = (req_pl_sz >> 16) & 0xff;
		}
	} else {
		/* while CCIs arent sent directly over ioctl, add general info */
		*req = (struct cxlmi_cci_msg) {
			.command = cmd,
			.command_set = cmdset,
			.vendor_ext_status = 0xabcd,
		};
	}
}
