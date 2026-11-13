// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Tests for the MCTP transport, over the kernel's real AF_MCTP sockets.
 *
 * The test moves into a network namespace of its own, gives the loopback
 * device an MCTP address, and runs a small CXL responder in a child
 * process: it binds the CXL CCI and FM-API message types and answers a
 * handful of commands, or misbehaves on request. The library then talks
 * to it with cxlmi_open_mctp() like to any other endpoint. No hardware,
 * QEMU devices or mctpd are involved.
 *
 * This needs a kernel with CONFIG_MCTP, and root: for the namespace, and
 * because binding an MCTP socket takes CAP_NET_BIND_SERVICE in the initial
 * user namespace. Exits with 77 (skipped) if either is missing.
 */
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <linux/if_addr.h>
#include <linux/mctp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <ccan/endian/endian.h>

#include <libcxlmi.h>

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

#define MCTP_TYPE_CXL_FMAPI	0x7
#define MCTP_TYPE_CXL_CCI	0x8

#define SKIP		77

#define NET		1	/* the kernel's default MCTP network */
#define EID		8
#define EID_NOBODY	9	/* not an address of ours */

#define SERIAL		0x0123456789abcdefULL
#define TIMESTAMP	0x1122334455667788ULL

/* responder, run in a child process */

struct cci_msg {
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3];
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__((packed));

enum fault {
	F_NONE,
	F_DROP,		/* no reply */
	F_BADTAG,	/* reply with another CCI tag */
	F_BADCAT,	/* reply is not marked as a response */
	F_BADOP,	/* reply to another command */
	F_SHORT,	/* reply cut short of the CCI header */
	F_BADLEN,	/* payload length field larger than the payload */
	F_TRUNC,	/* payload shorter than the payload length field */
};

struct responder {
	bool is_switch;
	int nr_faults;
	struct {
		uint16_t opcode;
		enum fault fault;
	} faults[8];
};

static enum fault fault_for(const struct responder *r, uint16_t opcode)
{
	int i;

	for (i = 0; i < r->nr_faults; i++) {
		if (r->faults[i].opcode == opcode)
			return r->faults[i].fault;
	}

	return F_NONE;
}

/* returns the output payload length, and the return code in *rc */
static size_t responder_handle(const struct responder *r, bool fmapi,
			       uint16_t opcode, const uint8_t *in,
			       size_t in_len, uint8_t *out, uint16_t *rc)
{
	static uint64_t timestamp = TIMESTAMP;
	static uint8_t msg_limit = 9;
	uint64_t le64;

	*rc = CXLMI_RET_SUCCESS;

	if (fmapi) {
		if (opcode == 0x5100 && r->is_switch) {
			/* Identify Switch Device */
			memset(out, 0, 73);
			out[2] = 4;		/* physical ports */
			out[3] = 1;		/* VCSs */
			out[4] = 0x0f;		/* active ports */
			out[36] = 0x01;		/* active VCSs */
			out[68] = 3;		/* vPPBs */
			out[70] = 1;		/* bound vPPBs */
			return 73;
		}
		*rc = CXLMI_RET_UNSUPPORTED;
		return 0;
	}

	switch (opcode) {
	case 0x0001:	/* Identify */
		memset(out, 0, 18);
		out[0] = 0x86;			/* vendor 8086h */
		out[1] = 0x80;
		out[2] = 0x0d;			/* device 0d0dh */
		out[3] = 0x0d;
		le64 = cpu_to_le64(SERIAL);
		memcpy(out + 8, &le64, 8);
		out[16] = 9;			/* max message size */
		out[17] = r->is_switch ? 0x00 : 0x03;
		return 18;
	case 0x0002:	/* Background Operation Status */
		memset(out, 0, 8);
		return 8;
	case 0x0003:	/* Get Response Message Limit */
		out[0] = msg_limit;
		return 1;
	case 0x0004:	/* Set Response Message Limit */
		if (in_len != 1) {
			*rc = CXLMI_RET_PAYLOADLEN;
			return 0;
		}
		msg_limit = in[0];
		out[0] = msg_limit;
		return 1;
	case 0x0300:	/* Get Timestamp */
		le64 = cpu_to_le64(timestamp);
		memcpy(out, &le64, 8);
		return 8;
	case 0x0301:	/* Set Timestamp */
		if (in_len != 8) {
			*rc = CXLMI_RET_PAYLOADLEN;
			return 0;
		}
		memcpy(&le64, in, 8);
		timestamp = le64_to_cpu(le64);
		return 0;
	case 0x0400:	/* Get Supported Logs: two entries */
		memset(out, 0, 8 + 2 * 20);
		out[0] = 2;
		memset(out + 8, 0xaa, 16);
		out[8 + 16] = 0x40;		/* log size 40h */
		memset(out + 28, 0xbb, 16);
		out[28 + 17] = 0x01;		/* log size 100h */
		return 8 + 2 * 20;
	case 0x4000:	/* Identify Memory Device */
		if (r->is_switch)
			break;
		memset(out, 0, 0x45);
		memcpy(out, "RESPONDER-1.0", 13);
		out[0x10] = 4;			/* total capacity */
		return 0x45;
	}

	*rc = CXLMI_RET_UNSUPPORTED;
	return 0;
}

static int responder_bind(uint8_t type)
{
	struct sockaddr_mctp addr = {
		.smctp_family = AF_MCTP,
		.smctp_network = MCTP_NET_ANY,
		.smctp_addr.s_addr = MCTP_ADDR_ANY,
		.smctp_type = type,
		.smctp_tag = MCTP_TAG_OWNER,
	};
	int sd;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0 || bind(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		return -1;

	return sd;
}

static void responder_reply(const struct responder *r, int sd, bool fmapi)
{
	static uint8_t rx[4096], tx[4096];
	struct cci_msg *req = (void *)rx, *rsp = (void *)tx;
	struct sockaddr_mctp peer = { 0 };
	socklen_t peer_len = sizeof(peer);
	uint16_t opcode, rc;
	size_t n, tx_len;
	uint32_t req_pl;
	ssize_t len;

	len = recvfrom(sd, rx, sizeof(rx), MSG_TRUNC,
		       (struct sockaddr *)&peer, &peer_len);
	if (len < (ssize_t)sizeof(*req) || len > (ssize_t)sizeof(rx) ||
	    req->category != 0)
		return;

	req_pl = req->pl_length[0] | req->pl_length[1] << 8 |
		(req->pl_length[2] & 0xf) << 16;
	opcode = req->command_set << 8 | req->command;

	memset(rsp, 0, sizeof(*rsp));
	rsp->category = 1;
	rsp->tag = req->tag;
	rsp->command = req->command;
	rsp->command_set = req->command_set;

	if (req_pl != len - sizeof(*req)) {
		rc = CXLMI_RET_PAYLOADLEN;
		n = 0;
	} else {
		n = responder_handle(r, fmapi, opcode, req->payload, req_pl,
				     rsp->payload, &rc);
	}

	rsp->return_code = cpu_to_le16(rc);
	rsp->pl_length[0] = n & 0xff;
	rsp->pl_length[1] = (n >> 8) & 0xff;
	rsp->pl_length[2] = (n >> 16) & 0xf;
	tx_len = sizeof(*rsp) + n;

	switch (fault_for(r, opcode)) {
	case F_DROP:
		return;
	case F_BADTAG:
		rsp->tag ^= 0x55;
		break;
	case F_BADCAT:
		rsp->category = 0;
		break;
	case F_BADOP:
		rsp->command ^= 1;
		break;
	case F_SHORT:
		tx_len = 6;
		break;
	case F_BADLEN:
		rsp->pl_length[0]++;
		break;
	case F_TRUNC:
		tx_len--;
		break;
	case F_NONE:
		break;
	}

	/* the reply goes back with the tag of the request, not as its owner */
	peer.smctp_tag &= ~MCTP_TAG_OWNER;
	sendto(sd, tx, tx_len, 0, (struct sockaddr *)&peer, sizeof(peer));
}

static void responder_run(const struct responder *r, int ready_fd)
{
	struct pollfd pfd[2];
	int i;

	prctl(PR_SET_PDEATHSIG, SIGKILL);

	pfd[0].fd = responder_bind(MCTP_TYPE_CXL_CCI);
	pfd[1].fd = responder_bind(MCTP_TYPE_CXL_FMAPI);
	if (pfd[0].fd < 0 || pfd[1].fd < 0) {
		i = errno;
		if (write(ready_fd, &i, sizeof(i)) != sizeof(i))
			_exit(1);
		_exit(1);
	}
	pfd[0].events = pfd[1].events = POLLIN;

	i = 0;
	if (write(ready_fd, &i, sizeof(i)) != sizeof(i))
		_exit(1);
	close(ready_fd);

	for (;;) {
		if (poll(pfd, 2, -1) < 0 && errno != EINTR)
			_exit(1);
		for (i = 0; i < 2; i++) {
			if (pfd[i].revents & POLLIN)
				responder_reply(r, pfd[i].fd, i == 1);
		}
	}
}

/* returns 0 and the pid, or the errno the responder failed to bind with */
static int responder_start(const struct responder *r, pid_t *pid)
{
	int fds[2], err = EIO;

	*pid = -1;

	if (pipe(fds))
		return errno;

	*pid = fork();
	if (*pid < 0)
		return errno;
	if (!*pid) {
		close(fds[0]);
		responder_run(r, fds[1]);
	}

	close(fds[1]);
	if (read(fds[0], &err, sizeof(err)) != sizeof(err))
		err = EIO;
	close(fds[0]);

	if (err)
		waitpid(*pid, NULL, 0);

	return err;
}

static void responder_stop(pid_t pid)
{
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

/* bring the loopback device up and give it an MCTP address */
static int setup_loopback(uint8_t eid)
{
	struct {
		struct nlmsghdr nh;
		struct ifaddrmsg ifa;
		struct rtattr rta;
		uint8_t eid;
		uint8_t pad[3];
	} req = { 0 };
	struct {
		struct nlmsghdr nh;
		struct nlmsgerr err;
	} ack;
	struct ifreq ifr = { .ifr_name = "lo" };
	int sd, rc;

	sd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sd < 0)
		return -1;
	rc = ioctl(sd, SIOCGIFFLAGS, &ifr);
	if (!rc) {
		ifr.ifr_flags |= IFF_UP;
		rc = ioctl(sd, SIOCSIFFLAGS, &ifr);
	}
	close(sd);
	if (rc)
		return -1;

	sd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sd < 0)
		return -1;

	req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(req.ifa)) + RTA_LENGTH(1);
	req.nh.nlmsg_type = RTM_NEWADDR;
	req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
	req.ifa.ifa_family = AF_MCTP;
	req.ifa.ifa_index = if_nametoindex("lo");
	req.rta.rta_type = IFA_LOCAL;
	req.rta.rta_len = RTA_LENGTH(1);
	req.eid = eid;

	if (send(sd, &req, req.nh.nlmsg_len, 0) < 0 ||
	    recv(sd, &ack, sizeof(ack), 0) < 0) {
		close(sd);
		return -1;
	}
	close(sd);

	if (ack.nh.nlmsg_type == NLMSG_ERROR && ack.err.error) {
		errno = -ack.err.error;
		return -1;
	}

	return 0;
}

/* tests */

static int failures, checks;

#define CHECK(cond, fmt, ...) do {					\
	checks++;							\
	if (!(cond)) {							\
		failures++;						\
		printf("FAIL %s: " fmt "\n", __func__, ##__VA_ARGS__);	\
	}								\
} while (0)

static void __attribute__((noreturn)) die(const char *what)
{
	fprintf(stderr, "mctp-loopback-tests: %s: %s\n", what,
		strerror(errno));
	exit(1);
}

static void __attribute__((noreturn)) skip(const char *why)
{
	fprintf(stderr, "mctp-loopback-tests: %s, skipping\n", why);
	exit(SKIP);
}

static long ms_since(const struct timespec *t0)
{
	struct timespec t1;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	return (t1.tv_sec - t0->tv_sec) * 1000 +
		(t1.tv_nsec - t0->tv_nsec) / 1000000;
}

static struct cxlmi_ctx *new_ctx(void)
{
	struct cxlmi_ctx *ctx = cxlmi_new_ctx(stdout, LOG_CRIT);

	if (!ctx)
		die("cannot create context");

	cxlmi_set_probe_enabled(ctx, true);

	return ctx;
}

static pid_t start(const struct responder *r)
{
	pid_t pid;

	errno = responder_start(r, &pid);
	if (errno)
		die("cannot start the responder");

	return pid;
}

static void report(const char *test, int before)
{
	printf("%s %s\n", failures == before ? "ok  " : "FAIL", test);
}

/* generic commands, and what the probe makes of the component type */
static void test_commands(bool is_switch)
{
	struct responder r = { .is_switch = is_switch };
	struct cxlmi_cmd_identify_rsp id = { 0 };
	struct cxlmi_cmd_get_timestamp_rsp ts = { 0 };
	struct cxlmi_cmd_set_timestamp_req set_ts = {
		.timestamp = 0xdeadbeefcafef00dULL,
	};
	struct cxlmi_cmd_get_response_msg_limit_rsp limit = { 0 };
	struct cxlmi_cmd_set_response_msg_limit_req set_limit = { .limit = 12 };
	struct cxlmi_cmd_set_response_msg_limit_rsp new_limit = { 0 };
	struct cxlmi_cmd_bg_op_status_rsp bg;
	struct cxlmi_cmd_get_supported_logs_rsp *logs;
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp sw = { 0 };
	struct cxlmi_ctx *ctx = new_ctx();
	struct cxlmi_endpoint *ep;
	pid_t pid = start(&r);
	int before = failures, rc;

	ep = cxlmi_open_mctp(ctx, NET, EID);
	CHECK(ep, "cannot open the endpoint");
	if (!ep)
		goto out;

	CHECK(!cxlmi_open_mctp(ctx, NET, EID), "endpoint opened twice");
	CHECK(cxlmi_endpoint_has_fmapi(ep), "probe did not enable FM-API");

	rc = cxlmi_cmd_identify(ep, NULL, &id);
	CHECK(rc == 0, "identify: %d", rc);
	CHECK(id.vendor_id == 0x8086 && id.device_id == 0x0d0d,
	      "identify: ids %04x:%04x", id.vendor_id, id.device_id);
	CHECK(id.serial_num == SERIAL, "identify: serial %llx",
	      (unsigned long long)id.serial_num);
	CHECK(id.component_type == (is_switch ? 0 : 3),
	      "identify: component type %d", id.component_type);

	rc = cxlmi_cmd_get_timestamp(ep, NULL, &ts);
	CHECK(rc == 0 && ts.timestamp == TIMESTAMP, "get timestamp: %d, %llx",
	      rc, (unsigned long long)ts.timestamp);
	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	CHECK(rc == 0, "set timestamp: %d", rc);
	rc = cxlmi_cmd_get_timestamp(ep, NULL, &ts);
	CHECK(rc == 0 && ts.timestamp == set_ts.timestamp,
	      "timestamp read back: %d, %llx", rc,
	      (unsigned long long)ts.timestamp);

	rc = cxlmi_cmd_get_response_msg_limit(ep, NULL, &limit);
	CHECK(rc == 0 && limit.limit == 9, "get message limit: %d, %d", rc,
	      limit.limit);
	rc = cxlmi_cmd_set_response_msg_limit(ep, NULL, &set_limit,
					      &new_limit);
	CHECK(rc == 0 && new_limit.limit == 12, "set message limit: %d, %d",
	      rc, new_limit.limit);

	rc = cxlmi_cmd_bg_op_status(ep, NULL, &bg);
	CHECK(rc == 0, "background operation status: %d", rc);

	/* a response of variable length */
	logs = calloc(1, sizeof(*logs) +
		      CXLMI_MAX_SUPPORTED_LOGS * sizeof(*logs->entries));
	if (!logs)
		die("out of memory");
	rc = cxlmi_cmd_get_supported_logs(ep, NULL, logs);
	CHECK(rc == 0 && logs->num_supported_log_entries == 2,
	      "get supported logs: %d, %d entries", rc,
	      logs->num_supported_log_entries);
	CHECK(logs->entries[0].uuid[0] == 0xaa &&
	      logs->entries[0].log_size == 0x40 &&
	      logs->entries[1].uuid[15] == 0xbb &&
	      logs->entries[1].log_size == 0x100,
	      "get supported logs: entries %x/%x %x/%x",
	      logs->entries[0].uuid[0], logs->entries[0].log_size,
	      logs->entries[1].uuid[15], logs->entries[1].log_size);
	free(logs);

	/* a return code from the device, not a transport error */
	rc = cxlmi_cmd_request_bg_op_abort(ep, NULL);
	CHECK(rc == CXLMI_RET_UNSUPPORTED, "unsupported command: %d", rc);

	/* the FM-API message type goes over a socket of its own */
	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &sw);
	if (is_switch) {
		CHECK(rc == 0 && sw.num_physical_ports == 4 &&
		      sw.num_total_vppb == 3,
		      "identify switch: %d, %d ports, %d vPPBs", rc,
		      sw.num_physical_ports, sw.num_total_vppb);
	} else {
		struct cxlmi_cmd_memdev_identify_rsp md = { 0 };

		CHECK(rc == CXLMI_RET_UNSUPPORTED,
		      "identify switch on a type 3: %d", rc);

		rc = cxlmi_cmd_memdev_identify(ep, NULL, &md);
		CHECK(rc == 0 && md.total_capacity == 4 &&
		      !strncmp(md.fw_revision, "RESPONDER-1.0",
			       sizeof(md.fw_revision)),
		      "identify memory device: %d, capacity %llu", rc,
		      (unsigned long long)md.total_capacity);
	}
out:
	responder_stop(pid);
	cxlmi_free_ctx(ctx);
	report(is_switch ? "commands to a switch" : "commands to a type 3",
	       before);
}

/* every way a reply can be wrong is a failure, and none is fatal */
static void test_bad_replies(void)
{
	struct responder r = {
		.is_switch = true,
		.nr_faults = 7,
		.faults = {
			{ 0x0002, F_DROP },
			{ 0x0003, F_BADTAG },
			{ 0x0300, F_BADLEN },
			{ 0x0400, F_SHORT },
			{ 0x0301, F_BADCAT },
			{ 0x0004, F_BADOP },
			{ 0x5100, F_TRUNC },
		},
	};
	struct cxlmi_cmd_identify_rsp id = { 0 };
	struct cxlmi_cmd_get_timestamp_rsp ts;
	struct cxlmi_cmd_set_timestamp_req set_ts = { .timestamp = 1 };
	struct cxlmi_cmd_get_response_msg_limit_rsp limit;
	struct cxlmi_cmd_set_response_msg_limit_req set_limit = { .limit = 12 };
	struct cxlmi_cmd_set_response_msg_limit_rsp new_limit;
	struct cxlmi_cmd_bg_op_status_rsp bg;
	struct cxlmi_cmd_get_supported_logs_rsp *logs;
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp sw;
	struct cxlmi_ctx *ctx = new_ctx();
	struct cxlmi_endpoint *ep;
	pid_t pid = start(&r);
	int before = failures, rc;
	struct timespec t0;
	long ms;

	ep = cxlmi_open_mctp(ctx, NET, EID);
	CHECK(ep, "cannot open the endpoint");
	if (!ep)
		goto out;

	CHECK(cxlmi_endpoint_set_timeout(ep, 300) == 0, "cannot set timeout");

	clock_gettime(CLOCK_MONOTONIC, &t0);
	errno = 0;
	rc = cxlmi_cmd_bg_op_status(ep, NULL, &bg);
	ms = ms_since(&t0);
	CHECK(rc == -1 && errno == ETIMEDOUT, "no reply: %d, errno %d", rc,
	      errno);
	CHECK(ms >= 250 && ms < 2000, "no reply: gave up after %ld ms", ms);

	rc = cxlmi_cmd_get_response_msg_limit(ep, NULL, &limit);
	CHECK(rc == -1, "wrong tag: %d", rc);

	rc = cxlmi_cmd_get_timestamp(ep, NULL, &ts);
	CHECK(rc == -1, "payload length field too large: %d", rc);

	logs = calloc(1, sizeof(*logs) +
		      CXLMI_MAX_SUPPORTED_LOGS * sizeof(*logs->entries));
	if (!logs)
		die("out of memory");
	rc = cxlmi_cmd_get_supported_logs(ep, NULL, logs);
	CHECK(rc == -1, "reply shorter than the header: %d", rc);
	free(logs);

	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	CHECK(rc == -1, "reply that is not a response: %d", rc);

	rc = cxlmi_cmd_set_response_msg_limit(ep, NULL, &set_limit,
					      &new_limit);
	CHECK(rc == -1, "reply to another command: %d", rc);

	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &sw);
	CHECK(rc == -1, "truncated payload: %d", rc);

	/* the endpoint is still good for a well-behaved command */
	rc = cxlmi_cmd_identify(ep, NULL, &id);
	CHECK(rc == 0 && id.serial_num == SERIAL, "identify afterwards: %d",
	      rc);
out:
	responder_stop(pid);
	cxlmi_free_ctx(ctx);
	report("bad replies", before);
}

/* nothing answers: commands fail, and do not hang */
static void test_no_responder(uint8_t eid, const char *test)
{
	struct cxlmi_cmd_identify_rsp id;
	struct cxlmi_ctx *ctx = new_ctx();
	struct cxlmi_endpoint *ep;
	int before = failures, rc;
	struct timespec t0;
	long ms;

	/* the probe would wait out the default timeout */
	cxlmi_set_probe_enabled(ctx, false);

	ep = cxlmi_open_mctp(ctx, NET, eid);
	CHECK(ep, "cannot open the endpoint");
	if (!ep)
		goto out;

	CHECK(cxlmi_endpoint_set_timeout(ep, 300) == 0, "cannot set timeout");

	clock_gettime(CLOCK_MONOTONIC, &t0);
	rc = cxlmi_cmd_identify(ep, NULL, &id);
	ms = ms_since(&t0);
	CHECK(rc == -1, "identify: %d", rc);
	CHECK(ms < 2000, "gave up after %ld ms", ms);
out:
	cxlmi_free_ctx(ctx);
	report(test, before);
}

int main(void)
{
	struct responder r = { .is_switch = true };
	pid_t pid;
	int sd, err;

	sd = socket(AF_MCTP, SOCK_DGRAM, 0);
	if (sd < 0)
		skip("no AF_MCTP sockets in this kernel");
	close(sd);

	if (unshare(CLONE_NEWNET)) {
		if (errno == EPERM)
			skip("not allowed to create a network namespace");
		die("cannot create a network namespace");
	}

	if (setup_loopback(EID))
		die("cannot set up an MCTP address on lo");

	err = responder_start(&r, &pid);
	if (err == EACCES || err == EPERM)
		skip("not allowed to bind MCTP sockets");
	if (err) {
		errno = err;
		die("cannot start the responder");
	}
	responder_stop(pid);

	test_commands(true);
	test_commands(false);
	test_bad_replies();
	test_no_responder(EID, "no responder");
	test_no_responder(EID_NOBODY, "no such endpoint");

	printf("%d checks, %d failed\n", checks, failures);
	return failures ? 1 : 0;
}
