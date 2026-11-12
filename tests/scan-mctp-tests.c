// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Tests for cxlmi_scan_mctp(), the D-Bus discovery of MCTP endpoints.
 *
 * A private dbus-daemon stands in for the system bus, and a child process
 * stands in for mctpd: it owns one of mctpd's bus names and answers
 * ObjectManager.GetManagedObjects with a canned set of endpoints. No MCTP
 * support is needed from the kernel: AF_MCTP sockets are replaced with
 * AF_UNIX ones, and endpoints are not probed.
 *
 * Exits with 77 (skipped) when dbus-daemon cannot be started.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include <dbus/dbus.h>

#include <libcxlmi.h>

#ifndef AF_MCTP
#define AF_MCTP 45
#endif

#define NAME_OPENBMC	"xyz.openbmc_project.MCTP"
#define PATH_OPENBMC	"/xyz/openbmc_project/mctp"
#define NAME_CC		"au.com.codeconstruct.MCTP1"
#define PATH_CC		"/au/com/codeconstruct/mctp1"
#define IFACE_ENDPOINT	"xyz.openbmc_project.MCTP.Endpoint"

#define TYPE_PLDM	0x01
#define TYPE_FMAPI	0x07
#define TYPE_CCI	0x08

#define SKIP		77

/*
 * The library is not asked to talk to the endpoints it finds, only to
 * open them, so any datagram socket will do in place of an AF_MCTP one.
 * This definition takes precedence over libc's for the library too.
 */
int socket(int domain, int type, int protocol)
{
	if (domain == AF_MCTP) {
		domain = AF_UNIX;
		protocol = 0;
	}
	return syscall(SYS_socket, domain, type, protocol);
}

struct fake_endpoint {
	unsigned int net;
	unsigned char eid;
	unsigned char types[4];
	int ntypes;
};

struct fake_mctpd {
	const char *name;	/* bus name, NULL for no mctpd at all */
	const char *path;
	int net_type;		/* D-Bus type of NetworkId */
	int eid_type;		/* D-Bus type of EID */
	bool no_props;		/* endpoints have an empty property dict */
	bool bare_object;	/* add an object with no interfaces */
	int nr;
	struct fake_endpoint ep[4];
};

static const struct fake_endpoint ep_cci_8 = { 1, 8, { TYPE_CCI }, 1 };
static const struct fake_endpoint ep_both_9 = {
	1, 9, { TYPE_PLDM, TYPE_FMAPI, TYPE_CCI }, 3
};
static const struct fake_endpoint ep_pldm_10 = { 1, 10, { TYPE_PLDM }, 1 };
static const struct fake_endpoint ep_cci_net2 = { 2, 8, { TYPE_CCI }, 1 };

static DBusConnection *ctl;	/* the test's own connection, for bookkeeping */

static void die(const char *what)
{
	fprintf(stderr, "scan-mctp-tests: %s\n", what);
	exit(1);
}

/* fake mctpd, run in a child process */

static void append_variant(DBusMessageIter *dict, const char *key,
			   const char *sig, int type, const void *val)
{
	DBusMessageIter ent, var;

	dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL,
					 &ent);
	dbus_message_iter_append_basic(&ent, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&ent, DBUS_TYPE_VARIANT, sig, &var);
	dbus_message_iter_append_basic(&var, type, val);
	dbus_message_iter_close_container(&ent, &var);
	dbus_message_iter_close_container(dict, &ent);
}

static void append_endpoint_props(DBusMessageIter *props,
				  const struct fake_mctpd *f,
				  const struct fake_endpoint *ep)
{
	const char *key = "SupportedMessageTypes";
	const unsigned char *types = ep->types;
	DBusMessageIter ent, var, arr;
	dbus_uint32_t u = ep->net, eid_u = ep->eid;
	dbus_int32_t i = ep->net;
	char sig[2] = { 0 };

	sig[0] = f->eid_type;
	if (f->eid_type == DBUS_TYPE_BYTE)
		append_variant(props, "EID", sig, DBUS_TYPE_BYTE, &ep->eid);
	else
		append_variant(props, "EID", sig, f->eid_type, &eid_u);

	sig[0] = f->net_type;
	append_variant(props, "NetworkId", sig, f->net_type,
		       f->net_type == DBUS_TYPE_INT32 ? (void *)&i : (void *)&u);

	dbus_message_iter_open_container(props, DBUS_TYPE_DICT_ENTRY, NULL,
					 &ent);
	dbus_message_iter_append_basic(&ent, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&ent, DBUS_TYPE_VARIANT, "ay", &var);
	dbus_message_iter_open_container(&var, DBUS_TYPE_ARRAY, "y", &arr);
	dbus_message_iter_append_fixed_array(&arr, DBUS_TYPE_BYTE, &types,
					     ep->ntypes);
	dbus_message_iter_close_container(&var, &arr);
	dbus_message_iter_close_container(&ent, &var);
	dbus_message_iter_close_container(props, &ent);
}

static void append_interface(DBusMessageIter *intfs, const char *name,
			     const struct fake_mctpd *f,
			     const struct fake_endpoint *ep)
{
	DBusMessageIter ent, props;

	dbus_message_iter_open_container(intfs, DBUS_TYPE_DICT_ENTRY, NULL,
					 &ent);
	dbus_message_iter_append_basic(&ent, DBUS_TYPE_STRING, &name);
	dbus_message_iter_open_container(&ent, DBUS_TYPE_ARRAY, "{sv}",
					 &props);
	if (ep && !f->no_props)
		append_endpoint_props(&props, f, ep);
	dbus_message_iter_close_container(&ent, &props);
	dbus_message_iter_close_container(intfs, &ent);
}

static void append_object(DBusMessageIter *objs, const char *path,
			  const struct fake_mctpd *f,
			  const struct fake_endpoint *ep)
{
	DBusMessageIter ent, intfs;

	dbus_message_iter_open_container(objs, DBUS_TYPE_DICT_ENTRY, NULL,
					 &ent);
	dbus_message_iter_append_basic(&ent, DBUS_TYPE_OBJECT_PATH, &path);
	dbus_message_iter_open_container(&ent, DBUS_TYPE_ARRAY, "{sa{sv}}",
					 &intfs);
	if (ep) {
		/* as mctpd does, list other interfaces around the endpoint one */
		append_interface(&intfs, "org.freedesktop.DBus.Peer", f, NULL);
		append_interface(&intfs, IFACE_ENDPOINT, f, ep);
		append_interface(&intfs, "xyz.openbmc_project.Common.UUID", f,
				 NULL);
	}
	dbus_message_iter_close_container(&ent, &intfs);
	dbus_message_iter_close_container(objs, &ent);
}

static DBusHandlerResult fake_mctpd_filter(DBusConnection *conn,
					   DBusMessage *msg, void *data)
{
	const struct fake_mctpd *f = data;
	DBusMessageIter args, objs;
	DBusMessage *reply;
	char path[128];
	int i;

	if (!dbus_message_is_method_call(msg,
					 "org.freedesktop.DBus.ObjectManager",
					 "GetManagedObjects") ||
	    !dbus_message_has_path(msg, f->path))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	reply = dbus_message_new_method_return(msg);
	dbus_message_iter_init_append(reply, &args);
	dbus_message_iter_open_container(&args, DBUS_TYPE_ARRAY,
					 "{oa{sa{sv}}}", &objs);
	if (f->bare_object) {
		snprintf(path, sizeof(path), "%s/networks", f->path);
		append_object(&objs, path, f, NULL);
	}
	for (i = 0; i < f->nr; i++) {
		snprintf(path, sizeof(path), "%s/networks/%u/endpoints/%u",
			 f->path, f->ep[i].net, f->ep[i].eid);
		append_object(&objs, path, f, &f->ep[i]);
	}
	dbus_message_iter_close_container(&args, &objs);

	dbus_connection_send(conn, reply, NULL);
	dbus_message_unref(reply);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void fake_mctpd_run(const struct fake_mctpd *f, int ready_fd)
{
	DBusConnection *conn;
	int i, rc = -1;

	prctl(PR_SET_PDEATHSIG, SIGKILL);

	conn = dbus_bus_get_private(DBUS_BUS_SYSTEM, NULL);
	if (!conn)
		_exit(1);

	/* a previous fake may not have been cleaned up by the bus yet */
	for (i = 0; i < 500; i++) {
		rc = dbus_bus_request_name(conn, f->name,
					   DBUS_NAME_FLAG_DO_NOT_QUEUE, NULL);
		if (rc == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
			break;
		usleep(10000);
	}
	if (rc != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER)
		_exit(1);

	if (!dbus_connection_add_filter(conn, fake_mctpd_filter, (void *)f,
					NULL))
		_exit(1);

	if (write(ready_fd, "r", 1) != 1)
		_exit(1);
	close(ready_fd);

	while (dbus_connection_read_write_dispatch(conn, -1))
		;
	_exit(0);
}

static pid_t fake_mctpd_start(const struct fake_mctpd *f)
{
	int fds[2];
	pid_t pid;
	char c;

	if (!f->name)
		return 0;

	if (pipe(fds))
		die("pipe failed");

	pid = fork();
	if (pid < 0)
		die("fork failed");
	if (!pid) {
		close(fds[0]);
		fake_mctpd_run(f, fds[1]);
	}

	close(fds[1]);
	if (read(fds[0], &c, 1) != 1)
		die("fake mctpd did not start");
	close(fds[0]);

	return pid;
}

static void fake_mctpd_stop(const struct fake_mctpd *f, pid_t pid)
{
	int i;

	if (!pid)
		return;

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);

	/* wait for the bus to notice, so the next test starts clean */
	for (i = 0; i < 500; i++) {
		if (!dbus_bus_name_has_owner(ctl, f->name, NULL))
			return;
		usleep(10000);
	}
	die("fake mctpd name still owned");
}

/* private bus */

static pid_t bus_start(void)
{
	char addr[256], arg[32];
	int fds[2];
	ssize_t n;
	pid_t pid;

	if (pipe(fds))
		die("pipe failed");

	pid = fork();
	if (pid < 0)
		die("fork failed");
	if (!pid) {
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		close(fds[0]);
		snprintf(arg, sizeof(arg), "--print-address=%d", fds[1]);
		execlp("dbus-daemon", "dbus-daemon", "--session", "--nofork",
		       "--nopidfile", arg, (char *)NULL);
		_exit(127);
	}

	close(fds[1]);
	n = read(fds[0], addr, sizeof(addr) - 1);
	close(fds[0]);
	if (n <= 0) {
		waitpid(pid, NULL, 0);
		fprintf(stderr, "scan-mctp-tests: cannot run dbus-daemon, skipping\n");
		exit(SKIP);
	}
	addr[n] = '\0';
	addr[strcspn(addr, "\n")] = '\0';

	/* what the library believes to be the system bus */
	setenv("DBUS_SYSTEM_BUS_ADDRESS", addr, 1);

	return pid;
}

/* tests */

static int nr_endpoints(struct cxlmi_ctx *ctx)
{
	struct cxlmi_endpoint *ep;
	int n = 0;

	cxlmi_for_each_endpoint(ctx, ep)
		n++;

	return n;
}

static struct cxlmi_ctx *new_ctx(void)
{
	struct cxlmi_ctx *ctx = cxlmi_new_ctx(stderr, LOG_ERR);

	if (!ctx)
		die("cannot create context");

	/* nothing is listening on the fake endpoints */
	cxlmi_set_probe_enabled(ctx, false);

	return ctx;
}

static int failures;

static void check(const char *test, const char *what, int got, int expected)
{
	if (got == expected)
		return;

	fprintf(stderr, "FAIL %s: %s is %d, expected %d\n", test, what, got,
		expected);
	failures++;
}

/* one scan of a fresh context against one fake mctpd */
static void test_scan(const char *test, const struct fake_mctpd *f,
		      int expected)
{
	struct cxlmi_ctx *ctx = new_ctx();
	pid_t pid = fake_mctpd_start(f);
	int before = failures;

	check(test, "scan result", cxlmi_scan_mctp(ctx), expected);
	check(test, "endpoint count", nr_endpoints(ctx),
	      expected < 0 ? 0 : expected);

	fake_mctpd_stop(f, pid);
	cxlmi_free_ctx(ctx);

	printf("%s %s\n", failures == before ? "ok  " : "FAIL", test);
}

/* scanning again only opens what is new, and keeps what is there */
static void test_rescan(void)
{
	static const char test[] = "rescan";
	struct fake_mctpd f = {
		.name = NAME_CC, .path = PATH_CC,
		.net_type = DBUS_TYPE_UINT32, .eid_type = DBUS_TYPE_BYTE,
		.nr = 2, .ep = { ep_cci_8, ep_pldm_10 },
	};
	struct cxlmi_ctx *ctx = new_ctx();
	int before = failures;
	pid_t pid;

	pid = fake_mctpd_start(&f);
	check(test, "first scan", cxlmi_scan_mctp(ctx), 1);
	check(test, "second scan", cxlmi_scan_mctp(ctx), 0);
	check(test, "endpoint count", nr_endpoints(ctx), 1);
	fake_mctpd_stop(&f, pid);

	/* two more CXL endpoints show up, one on another network */
	f.nr = 4;
	f.ep[2] = ep_both_9;
	f.ep[3] = ep_cci_net2;
	pid = fake_mctpd_start(&f);
	check(test, "scan after hotplug", cxlmi_scan_mctp(ctx), 2);
	check(test, "endpoint count after hotplug", nr_endpoints(ctx), 3);
	fake_mctpd_stop(&f, pid);

	/* an endpoint opened by hand is not opened again by a scan */
	cxlmi_free_ctx(ctx);
	ctx = new_ctx();
	if (!cxlmi_open_mctp(ctx, 1, 8))
		die("cannot open endpoint");
	pid = fake_mctpd_start(&f);
	check(test, "scan after manual open", cxlmi_scan_mctp(ctx), 2);
	check(test, "endpoint count after manual open", nr_endpoints(ctx), 3);
	fake_mctpd_stop(&f, pid);

	cxlmi_free_ctx(ctx);

	printf("%s %s\n", failures == before ? "ok  " : "FAIL", test);
}

#define MCTPD(_name, _path, _net, _eid, ...)				\
	&(struct fake_mctpd){ .name = _name, .path = _path,		\
			      .net_type = _net, .eid_type = _eid,	\
			      __VA_ARGS__ }

#define THREE	.nr = 3, .ep = { ep_cci_8, ep_pldm_10, ep_both_9 }

int main(void)
{
	pid_t bus;

	bus = bus_start();

	ctl = dbus_bus_get_private(DBUS_BUS_SYSTEM, NULL);
	if (!ctl)
		die("cannot connect to the private bus");
	dbus_connection_set_exit_on_disconnect(ctl, FALSE);

	/* mctpd v2.x: its own names, NetworkId is 'u' */
	test_scan("mctpd 2.x names",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			THREE), 2);

	/* mctpd v1.x: OpenBMC names, NetworkId is 'i' */
	test_scan("mctpd 1.x names, NetworkId as int32",
		  MCTPD(NAME_OPENBMC, PATH_OPENBMC, DBUS_TYPE_INT32,
			DBUS_TYPE_BYTE, THREE), 2);

	/* mctpd snapshots between the two: OpenBMC names, NetworkId is 'u' */
	test_scan("OpenBMC names, NetworkId as uint32",
		  MCTPD(NAME_OPENBMC, PATH_OPENBMC, DBUS_TYPE_UINT32,
			DBUS_TYPE_BYTE, THREE), 2);

	test_scan("mctpd with no endpoints",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			.nr = 0), 0);

	test_scan("object with no interfaces",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			.bare_object = true, THREE), 2);

	test_scan("only an object with no interfaces",
		  MCTPD(NAME_OPENBMC, PATH_OPENBMC, DBUS_TYPE_UINT32,
			DBUS_TYPE_BYTE, .bare_object = true, .nr = 0), 0);

	test_scan("endpoints with no properties",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			.no_props = true, THREE), 0);

	test_scan("no CXL endpoints",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			.nr = 1, .ep = { ep_pldm_10 }), 0);

	test_scan("same EID on two networks",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_BYTE,
			.nr = 2, .ep = { ep_cci_8, ep_cci_net2 }), 2);

	test_scan("EID of the wrong type",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_UINT32, DBUS_TYPE_UINT32,
			.nr = 1, .ep = { ep_cci_8 }), -1);

	test_scan("NetworkId of the wrong type",
		  MCTPD(NAME_CC, PATH_CC, DBUS_TYPE_BYTE, DBUS_TYPE_BYTE,
			.nr = 1, .ep = { ep_cci_8 }), -1);

	test_scan("no mctpd", MCTPD(NULL, NULL, 0, 0, .nr = 0), -1);

	test_rescan();

	dbus_connection_close(ctl);
	dbus_connection_unref(ctl);
	/* not SIGKILL, so that the bus removes its socket */
	kill(bus, SIGTERM);
	waitpid(bus, NULL, 0);

	printf("%s\n", failures ? "FAILED" : "all passed");
	return failures ? 1 : 0;
}
