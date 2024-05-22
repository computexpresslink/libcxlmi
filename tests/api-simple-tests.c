// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Do some simple API verifications.
 */
#include <stdio.h>
#include <stdlib.h>

#include <libcxlmi.h>

static int verify_num_endpoints(struct cxlmi_ctx *ctx, int expected)
{
	int num_ep = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep)
		num_ep++;

	if (num_ep != expected) {
		fprintf(stderr, "[FAIL] have %d endpoints, expected %d\n",
			num_ep, expected);
		return 1;
	}

	return 0;
}

static int query_mld_from_switch(struct cxlmi_endpoint *ep, int num_ports)
{
	int i, rc, nerr = 0;
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *in;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret;
	size_t ret_sz = sizeof(*ret) + num_ports * sizeof(*ret->ports);

	/* arm input for phys_port_state */
	in = calloc(1, num_ports + sizeof(*in));
	if (!in)
		goto done;
	in->num_ports = num_ports;
	for (i = 0; i < num_ports; i++)
		in->ports[i] = i;

	/* prepare output buffer for phy_port_state */
	ret = calloc(1, ret_sz);
	if (!ret)
		goto free_input;

	rc = cxlmi_cmd_fmapi_get_phys_port_state(ep, NULL, in, ret);
	if (rc)
		goto free_ret;

	/* query ports */
	for (i = 0; i < ret->num_ports; i++) {
		struct cxlmi_cmd_identify id;
		struct cxlmi_cmd_fmapi_port_state_info_block *port;
		struct cxlmi_tunnel_info ti = {
			.level = 2,
			.port = i,
			.ld = 0, /* MLD port, query LD-0 */
		};

		port = &ret->ports[i];
		if (port->conn_dev_type != 5)
			continue;

		rc = cxlmi_cmd_identify(ep, &ti, &id);
		if (rc > 0) {
			fprintf(stderr,
				"[FAIL] unexpected return code (0x%x)\n", rc);
			nerr++;
		}
	}

free_ret:
	free(ret);
free_input:
	free(in);
done:
	return nerr;
}

/* basic sanity tests for toggling fmapi */
static int verify_ep_fmapi(struct cxlmi_endpoint *ep)
{
	int nerr = 0;

	if (cxlmi_endpoint_has_fmapi(ep) && cxlmi_endpoint_disable_fmapi(ep)) {
		int rc;
		struct cxlmi_cmd_identify id;
		struct cxlmi_tunnel_info  ti = {
			.level = 1,
			.port = 0,
			.ld = 0,
		};

		rc = cxlmi_cmd_identify(ep, &ti, &id);

		if (rc != -1) { /* fails at a lib level, no socket */
			fprintf(stderr,
				"[FAIL] unexpected return code (0x%x)\n", rc);
			nerr++;
		}
		if (cxlmi_endpoint_has_fmapi(ep)) {
			fprintf(stderr, "[FAIL] FM-API is enabled\n");
			nerr++;
		}

		if (cxlmi_endpoint_enable_fmapi(ep)) {
			/*
			 * Test may trigger false positives simple because of
			 * spurious qemu/mctp failures (ie: unexpected fixed
			 * length of response), so don't check for -1 here.
			 */
			rc = cxlmi_cmd_identify(ep, &ti, &id);
			if (rc > 0) {
				fprintf(stderr,
					"[FAIL] unexpected return code (0x%x)\n", rc);
				nerr++;
			}

			/*
			 * Attempt a 2-level tunneled ID cmd if this is a
			 * switch + mld port (LD 0) scenario.
			 */
			if (id.component_type == 0x0) {
				struct cxlmi_cmd_fmapi_identify_sw_device idsw;

				rc = cxlmi_cmd_fmapi_identify_sw_device(ep,
								NULL, &idsw);
				if (rc)
					goto done;

				nerr += query_mld_from_switch(ep,
						      idsw.num_physical_ports);
			}
		} else {
			fprintf(stderr, "[FAIL] could not re-emable FM-API\n");
			nerr++;
		}
	}
done:
	return nerr;
}

/* ensure no duplicate mctp endpoints are opened */
static int test_ep_duplicates_mctp(unsigned int nid, int8_t eid)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int rc = 0, nerr = 0;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx)
		fprintf(stderr, "cannot create new context object\n");

	ep1 = cxlmi_open_mctp(ctx, nid, eid);
	if (!ep1) {
		fprintf(stderr, "cannot open endpoint\n");
	}

	ep2 = cxlmi_open_mctp(ctx, nid, eid);
	if (ep2) {
		fprintf(stderr,
			"[FAIL] no duplicate endpoints should be allowed\n");
		cxlmi_close(ep2);
		nerr++;
	}

	rc = verify_ep_fmapi(ep1);
	if (rc)
		goto free_ctx;

	cxlmi_close(ep1);
	nerr += verify_num_endpoints(ctx, 0);
free_ctx:
	cxlmi_free_ctx(ctx);
	return nerr;
}

/* ensure no duplicate ioctl endpoints are opened */
static int test_ep_duplicates_ioctl(char *devname)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int nerr = 0;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		return -1;
	}

	ep1 = cxlmi_open(ctx, devname);
	if (!ep1) {
		fprintf(stderr, "cannot open '%s' endpoint\n", devname);
		goto free_ctx;
	}

	ep2 = cxlmi_open(ctx, devname);
	if (ep2) {
		fprintf(stderr,
			"[FAIL] no duplicate endpoints should be allowed\n");
		cxlmi_close(ep2);
		nerr++;
	}

	cxlmi_close(ep1);
free_ctx:
	nerr += verify_num_endpoints(ctx, 0);
	cxlmi_free_ctx(ctx);
	return nerr;
}

/* ensure mctp and ioctl endpoints can co-exist */
static int test_mixed_ep(unsigned int nid, int8_t eid, char *devname)
{

	struct cxlmi_endpoint *ep1, *ep2;
	struct cxlmi_ctx *ctx;
	int nerr = 0;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		return -1;
	}

	ep1 = cxlmi_open_mctp(ctx, nid, eid);
	if (!ep1) {
		fprintf(stderr, "cannot open '%d:%d' endpoint\n", nid, eid);
		goto free_ctx;
	}

	ep2 = cxlmi_open(ctx, devname);
	if (!ep2) {
		fprintf(stderr,
			"[FAIL] mixed endpoints should be allowed\n");
		nerr++;
		goto free_ctx;
	}

	nerr += verify_num_endpoints(ctx, 2);
	cxlmi_close(ep2);
	cxlmi_close(ep1);
	nerr += verify_num_endpoints(ctx, 0);
free_ctx:
	cxlmi_free_ctx(ctx);
	return nerr;
}

/*
 * Ways to run these tests are determined by the passed arguments:
 *
 * api-simple-tests 13 5        <--- mctp tests
 * api-simple-tests switch0     <--- ioctl tests
 * api-simple-tests 23 8 mem2   <--- mctp + ioctl tests
 */
int main(int argc, char **argv)
{
	int errs = 0;
	unsigned int nid;
	uint8_t eid;

	if (argc == 1 || argc > 4) {
		fprintf(stderr,
		"Must provide mctp-endpoint and/or a Linux device (ie: mem0)\n");
		fprintf(stderr, "Usage: api-simple-tests <nid> <eid>\n");
		fprintf(stderr, "Usage: api-simple-tests <device>\n");
		fprintf(stderr, "Usage: api-simple-tests <nid> <eid> <device>\n");
		return EXIT_FAILURE;
	}

	if (argc == 2) { /* ioctl */
		errs += test_ep_duplicates_ioctl(argv[1]);
	} else if (argc == 3) { /* mctp */
		nid = atoi(argv[1]);
		eid = atoi(argv[2]);

		errs += test_ep_duplicates_mctp(nid, eid);
	} else if (argc == 4) { /* both */
		nid = atoi(argv[1]);
		eid = atoi(argv[2]);

		errs += test_ep_duplicates_mctp(nid, eid);
		errs += test_ep_duplicates_ioctl(argv[3]);

		errs += test_mixed_ep(nid, eid, argv[3]);
	}

	if (errs) {
		printf("%d errors found\n", errs);
		return -1;
	} else {
		printf("No errors found\n");
		return 0;
	}
}
