/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Common test infrastructure for libcxlmi unit tests
 *
 * This header provides shared macros, helper functions, and utilities
 * used across all CXL command set test programs.
 */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <libcxlmi.h>

/*
 * Test counters and options - declare in each test file with TEST_DECLARE_COUNTERS
 */
#define TEST_DECLARE_COUNTERS \
	static int tests_run = 0; \
	static int tests_passed = 0; \
	static int tests_failed = 0; \
	static int tests_skipped = 0; \
	static bool verbose = false

/*
 * Tunneling configuration - declare in each test file with TEST_DECLARE_TUNNEL_CONFIG
 *
 * Tunneling modes:
 *   No options:           Direct command (no tunneling)
 *   -p <port>:            Level 1 tunnel through switch to FM-owned LD (DEFINE_CXLMI_TUNNEL_SWITCH)
 *   -l <ld>:              Level 1 tunnel to LD in MLD (DEFINE_CXLMI_TUNNEL_MLD)
 *   -p <port> -l <ld>:    Level 2 tunnel through switch to LD in MLD (DEFINE_CXLMI_TUNNEL_SWITCH_MLD)
 *   -m:                   Tunnel to MHD LD Pool CCI (DEFINE_CXLMI_TUNNEL_MHD)
 */
#define TEST_DECLARE_TUNNEL_CONFIG \
	static int tunnel_port = -1; \
	static int tunnel_ld = -1; \
	static bool tunnel_mhd = false; \
	\
	static struct cxlmi_tunnel_info *get_tunnel_info(void) \
	{ \
		static struct cxlmi_tunnel_info ti; \
		\
		/* No tunneling options = direct command */ \
		if (tunnel_port < 0 && tunnel_ld < 0 && !tunnel_mhd) \
			return NULL; \
		\
		/* MHD tunneling (DEFINE_CXLMI_TUNNEL_MHD) */ \
		if (tunnel_mhd) { \
			ti.level = 1; \
			ti.port = 0; \
			ti.ld = -1; \
			ti.mhd = true; \
			return &ti; \
		} \
		\
		/* Level 2: switch + LD in MLD (DEFINE_CXLMI_TUNNEL_SWITCH_MLD) */ \
		if (tunnel_port >= 0 && tunnel_ld >= 0) { \
			ti.level = 2; \
			ti.port = tunnel_port; \
			ti.ld = tunnel_ld; \
			ti.mhd = false; \
			return &ti; \
		} \
		\
		/* Level 1: switch to FM-owned LD (DEFINE_CXLMI_TUNNEL_SWITCH) */ \
		if (tunnel_port >= 0) { \
			ti.level = 1; \
			ti.port = tunnel_port; \
			ti.ld = -1; \
			ti.mhd = false; \
			return &ti; \
		} \
		\
		/* Level 1: LD in MLD (DEFINE_CXLMI_TUNNEL_MLD) */ \
		if (tunnel_ld >= 0) { \
			ti.level = 1; \
			ti.port = 0; \
			ti.ld = tunnel_ld; \
			ti.mhd = false; \
			return &ti; \
		} \
		\
		return NULL; \
	} \
	\
	static void print_tunnel_config(void) \
	{ \
		if (tunnel_mhd) { \
			printf("Tunneling: MHD LD Pool CCI\n"); \
		} else if (tunnel_port >= 0 && tunnel_ld >= 0) { \
			printf("Tunneling: switch port %d -> LD %d (level 2)\n", \
			       tunnel_port, tunnel_ld); \
		} else if (tunnel_port >= 0) { \
			printf("Tunneling: switch port %d -> FM-owned LD (level 1)\n", \
			       tunnel_port); \
		} else if (tunnel_ld >= 0) { \
			printf("Tunneling: LD %d in MLD (level 1)\n", tunnel_ld); \
		} \
	} \
	\
	static int parse_tunnel_arg(int argc, char **argv, int argidx) \
	{ \
		if ((strcmp(argv[argidx], "-p") == 0 || \
		     strcmp(argv[argidx], "--port") == 0) && argidx + 1 < argc) { \
			tunnel_port = atoi(argv[argidx + 1]); \
			return 2; \
		} \
		if ((strcmp(argv[argidx], "-l") == 0 || \
		     strcmp(argv[argidx], "--ld") == 0) && argidx + 1 < argc) { \
			tunnel_ld = atoi(argv[argidx + 1]); \
			return 2; \
		} \
		if (strcmp(argv[argidx], "-m") == 0 || \
		    strcmp(argv[argidx], "--mhd") == 0) { \
			tunnel_mhd = true; \
			return 1; \
		} \
		return 0; \
	}

/*
 * Print usage for common tunneling options
 */
static inline void print_tunnel_usage(void)
{
	fprintf(stderr, "\nTunneling options:\n");
	fprintf(stderr, "  -p, --port <num>      Tunnel through switch to FM-owned LD (level 1)\n");
	fprintf(stderr, "  -l, --ld <num>        Tunnel to LD in MLD (level 1)\n");
	fprintf(stderr, "  -p <port> -l <ld>     Tunnel through switch to LD in MLD (level 2)\n");
	fprintf(stderr, "  -m, --mhd             Tunnel to MHD LD Pool CCI\n");
}

/*
 * Test result macros
 */
#define TEST_PASS(name) do { \
	printf("  [PASS] %s\n", name); \
	tests_passed++; \
	tests_run++; \
} while (0)

#define TEST_FAIL(name, reason) do { \
	printf("  [FAIL] %s: %s\n", name, reason); \
	tests_failed++; \
	tests_run++; \
} while (0)

#define TEST_SKIP(name, reason) do { \
	printf("  [SKIP] %s: %s\n", name, reason); \
	tests_skipped++; \
} while (0)

/*
 * Well-known log UUIDs (CXL r3.1 Section 8.2.9.4)
 */
static const uint8_t CEL_UUID[16] = {
	0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41, 0x4b, 0x78,
	0x8f, 0x79, 0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17
};

static const uint8_t VENDOR_DEBUG_UUID[16] = {
	0xe1, 0x81, 0x9d, 0x9a, 0x48, 0x2e, 0x4e, 0x2a,
	0xab, 0x45, 0x13, 0x75, 0x7d, 0xa8, 0x48, 0xe5
};

/*
 * Check if return code indicates command not supported
 */
static inline bool is_unsupported(int rc)
{
	if (rc == CXLMI_RET_UNSUPPORTED ||
	    rc == CXLMI_RET_MBUNSUPPORTED ||
	    rc < 0)  /* negative errno means kernel doesn't support this command */
		return true;
	return false;
}

/*
 * Convert return code to string for error messages
 */
static inline const char *rc_str(int rc)
{
	if (rc < 0)
		return "ioctl error";
	return cxlmi_cmd_retcode_tostr(rc);
}

/*
 * Wait for any ongoing background operation to complete
 *
 * Returns true if no background operation is running or wait succeeded,
 * false if timeout was reached while operation still in progress.
 */
static inline bool wait_for_bg_done(struct cxlmi_endpoint *ep, int timeout_ms)
{
	struct cxlmi_cmd_bg_op_status_rsp rsp = {0};
	int elapsed = 0;
	int rc;

	while (elapsed < timeout_ms) {
		rc = cxlmi_cmd_bg_op_status(ep, NULL, &rsp);
		if (rc)
			return true; /* Can't check, assume done */
		if (rsp.status == 0)
			return true; /* No background operation */
		usleep(100000); /* 100ms */
		elapsed += 100;
	}
	return false; /* Timeout */
}

/*
 * Check if return code indicates success for a background operation command
 *
 * Background operations may return:
 *   0                    - Completed synchronously
 *   CXLMI_RET_BACKGROUND - Started as background operation (success)
 */
static inline bool is_bg_success(int rc)
{
	return (rc == 0 || rc == CXLMI_RET_BACKGROUND);
}

/*
 * Print usage information for transport target specification
 */
static inline void print_target_usage(void)
{
	fprintf(stderr, "\nTarget (one of):\n");
	fprintf(stderr, "  <device>              CXL memory device name for ioctl (e.g., mem0)\n");
	fprintf(stderr, "  mctp:<net>,<eid>      MCTP endpoint (e.g., mctp:1,0x1a)\n");
}

/*
 * Open an endpoint supporting both ioctl and MCTP transports
 *
 * Target format:
 *   <device>         - ioctl transport (e.g., "mem0")
 *   mctp:<net>,<eid> - MCTP transport (e.g., "mctp:1,0x1a")
 */
static inline struct cxlmi_endpoint *open_endpoint(struct cxlmi_ctx *ctx,
						   const char *target)
{
	unsigned int net;
	unsigned int eid;

	/* Check for MCTP transport: mctp:<net>,<eid> */
	if (strncmp(target, "mctp:", 5) == 0) {
		if (sscanf(target + 5, "%u,%i", &net, &eid) != 2) {
			fprintf(stderr, "Invalid MCTP target format: %s\n", target);
			fprintf(stderr, "Expected: mctp:<net>,<eid>\n");
			return NULL;
		}
		return cxlmi_open_mctp(ctx, net, (uint8_t)eid);
	}

	/* Default to ioctl transport */
	return cxlmi_open(ctx, target);
}

/*
 * Print test results summary
 */
#define TEST_PRINT_RESULTS() do { \
	printf("\n========================================\n"); \
	printf("  Results: %d passed, %d failed, %d skipped\n", \
	       tests_passed, tests_failed, tests_skipped); \
	printf("========================================\n"); \
} while (0)

/*
 * Get test exit code:
 *   0 = success (at least one pass, no failures)
 *   1 = failure (at least one failure)
 *   2 = skipped (no passes, no failures - all tests skipped)
 */
#define TEST_EXIT_CODE() \
	(tests_failed > 0 ? 1 : (tests_passed > 0 ? 0 : 2))

/*
 * Common main() structure helper - starts test program
 *
 * Use this macro at the start of main() to handle common argument
 * parsing and initialization. Sets up ctx and ep variables.
 */
#define TEST_MAIN_START(test_name, usage_func) \
	struct cxlmi_ctx *ctx; \
	struct cxlmi_endpoint *ep; \
	const char *target = NULL; \
	int rc = 1; \
	int argidx; \
	\
	for (argidx = 1; argidx < argc; argidx++) { \
		if (strcmp(argv[argidx], "-h") == 0 || \
		    strcmp(argv[argidx], "--help") == 0) { \
			usage_func(argv[0]); \
			return 0; \
		} \
		if (strcmp(argv[argidx], "-v") == 0 || \
		    strcmp(argv[argidx], "--verbose") == 0) { \
			verbose = true; \
			continue; \
		} \
		if (argv[argidx][0] == '-') { \
			fprintf(stderr, "Unknown option: %s\n", argv[argidx]); \
			usage_func(argv[0]); \
			return 1; \
		} \
		target = argv[argidx]; \
	} \
	\
	if (!target) { \
		usage_func(argv[0]); \
		return 1; \
	} \
	\
	printf("========================================\n"); \
	printf("  libcxlmi %s Tests\n", test_name); \
	printf("========================================\n"); \
	printf("Target: %s\n", target); \
	\
	ctx = cxlmi_new_ctx(stdout, LOG_WARNING); \
	if (!ctx) { \
		fprintf(stderr, "Failed to create context\n"); \
		return 1; \
	} \
	\
	ep = open_endpoint(ctx, target); \
	if (!ep) { \
		fprintf(stderr, "Failed to open endpoint: %s\n", target); \
		cxlmi_free_ctx(ctx); \
		return 1; \
	}

/*
 * Common main() structure helper - ends test program
 *
 * Use this macro at the end of main() after run_tests(ep).
 */
#define TEST_MAIN_END() \
	TEST_PRINT_RESULTS(); \
	rc = TEST_EXIT_CODE(); \
	cxlmi_close(ep); \
	cxlmi_free_ctx(ctx); \
	return rc

#endif /* TEST_COMMON_H */
