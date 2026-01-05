// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * Minimal init for QEMU CXL unit testing
 *
 * Supports two modes:
 * - ioctl mode (default): Tests via /dev/cxl/memX devices
 * - MCTP mode (MCTP_TEST defined): Tests via MCTP over I2C
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <linux/reboot.h>

#define CXL_DEV_PATH "/dev/cxl"
#define TEST_GENERIC "/bin/cxl-test-generic"
#define TEST_MEMDEV "/bin/cxl-test-memdev"
#define TEST_FMAPI "/bin/cxl-test-fmapi"
#define MAX_WAIT_SECS 30
#define CMDLINE_PATH "/proc/cmdline"

static int verbose = 0;
static int sanitize = 0;

#ifdef MCTP_TEST
static int mctp_mode = 0;
static int mctp_net = 11;
static int mctp_local_eid = 50;
/*
 * MCTP endpoint configuration matching QEMU topology:
 *   EID 8:  CXL Switch (upstream port us0)
 *   EID 9:  Type3 SLD on switch port 0 (cxl-pmem1)
 *   EID 10: Type3 SLD on switch port 2 (cxl-pmem2)
 *   Note: Switch port 1 has virtio-rng (not a CXL device)
 */
static int switch_eid = 8;
static int type3_1_eid = 9;		/* on switch port 0 */
static int type3_2_eid = 10;		/* on switch port 2 */
static int switch_i2c_addr = 0x4;
static int type3_1_i2c_addr = 0x5;
static int type3_2_i2c_addr = 0x6;
#endif

static int mount_filesystems(void)
{
	if (mount("proc", "/proc", "proc", 0, NULL) < 0 ||
	    mount("sysfs", "/sys", "sysfs", 0, NULL) < 0 ||
	    mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) < 0 ||
	    mount("tmpfs", "/tmp", "tmpfs", 0, NULL) < 0) {
		perror("mount");
		return -1;
	}
	return 0;
}

#ifdef MCTP_TEST
static int parse_int_param(const char *buf, const char *param, int min, int max)
{
	const char *p = strstr(buf, param);
	char *endptr;
	long val;

	if (!p)
		return -1;

	p += strlen(param);
	errno = 0;
	val = strtol(p, &endptr, 10);

	/* Check for conversion errors or out-of-range values */
	if (errno != 0 || endptr == p || val < min || val > max)
		return -1;

	return (int)val;
}
#endif

/* SIGCHLD handler to reap zombie child processes */
static void sigchld_handler(int sig __attribute__((unused)))
{
	int saved_errno = errno;

	while (waitpid(-1, NULL, WNOHANG) > 0)
		;

	errno = saved_errno;
}

static void parse_cmdline(void)
{
	FILE *f;
	char buf[1024];
#ifdef MCTP_TEST
	int val;
#endif

	f = fopen(CMDLINE_PATH, "r");
	if (!f)
		return;

	if (fgets(buf, sizeof(buf), f)) {
		if (strstr(buf, "cxlmi_test.verbose=1"))
			verbose = 1;
		if (strstr(buf, "cxlmi_test.sanitize=1"))
			sanitize = 1;
#ifdef MCTP_TEST
		if (strstr(buf, "cxlmi_test.mctp=1"))
			mctp_mode = 1;
		/* MCTP network ID: 1-255 */
		if ((val = parse_int_param(buf, "cxlmi_test.mctp_net=", 1, 255)) > 0)
			mctp_net = val;
		/* MCTP EIDs: 1-254 (0=null, 255=broadcast) */
		if ((val = parse_int_param(buf, "cxlmi_test.switch_eid=", 1, 254)) > 0)
			switch_eid = val;
		if ((val = parse_int_param(buf, "cxlmi_test.type3_1_eid=", 1, 254)) > 0)
			type3_1_eid = val;
		if ((val = parse_int_param(buf, "cxlmi_test.type3_2_eid=", 1, 254)) > 0)
			type3_2_eid = val;
		/* I2C 7-bit addresses: 0x01-0x7F */
		if ((val = parse_int_param(buf, "cxlmi_test.switch_i2c_addr=", 0x01, 0x7F)) > 0)
			switch_i2c_addr = val;
		if ((val = parse_int_param(buf, "cxlmi_test.type3_1_i2c_addr=", 0x01, 0x7F)) > 0)
			type3_1_i2c_addr = val;
		if ((val = parse_int_param(buf, "cxlmi_test.type3_2_i2c_addr=", 0x01, 0x7F)) > 0)
			type3_2_i2c_addr = val;
#endif
	}
	fclose(f);
}

static int wait_for_cxl_devices(void)
{
	DIR *dir;
	struct dirent *entry;

	for (int i = 0; i < MAX_WAIT_SECS * 10; i++) {
		dir = opendir(CXL_DEV_PATH);
		if (dir) {
			while ((entry = readdir(dir)) != NULL) {
				if (strncmp(entry->d_name, "mem", 3) == 0) {
					closedir(dir);
					return 0;
				}
			}
			closedir(dir);
		}
		usleep(100000);
	}
	return -1;
}

static int run_test_impl(const char *binary, const char *name, const char *target,
			 int tunnel_port)
{
	pid_t pid;
	int status;
	char port_str[16];

	printf("--- %s: %s ---\n", name, target);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		if (sanitize)
			setenv("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1", 1);

		if (tunnel_port >= 0) {
			snprintf(port_str, sizeof(port_str), "%d", tunnel_port);
			if (verbose)
				execl(binary, binary, "-v", "-p", port_str, target, NULL);
			else
				execl(binary, binary, "-p", port_str, target, NULL);
		} else {
			if (verbose)
				execl(binary, binary, "-v", target, NULL);
			else
				execl(binary, binary, target, NULL);
		}
		_exit(127);
	}

	waitpid(pid, &status, 0);

	if (WIFEXITED(status)) {
		int code = WEXITSTATUS(status);
		const char *result;

		switch (code) {
		case 0:
			result = "PASS";
			break;
		case 1:
			result = "FAIL";
			break;
		case 2:
			result = "SKIP";
			break;
		case 127:
			printf("[FAIL] %s: %s (binary not found)\n\n", name, target);
			return 1; /* count as failure */
		default:
			result = "FAIL";
			code = 1;
			break;
		}
		printf("[%s] %s: %s\n\n", result, name, target);
		return code;
	}

	printf("[FAIL] %s: %s (crashed)\n\n", name, target);
	return 1; /* count as failure */
}

static void count_result(int rc, int *pass, int *fail, int *skip)
{
	switch (rc) {
	case 0:
		(*pass)++;
		break;
	case 2:
		(*skip)++;
		break;
	default:
		(*fail)++;
		break;
	}
}

#ifdef MCTP_TEST
static int run_cmd_quiet(const char *cmd)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0)
		return -1;

	if (pid == 0) {
		execl("/bin/sh", "sh", "-c", cmd, NULL);
		_exit(127);
	}

	waitpid(pid, &status, 0);
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static int run_cmd(const char *cmd)
{
	if (verbose)
		printf("Running: %s\n", cmd);

	return run_cmd_quiet(cmd);
}

static int wait_for_mctp_i2c(void)
{
	struct stat st;

	printf("Waiting for MCTP I2C device...\n");

	/* Wait for mctp-i2c-controller to create the mctp device */
	for (int i = 0; i < MAX_WAIT_SECS * 10; i++) {
		/* Check for any mctpi2c device in /sys/bus/mctp/devices/ */
		DIR *dir = opendir("/sys/bus/mctp/devices");
		if (dir) {
			struct dirent *entry;
			while ((entry = readdir(dir)) != NULL) {
				if (strncmp(entry->d_name, "mctpi2c", 7) == 0) {
					closedir(dir);
					printf("Found MCTP device: %s\n", entry->d_name);
					/* Give it a moment to fully initialize */
					usleep(500000);
					return 0;
				}
			}
			closedir(dir);
		}

		/* Also check /sys/class/net for mctp network interfaces */
		if (stat("/sys/class/net/mctpi2c0", &st) == 0) {
			printf("Found MCTP network interface: mctpi2c0\n");
			usleep(500000);
			return 0;
		}

		usleep(100000);
	}

	printf("Timeout waiting for MCTP I2C device\n");
	return -1;
}

static int assign_mctp_endpoint(int i2c_addr, int expected_eid)
{
	char cmd[512];
	int rc;

	/*
	 * Use busctl to call mctpd's AssignEndpoint method.
	 * This tells mctpd to assign an EID to the device at the given I2C address.
	 *
	 * In mctpd v2, AssignEndpoint is on the interface object:
	 *   Service: au.com.codeconstruct.MCTP1
	 *   Object: /au/com/codeconstruct/mctp1/interfaces/mctpi2c0
	 *   Interface: au.com.codeconstruct.MCTP.BusOwner1
	 *   Method: AssignEndpoint
	 *   Signature: ay (byte array for physical address)
	 *
	 * For I2C, the physical address is a single byte (7-bit I2C address).
	 */
	snprintf(cmd, sizeof(cmd),
		 "busctl call au.com.codeconstruct.MCTP1 "
		 "/au/com/codeconstruct/mctp1/interfaces/mctpi2c0 "
		 "au.com.codeconstruct.MCTP.BusOwner1 "
		 "AssignEndpoint ay 1 0x%x",
		 i2c_addr);

	rc = run_cmd(cmd);
	if (rc != 0) {
		printf("Warning: Failed to assign EID to I2C addr 0x%x\n", i2c_addr);
		return rc;
	}

	printf("Assigned EID to device at I2C addr 0x%x (expected EID %d)\n",
	       i2c_addr, expected_eid);
	return 0;
}

static int setup_mctp_network(void)
{
	char cmd[512];
	int rc;

	printf("Setting up MCTP network...\n");

	/* Bring up the MCTP I2C link */
	rc = run_cmd("mctp link set mctpi2c0 up 2>/dev/null || "
		     "ip link set mctpi2c0 up 2>/dev/null");
	if (rc != 0)
		printf("Warning: Failed to bring up mctpi2c0\n");

	/* Set local EID */
	snprintf(cmd, sizeof(cmd), "mctp addr add %d dev mctpi2c0", mctp_local_eid);
	rc = run_cmd(cmd);
	if (rc != 0)
		printf("Warning: Failed to set local EID\n");

	/* Set network ID */
	snprintf(cmd, sizeof(cmd), "mctp link set mctpi2c0 net %d", mctp_net);
	rc = run_cmd(cmd);
	if (rc != 0)
		printf("Warning: Failed to set MCTP network ID\n");

	/* Create run directories for dbus and mctpd */
	mkdir("/run", 0755);
	mkdir("/run/dbus", 0755);
	mkdir("/var", 0755);
	mkdir("/var/run", 0755);
	mkdir("/var/lib", 0755);
	mkdir("/var/lib/dbus", 0755);

	/* Create machine-id for dbus (required) */
	FILE *mid = fopen("/var/lib/dbus/machine-id", "w");
	if (mid) {
		fprintf(mid, "00000000000000000000000000000001\n");
		fclose(mid);
	}
	/* Also create /etc/machine-id as some dbus versions check there */
	mkdir("/etc", 0755);
	mid = fopen("/etc/machine-id", "w");
	if (mid) {
		fprintf(mid, "00000000000000000000000000000001\n");
		fclose(mid);
	}

	/* Show MCTP link configuration */
	if (verbose) {
		printf("\nMCTP Link Configuration:\n");
		run_cmd("mctp link 2>/dev/null || ip -d link show mctpi2c0 2>/dev/null");
		run_cmd("mctp addr 2>/dev/null");
	}

	/* Start dbus-daemon if available (required for mctpd) */
	if (access("/bin/dbus-daemon", X_OK) == 0) {
		printf("Starting dbus-daemon...\n");
		rc = run_cmd("dbus-daemon --system --fork --print-pid");
		if (rc != 0) {
			printf("Warning: Failed to start dbus-daemon (rc=%d)\n", rc);
			/* Try with more verbose output to see what's wrong */
			run_cmd("dbus-daemon --system --fork --print-address 2>&1 || true");
		}
		usleep(500000);
	}

	/* Try to start mctpd if available */
	if (access("/bin/mctpd", X_OK) == 0) {
		printf("Starting mctpd...\n");
		/* Run mctpd in background */
		pid_t pid = fork();
		if (pid < 0) {
			printf("Warning: Failed to fork for mctpd\n");
		} else if (pid == 0) {
			/* mctpd needs to run as a daemon */
			setsid();
			execl("/bin/mctpd", "mctpd", "-v", NULL);
			_exit(127);
		} else {
			/* Give mctpd time to start and register on D-Bus */
			sleep(3);

			if (verbose) {
				printf("Checking D-Bus services...\n");
				run_cmd("busctl list 2>&1 | head -20 || true");
			}

			/* Assign endpoints using busctl */
			printf("Assigning MCTP endpoints...\n");
			assign_mctp_endpoint(switch_i2c_addr, switch_eid);
			usleep(500000);
			assign_mctp_endpoint(type3_1_i2c_addr, type3_1_eid);
			usleep(500000);
			assign_mctp_endpoint(type3_2_i2c_addr, type3_2_eid);
		}
	} else {
		printf("Warning: mctpd not found, skipping endpoint assignment\n");
		printf("Tests will use static EID configuration\n");
	}

	/* Show final MCTP configuration */
	if (verbose) {
		printf("\nFinal MCTP Configuration:\n");
		run_cmd("mctp link 2>/dev/null");
		run_cmd("mctp addr 2>/dev/null");
		run_cmd("mctp route 2>/dev/null");
	}

	return 0;
}

static int run_mctp_test(const char *binary, const char *name, int net, int eid,
			 int tunnel_port)
{
	char target[64];

	snprintf(target, sizeof(target), "mctp:%d,%d", net, eid);
	return run_test_impl(binary, name, target, tunnel_port);
}

static void run_mctp_tests(int *pass, int *fail, int *skip)
{
	*pass = *fail = *skip = 0;

	printf("\n=== Testing Switch CCI (EID %d) ===\n\n", switch_eid);

	/* Run generic tests against switch */
	count_result(run_mctp_test(TEST_GENERIC, "generic", mctp_net, switch_eid, -1),
		     pass, fail, skip);

	/*
	 * Run FM-API tests against switch directly (no tunneling).
	 * FM-API commands (identify_sw_device, get_phys_port_state, etc.)
	 * are sent directly to the switch CCI. The test has an auto-detection
	 * section at the end that will discover downstream ports for tunneling.
	 */
	count_result(run_mctp_test(TEST_FMAPI, "fmapi", mctp_net, switch_eid, -1),
		     pass, fail, skip);

	/*
	 * Test tunneling generic/memdev commands through switch.
	 * These tests send commands to the switch (EID 8) which tunnels them
	 * to the Type3 device on the specified downstream port.
	 *
	 * Port 0 -> cxl-pmem1 (same device as EID 9)
	 * Port 2 -> cxl-pmem2 (same device as EID 10)
	 * Port 1 has virtio-rng (not a CXL device, skip)
	 */
	printf("\n=== Testing Tunneled Commands via Switch Port 0 (-> cxl-pmem1) ===\n\n");

	count_result(run_mctp_test(TEST_GENERIC, "generic-tunnel-p0", mctp_net, switch_eid, 0),
		     pass, fail, skip);
	count_result(run_mctp_test(TEST_MEMDEV, "memdev-tunnel-p0", mctp_net, switch_eid, 0),
		     pass, fail, skip);

	printf("\n=== Testing Tunneled Commands via Switch Port 2 (-> cxl-pmem2) ===\n\n");

	count_result(run_mctp_test(TEST_GENERIC, "generic-tunnel-p2", mctp_net, switch_eid, 2),
		     pass, fail, skip);
	count_result(run_mctp_test(TEST_MEMDEV, "memdev-tunnel-p2", mctp_net, switch_eid, 2),
		     pass, fail, skip);

	/*
	 * Test direct access to Type3 devices via their own MCTP endpoints.
	 * No tunneling - commands go directly to the device's MCTP CCI.
	 * These access the same physical devices as the tunneled tests above,
	 * but via their dedicated MCTP endpoints instead of through the switch.
	 */
	printf("\n=== Testing Type3 Device 1 Direct (EID %d, cxl-pmem1) ===\n\n", type3_1_eid);

	count_result(run_mctp_test(TEST_GENERIC, "generic", mctp_net, type3_1_eid, -1),
		     pass, fail, skip);
	count_result(run_mctp_test(TEST_MEMDEV, "memdev", mctp_net, type3_1_eid, -1),
		     pass, fail, skip);

	printf("\n=== Testing Type3 Device 2 Direct (EID %d, cxl-pmem2) ===\n\n", type3_2_eid);

	count_result(run_mctp_test(TEST_GENERIC, "generic", mctp_net, type3_2_eid, -1),
		     pass, fail, skip);
	count_result(run_mctp_test(TEST_MEMDEV, "memdev", mctp_net, type3_2_eid, -1),
		     pass, fail, skip);
}
#endif /* MCTP_TEST */

static int run_test(const char *binary, const char *name, const char *device)
{
	return run_test_impl(binary, name, device, -1);
}

static void run_all_tests(int *pass, int *fail, int *skip)
{
	DIR *dir;
	struct dirent *entry;

	*pass = *fail = *skip = 0;

	dir = opendir(CXL_DEV_PATH);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (strncmp(entry->d_name, "mem", 3) == 0) {
			/* Run generic command tests */
			count_result(run_test(TEST_GENERIC, "generic", entry->d_name),
				     pass, fail, skip);

			/* Run memdev command tests */
			count_result(run_test(TEST_MEMDEV, "memdev", entry->d_name),
				     pass, fail, skip);

			/* Run FM-API command tests */
			count_result(run_test(TEST_FMAPI, "fmapi", entry->d_name),
				     pass, fail, skip);
		}
	}
	closedir(dir);
}

int main(void)
{
	struct sigaction sa;
	sigset_t mask;
	int pass = 0, fail = 0, skip = 0;

	printf("\n========================================\n");
#ifdef MCTP_TEST
	printf("  libcxlmi QEMU CXL Unit Tests (MCTP)\n");
#else
	printf("  libcxlmi QEMU CXL Unit Tests\n");
#endif
	printf("========================================\n\n");

	if (mount_filesystems() < 0) {
		printf("TEST_RESULT=FAIL\n");
		goto out;
	}

	/* Install SIGCHLD handler to reap zombie processes (we are init/PID 1) */
	sa.sa_handler = sigchld_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, NULL);

	/*
	 * Block SIGCHLD to prevent the handler from racing with waitpid().
	 * We use explicit waitpid() for all test children, so we don't need
	 * the handler running concurrently. The handler will still reap any
	 * zombies when we exit (the signal will be delivered on unblock).
	 */
	sigemptyset(&mask);
	sigaddset(&mask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	parse_cmdline();
	if (verbose)
		printf("Verbose mode enabled\n");
	if (sanitize)
		printf("AddressSanitizer enabled\n");
#ifdef MCTP_TEST
	if (mctp_mode)
		printf("MCTP transport mode enabled\n");
#endif
	if (verbose || sanitize)
		printf("\n");

#ifdef MCTP_TEST
	if (mctp_mode) {
		/* MCTP mode: wait for MCTP I2C device and setup network */
		if (wait_for_mctp_i2c() < 0) {
			printf("[FAIL] No MCTP I2C device found\n");
			printf("TEST_RESULT=FAIL\n");
			goto out;
		}

		if (setup_mctp_network() < 0) {
			printf("[FAIL] Failed to setup MCTP network\n");
			printf("TEST_RESULT=FAIL\n");
			goto out;
		}

		run_mctp_tests(&pass, &fail, &skip);
	} else
#endif
	{
		/* Standard ioctl mode */
		if (wait_for_cxl_devices() < 0) {
			printf("[FAIL] No CXL devices found\n");
			printf("TEST_RESULT=FAIL\n");
			goto out;
		}

		run_all_tests(&pass, &fail, &skip);
	}

	printf("========================================\n");
	printf("  Results: %d passed, %d failed, %d skipped\n", pass, fail, skip);
	printf("========================================\n\n");
	printf("TEST_RESULT=%s\n", fail == 0 ? "PASS" : "FAIL");

out:
	/* Unblock SIGCHLD to let the handler reap any remaining zombies */
	sigprocmask(SIG_UNBLOCK, &mask, NULL);

	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	return 0;
}
