# libcxlmi-testing
This page describes how libcxlmi is tested with QEMU.

## Table of Contents
- [Overview](#overview)
- [Usage](#usage)
- [Goals](#goals)
- [How To Add a Test Case](#how-to-add-a-test-case)

## Overview
This section gives an overview of how the CI is run:

1. When a pull request is made, it will trigger a GitHub Runner to start and run
the workflow defined in `.github/workflows/run-tests.yml`.
2. A container is started using a Docker image with QEMU, Linux, and cxl-test-tool configured
3. In the container, `run_tests.py` generates test code for different CXL
topologies, starts VMs for the different tests, and executes tests on the VMs.

All test cases are defined in XML under `tests/qemu-tests/inputs`.
Tests are organized into files, which correspond to the suite they belong to,
which is determined by the topology they are run on. Currently there are 2 suites,
MAILBOX and MCTP.
Suites are defined in `tests/qemu-tests/suites.py`

### Environment Info
All tests are run on container created from this image: [anisasu/dcd-v6-image](https://hub.docker.com/repository/docker/anisasu/dcd-v6-image/general)
The QEMU and Linux versions compiled on the image are:
    > QEMU Branch: https://github.com/anisa-su993/qemu-anisa/tree/upstream-07-23-2025-usb-mctp
        > Upstream as of 07-23-2025 with Jonathan Cameron's [USB MCTP patches](https://lore.kernel.org/linux-cxl/20250609163334.922346-1-Jonathan.Cameron@huawei.com/T/#m21b9e0dfc689cb1890bb4d961710c23379e04902) applied
    > Linux version (Ira's dcd-v6): https://github.com/anisa-su993/anisa-linux-kernel/tree/dcd-v6-2025-04-13
        > The bzImage, kernel modules, and .config can all be found here for reference: https://github.com/anisa-su993/anisa-linux-kernel/releases/tag/usb-mctp-dcd

[cxl-test-tool](https://github.com/moking/cxl-test-tool) is used to facilitate
starting VMs with different CXL topologies. This [branch](https://github.com/moking/cxl-test-tool/compare/main...anisa-su993:anisa-cxl-test-tool:libcxlmi-testing)
containing some tweaks needed for the CI is used.

### Notes:
- The test code generation relies on the top-level `docs/` directory to get the
request/response struct names and method signatures for each command.
If the docs don't match the actual library struct type/method signatures, the
test files generated will not compile.

## Usage:
There are multiple ways to run locally:

### Simulate GH Runner Locally
To simulate the full Github Runner (recommended) using the workflow `.github/workflows/run-tests.yml`,
you will need to install [act](https://github.com/nektos/act/releases) and Docker, a tool which simulates
a Github Runner using Docker. This will most closely emulate the GitHub Runner's environment.

`run-tests.yml` runs in a container using an image with the kernel, kernel modules, QEMU binary, and
QEMU image, and [cxl-test-tool](https://github.com/moking/cxl-test-tool) already set up, which avoids configuration/environment issues.

Run `act` with the following command:
`act --privileged -W <path to run-tests.yml from working dir> pull_request`

`run-tests.yml` will run all tests. To run a single test or suite in the same environment, modify the "Run Tests" step defined in the workflow, which calls
the `run_test.py` script:

`python3 run_tests.py [OPTIONS]`

Default (no args): runs all tests in all suites
`-t --test [opcode]`: runs test for that opcode
`-s --suite [suite]`: runs tests in that suite (defined in `tests/qemu-tests/suites.py`)

### Generate Test Files Only
`tests/qemu-tests/generate_tests.py` is self-contained and can generate test files for each opcode. To use:

`python3 generate_tests.py [optional: suite]`

Default (no args): generate test-XXXX.c files for each opcode defined in the XML files in `tests/qemu-tests/inputs`
`[suite]`: generate tests for commands for that suite (defined in `SUITES` in `topo.py`)

It is up to the user to start a QEMU VM with the correct topology to execute the test file.

## Goal
The goal of end-to-end tests with QEMU is to ensure that the library is able to properly interact with the device, which includes all the layers between calling the cxlmi_cmd_X() function to interpreting and returning the end result from the device. As an example of what gets called from a cxlmi_cmd_X() call:

`cxlmi_cmd_identify() → send_cmd_cci() → send_mctp_direct() → sanity_check_mctp_rsp()`

This example shows the call stack for a direct MCTP message, but it will be different for an ioctl endpoint and/or with tunneling.

The best way to test this sequence of interactions will be with QEMU.

## How to Add a Test Case:
Add the input/output payload you want to test in the XML file for the suite it belongs to. Some commands don't have any input/output, some have one or the other, or both:

```
# This command has both an input and output
int cxlmi_cmd_fmapi_dc_list_tags(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_dc_list_tags_req *in,
			struct cxlmi_cmd_fmapi_dc_list_tags_rsp *ret);

# This command only has an output and no input
int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
		       struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_fmapi_identify_sw_device *ret);

# This command only has an input and no output
int cxlmi_cmd_memdev_release_dc(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_release_dc *in);

# This command has no input or output
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti);
```

Commands must be defined correctly in the input file or behavior is undefined
(most likely the test code will not compile).
Ex: defining an input when none is expected, including an incorrect field in
the req/rsp

Below is an example of the definition of a command with both input and output:
```
<command opcode="0004">
    <request>
        <limit>10</limit>
    </request>
    <response>
        <limit>10</limit>
    </response>
</command>
```
This corresponds to the following libcxlmi command with the corresponding request/response struct(s):
```
int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_set_response_msg_limit *in,
			     struct cxlmi_cmd_set_response_msg_limit *ret);

/* CXL r3.1 Section 8.2.9.1.4: Set Response Message Limit (Opcode 0004h) */
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));
```
The above XML will generate the following code:

```
struct cxlmi_cmd_set_response_msg_limit *actual = (struct cxlmi_cmd_set_response_msg_limit *) buf;

rc = cxlmi_cmd_set_response_msg_limit(ep, NULL, &request, actual);
if (rc != 0) {
    fprintf(stderr, "Error: Function cxlmi_cmd_set_response_msg_limit returned  non-zero rc: %d\n", rc);
    goto cleanup;
}
ASSERT_EQUAL(expected, actual, limit);
```
Note that the output defined in the XML file is the *expected output*. Defining the expected output is *optional*. If none is defined, the generated code will only check the rc. For example:

```
<command opcode="0004">
    <request>
        <limit>10</limit>
    </request>
    <response>
        <!-- empty -->
    </response>
</command>
```
Notice that the `<response>` node is still required. The `<response>` node *must*
bt included for every command that expects a response. Filling out the fields is
optional and the response node can be empty.
This will generate the following test code, skipping the assertions:
```
struct cxlmi_cmd_set_response_msg_limit *actual = (struct cxlmi_cmd_set_response_msg_limit *) buf;

rc = cxlmi_cmd_set_response_msg_limit(ep, NULL, &request, actual);
if (rc != 0) {
    fprintf(stderr, "Error: Function cxlmi_cmd_set_response_msg_limit returned  non-zero rc: %d\n", rc);
    goto cleanup;
}
```