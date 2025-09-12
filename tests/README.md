# Tests

## Table of Contents
- [Usage](#usage)
- [How To Add a Test Case](#how-to-add-a-test-case)

## Usage:
`python run_tests.py [OPTIONS]`

Number of Tests to Run:
- `-t --test [opcode]`: runs test for that opcode
- `-s --suite [suite]`: runs tests in that suite (defined in `tests/qemu-tests/suites.py`)
- default all

Other Flags:
- `-e/--endpoint`: endpoint type (ioctl devname | mctp nid eid)
- `-c/--check-rsp`: check expected rsp payloads?
- `-r/--rc`: expected rc (default 0)
- `-d/-mctpd`: mctpd compile flag [openbmc (default) | codeconstruct]

`run_tests.py` will generate the specified test/suite compile it with the
specified compilation flag and run them.
An `output/` directory will be created and each test specified will be written
to that directory, named `test-[opcode].c`

Each test will send a single command through the specified MCTP/ioctl endpoint
and check the rc. The command's request payload is generated from an XML file under
the `input/` directory. Each file corresponds to a suite. If the `--check-rsp`
flag is set to true and tje expected response payload is also defined in the XML file, then
`ASSERT_EQUALS` statements will also be generated to verify the response payload
against the expected payload.

### Example

`python tests/generate_tests.py --test 5601 --endpoint mctp 10 8 --rc 3 --mctpd codeconstruct --verify-rsp`

`--test 5601`: generates a single file `test-5601.c` which sends the
`cxlmi_cmd_fmapi_get_host_dc_region_config()` command

`--endpoint mctp 10 8`:

```
ep = cxlmi_open_mctp(ctx, 10, 8);
```

`--rc 3`:
```
rc = cxlmi_cmd_fmapi_get_dc_reg_config(ep, NULL, request_1, actual_1);
if (rc != 3) {
    fprintf(stdout, "Error: Function cxlmi_cmd_fmapi_get_dc_reg_config (5601h) returned rc of %d but expected 3\n", rc);
    goto cleanup;
}
rc = EXIT_SUCCESS;
```

`--verify-rsp`:
```
ASSERT_EQUAL(expected_1->host_id, actual_1->host_id);
ASSERT_EQUAL(expected_1->num_regions, actual_1->num_regions);
ASSERT_EQUAL(expected_1->regions_returned, actual_1->regions_returned);
ASSERT_EQUAL(expected_1->region_configs[0].base, actual_1->region_configs[0].base);
ASSERT_EQUAL(expected_1->region_configs[0].decode_len, actual_1->region_configs[0].decode_len);
ASSERT_EQUAL(expected_1->region_configs[0].region_len, actual_1->region_configs[0].region_len);
ASSERT_EQUAL(expected_1->region_configs[0].block_size, actual_1->region_configs[0].block_size);
ASSERT_EQUAL(expected_1->region_configs[0].flags, actual_1->region_configs[0].flags);
ASSERT_EQUAL(expected_1->region_configs[0].sanitize_on_release, actual_1->region_configs[0].sanitize_on_release);
ASSERT_EQUAL(expected_1->region_configs[1].base, actual_1->region_configs[1].base);
ASSERT_EQUAL(expected_1->region_configs[1].decode_len, actual_1->region_configs[1].decode_len);
ASSERT_EQUAL(expected_1->region_configs[1].region_len, actual_1->region_configs[1].region_len);
ASSERT_EQUAL(expected_1->region_configs[1].block_size, actual_1->region_configs[1].block_size);
ASSERT_EQUAL(expected_1->region_configs[1].flags, actual_1->region_configs[1].flags);
ASSERT_EQUAL(expected_1->region_configs[1].sanitize_on_release, actual_1->region_configs[1].sanitize_on_release);
```

`--mctpd codeconstruct`: The test will be compiled with the -Dmctpd=codeconstruct

```
meson setup -Dlibdbus=enabled -Dmctpd=codeconstruct build
```
## How to Add a Test Case:
Add the input/output payload you want to test in the XML file for the suite it belongs to.
Some commands don't have any input/output, some have one or the other, or both:

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
be included for every command that expects a response. Filling out the fields is
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