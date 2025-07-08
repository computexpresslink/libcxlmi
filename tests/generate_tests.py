import os
import argparse
import shutil
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from suites import Test, SUITES

class Endpoint(ABC):
    @abstractmethod
    def __init__(self):
        pass

class Ioctl(Endpoint):
    def __init__(self, devname:str):
        self.devname = devname

class Mctp(Endpoint):
    def __init__(self, nid, eid):
        self.nid = nid
        self.eid = eid

class Generate_Context:
    ep: Endpoint
    check_rsp: bool
    rc: int
    test: Test

    def __init__(self):
        self.ep = None
        self.check_rsp = False
        self.rc = 0
        self.test = None


CURR_DIR = os.path.dirname(os.path.abspath(__file__))

PREFIX = """#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <libcxlmi.h>

#define MAX_PAYLOAD_SIZE 4096

static inline void freep(void *p)
{
	free(*(void **)p);
}
#define _cleanup_free_ __attribute__((cleanup(freep)))

#define UUID(time_low, time_mid, time_hi_and_version,                    \\
  clock_seq_hi_and_reserved, clock_seq_low, node0, node1, node2,         \\
  node3, node4, node5)                                                   \\
  { ((time_low) >> 24) & 0xff, ((time_low) >> 16) & 0xff,                \\
    ((time_low) >> 8) & 0xff, (time_low) & 0xff,                         \\
    ((time_mid) >> 8) & 0xff, (time_mid) & 0xff,                         \\
    ((time_hi_and_version) >> 8) & 0xff, (time_hi_and_version) & 0xff,   \\
    (clock_seq_hi_and_reserved), (clock_seq_low),                        \\
    (node0), (node1), (node2), (node3), (node4), (node5)                 \\
  }
"""

ASSERT_MACRO = """
#define ASSERT_EQUAL(expected, actual) \\
    if (expected != actual) { \\
        printf("Assertion failed: %s = %llu, %s = %llu\\n", \\
               #expected, (unsigned long long)(expected), \\
               #actual, (unsigned long long)(actual)); \\
        rc = EXIT_FAILURE; \\
    }
"""

REQ_BUF = "req"
RSP_BUF = "rsp"
EXPECTED_BUF = "expected"

MAIN = f"""
int main() {{
    struct cxlmi_ctx *ctx;
    struct cxlmi_endpoint *ep;
    _cleanup_free_ void *{REQ_BUF} = calloc(1, MAX_PAYLOAD_SIZE);
    _cleanup_free_ void *{RSP_BUF} = calloc(1, MAX_PAYLOAD_SIZE);
    _cleanup_free_ void *{EXPECTED_BUF} = calloc(1, MAX_PAYLOAD_SIZE);
    int rc = EXIT_FAILURE;

    assert({REQ_BUF} != NULL);
    assert({RSP_BUF} != NULL);
    assert({EXPECTED_BUF} != NULL);
    ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
    assert(ctx != NULL);
"""

FOOTER = """
cleanup:
    cxlmi_close(ep);

exit_free_ctx:
    cxlmi_free_ctx(ctx);
    return rc;
}
"""

G_COUNT = 1
G_INDENT_LEVEL = 1
ASSERT_INDENT = "    " * G_INDENT_LEVEL
ASSERT_TYPE = "ASSERT_EQUAL"
TUNNEL_INFO = "NULL"

def get_expected_str():
    return 'expected_' + str(G_COUNT)

def get_actual_str():
    return 'actual_' + str(G_COUNT)

def get_req_str():
    return 'request_' + str(G_COUNT)

def generate_struct_body(element, indent_level=0, expected_name="expected_rsp", actual_name="actual", ptr=True):
    indent = "    " * indent_level
    struct_body = "{\n"
    assertions = ""

    for child in element:
        field_name = child.tag
        child_elements = list(child)
        has_grandchildren = any(list(grandchild) for grandchild in child_elements)

        # Skip flex array memebers, which can't be initialized in this format:
        # struct X = {.field = Y, .field1 = Z}...
        node_type = child.attrib.get('type', '').lower()
        if node_type == 'flex':
            # Flex array members must be handled separately
            continue

        # Case: Array of structs
        if len(child_elements) > 0 and has_grandchildren:
            struct_body += f"{indent}    .{field_name} = {{\n"
            for i, entry in enumerate(child_elements):
                nested_body, nested_assertions = generate_struct_body(
                    entry,
                    indent_level + 2,
                    f"{expected_name}->{field_name}[{i}]",
                    f"{actual_name}->{field_name}[{i}]",
                    ptr=False
                )
                struct_body += f"{indent}        {nested_body},\n"
                assertions += nested_assertions
            struct_body += f"{indent}    }},\n"

        # Case: Nested struct
        elif len(child_elements) > 0:
            nested_body, nested_assertions = generate_struct_body(
                child,
                indent_level + 1,
                f"{expected_name}.{field_name}",
                f"{actual_name}.{field_name}"
            )
            struct_body += f"{indent}    .{field_name} = {nested_body},\n"
            assertions += nested_assertions

        # Case: Scalar field
        else:
            if node_type == 'uuid':
                # UUID() generated from 11 elements
                uuid_elements = [e.strip for e in child.text.split(",")]
                if len(uuid_elements) != 11:
                    print(f"UUID WRONG USAGE: expected 11 elements, but got {len(uuid_elements)} while generating {child.tag}")
                    continue

                struct_body += f"{indent}    .{field_name} = UUID({child.text}),\n"
                assertions += f"{ASSERT_INDENT}{ASSERT_TYPE}(memcmp({expected_name}->{field_name}, {actual_name}->{field_name}, 11), 0);\n"

            else:
                ref = '->' if ptr else '.'
                struct_body += f"{indent}    .{field_name} = {child.text},\n"
                assertions += f"{ASSERT_INDENT}{ASSERT_TYPE}({expected_name}{ref}{field_name}, {actual_name}{ref}{field_name});\n"

    struct_body += f"{indent}}}"
    return struct_body, assertions


def generate_struct_code(var_name, struct_name, element, indent_level=0):
    """
    Recursively generate C code for requests/expected responses from the
    given XML node.

    Parameters:
        - var_name: variable name for the request/response
        (ex: req_1/expected_1/actual_1, etc.)
        - struct_name: name of the struct (ex: cxlmi_cmd_XXX_req/cxlmi_cmd_XXX_rsp)
        - element: corresponding XML node
        - indent_level: indent level

    Requests are generated in the following format. :
        struct cxlmi_cmd_XXX_req expected_1 = {
            .field_1 = value_1,
            .field_2 = value_2,
            ...
        }
    where value_1 and value_2 are read from the XML node.

    Expected responses are generated similarly with their assertions:
     struct cxlmi_cmd_XXX_rsp actual_1 = {
        .field_1 = value_1,
        ...
     }

     ASSERT_EQUAL(expected_1, actual_1, field_1);

     OR if the response node is empty, return ""
    """
    if len(element) == 0:
        return "", ""

    struct_body, assertions = generate_struct_body(element,
                                                   indent_level,
                                                   expected_name=get_expected_str(),
                                                   actual_name=get_actual_str())
    code = f"*{var_name} = ({struct_name}) {struct_body};\n\n"
    return code, assertions

# Generate code for 1 command (create req payload, send the command, then check rsp payload)
def generate_c_code(ctx:Generate_Context):
    test_info: Test = ctx.curr_test
    command = test_info.xml_node
    opcode = command.attrib['opcode']

    func = test_info.func_name
    request = command.find("request")
    response = command.find("response")

    req_str = get_req_str()
    actual = get_actual_str()
    expected = get_expected_str()

    req_code, expected_rsp_code, assertions = "", "", ""

    if request is not None:
        req_struct = test_info.req_struct
        # Generate req struct initialization. generate_struct_code always generates
        # assertions, but ASSERT_EQUAL() don't apply to requests, so throw them away
        req_code, _ = generate_struct_code(req_str,
                                           req_struct,
                                           request,
                                           indent_level=G_INDENT_LEVEL)

    if response is not None:
        rsp_struct = test_info.rsp_struct
        # Generate expected rsp struct initialization and checks
        expected_rsp_code, assertions = generate_struct_code(expected,
                                                             rsp_struct,
                                                             response,
                                                             indent_level=G_INDENT_LEVEL)

    function_call = ""
    cast_rsp = ""

    # Handle case for different method signatures
    if response is not None:
        cast_rsp = f"{rsp_struct} *{actual} = ({rsp_struct} *) {RSP_BUF};"
        if request is not None:
            function_call = f"{func}(ep, {TUNNEL_INFO}, {req_str}, {actual})"
        else:
            function_call = f"{func}(ep, {TUNNEL_INFO}, {actual})"
    elif request is not None:
        function_call = f"{func}(ep, {TUNNEL_INFO}, {req_str})"
    else:
        function_call = f"{func}(ep, {TUNNEL_INFO})"

    # Allocate and call the function
    alloc_and_call = f"""
    {cast_rsp}

    rc = {function_call};
    if (rc != {ctx.rc}) {{
        fprintf(stdout, "Error: Function {func} ({opcode}h) returned rc of %d but expected {ctx.rc}\\n", rc);
        goto cleanup;
    }}
    rc = EXIT_SUCCESS;
"""

    # Cast request buf to req_type
    if request is not None:
        req_code = f"""
    {req_struct} *{req_str} = ({req_struct} *){REQ_BUF};
    {req_code}
"""
    # Cast expected buf to rsp_type
    if response is not None:
        expected_rsp_code = f"""
    {rsp_struct} *{expected} = ({rsp_struct} *) {EXPECTED_BUF};
    {expected_rsp_code}"""

    # Skip assertions checking rsp.field = expected.field if check_rsp is False
    if ctx.check_rsp:
        return req_code + expected_rsp_code + alloc_and_call + assertions +"\n"
    else:
        return req_code + alloc_and_call

def generate_ioctl_code(devname='mem0'):
    return f"""
    ep = cxlmi_open(ctx, "{devname}");
    if (!ep) {{
        fprintf(stdout, "Failed to open device %s\\n", "{devname}");
        goto exit_free_ctx;
    }}

    printf("Opened endpoint on device %s\\n", "{devname}");

    """

def generate_mctp_code(nid=0, eid=0):
    return f"""
    ep = cxlmi_open_mctp(ctx, {nid}, {eid});

    if (!ep) {{
        printf("Failed to open MCTP EP with NID:EID =  %d:%d\\n", {nid}, {eid});
        goto exit_free_ctx;
    }}

    printf("Opened MCTP EP with NID:EID =  %d:%d\\n", {nid}, {eid});

    """

# Generate test file for a single command
def generate_test_file(ctx:Generate_Context):
    test = ctx.curr_test
    test_file = 'test-' + test.opcode + '.c'
    output_file = os.path.join(CURR_DIR, 'output', test_file)

    with open(output_file, 'w', newline='') as f:
        # Write the prefix (C file header) to the file
        f.write(PREFIX + "\n")

        # Write the generated assert macro to the file with explicit newlines
        f.write(ASSERT_MACRO)

        f.write(MAIN)

        if isinstance(ctx.ep, Mctp):
            f.write(generate_mctp_code(ctx.ep.nid, ctx.ep.eid))
        else:
            f.write(generate_ioctl_code(ctx.ep.devname))

        # Generate and write the C code for each command
        f.write(generate_c_code(ctx))
        global G_COUNT
        G_COUNT += 1

        # Write the footer to the file
        f.write(FOOTER)
        G_COUNT = 1  # Reset the global counter for the next suites

    add_to_build_file(test_file)

def load_xml(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()

def add_to_build_file(test_file):
    test_build_file = os.path.join(CURR_DIR, 'output', 'meson.build')

    with open(test_build_file, 'a') as f:
        f.write(f"""
executable(
    '{test_file[:-2]}',
    ['{test_file}'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)
""")

def clear_directory(dir_path):
    # Make sure the directory exists
    if os.path.exists(dir_path):
        # Delete all files and subdirectories
        for filename in os.listdir(dir_path):
            file_path = os.path.join(dir_path, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
    else:
        # Create the directory if it doesn't exist
        os.makedirs(dir_path)

# Create output dir and sets up meson build files
def setup_output_dir():
    output_dir = os.path.join(CURR_DIR, 'output')

    clear_directory(output_dir)

    line_to_add = "subdir('output')"
    current_build_file = os.path.join(CURR_DIR, 'meson.build')
    with open(current_build_file, 'r') as f:
            lines = f.readlines()

    # Check if the line already exists (stripped of whitespace)
    if not any(line_to_add in line for line in lines):
        # Append the line
        with open(current_build_file, 'a') as f:
            if not lines or not lines[-1].endswith('\n'):
                f.write('\n')  # ensure there's a newline before appending
            f.write(line_to_add + '\n')

    # Create test build file or clear it from previous run
    test_build_file = os.path.join(CURR_DIR, 'output', 'meson.build')
    with open(test_build_file, 'w') as f:
        f.write('')

def generate_suite(suite):

    for test in suite.tests.values():
        context.curr_test = test
        generate_test_file(context)

def add_args(parser):
    parser.add_argument('-t', '--test', type=str, required=False, help='opcode of the test')
    parser.add_argument('-s', '--suite', type=str, required=False, help='test suite (defined in suites.py)')
    parser.add_argument('-e', '--endpoint', nargs='*', type=str, required=False, default=['ioctl', 'mem0'], help='endpoint type to open (mctp nid eid| ioctl devname)')
    parser.add_argument('-v', '--verify-rsp', action='store_true', required=False, help='check expected response payloads?')
    parser.add_argument('-r', '--rc', type=int, required=False, default=0, help='expected return code')
    parser.add_argument('-d', '--mctpd', type=str, required=False, default='openbmc', help='mctpd compile flag (openbmc | codeconstruct)')

if __name__ == "__main__":
    # Parse args
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()

    context = Generate_Context()

    context.rc = args.rc
    context.check_rsp = args.verify_rsp

    ep_info = args.endpoint
    ep_type = ep_info[0]
    if ep_type == 'ioctl':
        context.ep = Ioctl(ep_info[1])
    else:
        context.ep = Mctp(ep_info[1], ep_info[2])

    setup_output_dir()

    # Generate single test case
    if args.test:
        print(f"Generating Test Case for Opcode {args.test}")
        opcode = args.test

        test = next((suite.tests[opcode] for suite in SUITES.values() if opcode in suite.tests), None)

        if test is None:
            print(f'No test defined for opcode {opcode}')
            exit(-1)

        context.curr_test = test
        generate_test_file(context)
    elif args.suite:
        suite_name = args.suite.upper()
        suite = SUITES.get(suite_name, None)

        if suite is None:
            print(f'Invalid suite {suite_name}')
            exit(-1)

        print(f"Generating Suite {suite_name}")
        generate_suite(suite)

    else:   # Default generate all
        print("Default: Generating All Test Code")

        for suite in SUITES.values():
            generate_suite(suite)



