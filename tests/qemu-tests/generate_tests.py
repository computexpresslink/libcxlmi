import sys
import os
import suites
from parse_docs import generate_default_opcode_map
import xml.etree.ElementTree as ET

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
        printf("Assertion failed: %s.%s = %llu, %s->%s = %llu\\n", \\
               #expected, expected, \\
               #actual, actual); \\
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
    if (rc != 0) {
        fprintf(stdout, "Failed.\\n");
    } else {
        printf("Passed!\\n");
    }
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
def generate_c_code(command, opcode_map):
    opcode = command.attrib['opcode']
    if opcode not in opcode_map:
        return f'printf("Unknown opcode {opcode}\\n");'

    mapping = opcode_map[opcode]
    func = mapping['function']
    request = command.find("request")
    response = command.find("response")

    req_str = get_req_str()
    actual = get_actual_str()
    expected = get_expected_str()

    req_code, expected_rsp_code, assertions = "", "", ""

    if request is not None:
        req_struct = mapping['req']
        # Generate req struct initialization. generate_struct_code always generates
        # assertions, but ASSERT_EQUAL() don't apply to requests, so throw them away
        req_code, _ = generate_struct_code(req_str,
                                           req_struct,
                                           request,
                                           indent_level=G_INDENT_LEVEL)

    if response is not None:
        rsp_struct = mapping['rsp']
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
            function_call = f"{func}(ep, {TUNNEL_INFO}, &{req_str}, {actual})"
        else:
            function_call = f"{func}(ep, {TUNNEL_INFO}, {actual})"
    elif request is not None:
        function_call = f"{func}(ep, {TUNNEL_INFO}, &{req_str})"
    else:
        function_call = f"{func}(ep, {TUNNEL_INFO})"

    # Allocate and call the function
    alloc_and_call = f"""
    {cast_rsp}

    rc = {function_call};
    if (rc != 0) {{
        fprintf(stdout, "Error: Function {func} ({opcode}h) returned non-zero rc: %d\\n", rc);
        goto cleanup;
    }}

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

    return req_code + expected_rsp_code + alloc_and_call + assertions +"\n"

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
def generate_test_file(output_file, command, suite_info, opcode_map):
    if not opcode_map:
        opcode_map = generate_default_opcode_map()

    with open(output_file, 'w', newline='') as f:
        # Write the prefix (C file header) to the file
        f.write(PREFIX + "\n")

        # Write the generated assert macro to the file with explicit newlines
        f.write(ASSERT_MACRO)

        f.write(MAIN)

        if (ep := suite_info['mctp']) is not None:
            nid, eid = ep
            f.write(generate_mctp_code(nid, eid))
        else:
            f.write(generate_ioctl_code(suite_info['ioctl']))

        # Generate and write the C code for each command
        f.write(generate_c_code(command, opcode_map))
        global G_COUNT
        G_COUNT += 1

        # Write the footer to the file
        f.write(FOOTER)
        G_COUNT = 1  # Reset the global counter for the next suites

def load_xml(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()

def generate_build_file(build_file, test_file):
    with open(build_file, 'a') as f:
        f.write(f"""
executable(
    '{test_file[:-2]}',
    ['{test_file}'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)
""")

if __name__ == "__main__":
    # Default Generate All
    if len(sys.argv) == 1:
        print("Default: Generating All Test Code")
        opcode_map = generate_default_opcode_map()
        for suite, suite_info in suites.SUITES.items():
            root = load_xml(CURR_DIR + '/' + suite_info['input'])

            for command in root:
                output = f'test-{command.get("opcode")}.c'
                print(f'Generating {output}')
                generate_test_file(output, command, suite_info, opcode_map)

    elif len(sys.argv) == 2:
        suite = sys.argv[1].upper()
        suite_info = suites.SUITES[sys.argv[1].upper()]
        print(f"Generating Test Code for Suite {suite}")
        root = load_xml(CURR_DIR + '/' + suite_info['input'])
        opcode_map = generate_default_opcode_map()

        for command in root:
            output = f'test-{command.get("opcode")}.c'
            print(f'Generating {output}')
            generate_test_file(output, command, suite_info, opcode_map)
    else:
        print("Usage: python generate_tests.py || python generate_tests.py <suite>")
        sys.exit(1)