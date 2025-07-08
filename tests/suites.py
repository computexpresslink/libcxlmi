import os
import re
import xml.etree.ElementTree as ET
from typing import Optional, Tuple

class Test:
     def __init__(self, opcode, xml_node, suite, func_name, req_struct, rsp_struct):
        self.opcode = opcode
        self.xml_node = xml_node
        self.suite = suite
        self.func_name = func_name
        self.req_struct = req_struct
        self.rsp_struct = rsp_struct

class Suite:
    name: str
    tests: dict[str, Test]
    num_passed: int
    num_tests: int

    def __init__(self, name ):
        self.name = name
        self.tests = {}
        self.num_passed = 0
        self.num_tests = 0


def load_xml(file_path):
    tree = ET.parse(file_path)
    return tree.getroot()

def extract_command_info(md_text: str, opcode: str | int) -> Optional[Tuple[str, Optional[str], Optional[str]]]:
    """
    Given a numeric opcode (e.g., "5500" or 5500), extract:
      - function name
      - request struct name (or None)
      - response struct name (or None)
    from documentation markdown.

    Returns:
        (function_name, req_struct, rsp_struct)
        or None if the opcode section or function_name is not found
    """

    # Match heading like: ## Some Command (5500h)
    section_pattern = re.compile(rf"## .*?\({opcode}h\)", re.IGNORECASE)
    section_match = section_pattern.search(md_text)
    if not section_match:
        return None

    # Slice the section
    start_index = section_match.start()
    next_heading_match = re.search(r"\n## ", md_text[start_index + 1:])
    end_index = start_index + 1 + next_heading_match.start() if next_heading_match else len(md_text)
    section = md_text[start_index:end_index]

    # Extract function name
    func_match = re.search(r"```C\s+int\s+([a-zA-Z0-9_]+)\s*\(", section)
    if not func_match:
        return None
    func_name = func_match.group(1)

    # Extract input struct name
    input_struct = None
    input_block_match = re.search(
        r"Input\s+Payload\s*:?\s*\n\s*(```C.*?```)",
        section,
        re.DOTALL | re.IGNORECASE
    )
    if input_block_match:
        struct_match = re.search(r"struct\s+([a-zA-Z0-9_]+)\s*{", input_block_match.group(1))
        input_struct = 'struct ' + struct_match.group(1) if struct_match else "None"

    # Extract return struct name
    return_struct = None
    return_block_match = re.search(
        r"Return\s+Payload\s*:?\s*\n\s*(```C.*?```)",
        section,
        re.DOTALL | re.IGNORECASE
    )

    if return_block_match:
        struct_match = re.search(r"struct\s+([a-zA-Z0-9_]+)\s*{", return_block_match.group(1))
        return_struct = 'struct ' + struct_match.group(1) if struct_match else "None"

    return [func_name, input_struct, return_struct]

def setup_suite(root):
    suite_name = root.attrib.get('suite')
    suite = Suite(suite_name)
    docs_path = ""
    curr_dir = os.path.dirname(os.path.abspath(__file__))

    match suite_name:
        case "FMAPI":
            docs_path = os.path.join(curr_dir, '..', 'docs', 'FM-API.md')
        case "GENERIC":
            docs_path = os.path.join(curr_dir, '..', 'docs', 'Generic-Component-Commands.md')
        case "MEMDEV":
            docs_path = os.path.join(curr_dir, '..', 'docs', 'Memory-Device-Commands.md')
        case _:
            print("Unknown suite")
            return

    with open(docs_path, 'r') as f:
        content = f.read()
        # Parse docs for command's req/rsp struct and function signature
        for command in root:
            opcode = command.attrib.get('opcode')
            info = extract_command_info(content, opcode)

            if info is None:
                print(f"No documentation for opcode {opcode}")
                continue

            t = Test(opcode, command, suite, func_name=info[0], req_struct=info[1], rsp_struct=info[2])

            suite.tests[opcode] = t

    SUITES[suite_name] = suite

# Parse all XML files and set up test info and suites
SUITES = {}
curr_dir = os.path.dirname(os.path.abspath(__file__))
test_dir = os.path.join(curr_dir, 'input')
for filename in os.listdir(test_dir):
    full_path = os.path.join(test_dir, filename)
    if os.path.isfile(full_path):
        root = load_xml(full_path)
        setup_suite(root)



