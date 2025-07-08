import sys
import os
import shutil
import argparse
import subprocess
from topo import SUITES
from parse_docs import generate_default_opcode_map, log_opcode_map
from generate_tests import generate_test_file, generate_build_file, load_xml

# Global Variables
CURR_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.join(CURR_DIR, '../', '../')
VM_PORT = 2025   # Must match .vars.config used by cxl-test-tool
VM_USER = 'root'
VM_HOSTNAME = 'localhost'
opcode_map = {}

# QEMU=tools.system_path("QEMU_ROOT") + "/build/qemu-system-x86_64"
# KERNEL=tools.system_path("KERNEL_ROOT") + "/arch/x86/boot/bzImage"
# CXL_TEST_TOOL_DIR=os.path.join(CURR_DIR, 'cxl_test_tool/')

def run_shell_cmd(cmd:str, echo=True):
    if echo:
        print(cmd)
    output = subprocess.getoutput(cmd)
    if echo:
        print(output)
    return output

def run_on_vm(cmd:str):
    return run_shell_cmd(f"cxl-tool --cmd '{cmd}'")

def install_libcxlmi_on_vm(target_dir="/tmp/libcxlmi"):
    print('Copy libcxlmi to VM')
    cmd = f"""rsync -av -e 'ssh -p {VM_PORT}' \
          --exclude='.git/' \
          --exclude='build/' \
          --exclude='venv/' \
          --exclude='__pycache___' \
          "{REPO_ROOT}" {VM_USER}@{VM_HOSTNAME}:{target_dir}"""
    run_shell_cmd(cmd)
    print('-------------------------------------------------')

    print('Compile libcxlmi')
    cmd="cd %s; meson setup -Dlibdbus=enabled build; meson compile -C build;"%target_dir
    run_on_vm(cmd)

def start_vm(suite):
    # Start VM
    topo = suite['qemu_str']
    run_shell_cmd(f'yes "" | cxl-tool --run --raw -T \'{topo}\'')

    print('-------------------------------------------------')
    print('Sleep for 60s while VM boots...')
    run_shell_cmd("sleep 60")
    print('-------------------------------------------------')

    # Set up MCTP
    if suite["mctp"] is not None:
        run_shell_cmd("yes '' | cxl-tool --setup-mctp")
        print('-------------------------------------------------')

    # Load drivers and ndctl
    print("Installing NDCTL")
    run_shell_cmd("yes '' | cxl-tool --install-ndctl")
    print('-------------------------------------------------')
    print("Loading Drivers")
    run_shell_cmd("yes '' | cxl-tool  --load-drv")
    print('-------------------------------------------------')

    # Show topo info as debug output
    run_on_vm("cxl list")
    print('-------------------------------------------------')

    # Copy current libcxlmi repo to VM and compile
    libcxlmi_path = "/tmp/libcxlmi"
    install_libcxlmi_on_vm(libcxlmi_path)
    print('-------------------------------------------------')

def execute_test(opcode, test_file, results_file):
    # Execute tests and capture output
    with open(results_file, 'w') as f:
        # Execute test file
        test_executable = f'/tmp/libcxlmi/build/tests/qemu-tests/output/{test_file[:-2]}'
        results = run_on_vm(test_executable)
        f.write(results)
        if results.splitlines()[-1] == "Passed!":
            print(f"Test {opcode} passed.")
            return 0
        else:
            print(f"Test {opcode} failed. Check {results_file} for details.")
            return -1

def run_tests(test_infos, topo_info) -> tuple[int, int]:
    """
        Takes a list of opcodes, generates test files for them, starts a VM, and
        executes them on the VM.

        Returns: (num_tests_passed, total_passed)
    """
    # maps opcode to its test_file and log file
    file_info = {}
    num_passed = 0
    total_tests = 0

    for opcode, command_xml in test_infos.items():
        file_info[opcode] = {}
        info = file_info[opcode]

        test_file = 'test-' + f'{opcode}' + '.c'
        info['test_file'] = test_file
        test_file_path = os.path.join(CURR_DIR, 'output/', test_file)
        build_file = os.path.join(CURR_DIR, 'output/', 'meson.build')
        results_file = os.path.join(CURR_DIR, 'output/', test_file[:-2] + '-results.txt')
        info['results_file'] = results_file

        generate_test_file(test_file_path, command_xml, topo_info, opcode_map)
        generate_build_file(build_file, test_file)
        total_tests += 1

        print(f"Test file has been written to {test_file_path}")

    if start_vm(topo_info):
        print("Startup failed. Test not run.")
        return (-1, total_tests)

    for opcode, files in file_info.items():
        test_file = files['test_file']
        results_file = files['results_file']
        if execute_test(opcode, test_file, results_file) == 0:
            num_passed += 1

    return (num_passed, total_tests)

def run_test(opcode) -> tuple[int, int]:
    topo_info = opcode_map[opcode]['suite']
    print(f"Opcode {opcode} belongs to suite {topo_info}")

    input_file = os.path.join(CURR_DIR, topo_info['input'])
    root = load_xml(input_file)
    command_xml = next((child for child in root if child.attrib.get('opcode') == opcode), None)

    num_passed, _ = run_tests(opcode=[opcode],
                                        topo_info=topo_info,
                                        command_xml=command_xml)

    if num_passed != 1:
        print(f'TEST {opcode} FAILED')

    return (num_passed, 1)

def run_suite(suite) -> tuple[int, int]:
    """
        Takes a suite defined in topo.py and runs all tests defined for the suite

        Returns: (num_tests_passed, total_passed)
    """
    topo_info = SUITES[suite]
    input_file = os.path.join(CURR_DIR, topo_info['input'])
    root = load_xml(input_file)
    test_infos = {}

    print('-------------------------------------------------')
    print(f'RUNNING SUITE {suite}')

    for command in root:
        test_infos[command.attrib.get('opcode')] = command

    (num_passed, total_tests) = run_tests(test_infos, topo_info)

    # Print results
    print('-------------------------------------------------')
    if num_passed <= 0:
        print(f'SUITE {suite} FAILED TO RUN')

        # Set to 0 when printing results
        num_passed = 0
    elif num_passed != total_tests:
        print(f'SUITE {suite} RESULTS: {num_passed} tests passed out of {total_tests}')
    else:
        print(f'SUITE {suite} ALL TESTS PASSED: {num_passed} / {total_tests}')

    # Shut down VM and clean up
    print('Shutting down VM...')
    run_shell_cmd('cxl-tool --shutdown')

    return (num_passed, total_tests)

def run_all():
    num_passed = 0
    total_tests = 0

    for suite, _ in SUITES.items():
        (suite_num_passed, suite_num_tests) = run_suite(suite)
        num_passed += suite_num_passed
        total_tests += suite_num_tests

    print('-------------------------------------------------')
    if num_passed != total_tests:
        print(f'AGGREGATE RESULTS: {num_passed} tests passed out of {total_tests}')
    else:
        print(f'ALL TESTS PASSED: {num_passed} / {total_tests}')
    return (num_passed, total_tests)

def clear_subdir(path):
    for filename in os.listdir(path):
        full_path = os.path.join(path, filename)
        try:
            if os.path.isfile(full_path) or os.path.islink(full_path):
                os.unlink(full_path)  # remove file or symlink
            elif os.path.isdir(full_path):
                shutil.rmtree(full_path)  # remove directory recursively
        except Exception as e:
            print(f'Failed to delete {full_path}. Reason: {e}')

def add_args(parser):
    parser.add_argument('-t', '--test', type=str, required=False, help='opcode of the test')
    parser.add_argument('-s', '--suite', type=str, required=False, help='test suite (defined in topo.py)')

def main():
    # Parse args
    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()

    # Create output dir for generating test code
    os.makedirs(CURR_DIR + '/output', exist_ok=True)

    # Parse opcode map
    opcode_map = generate_default_opcode_map()
    log_opcode_map(opcode_map)

    num_passed = 0
    total_tests = 0

    if args.test:
        num_passed, total_tests = run_test(args.test)
    elif args.suite:
        num_passed, total_tests = run_suite(args.suite)
    else:
        num_passed, total_tests = run_all()

    if num_passed != total_tests:
        return -1
    return 0

if __name__ == "__main__":
    sys.exit(main())