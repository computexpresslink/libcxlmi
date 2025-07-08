import sys
import os
import argparse
import subprocess
from suites import Test, Suite, SUITES
# Generate Tests and Run Tests share same args
from generate_tests import add_args

CURR_DIR = os.path.dirname(os.path.abspath(__file__))

class Run_Context:
    curr_test: Test
    curr_suite: Suite
    suites_run: list[Suite]
    num_passed: int
    num_tests: int

    def __init__(self):
        self.curr_test = None
        self.curr_suite = None
        self.suites_run = []
        self.num_passed = 0
        self.num_tests = 0

# Adds 1 to ctx.num_tests, and 1 to ctx.num_passed if passed
def run_test(ctx: Run_Context):
    test = ctx.curr_test
    suite = ctx.curr_suite

    build_dir = os.path.join(CURR_DIR, '..', 'build', 'tests', 'output')
    executable = os.path.join(build_dir, 'test-' + test.opcode)
    rc = subprocess.run(executable, stdout=sys.stdout, stderr=sys.stderr).returncode

    ctx.num_tests += 1
    suite.num_tests += 1
    if rc == 0:
        ctx.num_passed += 1
        suite.num_passed += 1


def run_suite(ctx: Run_Context):
    suite = ctx.curr_suite

    for test in suite.tests.values():
        ctx.curr_test = test
        run_test(ctx)

    ctx.suites_run.append(ctx.curr_suite)

def run_all(ctx: Run_Context):
    for suite in SUITES.values():
        ctx.curr_suite = suite
        run_suite(ctx)

def main():
    # Generate tests, check=True will stop execution if generating tests fails
    generate_test_path = os.path.join(CURR_DIR, 'generate_tests.py')
    subprocess.run([sys.executable, generate_test_path, *sys.argv[1:]], check=True)

    parser = argparse.ArgumentParser()
    add_args(parser)
    args = parser.parse_args()

    # Compile
    mctpd = args.mctpd
    subprocess.run(["meson", "setup", "-Dlibdbus=enabled", f"-Dmctpd={mctpd}", "build"],
                   stdout=sys.stdout,
                   stderr=sys.stderr,
                   check=True)

    subprocess.run(["meson", "compile", "-C", "build"],
                   stdout=sys.stdout,
                   stderr=sys.stderr,
                   check=True)

    # Run Tests
    ctx = Run_Context()
    if args.test:
        opcode = args.test

        for suite in SUITES.values():
            if opcode in suite.tests:
                ctx.curr_suite = suite
                ctx.curr_test = suite.tests[opcode]

        if ctx.curr_test is None:
            print(f'No test defined for opcode {opcode}')
            exit(-1)

        run_test(ctx)
        if ctx.num_passed == 1:
            print(f"Test {opcode} passed!")
        else:
            print(f"Test {opcode} failed!")
    elif args.suite:
        suite_name = args.suite.upper()
        print(suite_name)
        suite = SUITES.get(suite_name)

        if suite is None:
            print(f'Invalid suite {suite_name}')
            exit(-1)

        ctx.curr_suite = suite
        run_suite(ctx)

        print(f'Suite {suite_name} Results: {ctx.num_passed} / {ctx.num_tests}')
    else:
        run_all(ctx)

        print(f'Total tests passed: {ctx.num_passed} / {ctx.num_tests}')
        for suite in ctx.suites_run:
            print(f'\tSuite {suite.name} Results: {suite.num_passed} / {suite.num_tests}')

    return 0 if ctx.num_passed == ctx.num_tests else 1

if __name__ == "__main__":
    sys.exit(main())