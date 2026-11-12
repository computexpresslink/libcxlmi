# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
executable(
    'api-simple-tests',
    ['api-simple-tests.c'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)

mock_tests = executable(
    'mock-tests',
    ['mock-tests.c'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)

test('mock-tests', mock_tests)

# cxlmi_scan_mctp() against a fake mctpd on a private D-Bus; the test
# skips itself if there is no dbus-daemon to run.
if libdbus_dep.found()
    scan_mctp_tests = executable(
        'scan-mctp-tests',
        ['scan-mctp-tests.c'],
        dependencies: [libcxlmi_dep, libdbus_dep],
        include_directories: [inc]
    )

    test('scan-mctp-tests', scan_mctp_tests)
endif

executable(
    'cxl-test-generic',
    ['cxl-test-generic.c'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)

executable(
    'cxl-test-memdev',
    ['cxl-test-memdev.c'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)

executable(
    'cxl-test-fmapi',
    ['cxl-test-fmapi.c'],
    dependencies: libcxlmi_dep,
    include_directories: [inc]
)

# The test runs the build machine's python3, which cannot load a cross-built
# libcxlmi; it would fail, or silently load an installed native copy.
if build_python and not meson.is_cross_build()
    test('python-bindings',
        python,
        args: [files('python/test_cxlmi.py'), '-v'],
        depends: [cxlmi, python_bindings],
        env: {
            'PYTHONPATH': python_module_dir,
            'LD_LIBRARY_PATH': meson.project_build_root() / 'src',
        },
    )
endif
