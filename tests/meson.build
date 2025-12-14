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
