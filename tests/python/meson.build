# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Python tests for libcxlmi
#

if not build_python
    subdir_done()
endif

# Python test suite
test('python-bindings',
    python,
    args: [files('test_cxlmi.py')],
    env: {
        'PYTHONPATH': python_module_dir,
        'LD_LIBRARY_PATH': join_paths(meson.project_build_root(), 'src'),
    },
    timeout: 60,
)
