# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Python examples for libcxlmi
#

if not build_python
    subdir_done()
endif

# Install Python examples
python_examples = [
    'identify_device.py',
    'get_health_info.py',
    'get_partition_info.py',
    'list_endpoints_mctp.py',
    'tunnel_example.py',
    'fmapi_switch_info.py',
    'README.md',
]

install_data(
    python_examples,
    install_dir: join_paths(datadir, 'doc', 'libcxlmi', 'examples', 'python'),
    install_mode: 'rw-r--r--',
)

# Make examples executable
foreach example : python_examples
    if example.endswith('.py')
        meson.add_install_script('chmod', '+x',
            join_paths(get_option('prefix'), datadir, 'doc', 'libcxlmi', 'examples', 'python', example))
    endif
endforeach
