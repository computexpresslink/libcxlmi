# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Python bindings for libcxlmi
#

# Check if we should build Python bindings
python_option = get_option('python')
build_python = false

if python_option.disabled()
    subdir_done()
endif

# Find Python interpreter - don't require it yet if auto
python = find_program('python3', required: false)
if not python.found()
    if python_option.enabled()
        error('Python 3 not found but python=enabled')
    endif
    # Auto mode: silently skip without messages
    subdir_done()
endif

# Find SWIG - don't require it yet if auto
swig = find_program('swig', required: false)
if not swig.found()
    if python_option.enabled()
        error('SWIG not found but python=enabled')
    endif
    # Auto mode: silently skip without messages
    subdir_done()
endif

# Now check for Python installation and setuptools
# Only do this after we know python3 and swig exist
python_installation = import('python').find_installation(
    'python3',
    required: false,
    modules: ['setuptools']
)

if not python_installation.found()
    if python_option.enabled()
        error('Python setuptools module not found but python=enabled')
    endif
    # Auto mode: silently skip without messages
    subdir_done()
endif

# All dependencies found - proceed with build
build_python = true
message('Building Python bindings')

# Generate SWIG wrapper
swig_c_file = custom_target(
    'cxlmi_wrap.c',
    input: files('../cxlmi.i'),
    output: ['cxlmi_wrap.c', 'cxlmi.py'],
    command: [
        swig,
        '-python',
        # Suppress Warning 462: "Unable to set variable of type array"
        # This warning occurs for C99 flexible array members (uint8_t data[] at end of struct).
        # These are intentionally not exposed to Python because:
        # 1. They're variable-length and can't be safely mapped to Python attributes
        # 2. They're accessed through dedicated getter functions in the C API
        # 3. The structures are still fully usable - only the flex array field is hidden
        # 4. This is the standard approach for SWIG bindings (same as libnvme)
        # The warning is harmless - it just means SWIG skips these fields, which is correct.
        '-w462',
        '-I@SOURCE_ROOT@/src',
        '-I@SOURCE_ROOT@/src/cxlmi',
        '-I@BUILD_ROOT@',
        '-o', '@OUTPUT0@',
        '-outdir', '@OUTDIR@',
        '@INPUT@'
    ],
    depend_files: [
        files('../libcxlmi.h'),
        files('../cxlmi/api-types.h'),
    ],
)

# Build Python extension module using setup.py
python_build = custom_target(
    'python-build',
    input: [swig_c_file],
    output: '_cxlmi.so',
    build_by_default: true,
    command: [
        python,
        files('setup.py'),
        'build_ext',
        '--build-lib', '@OUTDIR@',
        '--build-temp', '@PRIVATE_DIR@',
    ],
    env: {
        'MESON_BUILD_ROOT': meson.project_build_root(),
        'MESON_SOURCE_ROOT': meson.project_source_root(),
    },
    depends: [cxlmi],
    install: false,
)

# Install Python module
if get_option('python-install')
    # Install using meson.add_install_script for generated files
    meson.add_install_script(
        'sh', '-c',
        'cp @0@/cxlmi.py @0@/_cxlmi*.so @1@/'.format(
            meson.current_build_dir(),
            python_installation.get_install_dir()
        )
    )
endif

# Make available for testing
python_module_dir = meson.current_build_dir()
