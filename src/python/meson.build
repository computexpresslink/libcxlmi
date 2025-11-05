
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

# Now check for Python installation and setuptools
# Only do this after we know python3 and clang2py exist
python_installation = import('python').find_installation(
    'python3',
    required: false,
)

if not python_installation.found()
    if python_option.enabled()
        error('Python setuptools module not found but python=enabled')
    endif
    # Auto mode: silently skip without messages
    subdir_done()
endif

# Try to locate clang2py (the tool that generates bindings). If not found
# we do not attempt to install anything automatically here; instead print a
# helpful message asking the user to install the package that provides
# `clang2py` (for example via `pip install clang2py` inside a venv).
clang2py = find_program('clang2py', required: false)
if not clang2py.found()
    message('clang2py not found; python bindings targets will not be available.\nPlease install the package that provides clang2py (for example: python3 -m pip install --user clang2py or install inside your venv).\nAfter installing, reconfigure meson and run the generate target.')
    subdir_done()
endif

message('Python install dir: ' + python_installation.get_path('purelib'))

# All dependencies found - proceed with build
build_python = true
message('Building Python bindings')

# Generate the Python bindings
src_h = meson.project_source_root() + '/src/libcxlmi.h'
out_py = 'cxlmi.py'

python_bindings = custom_target(
  'generate_python_bindings',
  input: src_h,
  output: out_py,
  command: [
    clang2py,
    '-l', 'cxlmi',
    '@INPUT@',
    '-o', meson.current_build_dir() + '/' + out_py,
  ],
  build_by_default: true,
)

# Install Python module when bindings are enabled
python_install_dir = run_command(
  python, '-c',
  'import site; print(site.getsitepackages()[0])',
  check: true,
).stdout().strip()

message('Python site-packages path: ' + python_install_dir)

meson.add_install_script(
    'sh', '-c',
    'cp @0@/@1@ @2@/'.format(
        meson.current_build_dir(),
        out_py,
        python_install_dir
    )
)

# Make available for testing
python_module_dir = meson.current_build_dir()