
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

# Find install dir to find dependencies and tell meson where to install bindings in
# add_install_script, which installs bindings when meson install is run.

python_install_dir = run_command(
  python, '-c',
  'import site; print(site.getsitepackages()[0])',
  check: true,
).stdout().strip()

message('Python site-packages path: ' + python_install_dir)

# clang2py requires clang, python-clang, and clang.version == python-clang.version
clang = find_program('clang', required: true)
clang_version_output = run_command(clang, '--version', check: true).stdout().strip()

clang_version = ''
clang_major = ''

foreach line : clang_version_output.split('\n')
  if line.contains('clang version')
    parts = line.split()
    found = false
    foreach p : parts
      if found
        clang_version = p
        clang_major = clang_version.split('.')[0]
        break
      endif
      if p == 'version'
        found = true
      endif
    endforeach
  endif
endforeach

message('Found clang: ' + clang.full_path())
message('Full clang version: ' + clang_version)
message('Clang major: ' + clang_major)

python_clang_cmd = run_command(
  python,
  '-c',
  'import importlib.metadata; print(importlib.metadata.version("clang"))',
  check: false
)

if python_clang_cmd.returncode() != 0
  error('Python clang not found. Install with "pip install clang"')
else
  python_clang_version = python_clang_cmd.stdout().strip()
  message('Python clang version: ' + python_clang_version)
endif

if clang_major != python_clang_version.split('.')[0]
    error('clang (' + clang_version + ') and python-clang (' + python_clang_version + ') versions differ!')
else
    message('clang and python-clang versions match: ' + clang_major)
endif

# Try to locate clang2py (the tool that generates bindings). If not found
# we do not attempt to install anything automatically here; instead print a
# helpful message asking the user to install the package that provides
# `clang2py` (for example via `pip install clang2py` inside a venv).
clang2py = find_program('clang2py', required: true)

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