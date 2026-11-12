#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
# Run clang2py against the libcxlmi that was just built, then make the
# generated module load the library by name rather than by its build path.
#
# Usage: gen-bindings.py <clang2py> <libcxlmi.so> <libcxlmi.h> <output.py>

import os
import subprocess
import sys

clang2py, lib, header, output = sys.argv[1:5]

# clang2py needs a path to the library to see which symbols it exports.
# Given a bare name it instead loads whatever libcxlmi is installed, if any.
subprocess.run([clang2py, '-l', lib, header, '-o', output], check=True)

with open(output) as f:
    text = f.read()

# The generated code loads the library with ctypes.CDLL(<the -l path>).
# Load it by name, so the module works once installed and does not
# point into the build directory.
build_path = repr(lib)
if build_path not in text:
    sys.exit(f'{output}: no reference to {lib}; clang2py output changed?')
text = text.replace(build_path, repr(os.path.basename(lib)))

with open(output, 'w') as f:
    f.write(text)
