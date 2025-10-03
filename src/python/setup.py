#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""
Python bindings for libcxlmi
"""

from setuptools import setup, Extension
import os
import sys

# Get build directory from environment or use default
build_dir = os.environ.get('MESON_BUILD_ROOT', '../..')
source_dir = os.environ.get('MESON_SOURCE_ROOT', '../..')

# SWIG extension module
# The wrap file is generated in the build directory
cxlmi_module = Extension(
    '_cxlmi',
    sources=[os.path.join(build_dir, 'src', 'python', 'cxlmi_wrap.c')],
    include_dirs=[
        os.path.join(source_dir, 'src'),
        os.path.join(source_dir, 'ccan'),
        os.path.join(build_dir),  # for config.h
    ],
    library_dirs=[os.path.join(build_dir, 'src')],
    libraries=['cxlmi'],
    # Suppress warnings in SWIG-generated code (these are safe to ignore):
    # -Wno-cast-function-type: SWIG generates function pointer casts for Python C API
    # -Wno-unused-variable: SWIG may generate helper variables that aren't always used
    # -Wno-address-of-packed-member: SWIG accesses fields in packed structs (CXL spec
    #   requires packed structs for wire format). The generated code uses proper
    #   alignment handling, so this warning is cosmetic.
    extra_compile_args=['-Wno-cast-function-type', '-Wno-unused-variable', '-Wno-address-of-packed-member'],
)

setup(
    name='cxlmi',
    version='0.0.1',
    author='libcxlmi contributors',
    description='Python bindings for libcxlmi - CXL Management Interface library',
    long_description=open(os.path.join(source_dir, 'README.md')).read() if os.path.exists(os.path.join(source_dir, 'README.md')) else '',
    long_description_content_type='text/markdown',
    ext_modules=[cxlmi_module],
    py_modules=['cxlmi'],
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: System :: Hardware',
    ],
)
