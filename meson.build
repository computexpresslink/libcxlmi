# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
project(
    'libcxlmi', ['c'],
    meson_version: '>= 0.50.0',
    version: '0.0.1',
    license: 'LGPL-2.1-or-later',
    default_options: [
	'c_std=gnu99',
	'warning_level=1',
	'buildtype=debugoptimized',
	'prefix=/usr/local',
	'sysconfdir=etc',
	'wrap_mode=nofallback'
    ]
)

################################################################################
cc = meson.get_compiler('c')
cxx_available = add_languages('cpp', required: false)

prefixdir  = get_option('prefix')
libdir     = join_paths(prefixdir, get_option('libdir'))
includedir = join_paths(prefixdir, get_option('includedir'))
datadir    = join_paths(prefixdir, get_option('datadir'))
mandir     = join_paths(prefixdir, get_option('mandir'))
bindir     = join_paths(prefixdir, get_option('bindir'))
sysconfdir = join_paths(prefixdir, get_option('sysconfdir'))

################################################################################
conf = configuration_data()

if get_option('libdbus').disabled()
    libdbus_dep = dependency('', required: false)
else
    # Check for libdus availability. Optional, only required for MCTP dbus scan
    libdbus_dep = dependency(
	'dbus-1',
	required: true,
	fallback: ['dbus', 'libdbus_dep'],
	default_options: [
	    'default_library=static',
	    'embedded_tests=false',
	    'message_bus=false',
	    'modular_tests=disabled',
	    'tools=false',
	],
    )

    mctpd = get_option('mctpd').to_lower()

    if mctpd == ''
        mctpd = 'codeconstruct'
    endif

    valid = ['openbmc', 'codeconstruct']
    if not(valid.contains(mctpd))
        error('Invalid mctpd value: ' + mctpd)
    endif

    if mctpd == 'openbmc'
        conf.set_quoted('MCTP_DBUS_PATH', '/xyz/openbmc_project/mctp')
        conf.set_quoted('MCTP_DBUS_IFACE', 'xyz.openbmc_project.MCTP')
        conf.set_quoted('MCTP_DBUS_IFACE_ENDPOINT', 'xyz.openbmc_project.MCTP.Endpoint')
    else
        conf.set_quoted('MCTP_DBUS_PATH', '/au/com/codeconstruct/mctp1')
        conf.set_quoted('MCTP_DBUS_IFACE', 'au.com.codeconstruct.MCTP1')
        conf.set_quoted('MCTP_DBUS_IFACE_ENDPOINT', 'xyz.openbmc_project.MCTP.Endpoint')
    endif
endif

conf.set('CONFIG_DBUS', libdbus_dep.found(), description: 'Enable dbus support?')

conf.set10(
    'HAVE_TYPEOF',
    cc.compiles(
	'''int main(void) {
		int a = 1;
		typeof(a) b;
		b = a;
	   }
	''',
	name: 'typeof'
    ),
    description: 'Is typeof available?'
)
conf.set10(
    'HAVE_BYTESWAP_H',
    cc.compiles(
	'''#include <byteswap.h>''',
	name: 'byteswap.h'
    ),
    description: 'Is byteswap.h include-able?'
)
conf.set10(
    'HAVE_BSWAP_64',
    cc.links(
	'''#include <byteswap.h>
	    int main(void) {
		return bswap_64(0);
	    }
	''',
	name: 'bswap64'
    ),
    description: 'Is bswap_64 available?'
)
conf.set10(
    'HAVE_LITTLE_ENDIAN',
    host_machine.endian() == 'little',
    description: 'Building for little-endian'
)
conf.set10(
    'HAVE_BIG_ENDIAN',
    host_machine.endian() == 'big',
    description: 'Building for big-endian'
)
conf.set10(
    'HAVE_LINUX_MCTP_H',
    cc.compiles(
	'''#include <linux/mctp.h>''',
	name: 'linux/mctp.h'
    ),
    description: 'Is linux/mctp.h include-able?'
)
conf.set10(
    'HAVE_LINUX_CXL_MEM_H',
    cc.compiles(
	'''#include <linux/cxl_mem.h>''',
	name: 'linux/cxl_mem.h'
    ),
    description: 'Is linux/cxl_mem.h include-able?'
)
conf.set(
    'HAVE_GLIBC_IOCTL',
    cc.compiles(
	'''#include <sys/ioctl.h>
	int ioctl(int fd, unsigned long request, ...);
	''',
	name: 'ioctl has glibc-style prototype'
    ),
    description: 'Is ioctl the glibc interface (rather than POSIX)'
)

conf.set(
    'HAVE_GCC_DYN_OBJSZ',
    cc.compiles(
	'''#include <stdio.h>
	int main(void) { __builtin_dynamic_object_size(NULL, 0); }
	''',
	name: 'gcc has dynamic object size'
    ),
    description: 'GCC dynamic object size feature'
)

add_project_arguments(
    [
	'-fomit-frame-pointer',
	'-D_GNU_SOURCE',
    ],
    language : 'c',
)
inc = include_directories(['ccan', 'src', '.'])

################################################################################
config_h = configure_file(
    output: 'config.h',
    configuration: conf
)

config_dep = declare_dependency(
  include_directories : inc,
  sources: config_h)

config_h_path = meson.current_build_dir() / 'config.h'

add_project_arguments(
    [
	'-include', config_h_path,
    ],
    language : 'c',
)
################################################################################

subdir('ccan')
subdir('src')
subdir('examples')
if get_option('tests')
    subdir('tests')
endif

################################################################################
if meson.version().version_compare('>=0.53.0')
    path_dict = {
	'prefixdir':         prefixdir,
	'bindir':            bindir,
	'includedir':        includedir,
	'libdir':            libdir,
	'build location':    meson.current_build_dir(),
    }
    summary(path_dict, section: 'Paths')
    dep_dict = {
	'libdbus':           libdbus_dep.found(),
    }
    summary(dep_dict, section: 'Dependencies')
endif

mode = ['rw-r--r--', 0, 0]
install_headers('src/libcxlmi.h', install_mode: mode)
