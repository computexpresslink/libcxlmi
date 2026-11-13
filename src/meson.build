# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
deps = [ libdbus_dep ]

sources = [
	'cxlmi/log.c',
	'cxlmi/commands.c',
	'cxlmi/cxlmi.c',
	'cxlmi/mock.c'
]

cxlmi = library('cxlmi', # defaults to shared lib
		sources,
		include_directories : inc,
		dependencies : deps,
		install : true,
		link_with: libccan)

libcxlmi_dep = declare_dependency(
    include_directories: ['.'],
    link_with: cxlmi,
)

# For projects that use libcxlmi as a meson subproject: let them find it
# with dependency('libcxlmi'). The headers are given as system headers,
# as they are when installed, so that the warning flags of the parent
# project do not apply to them: C++ built with -Wpedantic rejects the
# flexible array members of the payload structures.
meson.override_dependency('libcxlmi', libcxlmi_dep.as_system('system'))

subdir('python')