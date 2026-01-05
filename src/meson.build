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

subdir('python')