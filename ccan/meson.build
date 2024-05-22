# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxl.
#

sources = [
    'ccan/list/list.c',
    'ccan/str/debug.c',
    'ccan/str/str.c',
]

if get_option('buildtype') == 'debug'
    add_project_arguments('-DCCAN_LIST_DEBUG=1',  language : ['c', 'cpp'])
    add_project_arguments('-DCCAN_STR_DEBUG=1',  language : ['c', 'cpp'])
endif

libccan = static_library(
    'ccan',
    sources,
    install: false,
    include_directories: [inc],
)
