# SPDX-License-Identifier: LGPL-2.1-or-later
#
# This file is part of libcxlmi.
#
NAME          := libcxlmi
.DEFAULT_GOAL := ${NAME}
BUILD-DIR     := .build

${BUILD-DIR}:
	meson setup $@
	@echo "Configuration located in: $@"
	@echo "-------------------------------------------------------"

.PHONY: ${NAME}
${NAME}: ${BUILD-DIR}
	meson compile -C ${BUILD-DIR}

.PHONY: clean
clean:
ifneq ("$(wildcard ${BUILD-DIR})","")
	meson compile --clean -C ${BUILD-DIR}
endif

.PHONY: purge
purge:
ifneq ("$(wildcard ${BUILD-DIR})","")
	rm -rf ${BUILD-DIR}
endif

.PHONY: install
install: ${NAME}
	meson install -C ${BUILD-DIR} --skip-subprojects

.PHONY: uninstall
uninstall:
	cd ${BUILD-DIR} && meson --internal uninstall
