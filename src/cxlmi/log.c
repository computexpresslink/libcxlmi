// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 *
 * Authors: Hannes Reinecke <hare@suse.de>
 *
 * This file implements basic logging functionality.
 */
#include <sys/types.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#define LOG_FUNCNAME 1
#include "private.h"
#include "log.h"

#ifndef LOG_CLOCK
#define LOG_CLOCK CLOCK_MONOTONIC
#endif

void __attribute__((format(printf, 4, 5)))
__cxlmi_msg(struct cxlmi_ctx *c, int lvl,
	   const char *func, const char *format, ...)
{
	FILE *fp = stderr;
	va_list ap;
	char pidbuf[16];
	char timebuf[32];
	static const char *const formats[] = {
		"%s%s%s",
		"%s%s%s: ",
		"%s<%s>%s ",
		"%s<%s> %s: ",
		"[%s] %s%s ",
		"[%s]%s %s: ",
		"[%s] <%s>%s ",
		"[%s] <%s> %s: ",
	};
	_cleanup_free_ char *header = NULL;
	_cleanup_free_ char *message = NULL;
	int idx = 0;

	if (c)
		fp = c->fp;

	if (c && lvl > c->log_level)
		return;
	if (!c && lvl > DEFAULT_LOGLEVEL)
		return;

	if (c && c->log_timestamp) {
		struct timespec now;

		clock_gettime(LOG_CLOCK, &now);
		snprintf(timebuf, sizeof(timebuf), "%6ld.%06ld",
			 (long)now.tv_sec, now.tv_nsec / 1000);
		idx |= 1 << 2;
	} else
		*timebuf = '\0';

	*pidbuf = '\0';

	if (func)
		idx |= 1 << 0;

	if (asprintf(&header, formats[idx],
		     timebuf, pidbuf, func ? func : "") == -1)
		header = NULL;

	va_start(ap, format);
	if (vasprintf(&message, format, ap) == -1)
		message = NULL;
	va_end(ap);

	fprintf(fp, "libcxlmi: %s%s",
		header ? header : "<error>",
		message ? message : "<error>");
}
