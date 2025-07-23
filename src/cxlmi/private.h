// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#ifndef _LIBCXLMI_PRIVATE_H
#define _LIBCXLMI_PRIVATE_H

#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/types.h>

#include <linux/mctp.h>

#include <ccan/list/list.h>

#define CXLMI_EXPORT __attribute__ ((visibility("default")))

#define CXLMI_BUILD_BUG_ON_ZERO(e) ((int)(sizeof(struct { int:(-!!(e)); })))
#define CXLMI_BUILD_BUG_MSG(c, msg) _Static_assert(!(c), msg)
#define CXLMI_BUILD_BUG_ON(c) CXLMI_BUILD_BUG_MSG(c, "not expecting: " #c)

/*
 * When the size of an allocated object is needed, and sizeof()
 * is not an option, use the best available mechanism to find it.
 */
#ifdef HAVE_GCC_DYN_OBJSZ
#define __struct_size(p)	__builtin_dynamic_object_size(p, 0)
#define __member_size(p)	__builtin_dynamic_object_size(p, 1)
#else
#define __struct_size(p)	__builtin_object_size(p, 0)
#define __member_size(p)	__builtin_object_size(p, 1)
#endif

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)  CXLMI_BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

/*
 * This returns a constant expression while determining if an argument is
 * a constant expression, most importantly without evaluating the argument.
 * Glory to Martin Uecker <Martin.Uecker@med.uni-goettingen.de>
 */
#define __is_constexpr(x) \
	(sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0l)) : (int *)8)))

/*
 * flex_array_size() - Calculate size of a flexible array member
 *                     within an enclosing structure.
 * @p: Pointer to the structure.
 * @member: Name of the flexible array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of a flexible array of @count number of @member
 * elements, at the end of structure @p.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define flex_array_size(p, member, count)				\
	__builtin_choose_expr(__is_constexpr(count),			\
		(count) * sizeof(*(p)->member) + __must_be_array((p)->member),	\
		size_mul(count, sizeof(*(p)->member) + __must_be_array((p)->member)))


#define __must_check __attribute__((__warn_unused_result__))

/*
 * Allows for effectively applying __must_check to a macro so we can have
 * both the type-agnostic benefits of the macros while also being able to
 * enforce that the return value is, in fact, checked.
 */
static inline bool __must_check __must_check_overflow(bool overflow)
{
	return  __builtin_expect(!!(overflow), 0);
}

#define check_mul_overflow(a, b, d)				\
	__must_check_overflow(__builtin_mul_overflow(a, b, d))
/*
 * size_mul() - Calculate size_t multiplication with saturation at SIZE_MAX
 * @factor1: first factor
 * @factor2: second factor
 *
 * Returns: calculate @factor1 * @factor2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_mul(size_t factor1, size_t factor2)
{
	size_t bytes;

	if (check_mul_overflow(factor1, factor2, &bytes))
		return SIZE_MAX;

	return bytes;
}

#define check_add_overflow(a, b, d)	\
	__must_check_overflow(__builtin_add_overflow(a, b, d))
/*
 * size_add() - Calculate size_t addition with saturation at SIZE_MAX
 * @addend1: first addend
 * @addend2: second addend
 *
 * Returns: calculate @addend1 + @addend2, both promoted to size_t,
 * with any overflow causing the return value to be SIZE_MAX. The
 * lvalue must be size_t to avoid implicit type conversion.
 */
static inline size_t __must_check size_add(size_t addend1, size_t addend2)
{
	size_t bytes;

	if (check_add_overflow(addend1, addend2, &bytes))
		return SIZE_MAX;

	return bytes;
}

/*
 * struct_size() - Calculate size of structure with trailing flexible array.
 * @p: Pointer to the structure.
 * @member: Name of the array member.
 * @count: Number of elements in the array.
 *
 * Calculates size of memory needed for structure of @p followed by an
 * array of @count number of @member elements.
 *
 * Return: number of bytes needed or SIZE_MAX on overflow.
 */
#define struct_size(p, member, count)					\
	__builtin_choose_expr(__is_constexpr(count),			\
		sizeof(*(p)) + flex_array_size(p, member, count),	\
		size_add(sizeof(*(p)), flex_array_size(p, member, count)))


static inline void freep(void *p)
{
	free(*(void **)p);
}
#define _cleanup_free_ __attribute__((cleanup(freep)))

/*
 * pstrcpy:
 * @buf: buffer to copy string into
 * @buf_size: size of @buf in bytes
 * @str: string to copy
 *
 * Copy @str into @buf, including the trailing NUL, but do not
 * write more than @buf_size bytes. The resulting buffer is
 * always NUL terminated (even if the source string was too long).
 * If @buf_size is zero or negative then no bytes are copied.
 *
 * This function is similar to strncpy(), but avoids two of that
 * function's problems:
 *  * if @str fits in the buffer, pstrcpy() does not zero-fill the
 *    remaining space at the end of @buf
 *  * if @str is too long, pstrcpy() will copy the first @buf_size-1
 *    bytes and then add a NUL
 */
static inline void pstrcpy(char *buf, int buf_size, const char *str)
{
	int c;
	char *q = buf;

	if (buf_size <= 0)
		return;

	for(;;) {
		c = *str++;
		if (c == 0 || q >= buf + buf_size - 1)
			break;
		*q++ = c;
	}
	*q = '\0';
}

enum {
    INFOSTAT    = 0x00,
	#define IS_IDENTIFY                    0x1
	#define BACKGROUND_OPERATION_STATUS    0x2
	#define GET_RESP_MSG_LIMIT             003
	#define SET_RESP_MSG_LIMIT             0x4
	#define BACKGROUND_OPERATION_ABORT     0x5
    EVENTS      = 0x01,
	#define GET_RECORDS            0x0
	#define CLEAR_RECORDS          0x1
	#define GET_EVENT_IRQ_POL      0x2
	#define SET_EVENT_IRQ_POL      0x3
	#define GET_MCTP_EVENT_IRQ_POL 0x4
	#define SET_MCTP_EVENT_IRQ_POL 0x5
	#define NOTIFICATION           0x6
    FIRMWARE_UPDATE = 0x02,
	#define GET_INFO      0x0
	#define TRANSFER      0x1
	#define ACTIVATE      0x2
    TIMESTAMP   = 0x03,
	#define GET           0x0
	#define SET           0x1
    LOGS        = 0x04,
	#define GET_SUPPORTED 0x0
	#define GET_LOG       0x1
	#define GET_LOG_CAPS  0x2
	#define CLEAR_LOG     0x3
	#define POPULATE_LOG  0x4
	#define GET_SUPPORTED_SUBLIST  0x5
	FEATURES	= 0x05,
	#define GET_SUPPORTED_FEATURES 0x0
	#define GET_FEATURE 0x1
	#define SET_FEATURE 0x2
    IDENTIFY    = 0x40,
	#define MEMORY_DEVICE 0x0
    CCLS        = 0x41,
	#define GET_PARTITION_INFO     0x0
	#define SET_PARTITION_INFO     0x1
	#define GET_LSA                0x2
	#define SET_LSA                0x3
    HEALTH_INFO_ALERTS = 0x42,
	#define GET_HEALTH_INFO        0x0
	#define GET_ALERT_CONFIG       0x1
	#define SET_ALERT_CONFIG       0x2
	#define GET_SHUTDOWN_STATE     0x3
	#define SET_SHUTDOWN_STATE     0x4
    MEDIA_AND_POISON = 0x43,
	#define GET_POISON_LIST        0x0
	#define INJECT_POISON          0x1
	#define CLEAR_POISON           0x2
	#define GET_SCAN_MEDIA_CAPABILITIES 0x3
	#define SCAN_MEDIA             0x4
	#define GET_SCAN_MEDIA_RESULTS 0x5
    SANITIZE    = 0x44,
	#define SANITIZE      0x0
	#define SECURE_ERASE  0x1
	#define MEDIA_OPERATIONS 0x2
    PERSISTENT_MEM = 0x45,
	#define GET_SECURITY_STATE        0x0
	#define SET_PASSPHRASE            0x1
	#define DISABLE_PASSPHRASE        0x2
	#define UNLOCK                    0x3
	#define FREEZE_SECURITY_STATE     0x4
	#define PASSPHRASE_SECURE_ERASE   0x5
    SECURITY = 0x46,
	#define SECURITY_SEND           0x00
	#define SECURITY_RECEIVE        0x01
    SLD_QOS_TELEMETRY = 0x47,
	#define GET_SLD_QOS_CONTROL        0x0
	#define SET_SLD_QOS_CONTROL        0x1
	#define GET_SLD_QOS_STATUS         0x2
    DCD_CONFIG  = 0x48,
	#define GET_DC_CONFIG          0x0
	#define GET_DYN_CAP_EXT_LIST   0x1
	#define ADD_DYN_CAP_RSP        0x2
	#define RELEASE_DYN_CAP        0x3
    PHYSICAL_SWITCH = 0x51,
	#define IDENTIFY_SWITCH_DEVICE      0x0
	#define GET_PHYSICAL_PORT_STATE     0x1
	#define PHYSICAL_PORT_CONTROL       0x2
	#define SEND_PPB_CXLIO_CONFIG_REQ   0x3
	#define GET_DOMAIN_VALIDATION_SV_STATE     0x4
	#define SET_DOMAIN_VALIDATION_SV           0x5
	#define GET_VCS_DOMAIN_VALIDATION_SV_STATE 0x6
	#define GET_DOMAIN_VALIDATION_SV           0x7
	VIRTUAL_SWITCH = 0x52,
	#define BIND_VPPB     0x1
	#define UNBIND_VPPB   0x2
    MLD_PORT = 0x53,
	#define TUNNEL_MANAGEMENT_COMMAND     0x0
	#define SEND_LD_CXLIO_CONFIG_REQ      0x1
	#define SEND_LD_CXLIO_MEM_REQ         0x2
    MLD_COMPONENTS = 0x54,
	#define GET_LD_INFO            0x0
	#define GET_LD_ALLOCATIONS     0x1
	#define SET_LD_ALLOCATIONS     0x2
	#define GET_QOS_CONTROL        0x3
	#define SET_QOS_CONTROL        0x4
	#define GET_QOS_STATUS         0x5
	#define GET_QOS_ALLOCATED_BW   0x6
	#define SET_QOS_ALLOCATED_BW   0x7
	#define GET_QOS_BW_LIMIT       0x8
	#define SET_QOS_BW_LIMIT       0x9
    MHD = 0x55,
	#define GET_MHD_INFO 0x0
	#define GET_HEAD_INFO 0x1
    DCD_MANAGEMENT = 0x56,
	#define GET_DCD_INFO                0x0
	#define GET_HOST_DC_REGION_CONFIG   0x1
	#define SET_DC_REGION_CONFIG        0x2
	#define GET_DC_REGION_EXTENT_LIST   0x3
	#define INITIATE_DC_ADD             0x4
	#define INITIATE_DC_RELEASE         0x5
	#define DC_ADD_REFERENCE            0x6
	#define DC_REMOVE_REFERENCE         0x7
	#define DC_LIST_TAGS                0x8
};

struct cxlmi_ctx {
	FILE *fp;
	int log_level;

	bool log_timestamp;
	struct list_head endpoints; /* all opened endpoints */
	bool probe_enabled; /* probe upon open, default yes */
};

/*
 * Set a minimum time between receiving a response from one command and
 * sending the next request. Some devices may ignore new commands sent too soon
 * after the previous request, so manually insert a delay
 */
#define CXLMI_QUIRK_MIN_INTER_COMMAND_TIME	(1 << 0)

struct cxlmi_endpoint {
	struct cxlmi_ctx *ctx;

	/* mctp */
	void *transport_data;

	/* ioctl (primary mbox) */
	int fd;
	char *devname;

	bool has_fmapi;

	struct list_node entry;
	int timeout_ms;
	unsigned long quirks;

	/* inter-command delay, for CXLMI_QUIRK_MIN_INTER_COMMAND_TIME */
	unsigned int inter_command_us;
	struct timespec last_resp_time;
	bool last_resp_time_valid;
};

#if (LOG_FUNCNAME == 1)
#define __cxlmi_log_func __func__
#else
#define __cxlmi_log_func NULL
#endif

void __attribute__((format(printf, 4, 5)))
__cxlmi_msg(struct cxlmi_ctx *c, int lvl, const char *func, const char *format, ...);

#define cxlmi_msg(c, lvl, format, ...)					\
	do {								\
		if ((lvl) <= MAX_LOGLEVEL)				\
			__cxlmi_msg(c, lvl, __cxlmi_log_func,		\
				   format, ##__VA_ARGS__);		\
	} while (0)


/* for commands.c */
struct cxlmi_cci_msg;
struct cxlmi_tunnel_info;
void arm_cci_request(struct cxlmi_endpoint *ep, struct cxlmi_cci_msg *req,
		     size_t req_pl_sz, uint8_t cmdset, uint8_t cmd);
int send_cmd_cci(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti,
		 struct cxlmi_cci_msg *req_msg, size_t req_msg_sz,
		 struct cxlmi_cci_msg *rsp_msg, size_t rsp_msg_sz,
		 size_t rsp_msg_sz_min);

#endif /* _LIBCXLMI_PRIVATE_H */
