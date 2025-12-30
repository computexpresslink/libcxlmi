#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <libcxlmi.h>

#define MiB (1024 * 1024)
#define MIN(a, b) ((a) < (b) ? (a) : (b))

const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
    0xbf, 0x41,
    0x4b, 0x78,
    0x8f, 0x79,
    0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
       0x11, 0xa9,
       0x40, 0x0c,
       0x81, 0x1f,
       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
    0x01, 0xb6,
    0x43, 0x32,
    0x94, 0x3e,
    0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };

const int maxlogs = 10; /* Only 7 in CXL r3.1, but let us leave room */

typedef enum CxlExtentSelectionPolicy {
    CXL_EXTENT_SELECTION_POLICY_FREE,
    CXL_EXTENT_SELECTION_POLICY_CONTIGUOUS,
    CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE,
    CXL_EXTENT_SELECTION_POLICY_ENABLE_SHARED_ACCESS,
    CXL_EXTENT_SELECTION_POLICY__MAX,
} CxlExtentSelectionPolicy;

typedef enum CxlExtentRemovalPolicy {
    CXL_EXTENT_REMOVAL_POLICY_TAG_BASED,
    CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE,
    CXL_EXTENT_REMOVAL_POLICY__MAX,
} CxlExtentRemovalPolicy;

typedef struct {
    uint64_t start_dpa;
    uint64_t len;
} extent;

typedef enum physical_port_control_opcode {
    ASSERT_PERST = 0x00,
    DEASSERT_PERST = 0x01,
    RESET_PPB = 0x02,
    MAX_PPC_OPCODE
} physical_port_control_opcode;

static int parse_supported_logs(struct cxlmi_cmd_get_supported_logs_rsp *pl,
				size_t *cel_size)
{
	int i, j;

	*cel_size = 0;
	printf("Get Supported Logs Response %d\n",
	       pl->num_supported_log_entries);

	for (i = 0; i < pl->num_supported_log_entries; i++) {
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != cel_uuid[j])
				break;
		}
		if (j == 0x10) {
			*cel_size = pl->entries[i].log_size;
			printf("\tCommand Effects Log (CEL) available\n");
		}
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != ven_dbg[j])
				break;
		}
		if (j == 0x10)
			printf("\tVendor Debug Log available\n");
		for (j = 0; j < sizeof(pl->entries[i].uuid); j++) {
			if (pl->entries[i].uuid[j] != c_s_dump[j])
				break;
		}
		if (j == 0x10)
			printf("\tComponent State Dump Log available\n");
	}
	if (*cel_size == 0) {
		return -1;
	}
	return 0;
}

static int support_opcode(struct cxlmi_endpoint *ep, int cel_size,
		uint16_t opcode, bool *supported)
{
	struct cxlmi_cmd_get_log_req in = {
		.offset = 0,
		.length = cel_size,
	};
	struct cxlmi_cmd_get_log_cel_rsp *ret;
	int i, rc;

	ret = calloc(1, sizeof(*ret) + cel_size);
	if (!ret)
		return -1;

	memcpy(in.uuid, cel_uuid, sizeof(in.uuid));
	rc = cxlmi_cmd_get_log_cel(ep, NULL, &in, ret);
	if (rc)
		goto done;

	for (i = 0; i < cel_size / sizeof(*ret); i++) {
		if (opcode == ret[i].opcode) {
			*supported = true;
			break;
		}
	}
done:
	free(ret);
	return rc;
}

static inline bool ep_supports_op(struct cxlmi_endpoint *ep, uint16_t opcode)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs_rsp *gsl;
	bool op_support = false;

	gsl = calloc(1, sizeof(*gsl) + maxlogs * sizeof(*gsl->entries));
	if (!gsl)
		return op_support;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc) {
		free(gsl);
		return op_support;
	}

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc) {
		free(gsl);
		return op_support;
	}

	/* we know there is a CEL */
	(void)support_opcode(ep, cel_size, opcode, &op_support);

	free(gsl);
	return op_support;
}
