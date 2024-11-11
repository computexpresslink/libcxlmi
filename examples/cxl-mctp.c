// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <libcxlmi.h>

static int show_dc_extents(struct cxlmi_endpoint *ep);

static int show_memdev_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_memdev_identify id;

	rc = cxlmi_cmd_memdev_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("FW revision: %s\n", id.fw_revision);
	printf("total capacity: %ld Mb\n", 256 * id.total_capacity);
	printf("\tvolatile: %ld Mb\n", 256 * id.volatile_capacity);
	printf("\tpersistent: %ld Mb\n", 256 * id.persistent_capacity);
	printf("lsa size: %d bytes\n", id.lsa_size);
	printf("poison injection limit: %d\n", id.inject_poison_limit);
	printf("poison caps 0x%x\n", id.poison_caps);
	printf("DC event log size %d\n", id.dc_event_log_size);

       return 0;
}

static int show_switch_info(struct cxlmi_endpoint *ep)
{
	int rc, i;
	struct cxlmi_cmd_fmapi_identify_sw_device swid;

	rc = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &swid);
	if (rc)
		return rc;

	printf("Num tot vppb %d, Num Bound vPPB %d, Num HDM dec per USP %d\n",
	       swid.num_total_vppb, swid.num_active_vppb,
	       swid.num_hdm_decoder_per_usp);
	printf("\tPorts %d\n", swid.num_physical_ports);

	printf("\tActivePortMask ");
	for (i = 0; i < 32; i++)
		printf("%02x", swid.active_port_bitmask[i]);
	printf("\n");

	return 0;
}

static int show_device_info(struct cxlmi_endpoint *ep)
{
	int rc = 0;
	struct cxlmi_cmd_identify id;
	struct cxlmi_cmd_get_fw_info fw_info;

	rc = cxlmi_cmd_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

	switch (id.component_type) {
	case 0x00:
		printf("device type: CXL Switch\n");
		printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);

		show_switch_info(ep);
		break;
	case 0x03:
		printf("device type: CXL Type3 Device\n");
		printf("VID:%04x DID:%04x SubsysVID:%04x SubsysID:%04x\n",
		       id.vendor_id, id.device_id,
		       id.subsys_vendor_id, id.subsys_id);

		show_memdev_info(ep);
		break;
	case 0x04:
		printf("GFD not supported\n");
		/* fallthrough */
	default:
		break;
	}

	rc = cxlmi_cmd_get_fw_info(ep, NULL, &fw_info);
	if (rc)
		return rc;

	printf("Fimware info:\n");
	printf("\tslots supported: %d\n", fw_info.slots_supported);
	printf("\trevision: %s\n", fw_info.fw_rev1);

	return rc;
}


static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_bg_op_status sts;

	rc = cxlmi_cmd_bg_op_status(ep, NULL, &sts);
	if (rc)
		goto done;

	if (!(sts.status & (1 << 0))) {
		printf("no background operation in progress...\n");

		rc = cxlmi_cmd_memdev_sanitize(ep, NULL);
		if (rc && rc != CXLMI_RET_BACKGROUND) {
			printf("could not start sanitize: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
			goto done;
		} else {
			printf("sanitizing op started\n");
			sleep(1);
		}
	}

	rc = cxlmi_cmd_request_bg_op_abort(ep, NULL);
	if (rc) {
		if (rc > 0)
			printf("request_bg_operation_abort error: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
	} else
		printf("background operation abort requested\n");
done:
	return rc;
}

static int play_with_device_timestamp(struct cxlmi_endpoint *ep)
{
	int rc;
	uint64_t orig_ts;
	struct cxlmi_cmd_get_timestamp get_ts;
	struct cxlmi_cmd_set_timestamp set_ts = {
		.timestamp = 946684800, /* Jan 1, 2000 */
	};

	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("device timestamp: %lu\n", get_ts.timestamp);
	orig_ts = get_ts.timestamp;

	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	if (rc)
		return rc;

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("new device timestamp: %lu\n", get_ts.timestamp);

	memset(&set_ts, 0, sizeof(set_ts));
	set_ts.timestamp = orig_ts;
	rc = cxlmi_cmd_set_timestamp(ep, NULL, &set_ts);
	if (rc) {
		if (rc > 0)
			printf("set_timestamp error: %s\n",
			       cxlmi_cmd_retcode_tostr(rc));
		return rc;
	}

	memset(&get_ts, 0, sizeof(get_ts));
	rc = cxlmi_cmd_get_timestamp(ep, NULL, &get_ts);
	if (rc)
		return rc;
	printf("reset back to original device timestamp: %lu\n", get_ts.timestamp);

	return 0;
}

static int issue_dynamic_capacity_operation(struct cxlmi_endpoint *ep, bool add)
{
	struct cxlmi_cmd_memdev_add_dc_response *req;
	uint64_t dpa, len;
	int i = 0, rc = -1;

	req = calloc(1, sizeof(*req) + sizeof(req->extents[0]) * 2);
	if (!req)
		return -1;

	req->updated_extent_list_size = 2;
	req->flags = 0;
	dpa = 0;
	len = 16 * 1024 * 1024;
	for (i = 0; i < 2; i++) {
		req->extents[i].start_dpa = dpa;
		req->extents[i].len = len;
		dpa += len;
	}

	if (add) {
		printf("Send response to device for accepting %d extents\n",
				req->updated_extent_list_size);
		rc = cxlmi_cmd_memdev_add_dc_response(ep, NULL, req);
	} else {
		struct cxlmi_cmd_memdev_release_dc *in;
		in = (struct cxlmi_cmd_memdev_release_dc *)req;
		printf("Notify device to release %d extents\n",
				req->updated_extent_list_size);
		rc = cxlmi_cmd_memdev_release_dc(ep, NULL, in);
	}

    free(req);
	return rc;
}

static int play_with_dcd(struct cxlmi_endpoint *ep)
{
	int i, rc;
	struct cxlmi_cmd_memdev_get_dc_config_req req = {
		.region_cnt = 8,
		.start_region_id = 0,
	};
	struct cxlmi_cmd_memdev_get_dc_config_rsp *out;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -1;

	rc = cxlmi_cmd_memdev_get_dc_config(ep, NULL, &req, out);
	if (rc) {
		rc = -1;
		goto free_out;
	}

	printf("Print out get DC config response: \n");
	printf("# of regions: %d\n", out->num_regions);
	printf("# of regions returned: %d\n", out->regions_returned);

	for (i = 0; i < out->regions_returned; i++) {
		printf("region %d: base %lu decode_len %lu region_len %lu block_size %lu\n",
				req.start_region_id + i,
				out->region_configs[i].base,
				out->region_configs[i].decode_len,
				out->region_configs[i].region_len,
				out->region_configs[i].block_size);
	}

	printf("# of extents supported: %d\n", out->num_extents_supported);
	printf("# of extents available: %d\n", out->num_extents_available);
	printf("# of tags supported: %d\n", out->num_tags_supported);
	printf("# of tags available: %d\n", out->num_tags_available);

	printf("Print out get DC config response: done\n");
	rc = 0;

	if (out->num_regions) {
		rc = show_dc_extents(ep);
		if (rc)
			goto free_out;
		rc = issue_dynamic_capacity_operation(ep, true);
		if (rc)
			goto free_out;
		rc = show_dc_extents(ep);
		if (rc)
			goto free_out;
		rc = issue_dynamic_capacity_operation(ep, false);
		if (rc)
			goto free_out;
		rc = show_dc_extents(ep);
	}

free_out:
	free(out);

	return rc;
}

static int show_dc_extents(struct cxlmi_endpoint *ep)
{
	int i, rc;
	uint64_t total_cnt, extent_returned = 0;
	bool first = true;

	struct cxlmi_cmd_memdev_get_dc_extent_list_req req = {
		.extent_cnt = 0,
		.start_extent_idx = 0,
	};
	struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *out;

	out = calloc(1, sizeof(*out) + sizeof(out->extents[0]) * 8);
	if (!out)
		return -1;

	do {
		printf("Try to read %d extents starting with id: %d\n",
				req.extent_cnt, req.start_extent_idx);
		rc = cxlmi_cmd_memdev_get_dc_extent_list(ep, NULL, &req, out);
		if (rc)
			goto free_out;

		if (first) {
			total_cnt = out->total_num_extents;

			printf("# of total extents: %d\n", out->total_num_extents);
			printf("generation number: %d\n", out->generation_num);
			first = false;
		}

		printf("# of extents returned: %u\n", out->num_extents_returned);
		for (i = 0; i < out->num_extents_returned; i++) {
			printf("extent[%u] : [%lx, %lx]\n", i + req.start_extent_idx,
					out->extents[i].start_dpa,
					out->extents[i].len);
		}

		extent_returned += out->num_extents_returned;
		req.start_extent_idx = extent_returned;
		req.extent_cnt = total_cnt - extent_returned;
	} while (extent_returned < total_cnt);

free_out:
	free(out);

	return rc;
}

static const uint8_t cel_uuid[0x10] = { 0x0d, 0xa9, 0xc0, 0xb5,
					0xbf, 0x41,
					0x4b, 0x78,
					0x8f, 0x79,
					0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17 };

static const uint8_t ven_dbg[0x10] = { 0x5e, 0x18, 0x19, 0xd9,
				       0x11, 0xa9,
				       0x40, 0x0c,
				       0x81, 0x1f,
				       0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86 };

static const uint8_t c_s_dump[0x10] = { 0xb3, 0xfa, 0xb4, 0xcf,
					0x01, 0xb6,
					0x43, 0x32,
					0x94, 0x3e,
					0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67 };

static const int maxlogs = 10; /* Only 7 in CXL r3.1, but let us leave room */
static int parse_supported_logs(struct cxlmi_cmd_get_supported_logs *pl,
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
	if (cel_size == 0) {
		return -1;
	}
	return 0;
}

static int show_cel(struct cxlmi_endpoint *ep, int cel_size)
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
		printf("\t[%04x] %s%s%s%s%s%s%s%s\n",
		       ret[i].opcode,
		       ret[i].command_effect & 0x1 ? "ColdReset " : "",
		       ret[i].command_effect & 0x2 ? "ImConf " : "",
		       ret[i].command_effect & 0x4 ? "ImData " : "",
		       ret[i].command_effect & 0x8 ? "ImPol " : "",
		       ret[i].command_effect & 0x10 ? "ImLog " : "",
		       ret[i].command_effect & 0x20 ? "ImSec" : "",
		       ret[i].command_effect & 0x40 ? "BgOp" : "",
		       ret[i].command_effect & 0x80 ? "SecSup" : "");
	}
done:
	free(ret);
	return rc;
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

static bool ep_supports_op(struct cxlmi_endpoint *ep, uint16_t opcode)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs *gsl;
	bool op_support = false;

	gsl = calloc(1, sizeof(*gsl) + maxlogs * sizeof(*gsl->entries));
	if (!gsl)
		return op_support;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc)
		return op_support;

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc)
		return op_support;
	else {
		/* we know there is a CEL */
		rc = support_opcode(ep, cel_size, opcode, &op_support);
	}

	free(gsl);
	return op_support;
}

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs *gsl;

	gsl = calloc(1, sizeof(*gsl) + maxlogs * sizeof(*gsl->entries));
	if (!gsl)
		return -1;

	rc = cxlmi_cmd_get_supported_logs(ep, NULL, gsl);
	if (rc)
		return rc;

	rc = parse_supported_logs(gsl, &cel_size);
	if (rc)
		return rc;
	else {
		/* we know there is a CEL */
		rc = show_cel(ep, cel_size);
	}

	free(gsl);
	return rc;
}

static int play_with_poison_mgmt(struct cxlmi_endpoint *ep)
{
	const int num_poisons = 3;
	int i, rc[num_poisons];
	struct cxlmi_cmd_memdev_inject_poison inject_poison[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_req get_poison_list_req[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_rsp get_poison_list_rsp[num_poisons];
	struct cxlmi_cmd_memdev_clear_poison clear_poison[num_poisons];
	uint64_t phy_addr[num_poisons];
	uint64_t phy_start_addr = 0x00001000;

	for (i = 0; i < num_poisons; i++){
		phy_addr[i] = phy_start_addr;
		phy_start_addr += 0x100;
	}

	for (i = 0; i < num_poisons; i++) {
		int j;

		inject_poison[i].inject_poison_phy_addr = phy_addr[i];
		get_poison_list_req[i].get_poison_list_phy_addr = phy_addr[i];
		get_poison_list_req[i].get_poison_list_phy_addr_len = 64;
		clear_poison[i].clear_poison_phy_addr = phy_addr[i];
		for (j = 0; j < 64; j++) {
			clear_poison[i].clear_poison_write_data[j] = 0;
		}
	}

	for (i = 0; i < num_poisons; i++) {
		rc[i] = cxlmi_cmd_memdev_inject_poison(ep, NULL,
						       &inject_poison[i]);
		if (rc[i])
			return rc[i];
		else {
			printf("Inject poison physical address - %d - %ld\n",
			       i, inject_poison[i].inject_poison_phy_addr);
		}

		memset(&get_poison_list_rsp[i], 0, sizeof(get_poison_list_rsp[i]));
		rc[i] = cxlmi_cmd_get_poison_list(ep, NULL, &get_poison_list_req[i],
						  &get_poison_list_rsp[i]);
		if (rc[i])
			return rc[i];
		else {
			printf("Get poison list flags - %d\n",
			       get_poison_list_rsp[i].poison_list_flags);
			printf("Get poison list overflow timestamp - %ld\n",
			       get_poison_list_rsp[i].overflow_timestamp);
			printf("Get poison list more media err count - %d\n",
			       get_poison_list_rsp[i].more_err_media_record_cnt);
			printf("Get poison list media err records err address - %ld\n",
			       get_poison_list_rsp[i].records[0].media_err_addr);
			printf("Get poison list media err records err length - %d\n",
			       get_poison_list_rsp[i].records[0].media_err_len);
		}

		rc[i] = cxlmi_cmd_memdev_clear_poison(ep, NULL, &clear_poison[i]);
		if (rc[i])
			return rc[i];
	}

	printf("Poison mgmt commands executed successfully\n");

	return 0;
}

int main(int argc, char **argv)
{
	struct cxlmi_ctx *ctx;
	struct cxlmi_endpoint *ep, *tmp;
	int rc = EXIT_FAILURE;

	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		goto exit;
	}

	if (argc == 1) {
		int num_ep = cxlmi_scan_mctp(ctx);

		printf("scanning dbus...\n");

		if (num_ep < 0) {
			fprintf(stderr, "dbus scan error\n");
			goto exit_free_ctx;
		} else if (num_ep == 0) {
			printf("no endpoints found\n");
		} else
			printf("found %d endpoint(s)\n", num_ep);
	} else if (argc == 3) {
		unsigned int nid;
		uint8_t eid;

		nid = atoi(argv[1]);
		eid = atoi(argv[2]);
		printf("ep %d:%d\n", nid, eid);

		ep = cxlmi_open_mctp(ctx, nid, eid);
		if (!ep) {
			fprintf(stderr, "cannot open MCTP endpoint %d:%d\n", nid, eid);
			goto exit_free_ctx;
		}
	} else {
		fprintf(stderr, "must provide MCTP endpoint nid:eid touple\n");
		goto exit_free_ctx;
	}

	cxlmi_for_each_endpoint_safe(ctx, ep, tmp) {
		rc = show_device_info(ep);

		rc = play_with_device_timestamp(ep);

		rc = get_device_logs(ep);

		rc = play_with_poison_mgmt(ep);

		rc = toggle_abort(ep);

		if (ep_supports_op(ep, 0x4800))
			play_with_dcd(ep);

		cxlmi_close(ep);
	}

exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
