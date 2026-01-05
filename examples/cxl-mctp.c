// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <libcxlmi.h>
#include "examples.h"

static int show_dc_extents(struct cxlmi_endpoint *ep);

static int show_memdev_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_memdev_identify_rsp id;

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
#ifndef SUPPORT_CXL_2_0
	printf("DC event log size %d\n", id.dc_event_log_size);
#endif

       return 0;
}

static int show_switch_info(struct cxlmi_endpoint *ep)
{
	int rc, i;
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp swid;

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

static int get_physical_port_state(struct cxlmi_endpoint *ep)
{
	int rc, rc_p;
	int port_index = 0;
	uint8_t port_number = 0;
	struct cxlmi_cmd_fmapi_get_phys_port_state_req *req_pps;
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp swid;
	struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *rsp_pps;

	rc_p = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &swid);
	if (rc_p)
		return rc_p;

	req_pps = calloc(1, sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_req) +
				   swid.num_physical_ports * sizeof(uint8_t));

	req_pps->num_ports = swid.num_physical_ports;
	for (int byte_index = 0; byte_index < 32; byte_index++) {
		unsigned char byte = swid.active_port_bitmask[byte_index];
		for (int bit_index = 0; bit_index < 8; bit_index++, port_number++) {
			if (((byte) & (1 << bit_index)) != 0) {
				req_pps->ports[port_index] = port_number;
				port_index++;
			}
		}
	}

	rsp_pps = calloc(1, sizeof(struct cxlmi_cmd_fmapi_get_phys_port_state_rsp) +
				   req_pps->num_ports * sizeof(struct cxlmi_cmd_fmapi_port_state_info_block));

	rc = cxlmi_cmd_fmapi_get_phys_port_state(ep, NULL, req_pps, rsp_pps);
	if (rc)
		goto done;

	printf("Port_Info:\n");
	for (int k = 0; k < rsp_pps->num_ports; k++) {
		printf("\tPort_id: %d\n", rsp_pps->ports[k].port_id);
		printf("\tPort_config_state: %d\n", rsp_pps->ports[k].config_state);
		printf("\tConnected_device_mode: %d\n", rsp_pps->ports[k].conn_dev_cxl_ver);
		printf("\tConnected_device_type: %d\n", rsp_pps->ports[k].conn_dev_type);
		printf("\tPort_cxl_version_bitmask: %d\n", rsp_pps->ports[k].port_cxl_ver_bitmask);
		printf("\tMax_link_width: %d\n", rsp_pps->ports[k].max_link_width);
		printf("\tNegotiated_link_width: %d\n", rsp_pps->ports[k].negotiated_link_width);
		printf("\tSupported_link_speeds_vector: %d\n", rsp_pps->ports[k].supported_link_speeds_vector);
		printf("\tMax_link_speed: %d\n", rsp_pps->ports[k].max_link_speed);
		printf("\tCurrent_link_speed: %d\n", rsp_pps->ports[k].current_link_speed);
		printf("\tLTSSM_state: %d\n", rsp_pps->ports[k].ltssm_state);
		printf("\tFirst_lane_num: %d\n", rsp_pps->ports[k].first_lane_num);
		printf("\tLink_state: %d\n", rsp_pps->ports[k].link_state);
		printf("\tSupported_ld_count: %d\n\n", rsp_pps->ports[k].supported_ld_count);
	}
done:
	free(req_pps);
	free(rsp_pps);
	return rc;
}

static int physical_port_control(struct cxlmi_endpoint *ep)
{
	int rc, rc_p;
	uint8_t port_number = 0;
	struct cxlmi_cmd_fmapi_phys_port_control_req *ppc;
	struct cxlmi_cmd_fmapi_identify_sw_device_rsp swid;

	rc_p = cxlmi_cmd_fmapi_identify_sw_device(ep, NULL, &swid);
	if (rc_p)
		return rc_p;

	ppc = calloc(1, sizeof(struct cxlmi_cmd_fmapi_phys_port_control_req));
	for (int byte_index = 0; byte_index < 32; byte_index++) {
		unsigned char byte = swid.active_port_bitmask[byte_index];
		for (int bit_index = 0; bit_index < 8; bit_index++, port_number++) {
			if (((byte) & (1 << bit_index)) != 0) {
				ppc->ppb_id = port_number;
				for (int op = ASSERT_PERST; op < MAX_PPC_OPCODE; op++) {
					ppc->port_opcode = op;
					rc = cxlmi_cmd_fmapi_phys_port_control(ep, NULL, ppc);
					if (rc)
						return rc;
					printf("request for port:%d and opcode:%d sent successfully\n",port_number,op);
				}
			}
		}
	}
	free(ppc);
	return 0;
}

static int show_device_info(struct cxlmi_endpoint *ep)
{
	int rc = 0;
	struct cxlmi_cmd_identify_rsp id;
	struct cxlmi_cmd_get_fw_info_rsp fw_info;

	rc = cxlmi_cmd_identify(ep, NULL, &id);
	if (rc)
		return rc;

	printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

	switch (id.component_type) {
	case 0x00:
		printf("device type: CXL Switch\n");
		printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);

		show_switch_info(ep);
		get_physical_port_state(ep);
		physical_port_control(ep);
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

	printf("Firmware info:\n");
	printf("\tslots supported: %d\n", fw_info.slots_supported);
	printf("\trevision: %s\n", fw_info.fw_rev1);

	return rc;
}


static int toggle_abort(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_bg_op_status_rsp sts;

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
	struct cxlmi_cmd_get_timestamp_rsp get_ts;
	struct cxlmi_cmd_set_timestamp_req set_ts = {
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
	struct cxlmi_cmd_memdev_add_dc_response_req *req;
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
		struct cxlmi_cmd_memdev_release_dc_req *in;
		in = (struct cxlmi_cmd_memdev_release_dc_req *)req;
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

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs_rsp *gsl;

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
	struct cxlmi_cmd_memdev_inject_poison_req inject_poison[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_req get_poison_list_req[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_rsp get_poison_list_rsp[num_poisons];
	struct cxlmi_cmd_memdev_clear_poison_req clear_poison[num_poisons];
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

static int test_fmapi_get_dcd_info(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_fmapi_get_dcd_info_rsp *out;

	out = calloc(1, sizeof(*out));
	if (!out)
		return -1;

	rc = cxlmi_cmd_fmapi_get_dcd_info(ep, NULL, out);
	if (rc) {
		rc = -1;
		goto free_out;
	}

	printf("0x5600: FMAPI Get DCD Info Response:\n");
	printf("\t# hosts supported: %hhu\n", out->num_hosts);
	printf("\t# dc regions available/host: %hhu\n", out->num_supported_dc_regions);
	printf("\tcapacity_selection_policies: %hu\n", out->capacity_selection_policies);
	printf("\tcapacity_removal_policies: %hu\n", out->capacity_removal_policies);
	printf("\tsanitize_on_release: %hhu\n", out->sanitize_on_release_config_mask);
	printf("\ttotal dynamic capacity: %lu\n", out->total_dynamic_capacity);
	printf("\tregion 0 supported block sizes: %lu\n",
		out->region_0_supported_blk_sz_mask);
	printf("\tregion 1 supported block sizes: %lu\n",
		out->region_1_supported_blk_sz_mask);

free_out:
	free(out);
	return rc;
}

static int test_fmapi_get_host_dc_region_config(struct cxlmi_endpoint *ep)
{
	int i, rc;
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_req dc_region_config_req = {
		.host_id = 0,
		.region_cnt = 5,
		.start_region_id = 0,
	};
	struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp *dc_region_config_rsp;

	printf("0x5601: FMAPI Get DC Region Config Response:\n");
	dc_region_config_rsp = calloc(1, sizeof(*dc_region_config_rsp));

	if (!dc_region_config_rsp) {
		return -1;
	}

	rc = cxlmi_cmd_fmapi_get_dc_reg_config(ep, NULL, &dc_region_config_req, dc_region_config_rsp);
	if (rc) {
		rc = -1;
		goto free_out;
	}
	printf("\thost id: %hu\n", dc_region_config_rsp->host_id);
	printf("\tnum available regions: %hhu\n", dc_region_config_rsp->num_regions);
	printf("\tnum regions returned: %hhu\n", dc_region_config_rsp->regions_returned);
	printf("\tnum_extents_supported: %u\n", dc_region_config_rsp->num_extents_supported);
	printf("\tnum_extents_available: %u\n", dc_region_config_rsp->num_extents_available);
	printf("\tnum_tags_supported: %u\n", dc_region_config_rsp->num_tags_supported);

	for (i = 0; i < dc_region_config_rsp->regions_returned; i++) {
		printf("\t\tRegion %d:\n", i);
		printf("\t\t\tBase: %lu\n", dc_region_config_rsp->region_configs[i].base);
		printf("\t\t\tBlk_sz: %lu\n", dc_region_config_rsp->region_configs[i].block_size);
		printf("\t\t\tLen: %lu\n", dc_region_config_rsp->region_configs[i].region_len);
		printf("\t\t\tDecode_len: %lu\n", dc_region_config_rsp->region_configs[i].decode_len);
		printf("\t\t\tFlags: %hhu\n", dc_region_config_rsp->region_configs[i].flags);
	}

free_out:
	free(dc_region_config_rsp);
	return rc;
}

static int test_fmapi_set_dc_region_config(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_set_dc_region_config_req req = {
		.region_id = 0,
		.block_sz = 128 * MiB,
		.sanitize_on_release = 0,
	};

	printf("0x5602: FMAPI Set DC Region Config\n");

	if (cxlmi_cmd_fmapi_set_dc_region_config(ep, NULL, &req)) {
		return -1;
	}

	printf("FMAPI Set DC Region Config Success\n");

	return 0;

}

static int print_ext_list(struct cxlmi_endpoint *ep,
                          uint16_t host_id,
                          uint32_t ext_cnt,
                          uint32_t start_ext_ind)
{
    struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req;
    struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
    int i, rc, exts_returned = 0;
    bool first = true;

    req.host_id = host_id;
    req.extent_count = ext_cnt;
    req.start_ext_index = start_ext_ind;

    rsp = calloc(1, sizeof(*rsp) + req.extent_count * sizeof(rsp->extents[0]));

    if (!rsp) {
        return -1;
    }

    do {
        rc = cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, NULL, &req, rsp);
        if (rc) {
            rc = -1;
            goto free_out;
        }

        if (first) {
            ext_cnt = MIN(ext_cnt, rsp->total_extents);
            printf("\tHost Id: %hu\n", rsp->host_id);
            printf("\tStarting Extent Index: %u\n", rsp->start_ext_index);
            printf("\tNumber of Extents Returned: %u\n", rsp->extents_returned);
            printf("\tTotal Extents: %u\n", rsp->total_extents);
            printf("\tExtent List Generation Number: %u\n", rsp->list_generation_num);

            first = false;
        }

        for (i = 0; i < rsp->extents_returned; i++) {
            printf("\t\tExtent %d Info:\n", rsp->start_ext_index + i);
            printf("\t\t\tStart DPA: %lu\n", rsp->extents[i].start_dpa);
            printf("\t\t\tLength: %lu\n", rsp->extents[i].len);
        }

        exts_returned += rsp->extents_returned;
        req.start_ext_index += rsp->extents_returned;;
        req.extent_count -= rsp->extents_returned;;
    } while (exts_returned < ext_cnt);

free_out:
	free(rsp);
	return rc;
}

static int test_fmapi_get_dc_region_extent_list(struct cxlmi_endpoint *ep)
{
	printf("0x5603: FMAPI Get DC Region Extent List\n");
	return print_ext_list(ep, 0, 2, 0);
}

/* Returns number of dc extents or -1 if error */
static int get_num_dc_extents(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req req = {
		.host_id = 0,
		.extent_count = 0,
		.start_ext_index = 0
	};
	struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *rsp;
	int rc;

	rsp = calloc(1, sizeof(*rsp));
	if (!rsp) {
		return -1;
	}

	if (cxlmi_cmd_fmapi_get_dc_region_ext_list(ep, NULL, &req, rsp)) {
		rc = -1;
		goto free_out;
	}

	rc = rsp->total_extents;

free_out:
	free(rsp);
	return rc;
}

static int test_fmapi_initiate_dc_add_and_release(struct cxlmi_endpoint *ep)
{
	int rc, curr_num_extents;
	struct cxlmi_cmd_fmapi_initiate_dc_add_req* add_req = NULL;
	struct cxlmi_cmd_fmapi_initiate_dc_release_req* rls_req = NULL;

	printf("0x5604/0x5605: FMAPI Initiate DC Add/Release\n");
	add_req = calloc(1, sizeof(*add_req) + 1 * sizeof(add_req->extents[0]));
	if (!add_req) {
		return -1;
	}

	add_req->host_id = 0;
	add_req->selection_policy = CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE;
	add_req->length = 0;
	add_req->ext_count = 1;

	add_req->extents[0].start_dpa = 0;
	add_req->extents[0].len = 128 * MiB;

	printf("Sending Request to add 1 extent\n");
	rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, NULL, add_req);
	if (rc) {
		rc = -1;
		goto cleanup;
	}

	/* Loop until device/host finish processing. Number of extents should be 1 */
	while ((curr_num_extents = get_num_dc_extents(ep)) == 0);
	if (curr_num_extents != 1) {
		rc = -1;
		goto cleanup;
	}
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	rls_req = calloc(1, sizeof(*rls_req) + 2 * sizeof(rls_req->extents[0]));
	if (!rls_req) {
		rc = -1;
		goto cleanup;
	}

	printf("Attempt to release extent not backed by DPA\n");
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 128 * MiB;
	rls_req->extents[0].len = 256 * MiB;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 15 (CXL_MBOX_INVALID_PA) */
	if (!rc) {
		printf("\tWas able to release nonexistent extent!\n");
		rc = -1;
		goto cleanup;
	}

	printf("Attempt to release misaligned extent\n");
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 56 * MiB;
	rls_req->extents[0].len = 7 * MiB;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 30 (CXL_MBOX_INVALID_EXTENT_LIST) */
	if (!rc) {
		printf("\tWas able to release misaligned extent!\n");
		rc = -1;
		goto cleanup;
	}

	printf("Attempt to release overlapping extents\n");
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 2;
	rls_req->extents[0].start_dpa = 0;
	rls_req->extents[0].len = 128 * MiB;
	rls_req->extents[1].start_dpa = 56 * MiB;
	rls_req->extents[1].len = 184 * MiB;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* RC should be 30 (CXL_MBOX_INVALID_EXTENT_LIST) */
	if (!rc) {
		printf("\tWas able to release overlapping extents!\n");
		rc = -1;
		goto cleanup;
	}

	/* Should still have the same extent previously added from testing initiate add */
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	printf("Release extent\n");
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 0;
	rls_req->extents[0].len = 128 * MiB;

	(void)cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	/* Extent list should be empty */
	while ((curr_num_extents = get_num_dc_extents(ep)) == 1);
	if (curr_num_extents != 0) {
		rc = -1;
		goto cleanup;
	}
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	/*
	 * Add one extent (3 blocks long) and release the middle block
	 * Ext_0 = {[0 - 127] [128 - 255] [256 - 384]}
	 */
	printf("Add an extent that is 3 blocks long\n");
	add_req->host_id = 0;
	add_req->selection_policy = CXL_EXTENT_SELECTION_POLICY_PRESCRIPTIVE;
	add_req->length = 0;
	add_req->ext_count = 1;
	add_req->extents[0].start_dpa = 0;
	add_req->extents[0].len = 384 * MiB;

	rc = cxlmi_cmd_fmapi_initiate_dc_add(ep, NULL, add_req);
	if (rc) {
		rc = -1;
		goto cleanup;
	}

	/* Should have 1 extent [0 - 384]*/
	while ((curr_num_extents = get_num_dc_extents(ep)) == 0);
	if (curr_num_extents != 1) {
		rc = -1;
		goto cleanup;
	}
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	printf("Sending release req for middle block. Should clear entire extent\n");
	rls_req->host_id = 0;
	rls_req->flags = CXL_EXTENT_REMOVAL_POLICY_PRESCRIPTIVE;
	rls_req->length = 0;
	rls_req->ext_count = 1;
	rls_req->extents[0].start_dpa = 128 * MiB;
	rls_req->extents[0].len = 128 * MiB;

	rc = cxlmi_cmd_fmapi_initiate_dc_release(ep, NULL, rls_req);

	if (rc) {
		rc = -1;
		goto cleanup;
	}

	/* Entire should have been released. We should now have 0 extents. */
	while ((curr_num_extents = get_num_dc_extents(ep)) == 1);
	if (curr_num_extents != 0) {
		rc = -1;
		goto cleanup;
	}
	printf("Show Extents --\n");
	if (print_ext_list(ep, 0, 2, 0)) {
		rc = -1;
		goto cleanup;
	}

	printf("FMAPI Initiate DC Add/Release Success\n");

cleanup:
	free(add_req);
	if (rls_req) {
		free(rls_req);
	}
	return rc;
}

static int test_fmapi_dc_add_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_add_ref_req req = {
		.tag = {0}
	};

	printf("0x5606: FMAPI DC Add Reference\n");
	if (cxlmi_cmd_fmapi_dc_add_reference(ep, NULL, &req)) {
		printf("FMAPI DC Add Reference Error\n");
		return -1;
	}

	printf("FMAPI DC Add Reference Success\n");
	return 0;
}

static int test_fmapi_dc_remove_reference(struct cxlmi_endpoint *ep)
{
	struct cxlmi_cmd_fmapi_dc_remove_ref_req req = {
		.tag = {0}
	};

	printf("0x5607: FMAPI DC Remove Reference\n");
	if (cxlmi_cmd_fmapi_dc_remove_reference(ep, NULL, &req)) {
		printf("FMAPI DC Remove Reference Error\n");
		return -1;
	}

	printf("FMAPI DC Remove Reference Success\n");
	return 0;
}

static int test_fmapi_dc_list_tags(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_fmapi_dc_list_tags_req req = {
		.start_idx = 0,
		.tags_count = 2
	};
	struct cxlmi_cmd_fmapi_dc_list_tags_rsp * rsp =
			calloc(1, sizeof(*rsp) + sizeof(rsp->tags_list[0]));

	if (!rsp) {
		return -1;
	}

	printf("0x5608: FMAPI DC List Tags\n");
	rc = cxlmi_cmd_fmapi_dc_list_tags(ep, NULL, &req, rsp);
	if (rc) {
		rc = -1;
		goto cleanup;
	}

	printf("\t Generation Num: %u\n", rsp->generation_num);
	printf("\t Max Tags: %u\n", rsp->total_num_tags);
	printf("\t Num Tags Returned: %u\n", rsp->num_tags_returned);

cleanup:
	free(rsp);
	return rc;
}

static int play_with_fmapi_dcd_management(struct cxlmi_endpoint *ep)
{
	if (test_fmapi_get_dcd_info(ep)
		|| test_fmapi_get_host_dc_region_config(ep)
		|| test_fmapi_set_dc_region_config(ep)
		|| test_fmapi_get_dc_region_extent_list(ep)
		|| test_fmapi_initiate_dc_add_and_release(ep)
		|| test_fmapi_dc_add_reference(ep)
		|| test_fmapi_dc_remove_reference(ep)
		|| test_fmapi_dc_list_tags(ep)
	)
		return -1;

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
		fprintf(stderr, "must provide MCTP endpoint nid:eid tuple\n");
		goto exit_free_ctx;
	}

	cxlmi_for_each_endpoint_safe(ctx, ep, tmp) {
		(void)show_device_info(ep);

		(void)play_with_device_timestamp(ep);

		(void)get_device_logs(ep);

		(void)play_with_poison_mgmt(ep);

		(void)toggle_abort(ep);

		if (ep_supports_op(ep, 0x4800))
			play_with_dcd(ep);

		if (ep_supports_op(ep, 0x5600))
			play_with_fmapi_dcd_management(ep);

		cxlmi_close(ep);

		printf("-------------------------------------------------\n");
	}

exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
