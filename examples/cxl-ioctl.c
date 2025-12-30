// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#include <libcxlmi.h>
#include "examples.h"

#define CXL_LUPWT 70U
#define CXL_DOTPWT 10U
#define CXL_DUTPWT 30U
#define CXL_CVMEPWT 50U
#define CXL_CPMEPWT 50U

enum CXLAlertActions {
        LUPWT = (1 << 0),
        DOTPWT = (1 << 1),
        DUTPWT = (1 << 2),
        CVMEPWT = (1 << 3),
        CPMEPWT = (1 << 4),
        MAXALERT = (1 << 5)
};

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

static int show_some_info_from_all_devices(struct cxlmi_ctx *ctx)
{
	int rc = 0;
	struct cxlmi_endpoint *ep;

	cxlmi_for_each_endpoint(ctx, ep) {
		struct cxlmi_cmd_identify_rsp id;

		rc = cxlmi_cmd_identify(ep, NULL, &id);
		if (rc)
			break;

		printf("serial number: 0x%lx\n", (uint64_t)id.serial_num);

		switch (id.component_type) {
		case 0x00:
			printf("device type: CXL Switch\n");
			printf("VID:%04x DID:%04x\n", id.vendor_id, id.device_id);
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
	}

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

static int play_with_scan_media(struct cxlmi_endpoint *ep)
{
	int rc;

	struct cxlmi_cmd_get_scan_media_capabilities_req req ={
		.get_scan_media_capabilities_start_physaddr = 0x0,
		.get_scan_media_capabilities_physaddr_length = 64,
	};
	struct cxlmi_cmd_get_scan_media_capabilities_rsp rsp;
	struct cxlmi_cmd_scan_media_req media = {
		.scan_media_physaddr = 0x0,
		.scan_media_physaddr_length = 64,
		.scan_media_flags = 0x0,
	};
	struct cxlmi_cmd_get_scan_media_results_rsp results;

	memset(&req, 0, sizeof(struct cxlmi_cmd_get_scan_media_capabilities_req));

	rc = cxlmi_cmd_get_scan_media_capabilities(ep, NULL, &req, &rsp);
	if(rc)
		return rc;

	printf("Get scan media capabilities -\n"
	       "estimated scan media time : %d ms\n",
	       rsp.estimated_scan_media_time);

	memset(&media, 0, sizeof(struct cxlmi_cmd_scan_media_req));
	rc = cxlmi_cmd_scan_media(ep, NULL, &media);

	if(rc){
		return rc;
	}

	sleep(rsp.estimated_scan_media_time);

	rc = cxlmi_cmd_get_scan_media_results(ep, NULL, &results);

	if(rc){
		return rc;
	}

	printf("Get scan media results - \n restart phy address : 0x%lx\n"
	       "Physical address length : %ld\n scan media flags : %d\n"
	       "media error count : %d",
	       results.scan_media_restart_physaddr,
	       results.scan_media_restart_physaddr_length,
	       results.scan_media_flags,
	       results.media_error_count);

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

static int get_device_logs(struct cxlmi_endpoint *ep)
{
	int rc;
	size_t cel_size;
	struct cxlmi_cmd_get_supported_logs_rsp *gsl;

	gsl = calloc(1, sizeof(*gsl) +
		     CXLMI_MAX_SUPPORTED_LOGS * sizeof(*gsl->entries));
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

static int get_log_capabilities(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_get_log_capabilities_req req;
	memcpy(req.uuid, cel_uuid, sizeof(cel_uuid));

	struct cxlmi_cmd_get_log_capabilities_rsp *rsp;
	rsp = calloc(1, sizeof(*rsp));
	if (!rsp)
		return -1;

	rc = cxlmi_cmd_get_log_capabilities(ep, NULL, &req, rsp);
	if(rc)
		goto done;

	printf("Supported Log Capabilities: %s%s%s%s\n",
		rsp->parameter_flags & 0x01? "clear_log_supported " : "",
		rsp->parameter_flags & 0x02? "populate_log_supported " : "",
		rsp->parameter_flags & 0x04? "auto_populate_log_supported " : "",
		rsp->parameter_flags & 0x08? "persistent_across_cold_reset" : "");
done:
	free(rsp);
	return rc;
}

static int clear_log(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_clear_log_req *cl;
	cl = calloc(1, sizeof(*cl));
	if (!cl)
		return -1;

	memcpy(cl->uuid, cel_uuid, sizeof(cel_uuid));
	rc = cxlmi_cmd_clear_log(ep, NULL, cl);
	if(rc)
		goto done;

	printf("clear_log successfully executed\n");
done:
	free(cl);
	return rc;
}

static int populate_log(struct cxlmi_endpoint *ep)
{
	int rc;
	struct cxlmi_cmd_populate_log_req *pl;
	pl = calloc(1, sizeof(*pl));
	if (!pl)
		return -1;

	memcpy(pl->uuid, cel_uuid, sizeof(cel_uuid));
	rc = cxlmi_cmd_populate_log(ep, NULL, pl);
	if(rc)
		goto done;

	printf("populate_log successfully executed\n");
done:
	free(pl);
	return rc;
}

static int get_alert_config(struct cxlmi_endpoint *ep)
{
        struct cxlmi_cmd_memdev_get_alert_config_rsp *rsp;
        int rc;

        rsp = calloc(1, sizeof(*rsp));
        if(!rsp)
                return -1;

        rc = cxlmi_cmd_memdev_get_alert_config(ep, NULL, rsp);
        if(rc)
                goto exit;

        printf("valid_alerts:%d\n",rsp->valid_alerts);
        printf("programmable_alerts:%d\n",rsp->programmable_alerts);
        printf("life_used_critical_alert_threshold:%d\n",rsp->life_used_critical_alert_threshold);
        printf("life_used_programmable_warning_threshold:%d\n",rsp->life_used_programmable_warning_threshold);
        printf("device_over_temperature_critical_alert_threshold:%d\n",rsp->device_over_temperature_critical_alert_threshold);
        printf("device_under_temperature_critical_alert_threshold:%d\n",rsp->device_under_temperature_critical_alert_threshold);
        printf("device_over_temperature_programmable_warning_threshold:%d\n",rsp->device_over_temperature_programmable_warning_threshold);
        printf("device_under_temperature_programmable_warning_threshold:%d\n",rsp->device_under_temperature_programmable_warning_threshold);
        printf("corrected_volatile_mem_error_programmable_warning_threshold:%d\n",rsp->corrected_volatile_mem_error_programmable_warning_threshold);
        printf("corrected_persistent_mem_error_programmable_warning_threshold:%d\n",rsp->corrected_persistent_mem_error_programmable_warning_threshold);

exit:
        free(rsp);
        return rc;
}

static int set_alert_config(struct cxlmi_endpoint *ep)
{
        struct cxlmi_cmd_memdev_set_alert_config_req *req;
        int rc = -1;
        uint8_t alert_value = LUPWT;
        enum CXLAlertActions actions = LUPWT | DOTPWT | DUTPWT | CVMEPWT | CPMEPWT;
        req = calloc(1, sizeof(*req));
        if(!req)
                return -1;

        req->valid_alert_actions = actions;
        req->enable_alert_actions = actions;
        while(alert_value < MAXALERT) {
                if(actions & alert_value) {
                        switch (alert_value) {
			case LUPWT:
				req->life_used_programmable_warning_threshold = CXL_LUPWT;
				break;
			case DOTPWT:
				req->device_over_temperature_programmable_warning_threshold = CXL_DOTPWT;
				break;
			case DUTPWT:
				req->device_under_temperature_programmable_warning_threshold = CXL_DUTPWT;
				break;
			case CVMEPWT:
				req->corrected_volatile_mem_error_programmable_warning_threshold = CXL_CVMEPWT;
				break;
			case CPMEPWT:
				req->corrected_persistent_mem_error_programmable_warning_threshold = CXL_CPMEPWT;
				break;
			default:
				printf("Invalid alert config\n");
				goto err;
                        }
                }
                alert_value <<=  1;
        }
        rc = cxlmi_cmd_memdev_set_alert_config(ep, NULL, req);
err:
        free(req);
        return rc;
}

static int play_with_poison_mgmt(struct cxlmi_endpoint *ep)
{
	const int num_poisons = 3;
	int i, rc[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_req get_poison_list_req[num_poisons];
	struct cxlmi_cmd_memdev_get_poison_list_rsp get_poison_list_rsp[num_poisons];
	struct cxlmi_cmd_memdev_inject_poison_req inject_poison[num_poisons];
	struct cxlmi_cmd_memdev_clear_poison_req clear_poison[num_poisons];
	uint64_t phy_addr[num_poisons];
	uint64_t phy_start_addr = 0x00001000;

	for (i = 0; i < num_poisons; i++) {
		phy_addr[i] = phy_start_addr;
		phy_start_addr += 0x100;
	}

	for (i = 0; i < num_poisons; i++) {
		int j;

		inject_poison[i].inject_poison_phy_addr = phy_addr[i];
		get_poison_list_req[i].get_poison_list_phy_addr = phy_addr[i];
		get_poison_list_req[i].get_poison_list_phy_addr_len = 64;
		clear_poison[i].clear_poison_phy_addr = phy_addr[i];
		for (j = 0; j < 64; j++)
			clear_poison[i].clear_poison_write_data[j] = 0;
	}

	for (i = 0; i < num_poisons; i++) {
		rc[i] = cxlmi_cmd_memdev_inject_poison(ep, NULL, &inject_poison[i]);
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
	struct cxlmi_endpoint *ep;
	int rc = EXIT_FAILURE;

	if (argc != 2) {
		fprintf(stderr, "Must provide a device name (ie: mem0)\n");
		fprintf(stderr, "Usage: cxl-ioctl <device>\n");
		goto exit;
	}


	ctx = cxlmi_new_ctx(stdout, DEFAULT_LOGLEVEL);
	if (!ctx) {
		fprintf(stderr, "cannot create new context object\n");
		goto exit;
	}

	ep = cxlmi_open(ctx, argv[1]);
	if (!ep) {
		fprintf(stderr, "cannot open '%s' endpoint\n", argv[1]);
		goto exit_free_ctx;
	}

	printf("ep '%s'\n", argv[1]);

	/* yes, only 1 endpoint, but might add more */
	(void)show_some_info_from_all_devices(ctx);

	(void)play_with_device_timestamp(ep);

	(void)play_with_poison_mgmt(ep);

	(void)get_device_logs(ep);

	(void)get_log_capabilities(ep);

	(void)clear_log(ep);

	(void)populate_log(ep);

	(void)get_alert_config(ep);

	(void)set_alert_config(ep);

	(void)toggle_abort(ep);

	rc = play_with_scan_media(ep);

	cxlmi_close(ep);
exit_free_ctx:
	cxlmi_free_ctx(ctx);
exit:
	return rc;
}
