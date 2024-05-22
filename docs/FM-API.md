The following are the supported CXL commands belonging to the FM-API
command set, as per the latest specification.

<!--ts-->
* [Physical Switch (51h)](#physical-switch-51h)
   * [Identify Switch Device (5100h)](#identify-switch-device-5100h)
   * [Get Physical Port State (5101h)](#get-physical-port-state-5101h)
* [MLD Port (53h)](#mld-port-53h)
   * [Tunnel Management Command (5300h)](#tunnel-management-command-5300h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Tue May 21 04:45:59 PM PDT 2024 -->

<!--te-->

# Physical Switch (51h)

## Identify Switch Device (5100h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_identify_sw_device {
	uint8_t ingres_port_id;
	uint8_t rsv1;
	uint8_t num_physical_ports;
	uint8_t num_vcs;
	uint8_t active_port_bitmask[32];
	uint8_t active_vcs_bitmask[32];
	uint16_t num_total_vppb;
	uint16_t num_active_vppb;
	uint8_t num_hdm_decoder_per_usp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
		       struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_fmapi_identify_sw_device *ret);
   ```

## Get Physical Port State (5101h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_phys_port_state_req {
	uint8_t num_ports;
	uint8_t ports[];
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_port_state_info_block {
	uint8_t port_id;
	uint8_t config_state;
	uint8_t conn_dev_cxl_ver;
	uint8_t rsv1;
	uint8_t conn_dev_type;
	uint8_t port_cxl_ver_bitmask;
	uint8_t max_link_width;
	uint8_t negotiated_link_width;
	uint8_t supported_link_speeds_vector;
	uint8_t max_link_speed;
	uint8_t current_link_speed;
	uint8_t ltssm_state;
	uint8_t first_lane_num;
	uint16_t link_state;
	uint8_t supported_ld_count;
};

struct cxlmi_cmd_fmapi_get_phys_port_state_rsp {
	uint8_t num_ports;
	uint8_t rsv1[3];
	struct cxlmi_cmd_fmapi_port_state_info_block ports[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_phys_port_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_phys_port_state_req *in,
			struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret);
   ```

# MLD Port (53h)

## Tunnel Management Command (5300h)

Tunneling is supported through `struct cxlmi_tunnel_info`, passed as needed by the
user when sending a command.  When sent to an MLD, the provided command is tunneled
by the FM-owned LD to the specified LD. This can include an additional layer of
tunneling for commands issued on LDs in an MLD that is accessible through an
MLD port  of a CXL Switch.  Tunneling targets are: valid LDs within an MLD
(single level tunneling), switch MLD ports (double level tunneling).

For more information refer [Issuing CCI Commands](https://github.com/davidlohr/libcxlmi/tree/main?tab=readme-ov-file#issuing-cci-commands).

   ```C
/*
 * cxlmi_tunnel_info - Tunneling information associated with a specific command
 * @port: switch downstream port number
 * @ld: Logical Device (LD) id within an MLD
 * @level: tunneling level 1 or 2.
 */
struct cxlmi_tunnel_info {
	int port;
	int ld;
	int level;
};
   ```