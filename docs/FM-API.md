The following are the supported CXL commands belonging to the FM-API
command set, as per the latest specification.

<!--ts-->
* [Physical Switch (51h)](#physical-switch-51h)
   * [Identify Switch Device (5100h)](#identify-switch-device-5100h)
   * [Get Physical Port State (5101h)](#get-physical-port-state-5101h)
   * [Physical Port Control (5102h)](#physical-port-control-5102h)
   * [Get Domain Validation SV State (5104h)](#get-domain-validation-sv-state-5104h)
   * [Set Domain Validation SV (5105h)](#set-domain-validation-sv-5105h)
   * [Get VCS Domain Validation SV State (5106h)](#get-vcs-domain-validation-sv-state-5106h)
   * [Get Domain Validation SV (5107h)](#get-domain-validation-sv-5107h)
* [MLD Port (53h)](#mld-port-53h)
   * [Tunnel Management Command (5300h)](#tunnel-management-command-5300h)
* [MLD Components (54h)](#mld-components-54h)
   * [Get LD Info (5400h)](#get-ld-info-5400h)
   * [Get LD Allocations (5401h)](#get-ld-allocations-5401h)
   * [Set LD Allocations (5402h)](#set-ld-allocations-5402h)
   * [Get QoS Control (5403h)](#get-qos-control-5403h)
   * [Set QoS Control (5404h)](#set-qos-control-5404h)
   * [Get QoS Status (5405h)](#get-qos-status-5405h)
   * [Get QoS Allocated BW (5406h)](#get-qos-allocated-bw-5406h)
   * [Set QoS Allocated BW (5407h)](#set-qos-allocated-bw-5407h)
   * [Get QoS BW Limit (5408h)](#get-qos-bw-limit-5408h)
   * [Set QoS BW Limit (5409h)](#set-qos-bw-limit-5409h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Mon Aug 19 01:13:48 PM PDT 2024 -->

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

## Physical Port Control (5102h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_phys_port_control {
	uint8_t ppb_id;
	uint8_t port_opcode;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_phys_port_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_fmapi_phys_port_control *in);
   ```

## Get Domain Validation SV State (5104h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_domain_validation_sv_state {
	uint8_t secret_value_state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_domain_validation_sv_state(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_fmapi_get_domain_validation_sv_state *ret);
   ```

## Set Domain Validation SV (5105h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_set_domain_validation_sv {
	uint8_t secret_value_uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_set_domain_validation_sv(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_fmapi_set_domain_validation_sv *in);
   ```

## Get VCS Domain Validation SV State (5106h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req {
	uint8_t vcs_id;
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp {
	uint8_t secret_value_state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req *in,
			struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp *ret);
   ```

## Get Domain Validation SV (5107h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_domain_validation_sv_req {
	uint8_t vcs_id;
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp {
	uint8_t secret_value_uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_domain_validation_sv(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_domain_validation_sv_req *in,
			struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp *ret);
   ```

# MLD Port (53h)

## Tunnel Management Command (5300h)

Tunneling is supported through `struct cxlmi_tunnel_info`, passed as needed by the
user when sending a command.  When sent to an MLD, the provided command is tunneled
by the FM-owned LD to the specified LD. This can include an additional layer of
tunneling for commands issued on LDs in an MLD that is accessible through an
MLD port  of a CXL Switch.  Tunneling targets are: valid LDs within an MLD
(single level tunneling), switch MLD ports (double level tunneling).

For more information refer to [Issuing CCI Commands](https://github.com/computexpresslink/libcxlmi/tree/main?tab=readme-ov-file#issuing-cci-commands).

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


# MLD Components (54h)

## Get LD Info (5400h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_ld_info {
	uint64_t memory_size;
	uint16_t ld_count;
	uint8_t qos_telemetry_capability;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_ld_info(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_ld_info *ret);
   ```

## Get LD Allocations (5401h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_ld_allocations_req {
	uint8_t start_ld_id;
	uint8_t ld_allocation_list_limit;
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapu_ld_allocations_list {
	uint64_t range_1_allocation_mult;
	uint64_t range_2_allocation_mult;
};

struct cxlmi_cmd_fmapi_get_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t memory_granularity;
	uint8_t start_ld_id;
	uint8_t ld_allocation_list_len;
	struct cxlmi_cmd_fmapu_ld_allocations_list ld_allocation_list[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_ld_allocations(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_ld_allocations_req *in,
			struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret);
   ```

## Set LD Allocations (5402h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_set_ld_allocations_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t rsvd[2];
	struct cxlmi_cmd_fmapu_ld_allocations_list ld_allocation_list[];
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_set_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t rsvd[2];
	struct cxlmi_cmd_fmapu_ld_allocations_list ld_allocation_list[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_set_ld_allocations(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_ld_allocations_req *in,
			struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret);
   ```

## Get QoS Control (5403h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
	uint16_t recmpbasis;
	uint8_t completion_collection_interval;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_qos_control(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_fmapi_get_qos_control *ret);
   ```

## Set QoS Control (5404h)

Input/Output payload:

   ```C
struct cxlmi_cmd_fmapi_set_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
	uint16_t recmpbasis;
	uint8_t completion_collection_interval;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_set_qos_control(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_fmapi_set_qos_control *in,
				    struct cxlmi_cmd_fmapi_set_qos_control *ret);
   ```

## Get QoS Status (5405h)

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_status {
	uint8_t backpressure_avg_percentage;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_qos_status(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_get_qos_status *ret);
   ```

## Get QoS Allocated BW (5406h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_allocation_fraction[];
} __attribute__((packed));
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_qos_allocated_bw(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req *in,
			struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret);
   ```

## Set QoS Allocated BW (5407h)

Input/Output payload:

   ```C
struct cxlmi_cmd_fmapi_set_qos_allocated_bw {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_allocation_fraction[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_set_qos_allocated_bw(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_qos_allocated_bw *in,
			struct cxlmi_cmd_fmapi_set_qos_allocated_bw *ret);
   ```

## Get QoS BW Limit (5408h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_bw_limit_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
};
   ```

Output payload:

   ```C
struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_limit_fraction[];
} __attribute__((packed));
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_qos_bw_limit(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_qos_bw_limit_req *in,
			struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret);
   ```

## Set QoS BW Limit (5409h)

Input/Output payload:

   ```C
struct cxlmi_cmd_fmapi_set_qos_bw_limit {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_limit_fraction[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_set_qos_bw_limit(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_qos_bw_limit *in,
			struct cxlmi_cmd_fmapi_set_qos_bw_limit *ret);
   ```
