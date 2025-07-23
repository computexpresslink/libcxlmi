The following are the supported CXL commands belonging to the FM-API
command set, as per the latest specification.

<!--ts-->
* [Physical Switch (51h)](#physical-switch-51h)
   * [Identify Switch Device (5100h)](#identify-switch-device-5100h)
   * [Get Physical Port State (5101h)](#get-physical-port-state-5101h)
   * [Physical Port Control (5102h)](#physical-port-control-5102h)
   * [Send PPB CXL.io Configuration Request (5103)](#send-ppb-cxlio-configuration-request-5103)
   * [Get Domain Validation SV State (5104h)](#get-domain-validation-sv-state-5104h)
   * [Set Domain Validation SV (5105h)](#set-domain-validation-sv-5105h)
   * [Get VCS Domain Validation SV State (5106h)](#get-vcs-domain-validation-sv-state-5106h)
   * [Get Domain Validation SV (5107h)](#get-domain-validation-sv-5107h)
* [Virtual Switch (52h)](#virtual-switch-52h)
   * [Bind vPPB (5201h)](#bind-vppb-5201h)
   * [Unbind vPPB (5202)](#unbind-vppb-5202)
* [MLD Port (53h)](#mld-port-53h)
   * [Tunnel Management Command (5300h)](#tunnel-management-command-5300h)
   * [Send LD CXL.io Configuration Request (5301h)](#send-ld-cxlio-configuration-request-5301h)
   * [Send LD CXL.io Memory Request (5302h)](#send-ld-cxlio-memory-request-5302h)
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
* [Multi-Headed Devices (55h)](#multi-headed-devices-55h)
   * [Get Multi-Headed Info (5500h)](#get-multi-headed-info-5500h)
   * [Get Head Info (5501h)](#get-head-info-5501h)
* [DCD Management (56h)](#dcd-management-56h)
   * [Get DCD Info (5600h)](#get-dcd-info-5600h)
   * [Get Host DC Region Config (5601h)](#get-host-dc-region-config-5601h)
   * [Set Host DC Region Config (5602h)](#set-host-dc-region-config-5602h)
   * [Get DC Region Extent Lists (5603h)](#get-dc-region-extent-lists-5603h)
   * [Initiate DC Add (5604h)](#initiate-dc-add-5604h)
   * [Initiate DC Release (5605h)](#initiate-dc-release-5605h)
   * [DC Add Reference (5606h)](#dc-add-reference-5606h)
   * [DC Remove Reference (5607h)](#dc-remove-reference-5607h)
   * [DC List Tags (5608h)](#dc-list-tags-5608h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Wed Apr 30 05:02:19 PM PDT 2025 -->

<!--te-->

# Physical Switch (51h)

## Identify Switch Device (5100h)

Return payload:

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

## Send PPB CXL.io Configuration Request (5103)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req {
	uint8_t ppb_id;
	uint8_t field_1[0x3];
	uint32_t transaction_data;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp {
	uint32_t return_data;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_send_ppb_cxlio_config_request(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_req *in,
				  struct cxlmi_cmd_fmapi_send_ppb_cxlio_config_request_rsp *ret);
   ```

## Get Domain Validation SV State (5104h)

Return payload:

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

Return payload:

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

Return payload:

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

# Virtual Switch (52h)

## Bind vPPB (5201h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_bind_vppb {
	uint8_t vcs_id;
	uint8_t vppb_id;
	uint8_t port_id;
	uint8_t rsv1;
	uint16_t ld_id;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_bind_vppb(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_bind_vppb *in);
   ```

## Unbind vPPB (5202)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_unbind_vppb {
	uint8_t vcs_id;
	uint8_t vppb_id;
	uint8_t option;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_unbind_vppb(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_fmapi_unbind_vppb *in);
   ```

# MLD Port (53h)

## Tunnel Management Command (5300h)

Tunneling is supported through `struct cxlmi_tunnel_info`, passed as needed by the
user when sending a command.  When sent to an MLD, the provided command is tunneled
by the FM-owned LD to the specified LD. This can include an additional layer of
tunneling for commands issued on LDs in an MLD that is accessible through an
MLD port  of a CXL Switch. Tunneling targets are: CXL Switches, valid LDs within
an MLD (single level tunneling), switch MLD ports (double level tunneling). For
each of these, the below helper macros are provided to create (stack-allocated
variable) and arm the tunneling information.

For more information refer to [Issuing CCI Commands](https://github.com/computexpresslink/libcxlmi/tree/main?tab=readme-ov-file#issuing-cci-commands).

   ```C
/**
 * Tunneling Commands to an LD in an MLD.
 *
 * @name: tunnel variable name
 * @ld: Logical Device (LD) id within an MLD
 */
DEFINE_CXLMI_TUNNEL_MLD(name, ld)

/**
 * Tunneling Commands to an MLD through a CXL Switch.
 *
 * @name: tunnel variable name
 * @port: switch downstream port number
 */
DEFINE_CXLMI_TUNNEL_SWITCH(name, port)

/**
 * Tunneling Commands to an LD in an MLD through a CXL Switch.
 *
 * @name: tunnel variable name
 * @port: switch downstream port number (outter tunnel)
 * @ld: Logical Device (LD) id within an MLD (inner tunnel)
 */
DEFINE_CXLMI_TUNNEL_SWITCH_MLD(name, port, ld)

/**
 * Tunneling Commands to the LD Pool CCI in a Multi-Headed Device.
 *
 * @name: tunnel variable name
 */
DEFINE_CXLMI_TUNNEL_MHD(name)
   ```

## Send LD CXL.io Configuration Request (5301h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req {
	uint8_t ppb_id;
	uint8_t field_1[0x3];
	uint16_t ld_id;
	uint8_t rsvd[0x2];
	uint32_t transaction_data;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp {
	uint32_t return_data;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_send_ld_cxlio_config_request(struct cxlmi_endpoint *ep,
			 struct cxlmi_tunnel_info *ti,
			 struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_req *in,
			 struct cxlmi_cmd_fmapi_send_ld_cxlio_config_request_rsp *ret);
   ```

## Send LD CXL.io Memory Request (5302h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req {
	uint8_t port_id;
	uint8_t field_1[0x2];
	uint16_t ld_id;
	uint16_t transaction_len;
	uint16_t transaction_addr;
	uint8_t transaction_data[];
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp {
	uint16_t return_size;
	uint8_t rsvd[0x2];
	uint8_t return_data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_send_ld_cxlio_mem_request(struct cxlmi_endpoint *ep,
			 struct cxlmi_tunnel_info *ti,
			 struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_req *in,
			 struct cxlmi_cmd_fmapi_send_ld_cxlio_mem_request_rsp *ret);
   ```

# MLD Components (54h)

## Get LD Info (5400h)

Return payload:

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

Return payload:

   ```C
struct cxlmi_cmd_fmapi_ld_allocations_list {
	uint64_t range_1_allocation_mult;
	uint64_t range_2_allocation_mult;
};

struct cxlmi_cmd_fmapi_get_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t memory_granularity;
	uint8_t start_ld_id;
	uint8_t ld_allocation_list_len;
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
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
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_set_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t rsvd[2];
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
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

Return payload:

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

Input/Return payload:

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

Return payload:

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

Return payload:

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

Input/Return payload:

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

Return payload:

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

Input/Return payload:

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

# Multi-Headed Devices (55h)

## Get Multi-Headed Info (5500h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_multiheaded_info_req {
	uint8_t start_ld_id;
	uint8_t ld_map_list_limit;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp {
	uint8_t num_lds;
	uint8_t num_heads;
	uint8_t rsvd1[2];
	uint8_t start_ld_id;
	uint8_t ld_map_len;
	uint8_t rsvd2[2];
	uint8_t ld_map[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_multiheaded_info(struct cxlmi_endpoint *ep,
			 struct cxlmi_tunnel_info *ti,
			 struct cxlmi_cmd_fmapi_get_multiheaded_info_req *in,
			 struct cxlmi_cmd_fmapi_get_multiheaded_info_rsp *ret);
  ```

## Get Head Info (5501h)

Input payload:

   ```C
struct cxlmi_cmd_fmapi_get_head_info_req {
       uint8_t start_head;
       uint8_t num_heads;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_fmapi_get_head_info_blkfmt {
	uint8_t port_num;
	uint8_t field_1; /* max link width */
	uint8_t field_2; /* negotiated link width */
	uint8_t field_3; /* supported link speed vector */
	uint8_t field_4; /* max link speed */
	uint8_t field_5; /* current link speed */
	uint8_t ltssm_state;
	uint8_t first_negotiated_lane_num;
	uint8_t link_state_flags;
};

struct cxlmi_cmd_fmapi_get_head_info_rsp {
	uint8_t num_heads;
	uint8_t rsvd[0x3];
	struct cxlmi_cmd_fmapi_get_head_info_blkfmt head_info_list[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_head_info(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_fmapi_get_head_info_req *in,
				  struct cxlmi_cmd_fmapi_get_head_info_rsp *ret)
  ```

# DCD Management (56h)

## Get DCD Info (5600h)

Return payload:

   ```C
struct cxlmi_cmd_fmapi_get_dcd_info {
	uint8_t num_hosts;
	uint8_t num_supported_dc_regions;
	uint8_t rsvd1[0x2];
	uint16_t capacity_selection_policies;
	uint8_t rsvd2[0x2];
	uint16_t capacity_removal_policies;
	uint8_t sanitize_on_release_config_mask;
	uint8_t rsvd3;
	uint64_t total_dynamic_capacity;
	uint64_t supported_block_sizes[8];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_dcd_info(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_dcd_info *ret);
   ```

## Get Host DC Region Config (5601h)
Note that the returned number of DC region configurations
is limited by the library to 8. This is because of the
change of payload size in newer versions of the specification.

Input Payload:
```C
struct cxlmi_cmd_fmapi_get_host_dc_region_config_req {
	uint16_t host_id;
	uint8_t region_cnt;
	uint8_t start_region_id;
};
```
Return Payload:

   ```C
struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp {
	uint16_t host_id;
	uint8_t num_regions;
	uint8_t regions_returned;
	struct {
		uint64_t base;
		uint64_t decode_len;
		uint64_t region_len;
		uint64_t block_size;
		uint8_t flags;
		uint8_t rsvd[3];
		uint8_t sanitize_on_release;
		uint8_t rsvd2[3];
	} region_configs[8];
	uint32_t num_extents_supported;
	uint32_t num_extents_available;
	uint32_t num_tags_supported;
	uint32_t num_tags_available;
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_dc_reg_config(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_host_dc_region_config_req *in,
			struct cxlmi_cmd_fmapi_get_host_dc_region_config_rsp *ret);
   ```

## Set Host DC Region Config (5602h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_set_dc_region_config {
	uint8_t region_id;
	uint8_t rsvd[3];
	uint64_t block_sz;
	uint8_t sanitize_on_release;
	uint8_t rsvd2[3];
};
```

Command name:
   ```C
int cxlmi_cmd_fmapi_set_dc_region_config(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_dc_region_config *in);
   ```

## Get DC Region Extent Lists (5603h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req {
	uint16_t host_id;
	uint8_t rsvd[2];
	uint32_t extent_count;
	uint32_t start_ext_index;
};
```
Return Payload:

   ```C
struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp {
	uint16_t host_id;
	uint8_t rsvd1[2];
	uint32_t start_ext_index;
	uint32_t extents_returned;
	uint32_t total_extents;
	uint32_t list_generation_num;
	uint8_t rsvd2[4];
	struct {
	       uint64_t start_dpa;
	       uint64_t len;
	       uint8_t tag[0x10];
	       uint16_t shared_seq;
	       uint8_t rsvd[0x6];
       } extents[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_get_dc_region_ext_list(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_dc_region_ext_list_req *in,
			struct cxlmi_cmd_fmapi_get_dc_region_ext_list_rsp *ret);
   ```

## Initiate DC Add (5604h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_initiate_dc_add_req {
	uint16_t host_id;
	uint8_t selection_policy;
	uint8_t region_num;
	uint64_t length;
	uint8_t tag[0x10];
	uint32_t ext_count;
	struct {
	       uint64_t start_dpa;
	       uint64_t len;
	       uint8_t tag[0x10];
	       uint16_t shared_seq;
	       uint8_t rsvd[0x6];
       } extents[];
};
```

Command name:

   ```C
int cxlmi_cmd_fmapi_initiate_dc_add(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_initiate_dc_add_req *in);
   ```

## Initiate DC Release (5605h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_initiate_dc_release_req {
	uint16_t host_id;
	uint8_t flags;
	uint8_t rsvd;
	uint64_t length;
	uint8_t tag[0x10];
	uint32_t ext_count;
	struct {
	       uint64_t start_dpa;
	       uint64_t len;
	       uint8_t tag[0x10];
	       uint16_t shared_seq;
	       uint8_t rsvd[0x6];
       } extents[];
};
```

Command name:

   ```C
int cxlmi_cmd_fmapi_initiate_dc_release(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_initiate_dc_release_req *in);
   ```

## DC Add Reference (5606h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_dc_add_ref_req {
	uint8_t tag[0x10];
};
```

Command name:

   ```C
int cxlmi_cmd_fmapi_dc_add_reference(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_dc_add_ref_req *in);
   ```

## DC Remove Reference (5607h)
Input Payload:
```C
struct cxlmi_cmd_fmapi_dc_remove_ref_req {
	uint8_t tag[0x10];
};
```

Command name:

   ```C
int cxlmi_cmd_fmapi_dc_remove_reference(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_dc_remove_ref_req *in);
   ```


## DC List Tags (5608h)
Input Payload:

   ```C
struct cxlmi_cmd_fmapi_dc_list_tags_req {
	uint32_t start_ind;
	uint32_t max_tags;
};
   ```

Output Payload:
   ```C
struct cxlmi_cmd_fmapi_dc_list_tags_rsp {
	uint32_t generation_num;
	uint32_t total_num_tags;
	uint32_t num_tags_returned;
	uint8_t validity_bitmap;
	uint8_t rsvd[3];
	struct {
		uint8_t tag[0x10];
		uint8_t flags;
		uint8_t rsvd[3];
		uint8_t ref_bitmap[32];
		uint8_t pending_ref_bitmap[32];
	} tags_list[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_fmapi_dc_list_tags(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_dc_list_tags_req *in,
			struct cxlmi_cmd_fmapi_dc_list_tags_rsp *ret);
   ```
