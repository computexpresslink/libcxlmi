// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#ifndef _LIBCXLMI_API_TYPES_H
#define _LIBCXLMI_API_TYPES_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/types.h>

/* CXL r3.1 Figure 7-19: CCI Message Format */
struct cxlmi_cci_msg {
	uint8_t category;
	uint8_t tag;
	uint8_t rsv1;
	uint8_t command;
	uint8_t command_set;
	uint8_t pl_length[3]; /* 20 bit little endian, BO bit at bit 23 */
	uint16_t return_code;
	uint16_t vendor_ext_status;
	uint8_t payload[];
} __attribute__ ((packed));

/* CXL r3.1 Section 8.2.9.1.1: Identify (Opcode 0001h) */
struct cxlmi_cmd_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint64_t serial_num;
	uint8_t max_msg_size;
	uint8_t component_type;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.2: Background Operation Status (Opcode 0002h) */
struct cxlmi_cmd_bg_op_status {
	uint8_t status;
	uint8_t rsvd;
	uint16_t opcode;
	uint16_t returncode;
	uint16_t vendor_ext_status;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.3: Get Response Message Limit (Opcode 0003h) */
struct cxlmi_cmd_get_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.1.4: Set Response Message Limit (Opcode 0004h) */
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
} __attribute__((packed));

/*
 * Common Event Record Format
 * CXL r3.1 section 8.2.9.2.1: Event Records; Table 8-43
 */
struct cxlmi_event_record {
	uint8_t uuid[0x10];
	uint8_t length;
	uint8_t flags[3];
	uint16_t handle;
	uint16_t related_handle;
	uint64_t timestamp;
	uint8_t maint_op_class;
	uint8_t maint_op_subclass;
	uint8_t reserved[0xe];
	uint8_t data[0x50];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.2: Get Event Records (Opcode 0100h) */
struct cxlmi_cmd_get_event_records_req {
	uint8_t event_log;
} __attribute__((packed));

struct cxlmi_cmd_get_event_records_rsp {
	uint8_t flags;
	uint8_t reserved1;
	uint16_t overflow_err_count;
	uint64_t first_overflow_timestamp;
	uint64_t last_overflow_timestamp;
	uint16_t record_count;
	uint8_t reserved2[0xa];
	struct cxlmi_event_record records[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.3: Clear Event Records (Opcode 0101h) */
struct cxlmi_cmd_clear_event_records {
	uint8_t event_log;
	uint8_t clear_flags;
	uint8_t nr_recs;
	uint8_t reserved[3];
	uint16_t handles[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.4: Get Event Interrupt Policy (Opcode 0102h) */
struct cxlmi_cmd_get_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.5: Set Event Interrupt Policy (Opcode 0103h) */
struct cxlmi_cmd_set_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.6: Get MCTP Event Interrupt Policy (Opcode 0104h) */
struct cxlmi_cmd_get_mctp_event_interrupt_policy {
	uint16_t event_interrupt_settings;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.7: Set MCTP Event Interrupt Policy (Opcode 0105h) */
struct cxlmi_cmd_set_mctp_event_interrupt_policy {
	uint16_t event_interrupt_settings;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.2.8: Event Notification (Opcode 0106h) */
struct cxlmi_cmd_event_notification {
	uint16_t event;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.3.1: Get FW Info (Opcode 0200h) */
struct cxlmi_cmd_get_fw_info {
	uint8_t slots_supported;
	uint8_t slot_info;
	uint8_t caps;
	uint8_t rsvd[0xd];
	char fw_rev1[0x10];
	char fw_rev2[0x10];
	char fw_rev3[0x10];
	char fw_rev4[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.3.2: Transfer FW (Opcode 0201) */
struct cxlmi_cmd_transfer_fw {
	uint8_t action;
	uint8_t slot;
	uint8_t rsvd1[2];
	uint32_t offset;
	uint8_t rsvd2[0x78];
	uint8_t data[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.3.3: Activate FW (Opcode 0202h) */
struct cxlmi_cmd_activate_fw {
	uint8_t action;
	uint8_t slot;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.4.1: Get Timestamp (Opcode 0300h) */
struct cxlmi_cmd_get_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.4.2: Set Timestamp (Opcode 0301h) */
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.1: Get Supported Logs (Opcode 0400h) */
struct cxlmi_supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
} __attribute__((packed));

struct cxlmi_cmd_get_supported_logs {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct cxlmi_supported_log_entry entries[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.2: Get Log (Opcode 0401h) */
struct cxlmi_cmd_get_log_req {
	uint8_t uuid[0x10];
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

struct cxlmi_cmd_get_log_rsp {
	uint16_t opcode;
	uint16_t command_effect;
} __attribute__((packed));

struct cxlmi_cmd_get_log_cel_rsp {
	uint16_t opcode;
	uint16_t command_effect;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.3: Get Log Capabilities (Opcode 0402h) */
struct cxlmi_cmd_get_log_capabilities_req {
	uint8_t uuid[0x10];
} __attribute__((packed));

struct cxlmi_cmd_get_log_capabilities_rsp {
	uint32_t parameter_flags;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.4: Clear Log (Opcode 0403h) */
struct cxlmi_cmd_clear_log {
	uint8_t uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.4: Populate Log (Opcode 0404h) */
struct cxlmi_cmd_populate_log {
	uint8_t uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.5.5: Get Supported Logs Sub-List (Opcode 0405h) */
struct cxlmi_cmd_get_supported_logs_sublist_req {
	uint8_t max_supported_log_entries;
	uint8_t start_log_entry_index;
} __attribute__((packed));

struct cxlmi_cmd_get_supported_logs_sublist_rsp {
	uint8_t num_supported_log_entries;
	uint8_t rsvd1;
	uint16_t total_num_supported_log_entries;
	uint8_t start_log_entry_index;
	uint8_t rsvd2[0x3];
	struct cxlmi_supported_log_entry entries[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.1.1: Identify Memory Device (Opcode 4000h) */
struct cxlmi_cmd_memdev_identify {
	char fw_revision[0x10];
	uint64_t total_capacity;
	uint64_t volatile_capacity;
	uint64_t persistent_capacity;
	uint64_t partition_align;
	uint16_t info_event_log_size;
	uint16_t warning_event_log_size;
	uint16_t failure_event_log_size;
	uint16_t fatal_event_log_size;
	uint32_t lsa_size;
	uint8_t poison_list_max_mer[3];
	uint16_t inject_poison_limit;
	uint8_t poison_caps;
	uint8_t qos_telemetry_caps;
	uint16_t dc_event_log_size;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.2.1: Get Partition Info (Opcode 4100h) */
struct cxlmi_cmd_memdev_get_partition_info {
	uint64_t active_vmem;
	uint64_t active_pmem;
	uint64_t next_vmem;
	uint64_t next_pmem;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.2.2: Set Partition Info (Opcode 4101h) */
struct cxlmi_cmd_memdev_set_partition_info {
	uint64_t volatile_capacity;
	uint8_t flags;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.2.3: Get LSA (Opcode 4102h) */
struct cxlmi_cmd_memdev_get_lsa {
	uint32_t offset;
	uint32_t length;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.2.4: Set LSA (Opcode 4103h) */
struct cxlmi_cmd_memdev_set_lsa {
	uint32_t offset;
	uint32_t rsvd;
	uint8_t data[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.1: Get Health Info (Opcode 4200h) */
struct cxlmi_cmd_memdev_get_health_info {
	uint8_t health_status;
	uint8_t media_status;
	uint8_t additional_status;
	uint8_t life_used;
	uint16_t device_temperature;
	uint32_t dirty_shutdown_count;
	uint32_t corrected_volatile_error_count;
	uint32_t corrected_persistent_error_count;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.2: Get Alert Config (Opcode 4201h) */
struct cxlmi_cmd_memdev_get_alert_config {
	uint8_t valid_alerts;
	uint8_t programmable_alerts;
	uint8_t life_used_critical_alert_threshold;
	uint8_t life_used_programmable_warning_threshold;
	uint16_t device_over_temperature_critical_alert_threshold;
	uint16_t device_under_temperature_critical_alert_threshold;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.3: Set Alert Config (Opcode 4202h) */
struct cxlmi_cmd_memdev_set_alert_config {
	uint8_t valid_alert_actions;
	uint8_t enable_alert_actions;
	uint8_t life_used_programmable_warning_threshold;
	uint8_t rsvd1;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.4: Get Shutdown State (Opcode 4203h) */
struct cxlmi_cmd_memdev_get_shutdown_state {
	uint8_t state;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.3.5: Set Shutdown State (Opcode 4204h) */
struct cxlmi_cmd_memdev_set_shutdown_state {
	uint8_t state;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.4.1: Get poison List (Opcode 4300h) */
struct cxlmi_cmd_memdev_get_poison_list_req {
	uint64_t get_poison_list_phy_addr;
	uint64_t get_poison_list_phy_addr_len;
} __attribute__((packed));

struct cxlmi_memdev_media_err_record {
	uint64_t media_err_addr;
	uint32_t media_err_len;
	uint8_t rsvd1[4];
} __attribute__((packed));

struct cxlmi_cmd_memdev_get_poison_list_rsp {
	uint8_t poison_list_flags;
	uint8_t rsv1;
	uint64_t overflow_timestamp;
	uint16_t more_err_media_record_cnt;
	uint8_t rsv2[0x14];
	struct cxlmi_memdev_media_err_record records[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.4.2: Inject Poison (Opcode 4301h) */
struct cxlmi_cmd_memdev_inject_poison {
	uint64_t inject_poison_phy_addr;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.4.3: Clear Poison (Opcode 4302h) */
struct cxlmi_cmd_memdev_clear_poison {
	uint64_t clear_poison_phy_addr;
	uint8_t clear_poison_write_data[64];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.6.1: Get Security State (Opcode 4500h) */
struct cxlmi_cmd_memdev_get_security_state {
	uint32_t security_state;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.6.2: Set Passphrase (Opcode 4501h) */
struct cxlmi_cmd_memdev_set_passphrase {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t current_passphrase[0x20];
	uint8_t new_passphrase[0x20];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.6.3: Disable Passphrase (Opcode 4502h) */
struct cxlmi_cmd_memdev_disable_passphrase {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t passphrase[0x20];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.6.4: Unlock (Opcode 4503h) */
struct cxlmi_cmd_memdev_unlock {
	uint8_t current_passphrase[0x20];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.6.6: Passphrase Secure Erase (Opcode 4505h) */
struct cxlmi_cmd_memdev_passphrase_secure_erase {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t passphrase[0x20];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.8.1: Get SLD QoS Control (Opcode 4700h) */
struct cxlmi_cmd_memdev_get_sld_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.8.2: Set SLD QoS Control (Opcode 4701h) */
struct cxlmi_cmd_memdev_set_sld_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.8.3: Get SLD QoS Status (Opcode 4702h) */
struct cxlmi_cmd_memdev_get_sld_qos_status {
	uint8_t backpressure_avg_percentage;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.9.1 Get Dynamic Capacity Configuration (Opcode 4800h) */
/* Note: The region config structure array is fixed to hold 8 regions */
struct cxlmi_cmd_memdev_get_dc_config_req {
	uint8_t region_cnt;
	uint8_t start_region_id;
} __attribute__((packed));

struct cxlmi_cmd_memdev_get_dc_config_rsp {
	uint8_t num_regions;
	uint8_t regions_returned;
	uint8_t rsvd1[6];
	struct {
		uint64_t base;
		uint64_t decode_len;
		uint64_t region_len;
		uint64_t block_size;
		uint32_t dsmadhandle;
		uint8_t flags;
		uint8_t rsvd2[3];
	} __attribute__((packed)) region_configs[8];
	uint32_t num_extents_supported;
	uint32_t num_extents_available;
	uint32_t num_tags_supported;
	uint32_t num_tags_available;
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.9.2 Get Dynamic Capacity Extent List (Opcode 4801h) */
struct cxlmi_cmd_memdev_get_dc_extent_list_req {
       uint32_t extent_cnt;
       uint32_t start_extent_idx;
} __attribute__((packed));

struct cxlmi_cmd_memdev_get_dc_extent_list_rsp {
       uint32_t num_extents_returned;
       uint32_t total_num_extents;
       uint32_t generation_num;
       uint8_t rsvd[4];
       struct {
	       uint64_t start_dpa;
	       uint64_t len;
	       uint8_t tag[0x10];
	       uint16_t shared_seq;
	       uint8_t rsvd[0x6];
       } __attribute__((packed)) extents[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.9.3 Add Dynamic Capacity Response (Opcode 4802h) */
struct cxlmi_cmd_memdev_add_dc_response {
	uint32_t updated_extent_list_size;
	uint8_t flags;
	uint8_t rsvd1[3];
	struct {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t rsvd[8];
	} __attribute__((packed)) extents[];
} __attribute__((packed));

/* CXL r3.1 Section 8.2.9.9.9.4 Release Dynamic Capacity (Opcode 4803h) */
struct cxlmi_cmd_memdev_release_dc {
	uint32_t updated_extent_list_size;
	uint8_t flags;
	uint8_t rsvd1[3];
	struct {
		uint64_t start_dpa;
		uint64_t len;
		uint8_t rsvd[8];
	} __attribute__((packed)) extents[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.1: Identify Switch Device (Opcode 5100h) */
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
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.2: Get Physical Port State (Opcode 5101h) */
struct cxlmi_cmd_fmapi_get_phys_port_state_req {
	uint8_t num_ports; /* TODO: check may get too large for MCTP message size */
	uint8_t ports[];
} __attribute__((packed));

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
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_phys_port_state_rsp {
	uint8_t num_ports;
	uint8_t rsv1[3];
	struct cxlmi_cmd_fmapi_port_state_info_block ports[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.3: Physical Port Control (Opcode 5102h) */
struct cxlmi_cmd_fmapi_phys_port_control {
	uint8_t ppb_id;
	uint8_t port_opcode;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.5: Get Domain Validation SV State (Opcode 5104h) */
struct cxlmi_cmd_fmapi_get_domain_validation_sv_state {
	uint8_t secret_value_state;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.6: Set Domain Validation SV (Opcode 5105h) */
struct cxlmi_cmd_fmapi_set_domain_validation_sv {
	uint8_t secret_value_uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.7: Get VCS Domain Validation SV State (Opcode 5106h) */
struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req {
	uint8_t vcs_id;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp {
	uint8_t secret_value_state;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.1.8: Get Domain Validation SV (Opcode 5107h) */
struct cxlmi_cmd_fmapi_get_domain_validation_sv_req {
	uint8_t vcs_id;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp {
	uint8_t secret_value_uuid[0x10];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.1: Get LD Info (Opcode 5400h) */
struct cxlmi_cmd_fmapi_get_ld_info {
	uint64_t memory_size;
	uint16_t ld_count;
	uint8_t qos_telemetry_capability;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.2: Get LD Allocations (Opcode 5401h) */
struct cxlmi_cmd_fmapi_get_ld_allocations_req {
	uint8_t start_ld_id;
	uint8_t ld_allocation_list_limit;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_ld_allocations_list {
	uint64_t range_1_allocation_mult;
	uint64_t range_2_allocation_mult;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t memory_granularity;
	uint8_t start_ld_id;
	uint8_t ld_allocation_list_len;
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.3: Set LD Allocations (Opcode 5402h) */
struct cxlmi_cmd_fmapi_set_ld_allocations_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t rsvd[2];
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
} __attribute__((packed));

struct cxlmi_cmd_fmapi_set_ld_allocations_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t rsvd[2];
	struct cxlmi_cmd_fmapi_ld_allocations_list ld_allocation_list[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.4: Get QoS Control (Opcode 5403h) */
struct cxlmi_cmd_fmapi_get_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
	uint16_t recmpbasis;
	uint8_t completion_collection_interval;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.5: Set QoS Control (Opcode 5404h) */
struct cxlmi_cmd_fmapi_set_qos_control {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
	uint16_t recmpbasis;
	uint8_t completion_collection_interval;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.6: Get QoS Status (Opcode 5405h) */
struct cxlmi_cmd_fmapi_get_qos_status {
	uint8_t backpressure_avg_percentage;
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.7: Get QoS Allocated BW (Opcode 5406h) */
struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_allocation_fraction[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.8: Set QoS Allocated BW (Opcode 5407h) */
struct cxlmi_cmd_fmapi_set_qos_allocated_bw {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_allocation_fraction[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.9: Get QoS BW Limit (Opcode 5408h) */
struct cxlmi_cmd_fmapi_get_qos_bw_limit_req {
	uint8_t number_ld;
	uint8_t start_ld_id;
} __attribute__((packed));

struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_limit_fraction[];
} __attribute__((packed));

/* CXL r3.1 Section 7.6.7.4.10: Set QoS BW Limit (Opcode 5409h) */
struct cxlmi_cmd_fmapi_set_qos_bw_limit {
	uint8_t number_ld;
	uint8_t start_ld_id;
	uint8_t qos_limit_fraction[];
} __attribute__((packed));
#endif
