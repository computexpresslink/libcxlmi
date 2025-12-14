The following are the supported CXL commands belonging to the Memory Device
command set, as per the latest specification.

<!--ts-->
* [Identify Memory Device (40h)](#identify-memory-device-40h)
   * [Identify Memory Device (400h)](#identify-memory-device-400h)
* [Capacity Configuration and Label Storage (41h)](#capacity-configuration-and-label-storage-41h)
   * [Get Partition Info (4100h)](#get-partition-info-4100h)
   * [Set Partition Info (4101h)](#set-partition-info-4101h)
   * [Get LSA (4102h)](#get-lsa-4102h)
   * [Set LSA (4103h)](#set-lsa-4103h)
* [Health Info and Alerts (42h)](#health-info-and-alerts-42h)
   * [Get Health Info (4200h)](#get-health-info-4200h)
   * [Get Alert Configuration (4201h)](#get-alert-configuration-4201h)
   * [Set Alert Configuration (4202h)](#set-alert-configuration-4202h)
   * [Get Shutdown State (4203h)](#get-shutdown-state-4203h)
   * [Set Shutdown State (4204h)](#set-shutdown-state-4204h)
* [Media and Poison Management (43h)](#media-and-poison-management-43h)
   * [Get Poison List (4300h)](#get-poison-list-4300h)
   * [Inject Poison (4301h)](#inject-poison-4301h)
   * [Clear Poison (4302h)](#clear-poison-4302h)
   * [Get Scan Media Capabilities (4303h)](#get-scan-media-capabilities-4303h)
   * [Scan Media (4304h)](#scan-media-4304h)
   * [Get Scan Media Results (4305h)](#get-scan-media-results-4305h)
* [Sanitize and Media Operations (44h)](#sanitize-and-media-operations-44h)
   * [Sanitize (4400h)](#sanitize-4400h)
   * [Secure Erase (4401h)](#secure-erase-4401h)
   * [Media Operations (4402h)](#media-operations-4402h)
* [Persistent Memory Data-at-rest Security (45h)](#persistent-memory-data-at-rest-security-45h)
   * [Get Security State (4500h)](#get-security-state-4500h)
   * [Set Passphrase (4501h)](#set-passphrase-4501h)
   * [Disable Passphrase (4502h)](#disable-passphrase-4502h)
   * [Unlock (4503h)](#unlock-4503h)
   * [Freeze Security State (4504h)](#freeze-security-state-4504h)
   * [Passphrase Secure Erase (4505h)](#passphrase-secure-erase-4505h)
* [Security Passthrough (46h)](#security-passthrough-46h)
   * [Security Send (4600h)](#security-send-4600h)
   * [Security Receive (4601h)](#security-receive-4601h)
* [SLD QoS Telemetry (47h)](#sld-qos-telemetry-47h)
   * [Get SLD QoS Control (4700h)](#get-sld-qos-control-4700h)
   * [Set SLD QoS Control (4701h)](#set-sld-qos-control-4701h)
   * [Get SLD QoS Status (4702h)](#get-sld-qos-status-4702h)
* [Dynamic Capacity (48h)](#dynamic-capacity-48h)
   * [Get Dynamic Capacity Configuration (4800h)](#get-dynamic-capacity-configuration-4800h)
   * [Get Dynamic Capacity Extent List (4801h)](#get-dynamic-capacity-extent-list-4801h)
   * [Add Dynamic Capacity Response (4802h)](#add-dynamic-capacity-response-4802h)
   * [Release Dynamic Capacity (4803h)](#release-dynamic-capacity-4803h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Tue Apr 29 02:00:20 PM PDT 2025 -->

<!--te-->

# Identify Memory Device (40h)

## Identify Memory Device (400h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_identify_rsp {
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
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_identify_rsp *ret);
   ```

# Capacity Configuration and Label Storage (41h)

## Get Partition Info (4100h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_partition_info_rsp {
	uint64_t active_vmem;
	uint64_t active_pmem;
	uint64_t next_vmem;
	uint64_t next_pmem;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_partition_info_rsp *ret);
   ```

## Set Partition Info (4101h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_partition_info_req {
	uint64_t volatile_capacity;
	uint8_t flags;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_set_partition_info_req *in);
   ```


## Get LSA (4102h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_get_lsa_req {
	uint32_t offset;
	uint32_t length;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_lsa_req *in,
			     void *ret);
   ```

## Set LSA (4103h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_lsa_req {
	uint32_t offset;
	uint32_t rsvd;
	uint8_t data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_set_lsa_req *in,
			     size_t data_sz);
   ```

# Health Info and Alerts (42h)

## Get Health Info (4200h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_health_info_rsp {
	uint8_t health_status;
	uint8_t media_status;
	uint8_t additional_status;
	uint8_t life_used;
	uint16_t device_temperature;
	uint32_t dirty_shutdown_count;
	uint32_t corrected_volatile_error_count;
	uint32_t corrected_persistent_error_count;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_health_info(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_health_info_rsp *ret);
   ```

## Get Alert Configuration (4201h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_alert_config_rsp {
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
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_alert_config_rsp *ret);
   ```

## Set Alert Configuration (4202h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_alert_config_req {
	uint8_t valid_alert_actions;
	uint8_t enable_alert_actions;
	uint8_t life_used_programmable_warning_threshold;
	uint8_t rsvd1;
	uint16_t device_over_temperature_programmable_warning_threshold;
	uint16_t device_under_temperature_programmable_warning_threshold;
	uint16_t corrected_volatile_mem_error_programmable_warning_threshold;
	uint16_t corrected_persistent_mem_error_programmable_warning_threshold;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_alert_config_req *in);
   ```

## Get Shutdown State (4203h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_shutdown_state_rsp {
	uint8_t state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_shutdown_state_rsp *ret);
   ```

## Set Shutdown State (4204h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_shutdown_state_req {
	uint8_t state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_shutdown_state_req *in);
   ```

# Media and Poison Management (43h)

## Get Poison List (4300h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_get_poison_list_req {
	uint64_t get_poison_list_phy_addr;
	uint64_t get_poison_list_phy_addr_len;
};
   ```

Return payload:

   ```C
struct cxlmi_memdev_media_err_record {
	uint64_t media_err_addr;
	uint32_t media_err_len;
	uint8_t rsvd1[4];
};

struct cxlmi_cmd_memdev_get_poison_list_rsp {
	uint8_t poison_list_flags;
	uint8_t rsv1;
	uint64_t overflow_timestamp;
	uint16_t more_err_media_record_cnt;
	uint8_t rsv2[0x14];
	struct cxlmi_memdev_media_err_record records[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_poison_list(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_poison_list_req *in,
			struct cxlmi_cmd_memdev_get_poison_list_rsp *ret);
   ```

## Inject Poison (4301h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_inject_poison_req {
	uint64_t inject_poison_phy_addr;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_inject_poison(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_inject_poison_req *in);
   ```

## Clear Poison (4302h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_clear_poison_req {
	uint64_t clear_poison_phy_addr;
	uint8_t clear_poison_write_data[64];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_clear_poison(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_memdev_clear_poison_req *in);
   ```

## Get Scan Media Capabilities (4303h)

Input payload:

   ```C
struct cxlmi_cmd_get_scan_media_capabilities_req {
	uint64_t get_scan_media_capabilities_start_physaddr;
	uint64_t get_scan_media_capabilities_physaddr_length;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_get_scan_media_capabilities_rsp {
	uint32_t estimated_scan_media_time;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_scan_media_capabilities(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_get_scan_media_capabilities_req *in,
				  struct cxlmi_cmd_get_scan_media_capabilities_rsp *ret);
   ```

## Scan Media (4304h)

Input payload:

   ```C
struct cxlmi_cmd_scan_media_req {
	uint64_t scan_media_physaddr;
	uint64_t scan_media_physaddr_length;
	uint8_t scan_media_flags;
};
   ```

Command name:

   ```C
int cxlmi_cmd_scan_media(struct cxlmi_endpoint *ep,
			 struct cxlmi_tunnel_info *ti,
			 struct cxlmi_cmd_scan_media_req *in);
   ```

## Get Scan Media Results (4305h)

Return payload:

   ```C
struct cxlmi_media_error_record {
	uint64_t media_error_address;
	uint32_t media_error_length;
	uint8_t rsvd[4];
};

struct cxlmi_cmd_get_scan_media_results_rsp {
	uint64_t scan_media_restart_physaddr;
	uint64_t scan_media_restart_physaddr_length;
	uint8_t scan_media_flags;
	uint8_t rsvd1;
	uint16_t media_error_count;
	uint8_t rsvd2[12];
	struct cxlmi_media_error_record record[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_scan_media_results(struct cxlmi_endpoint *ep,
				     struct cxlmi_tunnel_info *ti,
				     struct cxlmi_cmd_get_scan_media_results_rsp *ret);
   ```


# Sanitize and Media Operations (44h)

## Sanitize (4400h)

No payload.

Command name:

   ```C
int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

## Secure Erase (4401h)

No payload.

Command name:

   ```C
int cxlmi_cmd_memdev_secure_erase(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

## Media Operations (4402h)

The correct class and subclass must be passed as payload inputs for the corresponding
discovery or sanitize operations, otherwise the payloads will not correspond to what
the hardware expects.

Discovery Input payload:

   ```C
struct cxlmi_cmd_memdev_media_operations_discovery_req {
	uint8_t media_operation_class;
	uint8_t media_operation_subclass;
	uint8_t rsvd[2];
	uint32_t dpa_range_count;
	struct {
		uint16_t start_index;
		uint16_t num_ops;
	} discovery_osa;
};
   ```

Discovery Return payload:

   ```C
struct cxlmi_cmd_memdev_media_ops_supported_list_entry {
	uint8_t media_op_class;
	uint8_t media_op_subclass;
};

struct cxlmi_cmd_memdev_media_operations_discovery_rsp {
	uint64_t dpa_range_granularity;
	uint16_t total_supported_ops;
	uint16_t num_supported_ops;
	struct cxlmi_cmd_memdev_media_ops_supported_list_entry entry[];
};
   ```

Discovery Command name:

   ```C
int cxlmi_cmd_memdev_media_operations_discovery(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_media_operations_discovery_req *in,
			struct cxlmi_cmd_memdev_media_operations_discovery_rsp *ret);
   ```

Sanitize Input payload:

   ```C
struct cxlmi_cmd_memdev_media_ops_dpa_range_list_entry {
    uint64_t starting_dpa;
    uint64_t length;
};

struct cxlmi_cmd_memdev_media_operations_sanitize_req {
	uint8_t media_operation_class;
	uint8_t media_operation_subclass;
	uint8_t rsvd[2];
	uint32_t dpa_range_count;
	struct cxlmi_cmd_memdev_media_ops_dpa_range_list_entry dpa_range_list[];
};
   ```

Sanitize Command name:

   ```C
int cxlmi_cmd_memdev_media_operations_sanitize(struct cxlmi_endpoint *ep,
			       struct cxlmi_tunnel_info *ti,
			       struct cxlmi_cmd_memdev_media_operations_sanitize_req *in);
   ```

# Persistent Memory Data-at-rest Security (45h)

## Get Security State (4500h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_security_state_rsp {
	uint32_t security_state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_security_state(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_security_state_rsp *ret);
   ```

## Set Passphrase (4501h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_passphrase_req {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t current_passphrase[0x20];
	uint8_t new_passphrase[0x20];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_passphrase(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_memdev_set_passphrase_req *in);
   ```

## Disable Passphrase (4502h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_disable_passphrase_req {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t passphrase[0x20];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_disable_passphrase(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_disable_passphrase_req *in);
   ```

## Unlock (4503h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_unlock_req {
	uint8_t current_passphrase[0x20];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_unlock(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_memdev_unlock_req *in);
   ```

## Freeze Security State (4504h)

No payload.

Command name:

   ```C
int cxlmi_cmd_memdev_freeze_security_state(struct cxlmi_endpoint *ep,
					struct cxlmi_tunnel_info *ti);
   ```

## Passphrase Secure Erase (4505h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_passphrase_secure_erase_req {
	uint8_t passphrase_type;
	uint8_t rsvd[0x1F];
	uint8_t passphrase[0x20];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_passphrase_secure_erase(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_passphrase_secure_erase_req *in);
   ```

# Security Passthrough (46h)

The library currently supports only discovery Security Protocol per SFSC, and allows
a maximum of 256 maximum protocols to be retrieved for each receive.

## Security Send (4600h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_security_send_req {
       uint8_t security_protocol;
       uint16_t sp_specific;
       uint8_t rsvd[0x5];
       uint8_t data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_security_send(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_security_send_req *in,
				   size_t data_sz);
   ```

## Security Receive (4601h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_security_receive_req {
       uint8_t security_protocol;
       uint16_t sp_specific;
       uint8_t rsvd[0x5];
};
   ```

Output payload: Generic pointer to the Security Protocol specific output data.

Command name:

   ```C
int cxlmi_cmd_memdev_security_receive(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_security_receive_req *in,
			      void *ret);
   ```

# SLD QoS Telemetry (47h)

## Get SLD QoS Control (4700h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_sld_qos_control_rsp {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_sld_qos_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_memdev_get_sld_qos_control_rsp *ret);
   ```

## Set SLD QoS Control (4701h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_sld_qos_control_req {
	uint8_t qos_telemetry_control;
	uint8_t egress_moderate_percentage;
	uint8_t egress_severe_percentage;
	uint8_t backpressure_sample_interval;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_sld_qos_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_memdev_set_sld_qos_control_req *in);
   ```

## Get SLD QoS Status (4702h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_sld_qos_status_rsp {
	uint8_t backpressure_avg_percentage;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_sld_qos_status(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_sld_qos_status_rsp *ret);
   ```

# Dynamic Capacity (48h)

## Get Dynamic Capacity Configuration (4800h)

Note that the returned number of DC region configurations
is limited by the library to 8. This is because of the
change of payload size in newer versions of the specification.

Input payload:

   ```C
struct cxlmi_cmd_memdev_get_dc_config_req {
	uint8_t region_cnt;
	uint8_t start_region_id;
};
   ```

Return payload:

   ```C
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
	} region_configs[8];
	uint32_t num_extents_supported;
	uint32_t num_extents_available;
	uint32_t num_tags_supported;
	uint32_t num_tags_available;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_dc_config(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_dc_config_req *in,
			struct cxlmi_cmd_memdev_get_dc_config_rsp *ret);
   ```

## Get Dynamic Capacity Extent List (4801h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_get_dc_extent_list_req {
		uint32_t extent_cnt;
		uint32_t start_extent_idx;
};
   ```

Return payload:

   ```C
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
	   } extents[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_dc_extent_list(struct cxlmi_endpoint *ep,
					   struct cxlmi_tunnel_info *ti,
					   struct cxlmi_cmd_memdev_get_dc_extent_list_req *in,
					   struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *ret);
   ```

## Add Dynamic Capacity Response (4802h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_add_dc_response_req {
		uint32_t updated_extent_list_size;
		uint8_t flags;
		uint8_t rsvd1[3];
		struct {
				uint64_t start_dpa;
				uint64_t len;
				uint8_t rsvd[8];
		} extents[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_add_dc_response(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_memdev_add_dc_response_req *in);
   ```

## Release Dynamic Capacity (4803h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_release_dc_req {
		uint32_t updated_extent_list_size;
		uint8_t flags;
		uint8_t rsvd1[3];
		struct {
				uint64_t start_dpa;
				uint64_t len;
				uint8_t rsvd[8];
		} extents[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_release_dc(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_release_dc_req *in);
   ```
