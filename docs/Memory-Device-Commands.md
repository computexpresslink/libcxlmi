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
* [Sanitize and Media Operations (44h)](#sanitize-and-media-operations-44h)
   * [Sanitize (4400h)](#sanitize-4400h)
   * [Secure Erase (4401h)](#secure-erase-4401h)
* [Persistent Memory Data-at-rest Security](#persistent-memory-data-at-rest-security)
   * [Get Security State](#get-security-state)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Mon May 20 03:21:37 PM PDT 2024 -->

<!--te-->

# Identify Memory Device (40h)

## Identify Memory Device (400h)

Return payload:

   ```C
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
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_identify *ret);
   ```

# Capacity Configuration and Label Storage (41h)

## Get Partition Info (4100h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_partition_info {
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
				struct cxlmi_cmd_memdev_get_partition_info *ret);
   ```

## Set Partition Info (4101h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_partition_info {
	uint64_t volatile_capacity;
	uint8_t flags;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_set_partition_info *in);
   ```


## Get LSA (4102h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_lsa {
	uint32_t offset;
	uint32_t length;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_lsa *ret);
   ```

## Set LSA (4103h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_set_lsa {
	uint32_t offset;
	uint32_t rsvd;
	uint8_t data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_set_lsa *in);
   ```

# Health Info and Alerts (42h)

## Get Health Info (4200h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_health_info {
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
			     struct cxlmi_cmd_memdev_get_health_info *ret);
   ```

## Get Alert Configuration (4201h)

Return payload:

   ```C
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
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_alert_config *ret);
   ```

## Set Alert Configuration (4202h)

Input payload:

   ```C
struct cxlmi_cmd_memdev_get_alert_config {
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
			      struct cxlmi_cmd_memdev_set_alert_config *in);
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


# Persistent Memory Data-at-rest Security (45h)

## Get Security State (4500h)

Return payload:

   ```C
struct cxlmi_cmd_memdev_get_security_state {
	uint32_t security_state;
};
   ```

Command name:

   ```C
int cxlmi_cmd_memdev_get_security_state(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_security_state *ret);
   ```