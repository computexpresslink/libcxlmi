The following are the supported CXL commands belonging to the Generic Component
command set, as per the latest specification.

<!--ts-->
* [Information and Status (00h)](#information-and-status-00h)
   * [Identify (0001h)](#identify-0001h)
   * [Background Operation Status (0002h)](#background-operation-status-0002h)
   * [Get Response Message Limit (0003h)](#get-response-message-limit-0003h)
   * [Set Response Message Limit (0004h)](#set-response-message-limit-0004h)
   * [Request Abort Background Operation (0005h)](#request-abort-background-operation-0005h)
* [Events (01h)](#events-01h)
   * [Get Event Records (0100h)](#get-event-records-0100h)
   * [Clear Event Records (0101h)](#clear-event-records-0101h)
   * [Get Event Interrupt Policy (0102h)](#get-event-interrupt-policy-0102h)
   * [Set Event Interrupt Policy (0103h)](#set-event-interrupt-policy-0103h)
   * [Get MCTP Event Interrupt Policy (0104h)](#get-mctp-event-interrupt-policy-0104h)
   * [Set MCTP Event Interrupt Policy (0105h)](#set-mctp-event-interrupt-policy-0105h)
   * [Event Notification (0106h)](#event-notification-0106h)
* [Firmware Update (02h)](#firmware-update-02h)
   * [Get FW Info (0200h)](#get-fw-info-0200h)
   * [Transfer FW (0201h)](#transfer-fw-0201h)
   * [Activate FW (0202h)](#activate-fw-0202h)
* [Timestamp (03h)](#timestamp-03h)
   * [Get Timestamp (Opcode 0300h)](#get-timestamp-opcode-0300h)
   * [Set Timestamp (Opcode 0301h)](#set-timestamp-opcode-0301h)
* [Logs (04h)](#logs-04h)
   * [Get Supported Logs (0400h)](#get-supported-logs-0400h)
   * [Get Log Capabilities (0402h)](#get-log-capabilities-0402h)
   * [Clear Log (0403h)](#clear-log-0403h)
   * [Populate Log (0404h)](#populate-log-0404h)
   * [Get Supported Logs Sub-List (0405h)](#get-supported-logs-sub-list-0405h)
* [Features (05h)](#features-05h)
	* [Get Supported Features (0500h)](#get-supported-features-0500h)

<!-- Created by https://github.com/ekalinin/github-markdown-toc -->
<!-- Added by: dave, at: Tue May 21 04:42:32 PM PDT 2024 -->

<!--te-->

# Information and Status (00h)

## Identify (0001h)

Return payload:

   ```C
struct cxlmi_cmd_identify {
	uint16_t vendor_id;
	uint16_t device_id;
	uint16_t subsys_vendor_id;
	uint16_t subsys_id;
	uint64_t serial_num;
	uint8_t max_msg_size;
	uint8_t component_type;
};
   ```

Command name:

   ```C
int cxlmi_cmd_identify(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti, struct cxlmi_cmd_identify *ret)
   ```

## Background Operation Status (0002h)

Return payload:

   ```C
struct cxlmi_cmd_bg_op_status {
	uint8_t status;
	uint8_t rsvd;
	uint16_t opcode;
	uint16_t returncode;
	uint16_t vendor_ext_status;
};
   ```
Command name:

   ```C
int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti, struct cxlmi_cmd_bg_op_status *ret);
   ```

## Get Response Message Limit (0003h)

Return payload:

   ```C
struct cxlmi_cmd_get_response_msg_limit {
	uint8_t limit;
};
   ```
Command name:

   ```C
int cxlmi_cmd_get_response_msg_limit(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_response_msg_limit *ret);
   ```

## Set Response Message Limit (0004h)

Input payload:

   ```C
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
};
   ```
Return payload:

   ```C
struct cxlmi_cmd_set_response_msg_limit {
	uint8_t limit;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
					 struct cxlmi_tunnel_info *ti,
					 struct cxlmi_cmd_set_response_msg_limit *in,
					 struct cxlmi_cmd_set_response_msg_limit *ret);
   ```

## Request Abort Background Operation (0005h)

No payload.

Command Name

   ```C
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

# Events (01h)

Events reported by devices through the 0100h  command. The device shall use
the Common Event Record format when generating events for any event log:

   ```C
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
};
   ```

The types of events can be any of:

- `fbcd0a77-c260-417f-85a9-088b1621eba6` – General Media Event Record
- `601dcbb3-9c06-4eab-b8af-4e9bfb5c9624` – DRAM Event Record
- `fe927475-dd59-4339-a586-79bab113b774` – Memory Module Event Record
- `e71f3a40-2d29-4092-8a39-4d1c966c7c65` - Memory Sparing Event Record
- `77cf9271-9c02-470b-9fe4-bc7b75f2da97` – Physical Switch Event Record
- `40d26425-3396-4c4d-a5da-3d47263af425` – Virtual Switch Event Record
- `8dc44363-0c96-4710-b7bf-04bb99534c3f` – MLD Port Event Record
- `ca95afa7-f183-4018-8c2f-95268e101a2a` - Dynamic Capacity Event Record

## Get Event Records (0100h)

This command shall retrieve as many event records from the
event log that fit into the mailbox output payload (20 records).

Input payload:

   ```C
struct cxlmi_cmd_get_event_records_req {
	uint8_t event_log;
};
   ```
Return payload:

   ```C
struct cxlmi_cmd_get_event_records_rsp {
	uint8_t flags;
	uint8_t reserved1;
	uint16_t overflow_err_count;
	uint64_t first_overflow_timestamp;
	uint64_t last_overflow_timestamp;
	uint16_t record_count;
	uint8_t reserved2[0xa];
	struct cxlmi_event_record records[];
};
   ```
Command name:

   ```C
int cxlmi_cmd_get_event_records(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_get_event_records_req *in,;
				struct cxlmi_cmd_get_event_records_rsp *ret);
   ```

## Clear Event Records (0101h)

Input payload:


   ```C
struct cxlmi_cmd_clear_event_records {
	uint8_t event_log;
	uint8_t clear_flags;
	uint8_t nr_recs;
	uint8_t reserved[3];
	uint16_t handles[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_clear_event_records(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_clear_event_records *in);
   ```

## Get Event Interrupt Policy (0102h)

Return payload:

   ```C
struct cxlmi_cmd_get_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_event_interrupt_policy *ret);
   ```

## Set Event Interrupt Policy (0103h)

Input payload:

   ```C
struct cxlmi_cmd_set_event_interrupt_policy {
	uint8_t informational_settings;
	uint8_t warning_settings;
	uint8_t failure_settings;
	uint8_t fatal_settings;
	uint8_t dcd_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_set_event_interrupt_policy *in);
   ```

## Get MCTP Event Interrupt Policy (0104h)

Return payload:

   ```C
struct cxlmi_cmd_get_mctp_event_interrupt_policy {
	uint16_t event_interrupt_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_get_mctp_event_interrupt_policy *ret);
   ```

## Set MCTP Event Interrupt Policy (0105h)

Input payload:

   ```C
struct cxlmi_cmd_set_mctp_event_interrupt_policy {
	uint16_t event_interrupt_settings;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_set_mctp_event_interrupt_policy *in);
   ```

## Event Notification (0106h)

Input payload:

   ```C
struct cxlmi_cmd_event_notification {
	uint16_t event;
};
   ```

Command name:

   ```C
int cxlmi_cmd_event_notification(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_event_notification *in);
   ```

# Firmware Update (02h)

## Get FW Info (0200h)

Return payload:

   ```C
struct cxlmi_cmd_get_fw_info {
	uint8_t slots_supported;
	uint8_t slot_info;
	uint8_t caps;
	uint8_t rsvd[0xd];
	char fw_rev1[0x10];
	char fw_rev2[0x10];
	char fw_rev3[0x10];
	char fw_rev4[0x10];
};
   ```

Command Name:

   ```C
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep, struct cxlmi_tunnel_info *ti);
   ```

## Transfer FW (0201h)

Input payload:

   ```C
struct cxlmi_cmd_transfer_fw {
	uint8_t action;
	uint8_t slot;
	uint8_t rsvd1[2];
	uint32_t offset;
	uint8_t rsvd2[0x78];
	uint8_t data[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_transfer_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_transfer_fw *in);
   ```

## Activate FW (0202h)

Input payload:

   ```C
struct cxlmi_cmd_activate_fw {
	uint8_t action;
	uint8_t slot;
};
   ```

Command name:

   ```C
int cxlmi_cmd_activate_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_activate_fw *in);
   ```

# Timestamp (03h)

## Get Timestamp (Opcode 0300h)

Return payload:
   ```C
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_get_timestamp *ret);
   ```

## Set Timestamp (Opcode 0301h)

Input payload:

   ```C
struct cxlmi_cmd_set_timestamp {
	uint64_t timestamp;
};
   ```

Command name:

   ```C
int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_set_timestamp *in);
   ```

# Logs (04h)

Both 0400h and 0405h use the common supported log entry:

   ```C
struct cxlmi_supported_log_entry {
	uint8_t uuid[0x10];
	uint32_t log_size;
};
   ```

The latest specification defines the following possible log entries, capped
by `CXLMI_MAX_SUPPORTED_LOGS`:

- `0da9c0b5-bf41-4b78-8f79-96b1623b3f17` – Command Effects Log (CEL)
- `5e1819d9-11a9-400c-811f-d60719403d86` – Vendor Debug Log
- `b3fab4cf-01b6-4332-943e-5e9962f23567` – Component State Dump Log
- `f1720d60-a7a9-4306-a003-11948f9e077c` – DDR5 Error Check Scrub (ECS) Log
- `e6dfa32c-d13e-4a5c-8ca8-99bebbf731a4` – Media Test Capability Log
- `2c255522-8ce4-11ec-b909-0242ac120002` – Media Test Results Short Log
- `c1fe0b3e-7a00-448e-a24e-a6aabbfe587a` – Media Test Results Long Log

## Get Supported Logs (0400h)

Return payload:

  ```C
struct cxlmi_cmd_get_supported_logs {
	uint16_t num_supported_log_entries;
	uint8_t reserved[6];
	struct cxlmi_supported_log_entry entries[];
};
  ```

Command name:

   ```C
int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_supported_logs *ret);
   ```

## Get Log (0401h)

General command name:

   ```C
int cxlmi_cmd_get_log(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_log_req *in,
			  void *ret);
   ```

CEL-specific command name:

   ```C
int cxlmi_cmd_get_log_cel(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_log_req *in,
			  struct cxlmi_cmd_get_log_cel_rsp *ret);
   ```


## Get Log Capabilities (0402h)

Input payload:

   ```C
struct cxlmi_cmd_get_log_capabilities_req {
	uint8_t uuid[0x10];
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_get_log_capabilities_rsp {
	uint32_t parameter_flags;
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_log_capabilities(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_get_log_capabilities_req *in,
			   struct cxlmi_cmd_get_log_capabilities_rsp *ret);
   ```

## Clear Log (0403h)

Input payload:

   ```C
struct cxlmi_cmd_clear_log {
	uint8_t uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_clear_log(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_clear_log *in);
   ```

## Populate Log (0404h)

Input payload:

   ```C
struct cxlmi_cmd_populate_log {
	uint8_t uuid[0x10];
};
   ```

Command name:

   ```C
int cxlmi_cmd_populate_log(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_populate_log *in);
   ```

## Get Supported Logs Sub-List (0405h)

Input payload:

   ```C
struct cxlmi_cmd_get_supported_logs_sublist_req {
	uint8_t max_supported_log_entries;
	uint8_t start_log_entry_index;
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_get_supported_logs_sublist_rsp {
	uint8_t num_supported_log_entries;
	uint8_t rsvd1;
	uint16_t total_num_supported_log_entries;
	uint8_t start_log_entry_index;
	uint8_t rsvd2[0x3];
	struct cxlmi_supported_log_entry entries[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_supported_logs_sublist(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_supported_logs_sublist_req *in,
			  struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret);
   ```

# Features (05h)

## Get Supported Features (0500h)

Input payload:

   ```C
struct cxlmi_cmd_get_supported_features_req {
	uint32_t count;
	uint16_t starting_feature_index;
	uint8_t rsvd[2];
};
   ```

Return payload:

   ```C
struct cxlmi_cmd_get_supported_features_rsp {
	uint32_t num_supported_feature_entries;
	uint16_t device_supported_features;
	uint8_t rsvd[4];
	struct {
		uint8_t feature_id[0x10];
		uint16_t feature_index;
		uint16_t get_feature_size;
		uint16_t set_feature_size;
		uint32_t attribute_flags;
		uint8_t get_feature_version;
		uint8_t set_feature_version;
		uint16_t set_feature_effects;
		uint8_t rsvd[18];
	} supported_feature_entries[];
};
   ```

Command name:

   ```C
int cxlmi_cmd_get_supported_features(struct cxlmi_endpoint *ep,
	struct cxlmi_tunnel_info *ti,
	struct cxlmi_cmd_get_supported_features_req *in,
	struct cxlmi_cmd_get_supported_features_rsp *ret);
   ```