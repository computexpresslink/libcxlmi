# libcxlmi Command Support Summary

This document summarizes the support status of CXL commands within the `libcxlmi` library, based on the CXL 3.2 Specification. Overall it the library supports approximately **55%** across all CCI commands listed in the specification.

---

## Generic Component Commands (~76% supported)

| Command Set         | Combined Opcode   | Command Name                               |
| :------------------ | :---------------- | :----------------------------------------- |
| **Information and Status** |                   |                                            |
|                     | ✅ `0001h`        | [Identify](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#identify-0001h)                |
|                     | ✅ `0002h`        | [Background Operation Status](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#background-operation-status-0002h) |
|                     | ✅ `0003h`        | [Get Response Message Limit](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-response-message-limit-0003h) |
|                     | ✅ `0004h`        | [Set Response Message Limit](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#set-response-message-limit-0004h) |
|                     | ✅ `0005h`        | [Request Abort Background Operation](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#request-abort-background-operation-0005h) |
| **Events** |                   |                                            |
|                     | ✅ `0100h`        | [Get Event Records](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-event-records-0100h) |
|                     | ✅ `0101h`        | [Clear Event Records](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#clear-event-records-0101h) |
|                     | ✅ `0102h`        | [Get Event Interrupt Policy](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-event-interrupt-policy-0102h) |
|                     | ✅ `0103h`        | [Set Event Interrupt Policy](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#set-event-interrupt-policy-0103h) |
|                     | ✅ `0104h`        | [Get MCTP Event Interrupt Policy](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-mctp-event-interrupt-policy-0104h) |
|                     | ✅ `0105h`        | [Set MCTP Event Interrupt Policy](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#set-mctp-event-interrupt-policy-0105h) |
|                     | ✅ `0106h`        | [Event Notification](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#event-notification-0106h) |
|                     | `0107h`           | GFD Enhanced Event Notification            |
|                     | `0108h`           | GFD to GAE Enhanced Event Notification   |
|                     | `0109h`           | Get GAM Buffer                             |
|                     | `010Ah`           | Set GAM Buffer                             |
| **Firmware Update** |                   |                                            |
|                     | ✅ `0200h`        | [Get FW Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-fw-info-0200h)          |
|                     | ✅ `0201h`        | [Transfer FW](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#transfer-fw-0201h)          |
|                     | ✅ `0202h`        | [Activate FW](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#activate-fw-0202h)          |
| **Timestamp** |                   |                                            |
|                     | ✅ `0300h`        | [Get Timestamp](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-timestamp-opcode-0300h) |
|                     | ✅ `0301h`        | [Set Timestamp](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#set-timestamp-opcode-0301h) |
| **Logs** |                   |                                            |
|                     | ✅ `0400h`        | [Get Supported Logs](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-supported-logs-0400h) |
|                     | ✅ `0401h`        | [Get Log](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-log-0401h)                 |
|                     | ✅ `0402h`        | [Get Log Capabilities](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-log-capabilities-0402h) |
|                     | ✅ `0403h`        | [Clear Log](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#clear-log-0403h)              |
|                     | ✅ `0404h`        | [Populate Log](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#populate-log-0404h)          |
|                     | ✅ `0405h`        | [Get Supported Logs Sub-List](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Generic-Component-Commands.md#get-supported-logs-sub-list-0405h) |
| **Features** |                   |                                            |
|                     | `0500h`           | Get Supported Features                     |
|                     | `0501h`           | Get Feature                                |
|                     | `0502h`           | Set Feature                                |
| **Maintenance** |                   |                                            |
|                     | `0600h`           | Perform Maintenance                        |
| **PBR Components** |                   |                                            |
|                     | `0700h`           | Identify PBR Component                     |
|                     | `0701h`           | Claim Ownership                            |
|                     | `0702h`           | Read CDAT                                  |

---

## Memory Device Commands (~62% supported)

| Command Set Group                     | Combined Opcode   | Command Name                               |
| :------------------------------------ | :---------------- | :----------------------------------------- |
| **Identify Memory Device** |                   |                                            |
|                                       | ✅ `4000h`        | [Identify Memory Device](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#identify-memory-device-400h) |
| **Capacity Configuration and LSA** |                   |                                            |
|                                       | ✅ `4100h`        | [Get Partition Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-partition-info-4100h) |
|                                       | ✅ `4101h`        | [Set Partition Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-partition-info-4101h) |
|                                       | ✅ `4102h`        | [Get LSA](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-lsa-4102h) |
|                                       | ✅ `4103h`        | [Set LSA](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-lsa-4103h) |
| **Health Info and Alerts** |                   |                                            |
|                                       | ✅ `4200h`        | [Get Health Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-health-info-4200h) |
|                                       | ✅ `4201h`        | [Get Alert Configuration](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-alert-configuration-4201h) |
|                                       | ✅ `4202h`        | [Set Alert Configuration](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-alert-configuration-4202h) |
|                                       | ✅ `4203h`        | [Get Shutdown State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-shutdown-state-4203h) |
|                                       | ✅ `4204h`        | [Set Shutdown State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-shutdown-state-4204h) |
| **Media and Poison Management** |                   |                                            |
|                                       | ✅ `4300h`        | [Get Poison List](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-poison-list-4300h) |
|                                       | ✅ `4301h`        | [Inject Poison](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#inject-poison-4301h) |
|                                       | ✅ `4302h`        | [Clear Poison](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#clear-poison-4302h) |
|                                       | ✅ `4303h`        | [Get Scan Media Capabilities](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-scan-media-capabilities-4303h) |
|                                       | ✅ `4304h`        | [Scan Media](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#scan-media-4304h) |
|                                       | ✅ `4305h`        | [Get Scan Media Results](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-scan-media-results-4305h) |
| **Sanitize and Media Operations** |                   |                                            |
|                                       | ✅ `4400h`        | [Sanitize](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#sanitize-4400h) |
|                                       | ✅ `4401h`        | [Secure Erase](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#secure-erase-4401h) |
|                                       | `4402h`           | Media Operations                         |
| **Persistent Memory Security** |                   |                                            |
|                                       | ✅ `4500h`        | [Get Security State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-security-state-4500h) |
|                                       | ✅ `4501h`        | [Set Passphrase](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-passphrase-4501h) |
|                                       | ✅ `4502h`        | [Disable Passphrase](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#disable-passphrase-4502h) |
|                                       | ✅ `4503h`        | [Unlock](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#unlock-4503h) |
|                                       | ✅ `4504h`        | [Freeze Security State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#freeze-security-state-4504h) |
|                                       | ✅ `4505h`        | [Passphrase Secure Erase](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#passphrase-secure-erase-4505h) |
| **Security Send/Receive** |                   |                                            |
|                                       | `4600h`           | Security Send                            |
|                                       | `4601h`           | Security Receive                         |
| **SLD QoS Telemetry** |                   |                                            |
|                                       | ✅ `4700h`        | [Get SLD QoS Control](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-sld-qos-control-4700h) |
|                                       | ✅ `4701h`        | [Set SLD QoS Control](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#set-sld-qos-control-4701h) |
|                                       | ✅ `4702h`        | [Get SLD QoS Status](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-sld-qos-status-4702h) |
| **Dynamic Capacity** |                   |                                            |
|                                       | ✅ `4800h`        | [Get Dynamic Capacity Configuration](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-dynamic-capacity-configuration-4800h) |
|                                       | ✅ `4801h`        | [Get Dynamic Capacity Extent List](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#get-dynamic-capacity-extent-list-4801h) |
|                                       | ✅ `4802h`        | [Add Dynamic Capacity Response](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#add-dynamic-capacity-response-4802h) |
|                                       | ✅ `4803h`        | [Release Dynamic Capacity](https://github.com/computexpresslink/libcxlmi/blob/main/docs/Memory-Device-Commands.md#release-dynamic-capacity-4803h) |
| **GFD Commands** |                   |                                            |
|                                       | `4900h`           | Identify GFD                             |
|                                       | `4901h`           | Get GFD Status                           |
|                                       | `4902h`           | Get GFD DC Region Configuration          |
|                                       | `4903h`           | Set GFD DC Region Configuration          |
|                                       | `4904h`           | Get GFD DC Region Extent Lists           |
|                                       | `4905h`           | Get GFD DMP Configuration                |
|                                       | `4906h`           | Set GFD DMP Configuration                |
|                                       | `4907h`           | GFD Dynamic Capacity Add                 |
|                                       | `4908h`           | GFD Dynamic Capacity Release             |
|                                       | `4909h`           | GFD Dynamic Capacity Add Reference       |
|                                       | `490Ah`           | GFD Dynamic Capacity Remove Reference    |
|                                       | `490Bh`           | GFD Dynamic Capacity List Tags           |
|                                       | `490Ch`           | Get GFD SAT Entry                        |
|                                       | `490Dh`           | Set GFD SAT Entry                        |
|                                       | `490Eh`           | Get GFD QoS Control                      |
|                                       | `490Fh`           | Set GFD QoS Control                      |
|                                       | `4910h`           | Get GFD QoS Status                       |
|                                       | `4911h`           | Get GFD QoS BW Limit                     |
|                                       | `4912h`           | Set GFD QoS BW Limit                     |
|                                       | `4913h`           | Get GDT Configuration                    |
|                                       | `4914h`           | Set GDT Configuration                    |

---

## FM-API Commands (~42% supported)

| Command Set Group                     | Combined Opcode   | Command Name                               |
| :------------------------------------ | :---------------- | :----------------------------------------- |
| **Physical Switch** |                   |                                            |
|                                       | ✅ `5100h`        | [Identify Switch Device](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#identify-switch-device-5100h) |
|                                       | ✅ `5101h`        | [Get Physical Port State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-physical-port-state-5101h) |
|                                       | ✅ `5102h`        | [Physical Port Control](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#physical-port-control-5102h) |
|                                       | `5103h`           | Send PPB CXL.io Configuration Request    |
|                                       | ✅ `5104h`        | [Get Domain Validation SV State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-domain-validation-sv-state-5104h) |
|                                       | ✅ `5105h`        | [Set Domain Validation SV](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-domain-validation-sv-5105h) |
|                                       | ✅ `5106h`        | [Get VCS Domain Validation SV State](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-vcs-domain-validation-sv-state-5106h) |
|                                       | ✅ `5107h`        | [Get Domain Validation SV](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-domain-validation-sv-5107h) |
| **Virtual Switch** |                   |                                            |
|                                       | `5200h`           | Get Virtual CXL Switch Info              |
|                                       | ✅ `5201h`        | [Bind vPPB](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#bind-vppb-5201h) |
|                                       | ✅ `5202h`        | [Unbind vPPB](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#unbind-vppb-5202) |
|                                       | `5203h`           | Generate AER Event                       |
| **MLD Port** |                   |                                            |
|                                       | ✅ `5300h`        | [Tunnel Management Command](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#tunnel-management-command-5300h) |
|                                       | `5301h`           | Send LD CXL.io Configuration Request     |
|                                       | `5302h`           | Send LD CXL.io Memory Request            |
| **MLD Components** |                   |                                            |
|                                       | ✅ `5400h`        | [Get LD Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-ld-info-5400h) |
|                                       | ✅ `5401h`        | [Get LD Allocations](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-ld-allocations-5401h) |
|                                       | ✅ `5402h`        | [Set LD Allocations](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-ld-allocations-5402h) |
|                                       | ✅ `5403h`        | [Get QoS Control](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-qos-control-5403h) |
|                                       | ✅ `5404h`        | [Set QoS Control](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-qos-control-5404h) |
|                                       | ✅ `5405h`        | [Get QoS Status](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-qos-status-5405h) |
|                                       | ✅ `5406h`        | [Get QoS Allocated BW](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-qos-allocated-bw-5406h) |
|                                       | ✅ `5407h`        | [Set QoS Allocated BW](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-qos-allocated-bw-5407h) |
|                                       | ✅ `5408h`        | [Get QoS BW Limit](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-qos-bw-limit-5408h) |
|                                       | ✅ `5409h`        | [Set QoS BW Limit](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-qos-bw-limit-5409h) |
| **Multi-Headed Devices** |                   |                                            |
|                                       | ✅ `5500h`        | [Get Multi-Headed Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-multi-headed-info-5500h) |
|                                       | `5501h`           | Get Head Info                            |
| **DCD Management** |                   |                                            |
|                                       | ✅ `5600h`        | [Get DCD Info](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-dcd-info-5600h) |
|                                       | ✅ `5601h`        | [Get Host DC Region Config](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-host-dc-region-config-5601h) |
|                                       | ✅ `5602h`        | [Set DC Region Configuration](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#set-host-dc-region-config-5602h) |
|                                       | ✅ `5603h`        | [Get DC Region Extent Lists](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#get-dc-region-extent-lists-5603h) |
|                                       | ✅ `5604h`        | [Initiate DC Add](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#initiate-dc-add-5604h) |
|                                       | ✅ `5605h`        | [Initiate DC Release](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#initiate-dc-release-5605h) |
|                                       | ✅ `5606h`        | [DC Add Reference](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#dc-add-reference-5606h) |
|                                       | ✅ `5607h`        | [DC Remove Reference](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#dc-remove-reference-5607h) |
|                                       | ✅ `5608h`        | [DC List Tags](https://github.com/computexpresslink/libcxlmi/blob/main/docs/FM-API.md#dc-list-tags-5608h) |
| **PBR Switch** |                   |                                            |
|                                       | `5700h`           | Identify PBR Switch                      |
|                                       | `5701h`           | Fabric Crawl Out                         |
|                                       | `5702h`           | Get PBR Link Partner Info                |
|                                       | `5703h`           | Get PID Target List                      |
|                                       | `5704h`           | Configure PID Assignment                 |
|                                       | `5705h`           | Get PID Binding                          |
|                                       | `5706h`           | Configure PID Binding                    |
|                                       | `5707h`           | Get Table Descriptors                    |
|                                       | `5708h`           | Get DRT                                  |
|                                       | `5709h`           | Set DRT                                  |
|                                       | `570Ah`           | Get RGT                                  |
|                                       | `570Bh`           | Set RGT                                  |
|                                       | `570Ch`           | Get LDST/IDT Capabilities                |
|                                       | `570Dh`           | Set LDST/IDT Configuration               |
|                                       | `570Eh`           | Get LDST Segment Entries                 |
|                                       | `570Fh`           | Set LDST Segment Entries                 |
|                                       | `5710h`           | Get LDST IDT DPID Entries                |
|                                       | `5711h`           | Set LDST IDT DPID Entries                |
|                                       | `5712h`           | Get Completer ID-Based Re-Router Entries |
|                                       | `5713h`           | Set Completer ID-Based Re-Router Entries |
|                                       | `5714h`           | Get LDST Access Vector                   |
|                                       | `5715h`           | Get VCS LDST Access Vector               |
|                                       | `5716h`           | Configure VCS LDST Access                |
| **Global Access Endpoint (GAE)** |                   |                                            |
|                                       | `5800h`           | Identify GAE                             |
|                                       | `5801h`           | Get PID Interrupt Vector                 |
|                                       | `5802h`           | Get PID Access Vectors                   |
|                                       | `5803h`           | Get FAST/IDT Capabilities                |
|                                       | `5804h`           | Set FAST/IDT Configuration               |
|                                       | `5805h`           | Get FAST Segment Entries                 |
|                                       | `5806h`           | Set FAST Segment Entries                 |
|                                       | `5807h`           | Get IDT DPID Entries                     |
|                                       | `5808h`           | Set IDT DPID Entries                     |
|                                       | `5809h`           | Proxy GFD Management Command             |
|                                       | `580Ah`           | Get Proxy Thread Status                  |
|                                       | `580Bh`           | Cancel Proxy Thread                      |
| **VCS GAE** |                   |                                            |
|                                       | `5900h`           | Identify VCS GAE                         |
|                                       | `5901h`           | Get VCS PID Access Vectors               |
|                                       | `5902h`           | Configure VCS PID Access                 |
|                                       | `5903h`           | Get VendPrefixLO State                   |
|                                       | `5904h`           | Set VendPrefixLO State                   |
