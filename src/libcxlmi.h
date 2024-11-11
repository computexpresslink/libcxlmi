// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of libcxlmi.
 */
#ifndef __LIBCXLMI_H__
#define __LIBCXLMI_H__

#include "cxlmi/api-types.h"
#include "cxlmi/log.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cxlmi_ctx;
struct cxlmi_endpoint;

/**
 * cxlmi_new_ctx() - Create top-level MI context handle.
 * @fp:		File descriptor for logging messages
 * @log_level:	Logging level to use (standard syslog)
 *
 * Create the top-level library handle for creating subsequent
 * endpoint objects.
 *
 * Return: new context object, or NULL on failure.
 *
 * See &cxlmi_free_ctx.
 */
struct cxlmi_ctx *cxlmi_new_ctx(FILE *fp, int log_level);

/**
 * cxlmi_free_ctx() - Free context object.
 * @ctx: context to free
 *
 * See &cxlmi_new_ctx.
 */
void cxlmi_free_ctx(struct cxlmi_ctx *ctx);

/**
 * cxlmi_open_mctp() - Create an endpoint using a MCTP connection.
 * @ctx: library context object to create under
 * @netid: MCTP network ID on this system
 * @eid: MCTP endpoint ID
 *
 * Transport-specific endpoint initialization for MI-connected endpoints.
 *
 * Return: New endpoint object for @netid & @eid, or NULL on failure.
 *
 * See &cxlmi_close
 */
struct cxlmi_endpoint *cxlmi_open_mctp(struct cxlmi_ctx *ctx,
				       unsigned int net, uint8_t eid);

/**
 * cxlmi_scan_mctp() - look for MCTP-connected CXL-MI endpoints.
 * @ctx: library context object to create under
 *
 * Description: This function queries the system MCTP daemon ("mctpd") over
 * D-Bus, to find MCTP endpoints that report support for CXL-MI over MCTP.
 *
 * This requires libcxlmi to be compiled with D-Bus support; if not, this
 * will return -1.
 *
 * Return: The number of opened MCTP endpoints after the scan, or -1
 * upon failure.
 *
 * See &cxlmi_open_mctp
 */
int cxlmi_scan_mctp(struct cxlmi_ctx *ctx);

/**
 * cxlmi_open() - Create an endpoint to send commands over a Mailbox.
 * @ctx: library context object to create under
 * @devname: cxl device to open (/under dev/cxl/<device>)
 *
 * Mailbox-specific (ioctl) endpoint initialization.
 *
 * Return: New endpoint object for @devname, or NULL on failure.
 *
 * See &cxlmi_close
 */
struct cxlmi_endpoint *cxlmi_open(struct cxlmi_ctx *ctx, const char *devname);

/**
 * cxlmi_close() - Close an endpoint connection and release resources
 *
 * @ep: Endpoint object to close
 *
 * See &cxlmi_open, &cxlmi_open_mctp
 */
void cxlmi_close(struct cxlmi_endpoint *ep);

/**
 * cxlmi_set_probe_enabled() - enable/disable the probe for new endpoints
 * @ctx: &cxlmi_ctx object
 * @enabled: whether to probe new endpoints
 *
 * Controls whether newly-created endpoints are probed upon creation.
 * Defaults to enabled, which results in some initial messaging with the
 * endpoint to determine model-specific details, such as CXL component type.
 */
void cxlmi_set_probe_enabled(struct cxlmi_ctx *ctx, bool enabled);

/**
 * cxlmi_endpoint_get_timeout - get the current timeout value for CXL-MI
 * responses
 * @ep: MI endpoint object
 *
 * Returns the current timeout value, in milliseconds, for this endpoint.
 */
unsigned int cxlmi_endpoint_get_timeout(struct cxlmi_endpoint *ep);

/**
 * cxlmi_endpoint_set_timeout - set a timeout for CXL-MI responses
 * @ep: MI endpoint object
 * @timeout_ms: Timeout for MI responses, given in milliseconds
 */
int cxlmi_endpoint_set_timeout(struct cxlmi_endpoint *ep,
			       unsigned int timeout_ms);

/**
 * cxlmi_endpoint_has_fmapi - determine whether or not the underlying
 * the library can send FM-API commands.
 * @ep: MI endpoint object
 *
 * Returns true if the FM-API commands are accepted/supported by this
 * device (and is opened by the lib). Otherwise, false.
 **/
bool cxlmi_endpoint_has_fmapi(struct cxlmi_endpoint *ep);

/**
 * cxlmi_endpoint_enable_fmapi - attempt to enable FM-API command set.
 * @ep: MI endpoint object
 *
 * Allows FM-API commands to be used if supported by the underlying CXL
 * component. Only makes sense to use if probing was disabled previously.
 *
 * Returns true if FM-API is enabled, otherwise false.
 **/
bool cxlmi_endpoint_enable_fmapi(struct cxlmi_endpoint *ep);

/**
 * cxlmi_endpoint_disable_fmapi - disable the FM-API command set.
 * @ep: MI endpoint object
 *
 * Returns true if the FM-API commands are disabled, or false otherwise.
 **/
bool cxlmi_endpoint_disable_fmapi(struct cxlmi_endpoint *ep);


/**
 * cxlmi_first_endpoint - Start endpoint iterator
 * @ctx: &cxlmi_ctx object
 *
 * Return: first MI endpoint object under this context, or NULL if no endpoints
 *         are present. This library does not guarantee any order upon endpoint
 *         enumeration.
 *
 * See: &cxlmi_next_endpoint, &cxlmi_for_each_endpoint
 */
struct cxlmi_endpoint *cxlmi_first_endpoint(struct cxlmi_ctx *ctx);

/**
 * cxlmi_next_endpoint - Continue endpoint iterator
 * @ctx: &cxlmi_ctx object
 * @ep: &cxlmi_endpoint current position of iterator
 *
 * Return: next endpoint MI endpoint object after @e under this root, or NULL
 *         if no further endpoints are present.
 *
 * See: &cxlmi_first_endpoint, &cxlmi_for_each_endpoint
 */
 struct cxlmi_endpoint *cxlmi_next_endpoint(struct cxlmi_ctx *ctx,
					    struct cxlmi_endpoint *ep);
/**
 * cxlmi_for_each_endpoint - Iterator for CXL-MI endpoints.
 * @m: &cxlmi_ctx containing endpoints
 * @e: &cxlmi_endpoint object, set on each iteration
 */
#define cxlmi_for_each_endpoint(m, e)			\
	for (e = cxlmi_first_endpoint(m); e != NULL;	\
	     e = cxlmi_next_endpoint(m, e))

/**
 * cxlmi_for_each_endpoint_safe - Iterator for CXL-MI endpoints, allowing
 * deletion during traversal
 * @m: &cxlmi_ctx containing endpoints
 * @e: &cxlmi_endpoint object, set on each iteration
 * @_e: &cxlmi_endpoint object used as temporary storage
 */
#define cxlmi_for_each_endpoint_safe(m, e, _e)				\
	for (e = cxlmi_first_endpoint(m), _e = cxlmi_next_endpoint(m, e); \
	     e != NULL;							\
	     e = _e, _e = cxlmi_next_endpoint(m, e))

/**
 * enum cxlmi_cmd_retcode - CXL-defined Command Return Codes
 * @CXLMI_RET_SUCCESS:            Success
 * @CXLMI_RET_BACKGROUND:         Background operation started (Success).
 * @CXLMI_RET_INPUT:              One or more command inputs are invalid.
 * @CXLMI_RET_UNSUPPORTED:        The command is not supported
 * @CXLMI_RET_INTERNAL:           The command was not completed because of an
				  internal device error.
 * @CXLMI_RET_RETRY:              The command was not completed because of a
				  temporary error. An optional single retry may
				  resolve the issue.
 * @CXLMI_RET_BUSY:               The device is currently busy processing a
				  background operation.
				  Wait until background command completes and then
				  retry the command.
 * @CXLMI_RET_MEDIADISABLED:      The command could not be completed because it
				  requires media access and media is disabled.
 * @CXLMI_RET_FWINPROGRESS:       Only one FW package can be transferred at a time.
				  Complete the current FW package transfer before
				  starting a new one.
 * @CXLMI_RET_FWOOO:              The FW package transfer was aborted because
				  the FW package content was transferred out
				  of order.
 * @CXLMI_RET_FWAUTH:             The FW package was not saved to the device
				  because the FW package verification failed.
 * @CXLMI_RET_FWSLOT:             The FW slot specified is not supported or not
				  valid for the requested operation.
 * @CXLMI_RET_FWROLLBACK:         The new FW failed to activate and rolled back
				  to the previous active FW.
 * @CXLMI_RET_FWRESET:            The new FW failed to activate. A cold reset is
				  required.
 * @CXLMI_RET_HANDLE:             One or more Event Record Handles were invalid
				  or specified out of order.
 * @CXLMI_RET_PADDR:              The physical address specified is invalid.
 * @CXLMI_RET_POISONLMT:          The device’s limit on allowed poison injection
				  has been reached. Clear injected poison requests
				  before attempting to inject more.
 * @CXLMI_RET_MEDIAFAILURE:       The device could not clear poison because of a
				  permanent issue with the media.
 * @CXLMI_RET_ABORT:              The background command was aborted by the device.
				  either on its own or as a result of a Request
				  Abort Background Operation command.
 * @CXLMI_RET_SECURITY:           The command is invalid in the current
				  security state.
 * @CXLMI_RET_PASSPHRASE:         The passphrase does not match the currently
				  set passphrase.
 * @CXLMI_RET_MBUNSUPPORTED:      The command is not supported on the mailbox
				  or CCI it was issued on.
 * @CXLMI_RET_PAYLOADLEN:         The input payload length specified for the
				  command is invalid or exceeds the component’s
				  Maximum Supported Message Size. The device is
				  required to perform this check prior to
				  processing any command defined in this
				  specification.
 * @CXLMI_RET_LOG:                The log page is not supported or not valid.
 * @CXLMI_RET_INTERRUPTED:        The command could not be successfully completed
				  because of an asynchronous event.
 * @CXLMI_RET_FEATUREVERSION:     The Feature version in the input payload is not
				  supported.
 * @CXLMI_RET_FEATURESELVALUE:    The selection value in the input payload is not
				  supported.
 * @CXLMI_RET_FEATURETRANSFERIP:  Only one Feature data can be transferred at a
				  time for each Feature. Complete the current
				  Feature data transfer before starting a new one.
 * @CXLMI_RET_FEATURETRANSFEROOO: The Feature data transfer was aborted because
				  the Feature data content was transferred out
				  of order.
 * @CXLMI_RET_RESOURCEEXHAUSTED:  The Device cannot perform the operation as
				  resources are exhausted.
 * @CXLMI_RET_EXTLIST:            The Dynamic Capacity Extent List contains
				  invalid starting DPA and length
 * @CXLMI_RET_TRANSFEROOO:        The input parameters data transfer was aborted
				  because it occurred out of order.
 * @CXLMI_RET_NO_BGABORT:         The ongoing background operation does not
				  support the Request Abort command.
*/
enum cxlmi_cmd_retcode {
	CXLMI_RET_SUCCESS = 0x0,
	CXLMI_RET_BACKGROUND,
	CXLMI_RET_INPUT,
	CXLMI_RET_UNSUPPORTED,
	CXLMI_RET_INTERNAL,
	CXLMI_RET_RETRY,
	CXLMI_RET_BUSY,
	CXLMI_RET_MEDIADISABLED,
	CXLMI_RET_FWINPROGRESS,
	CXLMI_RET_FWOOO,
	CXLMI_RET_FWAUTH,
	CXLMI_RET_FWSLOT,
	CXLMI_RET_FWROLLBACK,
	CXLMI_RET_FWRESET,
	CXLMI_RET_HANDLE,
	CXLMI_RET_PADDR,
	CXLMI_RET_POISONLMT,
	CXLMI_RET_MEDIAFAILURE,
	CXLMI_RET_ABORT,
	CXLMI_RET_SECURITY,
	CXLMI_RET_PASSPHRASE,
	CXLMI_RET_MBUNSUPPORTED,
	CXLMI_RET_PAYLOADLEN,
	CXLMI_RET_LOG,
	CXLMI_RET_INTERRUPTED,
	CXLMI_RET_FEATUREVERSION,
	CXLMI_RET_FEATURESELVALUE,
	CXLMI_RET_FEATURETRANSFERIP,
	CXLMI_RET_FEATURETRANSFEROOO,
	CXLMI_RET_RESOURCEEXHAUSTED,
	CXLMI_RET_EXTLIST,
	CXLMI_RET_TRANSFEROOO,
	CXLMI_RET_NO_BGABORT,
};

/**
 * cxlmi_cmd_retcode_tostr - Convert a CXL-defined return code to a string
 * @code: &cxlmi_cmd_retcode return code.
 *
 * Returned string is const, and should not be free()ed.
 *
 * Return: a string describing the return code, otherwise NULL if undefined.
 */
const char *cxlmi_cmd_retcode_tostr(enum cxlmi_cmd_retcode code);

/**
 * cxlmi_tunnel_info - Tunneling information associated with a specific command
 * @port: switch downstream port number
 * @ld: Logical Device (LD) id within an MLD
 * @level: tunneling level 1 or 2.
 *
 * When sent to an MLD, the provided command is tunneled by the FM-owned LD
 * to the specified LD. This can include an additional layer of tunneling for
 * commands issued on LDs in an MLD that is accessible through an MLD port
 * of a CXL Switch.
 *
 * Tunneling targets are:
 *   - valid LDs within an MLD - single level tunneling
 *   - switch MLD ports - double level tunneling
 */
struct cxlmi_tunnel_info {
	int port;
	int ld;
	int level;
};

/*
 * Definitions for Generic Component Commands, per CXL r3.1 Table 8-37.
 */
int cxlmi_cmd_identify(struct cxlmi_endpoint *ep,
		       struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_identify *ret);
int cxlmi_cmd_bg_op_status(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_bg_op_status *ret);
int cxlmi_cmd_get_response_msg_limit(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_get_response_msg_limit *ret);
int cxlmi_cmd_set_response_msg_limit(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_set_response_msg_limit *in);
int cxlmi_cmd_request_bg_op_abort(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti);

#define CXLMI_MAX_SUPPORTED_EVENT_RECORDS 20
int cxlmi_cmd_get_event_records(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_get_event_records_req *in,
				struct cxlmi_cmd_get_event_records_rsp *ret);
int cxlmi_cmd_clear_event_records(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti,
				  struct cxlmi_cmd_clear_event_records *in);
int cxlmi_cmd_get_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_event_interrupt_policy *ret);
int cxlmi_cmd_set_event_interrupt_policy(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_set_event_interrupt_policy *in);
int cxlmi_cmd_get_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_get_mctp_event_interrupt_policy *ret);
int cxlmi_cmd_set_mctp_event_interrupt_policy(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_set_mctp_event_interrupt_policy *in);
int cxlmi_cmd_event_notification(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_event_notification *in);

int cxlmi_cmd_get_fw_info(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_fw_info *out);
int cxlmi_cmd_transfer_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_transfer_fw *in);
int cxlmi_cmd_activate_fw(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_activate_fw *in);

int cxlmi_cmd_get_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_get_timestamp *ret);
int cxlmi_cmd_set_timestamp(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_set_timestamp *in);

#define CXLMI_MAX_SUPPORTED_LOGS 7
int cxlmi_cmd_get_supported_logs(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_get_supported_logs *ret);
int cxlmi_cmd_get_log(struct cxlmi_endpoint *ep,
		      struct cxlmi_tunnel_info *ti,
		      struct cxlmi_cmd_get_log_req *in,
		      void *ret);
int cxlmi_cmd_get_log_cel(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_log_req *in,
			  struct cxlmi_cmd_get_log_cel_rsp *ret);
int cxlmi_cmd_get_log_capabilities(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_get_log_capabilities_req *in,
			   struct cxlmi_cmd_get_log_capabilities_rsp *ret);
int cxlmi_cmd_clear_log(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_clear_log *in);
int cxlmi_cmd_populate_log(struct cxlmi_endpoint *ep,
			   struct cxlmi_tunnel_info *ti,
			   struct cxlmi_cmd_populate_log *in);
int cxlmi_cmd_get_supported_logs_sublist(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_get_supported_logs_sublist_req *in,
			  struct cxlmi_cmd_get_supported_logs_sublist_rsp *ret);


/*
 * Definitions for Memory Device Commands, per CXL r3.1 Table 8-126.
 */
int cxlmi_cmd_memdev_identify(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_identify *ret);

int cxlmi_cmd_memdev_get_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_partition_info *ret);
int cxlmi_cmd_memdev_set_partition_info(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_set_partition_info *in);
int cxlmi_cmd_memdev_get_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_lsa *ret);
int cxlmi_cmd_memdev_set_lsa(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_set_lsa *in);

int cxlmi_cmd_memdev_get_health_info(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_get_health_info *ret);
int cxlmi_cmd_memdev_get_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_alert_config *ret);
int cxlmi_cmd_memdev_set_alert_config(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_alert_config *in);
int cxlmi_cmd_memdev_get_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_get_shutdown_state *ret);
int cxlmi_cmd_memdev_set_shutdown_state(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      struct cxlmi_cmd_memdev_set_shutdown_state *in);

int cxlmi_cmd_get_poison_list(struct cxlmi_endpoint *ep,
					struct cxlmi_tunnel_info *ti,
					struct cxlmi_cmd_memdev_get_poison_list_req *in,
					struct cxlmi_cmd_memdev_get_poison_list_rsp *ret);
int cxlmi_cmd_memdev_inject_poison(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_inject_poison *in);
int cxlmi_cmd_memdev_clear_poison(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_memdev_clear_poison *in);

int cxlmi_cmd_memdev_sanitize(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti);
int cxlmi_cmd_memdev_secure_erase(struct cxlmi_endpoint *ep,
				  struct cxlmi_tunnel_info *ti);

int cxlmi_cmd_memdev_get_security_state(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_security_state *ret);
int cxlmi_cmd_memdev_set_passphrase(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_memdev_set_passphrase *in);
int cxlmi_cmd_memdev_disable_passphrase(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_disable_passphrase *in);
int cxlmi_cmd_memdev_unlock(struct cxlmi_endpoint *ep,
			    struct cxlmi_tunnel_info *ti,
			    struct cxlmi_cmd_memdev_unlock *in);
int cxlmi_cmd_memdev_freeze_security_state(struct cxlmi_endpoint *ep,
					   struct cxlmi_tunnel_info *ti);
int cxlmi_cmd_memdev_passphrase_secure_erase(struct cxlmi_endpoint *ep,
			     struct cxlmi_tunnel_info *ti,
			     struct cxlmi_cmd_memdev_passphrase_secure_erase *in);

int cxlmi_cmd_memdev_get_sld_qos_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_memdev_get_sld_qos_control *ret);
int cxlmi_cmd_memdev_set_sld_qos_control(struct cxlmi_endpoint *ep,
				 struct cxlmi_tunnel_info *ti,
				 struct cxlmi_cmd_memdev_set_sld_qos_control *in,
				 struct cxlmi_cmd_memdev_set_sld_qos_control *ret);
int cxlmi_cmd_memdev_get_sld_qos_status(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_get_sld_qos_status *ret);

int cxlmi_cmd_memdev_get_dc_config(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_dc_config_req *in,
			struct cxlmi_cmd_memdev_get_dc_config_rsp *ret);
int cxlmi_cmd_memdev_get_dc_extent_list(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_memdev_get_dc_extent_list_req *in,
			struct cxlmi_cmd_memdev_get_dc_extent_list_rsp *ret);
int cxlmi_cmd_memdev_add_dc_response(struct cxlmi_endpoint *ep,
			  struct cxlmi_tunnel_info *ti,
			  struct cxlmi_cmd_memdev_add_dc_response *in);
int cxlmi_cmd_memdev_release_dc(struct cxlmi_endpoint *ep,
				struct cxlmi_tunnel_info *ti,
				struct cxlmi_cmd_memdev_release_dc *in);

/*
 * Definitions for FMAPI Commands. per CXL r3.1 Table 8-215.
 */
int cxlmi_cmd_fmapi_identify_sw_device(struct cxlmi_endpoint *ep,
		       struct cxlmi_tunnel_info *ti,
		       struct cxlmi_cmd_fmapi_identify_sw_device *ret);
int cxlmi_cmd_fmapi_get_phys_port_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_phys_port_state_req *in,
			struct cxlmi_cmd_fmapi_get_phys_port_state_rsp *ret);
int cxlmi_cmd_fmapi_phys_port_control(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_phys_port_control *in);
int cxlmi_cmd_fmapi_get_domain_validation_sv_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_domain_validation_sv_state *ret);
int cxlmi_cmd_fmapi_set_domain_validation_sv(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_domain_validation_sv *in);
int cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_req *in,
			struct cxlmi_cmd_fmapi_get_vcs_domain_validation_sv_state_rsp *ret);
int cxlmi_cmd_fmapi_get_domain_validation_sv(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_domain_validation_sv_req *in,
			struct cxlmi_cmd_fmapi_get_domain_validation_sv_rsp *ret);
int cxlmi_cmd_fmapi_get_ld_info(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_ld_info *ret);
int cxlmi_cmd_fmapi_get_ld_allocations(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_ld_allocations_req *in,
			struct cxlmi_cmd_fmapi_get_ld_allocations_rsp *ret);
int cxlmi_cmd_fmapi_set_ld_allocations(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_ld_allocations_req *in,
			struct cxlmi_cmd_fmapi_set_ld_allocations_rsp *ret);
int cxlmi_cmd_fmapi_get_qos_control(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_fmapi_get_qos_control *ret);
int cxlmi_cmd_fmapi_set_qos_control(struct cxlmi_endpoint *ep,
				    struct cxlmi_tunnel_info *ti,
				    struct cxlmi_cmd_fmapi_set_qos_control *in,
				    struct cxlmi_cmd_fmapi_set_qos_control *ret);
int cxlmi_cmd_fmapi_get_qos_status(struct cxlmi_endpoint *ep,
				   struct cxlmi_tunnel_info *ti,
				   struct cxlmi_cmd_fmapi_get_qos_status *ret);
int cxlmi_cmd_fmapi_get_qos_allocated_bw(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_qos_allocated_bw_req *in,
			struct cxlmi_cmd_fmapi_get_qos_allocated_bw_rsp *ret);
int cxlmi_cmd_fmapi_set_qos_allocated_bw(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_qos_allocated_bw *in,
			struct cxlmi_cmd_fmapi_set_qos_allocated_bw *ret);
int cxlmi_cmd_fmapi_get_qos_bw_limit(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_get_qos_bw_limit_req *in,
			struct cxlmi_cmd_fmapi_get_qos_bw_limit_rsp *ret);
int cxlmi_cmd_fmapi_set_qos_bw_limit(struct cxlmi_endpoint *ep,
			struct cxlmi_tunnel_info *ti,
			struct cxlmi_cmd_fmapi_set_qos_bw_limit *in,
			struct cxlmi_cmd_fmapi_set_qos_bw_limit *ret);
#ifdef __cplusplus
}
#endif
#endif
