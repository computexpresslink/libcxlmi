The C000h-FFFFh opcode range describes vendor-specific commands, per the CXL specification. The command must pass the opcode along any input/output payload buffers. If the buffers are passed along invalid sizes, an error is returned. Same with payload sizes with nil buffers.

Command name:

   ```C
int cxlmi_cmd_vendor_specific(struct cxlmi_endpoint *ep,
			      struct cxlmi_tunnel_info *ti,
			      uint16_t opcode,
			      void *in, ssize_t in_size,
			      void *ret, ssize_t ret_size);
   ```
