# <--------------- XML files defining input ------------------------------>
GENERIC_COMMANDS = "inputs/generic-commands.xml"
FMAPI_COMMANDS = "inputs/fmapi-commands.xml"

# <--------------- Supported Topologies ------------------------------>

# 1 direct-attached T3 device
# NO MCTP
DIRECT_T3 = "-object memory-backend-file,id=cxl-mem1,share=on,mem-path=/tmp/cxltest.raw,size=512M \
-object memory-backend-file,id=cxl-lsa1,share=on,mem-path=/tmp/lsa.raw,size=1M \
-device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
-device cxl-rp,port=0,bus=cxl.1,id=root_port13,chassis=0,slot=2 \
-device cxl-type3,bus=root_port13,memdev=cxl-mem1,lsa=cxl-lsa1,id=cxl-pmem0,sn=0xabcd \
-M cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=8k"

# 1 DCD with 2 DC regions direct attached to the host
# and with 1 i2c bus for MCTP
FM_DCD = "-object memory-backend-file,id=cxl-mem1,mem-path=/tmp/t3_cxl1.raw,size=4G \
-device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
-device cxl-rp,port=0,bus=cxl.1,id=cxl_rp_port0,chassis=0,slot=2 \
-device cxl-type3,bus=cxl_rp_port0,volatile-dc-memdev=cxl-mem1,id=cxl-dcd0,num-dc-regions=2,sn=99 \
-machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=1k \
-device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=4,target=cxl-dcd0"

# <--------------- Topo Map ------------------------------>
"""
Map of topology to:
- input: path to XML file defining commands to test on it
- qemu_str: its QEMU string
- mctp: nid:eid tuple of EP to open
- ioctl: name of device if ioctl EP opened
"""
SUITES = {
    "GENERIC" : {
        "input": GENERIC_COMMANDS,
        "qemu_str" : DIRECT_T3,
        "mctp" : None,
        "ioctl" : "mem0"},
    "FMAPI" : {
        "input": FMAPI_COMMANDS,
        "qemu_str" : FM_DCD,
        "mctp" : (11, 8),
        "ioctl" : "mem0"},
}