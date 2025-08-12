# <--------------- XML files defining input ------------------------------>
MAILBOX_COMMANDS = "inputs/mailbox-commands.xml"
MCTP_COMMANDS = "inputs/mctp-commands.xml"

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
# and with 1 MCTP USB bus
FM_DCD = "-device usb-ehci,id=ehci \
     -object memory-backend-file,id=cxl-mem1,mem-path=/tmp/t3_cxl1.raw,size=4G \
     -object memory-backend-file,id=cxl-lsa1,mem-path=/tmp/t3_lsa1.raw,size=1M \
     -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
     -device cxl-rp,port=0,bus=cxl.1,id=cxl_rp_port0,chassis=0,slot=2 \
     -device cxl-upstream,port=2,sn=1234,bus=cxl_rp_port0,id=us0,addr=0.0,multifunction=on, \
     -device cxl-switch-mailbox-cci,bus=cxl_rp_port0,addr=0.1,target=us0 \
     -device cxl-downstream,port=0,bus=us0,id=swport0,chassis=0,slot=4 \
     -device cxl-type3,bus=swport0,volatile-dc-memdev=cxl-mem1,id=cxl-dcd0,lsa=cxl-lsa1,num-dc-regions=2,sn=99 \
     -device usb-cxl-mctp,bus=ehci.0,id=usb0,target=us0 \
     -device usb-cxl-mctp,bus=ehci.0,id=usb1,target=cxl-dcd0\
     -machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=1k"

# <--------------- Topo Map ------------------------------>
"""
Map of topology to:
- input: path to XML file defining commands to test on it
- qemu_str: its QEMU string
- mctp: nid:eid tuple of EP to open
- ioctl: name of device if ioctl EP opened
"""
SUITES = {
    "MAILBOX" : {
        "input": MAILBOX_COMMANDS,
        "qemu_str" : DIRECT_T3,
        "mctp" : None,
        "ioctl" : "mem0"},
    "MCTP" : {
        "input": MCTP_COMMANDS,
        "qemu_str" : FM_DCD,
        "mctp" : (1, 8),
        "ioctl" : "mem0"},
}