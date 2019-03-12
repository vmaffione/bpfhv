#!/bin/bash

##################### Setup hugepages #######################
# This is needed by both Snabb and OVS-DPDK.
# There are various methods: run-time allocation, sysctl,
# boot parameters, let's go with the simpler.
# Append 'hugepages=256' to the kernel
# boot cmdline and reboot the system.
# This will allocate 256 2M hugepages, and enable IOMMU (VT-d).
# Enable VT-d in the BIOS, if present.
#
# Check that hugepages are there:
#
#     $ grep -i huge /proc/meminfo
#
# Check that /dev/hugepages is mounted, otherwise mount it:
#
#     # mkdir /dev/hugepages
#     # mount -t hugetlbfs nodev /dev/hugepages

IMG="${1:-/home/vmaffione/git/vm/netmap.qcow2}"
SOCK=/var/run/vm20-20.socket
NOGRAPHIC=-nographic
sudo qemu-system-x86_64 ${IMG} \
        -enable-kvm -smp 2 -m 512M -vga std ${NOGRAPHIC} \
        -device e1000,netdev=mgmt,mac=00:AA:BB:CC:0a:99 \
        -netdev user,id=mgmt,hostfwd=tcp::20020-:22 \
        -numa node,memdev=mem0 \
        -object memory-backend-file,id=mem0,size=512M,mem-path=/dev/hugepages,share=on \
        -device bpfhv-pci,netdev=data20,mac=00:AA:BB:CC:0a:0a \
        -netdev type=bpfhv-proxy,id=data20,chardev=char20 \
        -chardev socket,id=char20,path=${SOCK},server

# sudo socat - UNIX-CONNECT:/var/run/vm20-20.socket
