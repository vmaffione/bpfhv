#!/bin/bash

sudo qemu-system-x86_64 /home/vmaffione/git/vm/netmap.qcow2 \
        -enable-kvm -smp 2 -m 2G -vga std \
        -device e1000,netdev=mgmt,mac=00:AA:BB:CC:0a:99 \
        -netdev user,id=mgmt,hostfwd=tcp::20020-:22 \
        -device bpfhv-pci,netdev=data20,mac=00:AA:BB:CC:0a:0a \
        -netdev type=bpfhv-proxy,id=data20,chardev=char20 \
        -chardev socket,id=char20,path=/var/run/vm20-20.socket,server

# sudo socat - UNIX-CONNECT:/var/run/vm20-20.socket
