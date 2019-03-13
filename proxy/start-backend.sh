#!/bin/bash

IF=tapx
IPADDR=10.0.0.10/24
SOCK=/var/run/vm20-20.socket

sigint() {
    echo "$0 interrupted"
    sudo ip link set $IF down
    sudo ip link del $IF
    exit 0
}
trap 'sigint' INT

set -x
sudo ip tuntap add mode tap name $IF
# Re-use the same MAC address (rather than a random address)
# so that the guest ARP table remains valid across multiple
# executions of this script (e.g. to restart the backend).
HSH=$(echo $IF | md5sum | awk '{print $1}')
HSH=${HSH:0:2}
sudo ip link set $IF address be:c7:54:8a:13:${HSH}
sudo ip link set $IF up
sudo ip addr add $IPADDR dev $IF
sudo proxy/backend -p $SOCK -t $IF -v $@
sigint
