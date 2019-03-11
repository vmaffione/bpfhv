#!/bin/bash

IF=tapx
IPADDR=10.0.0.10/24
SOCK=/var/run/vm20-20.socket

sigint() {
    sudo ip link set $IF down
    sudo ip link del $IF
}
trap 'sigint' INT

set -x
sudo ip tuntap add mode tap name $IF
sudo ip link set $IF up
sudo ip addr add $IPADDR dev $IF
sudo proxy/backend -p $SOCK -t $IF -v $@
sigint
