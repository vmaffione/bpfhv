#!/bin/bash

which termeter 1>/dev/null
if [ "$?" != 0 ]; then
    echo "Install termeter (go get github [...])"
    exit 1
fi

STATS="kvm:kvm_mmio,kvm:kvm_inj_virq,kvm:kvm_exit"
NUM_STATS=3
sudo perf stat -a -e ${STATS} --log-fd 1 -I 100 | $(dirname $0)/trans-to-termeter.py -n ${NUM_STATS} | termeter -d " "
