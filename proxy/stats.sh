#!/bin/bash

which termeter 1>/dev/null
if [ "$?" != 0 ]; then
    echo "Install termeter (go get github [...])"
    exit 1
fi

sudo perf stat -a -e 'kvm:kvm_exit,kvm:kvm_inj_virq' --log-fd 1 -I 30 | $(dirname $0)/trans-to-termeter.py -n 2 | termeter -d " "
