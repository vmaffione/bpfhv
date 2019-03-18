#!/usr/bin/env python

import argparse
import sys
import re


argparser = argparse.ArgumentParser()
argparser.add_argument('-n', '--num-metrics', required=True,
                       help = "How many perf-stat metrics to look for",
                       type = int)

args = argparser.parse_args()
if args.num_metrics < 1:
    print("At least one metric is needed")
    quit(1)

fmtstr = '%s ' * (args.num_metrics)
fmtstr.strip()
header = True
last_time = 0.0

try:
    mcnt = 0
    values = [0] * (args.num_metrics)
    metrics = [''] * (args.num_metrics)

    while True:
        line = sys.stdin.readline()
        tokens = line.split()
        if len(tokens) != 3:
            continue
        val = float(tokens[1].replace(',', ''))
        metric = tokens[2]

        values[mcnt] = val
        if header:
            metrics[mcnt] = metric
            if mcnt+1 == args.num_metrics:
                header = False
                print(fmtstr % tuple(metrics))
        mcnt += 1
        if mcnt == args.num_metrics:
            # Samples are counters, so we need to compute the rate.
            time = float(tokens[0])
            for i in range(len(values)):
                values[i] = values[i] / (time-last_time)
            last_time = time
            mcnt = 0
            print(fmtstr % tuple(values))
            sys.stdout.flush()
except KeyboardInterrupt:
    pass
