#!/usr/bin/python
#
# nodejs_http_server    Basic example of node.js USDT tracing.
#                       For Linux, uses BCC, BPF. Embedded C.
#
# USAGE: nodejs_http_server PID
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF, USDT
from bcc.utils import printb
import sys

if len(sys.argv) < 2:
    print("USAGE: nodejs_http_server PID")
    exit()
pid = sys.argv[1]
debug = 0

# load BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>

int do_entry(struct pt_regs *ctx) {
    bpf_trace_printk("hello");
    return 0;
};
"""

if debug:
    print(bpf_text)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_uprobe(name="/var/src/node/out/Release/node", sym="uv_fs_read", fn_name="do_entry")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "ARGS"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        print("value error")
        continue
    except KeyboardInterrupt:
        exit()
    printb(b"%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))