#!/usr/bin/python3
from bcc import BPF
# Use a shortcut to instrument a kprobe. Format is kprobe__<function_name>
# Basic example for hello world
b = BPF(text="""
int kprobe__do_nanosleep()
{
    //printk is only used for debugging because it can clash with the output of
    //other tools as they use the same buffer.
    //The buffer can be read from /sys/kernel/debug/tracing/trace_pipe/
    //Use the perf events buffer instead, as seen in sleepsnoop.py
    bpf_trace_printk("Hello World!\\n");
    return 0;
}""");

# Fetch the trace 
b.trace_print();