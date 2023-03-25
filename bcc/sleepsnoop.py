#!/usr/bin/python

# This example showcases the use of a perf event buffer to return
# results instead of trace_printk()

from bcc import BPF

b = BPF(text="""
#include <linux/sched.h>

struct data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(events);

int kprobe__do_nanosleep(void *ctx) {
    // this needs to be initalised because BPF won't allow
    // you to use unassigneed memory 
    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.ts = bpf_ktime_get_ns() / 1000;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
};
""")

print("%-18s %-6s %-6s %s" % ("TIME(s)", "PID", "COMM", "CALL"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-18.9f %-6d %-6s Hello World!" % ((float(event.ts) / 10000000), event.pid, event.comm))


# Register the callback with the perf buffer
b["events"].open_perf_buffer(print_event)

while 1:
    try:
        b.perf_buffer_poll()
        # You could add a small sleep here to buffer results and reduce overhead
    except KeyboardInterrupt:
        exit()