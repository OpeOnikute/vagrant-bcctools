#!/usr/bin/python3

# Record Power-of-2 histograms for Disk I/O completion
# You can write it in another way by getting the length of bytes from the req argument
# instead. Can do that later as a little exercise.
# You can fund the function defined here for Linux 4.15: https://elixir.bootlin.com/linux/v4.15/source/block/blk-core.c#L2565
# And you can find req defined as a struct here: https://elixir.bootlin.com/linux/v4.15/source/include/linux/blkdev.h#L135
# It's currently void now because BPF complains if you don't include where it's defined.
from bcc import BPF

from time import sleep

b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);

int kprobe__blk_account_io_completion(struct pt_regs *ctx, void *req, unsigned int bytes) {
    dist.increment(bpf_log2l(bytes/1024));
    return 0;
}
""")

print("Tracing block I/O... Hit Ctrl+C to end.")

try:
    sleep(9999999)
except KeyboardInterrupt:
    print()

# output
b["dist"].print_log2_hist("kbytes")