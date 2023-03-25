from bcc import BPF
from time import sleep, strftime

# EXERCISE
# Rewrite this to use tracepoints instead of kernel probes.
# You'd only be able to test on a 4.7+ machine though.
countdown = 10
debug = 1

bpf_text= """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

typedef struct disk_key {
    char disk[DISK_NAME_LEN];
    u64 slot;
} disk_key_t;
BPF_HASH(start, struct request *);
STORAGE

//time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;

    // fetch ts and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        return 0; // missed issue
    }
    delta = bpf_ktime_get_ns() - *tsp;
    FACTOR

    //store as histogram
    STORE

    start.delete(&req);
    return 0;
}
"""
milliseconds = True
if milliseconds:
    bpf_text = bpf_text.replace("FACTOR", "delta /= 1000000;")
    label = "msecs"
else:
    bpf_text = bpf_text.replace("FACTOR", "delta /= 1000;")
    label = "usecs"

disks=1
if disks:
    bpf_text = bpf_text.replace("STORAGE",
        "BPF_HISTOGRAM(dist, disk_key_t);")
    disks_str = """
    disk_key_t key = {.slot = bpf_log2l(delta)};
    void *__tmp = (void *)req->rq_disk->disk_name;
    bpf_probe_read(&key.disk, sizeof(key.disk), __tmp);
    dist.increment(key);
    """
    # The commented-out code below results in a memory dereference error.
    # I need to understand why this happens, even though I have a vague idea. 
    # 
    # bpf: Failed to load program: Permission denied
    # HINT: The invalid mem access 'inv' error can happen if you try to dereference 
    # memory without first using bpf_probe_read() to copy it to the BPF stack. 
    # Sometimes the bpf_probe_read is automatic by the bcc rewriter, other times 
    # you'll need to be explicit.
    #
    # ANSWER
    # That error is fixed by using a temporary void pointer instead of trying to dereference in bpf_probe_read directly
    # It makes sense because the error complains about dereferencing memory without copying to the BPF stack first.
    # Somehow, a void pointer is fine to be dereferenced. In this case, the BCC rewriter did not do the bpf_probe_read
    # automatically, but in some cases it will.
    #
    # From ChatGPT:
    # void *__tmp: declares a pointer variable named __tmp of type void *, which means it can point to any type of data.
    # (void *): casts the character string to a void pointer to avoid a compiler warning. Since __tmp is a void pointer, this cast is valid.
    #
    #
    #
    #
    # bpf_text = bpf_text.replace("STORE",
    #     "disk_key_t key = {.slot = bpf_log2l(delta)}; " +
    #     "bpf_probe_read(&key.disk, sizeof(key.disk), " +
    #     "req->rq_disk->disk_name); dist.increment(key);"
    # )
    bpf_text = bpf_text.replace("STORE", disks_str)
else:
    bpf_text = bpf_text.replace("STORAGE", "BPF_HISTOGRAM(dist);")
    bpf_text = bpf_text.replace("STORE",
        "dist.increment(bpf_log2l(delta));"    
    )

if debug:
    print(bpf_text)

b = BPF(text=bpf_text)
queued=True
if queued:
    b.attach_kprobe(event="blk_account_io_start", fn_name="trace_req_start")
else:
    b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
    b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion", fn_name="trace_req_completion")

print("Tracing block device I/O... Hit Ctrl+C to end.")

interval=1
exiting = 0 if interval else 1
dist = b.get_table("dist")

while True:
    try:
        sleep(int(interval))
    except KeyboardInterrupt:
        exiting = 1
    print()

    timestamp=True
    if timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"))
    
    dist.print_log2_hist(label, "disk")
    dist.clear()

    countdown -= 1
    if exiting or countdown == 0:
        exit()