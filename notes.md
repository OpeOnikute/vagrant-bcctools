Things you can do

Build node with debug symbols https://github.com/nodejs/node/blob/main/BUILDING.md
```
git clone https://github.com/nodejs/node.git
git checkout v12.x
./configure --debug
# The -j4 option will cause make to run 4 simultaneous compilation jobs which may reduce build time.
make -j4
```

Uprobes
- List uprobes by listing the segment symbols in the Node binary using a tool like objdump or nm.
- If you are looking to trace a specific node function, grep for the name .e.g. ReadFile
    ```
    root@vagrant:/home/vagrant# nm -C /node/out/Release/node | grep ReadFile
    0000000000f0e860 T v8::internal::ReadFile[abi:cxx11](_IO_FILE*, bool*, bool)
    0000000000f0e390 T v8::internal::ReadFile[abi:cxx11](char const*, bool*, bool)
    root@vagrant:/home/vagrant# objdump -tT /node/out/Release/node | grep ReadFile
    0000000000f0e390 g     F .text  00000000000004d0              _ZN2v88internal8ReadFileB5cxx11EPKcPbb
    0000000000f0e860 g     F .text  00000000000004ac              _ZN2v88internal8ReadFileB5cxx11EP8_IO_FILEPbb
    0000000000f0e860 g    DF .text  00000000000004ac  Base        _ZN2v88internal8ReadFileB5cxx11EP8_IO_FILEPbb
    0000000000f0e390 g    DF .text  00000000000004d0  Base        _ZN2v88internal8ReadFileB5cxx11EPKcPbb
    ```
- Looks like the right way to list USDT probes is by using the BCC tplist
    ```
    root@vagrant:/home/vagrant# /usr/share/bcc/tools/tplist -l /node/out/Release/node

    # or on a running process
    tplist -p `pgrep node`
    ```

- You can also check using readelf
    ```
    # readelf -n /mnt/src/node-v6.7.0/node
    [...]
    Displaying notes found at file offset 0x01814014 with length 0x000003c4:
    Owner                 Data size   Description
    stapsdt              0x0000003c   NT_STAPSDT (SystemTap probe descriptors)
        Provider: node
        Name: gc__start
        Location: 0x00000000011552f4, Base: 0x0000000001a444e4, Semaphore: 0x0000000001e13fdc
        Arguments: 4@%esi 4@%edx 8@%rdi
    [...]
    ```
- You have to build Node with USDT Probes using:
    ```
    $ sudo apt-get install systemtap-sdt-dev   # adds "dtrace", used by node build
    $ ./configure --with-dtrace
    $ make -j4
    ```

Bpftrace
- After getting uprobes, use bpftrace to trace the execution of the probe, do a histogram etc
    ```
    bpftrace -e "uprobe:/node/out/Release/node:"
    ```

- Install new Cmake
    ```
    127  sudo apt remove --purge --auto-remove cmake
    128  sudo apt update && sudo apt install -y software-properties-common lsb-release && sudo apt clean all
    129  wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | sudo tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
    130  sudo apt-add-repository "deb https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main"
    131  sudo apt update
    132  sudo apt install kitware-archive-keyring
    133  sudo rm /etc/apt/trusted.gpg.d/kitware.gpg
    134  sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 6AF7F09730B3F0A4
    135  sudo apt update
    136  sudo apt install cmake
    137  cmake --version
    ```


Misc
- There's a patch to list all uprobes in the system using perf, but I don't think it's everywhere yet https://www.spinics.net/lists/linux-perf-users/msg25434.html
- It might also be possible to add the uprobe using perf https://docs.windriver.com/bundle/Wind_River_Linux_Debug_and_Analysis_Command_Line_Tutorials_8.0_1/page/qnn1554301431820.html. This makes sense because I've not been able to confirm that the debug symbols contained in Node are uprobes too. I don't think they are.
- Nice long post from Julia Evans about Linux tracing as a whole https://jvns.ca/blog/2017/07/05/linux-tracing-systems/#ftrace
- Having trouble adding uprobes for basic Node library functions. Which is weird because they do exist:
    ```
    root@vagrant:/home/vagrant# perf probe -F -x /node/out/Release/node | grep ReadFile
    v8::internal::ReadFile[abi:cxx11]
    v8::internal::ReadFile[abi:cxx11]
    ```
    Or do they? Maybe my goal should be to understand why this doesn't work, but perf record actually does.
- Hm so debug symbols are just to add more information for a debugger? Not a tracing tool? That's why perf doesn't recognize stuff gotten from the output of even perf -F? The symbols are used to show you the function name. That's the same thing with the perf .map file?
- If I can't add a uprobe to Node, can I add a symbol to the underlying C libraries that are called? How can I see what C functions are being executed in Node? The perf out out should contain it?
    ```
    pgrep -n node
    sudo perf record -F 99 -p 11285 -g
    cat perf.data 
    sudo perf script > perfs.out
    cat ./perfs.out
    ```
- It seems like the lower level calls are abstracted away using the V8 engine, which does make sense, but how do we see them? e.g. I can't see a simple file read call in any of the perf stacks, but I see v8 internal calls. Are those the read function calls?
    ```
    node 11285 76792.523658:   10101010 cpu-clock: 
                 11979c0 Builtins_HandleApiCall (/node/out/Release/node)
                 1196c24 Builtins_InterpreterEntryTrampoline (/node/out/Release/node)
                 1196c24 Builtins_InterpreterEntryTrampoline (/node/out/Release/node)
                 1196c24 Builtins_InterpreterEntryTrampoline (/node/out/Release/node)
                 1196c24 Builtins_InterpreterEntryTrampoline (/node/out/Release/node)
                 1196c24 Builtins_InterpreterEntryTrampoline (/node/out/Release/node)
                 119419d Builtins_JSEntryTrampoline (/node/out/Release/node)
                 1193f78 Builtins_JSEntry (/node/out/Release/node)
                  a978d9 v8::internal::Execution::Call (/node/out/Release/node)
                  93b9d2 v8::Function::Call (/node/out/Release/node)
                  6e2b76 node::InternalMakeCallback (/node/out/Release/node)
                  6f2886 node::AsyncWrap::MakeCallback (/node/out/Release/node)
                  86428e node::StreamBase::CallJSOnreadMethod (/node/out/Release/node)
                  864512 node::EmitToJSStreamListener::OnStreamRead (/node/out/Release/node)
                  7a0430 non-virtual thunk to node::(anonymous namespace)::Parser::OnStreamRead(long, uv_buf_t const&) (/node/out/Release/node)
                  86f95e node::LibuvStreamWrap::ReadStart()::{lambda(uv_stream_s*, long, uv_buf_t const*)#2}::_FUN (/node/out/Release/node)
                 1182ab0 uv__read (/node/out/Release/node)
                 11830c8 uv__stream_io (/node/out/Release/node)
                 118a2c5 uv__io_poll (/node/out/Release/node)
                 117655a uv_run (/node/out/Release/node)
                  7cd38d node::NodeMainInstance::Run (/node/out/Release/node)
                  74db82 node::Start (/node/out/Release/node)
                   21c87 __libc_start_main (/lib/x86_64-linux-gnu/libc-2.27.so)
         afe258d4c544155 [unknown] ([unknown])
    ```

- Good post on Node internals to help understand how open() works https://www.smashingmagazine.com/2020/04/nodejs-internals/ 
    ```
    What we learn here is that for every module called from the binding object in the JavaScript section of the Node.js project, there is an equivalent of it in the C++ section, in the src folder.

    From our fs tour, we see that the module that does this is located in node_file.cc. Every function that is accessible through the module is defined in the file; for example, we have the writeBuffer on line 2258. The actual definition of that method in the C++ file is on line 1785. Also, the call to the part of libuv that does the actual writing to the file can be found on lines 1809 and 1815, where the libuv function uv_fs_write is called asynchronously.
    ```

    - Can you trace a node call by looking for the libuv equivalent of the call, and attaching a uprobe to it? e.g. uv_fs_write
        - Where are the lib uv functions defined?
            - They are documented in `deps/uv/docs/src/fs.rst`
            - Github also has a search thing. You can just search for the function in the Node repo? https://github.com/iovisor/bcc/search?q=bpf_usdt_readarg+path%3Aexamples&type=Code
        - How do you attach a uprobe?
            - You can attach one with BCC https://android.googlesource.com/platform/external/bcc/+/HEAD/docs/reference_guide.md#4_uprobes.
            - And if you can do it with BCC, you can probably do it with bpftrace too.
        - Are those functions in the debug symbols?
            - Yeah looks like. This means it's entirely possible to trace by finding the lower level libuv call? Even if you can't get the entire Node stack, you can at least tell what Node process is triggering it, and how often?
                ```
                vagrant@bullseye:~$ objdump -tT /var/src/node/out/Release/node | grep uv_fs_write
                000000000112b460 g     F .text  0000000000000147              uv_fs_write
                000000000112b460 g    DF .text  0000000000000147  Base        uv_fs_write
                vagrant@bullseye:~$ objdump -tT /var/src/node/out/Release/node | grep uv_fs_read
                000000000112a9a0 g     F .text  00000000000000c5              uv_fs_readdir
                000000000112a650 g     F .text  0000000000000147              uv_fs_read
                000000000112ab20 g     F .text  00000000000000e4              uv_fs_readlink
                000000000112a650 g    DF .text  0000000000000147  Base        uv_fs_read
                000000000112ab20 g    DF .text  00000000000000e4  Base        uv_fs_readlink
                000000000112a9a0 g    DF .text  00000000000000c5  Base        uv_fs_readdir
                ```

- What sticks out here is that libuv functions are the uv__read etc seen above. So that means we can trace Node specific actions by tracing libuv?
    ```
    root@vagrant:/home/vagrant# cat ./perfs.out
    node 11285 76792.523658:   10101010 cpu-clock:
    [...]
    1182ab0 uv__read (/node/out/Release/node)
    11830c8 uv__stream_io (/node/out/Release/node)
    118a2c5 uv__io_poll (/node/out/Release/node)
    117655a uv_run (/node/out/Release/node)
    ```

- Node (V8?) has an internal tracing API that has C functions like TRACE_EVENT_API_GET_NUM_TRACES_RECORDED. Wonder how this is used, or if you can tap into it?

- The source for this Async function call confirms that the actual call is hidden in that v8 engine function call in the stack
    ```
    // Returns nullptr if the operation fails from the start.
    template <typename Func, typename... Args>
    FSReqBase* AsyncDestCall(Environment* env, FSReqBase* req_wrap,
                            const v8::FunctionCallbackInfo<v8::Value>& args,
                            const char* syscall, const char* dest,
                            size_t len, enum encoding enc, uv_fs_cb after,
                            Func fn, Args... fn_args) {
    CHECK_NOT_NULL(req_wrap);
    req_wrap->Init(syscall, dest, len, enc);
    int err = req_wrap->Dispatch(fn, fn_args..., after);
    if (err < 0) {
        uv_fs_t* uv_req = req_wrap->req();
        uv_req->result = err;
        uv_req->path = nullptr;
        after(uv_req);  // after may delete req_wrap if there is an error
        req_wrap = nullptr;
    } else {
        req_wrap->SetReturnValue(args);
    }

    return req_wrap;
    }
    ```

    This def makes it difficult to correlate Node with the kernel

- The next step would be to look into the v8 engine calls to see if we can bring out more information? Compile v8 with debug too?
    - Is there a way to enable v8 tracing on Node?
    - The v8 inspector is too heavy to add to production workloads, making a case for using USDT probes instead

- But first, it's time to get info about why ebpf tracing has not been added to node yet. That could give more hints ✅
    - The Node Diagnostics WG hasn't decided to work on this yet https://github.com/nodejs/diagnostics/issues/386
        - Tbh I could just start cloning Node and chipping in with probes, tests here and there.
        - BUT DO I WANT TO COMMIT TO BEING AN ACTIVE MAINTAINER OF PROBES IN NODE? ESPECIALLY BC I DON'T HAVE C EXPERIENCE.
    - This comment (https://github.com/nodejs/diagnostics/issues/386#issuecomment-623789130) is important. Most Node users don't really care about the interaction between Node and the kernel, and that's why there's been no demand/movement on this. Most exciting use-case for BPF is correlating the application events with kernel events.
    - THE COMMENT TALKS ABOUT ATTACHING UPROBES TO NATIVE FUNCTIONS. PLEASE HOW CAN I DO THAT?
    - Node runs on libuv, and it handles filesystem events, so if you can instrument libuv functions .. ? https://github.com/libuv/libuv
        - e.g. the way this person wrote a bpftrace script to trace event loop blockage https://github.com/nodejs/diagnostics/issues/569#issue-1300078324

- How do tracers (specifically the DD Tracer) catch filesystecm calls? And why can't this be read from outside? I suspect that the reason is because it's easier to trace in-memory thatn from outside it
    - Don't think checking this is worth my time for now.

- Brendan talks about enabling Node USDT probes in this article: https://www.brendangregg.com/blog/2016-10-12/linux-bcc-nodejs-usdt.html. \
    - Is this still relevant?
    - Can I reproduce it? List probes using BCC tplist? This sounds useful
        - Yeah
            ```
            root@vagrant:/src# sudo apt-get install systemtap-sdt-dev 
            root@vagrant:/src# git clone https://github.com/nodejs/node.git && cd node
            root@vagrant:/src/node# git checkout v12.x
            root@vagrant:/src/node# ./configure --with-dtrace
            root@vagrant:/src/node# make -j2
            root@vagrant:/src/node# /usr/share/bcc/tools/tplist -l out/Release/node
            out/Release/node node:gc__start
            out/Release/node node:gc__done
            out/Release/node node:http__server__response
            out/Release/node node:net__stream__end
            out/Release/node node:net__server__connection
            out/Release/node node:http__client__response
            out/Release/node node:http__client__request
            out/Release/node node:http__server__request
            ```
    - Somehow DTrace relates to uprobes for NodeJS. How? Important to know this and add a section about it
        - There is native DTrace and ETW(?) probe point support within Node, but it's not actively maintained https://github.com/nodejs/node/issues/26571
            - They need tests for the probe points, but looks like noone cares to write them. I could do that? This would be incredible because it would help to understand the entire DTrace ecosystem in Node.
            - If there are no tests, there can be no new probe points, which I WANT.
        - More hints about the DTrace capabilities here https://github.com/nodejs/TSC/issues/853
        - DTRACE/ETW PROBES HAS BEEN REMOVED, but not released yet https://github.com/nodejs/node/pull/43652
            - Apparently people use this instead? https://www.npmjs.com/package/dtrace-provider
                - A seperate blog post about custom uprobes in Node JS apps could be nice. Add a uprobe that can be called without enabling debug mode. This would be an easy way to correlate Node tracing with kernel activity
            - If this has been removed, there are no plans to support in the future and another method should be found
            - There are plans to bring it back, but it's unlikely that it gets traction https://github.com/nodejs/node/issues/44550
    - Bryan Cantrill Instrumenting the real-time web: Node.js, DTrace and the Robinson Projection https://www.youtube.com/watch?v=_jS_XkCkpVI
        - http://dtrace.org/blogs/bmc/2010/08/30/dtrace-node-js-and-the-robinson-projection/
    - What's interesting about this, is that you can catch the libc probes (from the running node process) and create bcc helpers from there. What I was hoping to see! The libc probes only contain memory and mutex stuff, but it's a start.
        - *making a note to write/research about the various things you can trace from the libc probes below.
        ```
        root@vagrant:/src/node# /usr/share/bcc/tools/tplist -p `pgrep node`
        /src/node/out/Release/node node:gc__start
        [...]
        /lib/x86_64-linux-gnu/libc-2.27.so libc:setjmp
        /lib/x86_64-linux-gnu/libc-2.27.so libc:longjmp
        /lib/x86_64-linux-gnu/libc-2.27.so libc:longjmp_target
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_arena_max
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_arena_test
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_max_bytes
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_count
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tunable_tcache_unsorted_limit
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_trim_threshold
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_top_pad
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mmap_threshold
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mmap_max
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_perturb
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_new
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_sbrk_less
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse_wait
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_new
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_reuse_free_list
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_arena_retry
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_tcache_double_free
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_free
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_less
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_heap_more
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_sbrk_more
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_free_dyn_thresholds
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_malloc_retry
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_memalign_retry
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_realloc_retry
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_calloc_retry
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt
        /lib/x86_64-linux-gnu/libc-2.27.so libc:memory_mallopt_mxfast
        /lib/x86_64-linux-gnu/libc-2.27.so libc:lll_lock_wait_private
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:pthread_start
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:pthread_create
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:pthread_join
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:pthread_join_ret
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_init
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_destroy
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_acquired
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_entry
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_timedlock_entry
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_timedlock_acquired
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:mutex_release
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:rwlock_destroy
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:rdlock_entry
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:rdlock_acquire_read
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:wrlock_entry
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:wrlock_acquire_write
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:rwlock_unlock
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:cond_init
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:cond_destroy
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:cond_wait
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:cond_signal
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:cond_broadcast
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:lll_lock_wait_private
        /lib/x86_64-linux-gnu/libpthread-2.27.so libpthread:lll_lock_wait
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan2
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan2_inexact
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowlog_inexact
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowlog
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan_inexact
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowatan
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowtan
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowasin
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowacos
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowsin
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowcos
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowexp_p6
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowexp_p32
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowpow_p10
        /lib/x86_64-linux-gnu/libm-2.27.so libm:slowpow_p32
        /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25 libstdcxx:catch
        /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25 libstdcxx:throw
        /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.25 libstdcxx:rethrow
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:init_start
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:init_complete
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:map_failed
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:map_start
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:map_complete
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:reloc_start
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:reloc_complete
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:unmap_start
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:unmap_complete
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:setjmp
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:longjmp
        /lib/x86_64-linux-gnu/ld-2.27.so rtld:longjmp_target
        ```
        - Is there a lib source online that I can search? Like the kernel source?
        - libc functions should be traceable ordinarily? So if it has a file call function that Node uses, we can check if it does that?
        - The v8 --enable-tracing option is not available in Node yet, right? Brendan's vision hasn't come true yet
            - He lists the Node functions and calls them possible tracepoints, but how do we do that? How do we make them USDT probes?
                - I don't think this is possible yet, and was what he thought we'd be able to do soon.

- The tone of the blogpost should be "here's what could be possible". To get people as excited as possible about the possibility of correlating Node applications with kernel events. Opens up so many performance wins

- I'm learning that in open-source, if you don't talk, very likely that your desired features get dropped. Especially when performance-related. That's why Brendan Gregg is so far ahead - people don't care about these things until they have production problems.

- Testing the HTTP USDT Probes (Blog-worthy):
    ```
    vagrant@bullseye:/vagrant$ /var/src/node/out/Release/node src/app.js 
    go to http://localhost:8080/ to generate traffic

    # on another shell
    vagrant@bullseye:~$ sudo python3 /vagrant/bcc/node_function.py `pgrep node`
    3 warnings generated.
    TIME(s)            COMM             PID    ARGS
    2107.831368000     <...>            67641  path:/
    2253.196817000     node             67641  path:/wget
    2259.551289000     node             67641  path:/
    2284.295907000     node             67641  path:/
    2289.744545000     node             67641  path:/wget
    2293.650562000     node             67641  path:/wget
    ```

- Propose to the Node JS team that we should write a bunch of articles about possibilities of kernel correlation with eBPF in Node, and volunteer to write them. After writing this article, link to it in the comment. (EXCITING TIMES)

- Continue from here: the uv_fs_read function is not called, so I'll have to trace the fs.open call to see what libuv it actually uses, if at all.