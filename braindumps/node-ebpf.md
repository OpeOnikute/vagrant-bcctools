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
    sudo perf record -F 99 -p `pgrep -n node` -g
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
            - They are documented in `deps/uv/docs/src/fs.rst` e.g. https://github.com/nodejs/node/blob/951da5282c7b00eb86a989336d628218fb2df057/deps/uv/docs/src/fs.rst#api 
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

- You can attach a uprobe to the Node underlying function using bpftrace:

    ```
    /* Whenever any thread enters uv__run_timers, record the current time
   in nanoseconds in a map. */
    u:NODE_PATH:uv__run_timers { @[tid] = nsecs; }

    /* Whenever any thread returns from uv__run_check, clear its time from
    the map. */
    ur:NODE_PATH:uv__run_check /@[tid]/ { delete(@[tid]); }

    /* 99 times a second, check if any running thread has been blocked
    for longer than 10 seconds. If so, take a core dump and stop
    this script. */
    p:hz:99 /@[tid]/ {
        if (nsecs - @[tid] > 10000000000) {
            system("gcore %d", pid);
            exit();
        }
    }
    ```

    This means that the main issue here is finding the underlying libuv call for a node native function? Instead of reading the code, can we trace with perf and execute the function? That's a more sustainable approach.

- I can find the libuv function definitions, and what they relate to in Node?

- I can find the expected args to uv_read by searching in libuv?
    - Search on Github and look at the function definitions on the right for clues: https://github.com/search?q=repo%3Alibuv%2Flibuv%20uv__read&type=code
    - This is the definition: https://github.com/libuv/libuv/blob/7b43d70be4fe9c3f9003b189e62e4f86a6a88516/src/unix/stream.c#L1020
    - Well it expects a stream as a struct entry, so if we look at the definition of a stream, we can find a property to print
    - Maybe the flags field? https://github.com/libuv/libuv/blob/7b43d70be4fe9c3f9003b189e62e4f86a6a88516/include/uv.h#L474? Or data? 

- I might as well inspect uv_read with bpftrace at this point, to see what I can find in the args? (Step 2)

```
vagrant@bullseye:~$ sudo bpftrace -e 'u:/var/src/node/out/Release/node:uv__read { printf("arg0: %d\n", arg0) }'
Attaching 1 probe...
arg0: 432303552
arg0: 432303552
arg0: 432303552

vagrant@bullseye:~$ sudo bpftrace -e 'uretprobe:/var/src/node/out/Release/node:uv__read { printf("uv__read: \"%d\"\n", retval); }'
Attaching 1 probe...
uv__read: "431076576"
uv__read: "431076576"
```

- So I can trace file opens and print the stack trace, but how do I access the arguments of the function itself? I'm getting only numbers as the args. I suspect it's a lack of understanding of how the uprobe args work
```
vagrant@bullseye:~$ sudo bpftrace -e 'u:/var/src/node/out/Release/node:uv_fs_open { printf("process: %d %d %d %d %d %d\n", arg0, arg1, arg2, arg3, arg4, arg5) }'
Attaching 1 probe...
process: -2055237312 -2026691864 1492749352 0 438 -2087665872
process: -2055237312 -2026691864 1492749352 0 438 -2087665872
```
    - This explains the arguments issue a bit. https://github.com/iovisor/bpftrace/issues/1343#issuecomment-631862951 Bpftrace takes the integer or pointer arguments? Does this mean we can use the pointer to access the value?
        ```
        The first six integer or pointer arguments are passed in registers RDI, RSI, RDX, RCX, R8, R9 [...], while XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6 and XMM7 are used for the first floating point arguments.
        https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
        ```

- WELL I can access the function arguments by just reading the spec in the docs and printing out the arg that correspond to the input, in this case the 3rd argument (arg2):
```
vagrant@bullseye:~$ sudo bpftrace -e 'u:/var/src/node/out/Release/node:uv_fs_open { printf("process: %s, pid: %d, file path: %s\n", comm, pid, str(arg2)) }'
Attaching 1 probe...
process: node, pid: 336543, file path: /vagrant/src/text.txt
process: node, pid: 336543, file path: /vagrant/src/text.txt
```

- Brendan's BPFTrace cheatsheet is great for seeing what is available e.g. the pid, comm etc https://www.brendangregg.com/BPF/bpftrace-cheat-sheet.html

- Getting stack traces to work is not worth the effort. I have tried multiple things and no dice. Best thing to do is just talk about it and say it's possible with some luck, or make it a hypothetical and say it is useful if you have multiple Node processes running and want to tell which is responsible, or which thread is the cause.

- List of common node functions and their documentation locations for triage:
   ```
   fs: https://github.com/nodejs/node/blob/951da5282c7b00eb86a989336d628218fb2df057/deps/uv/docs/src/fs.rst#api. See uv_fs_open, uv_fs_read, uv_fs_close etc.
   dns: https://github.com/nodejs/node/blob/951da5282c7b00eb86a989336d628218fb2df057/deps/uv/docs/src/dns.rst#api. See uv_getaddrinfo, uv_getnameinfo etc.
   ```

- Reading through the docs, and I think you actually have to check what libuv functions are called by Node.

- Steps:
1. List the libuv functions in the Node binary. This is how you know what you can add a uprobe to. It's quite verbose so you can filter out unneeded functions using `egrep`. e.g to list the fs functions;
```
vagrant@bullseye:~$ objdump -tT /var/src/node/out/Release/node | grep uv_fs | egrep -v "(4node|ZN6)" | head -n10
0000000001138910 l     F .text  0000000000000466              uv_fs_event_start.part.0
00000000011295f0 g     F .text  0000000000000110              uv_fs_chmod
000000000111e6a0 g     F .text  000000000000018e              uv_fs_poll_start
000000000112a9a0 g     F .text  00000000000000c5              uv_fs_readdir
0000000001139a80 g     F .text  00000000000000bd              uv_fs_event_stop
000000000112ad00 g     F .text  000000000000013e              uv_fs_rename
0000000001129ce0 g     F .text  00000000000000a7              uv_fs_fsync
0000000001123f20 g     F .text  000000000000006e              uv_fs_event_getpath
000000000112b800 g     F .text  0000000000000007              uv_fs_get_system_error
000000000111e8f0 g     F .text  00000000000000ae              uv_fs_poll_getpath
```
2. Read the docs to see what the function argument are. You will need this when trying to print arguments like what path was called. To find a function, you can search the libuv docs. e.g. this search for [uv_fs_rename](https://github.com/search?q=repo%3Anodejs%2Fnode%20path%3Adeps%2Fuv%2Fdocs%20uv_fs_rename&type=code) shows that the 3rd argument is the file path, second is a req struct etc. If you're curious, you can search for the unfamiliar struct names using the same technique. Overall the file path seems the most useful for these FS calls.

```
.. c:function:: int uv_fs_rename(uv_loop_t* loop, uv_fs_t* req, const char* path, const char* new_path, uv_fs_cb cb)

    Equivalent to :man:`rename(2)`.
```

3. Attach a uprobe using bpftrace to the libuv function, and you can trace any calls from Node to that function. [This bpftrace cheatsheet](https://www.brendangregg.com/BPF/bpftrace-cheat-sheet.html) is useful for checking what is available to expose. The example below prints out the Process name, PID, File Path and Stack Trace when the `uv_fs_open` function is called. The file path is the string value of `arg2` as the path is the 3rd argument. For more information about args, see [this section](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md#4-uprobeuretprobe-dynamic-tracing-user-level-arguments) of the bpftrace reference guide. 

```
# Run Node with debug symbols and a mock endpoint that opens a file
vagrant@bullseye:~$ /var/src/node/out/Release/node --perf_basic_prof_only_functions /vagrant/src/app.js
go to http://localhost:8080/ to generate traffic
gotten file

vagrant@bullseye:/vagrant$ sudo bpftrace -e 'u:/var/src/node/out/Release/node:uv_fs_open { printf("process: %s, pid: %d, file path: %s, stack: %s\n", comm, pid, str(arg2), ustack) }'

process: node, pid: 349854, file path: /vagrant/src/text.txt, stack: 
        uv_fs_open+0
        [...]
        uv__read+629
        uv__stream_io+160
        uv__io_poll+1372
        uv_run+324
        node::NodeMainInstance::Run()+620
        node::Start(int, char**)+492
        __libc_start_main+234
        0x5541d68949564100
```

This is powerful because you can filter out by Node Process, Thread, Cgroups (for containerised environments) etc. You gain the ability to correlate what is happening on a machine with a Node process, without touching any code. The output is pretty verbose so I cut out the internal Node functions. In an ideal world, we'd see the full Node stack traces here all the time, but as mentioned above this is inconsistent because of the JIT-nature of Node. I get some express stacks once in a while, but not often enough to be useful.

For HTTP requests, I did some digging and I'm not convinced that Node uses libuv entirely for those. There are some [TCP](https://github.com/nodejs/node/blob/951da5282c7b00eb86a989336d628218fb2df057/deps/uv/docs/src/tcp.rst), [DNS](https://github.com/nodejs/node/blob/951da5282c7b00eb86a989336d628218fb2df057/deps/uv/docs/src/dns.rst#api) functions, but it's hard to draw a straight line from the Node HTTP module to them. Someone with a better understanding of NodeJS internals would be better placed to investigate that.

