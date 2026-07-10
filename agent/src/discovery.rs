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
        other         => TaskOutput::failure(&format!("enum: unknown method: {other}")),
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
