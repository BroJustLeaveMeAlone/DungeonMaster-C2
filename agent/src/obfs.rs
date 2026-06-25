// Compile-time string obfuscation. Sensitive API/DLL name strings are stored
// XOR'd so they never appear as plaintext in the binary. dec() decrypts at
// runtime just before the value is passed to a WinAPI call.

pub const KEY: u8 = 0x5A;

pub fn dec(enc: &[u8]) -> Vec<u8> {
    enc.iter().map(|&b| b ^ KEY).collect()
}

pub fn dec_str(enc: &[u8]) -> String {
    String::from_utf8(dec(enc)).unwrap_or_default()
}

/// DJB2 hash — const-fn so it can be used in const array initialisers.
/// Both compile-time (const HASHES) and runtime comparisons use the same fn,
/// so they are always consistent.  Tool/sandbox names never appear in the binary;
/// only their u32 hashes do.
pub const fn djb2(s: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    let mut i = 0;
    while i < s.len() {
        h = h.wrapping_mul(33).wrapping_add(s[i] as u32);
        i += 1;
    }
    h
}
