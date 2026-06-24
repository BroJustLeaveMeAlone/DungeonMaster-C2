// Compile-time string obfuscation. Sensitive API/DLL name strings are stored
// XOR'd so they never appear as plaintext in the binary. dec() decrypts at
// runtime just before the value is passed to a WinAPI call.

pub const KEY: u8 = 0x5A;

pub fn dec(enc: &[u8]) -> Vec<u8> {
    enc.iter().map(|&b| b ^ KEY).collect()
}
