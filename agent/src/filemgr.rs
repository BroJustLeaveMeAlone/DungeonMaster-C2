use crate::task::{Task, TaskOutput};
use base64::Engine;

pub fn exec_file(task: &Task) -> TaskOutput {
    let args = match task.args.as_deref() {
        Some(a) => a,
        None    => return TaskOutput::failure("file: no args"),
    };
    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&format!("file: {e}")),
    };
    match v.get("method").and_then(|m| m.as_str()).unwrap_or("") {
        "ls"     => file_ls(&v),
        "read"   => file_read(&v),
        "write"  => file_write(&v),
        "rm"     => file_rm(&v),
        "mkdir"  => file_mkdir(&v),
        "mv"     => file_mv(&v),
        "cp"     => file_cp(&v),
        "info"   => file_info(&v),
        other    => TaskOutput::failure(&format!("file: unknown method: {other}")),
    }
}

fn file_ls(v: &serde_json::Value) -> TaskOutput {
    let path = v.get("path").and_then(|p| p.as_str()).unwrap_or(".");
    match std::fs::read_dir(path) {
        Err(e) => TaskOutput::failure(&format!("ls: {e}")),
        Ok(entries) => {
            let mut out = String::new();
            let mut items: Vec<_> = entries.filter_map(|e| e.ok()).collect();
            items.sort_by_key(|e| e.file_name());
            for entry in items {
                let meta = entry.metadata();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size   = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let name   = entry.file_name().to_string_lossy().into_owned();
                if is_dir {
                    out.push_str(&format!("{:<50} <DIR>\n", name));
                } else {
                    out.push_str(&format!("{:<50} {}\n", name, size));
                }
            }
            TaskOutput::success(out.into_bytes())
        }
    }
}

fn file_read(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("file/read: missing path"),
    };
    match std::fs::read(path) {
        Ok(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            TaskOutput::success(encoded.into_bytes())
        }
        Err(e) => TaskOutput::failure(&format!("file/read: {e}")),
    }
}

fn file_write(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("file/write: missing path"),
    };
    let data_b64 = match v.get("data").and_then(|d| d.as_str()) {
        Some(d) => d,
        None    => return TaskOutput::failure("file/write: missing data"),
    };
    let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(d)  => d,
        Err(e) => return TaskOutput::failure(&format!("file/write: base64: {e}")),
    };
    match std::fs::write(path, &data) {
        Ok(_)  => TaskOutput::success(format!("written {} bytes to {path}", data.len()).into_bytes()),
        Err(e) => TaskOutput::failure(&format!("file/write: {e}")),
    }
}

fn file_rm(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("file/rm: missing path"),
    };
    let p = std::path::Path::new(path);
    let result = if p.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match result {
        Ok(_)  => TaskOutput::success(format!("removed {path}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("file/rm: {e}")),
    }
}

fn file_mkdir(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("file/mkdir: missing path"),
    };
    match std::fs::create_dir_all(path) {
        Ok(_)  => TaskOutput::success(format!("created {path}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("file/mkdir: {e}")),
    }
}

fn file_mv(v: &serde_json::Value) -> TaskOutput {
    let src = match v.get("src").and_then(|s| s.as_str()) {
        Some(s) => s,
        None    => return TaskOutput::failure("file/mv: missing src"),
    };
    let dst = match v.get("dst").and_then(|d| d.as_str()) {
        Some(d) => d,
        None    => return TaskOutput::failure("file/mv: missing dst"),
    };
    match std::fs::rename(src, dst) {
        Ok(_)  => TaskOutput::success(format!("moved {src} -> {dst}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("file/mv: {e}")),
    }
}

fn file_cp(v: &serde_json::Value) -> TaskOutput {
    let src = match v.get("src").and_then(|s| s.as_str()) {
        Some(s) => s,
        None    => return TaskOutput::failure("file/cp: missing src"),
    };
    let dst = match v.get("dst").and_then(|d| d.as_str()) {
        Some(d) => d,
        None    => return TaskOutput::failure("file/cp: missing dst"),
    };
    match std::fs::copy(src, dst) {
        Ok(n)  => TaskOutput::success(format!("copied {n} bytes: {src} -> {dst}").into_bytes()),
        Err(e) => TaskOutput::failure(&format!("file/cp: {e}")),
    }
}

fn file_info(v: &serde_json::Value) -> TaskOutput {
    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p,
        None    => return TaskOutput::failure("file/info: missing path"),
    };
    match std::fs::metadata(path) {
        Err(e) => TaskOutput::failure(&format!("file/info: {e}")),
        Ok(m)  => {
            let kind = if m.is_dir() { "dir" } else if m.is_symlink() { "symlink" } else { "file" };
            let size = m.len();
            let readonly = m.permissions().readonly();
            let out = format!("path: {path}\ntype: {kind}\nsize: {size}\nreadonly: {readonly}\n");
            TaskOutput::success(out.into_bytes())
        }
    }
}
