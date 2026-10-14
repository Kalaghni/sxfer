//! sxfer as a library: the transports and the transfer / verify / shred steps behind the `sxfer`
//! CLI and the `sxfer-mcp` server, and agent messaging on top of them (`mesh`).

pub mod common;
pub mod config;
pub mod identity;
pub mod lan;
pub mod mesh;
pub mod ssh;
