//! sxfer as a library: the transports and the transfer / verify / shred steps behind the `sxfer`
//! CLI and the `sxfer-mcp` server.

pub mod common;
pub mod config;
pub mod lan;
pub mod ssh;
