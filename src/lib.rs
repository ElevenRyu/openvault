//! openvault — an agent-safe secrets vault.
//!
//! `unsafe` is denied everywhere except the single audited `platform` module.
#![deny(unsafe_code)]

pub mod audit;
pub mod cli;
pub mod discover;
pub mod import;
pub mod mcp;
pub mod names;
pub mod platform;
pub mod policy;
pub mod redact;
pub mod run;
pub mod session;
pub mod unlock;
pub mod util;
pub mod vault;
