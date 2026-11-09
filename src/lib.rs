//! BunnieHop Helper. A fork of youtube-dl-gui (AGPL-3.0-or-later, see LICENSE and README.md).
//!
//! The web app at https://bunniehop.party drives this process over `127.0.0.1` (docs/helper-api.md).
//! Downloading and posting happen here, as the creator; nothing passes through BunnieHop servers.

pub mod binaries;
pub mod catalog;
pub mod cloud;
pub mod config;
pub mod connect;
pub mod connections;
pub mod error;
pub mod exports;
pub mod gdrive;
pub mod hops;
pub mod pacing;
pub mod pairing;
pub mod posted;
pub mod server;
pub mod sigv4;
pub mod uploaders;
pub mod vault;
pub mod ytdlp;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Ports tried in order (PLAN §4.3).
pub const PORTS: std::ops::RangeInclusive<u16> = 17333..=17340;
