//! Network Block Device (NBD) driver implementation and server functionality.
//!
//! This module provides core components for implementing an NBD server:
//!
//! - [`crate::device::NbdDriver`]: A trait for defining NBD devices
//! - [`crate::server::NbdServer`]: A struct for handling the NBD protocol
//!
//! # Protocol Compliance
//!
//! This implementation follows the NBD protocol specification as defined at
//! [NetworkBlockDevice/nbd](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md).
//!
//! # Security Considerations
//!
//! NBD does not provide built-in authentication or encryption. For secure deployments:
//!
//! - Use on trusted networks only
//! - Consider implementing TLS support (with the `START_TLS` option)
//! - Use firewall rules to restrict access

mod command_request;
pub mod device;
pub mod errors;
pub mod flags;
mod info;
mod io;
mod magic;
mod option_reply;
mod option_request;
pub mod server;
