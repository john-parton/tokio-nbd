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
//!
//! # Logging
//!
//! This crate uses the `tracing` crate for logging. To enable logging, you need to install
//! a tracing subscriber. For simple usage, you can use the `init_default_tracing` function
//! provided by this crate.
//!
//! ```rust,no_run
//! tokio_nbd::init_default_tracing();
//! ```
//!
//! For more advanced usage, you can use the tracing crate directly to configure logging.

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

/// Initializes a default tracing subscriber suitable for use with tokio-nbd.
///
/// This sets up basic console logging with RUST_LOG environment variable support.
/// If you want more advanced tracing configuration, you should set up your own
/// subscriber instead.
///
/// # Example
///
/// ```rust,no_run
/// // Initialize the default tracing subscriber at the beginning of your program
/// tokio_nbd::init_default_tracing();
///
/// // Now logs from tokio-nbd will be visible
/// ```
pub fn init_default_tracing() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("tokio_nbd=info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();
}
