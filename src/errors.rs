//! Error types for the NBD (Network Block Device) protocol.
//!
//! This module defines the error types used in the NBD protocol implementation:
//!
//! - [`ProtocolError`]: Errors that can occur during the normal NBD transmission loop
//! - [`OptionReplyError`]: Errors that can occur during the option negotiation phase
//!
//! These error types correspond to the error codes defined in the NBD protocol
//! specification, with appropriate Rust representation.
//!
//! # Examples
//!
//! ```
//! use tokio_nbd::errors::ProtocolError;
//!
//! // Check if an error is a specific type
//! fn handle_error(error: ProtocolError) {
//!     if error == ProtocolError::CommandNotSupported {
//!         println!("The command is not supported by this server");
//!     } else if error == ProtocolError::NoSpaceLeft {
//!         println!("The operation failed because the device is full");
//!     }
//! }
//! ```

use int_enum::IntEnum;
use thiserror::Error;

/// Errors that can occur during the normal NBD transmission loop.
///
/// These errors correspond to the standard NBD error codes defined in the protocol
/// specification. Each error maps to a specific numeric value that is sent over
/// the wire to the client.
///
/// The error codes follow POSIX errno values where possible, as per the NBD protocol
/// specification.
#[repr(u32)]
#[derive(Debug, Error, IntEnum, PartialEq, Eq)]
pub enum ProtocolError {
    /// The client is not permitted to perform the requested operation.
    ///
    /// Corresponds to POSIX EPERM (1) and NBD_EPERM.
    #[error("Command not permitted (NBD_EPERM)")]
    CommandNotPermitted = 1,

    /// An input/output error occurred during the operation.
    ///
    /// Corresponds to POSIX EIO (5) and NBD_EIO.
    #[error("Input/output error (NBD_EIO)")]
    IO = 5,

    /// The server cannot allocate sufficient memory to complete the operation.
    ///
    /// Corresponds to POSIX ENOMEM (12) and NBD_ENOMEM.
    #[error("Cannot allocate memory (NBD_ENOMEM)")]
    OutOfMemory = 12,

    /// The client provided an invalid argument or request structure.
    ///
    /// Corresponds to POSIX EINVAL (22) and NBD_EINVAL.
    #[error("Invalid argument (NBD_EINVAL)")]
    InvalidArgument = 22,

    /// There is no space left on the storage device to complete the operation.
    ///
    /// Corresponds to POSIX ENOSPC (28) and NBD_ENOSPC.
    #[error("No space left on device (NBD_ENOSPC)")]
    NoSpaceLeft = 28,

    /// The requested operation would cause a value to overflow.
    ///
    /// Corresponds to POSIX EOVERFLOW (75) and NBD_EOVERFLOW.
    #[error("Value too large (NBD_EOVERFLOW)")]
    ValueTooLarge = 75,

    /// The requested command is not supported by the server implementation.
    ///
    /// Corresponds to POSIX ENOTSUP (95) and NBD_ENOTSUP.
    #[error("Command not supported (NBD_ENOTSUP)")]
    CommandNotSupported = 95,

    /// The server is in the process of shutting down and cannot process the request.
    ///
    /// Corresponds to POSIX ESHUTDOWN (108) and NBD_ESHUTDOWN.
    #[error("Server is in the process of being shut down (NBD_ESHUTDOWN)")]
    ServerShuttingDown = 108,
}

/// Errors that can occur during the option negotiation phase of the NBD protocol.
///
/// These errors are sent in reply to option requests from the client during the handshake
/// and negotiation phase. All of these error codes have bit 31 set (0x80000000) to
/// distinguish them from successful replies.
///
/// Each error provides specific information about why an option request failed,
/// allowing clients to make informed decisions about how to proceed.
#[repr(u32)]
#[derive(Debug, Error, IntEnum, PartialEq, Eq, Clone, Copy)]
pub enum OptionReplyError {
    /// The option sent by the client is unknown by this server implementation.
    ///
    /// This may occur because the server is too old or from another source
    /// that doesn't support the requested option.
    ///
    /// Corresponds to NBD_REP_ERR_UNSUP (2^31 + 1).
    #[error("Unsupported option (NBD_REP_ERR_UNSUP)")]
    Unsupported = 0x80000001,

    /// The option sent by the client is known but forbidden by server policy.
    ///
    /// The server recognizes the option and it's syntactically valid, but
    /// server-side policy forbids the server to allow the option (e.g., the client
    /// sent NBD_OPT_LIST but server configuration has that disabled).
    ///
    /// Corresponds to NBD_REP_ERR_POLICY (2^31 + 2).
    #[error("Policy error (NBD_REP_ERR_POLICY)")]
    Policy = 0x80000002,

    /// The option sent by the client is known but syntactically or semantically invalid.
    ///
    /// For instance, the client sent an NBD_OPT_LIST with nonzero data length,
    /// or the client sent a second NBD_OPT_STARTTLS after TLS was already negotiated.
    ///
    /// Corresponds to NBD_REP_ERR_INVALID (2^31 + 3).
    #[error("Invalid option (NBD_REP_ERR_INVALID)")]
    Invalid = 0x80000003,

    /// The option is not supported on the platform where the server is running.
    ///
    /// This error occurs when an option requires compile-time options that
    /// were disabled on the server, e.g., when trying to use TLS but the server
    /// was built without TLS support.
    ///
    /// Corresponds to NBD_REP_ERR_PLATFORM (2^31 + 4).
    #[error("Platform error (NBD_REP_ERR_PLATFORM)")]
    Platform = 0x80000004,

    /// The server requires TLS to be initiated before continuing negotiation.
    ///
    /// For NBD_OPT_INFO and NBD_OPT_GO, this unwillingness may be limited to
    /// the export in question, depending on the TLS mode.
    ///
    /// Corresponds to NBD_REP_ERR_TLS_REQD (2^31 + 5).
    #[error("TLS required (NBD_REP_ERR_TLS_REQD)")]
    TLSRequired = 0x80000005,

    /// The requested export is not available on the server.
    ///
    /// This is typically returned when a client attempts to connect to an export
    /// that doesn't exist or isn't configured on the server.
    ///
    /// Corresponds to NBD_REP_ERR_UNKNOWN (2^31 + 6).
    #[error("Unknown export (NBD_REP_ERR_UNKNOWN)")]
    Unknown = 0x80000006,

    /// The server is in the process of shutting down.
    ///
    /// The server is unwilling to continue negotiation as it is being shut down.
    ///
    /// Corresponds to NBD_REP_ERR_SHUTDOWN (2^31 + 7).
    #[error("Server shutting down (NBD_REP_ERR_SHUTDOWN)")]
    Shutdown = 0x80000007,

    /// The server requires block size information before proceeding.
    ///
    /// The server is unwilling to enter transmission phase for a given export
    /// unless the client first acknowledges (via NBD_INFO_BLOCK_SIZE) that it
    /// will obey non-default block sizing requirements.
    ///
    /// Corresponds to NBD_REP_ERR_BLOCK_SIZE_REQD (2^31 + 8).
    #[error("Block size required (NBD_REP_ERR_BLOCK_SIZE_REQD)")]
    BlockSizeRequired = 0x80000008,

    /// The request or reply is too large for the server to process.
    ///
    /// This can occur when a client sends a request that exceeds the server's
    /// processing capabilities, or when a reply would be too large to send.
    ///
    /// Corresponds to NBD_REP_ERR_TOO_BIG (2^31 + 9).
    #[error("Request too big (NBD_REP_ERR_TOO_BIG)")]
    TooBig = 0x80000009,

    /// The server requires extended headers for the operation.
    ///
    /// This is defined by the experimental EXTENDED_HEADERS extension to the NBD protocol.
    ///
    /// Corresponds to NBD_REP_ERR_EXT_HEADER_REQD (2^31 + 10).
    #[error("Extended header required (NBD_REP_ERR_EXT_HEADER_REQD)")]
    ExtendedHeaderRequired = 0x8000000A,
}
