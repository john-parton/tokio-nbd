//! Flag definitions for the NBD (Network Block Device) protocol.
//!
//! This module contains the various flag types used in the Network Block Device protocol:
//!
//! - [`CommandFlags`]: Used with command requests to modify their behavior
//! - [`ServerFeatures`]: Public interface for NBD drivers to expose their capabilities
//!
//! All flags are implemented using the [`bitflags`](https://docs.rs/bitflags) crate.
//!
//! # Examples
//!
//! ```
//! use tokio_nbd::flags::{CommandFlags, ServerFeatures};
//!
//! // Create a flags value with multiple flags set
//! let cmd_flags = CommandFlags::FUA | CommandFlags::DF;
//!
//! // Testing if a flag is set
//! if cmd_flags.contains(CommandFlags::FUA) {
//!     println!("Force Unit Access flag is set");
//! }
//!
//! // Create server features
//! let features = ServerFeatures::SEND_FLUSH | ServerFeatures::SEND_FUA | ServerFeatures::SEND_TRIM;
//! ```

/// Shared flag bit values used in both `ServerFeatures` and `TransmissionFlags`.
///
/// These constants define the bit patterns for NBD protocol features.
/// Using shared constants ensures consistency between the two flag types.
///
/// The documentation here provides detailed explanations for each flag used in the NBD protocol.
mod flag_bits {
    // Administrative flags (TransmissionFlags only)

    /// MUST always be 1 in valid NBD protocol communications.
    pub(crate) const HAS_FLAGS: u16 = 0b00000001;

    /// Indicates the export is read-only. If set, the server MUST error on write operations.
    pub(crate) const READ_ONLY: u16 = 0b00000010;

    // Feature flags (shared between ServerFeatures and TransmissionFlags)

    /// Exposes support for `NBD_CMD_FLUSH`.
    pub(crate) const SEND_FLUSH: u16 = 0b00000100;

    /// Exposes support for `NBD_CMD_FLAG_FUA` (Force Unit Access).
    pub(crate) const SEND_FUA: u16 = 0b00001000;

    /// Indicates the export has characteristics of a rotational medium.
    /// The client MAY schedule I/O accesses accordingly.
    pub(crate) const ROTATIONAL: u16 = 0b00010000;

    /// Exposes support for `NBD_CMD_TRIM`.
    pub(crate) const SEND_TRIM: u16 = 0b00100000;

    /// Exposes support for `NBD_CMD_WRITE_ZEROES` and `NBD_CMD_FLAG_NO_HOLE`.
    pub(crate) const SEND_WRITE_ZEROES: u16 = 0b01000000;

    /// Do not fragment a structured reply.
    /// Indicates the server supports the `NBD_CMD_FLAG_DF` request flag.
    pub(crate) const SEND_DF: u16 = 0b10000000;

    /// Indicates that the server operates without cache or with a shared cache,
    /// making `FLUSH` and `FUA` operations visible across all connections.
    /// Without this flag, clients SHOULD NOT multiplex commands over multiple connections.
    pub(crate) const CAN_MULTI_CONN: u16 = 0b00000001_00000000;

    /// Exposes support for the experimental RESIZE extension.
    pub(crate) const SEND_RESIZE: u16 = 0b00000010_00000000;

    /// Documents that the server understands `NBD_CMD_CACHE`.
    /// Note that some servers may support the command without this bit,
    /// and this flag doesn't guarantee the command will succeed.
    pub(crate) const SEND_CACHE: u16 = 0b00000100_00000000;

    /// Allows clients to detect if `NBD_CMD_WRITE_ZEROES` is faster than
    /// a corresponding write via the `NBD_CMD_FLAG_FAST_ZERO` request flag.
    pub(crate) const SEND_FAST_ZERO: u16 = 0b00001000_00000000;

    /// Defined by the experimental EXTENDED_HEADERS extension.
    pub(crate) const BLOCK_STATUS_PAYLOAD: u16 = 0b00010000_00000000;
}

bitflags::bitflags! {
    /// Handshake flags used during the initial NBD protocol negotiation.
    ///
    /// This 16-bit field is sent by the server after the `INIT_PASSWD` and the first magic number.
    ///
    /// According to the NBD protocol specification:
    /// - The server MUST NOT set any flags other than those defined here
    /// - The server SHOULD NOT change behavior unless the client responds with a corresponding flag
    /// - The server MUST NOT set any of these flags during oldstyle negotiation
    ///
    /// Additional capability flags are unlikely to be defined in the NBD protocol since
    /// this phase is susceptible to MitM downgrade attacks when using TLS. Additional features
    /// are best negotiated using protocol options.
    #[derive(Debug)]
    pub(crate) struct HandshakeFlags: u16 {
        /// MUST be set by servers that support the fixed newstyle protocol.
        const FIXED_NEWSTYLE = 0b00000001;

        /// If set, and if the client replies with `NBD_FLAG_C_NO_ZEROES` in the client flags field,
        /// the server MUST NOT send the 124 bytes of zero when the client ends negotiation with
        /// `NBD_OPT_EXPORT_NAME`.
        const NO_ZEROES = 0b00000010;
    }

}
impl Default for HandshakeFlags {
    fn default() -> Self {
        Self::FIXED_NEWSTYLE | Self::NO_ZEROES
    }
}

bitflags::bitflags! {
    /// Command flags sent with NBD command requests to modify their behavior.
    ///
    /// These flags are used to specify special handling for individual command requests,
    /// such as forced unit access, handling of write zeroes, and structured reply options.
    ///
    /// Available flags:
    /// - `CommandFlags::FUA` (0x0001): Force Unit Access - ensures data is written to stable storage before reply.
    /// - `CommandFlags::NO_HOLE` (0x0002): When set on a write zeroes command, the server should ensure that the operation
    ///   creates a hole (i.e., will read back as zeroes) but need not guarantee allocation. If clear, the server may
    ///   punch a hole or write zeroes as it sees fit.
    /// - `CommandFlags::DF` (0x0004): Don't Fragment - indicates that structured replies should not be split
    ///   across multiple reply chunks.
    /// - `CommandFlags::REQ_ONE` (0x0008): Request that the server only provides one (i.e., the first) content
    ///   range when replying to a block status command.
    /// - `CommandFlags::FAST_ZERO` (0x0010): Fast Zero - indicates that the client would prefer the server to fail
    ///   the request rather than perform a time-consuming write of zeroes.
    /// - `CommandFlags::PAYLOAD_LEN` (0x0020): Indicates that the command carries a payload whose length is encoded
    ///   as part of the extended header.
    #[derive(Debug)]
    pub struct CommandFlags: u16 {
        /// Force Unit Access (FUA) - ensures data is written to stable storage before reply.
        const FUA = 0b00000001;

        /// When set on a write zeroes command, the server should ensure that the operation
        /// creates a hole (i.e., will read back as zeroes) but need not guarantee allocation.
        /// If clear, the server may punch a hole or write zeroes as it sees fit.
        const NO_HOLE = 0b00000010;

        /// Don't Fragment - indicates that structured replies should not be split
        /// across multiple reply chunks.
        const DF = 0b00000100;

        /// Request that the server only provides one (i.e., the first) content range
        /// when replying to a block status command.
        const REQ_ONE = 0b00001000;

        /// Fast Zero - indicates that the client would prefer the server to fail
        /// the request rather than perform a time-consuming write of zeroes.
        const FAST_ZERO = 0b00010000;

        /// Indicates that the command carries a payload whose length is encoded
        /// as part of the extended header.
        const PAYLOAD_LEN = 0b00100000;
    }
}
impl TryFrom<u16> for CommandFlags {
    type Error = u16;

    /// Attempts to convert a raw u16 value into CommandFlags.
    ///
    /// # Returns
    /// - `Ok(CommandFlags)` if all bits in the value represent valid flags
    /// - `Err(value)` if any bits in the value don't correspond to defined flags
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match Self::from_bits(value) {
            Some(flags) => Ok(flags),
            None => Err(value),
        }
    }
}

bitflags::bitflags! {
    /// Features supported by an NBD server implementation.
    ///
    /// Derived from transmission flags but excluding administrative flags like HAS_FLAGS and READ_ONLY.
    /// These flags allow the server to advertise which features it supports.
    ///
    /// For each flag, the server:
    /// - MAY set the flag for features it supports
    /// - MUST NOT set the flag for features it does not support
    /// - The client MUST NOT use a feature documented as 'exposed' by a flag unless that flag was set
    ///
    /// Available flags:
    /// - `ServerFeatures::SEND_FLUSH` (0x0004): Exposes support for `NBD_CMD_FLUSH`.
    /// - `ServerFeatures::SEND_FUA` (0x0008): Exposes support for `NBD_CMD_FLAG_FUA` (Force Unit Access).
    /// - `ServerFeatures::ROTATIONAL` (0x0010): Indicates the export has characteristics of a rotational medium.
    ///   The client MAY schedule I/O accesses accordingly.
    /// - `ServerFeatures::SEND_TRIM` (0x0020): Exposes support for `NBD_CMD_TRIM`.
    /// - `ServerFeatures::SEND_WRITE_ZEROES` (0x0040): Exposes support for `NBD_CMD_WRITE_ZEROES` and `NBD_CMD_FLAG_NO_HOLE`.
    /// - `ServerFeatures::SEND_DF` (0x0080): Do not fragment a structured reply.
    ///   Indicates the server supports the `NBD_CMD_FLAG_DF` request flag.
    /// - `ServerFeatures::CAN_MULTI_CONN` (0x0100): Indicates that the server operates without cache or with a shared cache,
    ///   making `FLUSH` and `FUA` operations visible across all connections.
    ///   Without this flag, clients SHOULD NOT multiplex commands over multiple connections.
    /// - `ServerFeatures::SEND_RESIZE` (0x0200): Exposes support for the experimental RESIZE extension.
    /// - `ServerFeatures::SEND_CACHE` (0x0400): Documents that the server understands `NBD_CMD_CACHE`.
    ///   Note that some servers may support the command without this bit,
    ///   and this flag doesn't guarantee the command will succeed.
    /// - `ServerFeatures::SEND_FAST_ZERO` (0x0800): Allows clients to detect if `NBD_CMD_WRITE_ZEROES` is faster than
    ///   a corresponding write via the `NBD_CMD_FLAG_FAST_ZERO` request flag.
    /// - `ServerFeatures::BLOCK_STATUS_PAYLOAD` (0x1000): Defined by the experimental EXTENDED_HEADERS extension.
    #[derive(Debug)]
    pub struct ServerFeatures: u16 {
        const SEND_FLUSH = flag_bits::SEND_FLUSH;
        const SEND_FUA = flag_bits::SEND_FUA;
        const ROTATIONAL = flag_bits::ROTATIONAL;
        const SEND_TRIM = flag_bits::SEND_TRIM;
        const SEND_WRITE_ZEROES = flag_bits::SEND_WRITE_ZEROES;
        const SEND_DF = flag_bits::SEND_DF;
        const CAN_MULTI_CONN = flag_bits::CAN_MULTI_CONN;
        const SEND_RESIZE = flag_bits::SEND_RESIZE;
        const SEND_CACHE = flag_bits::SEND_CACHE;
        const SEND_FAST_ZERO = flag_bits::SEND_FAST_ZERO;
        const BLOCK_STATUS_PAYLOAD = flag_bits::BLOCK_STATUS_PAYLOAD;
    }
}

bitflags::bitflags! {
    /// Transmission flags sent by the server after option haggling, or
    /// immediately after the handshake flags field in oldstyle negotiation.
    ///
    /// This 16-bit field includes both administrative flags (like HAS_FLAGS and READ_ONLY)
    /// and feature flags that describe the server's capabilities.
    ///
    /// See `flag_bits` module for detailed documentation of each flag.
    #[derive(Debug)]
    pub(crate) struct TransmissionFlags: u16 {
        const HAS_FLAGS = flag_bits::HAS_FLAGS;
        const READ_ONLY = flag_bits::READ_ONLY;
        const SEND_FLUSH = flag_bits::SEND_FLUSH;
        const SEND_FUA = flag_bits::SEND_FUA;
        const ROTATIONAL = flag_bits::ROTATIONAL;
        const SEND_TRIM = flag_bits::SEND_TRIM;
        const SEND_WRITE_ZEROES = flag_bits::SEND_WRITE_ZEROES;
        const SEND_DF = flag_bits::SEND_DF;
        const CAN_MULTI_CONN = flag_bits::CAN_MULTI_CONN;
        const SEND_RESIZE = flag_bits::SEND_RESIZE;
        const SEND_CACHE = flag_bits::SEND_CACHE;
        const SEND_FAST_ZERO = flag_bits::SEND_FAST_ZERO;
        const BLOCK_STATUS_PAYLOAD = flag_bits::BLOCK_STATUS_PAYLOAD;
    }
}

impl From<ServerFeatures> for TransmissionFlags {
    /// Converts ServerFeatures to TransmissionFlags.
    ///
    /// This implementation automatically adds the required HAS_FLAGS bit,
    /// which must always be set in valid NBD protocol communications.
    fn from(features: ServerFeatures) -> Self {
        Self::HAS_FLAGS | Self::from_bits_truncate(features.bits())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_flags() {
        // Test individual flags
        assert_eq!(HandshakeFlags::FIXED_NEWSTYLE.bits(), 0b00000001);
        assert_eq!(HandshakeFlags::NO_ZEROES.bits(), 0b00000010);

        // Test default implementation
        let default_flags = HandshakeFlags::default();
        assert!(default_flags.contains(HandshakeFlags::FIXED_NEWSTYLE));
        assert!(default_flags.contains(HandshakeFlags::NO_ZEROES));
        assert_eq!(default_flags.bits(), 0b00000011);

        // Test from_bits and contains
        let flags = HandshakeFlags::from_bits(0b00000001).unwrap();
        assert!(flags.contains(HandshakeFlags::FIXED_NEWSTYLE));
        assert!(!flags.contains(HandshakeFlags::NO_ZEROES));

        // Test invalid bits are rejected
        assert!(HandshakeFlags::from_bits(0b11111100).is_none());

        // Test union operation
        let flags1 = HandshakeFlags::FIXED_NEWSTYLE;
        let flags2 = HandshakeFlags::NO_ZEROES;
        let combined = flags1 | flags2;
        let default = HandshakeFlags::default();
        assert_eq!(combined.bits(), default.bits());
    }

    #[test]
    fn test_command_flags() {
        // Test individual flags
        assert_eq!(CommandFlags::FUA.bits(), 0b00000001);
        assert_eq!(CommandFlags::NO_HOLE.bits(), 0b00000010);
        assert_eq!(CommandFlags::DF.bits(), 0b00000100);
        assert_eq!(CommandFlags::REQ_ONE.bits(), 0b00001000);
        assert_eq!(CommandFlags::FAST_ZERO.bits(), 0b00010000);
        assert_eq!(CommandFlags::PAYLOAD_LEN.bits(), 0b00100000);

        // Test bitwise operations
        let fua_and_df = CommandFlags::FUA | CommandFlags::DF;
        assert!(fua_and_df.contains(CommandFlags::FUA));
        assert!(fua_and_df.contains(CommandFlags::DF));
        assert!(!fua_and_df.contains(CommandFlags::NO_HOLE));
        assert_eq!(fua_and_df.bits(), 0b00000101);

        // Test try_from
        let fua_flag = CommandFlags::try_from(0b00000001).unwrap();
        assert!(fua_flag.contains(CommandFlags::FUA));
        assert!(!fua_flag.contains(CommandFlags::NO_HOLE));

        let combined_flags = CommandFlags::try_from(0b00000011).unwrap();
        assert!(combined_flags.contains(CommandFlags::FUA));
        assert!(combined_flags.contains(CommandFlags::NO_HOLE));
        assert!(!combined_flags.contains(CommandFlags::DF));

        assert!(CommandFlags::try_from(0b11000000).is_err());
    }

    #[test]
    fn test_server_features() {
        // Test individual flags
        assert_eq!(ServerFeatures::SEND_FLUSH.bits(), 0b00000100);
        assert_eq!(ServerFeatures::SEND_FUA.bits(), 0b00001000);
        assert_eq!(ServerFeatures::ROTATIONAL.bits(), 0b00010000);
        assert_eq!(ServerFeatures::SEND_TRIM.bits(), 0b00100000);
        assert_eq!(ServerFeatures::SEND_WRITE_ZEROES.bits(), 0b01000000);
        assert_eq!(ServerFeatures::SEND_DF.bits(), 0b10000000);
        assert_eq!(ServerFeatures::CAN_MULTI_CONN.bits(), 0b00000001_00000000);
        assert_eq!(ServerFeatures::SEND_RESIZE.bits(), 0b00000010_00000000);
        assert_eq!(ServerFeatures::SEND_CACHE.bits(), 0b00000100_00000000);
        assert_eq!(ServerFeatures::SEND_FAST_ZERO.bits(), 0b00001000_00000000);
        assert_eq!(
            ServerFeatures::BLOCK_STATUS_PAYLOAD.bits(),
            0b00010000_00000000
        );

        // Test bitwise operations
        let features =
            ServerFeatures::SEND_FLUSH | ServerFeatures::SEND_FUA | ServerFeatures::SEND_TRIM;
        assert!(features.contains(ServerFeatures::SEND_FLUSH));
        assert!(features.contains(ServerFeatures::SEND_FUA));
        assert!(features.contains(ServerFeatures::SEND_TRIM));
        assert!(!features.contains(ServerFeatures::ROTATIONAL));
        assert_eq!(features.bits(), 0b00101100);
    }

    #[test]
    fn test_transmission_flags() {
        // Test individual flags
        assert_eq!(TransmissionFlags::HAS_FLAGS.bits(), 0b00000001);
        assert_eq!(TransmissionFlags::READ_ONLY.bits(), 0b00000010);
        assert_eq!(TransmissionFlags::SEND_FLUSH.bits(), 0b00000100);
        assert_eq!(TransmissionFlags::SEND_FUA.bits(), 0b00001000);
        assert_eq!(TransmissionFlags::ROTATIONAL.bits(), 0b00010000);
        assert_eq!(TransmissionFlags::SEND_TRIM.bits(), 0b00100000);
        assert_eq!(TransmissionFlags::SEND_WRITE_ZEROES.bits(), 0b01000000);
        assert_eq!(TransmissionFlags::SEND_DF.bits(), 0b10000000);
        assert_eq!(
            TransmissionFlags::CAN_MULTI_CONN.bits(),
            0b00000001_00000000
        );
        assert_eq!(TransmissionFlags::SEND_RESIZE.bits(), 0b00000010_00000000);
        assert_eq!(TransmissionFlags::SEND_CACHE.bits(), 0b00000100_00000000);
        assert_eq!(
            TransmissionFlags::SEND_FAST_ZERO.bits(),
            0b00001000_00000000
        );
        assert_eq!(
            TransmissionFlags::BLOCK_STATUS_PAYLOAD.bits(),
            0b00010000_00000000
        );

        // Test bitwise operations
        let basic_flags = TransmissionFlags::HAS_FLAGS
            | TransmissionFlags::READ_ONLY
            | TransmissionFlags::SEND_FLUSH;
        assert!(basic_flags.contains(TransmissionFlags::HAS_FLAGS));
        assert!(basic_flags.contains(TransmissionFlags::READ_ONLY));
        assert!(basic_flags.contains(TransmissionFlags::SEND_FLUSH));
        assert!(!basic_flags.contains(TransmissionFlags::SEND_FUA));
        assert_eq!(basic_flags.bits(), 0b00000111);

        // Test insertion and removal
        let mut flags = TransmissionFlags::HAS_FLAGS;
        flags.insert(TransmissionFlags::SEND_TRIM);
        assert!(flags.contains(TransmissionFlags::SEND_TRIM));
        assert_eq!(flags.bits(), 0b00100001);

        flags.remove(TransmissionFlags::SEND_TRIM);
        assert!(!flags.contains(TransmissionFlags::SEND_TRIM));
        assert_eq!(flags.bits(), 0b00000001);
    }

    #[test]
    fn test_server_features_to_transmission_flags() {
        // Test conversion from ServerFeatures to TransmissionFlags
        let features_bits =
            ServerFeatures::SEND_FLUSH | ServerFeatures::SEND_FUA | ServerFeatures::SEND_TRIM;
        let features_bits_value = features_bits.bits();

        let transmission_flags: TransmissionFlags = features_bits.into();

        // HAS_FLAGS should always be set
        assert!(transmission_flags.contains(TransmissionFlags::HAS_FLAGS));

        // The converted flags should contain all the original feature flags
        assert!(transmission_flags.contains(TransmissionFlags::SEND_FLUSH));
        assert!(transmission_flags.contains(TransmissionFlags::SEND_FUA));
        assert!(transmission_flags.contains(TransmissionFlags::SEND_TRIM));

        // Flags that weren't in the original ServerFeatures shouldn't be set
        assert!(!transmission_flags.contains(TransmissionFlags::READ_ONLY));
        assert!(!transmission_flags.contains(TransmissionFlags::ROTATIONAL));

        // The bits should be the original features + HAS_FLAGS
        assert_eq!(
            transmission_flags.bits(),
            features_bits_value | TransmissionFlags::HAS_FLAGS.bits()
        );
    }

    #[test]
    fn test_empty_server_features_conversion() {
        // Test conversion of empty ServerFeatures
        let empty_features = ServerFeatures::empty();
        let transmission_flags: TransmissionFlags = empty_features.into();

        // Only HAS_FLAGS should be set
        assert!(transmission_flags.contains(TransmissionFlags::HAS_FLAGS));
        assert_eq!(
            transmission_flags.bits(),
            TransmissionFlags::HAS_FLAGS.bits()
        );
    }
}
