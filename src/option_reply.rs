/// NBD Option Reply Types Implementation
///
/// This module implements the NBD (Network Block Device) protocol's option reply
/// types and their serialization according to the protocol specification.
/// These replies are sent by the server during option negotiation.
///
/// For full NBD protocol specification, see:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
use int_enum::IntEnum;

use crate::flags::TransmissionFlags;

/// Option reply types sent by the server during NBD negotiation.
///
/// Values correspond to the "reply type" field in the NBD protocol.
#[repr(u32)]
#[derive(Debug, IntEnum, PartialEq, Eq)]
pub(crate) enum OptionReplyType {
    /// Acknowledges option with no additional data (NBD_REP_ACK)
    Ack = 1,

    /// Provides export description (NBD_REP_SERVER)
    /// Data: export name and optional human-readable details
    Server = 2,

    /// Detailed export information (NBD_REP_INFO)
    /// Data: export size, flags, name, description, or block size constraints
    Info = 3,

    /// Metadata context information (NBD_REP_META_CONTEXT)
    /// Data: context ID and name
    MetaContext = 4,
    // Error replies have bit 31 set and may include error message text:

    // NBD_REP_ERR_UNSUP (2^31 + 1): Option unknown by server
    // NBD_REP_ERR_POLICY (2^31 + 2): Option forbidden by server policy
    // NBD_REP_ERR_INVALID (2^31 + 3): Option syntactically/semantically invalid
    // NBD_REP_ERR_PLATFORM (2^31 + 4): Option not supported on this platform
    // NBD_REP_ERR_TLS_REQD (2^31 + 5): TLS required to continue
    // NBD_REP_ERR_UNKNOWN (2^31 + 6): Export not available
    // NBD_REP_ERR_SHUTDOWN (2^31 + 7): Server shutting down
    // NBD_REP_ERR_BLOCK_SIZE_REQD (2^31 + 8): Client must acknowledge block sizing
    // NBD_REP_ERR_TOO_BIG (2^31 + 9): Request/reply too large
    // NBD_REP_ERR_EXT_HEADER_REQD (2^31 + 10): Extended headers required
}

/// Information payloads for NBD_REP_INFO replies.
///
/// These variants correspond to the info types (0-3) defined in the NBD protocol.
#[derive(Debug)]
pub(crate) enum InfoPayload {
    /// NBD_INFO_EXPORT (0): Size and flags for an export
    /// Length: 12 bytes
    Export(u64, TransmissionFlags),

    /// NBD_INFO_NAME (1): Canonical name of the export
    Name(String),

    /// NBD_INFO_DESCRIPTION (2): Human-readable description
    Description(String),

    /// NBD_INFO_BLOCK_SIZE (3): Size constraints
    /// Format: (min_block, preferred_block, max_block)
    BlockSize(u32, u32, u32),
}

impl InfoPayload {
    /// Serializes payload according to NBD protocol format.
    fn to_vec(&self) -> Vec<u8> {
        match self {
            InfoPayload::Export(size, flags) => {
                let mut data = Vec::with_capacity(12);
                data.extend(&0u16.to_be_bytes());
                data.extend(&size.to_be_bytes());
                data.extend(&flags.bits().to_be_bytes());
                data
            }
            InfoPayload::Name(name) => {
                let mut data = Vec::new();
                data.extend(1u16.to_be_bytes());
                data.extend(name.bytes());
                data
            }
            InfoPayload::Description(desc) => {
                let mut data = Vec::new();
                data.extend(2u16.to_be_bytes());
                data.extend(desc.bytes());
                data
            }
            InfoPayload::BlockSize(min, preferred, max) => {
                let mut data = Vec::with_capacity(14);
                data.extend(3u16.to_be_bytes());
                data.extend(min.to_be_bytes());
                data.extend(preferred.to_be_bytes());
                data.extend(max.to_be_bytes());
                data
            }
        }
    }
}

/// NBD option replies that can be sent by the server.
///
/// Each variant contains the data needed for its corresponding reply type.
#[derive(Debug)]
pub(crate) enum OptionReply {
    /// NBD_REP_ACK: Simple acknowledgment
    Ack,

    /// NBD_REP_SERVER: Export information
    Server(String),

    /// NBD_REP_INFO: Detailed export information
    Info(InfoPayload),

    /// NBD_REP_META_CONTEXT: Metadata context
    MetaContext(u32, String),
}

impl OptionReply {
    /// Returns the corresponding reply type enum value
    pub(crate) fn get_reply_type(&self) -> OptionReplyType {
        match self {
            OptionReply::Ack => OptionReplyType::Ack,
            OptionReply::Server(_) => OptionReplyType::Server,
            OptionReply::Info(_) => OptionReplyType::Info,
            OptionReply::MetaContext(_, _) => OptionReplyType::MetaContext,
        }
    }

    /// Serializes the reply data according to NBD protocol format
    pub(crate) fn get_data(&self) -> Vec<u8> {
        match self {
            OptionReply::Ack => vec![],
            OptionReply::Server(name) => name.as_bytes().to_vec(),
            OptionReply::Info(payload) => payload.to_vec(),
            OptionReply::MetaContext(id, name) => {
                let mut data = id.to_be_bytes().to_vec();
                data.extend(name.as_bytes());
                data
            }
        }
    }
}

// NBD Protocol Option Reply Format:
// - 64 bits: 0x3e889045565a9 (magic number for replies)
// - 32 bits: Option type from the client request
// - 32 bits: Reply type (e.g., NBD_REP_ACK)
// - 32 bits: Data length (may be zero)
// - [Data]: Optional payload as required by the reply type

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_reply_type_conversion() {
        // Test direct conversions to u32
        assert_eq!(OptionReplyType::Ack as u32, 1);
        assert_eq!(OptionReplyType::Server as u32, 2);
        assert_eq!(OptionReplyType::Info as u32, 3);
        assert_eq!(OptionReplyType::MetaContext as u32, 4);

        // Test IntEnum conversions from u32
        match OptionReplyType::try_from(1u32) {
            Ok(reply_type) => assert!(matches!(reply_type, OptionReplyType::Ack)),
            Err(_) => panic!("Failed to convert 1 to OptionReplyType::Ack"),
        }

        match OptionReplyType::try_from(2u32) {
            Ok(reply_type) => assert!(matches!(reply_type, OptionReplyType::Server)),
            Err(_) => panic!("Failed to convert 2 to OptionReplyType::Server"),
        }

        match OptionReplyType::try_from(3u32) {
            Ok(reply_type) => assert!(matches!(reply_type, OptionReplyType::Info)),
            Err(_) => panic!("Failed to convert 3 to OptionReplyType::Info"),
        }

        match OptionReplyType::try_from(4u32) {
            Ok(reply_type) => assert!(matches!(reply_type, OptionReplyType::MetaContext)),
            Err(_) => panic!("Failed to convert 4 to OptionReplyType::MetaContext"),
        }

        // Invalid value should return an error
        assert!(OptionReplyType::try_from(99u32).is_err());
    }

    #[test]
    fn test_option_reply_get_reply_type() {
        // Test that reply type matches the expected enum variant
        match OptionReply::Ack.get_reply_type() {
            OptionReplyType::Ack => (),
            _ => panic!("OptionReply::Ack returned wrong reply type"),
        }

        match OptionReply::Server("export1".to_string()).get_reply_type() {
            OptionReplyType::Server => (),
            _ => panic!("OptionReply::Server returned wrong reply type"),
        }

        match OptionReply::Info(InfoPayload::Name("export1".to_string())).get_reply_type() {
            OptionReplyType::Info => (),
            _ => panic!("OptionReply::Info returned wrong reply type"),
        }

        match OptionReply::MetaContext(42, "meta".to_string()).get_reply_type() {
            OptionReplyType::MetaContext => (),
            _ => panic!("OptionReply::MetaContext returned wrong reply type"),
        }
    }

    #[test]
    fn test_option_reply_get_data_ack() {
        let data = OptionReply::Ack.get_data();
        assert!(data.is_empty());
    }

    #[test]
    fn test_option_reply_get_data_server() {
        let export_name = "test_export";
        let data = OptionReply::Server(export_name.to_string()).get_data();
        assert_eq!(data, export_name.as_bytes());
    }

    #[test]
    fn test_option_reply_get_data_meta_context() {
        let id = 42u32;
        let name = "meta_context";
        let data = OptionReply::MetaContext(id, name.to_string()).get_data();

        // First 4 bytes should be the id
        let mut expected = id.to_be_bytes().to_vec();
        // Followed by the name
        expected.extend_from_slice(name.as_bytes());

        assert_eq!(data, expected);
    }

    #[test]
    fn test_info_payload_export() {
        use crate::flags::TransmissionFlags;

        let size = 1024u64;
        let flags = TransmissionFlags::HAS_FLAGS | TransmissionFlags::READ_ONLY;
        let flags_bits = flags.bits();

        // Create a copy of flags for the test
        let flags2 = TransmissionFlags::HAS_FLAGS | TransmissionFlags::READ_ONLY;
        let data = InfoPayload::Export(size, flags2).to_vec();

        // Check length
        assert_eq!(data.len(), 12);

        // First 2 bytes should be export type (0)
        assert_eq!(&data[0..2], &[0, 0]);

        // Next 8 bytes should be size in big-endian
        let size_bytes = size.to_be_bytes();
        assert_eq!(&data[2..10], &size_bytes);

        // Last 2 bytes should be flags
        let flags_bytes = flags_bits.to_be_bytes();
        assert_eq!(&data[10..12], &flags_bytes);
    }

    #[test]
    fn test_info_payload_name() {
        let name = "test_export";
        let data = InfoPayload::Name(name.to_string()).to_vec();

        // First 2 bytes should be name type (1)
        assert_eq!(&data[0..2], &[0, 1]);

        // Rest should be name
        assert_eq!(&data[2..], name.as_bytes());
    }

    #[test]
    fn test_info_payload_description() {
        let desc = "Test export description";
        let data = InfoPayload::Description(desc.to_string()).to_vec();

        // First 2 bytes should be description type (2)
        assert_eq!(&data[0..2], &[0, 2]);

        // Rest should be description
        assert_eq!(&data[2..], desc.as_bytes());
    }

    #[test]
    fn test_info_payload_block_size() {
        let min = 512u32;
        let preferred = 4096u32;
        let max = 33554432u32; // 32MB

        let data = InfoPayload::BlockSize(min, preferred, max).to_vec();

        // Check length
        assert_eq!(data.len(), 14);

        // First 2 bytes should be block size type (3)
        assert_eq!(&data[0..2], &[0, 3]);

        // Next 4 bytes should be min
        let min_bytes = min.to_be_bytes();
        assert_eq!(&data[2..6], &min_bytes);

        // Next 4 bytes should be preferred
        let preferred_bytes = preferred.to_be_bytes();
        assert_eq!(&data[6..10], &preferred_bytes);

        // Last 4 bytes should be max
        let max_bytes = max.to_be_bytes();
        assert_eq!(&data[10..14], &max_bytes);
    }

    #[test]
    fn test_info_payload_via_option_reply() {
        // Test that Info payload is correctly passed through OptionReply
        let desc = "Test description";
        let info_payload = InfoPayload::Description(desc.to_string());
        let option_reply = OptionReply::Info(info_payload);

        let data = option_reply.get_data();

        // First 2 bytes should be description type (2)
        assert_eq!(&data[0..2], &[0, 2]);

        // Rest should be description
        assert_eq!(&data[2..], desc.as_bytes());
    }
}
