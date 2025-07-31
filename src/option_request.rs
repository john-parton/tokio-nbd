/// NBD Option Request Types Implementation
///
/// This module implements the NBD (Network Block Device) protocol's option request
/// types and their deserialization according to the protocol specification.
/// These requests are sent by clients during the option negotiation phase.
///
/// For full NBD protocol specification, see:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
use int_enum::IntEnum;

use crate::errors::OptionReplyError;
use crate::info::InformationRequest;
use crate::io::option_request::OptionRequestRaw;

/// Option request types sent by the client during NBD handshake negotiation.
///
/// Values correspond to the NBD protocol's option identifiers in the "option haggling" phase.
/// These are sent after the initial handshake to negotiate export details and protocol features.
#[repr(u32)]
#[derive(Debug, IntEnum)]
enum OptionRequestType {
    /// Request for a specific export by name (NBD_OPT_EXPORT_NAME = 1)
    /// This ends the handshake and begins transmission phase
    ExportName = 1,

    /// Abort negotiation and terminate session (NBD_OPT_ABORT = 2)
    Abort = 2,

    /// List available exports (NBD_OPT_LIST = 3)
    List = 3,

    /// Query details about an export without selecting it (NBD_OPT_PEEK_EXPORT = 4)
    PeekExport = 4,

    /// Request TLS encryption for the session (NBD_OPT_STARTTLS = 5)
    StartTLS = 5,

    /// Request metadata about an export (NBD_OPT_INFO = 6)
    Info = 6,

    /// Request an export and its metadata (NBD_OPT_GO = 7)
    /// This ends the handshake and begins transmission phase
    Go = 7,

    /// Request structured replies during transmission (NBD_OPT_STRUCTURED_REPLY = 8)
    StructuredReply = 8,

    /// List available metadata contexts (NBD_OPT_LIST_META_CONTEXT = 9)
    ListMetaContext = 9,

    /// Set desired metadata contexts (NBD_OPT_SET_META_CONTEXT = 10)
    SetMetaContext = 10,

    /// Request extended headers support (NBD_OPT_EXTENDED_HEADERS = 11)
    ExtendedHeaders = 11,
}

/// NBD client option requests representation.
///
/// This enum represents the parsed option requests from the client according to the NBD protocol.
/// Each variant corresponds to a specific option request type with associated data where applicable.
/// These are deserialized from the wire format sent by clients during option negotiation phase.
#[derive(Debug)]
pub(crate) enum OptionRequest {
    /// Request to use a specific export, ending negotiation and starting transmission
    /// Data: name of the requested export
    ExportName(String),

    /// Request to abort negotiation and disconnect
    Abort,

    /// Request to list available exports on the server
    List,

    // Implementation note: PeekExport is currently unsupported
    // PeekExport(String),
    /// Request to upgrade connection to use TLS
    StartTLS,

    /// Request metadata about an export without selecting it
    /// Data: (export_name, list of information requests)
    Info(String, Vec<InformationRequest>),

    /// Request an export and specific metadata, starting transmission
    /// Data: (export_name, list of information requests)
    Go(String, Vec<InformationRequest>),

    /// Request to use structured replies during transmission
    StructuredReply,

    /// Request to list available metadata contexts for exports
    ListMetaContext,

    /// Request to set specific metadata contexts for use
    /// Data: raw payload containing context identifiers
    SetMetaContext(Vec<u8>),

    /// Request to use extended headers format
    /// Data: raw payload with header specifications
    ExtendedHeaders(Vec<u8>),
}

/// Parse the payload of NBD_OPT_INFO and NBD_OPT_GO requests.
///
/// The payload format for these requests consists of:
/// - 1 byte: length of export name (zero for default export)
/// - N bytes: export name (UTF-8 encoded, not null terminated)
/// - 1 byte: number of information requests
/// - 2*M bytes: M information request identifiers (each 2 bytes)
///
/// # Arguments
/// * `data` - Raw bytes of the option payload
///
/// # Returns
/// * `Ok((export_name, info_requests))` - Tuple of export name and information requests
/// * `Err(OptionReplyError)` - If payload cannot be parsed
fn parse_info_payload(data: &[u8]) -> Result<(String, Vec<InformationRequest>), OptionReplyError> {
    // Empty payload for default export with no specified info requests
    let Some((&name_length, rest)) = data.split_first() else {
        return Ok((String::new(), vec![]));
    };

    let (name, rest) = if name_length == 0 {
        (String::new(), rest)
    } else {
        // Not enough data for the name
        let Some((name, rest)) = rest.split_at_checked(name_length as usize) else {
            return Err(OptionReplyError::Invalid);
        };
        // Possible UTF-8 error
        (
            String::from_utf8(name.into()).map_err(|_| OptionReplyError::Invalid)?,
            rest,
        )
    };

    let Some((&count, rest)) = rest.split_first() else {
        return Err(OptionReplyError::Invalid);
    };

    // No requests is valid
    if count == 0 {
        return Ok((name, vec![]));
    }

    let count = count as usize;

    let (chunks, remainder) = rest.as_chunks::<2>();

    if !remainder.is_empty() || chunks.len() != count {
        return Err(OptionReplyError::Invalid);
    }

    let mut buff = Vec::with_capacity(count);

    for &chunk in chunks {
        match InformationRequest::try_from(u16::from_be_bytes(chunk)) {
            Ok(info_request) => buff.push(info_request),
            // Maybe would be nice to tell the client WHICH operation was unsupported
            // as there are multiple in this payload
            Err(_) => return Err(OptionReplyError::Unsupported),
        }
    }

    Ok((name, buff))
}

/// Conversion from raw NBD option request to structured representation.
///
/// This implementation handles parsing raw NBD request data from the wire format into
/// the appropriate structured Rust types. It validates the magic number, option type,
/// and payload formats according to the NBD protocol specification.
///
/// # NBD Protocol Option Request Format
///
/// ```text
/// C: 64 bits, 0x49484156454F5054 (ASCII 'IHAVEOPT') magic
/// C: 32 bits, option identifier
/// C: 32 bits, length of option data
/// C: [data]: option-specific data of specified length
/// ```
impl TryFrom<&OptionRequestRaw> for OptionRequest {
    type Error = OptionReplyError;

    fn try_from(raw: &OptionRequestRaw) -> Result<Self, Self::Error> {
        // Validate the magic number (IHAVEOPT)
        if raw.magic != crate::magic::NBD_IHAVEOPT {
            return Err(OptionReplyError::Invalid);
        }

        // Convert the numeric option type to enum
        let option_type = match OptionRequestType::try_from(raw.option) {
            Ok(option_type) => option_type,
            Err(_) => {
                return Err(OptionReplyError::Unsupported);
            }
        };

        // Parse based on option type
        let option = match option_type {
            // PeekExport is not supported by this implementation
            OptionRequestType::PeekExport => return Err(OptionReplyError::Unsupported),

            // Parse ExportName: payload is UTF-8 export name
            OptionRequestType::ExportName => {
                let name =
                    String::from_utf8(raw.data.clone()).map_err(|_| OptionReplyError::Invalid)?;
                OptionRequest::ExportName(name)
            }

            // Simple options with no payload
            OptionRequestType::Abort => OptionRequest::Abort,
            OptionRequestType::List => OptionRequest::List,
            OptionRequestType::StartTLS => OptionRequest::StartTLS,
            OptionRequestType::StructuredReply => OptionRequest::StructuredReply,
            OptionRequestType::ListMetaContext => OptionRequest::ListMetaContext,

            // Info and Go have identical payload format: export name + info requests
            OptionRequestType::Info => {
                let (name, info_requests) = parse_info_payload(&raw.data)?;
                OptionRequest::Info(name, info_requests)
            }
            OptionRequestType::Go => {
                let (name, info_requests) = parse_info_payload(&raw.data)?;
                OptionRequest::Go(name, info_requests)
            }

            // Options with complex binary payloads - store raw bytes for now
            OptionRequestType::SetMetaContext => OptionRequest::SetMetaContext(raw.data.clone()),
            OptionRequestType::ExtendedHeaders => OptionRequest::ExtendedHeaders(raw.data.clone()),
        };

        Ok(option)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::magic;

    #[test]
    fn test_option_request_type_conversion() {
        // Test direct conversions to u32
        assert_eq!(OptionRequestType::ExportName as u32, 1);
        assert_eq!(OptionRequestType::Abort as u32, 2);
        assert_eq!(OptionRequestType::List as u32, 3);
        assert_eq!(OptionRequestType::PeekExport as u32, 4);
        assert_eq!(OptionRequestType::StartTLS as u32, 5);
        assert_eq!(OptionRequestType::Info as u32, 6);
        assert_eq!(OptionRequestType::Go as u32, 7);
        assert_eq!(OptionRequestType::StructuredReply as u32, 8);
        assert_eq!(OptionRequestType::ListMetaContext as u32, 9);
        assert_eq!(OptionRequestType::SetMetaContext as u32, 10);
        assert_eq!(OptionRequestType::ExtendedHeaders as u32, 11);

        // Test IntEnum conversions from u32
        match OptionRequestType::try_from(1u32) {
            Ok(request_type) => assert!(matches!(request_type, OptionRequestType::ExportName)),
            Err(_) => panic!("Failed to convert 1 to OptionRequestType::ExportName"),
        }

        match OptionRequestType::try_from(7u32) {
            Ok(request_type) => assert!(matches!(request_type, OptionRequestType::Go)),
            Err(_) => panic!("Failed to convert 7 to OptionRequestType::Go"),
        }

        // Invalid value should return an error
        assert!(OptionRequestType::try_from(99u32).is_err());
    }

    #[test]
    fn test_parse_info_payload_empty() {
        // Test empty payload
        let result = parse_info_payload(&[]);
        assert!(result.is_ok());
        let (name, requests) = result.unwrap();
        assert_eq!(name, "");
        assert!(requests.is_empty());
    }

    #[test]
    fn test_parse_info_payload_with_name() {
        // Test with name only, no requests
        let mut data = vec![5]; // Name length
        data.extend_from_slice(b"hello"); // Name
        data.push(0); // 0 requests

        let result = parse_info_payload(&data);
        assert!(result.is_ok());
        let (name, requests) = result.unwrap();
        assert_eq!(name, "hello");
        assert!(requests.is_empty());
    }

    #[test]
    fn test_try_from_raw_invalid_magic() {
        // Test with invalid magic number
        let raw = OptionRequestRaw {
            magic: 0x123456789, // Invalid magic
            option: 1,          // ExportName
            data: b"export1".to_vec(),
        };

        let result = OptionRequest::try_from(&raw);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OptionReplyError::Invalid));
    }

    #[test]
    fn test_try_from_raw_export_name() {
        // Test valid ExportName request
        let raw = OptionRequestRaw {
            magic: magic::NBD_IHAVEOPT,
            option: 1, // ExportName
            data: b"export1".to_vec(),
        };

        let result = OptionRequest::try_from(&raw);
        assert!(result.is_ok());

        match result.unwrap() {
            OptionRequest::ExportName(name) => assert_eq!(name, "export1"),
            _ => panic!("Wrong variant returned for ExportName"),
        }
    }

    #[test]
    fn test_try_from_raw_unsupported() {
        // Test unsupported option
        let raw = OptionRequestRaw {
            magic: magic::NBD_IHAVEOPT,
            option: 99, // Invalid option
            data: vec![],
        };

        let result = OptionRequest::try_from(&raw);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), OptionReplyError::Unsupported));
    }
}
