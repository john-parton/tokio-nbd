/// NBD Information Request Types Implementation
///
/// Defines information types clients can request during NBD negotiation.
/// See protocol spec: https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// # Information Types
/// - Export (0): Size and flags (mandatory)
/// - Name (1): Canonical export name
/// - Description (2): Human-readable description
/// - BlockSize (3): Min/preferred/max block size constraints
/// - MetaContext (4): Metadata context information
use int_enum::IntEnum;

/// Information request types that clients can include in NBD_OPT_INFO and NBD_OPT_GO requests.
///
/// Each variant maps to a specific NBD protocol information type identifier.
/// When included in a request, the server will respond with the corresponding information.
#[repr(u16)]
#[derive(Debug, IntEnum)]
pub(crate) enum InformationRequest {
    /// Export size and transmission flags (NBD_INFO_EXPORT)
    /// Mandatory in server responses to NBD_OPT_INFO and NBD_OPT_GO
    Export = 0,

    /// Canonical name of the export (NBD_INFO_NAME)
    /// May differ from the name used in the request
    Name = 1,

    /// Human-readable description of the export (NBD_INFO_DESCRIPTION)
    /// Suitable for direct display to users
    Description = 2,

    /// Block size constraints (NBD_INFO_BLOCK_SIZE)
    /// Contains minimum, preferred, and maximum block sizes
    BlockSize = 3,

    /// Metadata context information (NBD_REP_META_CONTEXT)
    /// Used for extended metadata capabilities
    MetaContext = 4,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_information_request_conversion() {
        // Test direct conversions to u16
        assert_eq!(InformationRequest::Export as u16, 0);
        assert_eq!(InformationRequest::Name as u16, 1);
        assert_eq!(InformationRequest::Description as u16, 2);
        assert_eq!(InformationRequest::BlockSize as u16, 3);
        assert_eq!(InformationRequest::MetaContext as u16, 4);

        // Test IntEnum conversions from u16
        match InformationRequest::try_from(0u16) {
            Ok(req) => assert!(matches!(req, InformationRequest::Export)),
            Err(_) => panic!("Failed to convert 0 to InformationRequest::Export"),
        }

        match InformationRequest::try_from(3u16) {
            Ok(req) => assert!(matches!(req, InformationRequest::BlockSize)),
            Err(_) => panic!("Failed to convert 3 to InformationRequest::BlockSize"),
        }

        // Invalid value should return an error
        assert!(InformationRequest::try_from(99u16).is_err());
    }
}
