/// NBD Command Request Implementation
///
/// This module defines the commands that can be sent during the NBD transmission phase
/// according to the protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// Commands are used to read from, write to, and manage NBD devices after
/// the connection has been established and negotiated.
use int_enum::IntEnum;

use crate::errors::ProtocolError;
use crate::io::command_request::CommandRequestRaw;
use crate::magic::NBD_REQUEST_MAGIC;

/// Command types used in the NBD transmission phase.
///
/// Values correspond to the command type field in the NBD protocol.
#[repr(u16)]
#[derive(Debug, PartialEq, Eq, IntEnum)]
enum CommandType {
    /// Read data from device (offset, length)
    Read = 0,

    /// Write data to device (offset, data)
    Write = 1,

    /// Terminate the connection
    Disconnect = 2,

    /// Flush data to persistent storage
    Flush = 3,

    /// Discard/punch hole (offset, length)
    Trim = 4,

    /// Request caching of region (offset, length)
    Cache = 5,

    /// Write zeros efficiently (offset, length)
    WriteZeroes = 6,

    /// Query block allocation status (offset, length)
    BlockStatus = 7,

    /// Change device size
    Resize = 8,
}

/// NBD command requests for the transmission phase.
///
/// Each variant contains the data needed for its corresponding command type.
#[derive(Debug)]
pub(crate) enum CommandRequest {
    /// Read from device: (offset, length)
    Read(u64, u32),

    /// Write to device: (offset, data)
    Write(u64, Vec<u8>),

    /// Flush data to persistent storage
    Flush,

    /// Discard/punch hole: (offset, length)
    Trim(u64, u32),

    /// Write zeros efficiently: (offset, length)
    WriteZeroes(u64, u32),

    /// Terminate the connection
    Disconnect,

    /// Change device size to new_size
    Resize(u64),

    /// Request caching of region: (offset, length)
    Cache(u64, u32),

    /// Query block allocation status: (offset, length)
    BlockStatus(u64, u32),
}

impl TryFrom<&CommandRequestRaw> for CommandRequest {
    type Error = ProtocolError;

    fn try_from(command_raw: &CommandRequestRaw) -> Result<Self, Self::Error> {
        if command_raw.magic != NBD_REQUEST_MAGIC {
            return Err(ProtocolError::InvalidArgument);
        }

        let command_type = CommandType::try_from(command_raw.command_type)
            .map_err(|_| ProtocolError::CommandNotSupported)?;

        let offset = command_raw.offset;
        let length = command_raw.length;

        debug_assert!(command_raw.data.is_empty() || command_type == CommandType::Write);

        Ok(match command_type {
            CommandType::Read => Self::Read(offset, length),
            CommandType::Write => Self::Write(offset, command_raw.data.clone()),
            CommandType::Flush => Self::Flush,
            CommandType::Trim => Self::Trim(offset, length),
            CommandType::WriteZeroes => Self::WriteZeroes(offset, length),
            CommandType::Disconnect => Self::Disconnect,
            CommandType::Resize => Self::Resize(offset),
            CommandType::Cache => Self::Cache(offset, length),
            CommandType::BlockStatus => Self::BlockStatus(offset, length),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_type_conversion() {
        // Test direct conversions to u16
        assert_eq!(CommandType::Read as u16, 0);
        assert_eq!(CommandType::Write as u16, 1);
        assert_eq!(CommandType::Disconnect as u16, 2);
        assert_eq!(CommandType::Flush as u16, 3);
        assert_eq!(CommandType::Trim as u16, 4);
        assert_eq!(CommandType::Cache as u16, 5);
        assert_eq!(CommandType::WriteZeroes as u16, 6);
        assert_eq!(CommandType::BlockStatus as u16, 7);
        assert_eq!(CommandType::Resize as u16, 8);

        // Test IntEnum conversions from u16
        match CommandType::try_from(0u16) {
            Ok(cmd_type) => assert!(matches!(cmd_type, CommandType::Read)),
            Err(_) => panic!("Failed to convert 0 to CommandType::Read"),
        }

        match CommandType::try_from(3u16) {
            Ok(cmd_type) => assert!(matches!(cmd_type, CommandType::Flush)),
            Err(_) => panic!("Failed to convert 3 to CommandType::Flush"),
        }

        match CommandType::try_from(8u16) {
            Ok(cmd_type) => assert!(matches!(cmd_type, CommandType::Resize)),
            Err(_) => panic!("Failed to convert 8 to CommandType::Resize"),
        }

        // Invalid value should return an error
        assert!(CommandType::try_from(99u16).is_err());
    }

    #[test]
    fn test_try_from_raw_valid_read() {
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Read as u16,
            cookie: 42,
            offset: 1024,
            length: 512,
            data: vec![],
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_ok());

        if let Ok(CommandRequest::Read(offset, length)) = result {
            assert_eq!(offset, 1024);
            assert_eq!(length, 512);
        } else {
            panic!("Expected CommandRequest::Read variant");
        }
    }

    #[test]
    fn test_try_from_raw_valid_write() {
        let data = vec![1, 2, 3, 4, 5];
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Write as u16,
            cookie: 43,
            offset: 2048,
            length: data.len() as u32,
            data: data.clone(),
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_ok());

        if let Ok(CommandRequest::Write(offset, payload)) = result {
            assert_eq!(offset, 2048);
            assert_eq!(payload, data);
        } else {
            panic!("Expected CommandRequest::Write variant");
        }
    }

    #[test]
    fn test_try_from_raw_valid_flush() {
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Flush as u16,
            cookie: 44,
            offset: 0,
            length: 0,
            data: vec![],
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_ok());

        assert!(matches!(result.unwrap(), CommandRequest::Flush));
    }

    #[test]
    fn test_try_from_raw_invalid_magic() {
        let raw = CommandRequestRaw {
            magic: 0x12345678, // Invalid magic
            flags: 0,
            command_type: CommandType::Read as u16,
            cookie: 45,
            offset: 1024,
            length: 512,
            data: vec![],
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProtocolError::InvalidArgument);
    }

    #[test]
    fn test_try_from_raw_unsupported_command() {
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: 99, // Invalid command type
            cookie: 46,
            offset: 1024,
            length: 512,
            data: vec![],
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ProtocolError::CommandNotSupported);
    }

    #[test]
    fn test_try_from_raw_other_commands() {
        // Test Trim command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Trim as u16,
            cookie: 47,
            offset: 4096,
            length: 1024,
            data: vec![],
        };

        if let Ok(CommandRequest::Trim(offset, length)) = CommandRequest::try_from(&raw) {
            assert_eq!(offset, 4096);
            assert_eq!(length, 1024);
        } else {
            panic!("Expected CommandRequest::Trim variant");
        }

        // Test WriteZeroes command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::WriteZeroes as u16,
            cookie: 48,
            offset: 8192,
            length: 2048,
            data: vec![],
        };

        if let Ok(CommandRequest::WriteZeroes(offset, length)) = CommandRequest::try_from(&raw) {
            assert_eq!(offset, 8192);
            assert_eq!(length, 2048);
        } else {
            panic!("Expected CommandRequest::WriteZeroes variant");
        }

        // Test Resize command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Resize as u16,
            cookie: 49,
            offset: 65536, // New size
            length: 0,
            data: vec![],
        };

        if let Ok(CommandRequest::Resize(size)) = CommandRequest::try_from(&raw) {
            assert_eq!(size, 65536);
        } else {
            panic!("Expected CommandRequest::Resize variant");
        }
    }

    #[test]
    fn test_try_from_raw_disconnect() {
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Disconnect as u16,
            cookie: 50,
            offset: 0,
            length: 0,
            data: vec![],
        };

        let result = CommandRequest::try_from(&raw);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), CommandRequest::Disconnect));
    }

    #[test]
    fn test_try_from_raw_cache_and_block_status() {
        // Test Cache command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Cache as u16,
            cookie: 51,
            offset: 16384,
            length: 4096,
            data: vec![],
        };

        if let Ok(CommandRequest::Cache(offset, length)) = CommandRequest::try_from(&raw) {
            assert_eq!(offset, 16384);
            assert_eq!(length, 4096);
        } else {
            panic!("Expected CommandRequest::Cache variant");
        }

        // Test BlockStatus command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::BlockStatus as u16,
            cookie: 52,
            offset: 32768,
            length: 8192,
            data: vec![],
        };

        if let Ok(CommandRequest::BlockStatus(offset, length)) = CommandRequest::try_from(&raw) {
            assert_eq!(offset, 32768);
            assert_eq!(length, 8192);
        } else {
            panic!("Expected CommandRequest::BlockStatus variant");
        }
    }

    #[test]
    #[should_panic(
        expected = "assertion failed: command_raw.data.is_empty() || command_type == CommandType::Write"
    )]
    fn test_try_from_raw_invalid_write_data() {
        // This test verifies that the debug_assert triggers when data is provided for a non-write command
        let raw = CommandRequestRaw {
            magic: NBD_REQUEST_MAGIC,
            flags: 0,
            command_type: CommandType::Read as u16, // Not a write command
            cookie: 53,
            offset: 1024,
            length: 512,
            data: vec![1, 2, 3, 4], // Data included but not a write command
        };

        // This should panic in debug mode due to the debug_assert
        let _ = CommandRequest::try_from(&raw);
    }
}
