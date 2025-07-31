/// NBD Command Request Wire Format Implementation
///
/// This module handles the deserialization of NBD command requests during the 
/// transmission phase according to the protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// # Wire Format
/// - 32 bits: Magic (0x25609513)
/// - 16 bits: Command flags
/// - 16 bits: Command type
/// - 64 bits: Handle (cookie)
/// - 64 bits: Offset
/// - 32 bits: Length
/// - [Data]: Command data (only for write commands)
use tokio::io::AsyncReadExt;

/// Raw representation of an NBD command request from the wire format
pub(crate) struct CommandRequestRaw {
    pub(crate) magic: u32,
    pub(crate) flags: u16,
    pub(crate) command_type: u16,
    pub(crate) cookie: u64,
    pub(crate) offset: u64,
    pub(crate) length: u32,
    pub(crate) data: Vec<u8>,
}

impl CommandRequestRaw {
    // Only the write command has data.
    const WRITE_COMMAND: u16 = 1;

    pub(crate) async fn read<R>(reader: &mut R) -> Result<Self, std::io::Error>
    where
        R: AsyncReadExt + Unpin,
    {
        let magic = reader.read_u32().await?;
        let flags = reader.read_u16().await?;
        let command_type = reader.read_u16().await?;
        let cookie = reader.read_u64().await?;
        let offset = reader.read_u64().await?;
        let length = reader.read_u32().await?;

        let data = if command_type == Self::WRITE_COMMAND {
            let mut data = vec![0; length as usize];
            reader.read_exact(&mut data).await?;
            data
        } else {
            vec![] // No data for other commands
        };

        Ok(Self {
            magic,
            flags,
            command_type,
            cookie,
            offset,
            length,
            data,
        })
    }
}
