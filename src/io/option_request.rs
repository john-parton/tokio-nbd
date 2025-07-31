/// NBD Option Request Wire Format Implementation
///
/// This module implements the wire format deserialization for NBD option requests
/// according to the protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// # Wire Format
/// - 64 bits: 0x49484156454F5054 (ASCII 'IHAVEOPT') magic number
/// - 32 bits: Option identifier
/// - 32 bits: Length of option data
/// - [Data]: Option-specific data of specified length
pub(crate) struct OptionRequestRaw {
    pub(crate) magic: u64,
    pub(crate) option: u32,
    pub(crate) data: Vec<u8>,
}

impl OptionRequestRaw {
    pub(crate) async fn read<R>(reader: &mut R) -> Result<Self, std::io::Error>
    where
        R: tokio::io::AsyncReadExt + Unpin,
    {
        // C: 64 bits, `0x49484156454F5054` (ASCII '`IHAVEOPT`') (note same
        //    newstyle handshake's magic number)
        // C: 32 bits, option
        // C: 32 bits, length of option data (unsigned)
        // C: any data needed for the chosen option, of length as specified above.

        let magic = reader.read_u64().await?;
        let option = reader.read_u32().await?;
        let data_len = reader.read_u32().await?;
        let mut data = vec![0; data_len as usize];
        reader.read_exact(&mut data).await?;

        Ok(Self {
            magic,
            option,
            data,
        })
    }
}
