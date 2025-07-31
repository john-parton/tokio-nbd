/// NBD Option Reply Wire Format Implementation
///
/// This module implements the wire format serialization for NBD option replies
/// according to the protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// # Wire Format
/// - 64 bits: 0x3e889045565a9 (magic number for replies)
/// - 32 bits: Option type from the client request
/// - 32 bits: Reply type (e.g., NBD_REP_ACK)
/// - 32 bits: Data length (may be zero)
/// - [Data]: Optional payload as required by the reply type
use crate::magic::NBD_REPLY_MAGIC;

/// Raw structure representing NBD option reply on the wire.
///
/// Contains the binary data that will be transmitted to the client.
pub(crate) struct OptionReplyRaw {
    option: u32,
    reply_type: u32,
    data: Vec<u8>,
}

impl OptionReplyRaw {
    pub(crate) fn new(option: u32, reply_type: u32, data: Vec<u8>) -> Self {
        Self {
            option,
            reply_type,
            data,
        }
    }

    pub(crate) async fn write<W>(&self, writer: &mut W) -> Result<(), std::io::Error>
    where
        W: tokio::io::AsyncWriteExt + Unpin,
    {
        // S: 64 bits, `0x3e889045565a9` (magic number for replies)
        // S: 32 bits, the option as sent by the client to which this is a reply
        // S: 32 bits, reply type (e.g., `NBD_REP_ACK` for successful completion,
        //    or `NBD_REP_ERR_UNSUP` to mark use of an option not known by this
        //    server
        // S: 32 bits, length of the reply. This MAY be zero for some replies, in
        //    which case the next field is not sent
        // S: any data as required by the reply (e.g., an export name in the case
        //    of `NBD_REP_SERVER`)

        writer.write_u64(NBD_REPLY_MAGIC).await?;
        writer.write_u32(self.option).await?;
        writer.write_u32(self.reply_type).await?;
        writer.write_u32(self.data.len() as u32).await?;
        writer.write_all(&self.data).await?;
        Ok(())
    }
}
