/// NBD Command Reply Wire Format Implementation
///
/// This module handles the serialization of NBD command replies during the
/// transmission phase according to the protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// # Wire Format
/// - 32 bits: Magic (0x67446698)
/// - 32 bits: Error (0 for success)
/// - 64 bits: Handle (cookie matching the request)
/// - [Data]: Reply data (only for read commands)
use tokio::io::AsyncWriteExt;

/// Raw representation of a simple NBD reply for transmission
pub(crate) struct SimpleReplyRaw {
    error: u32,
    cookie: u64,
    data: Vec<u8>,
}

impl SimpleReplyRaw {
    const NBD_SIMPLE_REPLY_MAGIC: u32 = 0x67446698;

    pub(crate) fn new(error: u32, cookie: u64, data: Vec<u8>) -> Self {
        Self {
            error,
            cookie,
            data,
        }
    }

    pub(crate) async fn write<W>(&self, writer: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWriteExt + Unpin,
    {
        writer.write_u32(Self::NBD_SIMPLE_REPLY_MAGIC).await?;
        writer.write_u32(self.error).await?;
        writer.write_u64(self.cookie).await?;
        if !self.data.is_empty() {
            writer.write_all(&self.data).await?;
        }
        Ok(())
    }
}

// Don't include data in debug output
impl std::fmt::Debug for SimpleReplyRaw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        #[derive(Debug)]
        struct SimpleReplyRaw<'a> {
            error: &'a u32,
            cookie: &'a u64,
        }

        let tmp = SimpleReplyRaw {
            error: &self.error,
            cookie: &self.cookie,
        };

        std::fmt::Debug::fmt(&tmp, f)
    }
}
