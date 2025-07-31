/// NBD Protocol Magic Numbers
///
/// This module contains the magic numbers defined in the NBD protocol specification:
/// https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md
///
/// Magic numbers are used to identify different parts of the NBD protocol,
/// ensure message integrity, and detect protocol version.

/// Initial handshake identifier (ASCII "NBDMAGIC")
pub(crate) const NBD_MAGIC: u64 = 0x4e42444d41474943;

/// Newstyle negotiation magic (ASCII "IHAVEOPT")
pub(crate) const NBD_IHAVEOPT: u64 = 0x49484156454F5054;

/// Option reply magic (fixed value from protocol)
pub(crate) const NBD_REPLY_MAGIC: u64 = 0x3e889045565a9;

/// NBD Request Magic value from protocol specification
pub(crate) const NBD_REQUEST_MAGIC: u32 = 0x25609513;
