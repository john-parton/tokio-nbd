//! Network Block Device (NBD) driver implementation and server functionality.
//!
//! This module provides the core components for implementing an NBD server:
//!
//! - [`NBDDriver`]: A trait for implementing storage backends
//! - [`NBDServer`]: A server implementation that handles the NBD protocol
//!
//! The NBD protocol enables remote access to block devices over a network connection.
//! It consists of two phases:
//!
//! 1. **Handshake and negotiation phase**: Where the server and client establish
//!    capabilities and select an export (a block device to be served).
//! 2. **Transmission phase**: Where commands like read/write operations are handled.
//!
//! # Usage
//!
//! To create an NBD server:
//!
//! 1. Implement the [`NBDDriver`] trait for your storage backend
//! 2. Create an instance of [`NBDServer`] with your driver
//! 3. Call `start()` with a TcpStream to begin serving
//!
//! ```rust,compile_fail
//! use tokio_nbd::driver::{NBDDriver, NBDServer};
//! use tokio_nbd::flags::ServerFeatures;
//! use tokio_nbd::errors::{ProtocolError, OptionReplyError};
//! use tokio::net::{TcpListener, TcpStream};
//! use std::sync::{Arc, RwLock};
//!
//! // Implement a simple in-memory driver
//! struct MemoryDriver {
//!     data: RwLock<Vec<u8>>,
//! }
//!
//! // ... implement NBDDriver for MemoryDriver
//!
//! async fn start_nbd(host: &str, port: u16, driver: Arc<MemoryDriver>) -> std::io::Result<()> {
//!     let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;
//!     println!("NBD server listening on {}:{}", host, port);
//!
//!     loop {
//!         let (stream, addr) = listener.accept().await?;
//!         println!("NBD client connected from {}", addr);
//!
//!         let driver = Arc::clone(&driver);
//!
//!         tokio::spawn(async move {
//!             let server = NBDServer::new(driver);
//!
//!             if let Err(e) = server.start(stream).await {
//!                 println!("Error starting NBD server: {:?}", e);
//!                 return;
//!             }
//!         });
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // Need signal handling for graceful shutdown in production code
//!
//!     let port: u16 = 10809; // Default NBD port
//!
//!     println!("Starting NBD server on port {}", port);
//!     
//!     // Create a driver with 1MB of storage
//!     let driver = Arc::new(MemoryDriver {
//!         data: RwLock::new(vec![0; 1024 * 1024]),
//!     });
//!
//!     start_nbd("127.0.0.1", port, driver)
//!         .await
//!         .map_err(|e| {
//!             println!("Failed to start NBD server: {:?}", e);
//!             std::io::Error::new(std::io::ErrorKind::Other, "Failed to start NBD server")
//!         })
//! }
//! ```
//!
//! # Protocol Compliance
//!
//! This implementation follows the NBD protocol specification as defined at
//! [NetworkBlockDevice/nbd](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md).
//!
//! # Security Considerations
//!
//! NBD does not provide built-in authentication or encryption. For secure deployments:
//!
//! - Use on trusted networks only
//! - Consider implementing TLS support (with the `START_TLS` option)
//! - Use firewall rules to restrict access
//!

use std::sync::Arc;
use std::{io, vec};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;

use crate::command_request::CommandRequest;
use crate::errors::{OptionReplyError, ProtocolError};
use crate::flags::{CommandFlags, HandshakeFlags, ServerFeatures, TransmissionFlags};
use crate::io::command_reply::SimpleReplyRaw;
use crate::io::command_request::CommandRequestRaw;
use crate::io::option_reply::OptionReplyRaw;
use crate::io::option_request::OptionRequestRaw;
use crate::magic::{NBD_IHAVEOPT, NBD_MAGIC};
use crate::option_reply::{InfoPayload, OptionReply};
use crate::option_request::OptionRequest;
use std::future::Future;

/// A trait that represents a Network Block Device driver implementation.
///
/// This trait defines the interface that must be implemented to provide
/// a functional NBD server. Implementors of this trait will handle the
/// actual storage operations, while the NBD protocol handling is
/// provided by the `NBDServer`.
///
/// # Implementation Guidelines
///
/// When implementing this trait:
///
/// 1. Consider which server features you want to support and expose them
///    via the `get_features()` method
/// 2. For features you don't support, return `ProtocolError::CommandNotSupported`
///    from the corresponding method
/// 3. Implement proper error handling for all methods
/// 4. Consider thread safety if your implementation will be shared across threads
///
/// # Default Implementations
///
/// For many methods, if your driver doesn't support the functionality, you should
/// return `ProtocolError::CommandNotSupported`. This is particularly common for:
///
/// - `cache`: Many backends don't need explicit caching
/// - `trim`: Not all storage systems support hole punching
/// - `write_zeroes`: May not be optimized in some backends
/// - `block_status`: Advanced feature rarely implemented
/// - `resize`: Many backends don't support dynamic resizing
///
/// # Example Implementation
///
/// Here's a simplified example of a memory-backed NBD driver:
///
/// ```rust,compile_fail
/// use tokio_nbd::driver::NBDDriver;
/// use tokio_nbd::flags::{ServerFeatures, CommandFlags};
/// use tokio_nbd::errors::{ProtocolError, OptionReplyError};
/// use std::sync::RwLock;
/// use std::future::Future;
/// use std::pin::Pin;
///
/// struct MemoryDriver {
///     data: RwLock<Vec<u8>>,
/// }
///
/// impl NBDDriver for MemoryDriver {
///     fn get_features(&self) -> ServerFeatures {
///         // Support basic read/write operations but not advanced features
///         ServerFeatures::SEND_FLUSH | ServerFeatures::SEND_FUA
///     }
///     
///     // Basic device info methods implementation
///     async fn list_devices(&self) -> Result<Vec<String>, OptionReplyError> {
///         // Only one device available
///         Ok(vec!["memory".to_string()])
///     }
///     
///     async fn get_read_only(&self, device_name: &str) -> Result<bool, OptionReplyError> {
///         if device_name == "memory" {
///             Ok(false) // Device is writable
///         } else {
///             Err(OptionReplyError::Unknown)
///         }
///     }
///     
///     // Example of a core data operation
///     async fn read(
///         &self,
///         _flags: CommandFlags,
///         offset: u64,
///         length: u32,
///     ) -> Result<Vec<u8>, ProtocolError> {
///         let data = self.data.read().unwrap();
///         let start = offset as usize;
///         let end = start + length as usize;
///         
///         if end > data.len() {
///             return Err(ProtocolError::InvalidArgument);
///         }
///         
///         Ok(data[start..end].to_vec())
///     }
///     
///     // Example of an unsupported operation
///     async fn cache(
///         &self,
///         _flags: CommandFlags,
///         _offset: u64,
///         _length: u32,
///     ) -> Result<(), ProtocolError> {
///         // Memory-backed driver doesn't need explicit caching
///         Err(ProtocolError::CommandNotSupported)
///     }
///     
///     // Other methods implementation...
/// }
/// ```
pub trait NBDDriver {
    /// Returns the features supported by this driver implementation.
    ///
    /// This method should return a combination of `ServerFeatures` flags
    /// that indicate which NBD protocol features are supported by this driver.
    /// These features will be advertised to clients during the negotiation phase.
    fn get_features(&self) -> ServerFeatures;

    /// Returns a list of available devices provided by this driver.
    ///
    /// # Returns
    /// - `Ok(Vec<String>)`: A list of device names that can be exported
    /// - `Err(OptionReplyError)`: If an error occurs while retrieving the device list
    fn list_devices(&self) -> impl Future<Output = Result<Vec<String>, OptionReplyError>>;

    /// Checks if a device is read-only.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device to check
    ///
    /// # Returns
    /// - `Ok(bool)`: `true` if the device is read-only, `false` otherwise
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_read_only(
        &self,
        device_name: &str,
    ) -> impl Future<Output = Result<bool, OptionReplyError>>;

    /// Returns the block size information for a device.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device to query
    ///
    /// # Returns
    /// - `Ok((min_block_size, preferred_block_size, max_block_size))`: Block size constraints for the device
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_block_size(
        &self,
        device_name: &str,
    ) -> impl Future<Output = Result<(u32, u32, u32), OptionReplyError>>;

    /// Returns the canonical name of a device.
    ///
    /// The canonical name may differ from the requested name if aliases are supported.
    ///
    /// # Parameters
    /// - `device_name`: The name or alias of the device
    ///
    /// # Returns
    /// - `Ok(String)`: The canonical device name
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_canonical_name(
        &self,
        device_name: &str,
    ) -> impl Future<Output = Result<String, OptionReplyError>>;

    /// Returns a human-readable description of the device.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device
    ///
    /// # Returns
    /// - `Ok(String)`: The device description
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_description(
        &self,
        device_name: &str,
    ) -> impl Future<Output = Result<String, OptionReplyError>>;

    /// Returns the size of a device in bytes.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device
    ///
    /// # Returns
    /// - `Ok(u64)`: The device size in bytes
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_device_size(
        &self,
        device_name: &str,
    ) -> impl Future<Output = Result<u64, OptionReplyError>>;

    // ----- Core Data Operations -----

    /// Reads data from the device.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the read operation
    /// - `offset`: Byte offset within the device to start reading from
    /// - `length`: Number of bytes to read
    ///
    /// # Returns
    /// - `Ok(Vec<u8>)`: The data read from the device
    /// - `Err(ProtocolError)`: If an error occurs during the read operation
    ///
    /// # Implementation Notes
    /// - Check for out-of-bounds reads and return appropriate errors
    /// - Honor any relevant flags (e.g., `CommandFlags::DF` for Don't Fragment)
    /// - For optimal performance, consider pre-allocating the result vector
    fn read(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<Vec<u8>, ProtocolError>>;

    /// Writes data to the device.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the write operation
    /// - `offset`: Byte offset within the device to start writing to
    /// - `data`: The data to write to the device
    ///
    /// # Returns
    /// - `Ok(())`: If the write operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs during the write operation
    ///
    /// # Implementation Notes
    /// - Check for out-of-bounds writes and return appropriate errors
    /// - Honor the Force Unit Access flag (`CommandFlags::FUA`) if supported
    /// - Consider atomicity guarantees for your storage backend
    fn write(
        &self,
        flags: CommandFlags,
        offset: u64,
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Ensures all pending writes are committed to stable storage.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the flush operation
    ///
    /// # Returns
    /// - `Ok(())`: If the flush operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs during the flush operation
    ///
    /// # Implementation Notes
    /// - If your backend doesn't need explicit flushing, you can implement this as a no-op
    /// - This operation should block until all data is safely persisted
    fn flush(&self, flags: CommandFlags) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Discards (trims) a range of bytes on the device.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the trim operation
    /// - `offset`: Byte offset within the device to start trimming from
    /// - `length`: Number of bytes to trim
    ///
    /// # Returns
    /// - `Ok(())`: If the trim operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs or trim operations are not supported
    ///
    /// # Implementation Notes
    /// - If your storage backend doesn't support trim operations, return `ProtocolError::CommandNotSupported`
    /// - This operation indicates that the data in the specified range is no longer needed
    fn trim(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Writes zeroes to a range of bytes on the device.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the write zeroes operation
    /// - `offset`: Byte offset within the device to start writing zeroes from
    /// - `length`: Number of bytes to zero
    ///
    /// # Returns
    /// - `Ok(())`: If the write zeroes operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs or the operation is not supported
    ///
    /// # Implementation Notes
    /// - If `CommandFlags::NO_HOLE` is set, the operation should ensure the resulting zeroes will read back as zeroes
    /// - If your backend has a native "write zeroes" operation, use it for efficiency
    /// - Otherwise, consider whether to allocate and write a buffer of zeroes or to use hole punching
    fn write_zeroes(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Notifies the driver that a client is disconnecting.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the disconnect operation
    ///
    /// # Returns
    /// - `Ok(())`: If the disconnect operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs during the disconnect operation
    ///
    /// # Implementation Notes
    /// - Use this to clean up any resources associated with the client
    /// - This is the last command sent by a client before disconnecting
    fn disconnect(&self, flags: CommandFlags) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Resizes the device to the specified size.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the resize operation
    /// - `size`: The new size of the device in bytes
    ///
    /// # Returns
    /// - `Ok(())`: If the resize operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs or resize operations are not supported
    ///
    /// # Implementation Notes
    /// - If your storage backend doesn't support dynamic resizing, return `ProtocolError::CommandNotSupported`
    /// - If resizing would cause data loss, consider required flags or permissions
    fn resize(
        &self,
        flags: CommandFlags,
        size: u64,
    ) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Requests that the driver cache a range of bytes for faster access.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the cache operation
    /// - `offset`: Byte offset within the device to start caching from
    /// - `length`: Number of bytes to cache
    ///
    /// # Returns
    /// - `Ok(())`: If the cache operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs or cache operations are not supported
    ///
    /// # Implementation Notes
    /// - Most implementations should return `ProtocolError::CommandNotSupported` unless they implement
    ///   specific caching mechanisms
    /// - A typical implementation might look like:
    ///   ```rust,compile_fail
    ///   async fn cache(&self, _flags: CommandFlags, _offset: u64, _length: u32) -> Result<(), ProtocolError> {
    ///       // Most implementations don't support caching, so return CommandNotSupported
    ///       Err(ProtocolError::CommandNotSupported)
    ///   }
    ///   ```
    /// - If your backend has a native prefetch/cache mechanism, you can use it here
    fn cache(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>>;

    /// Retrieves information about block allocation status.
    ///
    /// # Parameters
    /// - `flags`: Command flags that may modify the behavior of the block status operation
    /// - `offset`: Byte offset within the device to start checking from
    /// - `length`: Number of bytes to check
    ///
    /// # Returns
    /// - `Ok(())`: If the block status operation succeeds
    /// - `Err(ProtocolError)`: If an error occurs or the operation is not supported
    ///
    /// # Implementation Notes
    /// - This is an advanced feature defined by the EXTENDED_HEADERS extension
    /// - Most implementations should return `ProtocolError::CommandNotSupported`
    /// - Consider implementing this if your storage backend has efficient ways to check if blocks are allocated
    fn block_status(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>>;
}

/// # Additional Implementation Guidance
///
/// ## Handling Command Flags
///
/// The `CommandFlags` parameter passed to each method may include flags that modify the behavior:
///
/// - `CommandFlags::FUA` (Force Unit Access): When set, ensure data is written to stable storage
///   before completing the operation. Implement this by calling `flush()` after the operation
///   or using direct I/O facilities if available.
///
/// - `CommandFlags::NO_HOLE`: For write_zeroes operations, this flag indicates that the resulting
///   zeroed area should read back as zeroes rather than being potentially a "hole" in the storage.
///   Without this flag, you can use more efficient mechanisms like hole punching.
///
/// - `CommandFlags::DF` (Don't Fragment): Used mainly with block_status operations to indicate
///   that structured replies should not be split across multiple reply chunks.
///
/// ## Error Handling Strategy
///
/// Use appropriate error codes from `ProtocolError`:
///
/// - `ProtocolError::CommandNotSupported`: For operations your driver doesn't implement
/// - `ProtocolError::InvalidArgument`: For invalid parameters (e.g., out-of-bounds access)
/// - `ProtocolError::NoSpaceLeft`: When the device is full
/// - `ProtocolError::IO`: For general I/O errors
/// - `ProtocolError::CommandNotPermitted`: For operations not allowed (e.g., writing to read-only devices)
///
/// ## Thread Safety
///
/// Since the `NBDDriver` trait is used with a server that may handle multiple connections,
/// implementations should be thread-safe. Consider using synchronization primitives like
/// `Arc<Mutex<T>>`, `RwLock`, or other concurrency controls appropriate for your storage backend.

// Some basic data to keep track of the selected device
#[derive(Debug)]
/// Internal structure to track a selected device's properties.
///
/// Used during the command processing phase to enforce permissions
/// and other device-specific settings.
struct SelectedDevice {
    /// Whether the device is read-only
    read_only: bool,
}

impl SelectedDevice {
    /// Determines if a command is permitted based on device properties.
    ///
    /// Checks if write operations are allowed on read-only devices.
    ///
    /// # Parameters
    /// - `command`: The command to check
    ///
    /// # Returns
    /// - `true` if the command is permitted, `false` otherwise
    fn is_command_permitted(&self, command: &CommandRequest) -> bool {
        return !(self.read_only
            && matches!(
                command,
                CommandRequest::Write(_, _)
                    | CommandRequest::Flush
                    | CommandRequest::Trim(_, _)
                    | CommandRequest::WriteZeroes(_, _)
                    | CommandRequest::Resize(_)
            ));
    }
}

/// Internal enum to control flow during option negotiation.
///
/// Used by the option handling code to determine what action to take
/// after processing an option request.
enum OptionReplyFinalize {
    /// Abort the negotiation (e.g., client sent an Abort request)
    Abort,

    /// Continue the negotiation (wait for more options)
    Continue,

    /// End the negotiation and proceed to transmission phase
    End(SelectedDevice),
}

/// The main NBD server implementation.
///
/// Handles the NBD protocol including handshake, option negotiation,
/// and command processing. Uses a generic `NBDDriver` implementation to
/// perform the actual storage operations.
///
/// # Type Parameters
///
/// - `T`: A type that implements the `NBDDriver` trait
pub struct NBDServer<T: NBDDriver> {
    /// The driver implementation for handling storage operations
    driver: Arc<T>,
}

impl<T: NBDDriver> NBDServer<T> {
    /// Creates a new NBD server with the given driver.
    ///
    /// # Parameters
    /// - `driver`: The driver implementation to use for storage operations
    ///
    /// # Returns
    /// A new `NBDServer` instance
    pub fn new(driver: Arc<T>) -> Self {
        NBDServer { driver }
    }

    /// Starts the NBD server on the given TCP stream.
    ///
    /// This is the main entry point for the NBD server. It handles the complete
    /// protocol flow from handshake to command processing.
    ///
    /// # Parameters
    /// - `stream`: The TCP stream connected to an NBD client
    ///
    /// # Returns
    /// - `Ok(())`: If the session completes successfully (client disconnects)
    /// - `Err(io::Error)`: If an error occurs during the session
    ///
    /// # Protocol Flow
    ///
    /// 1. Perform the initial handshake
    /// 2. Handle option negotiation to select a device
    /// 3. Process commands for the selected device
    pub async fn start(&self, stream: TcpStream) -> std::io::Result<()> {
        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        dbg!("Starting handshake");
        self.handle_handshake(&mut reader, &mut writer).await?;
        dbg!("Starting options negotiation");
        let selected_device = self.handle_options(&mut reader, &mut writer).await?;
        dbg!("Starting command handling");
        self.handle_commands(&selected_device, &mut reader, &mut writer)
            .await?;
        Ok(())
    }

    /// Handles the initial NBD handshake.
    ///
    /// This implements the handshake phase of the NBD protocol where the server and client
    /// exchange capability flags.
    ///
    /// # Parameters
    /// - `reader`: The reader for incoming client data
    /// - `writer`: The writer for outgoing server data
    ///
    /// # Returns
    /// - `Ok(())`: If the handshake completes successfully
    /// - `Err(io::Error)`: If an error occurs during the handshake
    ///
    /// # Protocol Details
    ///
    /// The server sends:
    /// 1. The NBD magic number
    /// 2. The IHAVEOPT magic number (indicating support for option negotiation)
    /// 3. Handshake flags (including FIXED_NEWSTYLE and NO_ZEROES)
    ///
    /// The client responds with its own flags, which must include FIXED_NEWSTYLE
    /// and NO_ZEROES for the negotiation to continue.
    async fn handle_handshake<R, W>(&self, reader: &mut R, writer: &mut W) -> std::io::Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWrite + Unpin,
    {
        // Write the initial handshake
        // Send NBD magic
        writer.write_all(&NBD_MAGIC.to_be_bytes()).await?;

        // Send the IHAVEOPT magic
        writer.write_all(&NBD_IHAVEOPT.to_be_bytes()).await?;

        // Send handshake flags (16 bits)
        writer
            .write_all(&HandshakeFlags::default().bits().to_be_bytes())
            .await?;
        writer.flush().await?;

        let client_flags = reader.read_u32().await?;

        let Ok(client_flags) = u16::try_from(client_flags) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid client flags",
            ));
        };

        let client_flags = HandshakeFlags::from_bits(client_flags)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid client flags"))?;

        if !client_flags.contains(HandshakeFlags::FIXED_NEWSTYLE) {
            dbg!("Client did not send FIXED_NEWSTYLE flag, which is required");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Client did not send FIXED_NEWSTYLE flag, which is required",
            ));
        }

        if !client_flags.contains(HandshakeFlags::NO_ZEROES) {
            dbg!("Client did not send NO_ZEROES flag, which is required");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Client did not send NO_ZEROES flag, which is required",
            ));
        }

        Ok(())
    }

    /// Processes an option request from the client.
    ///
    /// This method handles the various NBD option requests during the negotiation
    /// phase, such as listing available devices, requesting information, and
    /// selecting a device for export.
    ///
    /// # Parameters
    /// - `request`: The option request from the client
    ///
    /// # Returns
    /// - `Ok((replies, finalize))`: The replies to send back and how to proceed
    /// - `Err(OptionReplyError)`: If an error occurs processing the request
    ///
    /// # Response Structure
    ///
    /// The method returns two pieces of information:
    /// 1. A vector of replies to send to the client
    /// 2. A control signal indicating what to do after sending the replies:
    ///    - `Abort`: End the negotiation with an error
    ///    - `Continue`: Keep accepting option requests
    ///    - `End`: Finish negotiation and proceed to command phase
    async fn handle_option_request(
        &self,
        request: &OptionRequest,
    ) -> Result<(Vec<OptionReply>, OptionReplyFinalize), OptionReplyError> {
        let mut responses: Vec<OptionReply> = Vec::new();

        match request {
            OptionRequest::Abort => {
                responses.push(OptionReply::Ack);
                return Ok((responses, OptionReplyFinalize::Abort));
            }
            OptionRequest::List => {
                // List request, send the list of devices
                for device in self.driver.list_devices().await? {
                    responses.push(OptionReply::Server(device));
                }
            }
            OptionRequest::StartTLS => unimplemented!(),
            OptionRequest::Info(name, _info_requests) | OptionRequest::Go(name, _info_requests) => {
                let read_only = self.driver.get_read_only(name).await?;
                let size = self.driver.get_device_size(name).await?;

                let mut flags: TransmissionFlags = self.driver.get_features().into();

                // A separate method to make the driver API cleaner
                if read_only {
                    flags.insert(TransmissionFlags::READ_ONLY);
                }

                // No matter what info is explicitly requested, always send all of the information we have
                // The client may or may not honor it, but some don't request it at all and just move on
                // We should probably store which information types were explicitly requested and
                // expose that information to the driver
                responses.push(OptionReply::Info(InfoPayload::Export(size, flags)));
                responses.push(OptionReply::Info(InfoPayload::Name(name.clone())));
                responses.push(OptionReply::Info(InfoPayload::Description(
                    self.driver.get_description(name).await?,
                )));
                let (min, optimal, max) = self.driver.get_block_size(name).await?;
                responses.push(OptionReply::Info(InfoPayload::BlockSize(min, optimal, max)));

                responses.push(OptionReply::Ack);

                if matches!(request, OptionRequest::Go(..)) {
                    return Ok((
                        responses,
                        OptionReplyFinalize::End(SelectedDevice { read_only }),
                    ));
                }
            }
            OptionRequest::StructuredReply => unimplemented!(),
            OptionRequest::ListMetaContext => unimplemented!(),
            OptionRequest::SetMetaContext(_) => unimplemented!(),
            OptionRequest::ExtendedHeaders(_) => unimplemented!(),
            OptionRequest::ExportName(name) => {
                // Is this really correct? No ack, just go right into transmission?
                return Ok((
                    vec![],
                    OptionReplyFinalize::End(SelectedDevice {
                        read_only: self.driver.get_read_only(name).await?,
                    }),
                ));
            }
        }
        Ok((responses, OptionReplyFinalize::Continue))
    }

    /// Writes an option reply error to the client.
    ///
    /// This helper method creates and sends an error response during option negotiation.
    ///
    /// # Parameters
    /// - `writer`: The writer to send the error to
    /// - `option`: The option code being responded to
    /// - `error`: The error that occurred
    ///
    /// # Returns
    /// - `Ok(())`: If the error was written successfully
    /// - `Err(io::Error)`: If an I/O error occurs
    ///
    /// # Special Case
    /// If the error is `OptionReplyError::Shutdown`, this method will return an error
    /// to trigger server shutdown after writing the response.
    async fn write_option_reply_error<W>(
        &self,
        writer: &mut W,
        option: u32,
        error: OptionReplyError,
    ) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let reply = OptionReplyRaw::new(option, error.into(), error.to_string().into_bytes());
        reply.write(writer).await?;
        writer.flush().await?;

        if error == OptionReplyError::Shutdown {
            // If the error is a shutdown, we should stop handling options
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Server is shutting down",
            ))
        } else {
            // Otherwise, continue handling options
            Ok(())
        }
    }

    /// Handles the option negotiation phase of the NBD protocol.
    ///
    /// This method processes option requests from the client until a device
    /// is successfully selected or an error occurs.
    ///
    /// # Parameters
    /// - `reader`: The reader for incoming option requests
    /// - `writer`: The writer for outgoing option replies
    ///
    /// # Returns
    /// - `Ok(SelectedDevice)`: The selected device information if negotiation succeeds
    /// - `Err(io::Error)`: If an error occurs during negotiation
    ///
    /// # Option Negotiation Flow
    ///
    /// 1. Read option requests from the client
    /// 2. Process each request and generate replies
    /// 3. Send replies back to the client
    /// 4. Continue until a device is selected or an error occurs
    ///
    /// The negotiation phase allows the client to:
    /// - List available devices
    /// - Query device information (size, read-only status, etc.)
    /// - Select a device for the transmission phase
    async fn handle_options<R, W>(
        &self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<SelectedDevice>
    where
        R: AsyncReadExt + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            let request_raw = OptionRequestRaw::read(reader).await?;

            dbg!("Received option request, raw");

            let request = match OptionRequest::try_from(&request_raw) {
                Err(e) => {
                    self.write_option_reply_error(writer, request_raw.option, e)
                        .await?;

                    continue;
                }
                Ok(req) => req,
            };

            dbg!("Parsed option request: {:?}", &request);

            match self.handle_option_request(&request).await {
                Err(e) => {
                    self.write_option_reply_error(writer, request_raw.option, e)
                        .await?;

                    continue;
                }
                Ok((responses, finalize)) => {
                    // Continue negotiation, write the responses
                    for response in responses {
                        dbg!("Writing option reply: {:?}", &response);
                        let response_raw = OptionReplyRaw::new(
                            request_raw.option,
                            response.get_reply_type().into(),
                            response.get_data(),
                        );
                        response_raw.write(writer).await?;
                    }
                    // Flush the writer to ensure the replies are sent
                    writer.flush().await?;

                    match finalize {
                        OptionReplyFinalize::Abort => {
                            dbg!("Aborting option negotiation");
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "Abort request received",
                            ));
                        }
                        OptionReplyFinalize::Continue => {
                            dbg!("Continuing option negotiation");
                        }
                        OptionReplyFinalize::End(selected_device) => {
                            dbg!(
                                "Ending option negotiation with selected device: {:?}",
                                &selected_device
                            );
                            return Ok(selected_device);
                        }
                    }
                }
            };
        }
    }

    /// Handles NBD commands during the transmission phase.
    ///
    /// This method is responsible for processing NBD commands after option
    /// negotiation has completed. It reads command requests, passes them to
    /// the driver implementation, and writes replies back to the client.
    ///
    /// # Parameters
    /// - `selected_device`: The device selected during option negotiation
    /// - `reader`: The reader for incoming command requests
    /// - `writer`: The writer for outgoing command replies
    ///
    /// # Returns
    /// - `Ok(())`: If the command processing completes successfully (client disconnects)
    /// - `Err(io::Error)`: If an error occurs during command processing
    ///
    /// # Command Flow
    ///
    /// For each command:
    /// 1. Read the raw command request
    /// 2. Convert it to a typed command
    /// 3. Check if the command is permitted (e.g., write to read-only device)
    /// 4. Execute the command using the driver
    /// 5. Send the reply back to the client
    ///
    /// This continues until either the client disconnects or an error occurs.
    async fn handle_commands<R, W>(
        &self,
        selected_device: &SelectedDevice,
        reader: &mut R,
        writer: &mut W,
    ) -> io::Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let command_raw = CommandRequestRaw::read(reader).await?;

            // should be before match due to partial move
            let cookie = command_raw.cookie;

            let Ok(flags) = CommandFlags::try_from(command_raw.flags) else {
                // If flags are invalid, write an error reply and continue
                let reply =
                    SimpleReplyRaw::new(ProtocolError::InvalidArgument.into(), cookie, vec![]);
                reply.write(writer).await?;
                writer.flush().await?;
                continue;
            };

            let command = match CommandRequest::try_from(&command_raw) {
                Ok(op) => op,
                Err(e) => {
                    // Write an error reply and continue
                    let reply = SimpleReplyRaw::new(e.into(), cookie, vec![]);
                    reply.write(writer).await?;
                    writer.flush().await?;
                    continue;
                }
            };

            // If the device is read-only, we should not allow write operations
            let command_not_permitted = !selected_device.is_command_permitted(&command);

            let result = if command_not_permitted {
                Err(ProtocolError::CommandNotPermitted)
            } else {
                match command {
                    // Disconnection is the only operation without a reply
                    // and a return early
                    CommandRequest::Disconnect => {
                        self.driver
                            .disconnect(flags)
                            .await
                            .expect("Failed to disconnect");
                        return Ok(());
                    }
                    CommandRequest::Read(offset, length) => {
                        self.driver.read(flags, offset, length).await
                    }
                    CommandRequest::Write(offset, data) => {
                        self.driver.write(flags, offset, data).await.map(|_| vec![])
                    }
                    CommandRequest::Flush => self.driver.flush(flags).await.map(|_| vec![]),
                    CommandRequest::Trim(offset, length) => self
                        .driver
                        .trim(flags, offset, length)
                        .await
                        .map(|_| vec![]),
                    CommandRequest::WriteZeroes(offset, length) => self
                        .driver
                        .write_zeroes(flags, offset, length)
                        .await
                        .map(|_| vec![]),
                    CommandRequest::Resize(size) => {
                        self.driver.resize(flags, size).await.map(|_| vec![])
                    }
                    CommandRequest::Cache(offset, length) => self
                        .driver
                        .cache(flags, offset, length)
                        .await
                        .map(|_| vec![]),
                    // Not implemented yet
                    CommandRequest::BlockStatus(..) => self
                        .driver
                        .block_status(flags, command_raw.offset, command_raw.length)
                        .await
                        .map(|_| vec![]),
                }
            };

            let (reply, abort) = match result {
                Err(e) => {
                    dbg!("Error processing command: {:?}", &e);
                    (
                        SimpleReplyRaw::new(
                            ProtocolError::ServerShuttingDown.into(),
                            cookie,
                            vec![],
                        ),
                        e == ProtocolError::ServerShuttingDown,
                    )
                }
                Ok(data) => (SimpleReplyRaw::new(0, cookie, data), false),
            };

            // Write the reply
            reply.write(writer).await?;
            // Flush the writer to ensure the reply is sent so we can start waiting for the next command
            writer.flush().await?;

            if abort {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Unrecoverable error in NBD driver",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NBDDriver;
    use crate::errors::{OptionReplyError, ProtocolError};
    use crate::flags::{CommandFlags, ServerFeatures};

    use tokio;

    use std::sync::RwLock;

    struct MemoryDriver {
        data: RwLock<Vec<u8>>,
    }

    impl NBDDriver for MemoryDriver {
        fn get_features(&self) -> ServerFeatures {
            // Support basic read/write operations but not advanced features
            ServerFeatures::SEND_FLUSH | ServerFeatures::SEND_FUA
        }

        // Basic device info methods implementation
        async fn list_devices(&self) -> Result<Vec<String>, OptionReplyError> {
            // Only one device available
            Ok(vec!["memory".to_string()])
        }

        async fn get_read_only(&self, device_name: &str) -> Result<bool, OptionReplyError> {
            if device_name == "memory" {
                Ok(false) // Device is writable
            } else {
                Err(OptionReplyError::Unknown)
            }
        }

        async fn read(
            &self,
            _flags: CommandFlags,
            offset: u64,
            length: u32,
        ) -> Result<Vec<u8>, ProtocolError> {
            let data = self.data.read().unwrap();
            let start = offset as usize;
            let end = start + length as usize;

            if end > data.len() {
                return Err(ProtocolError::InvalidArgument);
            }

            Ok(data[start..end].to_vec())
        }

        async fn cache(
            &self,
            _flags: CommandFlags,
            _offset: u64,
            _length: u32,
        ) -> Result<(), ProtocolError> {
            // Memory-backed driver doesn't need explicit caching
            Err(ProtocolError::CommandNotSupported)
        }

        async fn get_block_size(
            &self,
            device_name: &str,
        ) -> Result<(u32, u32, u32), OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_canonical_name(&self, device_name: &str) -> Result<String, OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_description(&self, device_name: &str) -> Result<String, OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_device_size(&self, device_name: &str) -> Result<u64, OptionReplyError> {
            Ok(self.data.read().unwrap().len() as u64)
        }

        async fn write(
            &self,
            flags: CommandFlags,
            offset: u64,
            data: Vec<u8>,
        ) -> Result<(), ProtocolError> {
            let mut memory = self.data.write().unwrap();
            let start = offset as usize;
            let end = start + data.len();

            if end > memory.len() {
                return Err(ProtocolError::InvalidArgument);
            }

            memory[start..end].copy_from_slice(&data);
            Ok(())
        }

        async fn flush(&self, flags: CommandFlags) -> Result<(), ProtocolError> {
            Err(ProtocolError::CommandNotSupported)
        }

        async fn trim(
            &self,
            flags: CommandFlags,
            offset: u64,
            length: u32,
        ) -> Result<(), ProtocolError> {
            Err(ProtocolError::CommandNotSupported)
        }

        async fn write_zeroes(
            &self,
            flags: CommandFlags,
            offset: u64,
            length: u32,
        ) -> Result<(), ProtocolError> {
            Err(ProtocolError::CommandNotSupported)
        }

        async fn disconnect(&self, flags: CommandFlags) -> Result<(), ProtocolError> {
            Ok(())
        }

        async fn resize(&self, flags: CommandFlags, size: u64) -> Result<(), ProtocolError> {
            Err(ProtocolError::CommandNotSupported)
        }

        async fn block_status(
            &self,
            flags: CommandFlags,
            offset: u64,
            length: u32,
        ) -> Result<(), ProtocolError> {
            Err(ProtocolError::CommandNotSupported)
        }

        // Other methods implementation...
    }

    #[tokio::test]
    async fn driver_memory_read() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        let result = driver.read(CommandFlags::empty(), 0, 512).await;
        assert_eq!(result, Ok(vec![0; 512]));
    }

    #[tokio::test]
    async fn driver_memory_write_read() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        let write_data = vec![1; 512];
        let write_result = driver
            .write(CommandFlags::empty(), 0, write_data.clone())
            .await;
        assert!(write_result.is_ok());

        let read_result = driver.read(CommandFlags::empty(), 0, 512).await;
        assert_eq!(read_result, Ok(write_data));
    }

    #[tokio::test]
    async fn driver_memory_resize() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        let resize_result = driver.resize(CommandFlags::empty(), 2048).await;
        assert_eq!(resize_result, Err(ProtocolError::CommandNotSupported));
    }

    #[tokio::test]
    async fn driver_memory_read_out_of_bounds() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Try to read beyond the buffer size
        let result = driver.read(CommandFlags::empty(), 512, 600).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));

        // Try to read with offset outside the buffer
        let result = driver.read(CommandFlags::empty(), 2000, 10).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));
    }

    #[tokio::test]
    async fn driver_memory_write_out_of_bounds() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Try to write beyond the buffer size
        let write_data = vec![1; 600];
        let result = driver.write(CommandFlags::empty(), 512, write_data).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));

        // Try to write with offset outside the buffer
        let write_data = vec![1; 10];
        let result = driver.write(CommandFlags::empty(), 2000, write_data).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));
    }

    #[tokio::test]
    async fn driver_memory_partial_write_read() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Write to a specific section
        let write_data = vec![1, 2, 3, 4, 5];
        let offset = 100;
        let data_len = write_data.len();
        let result = driver
            .write(CommandFlags::empty(), offset, write_data)
            .await;
        assert!(result.is_ok());

        // Read that section back
        let read_result = driver
            .read(CommandFlags::empty(), offset, data_len as u32)
            .await;
        assert_eq!(read_result, Ok(vec![1, 2, 3, 4, 5]));

        // Ensure data before this section is still zeros
        let before_result = driver.read(CommandFlags::empty(), offset - 10, 10).await;
        assert_eq!(before_result, Ok(vec![0; 10]));

        // Ensure data after this section is still zeros
        let after_result = driver
            .read(CommandFlags::empty(), offset + data_len as u64, 10)
            .await;
        assert_eq!(after_result, Ok(vec![0; 10]));
    }

    #[tokio::test]
    async fn driver_memory_zero_length_operations() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Zero-length read should return empty vector
        let read_result = driver.read(CommandFlags::empty(), 100, 0).await;
        assert_eq!(read_result, Ok(vec![]));

        // Zero-length write should succeed
        let write_result = driver.write(CommandFlags::empty(), 100, vec![]).await;
        assert!(write_result.is_ok());
    }

    #[tokio::test]
    async fn driver_memory_list_devices_and_info() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Check list_devices returns the expected device
        let devices = driver.list_devices().await.unwrap();
        assert_eq!(devices, vec!["memory".to_string()]);

        // Check device size
        let size = driver.get_device_size("memory").await.unwrap();
        assert_eq!(size, 1024);

        // Check read-only status
        let read_only = driver.get_read_only("memory").await.unwrap();
        assert_eq!(read_only, false);

        // Check non-existent device
        let read_only_result = driver.get_read_only("nonexistent").await;
        assert!(matches!(read_only_result, Err(OptionReplyError::Unknown)));
    }

    #[tokio::test]
    async fn driver_memory_command_flags() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Check server features
        let features = driver.get_features();
        assert!(features.contains(ServerFeatures::SEND_FLUSH));
        assert!(features.contains(ServerFeatures::SEND_FUA));
        // HAS_FLAGS is not a ServerFeature, it's a TransmissionFlag

        // Even with FUA flag, operations should work the same
        let fua_flag = CommandFlags::FUA; // FUA flag
        let write_data = vec![42; 128];
        let data_len = write_data.len();
        let write_result = driver.write(fua_flag, 200, write_data).await;
        assert!(write_result.is_ok());

        // Read back should show the written data
        let read_result = driver
            .read(CommandFlags::empty(), 200, data_len as u32)
            .await;
        assert_eq!(read_result, Ok(vec![42; data_len]));
    }

    #[tokio::test]
    async fn driver_memory_unsupported_operations() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Test all unsupported operations
        assert_eq!(
            driver.flush(CommandFlags::empty()).await,
            Err(ProtocolError::CommandNotSupported)
        );

        assert_eq!(
            driver.trim(CommandFlags::empty(), 0, 100).await,
            Err(ProtocolError::CommandNotSupported)
        );

        assert_eq!(
            driver.write_zeroes(CommandFlags::empty(), 0, 100).await,
            Err(ProtocolError::CommandNotSupported)
        );

        assert_eq!(
            driver.cache(CommandFlags::empty(), 0, 100).await,
            Err(ProtocolError::CommandNotSupported)
        );

        assert_eq!(
            driver.block_status(CommandFlags::empty(), 0, 100).await,
            Err(ProtocolError::CommandNotSupported)
        );

        // Check unsupported info methods
        assert_eq!(
            driver.get_block_size("memory").await,
            Err(OptionReplyError::Unsupported)
        );

        assert_eq!(
            driver.get_canonical_name("memory").await,
            Err(OptionReplyError::Unsupported)
        );

        assert_eq!(
            driver.get_description("memory").await,
            Err(OptionReplyError::Unsupported)
        );
    }

    #[tokio::test]
    async fn driver_memory_disconnect() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Disconnect should succeed
        let result = driver.disconnect(CommandFlags::empty()).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn driver_memory_error_handling_and_recovery() {
        let driver = MemoryDriver {
            data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
        };

        // Test error conditions followed by successful operations

        // 1. Try invalid operation, then valid operation
        let trim_result = driver.trim(CommandFlags::empty(), 0, 100).await;
        assert_eq!(trim_result, Err(ProtocolError::CommandNotSupported));

        let write_data = vec![123; 50];
        let write_result = driver
            .write(CommandFlags::empty(), 200, write_data.clone())
            .await;
        assert!(write_result.is_ok());

        // 2. Try out-of-bounds, then in-bounds operation
        let out_of_bounds = driver.read(CommandFlags::empty(), 2000, 10).await;
        assert_eq!(out_of_bounds, Err(ProtocolError::InvalidArgument));

        let read_result = driver.read(CommandFlags::empty(), 200, 50).await;
        assert_eq!(read_result, Ok(vec![123; 50]));

        // 3. Try error in the middle of a sequence of operations
        let data1 = vec![1, 2, 3, 4, 5];
        let data2 = vec![6, 7, 8, 9, 10];

        // First write succeeds
        let write1_result = driver
            .write(CommandFlags::empty(), 100, data1.clone())
            .await;
        assert!(write1_result.is_ok());

        // Second write fails (out of bounds)
        let write2_result = driver.write(CommandFlags::empty(), 5000, vec![0; 10]).await;
        assert_eq!(write2_result, Err(ProtocolError::InvalidArgument));

        // Third write succeeds
        let write3_result = driver
            .write(CommandFlags::empty(), 300, data2.clone())
            .await;
        assert!(write3_result.is_ok());

        // Verify all the successful writes are readable
        assert_eq!(driver.read(CommandFlags::empty(), 100, 5).await, Ok(data1));
        assert_eq!(driver.read(CommandFlags::empty(), 300, 5).await, Ok(data2));
    }
}
