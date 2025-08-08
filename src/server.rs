//! Network Block Device (NBD) driver implementation and server functionality.
//!
//! This module provides the core components for implementing an NBD server:
//!
//! - [`NbdDriver`]: A trait for implementing storage backends
//! - [`NbdServer`]: A server implementation that handles the NBD protocol
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
//! 1. Implement the [`NbdDriver`] trait for your storage backend
//! 2. Create an instance of [`NbdServer`] with your driver
//! 3. Call `start()` with a TcpStream to begin serving
//!
//! ```rust,compile_fail
//! use tokio_nbd::device::NbdDriver;
//! use tokio_nbd::server::NbdServer;
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
//! // ... implement NbdDriver for MemoryDriver
//!
//! async fn start_nbd(host: &str, port: u16, driver: Arc<MemoryDriver>) -> std::io::Result<()> {

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
//!             let server = NbdServer::new(driver);
//!
//!             if let Err(e) = server.start(stream).await {
//!                 println!("Error starting NBD server: {:?}", e);
//!                 return;
//!             }
//!         });
//!     }
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
use std::sync::atomic::Ordering;
use std::{io, vec};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};

use crate::command_request::CommandRequest;
use crate::device::NbdDriver;
use crate::errors::{OptionReplyError, ProtocolError};
use crate::flags::{CommandFlags, HandshakeFlags, TransmissionFlags};
use crate::io::command_reply::SimpleReplyRaw;
use crate::io::command_request::CommandRequestRaw;
use crate::io::option_reply::OptionReplyRaw;
use crate::io::option_request::OptionRequestRaw;
use crate::magic::{NBD_IHAVEOPT, NBD_MAGIC};
use crate::option_reply::{InfoPayload, OptionReply};
use crate::option_request::OptionRequest;

/// A trait that represents a Network Block Device driver implementation.
///
/// This trait defines the interface that must be implemented to provide
/// a functional NBD server. Implementors of this trait will handle the
/// actual storage operations, while the NBD protocol handling is
/// provided by the `NbdServer`.
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
/// use tokio_nbd::driver::NbdDriver;
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
/// impl NbdDriver for MemoryDriver {
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
/// Since the `NbdDriver` trait is used with a server that may handle multiple connections,
/// implementations should be thread-safe. Consider using synchronization primitives like
/// `Arc<Mutex<T>>`, `RwLock`, or other concurrency controls appropriate for your storage backend.

struct SelectedDevice<'a, T>
where
    T: NbdDriver + 'a,
{
    /// The selected device for the transmission phase
    device: &'a T,
    // It's assumed that once a device is selected, the
    // read-only status is known and does not change
    // This let's us implement the check to forbid
    // write commands on a read-only device.
    read_only: bool,
    /// The size of the device in bytes
    /// This is so that we can do automatic bounds checking
    /// without requiring implementors to check it themselves
    size: u64,
    name: String,
}

/// Internal enum to control flow during option negotiation.
///
/// Used by the option handling code to determine what action to take
/// after processing an option request.
enum OptionReplyFinalize<'a, T>
where
    T: NbdDriver + 'a,
{
    /// Abort the negotiation (e.g., client sent an Abort request)
    Abort,

    /// Continue the negotiation (wait for more options)
    Continue,

    /// End the negotiation and proceed to transmission phase
    End(SelectedDevice<'a, T>),
}

/// The main NBD server implementation.
///
/// Handles the NBD protocol including handshake, option negotiation,
/// and command processing. Uses a generic `NbdDriver` implementation to
/// perform the actual storage operations.
///
/// # Type Parameters
///
/// - `T`: A type that implements the `NbdDriver` trait
pub struct NbdServer<T>
where
    T: NbdDriver,
{
    /// The driver implementation for handling storage operations
    devices: Arc<Vec<T>>,
}

impl<T> NbdServer<T>
where
    T: NbdDriver + Send + Sync + 'static,
{
    /// Creates a new NBD server with the given devices.
    ///
    /// # Parameters
    /// - `devices`: The driver implementations to use for storage operations
    ///
    /// # Returns
    /// A new `NbdServer` instance
    pub fn new(devices: Arc<Vec<T>>) -> Self {
        // Initializing the server with zero length vec is an error, but not
        // checked here. Check in 'start'
        Self { devices }
    }

    /// Starts a TCP server that listens for NBD client connections.
    ///
    /// This method binds to the specified host and port, and handles incoming NBD client
    /// connections. For each connection, it spawns a new task that runs an NBD server
    /// instance with the provided devices. This allows handling multiple NBD clients
    /// concurrently.
    ///
    /// # Parameters
    /// - `devices`: Vector of driver implementations to serve to clients
    /// - `host`: The hostname or IP address to bind to (e.g., "127.0.0.1", "0.0.0.0")
    /// - `port`: Optional port number to listen on; defaults to 10809 (the standard NBD port)
    ///
    /// # Returns
    /// - `Ok(())`: The server will run indefinitely unless an error occurs
    /// - `Err(std::io::Error)`: If binding to the socket fails or another I/O error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use tokio_nbd::server::NbdServer;
    ///
    /// #[tokio::main]
    /// async fn main() -> std::io::Result<()> {
    ///     // Create your driver implementations
    ///     let devices = vec![/* your NBD driver implementations */];
    ///
    ///     // Start the server on all interfaces, default NBD port
    ///     NbdServer::listen(devices, "0.0.0.0", None).await
    /// }
    /// ```
    ///
    /// This method runs indefinitely. To handle graceful shutdown, consider
    /// running it in a separate task and implementing signal handling.
    pub async fn listen(devices: Vec<T>, host: &str, port: Option<u16>) -> std::io::Result<()> {
        let port = port.unwrap_or(10809);
        let devices = Arc::new(devices);
        let listener = TcpListener::bind(format!("{host}:{port}")).await?;

        loop {
            let (stream, addr) = listener.accept().await?;
            println!("NBD client connected from {}", addr);

            let devices = Arc::clone(&devices);

            tokio::spawn(async move {
                let server = NbdServer::new(devices);

                if let Err(e) = server.start(stream).await {
                    println!("Error starting NBD server: {:?}", e);
                    return;
                }
            });
        }
    }

    async fn list_devices(&self) -> Result<Vec<String>, OptionReplyError> {
        if self.devices.is_empty() {
            return Err(OptionReplyError::UnknownExport);
        }

        // Collect the names of all devices
        let mut device_names: Vec<String> = Vec::with_capacity(self.devices.len());
        for device in &*self.devices {
            device_names.push(device.get_name());
        }
        Ok(device_names)
    }

    // Should be be sync or async
    fn get_device(&self, device_name: &str) -> Option<&T> {
        // If device name is blank, get the first device as "default"
        if device_name.is_empty() {
            return self.devices.first();
        }

        self.devices.iter().find(|d| d.get_name() == device_name)
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
        if self.devices.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "No devices available for NBD server",
            ));
        }

        let (reader, writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        dbg!("Starting handshake");
        self.handle_handshake(&mut reader, &mut writer).await?;
        dbg!("Starting options negotiation");
        let selected_device = self.handle_options(&mut reader, &mut writer).await?;
        dbg!("Starting command handling");
        // Function signature is getting too long
        self.handle_commands(
            &selected_device.device,
            &mut reader,
            &mut writer,
            selected_device.read_only,
            selected_device.size,
        )
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
    ) -> Result<(Vec<OptionReply>, OptionReplyFinalize<T>), OptionReplyError> {
        let mut responses: Vec<OptionReply> = Vec::new();

        match request {
            OptionRequest::Abort => {
                responses.push(OptionReply::Ack);
                return Ok((responses, OptionReplyFinalize::Abort));
            }
            OptionRequest::List => {
                // List request, send the list of devices
                for device in self.list_devices().await? {
                    responses.push(OptionReply::Server(device));
                }
            }
            OptionRequest::StartTLS => unimplemented!(),
            OptionRequest::Info(name, _info_requests) | OptionRequest::Go(name, _info_requests) => {
                let Some(device) = self.get_device(name) else {
                    return Err(OptionReplyError::UnknownExport);
                };

                let mut flags: TransmissionFlags = device.get_features().into();

                let read_only = device.get_read_only().await?;
                let size = device.get_device_size().load(Ordering::Acquire);

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
                    device.get_description().await?,
                )));
                let (min, optimal, max) = device.get_block_size().await?;
                responses.push(OptionReply::Info(InfoPayload::BlockSize(min, optimal, max)));

                responses.push(OptionReply::Ack);

                if matches!(request, OptionRequest::Go(..)) {
                    return Ok((
                        responses,
                        OptionReplyFinalize::End(SelectedDevice {
                            device: &device,
                            read_only,
                            size,
                            name: name.clone(),
                        }),
                    ));
                }
            }
            OptionRequest::StructuredReply => unimplemented!(),
            OptionRequest::ListMetaContext => unimplemented!(),
            OptionRequest::SetMetaContext(_) => unimplemented!(),
            OptionRequest::ExtendedHeaders(_) => unimplemented!(),
            OptionRequest::ExportName(name) => {
                let Some(device) = self.get_device(name) else {
                    return Err(OptionReplyError::UnknownExport);
                };
                // Is this really correct? No ack, just go right into transmission?
                return Ok((
                    vec![],
                    OptionReplyFinalize::End(SelectedDevice {
                        device: &device,
                        read_only: device.get_read_only().await?,
                        size: device.get_device_size().load(Ordering::Acquire),
                        name: name.clone(),
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
    ) -> std::io::Result<SelectedDevice<T>>
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
                                &selected_device.name
                            );
                            return Ok(selected_device);
                        }
                    }
                }
            };
        }
    }

    fn check_command(
        &self,
        command: &CommandRequest,
        read_only: bool,
        device_size: u64,
    ) -> Result<(), ProtocolError> {
        // If the device is read-only, we should not allow write operations
        if read_only && command.is_write_command() {
            // If the command requires write access but the device is read-only,
            // write an error reply and continue
            return Err(ProtocolError::CommandNotPermitted);
        }

        // For Read, Write, Trim, WriteZeroes, Cache, BlockStatus, we do a bounds check
        // to ensure the operation does not exceed the device size.
        let command_end = match command {
            CommandRequest::Read(offset, length)
            | CommandRequest::Trim(offset, length)
            | CommandRequest::WriteZeroes(offset, length)
            | CommandRequest::Cache(offset, length)
            | CommandRequest::BlockStatus(offset, length) => offset + *length as u64,
            CommandRequest::Write(offset, data) => offset + data.len() as u64,
            _ => return Ok(()),
        };

        if command_end > device_size {
            return Err(ProtocolError::ValueTooLarge);
        }

        Ok(())
    }

    fn bounds_check(&self, command: &CommandRequest, device_size: u64) -> bool {
        // For Read, Write, Trim, WriteZeroes, Cache, BlockStatus, we do a bounds check
        // to ensure the operation does not exceed the device size.
        let command_end = match command {
            CommandRequest::Read(offset, length)
            | CommandRequest::Trim(offset, length)
            | CommandRequest::WriteZeroes(offset, length)
            | CommandRequest::Cache(offset, length)
            | CommandRequest::BlockStatus(offset, length) => offset + *length as u64,
            CommandRequest::Write(offset, data) => offset + data.len() as u64,
            _ => return true,
        };

        command_end <= device_size
    }

    fn parse_command(
        &self,
        command_raw: &CommandRequestRaw,
        read_only: bool,
        device_size: u64,
    ) -> Result<(CommandFlags, CommandRequest), ProtocolError> {
        let flags = CommandFlags::try_from(command_raw.flags)
            .map_err(|_| ProtocolError::InvalidArgument)?;

        let command =
            CommandRequest::try_from(command_raw).map_err(|_| ProtocolError::InvalidArgument)?;

        if read_only && command.is_write_command() {
            Err(ProtocolError::CommandNotPermitted)
        } else if !self.bounds_check(&command, device_size) {
            Err(ProtocolError::ValueTooLarge)
        } else {
            Ok((flags, command))
        }
    }

    fn check_noop(&self, command: &CommandRequest) -> bool {
        match command {
            CommandRequest::Read(_, 0)
            | CommandRequest::Cache(_, 0)
            | CommandRequest::Trim(_, 0)
            | CommandRequest::WriteZeroes(_, 0) => true,
            CommandRequest::Write(_, data) if data.is_empty() => true,
            _ => false,
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
        device: &T,
        reader: &mut R,
        writer: &mut W,
        read_only: bool,
        device_size: u64,
    ) -> io::Result<()>
    where
        R: AsyncReadExt + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        loop {
            let command_raw = CommandRequestRaw::read(reader).await?;

            let cookie = command_raw.cookie;

            let (flags, command) = match self.parse_command(&command_raw, read_only, device_size) {
                Ok((flags, command)) => (flags, command),
                Err(e) => {
                    // Write an error reply and continue
                    let reply = SimpleReplyRaw::new(e.into(), cookie, vec![]);
                    reply.write(writer).await?;
                    writer.flush().await?;
                    continue;
                }
            };

            // A few edge cases we handle here.
            // For example, a `Write` command with an empty data vector,
            // A `Read` command with a length of 0,
            // and so on
            if self.check_noop(&command) {
                // If the command is a no-op, we can skip processing it
                let reply = SimpleReplyRaw::new(0, cookie, vec![]);
                reply.write(writer).await?;
                writer.flush().await?;
                continue;
            }

            let result = match command {
                // Disconnection is the only operation without a reply
                // and a return early
                CommandRequest::Disconnect => {
                    device
                        .disconnect(flags)
                        .await
                        .expect("Failed to disconnect");
                    return Ok(());
                }
                CommandRequest::Read(offset, length) => device.read(flags, offset, length).await,
                CommandRequest::Write(offset, data) => {
                    device.write(flags, offset, data).await.map(|_| vec![])
                }
                CommandRequest::Flush => device.flush(flags).await.map(|_| vec![]),
                CommandRequest::Trim(offset, length) => {
                    device.trim(flags, offset, length).await.map(|_| vec![])
                }
                CommandRequest::WriteZeroes(offset, length) => device
                    .write_zeroes(flags, offset, length)
                    .await
                    .map(|_| vec![]),
                CommandRequest::Resize(size) => device.resize(flags, size).await.map(|_| vec![]),
                CommandRequest::Cache(offset, length) => {
                    device.cache(flags, offset, length).await.map(|_| vec![])
                }
                // Not implemented yet
                CommandRequest::BlockStatus(_, _) => {
                    device
                        .block_status(flags, command_raw.offset, command_raw.length)
                        .await
                }
                .map(|_| vec![]),
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
