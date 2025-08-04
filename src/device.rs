//! Network Block Device (NBD) driver implementation and server functionality.
//!
//! This module provides the core component for implementing an NBD server:
//!
//! - [`NbdDriver`]: A trait for implementing storage backends
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

use crate::errors::{OptionReplyError, ProtocolError};
use crate::flags::{CommandFlags, ServerFeatures};

/// A trait that represents a Network Block Device driver implementation.
///
/// This trait defines the interface that must be implemented to provide
/// a functional NBD server. Implementors of this trait will handle the
/// actual storage operations, while the NBD protocol handling is
/// provided by the [`crate::server::NbdServer`].
///
/// # Implementation Guidelines
///
/// When implementing this trait:
///
/// 1. Consider which server features you want to support and expose them
///    via the `get_features()` method
/// 2. Implement the required methods to handle the transmission phase: read, write, and disconnect.
/// 3. Implement the required methods to provide device metadata: get_name, get_read_only, get_block_size,
///    get_canonical_name, get_description, and get_device_size.
/// 4. Implement proper error handling for all methods
/// 5. Consider thread safety if your implementation will be shared across threads
/// 6. Optionally implement additional methods as needed for your storage backend
///
/// # Default Implementations
///
/// For many methods, if your driver doesn't support the functionality, you do not need to implement it yourself:
/// the default implementation will return `Err(ProtocolError::CommandNotSupported)` for many methods.
///
/// In particular, the following methods can be left unimplemented if not needed:
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
/// ```rust
/// use tokio_nbd::device::NbdDriver;
/// use tokio_nbd::flags::{CommandFlags, ServerFeatures};
/// use tokio_nbd::errors::{ProtocolError, OptionReplyError};
/// use std::sync::RwLock;
/// use std::future::Future;
///
/// #[derive(Debug)]
/// struct MemoryDriver {
///     data: RwLock<Vec<u8>>,
///     read_only: bool,
///     name: String,
/// }
///
/// impl Default for MemoryDriver {
///     fn default() -> Self {
///         MemoryDriver {
///             data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory
///             read_only: false,
///             name: "".to_string(),
///         }
///     }
/// }
///
/// impl NbdDriver for MemoryDriver {
///     fn get_features(&self) -> ServerFeatures {
///         ServerFeatures::SEND_FUA
///     }
///
///     fn get_name(&self) -> String {
///         self.name.clone()
///     }
///
///     async fn get_read_only(&self) -> Result<bool, OptionReplyError> {
///         Ok(self.read_only)
///     }
///
///     async fn get_block_size(&self) -> Result<(u32, u32, u32), OptionReplyError> {
///         Err(OptionReplyError::Unsupported)
///     }
///
///     async fn get_canonical_name(&self) -> Result<String, OptionReplyError> {
///         Err(OptionReplyError::Unsupported)
///     }
///
///     async fn get_description(&self) -> Result<String, OptionReplyError> {
///         Err(OptionReplyError::Unsupported)
///     }
///
///     async fn get_device_size(&self) -> Result<u64, OptionReplyError> {
///         Ok(self.data.read().unwrap().len() as u64)
///     }
///
///     async fn read(
///         &self,
///         _flags: CommandFlags,
///         offset: u64,
///         length: u32,
///     ) -> Result<Vec<u8>, ProtocolError> {
///         let data = self.data.read().unwrap();
///         let start = offset as usize;
///         let end = start + length as usize;
///         Ok(data[start..end].to_vec())
///     }
///
///     async fn write(
///         &self,
///         _flags: CommandFlags,
///         offset: u64,
///         data: Vec<u8>,
///     ) -> Result<(), ProtocolError> {
///         let mut memory = self.data.write().unwrap();
///         let start = offset as usize;
///         let end = start + data.len();
///         memory[start..end].copy_from_slice(&data);
///         Ok(())
///     }
///
///     async fn disconnect(&self, _flags: CommandFlags) -> Result<(), ProtocolError> {
///         Ok(())
///     }
/// }
/// ```

// A singular NBD device interface.
pub trait NbdDriver {
    // Note that this is a synchronous method, as it is used to identify the driver
    // There's likely not a big need for async here
    fn get_name(&self) -> String;

    /// Returns the features supported by this device implementation.
    ///
    /// This method should return a combination of `ServerFeatures` flags
    /// that indicate which NBD protocol features are supported by this device.
    /// These features will be advertised to clients during the negotiation phase.
    /// Returns the features supported by this device implementation.
    ///
    /// This method should return a combination of `ServerFeatures` flags
    /// that indicate which NBD protocol features are supported by this device.
    /// These features will be advertised to clients during the negotiation phase.
    ///
    /// # Returns
    /// - `ServerFeatures`: A bitmask of supported features
    fn get_features(&self) -> ServerFeatures;

    /// Checks if a device is read-only.
    ///
    /// # Returns
    /// - `Ok(bool)`: `true` if the device is read-only, `false` otherwise
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_read_only(&self) -> impl Future<Output = Result<bool, OptionReplyError>>;

    /// Returns the block size information for a device.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device to query
    ///
    /// # Returns
    /// - `Ok((min_block_size, preferred_block_size, max_block_size))`: Block size constraints for the device
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_block_size(&self) -> impl Future<Output = Result<(u32, u32, u32), OptionReplyError>>;

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
    fn get_canonical_name(&self) -> impl Future<Output = Result<String, OptionReplyError>>;

    /// Returns a human-readable description of the device.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device
    ///
    /// # Returns
    /// - `Ok(String)`: The device description
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_description(&self) -> impl Future<Output = Result<String, OptionReplyError>>;

    /// Returns the size of a device in bytes.
    ///
    /// # Parameters
    /// - `device_name`: The name of the device
    ///
    /// # Returns
    /// - `Ok(u64)`: The device size in bytes
    /// - `Err(OptionReplyError)`: If the device doesn't exist or another error occurs
    fn get_device_size(&self) -> impl Future<Output = Result<u64, OptionReplyError>>;

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
    /// - It is not necessary to check for out-of-bounds writes, as the server implementation
    ///  handles these cases before they reach the driver
    /// - Other errors should be mapped to a `ProtocolError` member as appropriate
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
    /// - It is not necessary to check for out-of-bounds writes, as the server implementation
    ///  handles these cases before they reach the driver
    /// - Other errors should be mapped to a `ProtocolError` member as appropriate
    /// - Honor the Force Unit Access flag (`CommandFlags::FUA`) if supported
    /// - Consider atomicity guarantees for your storage backend
    fn write(
        &self,
        flags: CommandFlags,
        offset: u64,
        data: Vec<u8>,
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
    fn flush(&self, _flags: CommandFlags) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }

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
    /// - It is not necessary to check for out-of-bounds writes, as the server implementation
    ///  handles these cases before they reach the driver
    /// - Other errors should be mapped to a `ProtocolError` member as appropriate
    /// - This operation indicates that the data in the specified range is no longer needed
    fn trim(
        &self,
        _flags: CommandFlags,
        _offset: u64,
        _length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }

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
    /// - It is not necessary to check for out-of-bounds writes, as the server implementation
    ///  handles these cases before they reach the driver
    /// - Other errors should be mapped to a `ProtocolError` member as appropriate
    /// - If `CommandFlags::NO_HOLE` is set, the operation should ensure the resulting zeroes will read back as zeroes
    /// - If your backend has a native "write zeroes" operation, use it for efficiency
    /// - Otherwise, consider whether to allocate and write a buffer of zeroes or to use hole punching
    fn write_zeroes(
        &self,
        _flags: CommandFlags,
        _offset: u64,
        _length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }
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
    ) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }

    /// Requests that the driver cache a range of bytes for faster access.
    ///
    /// # Parameters
    /// - `flags`: Command flags for the cache operation
    /// - `offset`: Start offset in bytes
    /// - `length`: Number of bytes to cache
    ///
    /// # Returns
    /// - `Ok(())`: If caching succeeds
    /// - `Err(ProtocolError)`: If not supported or on error
    ///
    /// # Notes
    /// Most backends should return `ProtocolError::CommandNotSupported` unless caching is implemented.
    fn cache(
        &self,
        flags: CommandFlags,
        offset: u64,
        length: u32,
    ) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }

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
    ) -> impl Future<Output = Result<(), ProtocolError>> {
        async move { Err(ProtocolError::CommandNotSupported) }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    // Note that these tests include test for out-of-bounds reads/writes,
    // but the server implementation does handle these cases before they
    // reach the driver.

    use super::NbdDriver;
    use crate::errors::{OptionReplyError, ProtocolError};
    use crate::flags::{CommandFlags, ServerFeatures};

    use tokio;

    use std::sync::RwLock;

    #[derive(Debug)]
    pub(crate) struct MemoryDriver {
        data: RwLock<Vec<u8>>,
        read_only: bool,
        name: String,
    }

    impl Default for MemoryDriver {
        fn default() -> Self {
            MemoryDriver {
                data: RwLock::new(vec![0; 1024]), // 1KB of zeroed memory for tests
                read_only: false,
                name: "".to_string(),
            }
        }
    }

    impl NbdDriver for MemoryDriver {
        fn get_features(&self) -> ServerFeatures {
            // Support basic read/write operations but not advanced features
            ServerFeatures::SEND_FUA
        }

        fn get_name(&self) -> String {
            self.name.clone()
        }

        async fn get_read_only(&self) -> Result<bool, OptionReplyError> {
            Ok(self.read_only)
        }

        async fn get_block_size(&self) -> Result<(u32, u32, u32), OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_canonical_name(&self) -> Result<String, OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_description(&self) -> Result<String, OptionReplyError> {
            Err(OptionReplyError::Unsupported)
        }

        async fn get_device_size(&self) -> Result<u64, OptionReplyError> {
            Ok(self.data.read().unwrap().len() as u64)
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

            // Check if read is within bounds
            if start >= data.len() || (length > 0 && end > data.len()) {
                return Err(ProtocolError::InvalidArgument);
            }

            Ok(data[start..end].to_vec())
        }

        async fn write(
            &self,
            _flags: CommandFlags,
            offset: u64,
            data: Vec<u8>,
        ) -> Result<(), ProtocolError> {
            let mut memory = self.data.write().unwrap();
            let start = offset as usize;
            let end = start + data.len();

            // Check if write is within bounds
            if start >= memory.len() || (data.len() > 0 && end > memory.len()) {
                return Err(ProtocolError::InvalidArgument);
            }

            memory[start..end].copy_from_slice(&data);
            Ok(())
        }

        async fn disconnect(&self, _flags: CommandFlags) -> Result<(), ProtocolError> {
            Ok(())
        }

        // Other methods implementation...
    }

    #[tokio::test]
    async fn driver_memory_read() {
        let driver = MemoryDriver::default();

        let result = driver.read(CommandFlags::empty(), 0, 512).await;
        assert_eq!(result, Ok(vec![0; 512]));
    }

    #[tokio::test]
    async fn driver_memory_write_read() {
        let driver = MemoryDriver::default();

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
        let driver = MemoryDriver::default();

        let resize_result = driver.resize(CommandFlags::empty(), 2048).await;
        assert_eq!(resize_result, Err(ProtocolError::CommandNotSupported));
    }

    #[tokio::test]
    async fn driver_memory_read_out_of_bounds() {
        let driver = MemoryDriver::default();

        // Try to read beyond the buffer size
        let result = driver.read(CommandFlags::empty(), 512, 600).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));

        // Try to read with offset outside the buffer
        let result = driver.read(CommandFlags::empty(), 2000, 10).await;
        assert_eq!(result, Err(ProtocolError::InvalidArgument));
    }

    #[tokio::test]
    async fn driver_memory_write_out_of_bounds() {
        let driver = MemoryDriver::default();

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
        let driver = MemoryDriver::default();

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
        let driver = MemoryDriver::default();

        // Zero-length read should return empty vector
        let read_result = driver.read(CommandFlags::empty(), 100, 0).await;
        assert_eq!(read_result, Ok(vec![]));

        // Zero-length write should succeed
        let write_result = driver.write(CommandFlags::empty(), 100, vec![]).await;
        assert!(write_result.is_ok());
    }

    #[tokio::test]
    async fn driver_memory_list_devices_and_info() {
        let driver = MemoryDriver::default();

        // Check device size
        let size = driver.get_device_size().await.unwrap();
        assert_eq!(size, 1024);

        // Check read-only status
        let read_only = driver.get_read_only().await.unwrap();
        assert_eq!(read_only, false);
    }

    #[tokio::test]
    async fn driver_memory_get_name() {
        // Create driver with a specific name
        let mut driver = MemoryDriver::default();
        driver.name = "test-device".to_string();

        // Verify that get_name returns the expected name
        let name = driver.get_name();
        assert_eq!(name, "test-device");

        // Verify name changes are reflected
        driver.name = "another-device".to_string();
        let name = driver.get_name();
        assert_eq!(name, "another-device");
    }

    #[tokio::test]
    async fn driver_memory_command_flags() {
        let driver = MemoryDriver::default();

        // Check server features
        let features = driver.get_features();
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
        let driver = MemoryDriver::default();

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
            driver.get_block_size().await,
            Err(OptionReplyError::Unsupported)
        );

        assert_eq!(
            driver.get_canonical_name().await,
            Err(OptionReplyError::Unsupported)
        );

        assert_eq!(
            driver.get_description().await,
            Err(OptionReplyError::Unsupported)
        );
    }

    #[tokio::test]
    async fn driver_memory_disconnect() {
        let driver = MemoryDriver::default();

        // Disconnect should succeed
        let result = driver.disconnect(CommandFlags::empty()).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn driver_memory_error_handling_and_recovery() {
        let driver = MemoryDriver::default();

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
