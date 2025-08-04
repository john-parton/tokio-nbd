# tokio-nbd

Network Block Device (NBD) server with pluggable backend support using Rust and the tokio runtime.

[![License: GPL-2.0+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## Overview

`tokio-nbd` is a Rust implementation of the Network Block Device (NBD) protocol that leverages the tokio asynchronous runtime. It provides a modern, high-performance, and extensible NBD server implementation that can be used with various storage backends.

## Features

- **Asynchronous I/O**: Built on tokio for efficient non-blocking I/O operations
- **Pluggable Backends**: Implement the `NbdDriver` trait for custom storage systems
- **Protocol Compliance**: Nearly complete support for the NBD protocol specification
- **Type-safe Error Handling**: Well-defined error types for protocol operations
- **Feature Negotiation**: Fine-grained control over supported protocol features

The library implements the most of the NBD protocol specification as defined at [NetworkBlockDevice/nbd](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md), with the exception of structured replies.

## Installation

Add `tokio-nbd` to your `Cargo.toml` using `cargo add tokio-nbd`

### Example: Creating a Simple In-Memory NBD Server

```rust
use std::sync::RwLock;

use tokio;
use tokio_nbd::device::NbdDriver;
use tokio_nbd::server::NbdServer;
use tokio_nbd::errors::{OptionReplyError, ProtocolError};
use tokio_nbd::flags::{CommandFlags, ServerFeatures};


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

async fn start_nbd(host: &str, port: u16, driver: Arc<MemoryDriver>) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;
    println!("NBD server listening on {}:{}", host, port);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("NBD client connected from {}", addr);

        let driver = Arc::clone(&driver);

        tokio::spawn(async move {
            let server = NbdServer::new(driver);

            if let Err(e) = server.start(stream).await {
                println!("Error starting NBD server: {:?}", e);
                return;
            }
        });
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = 10809; // Default NBD port

    // Create a driver with 1MB of storage
    let driver = Arc::new(MemoryDriver {
        data: RwLock::new(vec![0; 1024 * 1024]),
    });

    start_nbd("127.0.0.1", port, driver).await
}
```

## Security Considerations

NBD does not provide built-in authentication or encryption. For secure deployments:

- Use on trusted networks only
- Consider implementing TLS support (with the `START_TLS` option)
- Use firewall rules to restrict access

## Implementation Guidelines

When implementing the `NBDDriver` trait:

1. Consider which server features you want to support and expose them via the `get_features()` method
2. For features you don't support, return `ProtocolError::CommandNotSupported` from the corresponding method
3. Implement proper error handling for all methods
4. Consider thread safety if your implementation will be shared across threads

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [GPL-2.0-or-later](LICENSE) license.
