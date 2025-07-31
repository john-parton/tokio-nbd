# tokio-nbd

Network Block Device (NBD) server with pluggable backend support using Rust and the tokio runtime.

[![License: GPL-2.0+](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## Overview

`tokio-nbd` is a Rust implementation of the Network Block Device (NBD) protocol that leverages the tokio asynchronous runtime. It provides a modern, high-performance, and extensible NBD server framework that can be used with various storage backends.

The library implements the full NBD protocol specification as defined at [NetworkBlockDevice/nbd](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md), including features like:

- Newstyle negotiation
- Export discovery
- Read/write operations
- Flush, FUA (Force Unit Access), and Trim commands
- Write Zeroes optimization
- Structured replies

## Features

- **Asynchronous I/O**: Built on tokio for efficient non-blocking I/O operations
- **Pluggable Backends**: Implement the `NBDDriver` trait for custom storage systems
- **Protocol Compliance**: Full support for the NBD protocol specification
- **Type-safe Error Handling**: Well-defined error types for protocol operations
- **Feature Negotiation**: Fine-grained control over supported protocol features

## Usage

Add `tokio-nbd` to your `Cargo.toml`:

```toml
[dependencies]
tokio-nbd = "0.1.0"
tokio = { version = "1.46.1", features = ["full"] }
```

### Example: Creating a Simple In-Memory NBD Server

```rust
use tokio_nbd::driver::{NBDDriver, NBDServer};
use tokio_nbd::flags::ServerFeatures;
use tokio_nbd::errors::{ProtocolError, OptionReplyError};
use tokio::net::{TcpListener, TcpStream};
use std::sync::{Arc, RwLock};

// Implement a simple in-memory driver
struct MemoryDriver {
    data: RwLock<Vec<u8>>,
}

// Implement the NBDDriver trait for MemoryDriver
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

    // Core data operations (partial implementation shown)
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

    // Implement other required methods...
}

async fn start_nbd(host: &str, port: u16, driver: Arc<MemoryDriver>) -> std::io::Result<()> {
    let listener = TcpListener::bind(format!("{}:{}", host, port)).await?;
    println!("NBD server listening on {}:{}", host, port);

    loop {
        let (stream, addr) = listener.accept().await?;
        println!("NBD client connected from {}", addr);

        let driver = Arc::clone(&driver);

        tokio::spawn(async move {
            let server = NBDServer::new(driver);

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
