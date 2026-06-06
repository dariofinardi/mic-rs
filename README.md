# mic-rs

Rust library and CLI for downloading audio recordings from BLE-enabled voice recorders.

Currently supports the **Anker Soundcore Work D3200**. Support for **Plaud** devices is planned. Additional devices may follow based on demand and community contributions.

## Features

- BLE device scanning and connection via [btleplug](https://crates.io/crates/btleplug)
- ECDH P-256 handshake with HKDF-SHA256 session key derivation
- AES-CTR encrypted audio transfer and decryption
- Proprietary binary protocol: file listing, download with progress, deletion
- OGG/Opus container wrapping for downloaded audio
- Raw command interface for protocol exploration
- Cross-platform: Windows, macOS, Linux

## Library usage

Add to your `Cargo.toml`:

```toml
[dependencies]
mic-rs = { git = "https://github.com/dariofinardi/mic-rs.git" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

### Scan for devices

```rust
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let devices = mic_rs::SoundcoreRecorder::scan(Duration::from_secs(5)).await?;
    for dev in &devices {
        println!("{dev}"); // "Soundcore D3200 (AA:BB:CC:DD:EE:FF)"
    }
    Ok(())
}
```

### Connect, list files, download

```rust
use std::path::Path;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Scan and connect
    let devices = mic_rs::SoundcoreRecorder::scan(Duration::from_secs(5)).await?;
    let device = devices.into_iter().next().expect("no device found");
    let mut recorder = mic_rs::SoundcoreRecorder::connect(device).await?;

    // 2. Establish encrypted session
    recorder.handshake().await?;

    // 3. List files on the device
    let files = recorder.list_files().await?;
    for f in &files {
        println!("{f}"); // file ID, size, timestamp
    }

    // 4. Download a file with progress
    let file_id = files[0].file_id;
    let path = recorder
        .download_file(file_id, Path::new("./output"), |p| {
            let pct = p.bytes_received * 100 / p.total_bytes.max(1);
            eprintln!("\r  {pct}% ({}/{})", p.bytes_received, p.total_bytes);
        })
        .await?;
    println!("Saved: {}", path.display());

    // 5. Optionally delete the file from the device
    recorder.delete_file(file_id).await?;

    // 6. Disconnect
    recorder.disconnect().await?;
    Ok(())
}
```

### Progress callback

`download_file` reports progress via a `DownloadProgress` struct:

```rust
pub struct DownloadProgress {
    pub file_id: u32,
    pub bytes_received: u32,
    pub total_bytes: u32,
    pub sequence: u32,
}
```

### Error handling

All operations return `mic_rs::Result<T>`, which wraps `SoundcoreError`:

```rust
pub enum SoundcoreError {
    NoAdapter,
    DeviceNotFound,
    ConnectionFailed(String),
    HandshakeFailed(String),
    FileNotExists(u32),
    FileTransferError(String),
    CryptoError(String),
    Timeout,
    Disconnected,
    // ...
}
```

## CLI (`mike`)

The crate includes a binary for direct device interaction:

```bash
# Scan for devices
mike scan

# List files on a device (by name or address)
mike list -d "D3200"

# Download a specific file
mike download -d "D3200" -f 1780722187 -o ./recordings

# Send a raw hex command (protocol exploration)
mike raw -d "D3200" -x "08EE0000001A0700000001"
```

## Architecture

```
mic-rs/
  src/
    lib.rs       -- SoundcoreRecorder public API
    ble.rs       -- BLE scanning, connection, GATT read/write
    protocol.rs  -- Binary protocol: command building, response parsing
    crypto.rs    -- ECDH, HKDF, AES-CTR encryption/decryption
    download.rs  -- File transfer state machine, OGG/Opus wrapping
    error.rs     -- Error types
    bin/mike.rs  -- CLI binary
```

## Device support roadmap

| Device | Status |
|--------|--------|
| Anker Soundcore Work D3200 | Supported |
| Plaud Note / NotePin | Planned |
| Others | On request |

Contributions and protocol captures for new devices are welcome.

## License

Copyright 2025-2026 Dario Finardi

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

See [LICENSE](LICENSE) for the full text.
