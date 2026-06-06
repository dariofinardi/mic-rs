pub mod error;
pub mod protocol;
pub mod crypto;
pub mod ble;
pub mod download;

pub use download::DownloadProgress;
pub use error::{Result, RecorderError};
pub use protocol::FileInfo;

use std::path::{Path, PathBuf};
use std::time::Duration;

use log::info;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// Supported device families.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// Anker Soundcore Work D3200
    SoundcoreD3200,
    // PlaudNote,  // planned
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeviceKind::SoundcoreD3200 => write!(f, "Soundcore D3200"),
        }
    }
}

/// A discovered BLE recording device.
pub struct Device {
    pub name: String,
    pub address: String,
    pub kind: DeviceKind,
    pub(crate) peripheral: btleplug::platform::Peripheral,
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}) [{}]", self.name, self.address, self.kind)
    }
}

/// High-level client for BLE audio recorders.
///
/// Abstracts over device-specific protocols. Currently supports
/// the Anker Soundcore D3200; additional devices can be added
/// by extending `DeviceKind` and the internal protocol modules.
pub struct Recorder {
    conn: ble::BleConnection,
    session_key: Option<[u8; 32]>,
    pub kind: DeviceKind,
}

impl Recorder {
    /// Scan for supported BLE recording devices.
    ///
    /// Pass `None` to scan for all supported devices, or `Some(kind)` to
    /// filter by a specific device family.
    pub async fn scan(filter: Option<DeviceKind>, timeout: Duration) -> Result<Vec<Device>> {
        let mut devices = Vec::new();

        match filter {
            None | Some(DeviceKind::SoundcoreD3200) => {
                let found = ble::scan_devices(timeout).await?;
                devices.extend(found.into_iter().map(|d| Device {
                    name: d.name,
                    address: d.address,
                    kind: DeviceKind::SoundcoreD3200,
                    peripheral: d.peripheral,
                }));
            }
        }

        Ok(devices)
    }

    /// Connect to a discovered device.
    pub async fn connect(device: Device) -> Result<Self> {
        let kind = device.kind;
        let info = ble::DeviceInfo {
            name: device.name,
            address: device.address,
            peripheral: device.peripheral,
        };
        let conn = ble::BleConnection::connect(info).await?;
        Ok(Self {
            conn,
            session_key: None,
            kind,
        })
    }

    /// Perform the device-specific handshake to establish an encrypted session.
    ///
    /// For Soundcore D3200: ECDH P-256 key exchange with HKDF-SHA256
    /// session key derivation.
    pub async fn handshake(&mut self) -> Result<()> {
        match self.kind {
            DeviceKind::SoundcoreD3200 => self.soundcore_handshake().await,
        }
    }

    /// Set session key directly (for testing or when key is known).
    pub fn set_session_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    /// Request the list of recorded files from the device.
    pub async fn list_files(&mut self) -> Result<Vec<FileInfo>> {
        match self.kind {
            DeviceKind::SoundcoreD3200 => self.soundcore_list_files().await,
        }
    }

    /// Download a file by its ID to the output directory.
    /// Returns the path to the saved audio file.
    pub async fn download_file(
        &mut self,
        file_id: u32,
        output_dir: &Path,
        progress: impl Fn(DownloadProgress),
    ) -> Result<PathBuf> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| RecorderError::HandshakeFailed("no session key — call handshake() first".into()))?;
        let key = *key;
        download::download_file(&mut self.conn, file_id, &key, output_dir, progress).await
    }

    /// Delete a file from the device by its ID.
    pub async fn delete_file(&mut self, file_id: u32) -> Result<()> {
        match self.kind {
            DeviceKind::SoundcoreD3200 => self.soundcore_delete_file(file_id).await,
        }
    }

    /// Send a raw BLE command and receive the first response.
    /// Useful for protocol exploration and discovering undocumented commands.
    pub async fn raw_command(&mut self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.conn.send_and_recv(data, timeout).await
    }

    /// Send raw bytes without waiting for response.
    pub async fn raw_send(&self, data: &[u8]) -> Result<()> {
        self.conn.send(data).await
    }

    /// Build a BLE command packet with standard header, length, and checksum.
    pub fn build_command(cmd_type: u8, cmd_id: u8, payload: &[u8]) -> Vec<u8> {
        protocol::build_command(cmd_type, cmd_id, payload)
    }

    /// Print all discovered GATT characteristics (for debugging).
    pub fn list_characteristics(&self) {
        self.conn.list_characteristics();
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.conn.disconnect().await
    }

    // ── Soundcore D3200 internals ──────────────────────────

    async fn soundcore_handshake(&mut self) -> Result<()> {
        let keypair = crypto::EcdhKeypair::generate();
        let pubkey = keypair.public_key_bytes.clone();

        let cmd = protocol::ecdh_pubkey_command(&pubkey);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;

        let ecdh_resp = protocol::parse_ecdh_response(&resp).ok_or_else(|| {
            RecorderError::HandshakeFailed(format!(
                "ECDH response too short: {} bytes (need {})",
                resp.len(),
                9 + 65 + 32
            ))
        })?;

        let shared_secret = keypair.derive_shared_secret(&ecdh_resp.device_pubkey)?;

        if shared_secret.as_slice() != ecdh_resp.device_shared_key.as_slice() {
            return Err(RecorderError::HandshakeFailed(
                "ECDH shared secret mismatch — device computed a different value".into(),
            ));
        }

        let session_key = crypto::derive_session_key(&shared_secret);
        self.session_key = Some(session_key);
        info!("ECDH handshake complete, session key derived");
        Ok(())
    }

    async fn soundcore_list_files(&mut self) -> Result<Vec<FileInfo>> {
        let cmd = protocol::file_list_request(0);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;

        let header = protocol::parse_response(&resp).ok_or_else(|| {
            RecorderError::InvalidResponse("invalid file list response".into())
        })?;

        if header.cmd_type != protocol::CMD_TYPE_FILE
            || header.cmd_id != protocol::CMD_GET_ALL_FILES
        {
            return Err(RecorderError::InvalidResponse(format!(
                "unexpected response: {:02X}{:02X}",
                header.cmd_type, header.cmd_id
            )));
        }

        protocol::parse_file_list(&resp)
            .ok_or_else(|| RecorderError::InvalidResponse("failed to parse file list".into()))
    }

    async fn soundcore_delete_file(&mut self, file_id: u32) -> Result<()> {
        let cmd = protocol::delete_file_command(file_id);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;
        let header = protocol::parse_response(&resp).ok_or_else(|| {
            RecorderError::InvalidResponse("invalid delete response".into())
        })?;
        if header.success_flag != 1 {
            return Err(RecorderError::InvalidResponse(format!(
                "delete_file failed: flag={}",
                header.success_flag
            )));
        }
        info!("deleted file {} from device", file_id);
        Ok(())
    }
}
