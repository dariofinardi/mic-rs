pub mod error;
pub mod protocol;
pub mod crypto;
pub mod ble;
pub mod download;

pub use ble::DeviceInfo;
pub use download::DownloadProgress;
pub use error::{Result, SoundcoreError};
pub use protocol::FileInfo;

use std::path::{Path, PathBuf};
use std::time::Duration;

use log::info;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

/// High-level client for Soundcore D3200 audio recorder.
pub struct SoundcoreRecorder {
    conn: ble::BleConnection,
    session_key: Option<[u8; 32]>,
}

impl SoundcoreRecorder {
    /// Scan for Soundcore D3200 devices via BLE.
    pub async fn scan(timeout: Duration) -> Result<Vec<DeviceInfo>> {
        ble::scan_devices(timeout).await
    }

    /// Connect to a discovered device.
    pub async fn connect(device: DeviceInfo) -> Result<Self> {
        let conn = ble::BleConnection::connect(device).await?;
        Ok(Self {
            conn,
            session_key: None,
        })
    }

    /// Perform ECDH handshake to establish encrypted session.
    ///
    /// Sends our P-256 public key (cmdType=0x2E, cmdId=0x01), receives the
    /// device's public key + shared secret, verifies agreement, and derives
    /// the session key via HKDF-SHA256.
    pub async fn handshake(&mut self) -> Result<()> {
        let keypair = crypto::EcdhKeypair::generate();
        let pubkey = keypair.public_key_bytes.clone();

        let cmd = protocol::ecdh_pubkey_command(&pubkey);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;

        let ecdh_resp = protocol::parse_ecdh_response(&resp).ok_or_else(|| {
            SoundcoreError::HandshakeFailed(format!(
                "ECDH response too short: {} bytes (need {})",
                resp.len(),
                9 + 65 + 32
            ))
        })?;

        let shared_secret = keypair.derive_shared_secret(&ecdh_resp.device_pubkey)?;

        if shared_secret.as_slice() != ecdh_resp.device_shared_key.as_slice() {
            return Err(SoundcoreError::HandshakeFailed(
                "ECDH shared secret mismatch — device computed a different value".into(),
            ));
        }

        let session_key = crypto::derive_session_key(&shared_secret);
        self.session_key = Some(session_key);
        info!("ECDH handshake complete, session key derived");
        Ok(())
    }

    /// Set session key directly (for testing or when key is known).
    pub fn set_session_key(&mut self, key: [u8; 32]) {
        self.session_key = Some(key);
    }

    /// Open the BLE transport channel. Call before file operations.
    pub async fn open_transport(&mut self) -> Result<()> {
        let cmd = protocol::open_bt_transport();
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;
        let header = protocol::parse_response(&resp).ok_or_else(|| {
            SoundcoreError::InvalidResponse("invalid open_transport response".into())
        })?;
        if header.success_flag != 1 {
            return Err(SoundcoreError::InvalidResponse(format!(
                "open_transport failed: flag={}",
                header.success_flag
            )));
        }
        info!("BT transport channel opened");
        Ok(())
    }

    /// Close the BLE transport channel.
    pub async fn close_transport(&mut self) -> Result<()> {
        let cmd = protocol::close_bt_transport();
        self.conn.send(&cmd).await?;
        Ok(())
    }

    /// Request the list of offline recorded files from the device.
    pub async fn list_files(&mut self) -> Result<Vec<FileInfo>> {
        let cmd = protocol::file_list_request(0);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;

        let header = protocol::parse_response(&resp).ok_or_else(|| {
            SoundcoreError::InvalidResponse("invalid file list response".into())
        })?;

        if header.cmd_type != protocol::CMD_TYPE_FILE
            || header.cmd_id != protocol::CMD_GET_ALL_FILES
        {
            return Err(SoundcoreError::InvalidResponse(format!(
                "unexpected response: {:02X}{:02X}",
                header.cmd_type, header.cmd_id
            )));
        }

        protocol::parse_file_list(&resp)
            .ok_or_else(|| SoundcoreError::InvalidResponse("failed to parse file list".into()))
    }

    /// Download a file by its ID (timestamp) to the output directory.
    /// Returns the path to the saved .opus file.
    pub async fn download_file(
        &mut self,
        file_id: u32,
        output_dir: &Path,
        progress: impl Fn(DownloadProgress),
    ) -> Result<PathBuf> {
        let key = self
            .session_key
            .as_ref()
            .ok_or_else(|| SoundcoreError::HandshakeFailed("no session key — call handshake() or set_session_key() first".into()))?;
        let key = *key;
        download::download_file(&mut self.conn, file_id, &key, output_dir, progress).await
    }

    /// Delete a file from the device by its ID (timestamp).
    pub async fn delete_file(&mut self, file_id: u32) -> Result<()> {
        let cmd = protocol::delete_file_command(file_id);
        let resp = self.conn.send_and_recv(&cmd, CMD_TIMEOUT).await?;
        let header = protocol::parse_response(&resp).ok_or_else(|| {
            SoundcoreError::InvalidResponse("invalid delete response".into())
        })?;
        if header.success_flag != 1 {
            return Err(SoundcoreError::InvalidResponse(format!(
                "delete_file failed: flag={}",
                header.success_flag
            )));
        }
        info!("deleted file {} from device", file_id);
        Ok(())
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
}
