use thiserror::Error;

#[derive(Debug, Error)]
pub enum RecorderError {
    #[error("BLE adapter not found")]
    NoAdapter,

    #[error("device not found during scan")]
    DeviceNotFound,

    #[error("BLE connection failed: {0}")]
    ConnectionFailed(String),

    #[error("GATT characteristic not found: {0}")]
    CharacteristicNotFound(String),

    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("file transfer error: {0}")]
    FileTransferError(String),

    #[error("crypto error: {0}")]
    CryptoError(String),

    #[error("file not found on device (id={0})")]
    FileNotExists(u32),

    #[error("timeout waiting for response")]
    Timeout,

    #[error("device disconnected")]
    Disconnected,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("BLE error: {0}")]
    Ble(#[from] btleplug::Error),
}

pub type Result<T> = std::result::Result<T, RecorderError>;
