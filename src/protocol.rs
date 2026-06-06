// ---------- Constants ----------

pub const BLE_HEADER_MAGIC: [u8; 2] = [0x08, 0xEE];
pub const BLE_HEADER_SIZE: usize = 7;

// Command groups
pub const CMD_TYPE_FILE: u8 = 0x1A;
pub const CMD_TYPE_FILE_WITH_END_TIME: u8 = 0x1B;
pub const CMD_TYPE_AUDIO: u8 = 0x18;
pub const CMD_TYPE_ENCRYPT: u8 = 0x2E;
pub const CMD_TYPE_BINDING: u8 = 0x0B;

// File/transport commands (cmdType = 0x1A)
pub const CMD_WIFI_CLOSE: u8 = 0x02;
pub const CMD_WIFI_CONFIG: u8 = 0x05;
pub const CMD_SWITCH_TO_BLE: u8 = 0x06;
pub const CMD_FILE_HEADER: u8 = 0x07;
pub const CMD_FILE_SLICE: u8 = 0x08;
pub const CMD_FILE_COMPLETE: u8 = 0x0A;
pub const CMD_GET_ALL_FILES: u8 = 0x0E;
pub const CMD_OPEN_BT_TRANSPORT: u8 = 0x0F;
pub const CMD_DELETE_FILE: u8 = 0x10;
pub const CMD_CLOSE_BT_TRANSPORT: u8 = 0x11;
pub const CMD_FILE_SLICE_SUPPL: u8 = 0x12;

// Encrypt commands (cmdType = 0x2E)
pub const CMD_ENCRYPT_KEY_EXCHANGE: u8 = 0x01;

// Binding commands (cmdType = 0x0B)
pub const CMD_BINDING_REQUEST: u8 = 0x87;
pub const CMD_BINDING_CONFIRM: u8 = 0x88;
pub const CMD_AUTH_REQUEST: u8 = 0x8B;

// Audio commands (cmdType = 0x18)
pub const CMD_RECORD_CONTROL: u8 = 0x82;

// Sizes
pub const SLICE_PAYLOAD_SIZE: usize = 166;
pub const CHUNK_ENCRYPTED_SIZE: usize = 160;
pub const FILE_HEADER_MIN_SIZE: usize = 97;
pub const BLOCKS_PER_PACKET: u32 = 10;

// Crypto constants
pub const HKDF_SALT: [u8; 3] = [0x01, 0x02, 0x03];
pub const HKDF_INFO: [u8; 3] = [0x01, 0x02, 0x03];
pub const FILE_KEY_MAGIC: &[u8; 14] = b"soundcored3200";

pub const COMMAND_QUEUE_MAX: usize = 50;
pub const PROGRESS_UPDATE_INTERVAL_MS: u64 = 300;

// ---------- Checksum ----------

pub fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

// ---------- Packet building ----------

pub fn build_header(cmd_type: u8, cmd_id: u8) -> [u8; 7] {
    [0x08, 0xEE, 0x00, 0x00, 0x00, cmd_type, cmd_id]
}

/// Build a complete BLE command packet with length field and checksum.
///
/// Wire format: `[header(7)] [len_lo, len_hi] [payload(N)] [checksum(1)]`
/// where total_len = 7 + 2 + N + 1 = N + 10.
pub fn build_command(cmd_type: u8, cmd_id: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = BLE_HEADER_SIZE + 2 + payload.len() + 1;
    let mut cmd = Vec::with_capacity(total_len);
    cmd.extend_from_slice(&build_header(cmd_type, cmd_id));
    cmd.push((total_len & 0xFF) as u8);
    cmd.push(((total_len >> 8) & 0xFF) as u8);
    cmd.extend_from_slice(payload);
    let cs = checksum(&cmd);
    cmd.push(cs);
    cmd
}

// ---------- Command builders ----------

/// Request file header (1A07).
/// Payload: `[offset(4 LE)] [file_id(4 LE)] [realtime_flag(1)]`
pub fn file_header_request(file_id: u32, offset: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(9);
    payload.extend_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(&file_id.to_le_bytes());
    payload.push(0x00); // offline transfer
    build_command(CMD_TYPE_FILE, CMD_FILE_HEADER, &payload)
}

/// Delete file command (1A10). Payload: `[file_id(4 LE)]`
pub fn delete_file_command(file_id: u32) -> Vec<u8> {
    build_command(CMD_TYPE_FILE, CMD_DELETE_FILE, &file_id.to_le_bytes())
}

/// Request file list (1A0E). Payload: `[page(2 LE)]`
pub fn file_list_request(page: u16) -> Vec<u8> {
    build_command(CMD_TYPE_FILE, CMD_GET_ALL_FILES, &page.to_le_bytes())
}

/// ECDH public key exchange (2E01). Payload: 65-byte uncompressed SEC1 pubkey.
pub fn ecdh_pubkey_command(pubkey: &[u8]) -> Vec<u8> {
    build_command(CMD_TYPE_ENCRYPT, CMD_ENCRYPT_KEY_EXCHANGE, pubkey)
}

/// Open BT transport channel (1A0F). Payload: `[platform(1)]` (0x00=Android/Win)
pub fn open_bt_transport() -> Vec<u8> {
    build_command(CMD_TYPE_FILE, CMD_OPEN_BT_TRANSPORT, &[0x00])
}

/// Close BT transport channel (1A11). Payload: `[platform(1)]`
pub fn close_bt_transport() -> Vec<u8> {
    build_command(CMD_TYPE_FILE, CMD_CLOSE_BT_TRANSPORT, &[0x00])
}

// ---------- Response parsing ----------

#[derive(Debug, Clone)]
pub struct ResponseHeader {
    pub cmd_type: u8,
    pub cmd_id: u8,
    pub success_flag: u8,
    pub type_variant: u8,
}

pub fn parse_response(data: &[u8]) -> Option<ResponseHeader> {
    if data.len() < 7 {
        return None;
    }
    Some(ResponseHeader {
        cmd_type: data[5],
        cmd_id: data[6],
        success_flag: data[4] & 0x0F,
        type_variant: (data[4] >> 4) & 0x0F,
    })
}

// ---------- File header (1A07 response) ----------

#[derive(Debug, Clone)]
pub struct FileHeader {
    pub file_id: u32,
    pub size: u32,
    pub nonce: [u8; 16],
    pub encrypted_key: [u8; 46],
    pub session_nonce: [u8; 16],
    pub code: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileHeaderCode {
    Ok,
    FileNotExists,
    LocalFileError,
    AlreadyComplete,
    Unknown(u8),
}

impl From<u8> for FileHeaderCode {
    fn from(code: u8) -> Self {
        match code {
            0 => Self::Ok,
            1 => Self::FileNotExists,
            2 => Self::LocalFileError,
            3 => Self::AlreadyComplete,
            other => Self::Unknown(other),
        }
    }
}

pub fn parse_file_header(data: &[u8]) -> Option<FileHeader> {
    if data.len() < FILE_HEADER_MIN_SIZE {
        return None;
    }
    let success_flag = data[4] & 0x0F;
    if success_flag != 1 {
        return None;
    }
    Some(FileHeader {
        file_id: u32::from_le_bytes(data[9..13].try_into().ok()?),
        size: u32::from_le_bytes(data[13..17].try_into().ok()?),
        nonce: data[17..33].try_into().ok()?,
        encrypted_key: data[33..79].try_into().ok()?,
        session_nonce: data[79..95].try_into().ok()?,
        code: data[95],
    })
}

// ---------- Audio slice (1A08 response) ----------

#[derive(Debug, Clone)]
pub struct AudioSlice {
    pub sequence_number: u32,
    pub has_marker: bool,
    pub encrypted_chunk: Vec<u8>,
}

pub fn parse_audio_slices(data: &[u8]) -> Vec<AudioSlice> {
    let mut slices = Vec::new();
    let mut offset = 9usize; // skip header (7) + length (2)

    while offset + SLICE_PAYLOAD_SIZE <= data.len() {
        let seq = u32::from_le_bytes(
            data[offset..offset + 4].try_into().unwrap(),
        );
        let flags = data[offset + 4];
        let has_marker = (flags & 0x01) != 0;
        let chunk = data[offset + 5..offset + 5 + CHUNK_ENCRYPTED_SIZE].to_vec();

        slices.push(AudioSlice {
            sequence_number: seq,
            has_marker,
            encrypted_chunk: chunk,
        });
        offset += SLICE_PAYLOAD_SIZE;
    }
    slices
}

// ---------- File list (1A0E response) ----------

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub file_id: u32,
    pub size: u32,
    pub duration_ms: u32,
}

impl std::fmt::Display for FileInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let secs = self.duration_ms / 1000;
        let mb = self.size as f64 / (1024.0 * 1024.0);
        write!(
            f,
            "id={} size={:.1}MB duration={}:{:02}",
            self.file_id,
            mb,
            secs / 60,
            secs % 60,
        )
    }
}

/// Parse file list response (1A0E).
/// Layout: `[header(9)] [file_count(2 LE)] [entries(N * 8)]`
/// Each entry: `[time(4 LE)] [duration_ms(4 LE)]`
pub fn parse_file_list(data: &[u8]) -> Option<Vec<FileInfo>> {
    if data.len() < 11 {
        return None;
    }
    let file_count = u16::from_le_bytes(data[9..11].try_into().ok()?) as usize;
    let mut files = Vec::with_capacity(file_count);
    let mut offset = 11;
    for _ in 0..file_count {
        if offset + 8 > data.len() {
            break;
        }
        let time = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
        let duration = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().ok()?);
        let size = (duration / 20) * SLICE_PAYLOAD_SIZE as u32;
        files.push(FileInfo {
            file_id: time,
            size,
            duration_ms: duration,
        });
        offset += 8;
    }
    Some(files)
}

// ---------- ECDH response parsing ----------

pub struct EcdhResponse {
    pub device_pubkey: Vec<u8>,
    pub device_shared_key: Vec<u8>,
}

/// Parse ECDH key exchange response (2E01).
/// Layout: `[header(9)] [device_pubkey(65)] [device_shared_key(32)]`
pub fn parse_ecdh_response(data: &[u8]) -> Option<EcdhResponse> {
    if data.len() < 9 + 65 + 32 {
        return None;
    }
    Some(EcdhResponse {
        device_pubkey: data[9..74].to_vec(),
        device_shared_key: data[74..106].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- checksum ----------

    #[test]
    fn checksum_empty() {
        assert_eq!(checksum(&[]), 0);
    }

    #[test]
    fn checksum_wraps() {
        assert_eq!(checksum(&[0xFF, 0x02]), 0x01);
    }

    // ---------- build_header ----------

    #[test]
    fn header_magic_bytes() {
        let h = build_header(0x1A, 0x07);
        assert_eq!(h[0], 0x08);
        assert_eq!(h[1], 0xEE);
        assert_eq!(&h[2..5], &[0x00, 0x00, 0x00]);
        assert_eq!(h[5], 0x1A);
        assert_eq!(h[6], 0x07);
    }

    #[test]
    fn header_length_is_7() {
        assert_eq!(build_header(0, 0).len(), BLE_HEADER_SIZE);
    }

    // ---------- build_command ----------

    #[test]
    fn command_empty_payload() {
        let cmd = build_command(0x1A, 0x02, &[]);
        // 7 header + 2 length + 0 payload + 1 checksum = 10
        assert_eq!(cmd.len(), 10);
        assert_eq!(cmd[5], 0x1A);
        assert_eq!(cmd[6], 0x02);
        // length field = 10
        assert_eq!(cmd[7], 10);
        assert_eq!(cmd[8], 0);
        // checksum is last byte
        let cs = checksum(&cmd[..cmd.len() - 1]);
        assert_eq!(*cmd.last().unwrap(), cs);
    }

    #[test]
    fn command_with_payload() {
        let cmd = build_command(0x1A, 0x05, &[0xAA, 0xBB]);
        // 7 + 2 + 2 + 1 = 12
        assert_eq!(cmd.len(), 12);
        assert_eq!(&cmd[9..11], &[0xAA, 0xBB]);
        let cs = checksum(&cmd[..cmd.len() - 1]);
        assert_eq!(*cmd.last().unwrap(), cs);
    }

    #[test]
    fn command_checksum_validates() {
        let cmd = build_command(0x1A, 0x07, &[0x01, 0x02, 0x03]);
        let computed = checksum(&cmd[..cmd.len() - 1]);
        assert_eq!(cmd[cmd.len() - 1], computed);
    }

    // ---------- file_header_request ----------

    #[test]
    fn file_header_request_structure() {
        let req = file_header_request(0x12345678, 0x00001000);
        // 7 header + 2 length + 9 payload(offset+fileId+flag) + 1 checksum = 19
        assert_eq!(req.len(), 19);
        assert_eq!(req[5], CMD_TYPE_FILE);
        assert_eq!(req[6], CMD_FILE_HEADER);
        // payload: offset first, then fileId, then flag
        assert_eq!(&req[9..13], &0x00001000u32.to_le_bytes()); // offset
        assert_eq!(&req[13..17], &0x12345678u32.to_le_bytes()); // fileId
        assert_eq!(req[17], 0x00); // realtime flag
    }

    #[test]
    fn file_header_request_zero_offset() {
        let req = file_header_request(42, 0);
        assert_eq!(&req[9..13], &[0, 0, 0, 0]); // offset = 0
    }

    // ---------- delete_file_command ----------

    #[test]
    fn delete_command_structure() {
        let cmd = delete_file_command(999);
        // 7 + 2 + 4 + 1 = 14
        assert_eq!(cmd.len(), 14);
        assert_eq!(cmd[5], CMD_TYPE_FILE);
        assert_eq!(cmd[6], CMD_DELETE_FILE);
        assert_eq!(&cmd[9..13], &999u32.to_le_bytes());
    }

    // ---------- file_list_request ----------

    #[test]
    fn file_list_request_structure() {
        let cmd = file_list_request(0);
        // 7 + 2 + 2 + 1 = 12
        assert_eq!(cmd.len(), 12);
        assert_eq!(cmd[5], CMD_TYPE_FILE);
        assert_eq!(cmd[6], CMD_GET_ALL_FILES);
        assert_eq!(&cmd[9..11], &0u16.to_le_bytes());
    }

    // ---------- ecdh_pubkey_command ----------

    #[test]
    fn ecdh_command_structure() {
        let fake_pubkey = vec![0x04; 65];
        let cmd = ecdh_pubkey_command(&fake_pubkey);
        // 7 + 2 + 65 + 1 = 75
        assert_eq!(cmd.len(), 75);
        assert_eq!(cmd[5], CMD_TYPE_ENCRYPT);
        assert_eq!(cmd[6], CMD_ENCRYPT_KEY_EXCHANGE);
        assert_eq!(&cmd[9..74], &fake_pubkey[..]);
    }

    // ---------- open/close bt transport ----------

    #[test]
    fn open_bt_transport_structure() {
        let cmd = open_bt_transport();
        assert_eq!(cmd.len(), 11); // 7 + 2 + 1 + 1
        assert_eq!(cmd[5], CMD_TYPE_FILE);
        assert_eq!(cmd[6], CMD_OPEN_BT_TRANSPORT);
        assert_eq!(cmd[9], 0x00);
    }

    #[test]
    fn close_bt_transport_structure() {
        let cmd = close_bt_transport();
        assert_eq!(cmd[6], CMD_CLOSE_BT_TRANSPORT);
    }

    // ---------- parse_response ----------

    #[test]
    fn parse_response_valid() {
        let data = [0x09, 0xFF, 0x00, 0x00, 0x31, 0x1A, 0x07, 0x00, 0x00];
        let r = parse_response(&data).unwrap();
        assert_eq!(r.cmd_type, 0x1A);
        assert_eq!(r.cmd_id, 0x07);
        assert_eq!(r.success_flag, 1);
        assert_eq!(r.type_variant, 3);
    }

    #[test]
    fn parse_response_too_short() {
        assert!(parse_response(&[0x09, 0xFF, 0x00]).is_none());
        assert!(parse_response(&[]).is_none());
    }

    #[test]
    fn parse_response_nibble_isolation() {
        let data = [0x09, 0xFF, 0x00, 0x00, 0xF9, 0x1A, 0x08];
        let r = parse_response(&data).unwrap();
        assert_eq!(r.success_flag, 0x09);
        assert_eq!(r.type_variant, 0x0F);
    }

    #[test]
    fn parse_response_ignores_extra_bytes() {
        let data = [0x09, 0xFF, 0x00, 0x00, 0x01, 0x1A, 0x0A, 0xFF, 0xFF];
        let r = parse_response(&data).unwrap();
        assert_eq!(r.cmd_id, CMD_FILE_COMPLETE);
    }

    // ---------- FileHeaderCode ----------

    #[test]
    fn file_header_code_mapping() {
        assert_eq!(FileHeaderCode::from(0), FileHeaderCode::Ok);
        assert_eq!(FileHeaderCode::from(1), FileHeaderCode::FileNotExists);
        assert_eq!(FileHeaderCode::from(2), FileHeaderCode::LocalFileError);
        assert_eq!(FileHeaderCode::from(3), FileHeaderCode::AlreadyComplete);
        assert_eq!(FileHeaderCode::from(99), FileHeaderCode::Unknown(99));
    }

    // ---------- parse_file_header ----------

    fn make_file_header_bytes(success: u8, code: u8) -> Vec<u8> {
        let mut data = vec![0u8; 97];
        data[0] = 0x09;
        data[1] = 0xFF;
        data[4] = success;
        data[5] = 0x1A;
        data[6] = 0x07;
        data[9..13].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        data[13..17].copy_from_slice(&160_000u32.to_le_bytes());
        data[17..33].fill(0x11);
        data[33..79].fill(0x22);
        data[79..95].fill(0x33);
        data[95] = code;
        data
    }

    #[test]
    fn parse_file_header_valid() {
        let data = make_file_header_bytes(0x01, 0x00);
        let h = parse_file_header(&data).unwrap();
        assert_eq!(h.file_id, 0xDEADBEEF);
        assert_eq!(h.size, 160_000);
        assert_eq!(h.nonce, [0x11; 16]);
        assert_eq!(h.encrypted_key, [0x22; 46]);
        assert_eq!(h.session_nonce, [0x33; 16]);
        assert_eq!(h.code, 0);
    }

    #[test]
    fn parse_file_header_too_short() {
        assert!(parse_file_header(&[0u8; 96]).is_none());
        assert!(parse_file_header(&[]).is_none());
    }

    #[test]
    fn parse_file_header_bad_success_flag() {
        let data = make_file_header_bytes(0x00, 0x00);
        assert!(parse_file_header(&data).is_none());
    }

    #[test]
    fn parse_file_header_success_nibble_only() {
        let data = make_file_header_bytes(0xA1, 0x00);
        assert!(parse_file_header(&data).is_some());
    }

    #[test]
    fn parse_file_header_error_codes() {
        for code in [0, 1, 2, 3] {
            let data = make_file_header_bytes(0x01, code);
            let h = parse_file_header(&data).unwrap();
            assert_eq!(h.code, code);
        }
    }

    #[test]
    fn parse_file_header_extra_bytes_ok() {
        let mut data = make_file_header_bytes(0x01, 0x00);
        data.extend_from_slice(&[0xFF; 50]);
        let h = parse_file_header(&data).unwrap();
        assert_eq!(h.file_id, 0xDEADBEEF);
    }

    // ---------- parse_audio_slices ----------

    fn make_slice_packet(slices: &[(u32, u8)]) -> Vec<u8> {
        let mut data = vec![0u8; 9];
        data[0] = 0x09;
        data[1] = 0xFF;
        data[5] = 0x1A;
        data[6] = 0x08;

        for &(seq, flags) in slices {
            let mut slice_data = vec![0u8; SLICE_PAYLOAD_SIZE];
            slice_data[0..4].copy_from_slice(&seq.to_le_bytes());
            slice_data[4] = flags;
            for i in 0..CHUNK_ENCRYPTED_SIZE {
                slice_data[5 + i] = (seq as u8).wrapping_add(i as u8);
            }
            data.extend_from_slice(&slice_data);
        }
        data
    }

    #[test]
    fn parse_slices_empty_packet() {
        let data = vec![0u8; 9];
        assert!(parse_audio_slices(&data).is_empty());
    }

    #[test]
    fn parse_slices_too_short_for_one() {
        let data = vec![0u8; 9 + SLICE_PAYLOAD_SIZE - 1];
        assert!(parse_audio_slices(&data).is_empty());
    }

    #[test]
    fn parse_slices_single() {
        let data = make_slice_packet(&[(1, 0x00)]);
        let slices = parse_audio_slices(&data);
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].sequence_number, 1);
        assert!(!slices[0].has_marker);
        assert_eq!(slices[0].encrypted_chunk.len(), CHUNK_ENCRYPTED_SIZE);
    }

    #[test]
    fn parse_slices_multiple() {
        let data = make_slice_packet(&[(10, 0x00), (11, 0x01), (12, 0x00)]);
        let slices = parse_audio_slices(&data);
        assert_eq!(slices.len(), 3);
        assert_eq!(slices[0].sequence_number, 10);
        assert_eq!(slices[1].sequence_number, 11);
        assert_eq!(slices[2].sequence_number, 12);
    }

    #[test]
    fn parse_slices_marker_flag() {
        let data = make_slice_packet(&[(0, 0x01), (1, 0x00), (2, 0x03)]);
        let slices = parse_audio_slices(&data);
        assert!(slices[0].has_marker);
        assert!(!slices[1].has_marker);
        assert!(slices[2].has_marker);
    }

    #[test]
    fn parse_slices_trailing_bytes_ignored() {
        let mut data = make_slice_packet(&[(5, 0x00)]);
        data.extend_from_slice(&[0xFF; 100]);
        let slices = parse_audio_slices(&data);
        assert_eq!(slices.len(), 1);
    }

    #[test]
    fn parse_slices_chunk_content() {
        let data = make_slice_packet(&[(7, 0x00)]);
        let slices = parse_audio_slices(&data);
        assert_eq!(slices[0].encrypted_chunk[0], 7);
        assert_eq!(slices[0].encrypted_chunk[100], 107);
    }

    // ---------- parse_file_list ----------

    #[test]
    fn parse_file_list_empty() {
        let mut data = vec![0u8; 11];
        data[9] = 0; // file_count = 0
        data[10] = 0;
        let files = parse_file_list(&data).unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn parse_file_list_single_file() {
        let mut data = vec![0u8; 11 + 8];
        data[9] = 1; // file_count = 1
        data[10] = 0;
        // time = 1717600000
        data[11..15].copy_from_slice(&1717600000u32.to_le_bytes());
        // duration = 60000 ms (1 minute)
        data[15..19].copy_from_slice(&60000u32.to_le_bytes());
        let files = parse_file_list(&data).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].file_id, 1717600000);
        assert_eq!(files[0].duration_ms, 60000);
        assert_eq!(files[0].size, (60000 / 20) * 166);
    }

    #[test]
    fn parse_file_list_multiple() {
        let mut data = vec![0u8; 11 + 16];
        data[9] = 2;
        data[10] = 0;
        data[11..15].copy_from_slice(&100u32.to_le_bytes());
        data[15..19].copy_from_slice(&20000u32.to_le_bytes());
        data[19..23].copy_from_slice(&200u32.to_le_bytes());
        data[23..27].copy_from_slice(&40000u32.to_le_bytes());
        let files = parse_file_list(&data).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].file_id, 100);
        assert_eq!(files[1].file_id, 200);
    }

    #[test]
    fn parse_file_list_too_short() {
        assert!(parse_file_list(&[0u8; 10]).is_none());
    }

    // ---------- parse_ecdh_response ----------

    #[test]
    fn parse_ecdh_response_valid() {
        let mut data = vec![0u8; 9 + 65 + 32];
        data[9] = 0x04; // uncompressed point marker
        data[74] = 0xAB; // first byte of shared key
        let resp = parse_ecdh_response(&data).unwrap();
        assert_eq!(resp.device_pubkey.len(), 65);
        assert_eq!(resp.device_pubkey[0], 0x04);
        assert_eq!(resp.device_shared_key.len(), 32);
        assert_eq!(resp.device_shared_key[0], 0xAB);
    }

    #[test]
    fn parse_ecdh_response_too_short() {
        assert!(parse_ecdh_response(&[0u8; 105]).is_none());
    }

    // ---------- FileInfo display ----------

    #[test]
    fn file_info_display_format() {
        let fi = FileInfo {
            file_id: 1717600000,
            size: 5 * 1024 * 1024,
            duration_ms: 125_000,
        };
        let s = fi.to_string();
        assert!(s.contains("id=1717600000"));
        assert!(s.contains("5.0MB"));
        assert!(s.contains("2:05"));
    }

    #[test]
    fn file_info_display_zero_duration() {
        let fi = FileInfo {
            file_id: 1,
            size: 0,
            duration_ms: 0,
        };
        let s = fi.to_string();
        assert!(s.contains("0:00"));
        assert!(s.contains("0.0MB"));
    }

    // ---------- round-trip ----------

    #[test]
    fn roundtrip_build_parse_response() {
        let cmd = build_command(0x1A, 0x07, &[0xAA]);
        let r = parse_response(&cmd).unwrap();
        assert_eq!(r.cmd_type, 0x1A);
        assert_eq!(r.cmd_id, 0x07);
        assert_eq!(r.success_flag, 0);
    }

    // ---------- constants sanity ----------

    #[test]
    fn constants_consistent() {
        assert_eq!(BLE_HEADER_MAGIC, [0x08, 0xEE]);
        assert_eq!(CMD_TYPE_FILE, 0x1A);
        assert!(FILE_HEADER_MIN_SIZE > BLE_HEADER_SIZE);
        assert_eq!(SLICE_PAYLOAD_SIZE, 4 + 1 + CHUNK_ENCRYPTED_SIZE + 1);
        assert_eq!(BLOCKS_PER_PACKET, (CHUNK_ENCRYPTED_SIZE / 16) as u32);
        assert_eq!(FILE_KEY_MAGIC, b"soundcored3200");
    }
}
