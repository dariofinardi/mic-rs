use std::path::{Path, PathBuf};
use std::time::Duration;

use log::{debug, info, warn};
use tokio::io::AsyncWriteExt;

use crate::ble::BleConnection;
use crate::crypto;
use crate::error::{Result, RecorderError};
use crate::protocol::*;

#[derive(Debug, Clone)]
pub struct DownloadProgress {
    pub file_id: u32,
    pub bytes_received: u32,
    pub total_bytes: u32,
    pub sequence: u32,
}

const RECV_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn download_file(
    conn: &mut BleConnection,
    file_id: u32,
    session_key: &[u8; 32],
    output_dir: &Path,
    progress: impl Fn(DownloadProgress),
) -> Result<PathBuf> {
    // Step 1: Send file header request (1A07)
    let request = file_header_request(file_id, 0);
    conn.send(&request).await?;

    // Step 2: Wait for 1A07 response
    let file_header = loop {
        let data = conn.recv(RECV_TIMEOUT).await?;
        let resp = match parse_response(&data) {
            Some(r) => r,
            None => continue,
        };
        if resp.cmd_type == CMD_TYPE_FILE && resp.cmd_id == CMD_FILE_HEADER {
            let hdr = parse_file_header(&data).ok_or_else(|| {
                RecorderError::InvalidResponse("failed to parse file header".into())
            })?;
            break hdr;
        }
        debug!("skipping cmd {:02X}{:02X} while waiting for header", resp.cmd_type, resp.cmd_id);
    };

    match FileHeaderCode::from(file_header.code) {
        FileHeaderCode::Ok => {}
        FileHeaderCode::FileNotExists => return Err(RecorderError::FileNotExists(file_id)),
        FileHeaderCode::AlreadyComplete => {
            info!("file {} already downloaded", file_id);
            return Ok(output_dir.join(format!("{}.opus", file_id)));
        }
        other => {
            return Err(RecorderError::FileTransferError(format!(
                "file header code: {:?}",
                other
            )));
        }
    }

    info!(
        "file {} header ok: size={} bytes",
        file_id, file_header.size
    );

    // Step 3: Derive file decryption key
    let file_key = crypto::decrypt_file_key(
        session_key,
        &file_header.encrypted_key,
        &file_header.session_nonce,
    )?;

    // Step 4: Receive data slices (1A08) until completion (1A0A)
    let mut raw_frames: Vec<Vec<u8>> = Vec::new();
    let mut bytes_received: u32 = 0;
    let mut last_seq: u32 = 0;

    loop {
        let data = conn.recv(RECV_TIMEOUT).await?;
        let resp = match parse_response(&data) {
            Some(r) => r,
            None => continue,
        };

        if resp.cmd_type != CMD_TYPE_FILE {
            continue;
        }

        match resp.cmd_id {
            CMD_FILE_SLICE | CMD_FILE_SLICE_SUPPL => {
                let slices = parse_audio_slices(&data);
                for slice in &slices {
                    if slice.sequence_number > last_seq + 1 && last_seq > 0 {
                        warn!(
                            "packet gap: expected {}, got {}",
                            last_seq + 1,
                            slice.sequence_number
                        );
                    }

                    let decrypted = crypto::decrypt_chunk(
                        &file_key,
                        &file_header.nonce,
                        slice.sequence_number,
                        &slice.encrypted_chunk,
                    );

                    bytes_received += decrypted.len() as u32;
                    raw_frames.push(decrypted);
                    last_seq = slice.sequence_number;

                    progress(DownloadProgress {
                        file_id,
                        bytes_received,
                        total_bytes: file_header.size,
                        sequence: slice.sequence_number,
                    });
                }
            }
            CMD_FILE_COMPLETE => {
                info!("file {} complete: {} bytes received", file_id, bytes_received);
                break;
            }
            _ => {
                debug!("ignoring cmd {:02X} during download", resp.cmd_id);
            }
        }
    }

    // Step 5: Wrap raw Opus frames in OGG container and write .opus file
    let opus_path = output_dir.join(format!("{}.opus", file_id));
    let ogg_data = wrap_ogg_opus(&raw_frames, file_id);
    let mut file = tokio::fs::File::create(&opus_path).await?;
    file.write_all(&ogg_data).await?;
    file.flush().await?;

    Ok(opus_path)
}

// ---------- OGG Opus container ----------

const OPUS_SAMPLE_RATE: u32 = 48000;
const OPUS_CHANNELS: u8 = 2;
const SAMPLES_PER_FRAME: u64 = 960; // 48kHz × 20ms
const FRAMES_PER_PAGE: usize = 10;

fn wrap_ogg_opus(frames: &[Vec<u8>], serial: u32) -> Vec<u8> {
    let mut out = Vec::new();

    // Page 0: OpusHead (BOS)
    let mut opus_head = Vec::with_capacity(19);
    opus_head.extend_from_slice(b"OpusHead");
    opus_head.push(1); // version
    opus_head.push(OPUS_CHANNELS);
    opus_head.extend_from_slice(&312u16.to_le_bytes()); // pre-skip
    opus_head.extend_from_slice(&OPUS_SAMPLE_RATE.to_le_bytes());
    opus_head.extend_from_slice(&0i16.to_le_bytes()); // output gain
    opus_head.push(0); // channel mapping family
    out.extend(ogg_page(serial, 0, 0, OGG_BOS, &[&opus_head]));

    // Page 1: OpusTags
    let vendor = b"mic-rs";
    let mut tags = Vec::new();
    tags.extend_from_slice(b"OpusTags");
    tags.extend_from_slice(&(vendor.len() as u32).to_le_bytes());
    tags.extend_from_slice(vendor);
    tags.extend_from_slice(&0u32.to_le_bytes()); // no user comments
    out.extend(ogg_page(serial, 1, 0, 0, &[&tags]));

    // Audio pages
    let mut page_no: u32 = 2;
    let mut granule: u64 = 0;
    for chunk in frames.chunks(FRAMES_PER_PAGE) {
        granule += chunk.len() as u64 * SAMPLES_PER_FRAME;
        let segments: Vec<&[u8]> = chunk.iter().map(|f| f.as_slice()).collect();
        let is_last = page_no as usize - 2 + 1 >= (frames.len() + FRAMES_PER_PAGE - 1) / FRAMES_PER_PAGE;
        let flags = if is_last { OGG_EOS } else { 0 };
        out.extend(ogg_page(serial, page_no, granule, flags, &segments));
        page_no += 1;
    }

    out
}

const OGG_BOS: u8 = 0x02;
const OGG_EOS: u8 = 0x04;

fn ogg_page(serial: u32, page_no: u32, granule: u64, flags: u8, segments: &[&[u8]]) -> Vec<u8> {
    // Build segment table
    let mut seg_table = Vec::new();
    for seg in segments {
        let mut remaining = seg.len();
        while remaining >= 255 {
            seg_table.push(255u8);
            remaining -= 255;
        }
        seg_table.push(remaining as u8);
    }

    // Header (27 bytes + segment table)
    let mut page = Vec::with_capacity(27 + seg_table.len() + segments.iter().map(|s| s.len()).sum::<usize>());
    page.extend_from_slice(b"OggS");
    page.push(0); // version
    page.push(flags);
    page.extend_from_slice(&granule.to_le_bytes());
    page.extend_from_slice(&serial.to_le_bytes());
    page.extend_from_slice(&page_no.to_le_bytes());
    page.extend_from_slice(&0u32.to_le_bytes()); // CRC placeholder
    page.push(seg_table.len() as u8);
    page.extend_from_slice(&seg_table);

    // Body
    for seg in segments {
        page.extend_from_slice(seg);
    }

    // Compute and insert CRC
    let crc = ogg_crc32(&page);
    page[22..26].copy_from_slice(&crc.to_le_bytes());

    page
}

fn ogg_crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &b in data {
        crc ^= (b as u32) << 24;
        for _ in 0..8 {
            if crc & 0x80000000 != 0 {
                crc = (crc << 1) ^ 0x04C11DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}
