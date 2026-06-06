use std::path::PathBuf;
use std::time::Duration;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mike", about = "Soundcore D3200 BLE audio downloader")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan for Soundcore D3200 devices
    Scan {
        /// Scan duration in seconds
        #[arg(short, long, default_value = "5")]
        timeout: u64,
    },
    /// Connect and list all GATT characteristics (for protocol discovery)
    Chars {
        /// Device address or name substring
        #[arg(short, long)]
        device: String,
    },
    /// List recorded files on the device
    List {
        /// Device address or name substring
        #[arg(short, long)]
        device: String,
    },
    /// Download a file from the device
    Download {
        /// Device address or name substring
        #[arg(short, long)]
        device: String,
        /// File ID (timestamp) to download
        #[arg(short, long)]
        file_id: u32,
        /// Output directory
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
    /// Send raw hex command for protocol exploration
    Raw {
        /// Device address or name substring
        #[arg(short, long)]
        device: String,
        /// Hex bytes to send (e.g. "08EE0000001A07...")
        #[arg(short = 'x', long)]
        hex: String,
        /// Response timeout in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { timeout } => {
            println!("Scanning for Soundcore devices ({timeout}s)…");
            let devices =
                mic_rs::SoundcoreRecorder::scan(Duration::from_secs(timeout)).await?;

            if devices.is_empty() {
                println!("No devices found.");
            } else {
                for (i, d) in devices.iter().enumerate() {
                    println!("  [{}] {}", i, d);
                }
            }
        }

        Commands::Chars { device } => {
            let dev = find_device(&device).await?;
            println!("Connecting to {}…", dev);
            let recorder = mic_rs::SoundcoreRecorder::connect(dev).await?;
            println!("GATT characteristics:");
            recorder.list_characteristics();
            recorder.disconnect().await?;
        }

        Commands::List { device } => {
            let dev = find_device(&device).await?;
            println!("Connecting to {}…", dev);
            let mut recorder = mic_rs::SoundcoreRecorder::connect(dev).await?;

            println!("ECDH handshake…");
            recorder.handshake().await?;

            println!("Requesting file list…");
            let files = recorder.list_files().await?;

            if files.is_empty() {
                println!("No files on device.");
            } else {
                println!("{} file(s):", files.len());
                for f in &files {
                    println!("  {}", f);
                }
            }

            recorder.disconnect().await?;
        }

        Commands::Download {
            device,
            file_id,
            output,
        } => {
            let dev = find_device(&device).await?;
            println!("Connecting to {}…", dev);
            let mut recorder = mic_rs::SoundcoreRecorder::connect(dev).await?;

            println!("ECDH handshake…");
            recorder.handshake().await?;

            tokio::fs::create_dir_all(&output).await?;

            println!("Downloading file {file_id}…");
            let path = recorder
                .download_file(file_id, &output, |p| {
                    let pct = if p.total_bytes > 0 {
                        (p.bytes_received as f64 / p.total_bytes as f64 * 100.0) as u32
                    } else {
                        0
                    };
                    eprint!("\r  {}% ({}/{} bytes, seq={})", pct, p.bytes_received, p.total_bytes, p.sequence);
                })
                .await?;

            eprintln!();
            println!("Saved: {}", path.display());
            recorder.disconnect().await?;
        }

        Commands::Raw {
            device,
            hex,
            timeout,
        } => {
            let bytes = parse_hex(&hex)?;
            let dev = find_device(&device).await?;
            println!("Connecting to {}…", dev);
            let mut recorder = mic_rs::SoundcoreRecorder::connect(dev).await?;

            println!("TX ({} bytes):", bytes.len());
            hexdump(&bytes);

            let response = recorder
                .raw_command(&bytes, Duration::from_secs(timeout))
                .await?;

            println!("RX ({} bytes):", response.len());
            hexdump(&response);

            recorder.disconnect().await?;
        }
    }

    Ok(())
}

async fn find_device(query: &str) -> anyhow::Result<mic_rs::DeviceInfo> {
    println!("Scanning…");
    let devices = mic_rs::SoundcoreRecorder::scan(Duration::from_secs(5)).await?;
    devices
        .into_iter()
        .find(|d| d.address == query || d.name.to_lowercase().contains(&query.to_lowercase()))
        .ok_or_else(|| anyhow::anyhow!("device '{}' not found", query))
}

fn parse_hex(hex: &str) -> anyhow::Result<Vec<u8>> {
    let hex = hex.replace(' ', "");
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string has odd length");
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(Into::into))
        .collect()
}

fn hexdump(data: &[u8]) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("  {:04X}  {:<48}  {}", i * 16, hex.join(" "), ascii);
    }
}
