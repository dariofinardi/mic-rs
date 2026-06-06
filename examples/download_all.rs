use std::path::Path;
use std::time::Duration;

use mic_rs::Recorder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // 1. Scan for any supported device
    println!("Scanning for devices (5s)…");
    let devices = Recorder::scan(None, Duration::from_secs(5)).await?;

    if devices.is_empty() {
        println!("No devices found.");
        return Ok(());
    }

    let device = devices.into_iter().next().unwrap();
    println!("Found: {device}");

    // 2. Connect and handshake
    let mut recorder = Recorder::connect(device).await?;
    println!("Connected. Running handshake…");
    recorder.handshake().await?;
    println!("Session established.");

    // 3. List files
    let files = recorder.list_files().await?;
    if files.is_empty() {
        println!("No files on device.");
        recorder.disconnect().await?;
        return Ok(());
    }

    println!("{} file(s) found:", files.len());
    for f in &files {
        println!("  {f}");
    }

    // 4. Download all files
    let output_dir = Path::new("./recordings");
    std::fs::create_dir_all(output_dir)?;

    for (i, f) in files.iter().enumerate() {
        println!("\nDownloading file {}/{} (id={})…", i + 1, files.len(), f.file_id);
        let path = recorder
            .download_file(f.file_id, output_dir, |p| {
                let pct = if p.total_bytes > 0 {
                    p.bytes_received * 100 / p.total_bytes
                } else {
                    0
                };
                eprint!("\r  {pct}% ({}/{} bytes)", p.bytes_received, p.total_bytes);
            })
            .await?;
        eprintln!();
        println!("  Saved: {}", path.display());
    }

    // 5. Disconnect
    recorder.disconnect().await?;
    println!("\nDone.");
    Ok(())
}
