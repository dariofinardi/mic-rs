use std::time::Duration;

use btleplug::api::{
    Central, CharPropFlags, Manager as _, Peripheral as _, ScanFilter, WriteType,
};
use btleplug::platform::{Manager, Peripheral};
use futures::stream::StreamExt;
use log::{debug, info};
use uuid::Uuid;

use crate::error::{Result, RecorderError};

pub const SERVICE_UUID: Uuid = Uuid::from_u128(0x020cf5da_0000_1000_8000_00805f9b34fb);

// ---------- Device info ----------

pub struct DeviceInfo {
    pub name: String,
    pub address: String,
    pub(crate) peripheral: Peripheral,
}

impl std::fmt::Display for DeviceInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.address)
    }
}

// ---------- BLE scanning ----------

pub async fn scan_devices(timeout: Duration) -> Result<Vec<DeviceInfo>> {
    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    let adapter = adapters.into_iter().next().ok_or(RecorderError::NoAdapter)?;

    info!("starting BLE scan ({:.0}s)…", timeout.as_secs_f64());
    adapter
        .start_scan(ScanFilter {
            services: vec![SERVICE_UUID],
        })
        .await?;

    tokio::time::sleep(timeout).await;
    let _ = adapter.stop_scan().await;

    let peripherals = adapter.peripherals().await?;
    let mut devices = Vec::new();

    for p in peripherals {
        let props = match p.properties().await? {
            Some(pr) => pr,
            None => continue,
        };

        if !props.services.contains(&SERVICE_UUID) {
            continue;
        }

        let name = props.local_name.unwrap_or_else(|| "Soundcore".into());
        let address = p.address().to_string();
        info!("found device: {name} ({address})");
        devices.push(DeviceInfo {
            name,
            address,
            peripheral: p,
        });
    }

    Ok(devices)
}

// ---------- BLE connection ----------

pub struct BleConnection {
    peripheral: Peripheral,
    write_char: btleplug::api::Characteristic,
    rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
}

impl BleConnection {
    pub async fn connect(device: DeviceInfo) -> Result<Self> {
        let peripheral = device.peripheral;

        info!("connecting to {} ({})…", device.name, device.address);
        peripheral.connect().await?;
        peripheral.discover_services().await?;

        let chars = peripheral.characteristics();
        debug!("discovered {} characteristics", chars.len());

        // Find write + notify characteristics, preferring ones under our service UUID
        let write_char = chars
            .iter()
            .filter(|c| c.service_uuid == SERVICE_UUID)
            .find(|c| {
                c.properties.contains(CharPropFlags::WRITE)
                    || c.properties.contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
            })
            .or_else(|| {
                chars.iter().find(|c| {
                    c.properties.contains(CharPropFlags::WRITE)
                        || c.properties.contains(CharPropFlags::WRITE_WITHOUT_RESPONSE)
                })
            })
            .ok_or_else(|| RecorderError::CharacteristicNotFound("write".into()))?
            .clone();

        let notify_char = chars
            .iter()
            .filter(|c| c.service_uuid == SERVICE_UUID)
            .find(|c| c.properties.contains(CharPropFlags::NOTIFY))
            .or_else(|| {
                chars
                    .iter()
                    .find(|c| c.properties.contains(CharPropFlags::NOTIFY))
            })
            .ok_or_else(|| RecorderError::CharacteristicNotFound("notify".into()))?
            .clone();

        info!(
            "write={} notify={}",
            write_char.uuid, notify_char.uuid
        );

        peripheral.subscribe(&notify_char).await?;
        let mut stream = peripheral.notifications().await?;

        let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        tokio::spawn(async move {
            while let Some(notif) = stream.next().await {
                if tx.send(notif.value).await.is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            peripheral,
            write_char,
            rx,
        })
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let wt = if self
            .write_char
            .properties
            .contains(CharPropFlags::WRITE)
        {
            WriteType::WithResponse
        } else {
            WriteType::WithoutResponse
        };
        debug!("BLE send {} bytes", data.len());
        self.peripheral.write(&self.write_char, data, wt).await?;
        Ok(())
    }

    pub async fn recv(&mut self, timeout: Duration) -> Result<Vec<u8>> {
        match tokio::time::timeout(timeout, self.rx.recv()).await {
            Ok(Some(data)) => {
                debug!("BLE recv {} bytes", data.len());
                Ok(data)
            }
            Ok(None) => Err(RecorderError::Disconnected),
            Err(_) => Err(RecorderError::Timeout),
        }
    }

    pub async fn send_and_recv(&mut self, data: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.send(data).await?;
        self.recv(timeout).await
    }

    pub async fn disconnect(&self) -> Result<()> {
        self.peripheral.disconnect().await?;
        Ok(())
    }

    pub fn list_characteristics(&self) {
        for c in self.peripheral.characteristics() {
            println!(
                "  svc={} char={} props={:?}",
                c.service_uuid, c.uuid, c.properties
            );
        }
    }
}
