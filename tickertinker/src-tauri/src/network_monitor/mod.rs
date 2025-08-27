
// src/network_monitor/mod.rs

// This module will contain the integrated network monitoring logic from sniffnet.
// It will include packet capturing, parsing, and data management.
// Functions will be exposed to the Tauri frontend for controlling the capture
// and retrieving network traffic data.

use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use maxminddb::Reader;
use serde::Serialize;

use async_channel::{Receiver, Sender, unbounded, TryRecvError};
use pcap::{Capture, Device, Packet};
pub mod manage_packets;
pub mod parse_packets;
pub mod types;

// Placeholder for MmdbReaders
#[derive(Clone, Default)]
pub struct MmdbReaders {
    pub country: Option<Reader<Vec<u8>>>,
    pub asn: Option<Reader<Vec<u8>>>,
}
use crate::network_monitor::types::capture_context::CaptureContext;
// Placeholder for the data returned by get_traffic_data
#[derive(Serialize)]
pub struct TrafficData {
    // TODO: Define the actual structure based on InfoTraffic and Hosts
    pub placeholder: String,
}

static mut CAPTURE_CHANNEL: Option<(Sender<parse_packets::BackendTrafficMessage>, Receiver<parse_packets::BackendTrafficMessage>)> = None;

pub fn start_capture(interface_name: String) -> Result<(), String> {
    let devices = Device::list().map_err(|e| e.to_string())?;
    let device = devices
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

    let (tx, rx) = unbounded();
    unsafe {
        CAPTURE_CHANNEL = Some((tx.clone(), rx));
    }

    let capture_context = CaptureContext::from_device(device);
    thread::spawn(move || parse_packets(0, capture_context.capture_source(), &MmdbReaders::default(), capture_context, &tx));
    Ok(())
}

pub fn stop_capture() {
    // TODO: Implement capture stop logic
}

pub fn get_traffic_data() -> TrafficData { TrafficData { placeholder: "Traffic data placeholder".to_string() } }

pub fn list_interfaces() -> Result<Vec<String>, String> {
    let devices = Device::list();
    match devices {
        Ok(devices) => Ok(devices.into_iter().map(|d| d.name).collect()),
        Err(e) => Err(e.to_string()),
    }
}

