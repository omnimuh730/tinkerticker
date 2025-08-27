
// src/network_monitor/mod.rs

// This module will contain the integrated network monitoring logic from sniffnet.
// It will include packet capturing, parsing, and data management.
// Functions will be exposed to the Tauri frontend for controlling the capture
// and retrieving network traffic data.

use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

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

use crate::network_monitor::types::capture_context::{CaptureContext, CaptureSource};
use crate::network_monitor::types::info_traffic::InfoTraffic;
use crate::network_monitor::types::address_port_pair::AddressPortPair;
use crate::network_monitor::types::data_info::DataInfo;
use crate::network_monitor::types::data_info_host::DataInfoHost;
use crate::network_monitor::types::arp_type::ArpType;
use crate::network_monitor::types::icmp_type::IcmpType;
use crate::network_monitor::types::packet_filters_fields::PacketFiltersFields;
use crate::network_monitor::manage_packets::{analyze_headers, modify_or_insert_in_map, get_address_to_lookup, get_traffic_type, is_local_connection};
use crate::network_monitor::types::bogon::is_bogon;
// Placeholder for the data returned by get_traffic_data
#[derive(Serialize)]
#[derive(Default)]
pub struct TrafficData {
    pub total_packets: u64,
    pub total_bytes: u64,
}

static mut CAPTURE_CHANNEL: Option<(Sender<TrafficData>, Receiver<TrafficData>)> = None;

pub fn start_capture(interface_name: String) -> Result<(), String> {
    let devices = Device::list().map_err(|e| e.to_string())?;
    let device = devices
        .into_iter()
        .find(|d| d.name == interface_name)
        .ok_or_else(|| format!("Interface '{}' not found", interface_name))?;

    let (tx, rx) = unbounded::<TrafficData>();
    unsafe {
        CAPTURE_CHANNEL = Some((tx.clone(), rx));
    }

    let capture_context = CaptureContext::from_device(device).map_err(|e| e.to_string())?;
    let stop_signal = Arc::new(AtomicBool::new(false));
    let stop_signal_clone = Arc::clone(&stop_signal);
    let mmdb_readers = MmdbReaders::default(); // Initialize with actual readers if available
    let mut cap = capture_context.consume().0;
    let my_link_type = capture_context.my_link_type();
    let interface_addresses = capture_context.capture_source().get_addresses().clone();

    thread::spawn(move || {
        let mut traffic_data: TrafficData = TrafficData::default();
        let mut last_send_time = Instant::now();
        let send_interval = Duration::from_millis(500); // Send updates twice a second

        while !stop_signal_clone.load(Ordering::SeqCst) {
            match cap.next_packet() {
                Ok(packet) => {
                    if let Ok(headers) = parse_packets::get_sniffable_headers(&packet, my_link_type) {
                        let mut exchanged_bytes = 0;
                        let mut mac_addresses = (None, None);
                        let mut icmp_type = IcmpType::default();
                        let mut arp_type = ArpType::default();
                        let mut packet_filters_fields = PacketFiltersFields::default();

                        let key_option = analyze_headers(
                            headers,
                            &mut mac_addresses,
                            &mut exchanged_bytes,
                            &mut icmp_type,
                            &mut arp_type,
                            &mut packet_filters_fields,
                        );

                        if let Some(key) = key_option {
                            traffic_data.total_packets += 1;
                            traffic_data.total_bytes += packet.len() as u64;

                            // Periodically send updated traffic data
                            if last_send_time.elapsed() >= send_interval {
                                let _ = tx.send_blocking(traffic_data.clone());
                                last_send_time = Instant::now();
                            }
                        }
                    }
                }
                Err(pcap::Error::TimeoutExpired) => {
                    // Timeout, continue loop
                }
                Err(_) => {
                    // Other errors, potentially stop capture
                    break;
                }
            }
        }
    });

    Ok(())
}

static mut STOP_SIGNAL: Option<Arc<AtomicBool>> = None;
static mut CAPTURE_THREAD: Option<thread::JoinHandle<()>> = None;

pub fn stop_capture() {
    unsafe {
        if let Some(signal) = &STOP_SIGNAL {
            signal.store(true, Ordering::SeqCst);
            // Wait for the capture thread to finish
 if let Some(handle) = CAPTURE_THREAD.take() {
 handle.join().unwrap();
 }
        }
    }
}

pub fn get_traffic_data() -> TrafficData {
    unsafe {
        if let Some((_, rx)) = &CAPTURE_CHANNEL {
            // Try to receive the latest InfoTraffic. If the channel is empty,
            // return a default or the last known state.
            match rx.try_recv() {
                Ok(info) => info,
                Err(TryRecvError::Empty) => {
                    TrafficData::default() // Channel is empty, return a default or cached state
                }
            }
        } else {
            // Capture not started
            TrafficData::default()
        }
    }
}

pub fn list_interfaces() -> Result<Vec<String>, String> {
    let devices = Device::list();
    match devices {
        Ok(devices) => Ok(devices.into_iter().map(|d| d.name).collect()),
        Err(e) => Err(e.to_string()),
    }
}
#[derive(Default)]
pub struct AddressesResolutionState {
    /// Map of the addresses waiting for a rDNS resolution; used to NOT send multiple rDNS for the same address
    addresses_waiting_resolution: HashMap<IpAddr, DataInfo>,
    /// Map of the resolved addresses with the corresponding host
    pub addresses_resolved: HashMap<IpAddr, crate::network_monitor::types::host::Host>,
}
