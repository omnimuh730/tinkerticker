rust
//! Module containing functions executed by the thread in charge of parsing sniffed packets

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use etherparse::err::ip::{HeaderError, LaxHeaderSliceError};
use etherparse::err::{Layer, LenError};
use etherparse::{LaxPacketHeaders, LenSource};
use pcap::{Address, Capture, Device, Packet, Savefile, Stat};
use tauri::AppHandle;

use crate::network_monitor::types::address_port_pair::AddressPortPair;
use crate::network_monitor::types::arp_type::ArpType;
use crate::network_monitor::types::bogon::is_bogon;
use crate::network_monitor::types::capture_context::{CaptureContext, CaptureSource};
use crate::network_monitor::types::data_info::DataInfo;
use crate::network_monitor::types::data_info_host::DataInfoHost;
use crate::network_monitor::types::host::{Host, HostMessage};
use crate::network_monitor::types::icmp_type::IcmpType;
use crate::network_monitor::types::info_traffic::InfoTraffic;
use crate::network_monitor::types::my_link_type::MyLinkType;
use crate::network_monitor::types::packet_filters_fields::PacketFiltersFields;
use crate::network_monitor::types::traffic_direction::TrafficDirection;
use crate::network_monitor::types::traffic_type::TrafficType;
use crate::network_monitor::types::{IpVersion, Protocol};
use crate::network_monitor::manage_packets::{analyze_headers, get_address_to_lookup, get_traffic_type, is_local_connection, modify_or_insert_in_map};
// Assuming necessary utils functions are also copied or adapted
use crate::network_monitor::utils::formatted_strings::get_domain_from_r_dns;
use crate::network_monitor::utils::types::timestamp::Timestamp;
use crate::network_monitor::mmdb::asn::get_asn;
use crate::network_monitor::mmdb::country::get_country;
use crate::network_monitor::mmdb::types::mmdb_reader::MmdbReaders;


/// The calling thread enters a loop in which it waits for network packets
pub fn parse_packets(
    tx: async_channel::Sender<InfoTraffic>,
    mut cs: CaptureSource,
    mmdb_readers: MmdbReaders,
    capture_context: CaptureContext,
) {
    let my_link_type = capture_context.my_link_type();
    let (mut cap, mut savefile) = capture_context.consume();

    let mut info_traffic_msg = InfoTraffic::default();
    // This instant is used for periodic sending of InfoTraffic updates
    let mut first_packet_ticks = None;

    loop {
        // Check if the capture should stop (e.g., based on a shared atomic flag or a channel)
        // For now, let's assume a mechanism to signal stopping.
        // You would need to implement a way to gracefully stop this thread.
        // For example, a shared atomic boolean: if stop_flag.load(Ordering::SeqCst) { break; }


        let packet_res = cap.next_packet();

        if matches!(cs, CaptureSource::Device(_)) {
            // In Tauri, we'll emit events to the frontend
            maybe_emit_traffic_update_live(
                &app_handle,
                cap_id,
                &mut info_traffic_msg,
                &new_hosts_to_send,
                &mut cs,
                &mut first_packet_ticks,
            );
        }

        match packet_res {
            Err(e) => {
                if e == pcap::Error::NoMorePackets {
                    // send a message including data from the last interval (only happens in offline captures)
                     let _ = app_handle.emit_all(
                        "traffic_update",
                        TrafficUpdateMessage {
                            cap_id,
                            info_traffic: info_traffic_msg.clone(), // Clone if necessary for the event payload
                            new_hosts: new_hosts_to_send.lock().unwrap().drain(..).collect(),
                            is_final: true,
                        },
                    );
                    // wait until there is still some thread doing rdns
                     // This loop might block the thread, consider an alternative in Tauri
                    while thread::active_count() > 1 { // This condition might need adjustment
                        thread::sleep(Duration::from_millis(1000));
                    }
                    // send one last message including all pending hosts
                    let _ = app_handle.emit_all(
                         "pending_hosts",
                         PendingHostsMessage {
                             cap_id,
                             new_hosts: new_hosts_to_send.lock().unwrap().drain(..).collect(),
                         },
                     );
                    return;
                }
            }
            Ok(packet) => {
                if let Ok(headers) = get_sniffable_headers(&packet, my_link_type) {
                    #[allow(clippy::useless_conversion)]
                    let secs = i64::from(packet.header.ts.tv_sec);
                    #[allow(clippy::useless_conversion)]
                    let usecs = i64::from(packet.header.ts.tv_usec);
                    let next_packet_timestamp = Timestamp::new(secs, usecs);

                    if matches!(cs, CaptureSource::File(_)) {
                         maybe_emit_traffic_update_offline(
                            &app_handle,
                            cap_id,
                            &mut info_traffic_msg,
                            &new_hosts_to_send,
                            next_packet_timestamp,
                         );
                    } else if first_packet_ticks.is_none() {
                        first_packet_ticks = Some(Instant::now());
                    }

                    info_traffic_msg.last_packet_timestamp = next_packet_timestamp;

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

                    let Some(key) = key_option else {
                        continue;
                    };

                    // save this packet to PCAP file
                    if let Some(file) = savefile.as_mut() {
                        file.write(&packet);
                    }
                    // update the map
                    let (traffic_direction, service) = modify_or_insert_in_map(
                        &mut info_traffic_msg,
                        &key,
                        &cs,
                        mac_addresses,
                        icmp_type,
                        arp_type,
                        exchanged_bytes,
                    );

                    info_traffic_msg
                        .tot_data_info
                        .add_packet(exchanged_bytes, traffic_direction);

                    // check the rDNS status of this address and act accordingly
                    let address_to_lookup = get_address_to_lookup(&key, traffic_direction);
                    let mut r_dns_waiting_resolution = false;
                    let mut resolutions_lock = resolutions_state.lock().unwrap();
                    let r_dns_already_resolved = resolutions_lock
                        .addresses_resolved
                        .contains_key(&address_to_lookup);
                    if !r_dns_already_resolved {
                        r_dns_waiting_resolution = resolutions_lock
                            .addresses_waiting_resolution
                            .contains_key(&address_to_lookup);
                    }

                    match (r_dns_waiting_resolution, r_dns_already_resolved) {
                        (false, false) => {
                            // rDNS not requested yet (first occurrence of this address to lookup)

                            // Add this address to the map of addresses waiting for a resolution
                            // Useful to NOT perform again a rDNS lookup for this entry
                            resolutions_lock.addresses_waiting_resolution.insert(
                                address_to_lookup,
                                DataInfo::new_with_first_packet(exchanged_bytes, traffic_direction),
                            );
                            drop(resolutions_lock);

                            // launch new thread to resolve host name
                            let key2 = key;
                            let resolutions_state2 = resolutions_state.clone();
                            let new_hosts_to_send2 = new_hosts_to_send.clone();
                            let interface_addresses = cs.get_addresses().clone();
                            let mmdb_readers_2 = mmdb_readers.clone();
                            let app_handle2 = app_handle.clone();
                            let _ = thread::Builder::new()
                                .name("thread_reverse_dns_lookup".to_string())
                                .spawn(move || {
                                    reverse_dns_lookup(
                                        &resolutions_state2,
                                        &new_hosts_to_send2,
                                        &key2,
                                        traffic_direction,
                                        &interface_addresses,
                                        &mmdb_readers_2,
                                        &app_handle2, // Pass app_handle for emitting events
                                    );
                                }); // Removed .log_err(location!()) as it's specific to sniffnet's error handling
                        }
                        (true, false) => {
                            // waiting for a previously requested rDNS resolution
                            // update the corresponding waiting address data
                            resolutions_lock
                                .addresses_waiting_resolution
                                .entry(address_to_lookup)
                                .and_modify(|data_info| {
                                    data_info.add_packet(exchanged_bytes, traffic_direction);
                                });
                            drop(resolutions_lock);
                        }
                        (_, true) => {
                            // rDNS already resolved
                            // update the corresponding host\'s data info
                            let host = resolutions_lock
                                .addresses_resolved
                                .get(&address_to_lookup)
                                .unwrap_or(&Host::default())
                                .clone();
                            drop(resolutions_lock);
                            info_traffic_msg
                                .hosts
                                .entry(host)
                                .and_modify(|data_info_host| {
                                    data_info_host
                                        .data_info
                                        .add_packet(exchanged_bytes, traffic_direction);
                                })
                                .or_insert_with(|| {
                                    let my_interface_addresses = cs.get_addresses();
                                    let traffic_type = get_traffic_type(
                                        &address_to_lookup,
                                        my_interface_addresses,
                                        traffic_direction,
                                    );
                                    let is_loopback = address_to_lookup.is_loopback();
                                    let is_local = is_local_connection(
                                        &address_to_lookup,
                                        my_interface_addresses,
                                    );
                                    let is_bogon = is_bogon(&address_to_lookup);
                                    DataInfoHost {
                                        data_info: DataInfo::new_with_first_packet(
                                            exchanged_bytes,
                                            traffic_direction,
                                        ),
                                        is_favorite: false, // Assuming this is a UI concept, set to default
                                        is_loopback,
                                        is_local,
                                        is_bogon,
                                        traffic_type,
                                    }
                                });
                        }
                    }

                    //increment the packet count for the sniffed service
                    info_traffic_msg
                        .services
                        .entry(service)
                        .and_modify(|data_info| {
                            data_info.add_packet(exchanged_bytes, traffic_direction);
                        })
                        .or_insert_with(|| {
                            DataInfo::new_with_first_packet(exchanged_bytes, traffic_direction)
                        });

                    // update dropped packets number
                    if let Ok(stats) = cap.stats() {
                        info_traffic_msg.dropped_packets = stats.dropped;
                    }
                }
            }
        }
    }
}

fn get_sniffable_headers<'a>(
    packet: &'a Packet,
    my_link_type: MyLinkType,
) -> Result<LaxPacketHeaders<'a>, LaxHeaderSliceError> {
    match my_link_type {
        MyLinkType::Ethernet(_) | MyLinkType::Unsupported(_) | MyLinkType::NotYetAssigned => {
            LaxPacketHeaders::from_ethernet(packet).map_err(LaxHeaderSliceError::Len)
        }
        MyLinkType::RawIp(_) | MyLinkType::IPv4(_) | MyLinkType::IPv6(_) => {
            LaxPacketHeaders::from_ip(packet)
        }
        MyLinkType::Null(_) | MyLinkType::Loop(_) => from_null(packet),
    }
}

fn from_null(packet: &[u8]) -> Result<LaxPacketHeaders<'_>, LaxHeaderSliceError> {
    if packet.len() <= 4 {
        return Err(LaxHeaderSliceError::Len(LenError {
            required_len: 4,
            len: packet.len(),
            len_source: LenSource::Slice,
            layer: Layer::Ethernet2Header,
            layer_start_offset: 0,
        }));
    }

    let is_valid_af_inet = {
        // based on https://wiki.wireshark.org/NullLoopback.md (2023-12-31)
        fn matches(value: u32) -> bool {
            match value {
                // 2 = IPv4 on all platforms
                // 24, 28, or 30 = IPv6 depending on platform
                2 | 24 | 28 | 30 => true,
                _ => false,
            }
        }
        let h = &packet[..4];
        let b = [h[0], h[1], h[2], h[3]];
        // check both big endian and little endian representations
        // as some OS\'es use native endianness and others use big endian
        matches(u32::from_le_bytes(b)) || matches(u32::from_be_bytes(b))
    };

    if is_valid_af_inet {
        LaxPacketHeaders::from_ip(&packet[4..])
    } else {
        Err(LaxHeaderSliceError::Content(
            HeaderError::UnsupportedIpVersion { version_number: 0 },
        ))
    }
}

fn reverse_dns_lookup(
    resolutions_state: &Arc<Mutex<AddressesResolutionState>>,\
    new_hosts_to_send: &Arc<Mutex<Vec<HostMessage>>>,\
    key: &AddressPortPair,\
    traffic_direction: TrafficDirection,\
    interface_addresses: &Vec<Address>,\
    mmdb_readers: &MmdbReaders,\
    app_handle: &AppHandle, // Use AppHandle to emit events
) {
    let address_to_lookup = get_address_to_lookup(key, traffic_direction);

    // perform rDNS lookup
    let lookup_result = lookup_addr(&address_to_lookup);

    // get new host info and build the new host
    let traffic_type = get_traffic_type(&address_to_lookup, interface_addresses, traffic_direction);
    let is_loopback = address_to_lookup.is_loopback();
    let is_local = is_local_connection(&address_to_lookup, interface_addresses);
    let is_bogon = is_bogon(&address_to_lookup);
    let country = get_country(&address_to_lookup, &mmdb_readers.country);
    let asn = get_asn(&address_to_lookup, &mmdb_readers.asn);
    let rdns = if let Ok(result) = lookup_result {
        if result.is_empty() {
            address_to_lookup.to_string()
        } else {
            result
        }
    } else {
        address_to_lookup.to_string()
    };
    let new_host = Host {
        domain: get_domain_from_r_dns(rdns.clone()),
        asn,
        country,
    };

    // collect the data exchanged from the same address so far and remove the address from the collection of addresses waiting a rDNS
    let mut resolutions_lock = resolutions_state.lock().unwrap();
    let other_data = resolutions_lock
        .addresses_waiting_resolution
        .remove(&address_to_lookup)
        .unwrap_or_default();
    // insert the newly resolved host in the collections, with the data it exchanged so far
    resolutions_lock
        .addresses_resolved
        .insert(address_to_lookup, new_host.clone());
    drop(resolutions_lock);

    let data_info_host = DataInfoHost {
        data_info: other_data,
        is_favorite: false, // Assuming this is a UI concept, set to default
        is_local,
        is_bogon,
        is_loopback,
        traffic_type,
    };

    let msg_data = HostMessage {
        host: new_host,
        data_info_host,
        address_to_lookup,
        rdns,
    };

    // add the new host to the list of hosts to be sent
    new_hosts_to_send.lock().unwrap().push(msg_data);

    // Emit an event to the frontend when a new host is resolved
    let _ = app_handle.emit_all(
        "new_host_resolved",
        NewHostMessage {
            cap_id: 0, // You might need to pass the cap_id to reverse_dns_lookup
            host_message: msg_data,
        },
    );
}

#[derive(Default)]
pub struct AddressesResolutionState {
    /// Map of the addresses waiting for a rDNS resolution; used to NOT send multiple rDNS for the same address
    addresses_waiting_resolution: HashMap<IpAddr, DataInfo>,
    /// Map of the resolved addresses with the corresponding host
    pub addresses_resolved: HashMap<IpAddr, Host>,
}

// Define messages to be sent to the frontend via Tauri events
#[derive(Clone, serde::Serialize)]
struct TrafficUpdateMessage {
    cap_id: usize,
    info_traffic: InfoTraffic,
    new_hosts: Vec<HostMessage>,
    is_final: bool,
}

#[derive(Clone, serde::Serialize)]
struct PendingHostsMessage {
    cap_id: usize,
    new_hosts: Vec<HostMessage>,
}

#[derive(Clone, serde::Serialize)]
struct OfflineGapMessage {
    cap_id: usize,
    duration: u32,
}

#[derive(Clone, serde::Serialize)]
struct NewHostMessage {
    cap_id: usize,
    host_message: HostMessage,
}


fn maybe_emit_traffic_update_live(
    app_handle: &AppHandle,
    cap_id: usize,
    info_traffic_msg: &mut InfoTraffic,
    new_hosts_to_send: &Arc<Mutex<Vec<HostMessage>>>,
    cs: &mut CaptureSource,
    first_packet_ticks: &mut Option<Instant>,
) {
    if first_packet_ticks.is_some_and(|i| i.elapsed() >= Duration::from_millis(1000)) {
        *first_packet_ticks =\
            first_packet_ticks.and_then(|i| i.checked_add(Duration::from_millis(1000)));
        let _ = app_handle.emit_all(
            "traffic_update",
            TrafficUpdateMessage {
                cap_id,
                info_traffic: info_traffic_msg.take_but_leave_something(), // Clone if necessary for the event payload
                new_hosts: new_hosts_to_send.lock().unwrap().drain(..).collect(),
                is_final: false,
            },
        );
        // This part updates device addresses, might need adaptation or separate handling in Tauri
        for dev in Device::list().unwrap_or_default() {
            if dev.name.eq(&cs.get_name()) {
                cs.set_addresses(dev.addresses);
                break;
            }
        }
    }
}

fn maybe_emit_traffic_update_offline(
    app_handle: &AppHandle,
    cap_id: usize,
    info_traffic_msg: &mut InfoTraffic,
    new_hosts_to_send: &Arc<Mutex<Vec<HostMessage>>>,
    next_packet_timestamp: Timestamp,
) {
    if info_traffic_msg.last_packet_timestamp == Timestamp::default() {
        info_traffic_msg.last_packet_timestamp = next_packet_timestamp;
    }
    if info_traffic_msg.last_packet_timestamp.secs() < next_packet_timestamp.secs() {
        let diff_secs =\
            next_packet_timestamp.secs() - info_traffic_msg.last_packet_timestamp.secs();
        let _ = app_handle.emit_all(
            "traffic_update",
            TrafficUpdateMessage {
                cap_id,
                info_traffic: info_traffic_msg.take_but_leave_something(), // Clone if necessary for the event payload
                new_hosts: new_hosts_to_send.lock().unwrap().drain(..).collect(),
                is_final: false,
            },
        );
        if diff_secs > 1 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let _ = app_handle.emit_all(
                "offline_gap",
                OfflineGapMessage {
                    cap_id,
                    duration: diff_secs as u32 - 1,
                },
            );
        }
    }
}