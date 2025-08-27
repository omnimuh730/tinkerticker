use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::fmt::Write;

use etherparse::{EtherType, LaxPacketHeaders, LinkHeader, NetHeaders, TransportHeader};
use pcap::Address;

use crate::network_monitor::types::address_port_pair::AddressPortPair;
use crate::network_monitor::types::arp_type::ArpType;
use crate::network_monitor::types::bogon::is_bogon;
use crate::network_monitor::types::capture_context::CaptureSource;
use crate::network_monitor::types::icmp_type::{IcmpType, IcmpTypeV4, IcmpTypeV6};
use crate::network_monitor::types::info_address_port_pair::InfoAddressPortPair;
use crate::network_monitor::types::info_traffic::InfoTraffic;
use crate::network_monitor::types::packet_filters_fields::PacketFiltersFields;
use crate::network_monitor::types::service::Service;
use crate::network_monitor::types::service_query::ServiceQuery;
use crate::network_monitor::types::traffic_direction::TrafficDirection;
use crate::network_monitor::types::traffic_type::TrafficType;
use crate::network_monitor::types::ip_version::IpVersion;
use crate::network_monitor::types::protocol::Protocol;

// This include needs to be handled by the build script to generate the services.rs file
// include!(concat!(env!("OUT_DIR"), "/services.rs"));

// Placeholder for SERVICES, replace with generated code from build.rs
static SERVICES: phf::Map<ServiceQuery, Service> = phf::phf_map! {};


/// Calls methods to analyze link, network, and transport headers.
/// Returns the relevant collected information.
pub fn analyze_headers(
    headers: LaxPacketHeaders,
    mac_addresses: &mut (Option<String>, Option<String>),
    exchanged_bytes: &mut u128,
    icmp_type: &mut IcmpType,
    arp_type: &mut ArpType,
    packet_filters_fields: &mut PacketFiltersFields,
) -> Option<AddressPortPair> {
    analyze_link_header(
        headers.link,
        &mut mac_addresses.0,
        &mut mac_addresses.1,
        exchanged_bytes,
    );

    let is_arp = matches!(&headers.net, Some(NetHeaders::Arp(_)));

    if !analyze_network_header(
        headers.net,
        exchanged_bytes,
        &mut packet_filters_fields.ip_version,
        &mut packet_filters_fields.source,
        &mut packet_filters_fields.dest,
        arp_type,
    ) {
        return None;
    }

    if !is_arp
        && !analyze_transport_header(
            headers.transport,
            &mut packet_filters_fields.sport,
            &mut packet_filters_fields.dport,
            &mut packet_filters_fields.protocol,
            icmp_type,
        )
    {
        return None;
    }

    Some(AddressPortPair::new(
        packet_filters_fields.source,
        packet_filters_fields.sport,
        packet_filters_fields.dest,
        packet_filters_fields.dport,
        packet_filters_fields.protocol,
    ))
}

/// This function analyzes the data link layer header passed as parameter and updates variables
/// passed by reference on the basis of the packet header content.
/// Returns false if packet has to be skipped.
fn analyze_link_header(
    link_header: Option<LinkHeader>,
    mac_address1: &mut Option<String>,
    mac_address2: &mut Option<String>,
    exchanged_bytes: &mut u128,
) {
    if let Some(LinkHeader::Ethernet2(header)) = link_header {
        *exchanged_bytes += 14;
        *mac_address1 = Some(mac_from_dec_to_hex(header.source));
        *mac_address2 = Some(mac_from_dec_to_hex(header.destination));
    } else {
        *mac_address1 = None;
        *mac_address2 = None;
    }
}

/// This function analyzes the network layer header passed as parameter and updates variables
/// passed by reference on the basis of the packet header content.
/// Returns false if packet has to be skipped.
fn analyze_network_header(
    network_header: Option<NetHeaders>,
    exchanged_bytes: &mut u128,
    network_protocol: &mut IpVersion,
    address1: &mut IpAddr,
    address2: &mut IpAddr,
    arp_type: &mut ArpType,
) -> bool {
    match network_header {
        Some(NetHeaders::Ipv4(ipv4header, _)) => {
            *network_protocol = IpVersion::IPv4;
            *address1 = IpAddr::from(ipv4header.source);
            *address2 = IpAddr::from(ipv4header.destination);
            *exchanged_bytes += u128::from(ipv4header.total_len);
            true
        }
        Some(NetHeaders::Ipv6(ipv6header, _)) => {
            *network_protocol = IpVersion::IPv6;
            *address1 = IpAddr::from(ipv6header.source);
            *address2 = IpAddr::from(ipv6header.destination);
            *exchanged_bytes += u128::from(40 + ipv6header.payload_length);
            true
        }
        Some(NetHeaders::Arp(arp_packet)) => {
            match arp_packet.proto_addr_type {
                EtherType::IPV4 => {
                    *network_protocol = IpVersion::IPv4;
                    *address1 =
                        match TryInto::<[u8; 4]>::try_into(arp_packet.sender_protocol_addr()) {
                            Ok(source) => IpAddr::from(source),
                            Err(_) => return false,
                        };
                    *address2 =
                        match TryInto::<[u8; 4]>::try_into(arp_packet.target_protocol_addr()) {
                            Ok(destination) => IpAddr::from(destination),
                            Err(_) => return false,
                        };
                }
                EtherType::IPV6 => {
                    *network_protocol = IpVersion::IPv6;
                    *address1 =
                        match TryInto::<[u8; 16]>::try_into(arp_packet.sender_protocol_addr()) {
                            Ok(source) => IpAddr::from(source),
                            Err(_) => return false,
                        };
                    *address2 =
                        match TryInto::<[u8; 16]>::try_into(arp_packet.target_protocol_addr()) {
                            Ok(destination) => IpAddr::from(destination),
                            Err(_) => return false,
                        };
                }
                _ => return false,
            }
            *exchanged_bytes += arp_packet.packet_len() as u128;
            *arp_type = ArpType::from_etherparse(arp_packet.operation);
            true
        }
        _ => false,
    }
}

/// This function analyzes the transport layer header passed as parameter and updates variables
/// passed by reference on the basis of the packet header content.
/// Returns false if packet has to be skipped.
fn analyze_transport_header(
    transport_header: Option<TransportHeader>,
    port1: &mut Option<u16>,
    port2: &mut Option<u16>,
    protocol: &mut Protocol,
    icmp_type: &mut IcmpType,
) -> bool {
    match transport_header {
        Some(TransportHeader::Udp(udp_header)) => {
            *port1 = Some(udp_header.source_port);
            *port2 = Some(udp_header.destination_port);
            *protocol = Protocol::UDP;
            true
        }
        Some(TransportHeader::Tcp(tcp_header)) => {
            *port1 = Some(tcp_header.source_port);
            *port2 = Some(tcp_header.destination_port);
            *protocol = Protocol::TCP;
            true
        }
        Some(TransportHeader::Icmpv4(icmpv4_header)) => {
            *port1 = None;
            *port2 = None;
            *protocol = Protocol::ICMP;
            *icmp_type = IcmpTypeV4::from_etherparse(&icmpv4_header.icmp_type);
            true
        }
        Some(TransportHeader::Icmpv6(icmpv6_header)) => {
            *port1 = None;
            *port2 = None;
            *protocol = Protocol::ICMP;
            *icmp_type = IcmpTypeV6::from_etherparse(&icmpv6_header.icmp_type);
            true
        }
        _ => false,
    }
}

pub fn get_service(
    key: &AddressPortPair,
    traffic_direction: TrafficDirection,
    my_interface_addresses: &[Address],
) -> Service {
    if key.protocol == Protocol::ICMP || key.protocol == Protocol::ARP {
        return Service::NotApplicable;
    }

    let Some(port1) = key.port1 else {
        return Service::NotApplicable;
    };
    let Some(port2) = key.port2 else {
        return Service::NotApplicable;
    };

    // to return the service associated with the highest score:
    // score = service_is_some * (port_is_well_known + bonus_direction)
    // service_is_some: 1 if some, 0 if unknown
    // port_is_well_known: 3 if well known, 1 if not
    // bonus_direction: +1 assigned to remote port, or to destination port in case of multicast
    let compute_service_score = |service: &Service, port: u16, bonus_direction: bool| {
        let service_is_some = u8::from(matches!(service, Service::Name(_)));
        let port_is_well_known = if port < 1024 { 3 } else { 1 };
        let bonus_direction = u8::from(bonus_direction);
        service_is_some * (port_is_well_known + bonus_direction)
    };

    let unknown = Service::Unknown;
    let service1 = SERVICES
        .get(&ServiceQuery(port1, key.protocol))
        .unwrap_or(&unknown);
    let service2 = SERVICES
        .get(&ServiceQuery(port2, key.protocol))
        .unwrap_or(&unknown);

    let dest_ip = key.address2;
    let bonus_dest = traffic_direction.eq(&TrafficDirection::Outgoing)
        || dest_ip.is_multicast()
        || is_broadcast_address(&dest_ip, my_interface_addresses);

    let score1 = compute_service_score(service1, port1, !bonus_dest);
    let score2 = compute_service_score(service2, port2, bonus_dest);

    if score1 > score2 {
        *service1
    } else {
        *service2
    }
}

/// Function to insert the source and destination of a packet into the map containing the analyzed traffic
pub fn modify_or_insert_in_map(
    info_traffic_msg: &mut InfoTraffic,
    key: &AddressPortPair,
    cs: &CaptureSource,
    mac_addresses: (Option<String>, Option<String>),
    icmp_type: IcmpType,
    arp_type: ArpType,
    exchanged_bytes: u128,
) -> (TrafficDirection, Service) {
    let mut traffic_direction = TrafficDirection::default();
    let mut service = Service::Unknown;

    if !info_traffic_msg.map.contains_key(key) {
        // first occurrence of key (in this time interval)

        let my_interface_addresses = cs.get_addresses();
        // determine traffic direction
        let source_ip = &key.address1;
        let destination_ip = &key.address2;
        traffic_direction = get_traffic_direction(
            source_ip,
            destination_ip,
            key.port1,
            key.port2,
            my_interface_addresses,
        );
        // determine upper layer service
        service = get_service(key, traffic_direction, my_interface_addresses);
    }

    let timestamp = info_traffic_msg.last_packet_timestamp;
    let new_info = info_traffic_msg
        .map
        .entry(*key)
        .and_modify(|info| {
            info.transmitted_bytes += exchanged_bytes;
            info.transmitted_packets += 1;
            info.final_timestamp = timestamp;
            if key.protocol.eq(&Protocol::ICMP) {
                info.icmp_types
                    .entry(icmp_type)
                    .and_modify(|n| *n += 1)
                    .or_insert(1);
            }
            if key.protocol.eq(&Protocol::ARP) {
                info.arp_types
                    .entry(arp_type)
                    .and_modify(|n| *n += 1)
                    .or_insert(1);
            }
        })
        .or_insert_with(|| InfoAddressPortPair {
            mac_address1: mac_addresses.0,
            mac_address2: mac_addresses.1,
            transmitted_bytes: exchanged_bytes,
            transmitted_packets: 1,
            initial_timestamp: timestamp,
            final_timestamp: timestamp,
            service,
            traffic_direction,
            icmp_types: if key.protocol.eq(&Protocol::ICMP) {
                HashMap::from([(icmp_type, 1)])
            } else {
                HashMap::new()
            },
            arp_types: if key.protocol.eq(&Protocol::ARP) {
                HashMap::from([(arp_type, 1)])
            } else {
                HashMap::new()
            },
        });

    (new_info.traffic_direction, new_info.service)
}

/// Returns the traffic direction observed (incoming or outgoing)
fn get_traffic_direction(
    source_ip: &IpAddr,
    destination_ip: &IpAddr,
    source_port: Option<u16>,
    dest_port: Option<u16>,
    my_interface_addresses: &[Address],
) -> TrafficDirection {
    let my_interface_addresses_ip: Vec<IpAddr> = my_interface_addresses
        .iter()
        .map(|address| address.addr)
        .collect();

    // first let's handle TCP and UDP loopback
    if source_ip.is_loopback()
        && destination_ip.is_loopback()
        && let (Some(sport), Some(dport)) = (source_port, dest_port)
    {
        return if sport > dport {
            TrafficDirection::Outgoing
        } else {
            TrafficDirection::Incoming
        };
    }

    // if interface_addresses is empty, check if the IP is a bogon (useful when importing pcap files)
    let is_local = |interface_addresses: &Vec<IpAddr>, ip: &IpAddr| -> bool {
        if interface_addresses.is_empty() {
            is_bogon(ip).is_some()
        } else {
            interface_addresses.contains(ip)
        }
    };

    if is_local(&my_interface_addresses_ip, source_ip) {
        // source is local
        TrafficDirection::Outgoing
    } else if source_ip.ne(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        && source_ip.ne(&IpAddr::V6(Ipv6Addr::UNSPECIFIED))
    {
        // source not local and different from 0.0.0.0 and different from ::
        TrafficDirection::Incoming
    } else if !is_local(&my_interface_addresses_ip, destination_ip) {
        // source is 0.0.0.0 or :: (local not yet assigned an IP) and destination is not local
        TrafficDirection::Outgoing
    } else {
        TrafficDirection::Incoming
    }
}

/// Returns the traffic type observed (unicast, multicast or broadcast)
/// It refers to the remote host
pub fn get_traffic_type(
    destination_ip: &IpAddr,
    my_interface_addresses: &[Address],
    traffic_direction: TrafficDirection,
) -> TrafficType {
    if traffic_direction.eq(&TrafficDirection::Outgoing) {
        if destination_ip.is_multicast() {
            TrafficType::Multicast
        } else if is_broadcast_address(destination_ip, my_interface_addresses) {
            TrafficType::Broadcast
        } else {
            TrafficType::Unicast
        }
    } else {
        TrafficType::Unicast
    }
}

/// Determines if the input address is a broadcast address or not.
///
/// # Arguments
///
/// * `address` - string representing an IPv4 or IPv6 network address.
fn is_broadcast_address(address: &IpAddr, my_interface_addresses: &[Address]) -> bool {
    if address.eq(&IpAddr::from([255, 255, 255, 255])) {
        return true;
    }
    // check if directed broadcast
    let my_broadcast_addresses: Vec<IpAddr> = my_interface_addresses
        .iter()
        .map(|address| {
            address
                .broadcast_addr
                .unwrap_or_else(|| IpAddr::from([255, 255, 255, 255]))
        })
        .collect();
    if my_broadcast_addresses.contains(address) {
        return true;
    }
    false
}

/// Determines if the connection is local
pub fn is_local_connection(
    address_to_lookup: &IpAddr,
    my_interface_addresses: &Vec<Address>,\
) -> bool {
    let mut ret_val = false;

    for address in my_interface_addresses {
        match address.addr {
            IpAddr::V4(local_addr) => {
                if let IpAddr::V4(address_to_lookup_v4) = address_to_lookup {
                    // remote is link local?
                    if address_to_lookup_v4.is_link_local() {
                        ret_val = true;
                    }
                    // is the same subnet?
                    else if let Some(IpAddr::V4(netmask)) = address.netmask {
                        let mut local_subnet = Vec::new();
                        let mut remote_subnet = Vec::new();
                        let netmask_digits = netmask.octets();
                        let local_addr_digits = local_addr.octets();
                        let remote_addr_digits = address_to_lookup_v4.octets();
                        for (i, netmask_digit) in netmask_digits.iter().enumerate() {
                            local_subnet.push(netmask_digit & local_addr_digits[i]);
                            remote_subnet.push(netmask_digit & remote_addr_digits[i]);
                        }
                        if local_subnet == remote_subnet {
                            ret_val = true;
                        }
                    }
                }
            }
            IpAddr::V6(local_addr) => {
                if let IpAddr::V6(address_to_lookup_v6) = address_to_lookup {
                    // remote is link local?
                    if address_to_lookup_v6.is_unicast_link_local() {
                        ret_val = true;
                    }
                    // is the same subnet?
                    else if let Some(IpAddr::V6(netmask)) = address.netmask {
                        let mut local_subnet = Vec::new();
                        let mut remote_subnet = Vec::new();
                        let netmask_digits = netmask.octets();
                        let local_addr_digits = local_addr.octets();
                        let remote_addr_digits = address_to_lookup_v6.octets();
                        for (i, netmask_digit) in netmask_digits.iter().enumerate() {
                            local_subnet.push(netmask_digit & local_addr_digits[i]);
                            remote_subnet.push(netmask_digit & remote_addr_digits[i]);
                        }
                        if local_subnet == remote_subnet {
                            ret_val = true;
                        }
                    }
                }
            }
        }
    }

    ret_val
}

/// Determines if the address passed as parameter belong to the chosen adapter
pub fn is_my_address(local_address: &IpAddr, my_interface_addresses: &Vec<Address>) -> bool {
    for address in my_interface_addresses {
        if address.addr.eq(local_address) {
            return true;
        }
    }
    local_address.is_loopback()
}

/// Converts a MAC address in its hexadecimal form
fn mac_from_dec_to_hex(mac_dec: [u8; 6]) -> String {
    let mut mac_hex = String::new();
    for n in &mac_dec {
        let _ = write!(mac_hex, "{n:02x}:");
    }
    mac_hex.pop();
    mac_hex
}

pub fn get_address_to_lookup(key: &AddressPortPair, traffic_direction: TrafficDirection) -> IpAddr {
    match traffic_direction {
        TrafficDirection::Outgoing => key.address2,
        TrafficDirection::Incoming => key.address1,
    }
}

// Tests are omitted as they are not part of the core logic to be copied for integration.
