//! Module containing the definition of bogon addresses.

use crate::network_monitor::types::ip_collection::IpCollection;
use std::net::IpAddr;
use std::sync::LazyLock;

pub struct Bogon {
    pub range: IpCollection,
    pub description: &'static str,
}

// IPv4 bogons

static THIS_NETWORK: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("0.0.0.0-0.255.255.255").unwrap(),
    description: "\"this\" network",
});

static PRIVATE_USE: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new(
        "10.0.0.0-10.255.255.255, 172.16.0.0-172.31.255.255, 192.168.0.0-192.168.255.255",
    )
    .unwrap(),
    description: "private-use",
});

static CARRIER_GRADE: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("100.64.0.0-100.127.255.255").unwrap(),
    description: "carrier-grade NAT",
});

static LOOPBACK: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("127.0.0.0-127.255.255.255").unwrap(),
    description: "loopback",
});

static LINK_LOCAL: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("169.254.0.0-169.254.255.255").unwrap(),
    description: "link local",
});

static IETF_PROTOCOL: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("192.0.0.0-192.0.0.255").unwrap(),
    description: "IETF protocol assignments",
});

static TEST_NET_1: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("192.0.2.0-192.0.2.255").unwrap(),
    description: "TEST-NET-1",
});

static NETWORK_INTERCONNECT: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("198.18.0.0-198.19.255.255").unwrap(),
    description: "network interconnect device benchmark testing",
});

static TEST_NET_2: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("198.51.100.0-198.51.100.255").unwrap(),
    description: "TEST-NET-2",
});

static TEST_NET_3: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("203.0.113.0-203.0.113.255").unwrap(),
    description: "TEST-NET-3",
});

static MULTICAST: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("224.0.0.0-239.255.255.255").unwrap(),
    description: "multicast",
});

static FUTURE_USE: LazyLock<Bogon> = LazyLock::new(|| Bogon {
    range: IpCollection::new("240.0.0.0-255.255.255.255").unwrap(),
    description: "future use",
});

// IPv6 bogons

static NODE_SCOPE_UNSPECIFIED: LazyLock<Bogon> = LazyLock::new(|| Bog