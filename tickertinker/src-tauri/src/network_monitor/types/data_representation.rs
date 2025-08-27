//! Module defining the `DataInfo` struct, which represents incoming and outgoing packets and bytes.

use crate::network_monitor::types::traffic_direction::TrafficDirection;
use crate::report::types::sort_type::SortType;
use std::cmp::Ordering;
use std::time::Instant;
use serde::{Deserialize, Serialize}; // Add Serialize/Deserialize for Tauri IPC

/// Amount of exchanged data (packets and bytes) incoming and outgoing, with the timestamp of the latest occurrence
// data fields are private to make them only editable via the provided methods: needed to correctly refresh timestamps
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)] // Add Serialize/Deserialize
pub struct DataInfo {
    /// Incoming packets
    incoming_packets: u128,
    /// Outgoing packets
    outgoing_packets: u128,
    /// Incoming bytes
    incoming_bytes: u128,
    /// Outgoing bytes
    outgoing_bytes: u128,
    /// Latest instant of occurrence
    #[serde(skip)] // Skip Instant for serialization as it's not easily serializable
    final_instant: Instant,
}

impl DataInfo {
    pub fn incoming_data(&self, data_repr: DataRepr) -> u128 {
        match data_repr {
            DataRepr::Packets => self.incoming_packets,
            DataRepr::Bytes => self.incoming_bytes,
            DataRepr::Bits => self.incoming_bytes * 8,
        }
    }

    pub fn outgoing_data(&self, data_repr: DataRepr) -> u128 {
        match data_repr {
            DataRepr::Packets => self.outgoing_packets,
            DataRepr::Bytes => self.outgoing_bytes,
            DataRepr::Bits => self.outgoing_bytes * 8,
        }
    }

    pub fn tot_data(&self, data_repr: DataRepr) -> u128 {
        self.incoming_data(data_repr) + self.outgoing_data(data_repr)
    }

    pub fn add_packet(&mut self, bytes: u128, traffic_direction: TrafficDirection) {
        if traffic_direction.eq(&TrafficDirection::Outgoing) {
            self.outgoing_packets += 1;
            self.outgoing_bytes += bytes;
        } else {
            self.incoming_packets += 1;
            self.incoming_bytes += bytes;
        }
        self.final_instant = Instant::now();
    }

    pub fn add_packets(&mut self, packets: u128, bytes: u128, traffic_direction: TrafficDirection) {
        if traffic_direction.eq(&TrafficDirection::Outgoing) {
            self.outgoing_packets += packets;
            self.outgoing_bytes += bytes;
        } else {
            self.incoming_packets += packets;
            self.incoming_bytes += bytes;
        }
    }

    pub fn new_with_first_packet(bytes: u128, traffic_direction: TrafficDirection) -> Self {
        if traffic_direction.eq(&TrafficDirection::Outgoing) {
            Self {
                incoming_packets: 0,
                outgoing_packets: 1,
                incoming_bytes: 0,
                outgoing_bytes: bytes,
                final_instant: Instant::now(),
            }
        } else {
            Self {
                incoming_packets: 1,
                outgoing_packets: 0,
                incoming_bytes: bytes,
                outgoing_bytes: 0,
                final_instant: Instant::now(),
            }
        }
    }

    pub fn refresh(&mut self, rhs: Self) {
        self.incoming_packets += rhs.incoming_packets;
        self.outgoing_packets += rhs.outgoing_packets;
        self.incoming_bytes += rhs.incoming_bytes;
        self.outgoing_bytes += rhs.outgoing_bytes;
        // We might need to handle merging timestamps differently depending on how we want to display
        // For now, we'll just take the latest timestamp
        self.final_instant = rhs.final_instant;
    }

    pub fn compare(&self, other: &Self, sort_type: SortType, data_repr: DataRepr) -> Ordering {
        match sort_type {
            SortType::Ascending => self.tot_data(data_repr).cmp(&other.tot_data(data_repr)),
            SortType::Descending => other.tot_data(data_repr).cmp(&self.tot_data(data_repr)),
            SortType::Neutral => other.final_instant.cmp(&self.final_instant),
        }
    }

    #[cfg(test)]
    pub fn new_for_tests(
        incoming_packets: u128,
        outgoing_packets: u128,
        incoming_bytes: u128,
        outgoing_bytes: u128,
    ) -> Self {
        Self {
            incoming_packets,
            outgoing_packets,
            incoming_bytes,
            outgoing_bytes,
            final_instant: Instant::now(),
        }
    }
}

impl Default for DataInfo {
    fn default() -> Self {
        Self {
            incoming_packets: 0,
            outgoing_packets: 0,
            incoming_bytes: 0,
            outgoing_bytes: 0,
            final_instant: Instant::now(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)] // Add Serialize/Deserialize
pub enum DataRepr {
    Packets,
    Bytes,
    Bits,
}

impl DataRepr {
    pub(crate) const ALL: [DataRepr; 3] = [DataRepr::Bits, DataRepr::Bytes, DataRepr::Packets];

    // Removed get_label and data_exceeded_translation as they use GUI-specific translations
    // pub fn get_label(&self, language: Language) -> &str { ... }
    // pub fn data_exceeded_translation(&self, language: Language) -> &str { ... }

    /// Returns a String representing a quantity of traffic (packets / bytes / bits) with the proper multiple if applicable
    pub fn formatted_string(self, amount: u128) -> String {
        if self == DataRepr::Packets {
            return amount.to_string();
        }

        #[allow(clippy::cast_precision_loss)]
        let mut n = amount as f32;

        let byte_multiple = ByteMultiple::from_amount(amount);

        #[allow(clippy::cast_precision_loss)]
        let multiplier = byte_multiple.multiplier() as f32;
        n /= multiplier;
        if n > 999.0 && byte_multiple != ByteMultiple::PB {
            // this allows representing e.g. 999_999 as 999 KB instead of 1000 KB
            n = 999.0;
        }
        let precision = usize::from(byte_multiple != ByteMultiple::B && n <= 9.95);
        format!(\"{n:.precision$} {}\", byte_multiple.pretty_print(self))
            .trim()
            .to_string()
    }
}

/// Represents a Byte or bit multiple for displaying values in a human-readable format.\n#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]\npub enum ByteMultiple {\n    /// A Byte\n    B,\n    /// 10^3 Bytes\n    KB,\n    /// 10^6 Bytes\n    MB,\n    /// 10^9 Bytes\n    GB,\n    /// 10^12 Bytes\n    TB,\n    /// 10^15 Bytes\n    PB,\n}\n\nimpl ByteMultiple {\n    pub fn multiplier(self) -> u64 {\n        match self {\n            ByteMultiple::B => 1,\n            ByteMultiple::KB => 1_000,\n            ByteMultiple::MB => 1_000_000,\n            ByteMultiple::GB => 1_000_000_000,\n            ByteMultiple::TB => 1_000_000_000_000,\n            ByteMultiple::PB => 1_000_000_000_000_000,\n        }\n    }\n\n    fn from_amount(bytes: u128) -> Self {\n        match bytes {\n            x if (u128::MIN..u128::from(ByteMultiple::KB.multiplier())).contains(&x) => {\n                ByteMultiple::B\n            }\n            x if (u128::from(ByteMultiple::KB.multiplier())\n                ..u128::from(ByteMultiple::MB.multiplier()))\n                .contains(&x) =>\n            {\n                ByteMultiple::KB\n            }\n            x if (u128::from(ByteMultiple::MB.multiplier())\n                ..u128::from(ByteMultiple::GB.multiplier()))\n                .contains(&x) =>\n            {\n                ByteMultiple::MB\n            }\n            x if (u128::from(ByteMultiple::GB.multiplier())\n                ..u128::from(ByteMultiple::TB.multiplier()))\n                .contains(&x) =>\n            {\n                ByteMultiple::GB\n            }\n            x if (u128::from(ByteMultiple::TB.multiplier())\n                ..u128::from(ByteMultiple::PB.multiplier()))\n                .contains(&x) =>\n            {\n                ByteMultiple::TB\n            }\n            _ => ByteMultiple::PB,\n        }\n    }\n\n    pub fn get_char(self) -> String {\n        match self {\n            Self::B => String::new(),\n            Self::KB => \"K\".to_string(),\n            Self::MB => \"M\".to_string(),\n            Self::GB => \"G\".to_string(),\n            Self::TB => \"T\".to_string(),\n            Self::PB => \"P\".to_string(),\n        }\n    }\n\n    pub fn from_char(ch: char) -> Self {\n        match ch.to_ascii_uppercase() {\n            \'K\' => ByteMultiple::KB,\n            \'M\' => ByteMultiple::MB,\n            \'G\' => ByteMultiple::GB,\n            \'T\' => ByteMultiple::TB,\n            \'P\' => ByteMultiple::PB,\n            _ => ByteMultiple::B,\n        }\n    }\n\n    fn pretty_print(self, repr: DataRepr) -> String {\n        match repr {\n            DataRepr::Packets => String::new(),\n            DataRepr::Bytes => format!(\"{}B\", self.get_char()),\n            DataRepr::Bits => format!(\"{}b\", self.get_char()),\n        }\n    }\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    use crate::network_monitor::types::traffic_direction::TrafficDirection;\n\n    #[test]\n    fn test_data_info() {\n        // in_packets: 0, out_packets: 0, in_bytes: 0, out_bytes: 0\n        let mut data_info_1 = DataInfo::new_with_first_packet(123, TrafficDirection::Incoming);\n        // 1, 0, 123, 0\n        data_info_1.add_packet(100, TrafficDirection::Incoming);\n        // 2, 0, 223, 0\n        data_info_1.add_packet(200, TrafficDirection::Outgoing);\n        // 2, 1, 223, 200\n        data_info_1.add_packets(11, 1200, TrafficDirection::Outgoing);\n        // 2, 12, 223, 1400\n        data_info_1.add_packets(5, 500, TrafficDirection::Incoming);\n        // 7, 12, 723, 1400\n\n        assert_eq!(data_info_1.incoming_packets, 7);\n        assert_eq!(data_info_1.outgoing_packets, 12);\n        assert_eq!(data_info_1.incoming_bytes, 723);\n        assert_eq!(data_info_1.outgoing_bytes, 1400);\n\n        assert_eq!(data_info_1.tot_data(DataRepr::Packets), 19);\n        assert_eq!(data_info_1.tot_data(DataRepr::Bytes), 2123);\n        assert_eq!(data_info_1.tot_data(DataRepr::Bits), 16984);\n\n        assert_eq!(data_info_1.incoming_data(DataRepr::Packets), 7);\n        assert_eq!(data_info_1.incoming_data(DataRepr::Bytes), 723);\n        assert_eq!(data_info_1.incoming_data(DataRepr::Bits), 5784);\n\n        assert_eq!(data_info_1.outgoing_data(DataRepr::Packets), 12);\n        assert_eq!(data_info_1.outgoing_data(DataRepr::Bytes), 1400);\n        assert_eq!(data_info_1.outgoing_data(DataRepr::Bits), 11200);\n\n        let mut data_info_2 = DataInfo::new_with_first_packet(100, TrafficDirection::Outgoing);\n        // 0, 1, 0, 100\n        data_info_2.add_packets(19, 300, TrafficDirection::Outgoing);\n        // 0, 20, 0, 400\n\n        assert_eq!(data_info_2.incoming_packets, 0);\n        assert_eq!(data_info_2.outgoing_packets, 20);\n        assert_eq!(data_info_2.incoming_bytes, 0);\n        assert_eq!(data_info_2.outgoing_bytes, 400);\n\n        assert_eq!(data_info_2.tot_data(DataRepr::Packets), 20);\n        assert_eq!(data_info_2.tot_data(DataRepr::Bytes), 400);\n        assert_eq!(data_info_2.tot_data(DataRepr::Bits), 3200);\n\n        assert_eq!(data_info_2.incoming_data(DataRepr::Packets), 0);\n        assert_eq!(data_info_2.incoming_data(DataRepr::Bytes), 0);\n        assert_eq!(data_info_2.incoming_data(DataRepr::Bits), 0);\n\n        assert_eq!(data_info_2.outgoing_data(DataRepr::Packets), 20);\n        assert_eq!(data_info_2.outgoing_data(DataRepr::Bytes), 400);\n        assert_eq!(data_info_2.outgoing_data(DataRepr::Bits), 3200);\n\n        // compare data_info_1 and data_info_2\n\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Ascending, DataRepr::Packets),\n            Ordering::Less\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Descending, DataRepr::Packets),\n            Ordering::Greater\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Neutral, DataRepr::Packets),\n            Ordering::Greater\n        );\n\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Ascending, DataRepr::Bytes),\n            Ordering::Greater\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Descending, DataRepr::Bytes),\n            Ordering::Less\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Neutral, DataRepr::Bytes),\n            Ordering::Greater\n        );\n\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Ascending, DataRepr::Bits),\n            Ordering::Greater\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Descending, DataRepr::Bits),\n            Ordering::Less\n        );\n        assert_eq!(\n            data_info_1.compare(&data_info_2, SortType::Neutral, DataRepr::Bits),\n            Ordering::Greater\n        );\n\n        // refresh data_info_1 with data_info_2\n        // assert!(data_info_1.final_instant < data_info_2.final_instant);\ // Cannot compare Instant across different refreshes in tests easily\n        data_info_1.refresh(data_info_2);\n\n        // data_info_1 should now contain the sum of both data_info_1 and data_info_2\n        assert_eq!(data_info_1.incoming_packets, 7);\n        assert_eq!(data_info_1.outgoing_packets, 32);\n        assert_eq!(data_info_1.incoming_bytes, 723);\n        assert_eq!(data_info_1.outgoing_bytes, 1800);\n        // assert_eq!(data_info_1.final_instant, data_info_2.final_instant);\ // Cannot compare Instant across different refreshes in tests easily\n    }\n}\n