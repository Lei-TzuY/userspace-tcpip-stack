//! IGMPv3 & Source-Specific Multicast (SSM) Protocol Engine (RFC 3376 / RFC 4607).
//!
//! Provides IGMPv3 Query & Report packet encoding/decoding, Group Record serialization,
//! Host Filter-Mode state machines (INCLUDE/EXCLUDE), and SSM Channel (S,G) subscriptions.

use crate::checksum::compute_checksum;
use crate::igmp::IgmpError;
use crate::ipv4::Ipv4Address;
use std::collections::{HashMap, HashSet};

pub const IGMPV3_TYPE_MEMBERSHIP_QUERY: u8 = 0x11;
pub const IGMPV3_TYPE_MEMBERSHIP_REPORT: u8 = 0x22;

pub const IGMPV3_ALL_ROUTERS_MCAST: Ipv4Address = Ipv4Address([224, 0, 0, 22]);

// IGMPv3 Group Record Types (RFC 3376 Section 4.2.12)
pub const IGMPV3_MODE_IS_INCLUDE: u8 = 1;
pub const IGMPV3_MODE_IS_EXCLUDE: u8 = 2;
pub const IGMPV3_CHANGE_TO_INCLUDE: u8 = 3;
pub const IGMPV3_CHANGE_TO_EXCLUDE: u8 = 4;
pub const IGMPV3_ALLOW_NEW_SOURCES: u8 = 5;
pub const IGMPV3_BLOCK_OLD_SOURCES: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    Include,
    Exclude,
}

/// IGMPv3 Group Record in Membership Report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igmpv3GroupRecord {
    pub record_type: u8,
    pub multicast_address: Ipv4Address,
    pub source_addresses: Vec<Ipv4Address>,
    pub auxiliary_data: Vec<u8>,
}

impl Igmpv3GroupRecord {
    pub fn new(record_type: u8, group: Ipv4Address, sources: Vec<Ipv4Address>) -> Self {
        Igmpv3GroupRecord {
            record_type,
            multicast_address: group,
            source_addresses: sources,
            auxiliary_data: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let aux_words = (self.auxiliary_data.len() + 3) / 4;
        let mut buf = Vec::with_capacity(8 + self.source_addresses.len() * 4 + aux_words * 4);
        buf.push(self.record_type);
        buf.push(aux_words as u8);
        buf.extend_from_slice(&(self.source_addresses.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.multicast_address.0);
        for src in &self.source_addresses {
            buf.extend_from_slice(&src.0);
        }
        buf.extend_from_slice(&self.auxiliary_data);
        let pad = (4 - (self.auxiliary_data.len() % 4)) % 4;
        buf.extend(std::iter::repeat(0u8).take(pad));
        buf
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), IgmpError> {
        if data.len() < 8 {
            return Err(IgmpError::PacketTooShort(data.len()));
        }
        let record_type = data[0];
        let aux_data_len = data[1] as usize * 4; // in 32-bit words
        let num_sources = u16::from_be_bytes([data[2], data[3]]) as usize;
        let multicast_address = Ipv4Address([data[4], data[5], data[6], data[7]]);

        let total_header_and_sources = 8 + num_sources * 4;
        let total_record_len = total_header_and_sources + aux_data_len;
        if data.len() < total_record_len {
            return Err(IgmpError::PacketTooShort(data.len()));
        }

        let mut source_addresses = Vec::with_capacity(num_sources);
        for i in 0..num_sources {
            let off = 8 + i * 4;
            source_addresses.push(Ipv4Address([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }

        let auxiliary_data =
            data[total_header_and_sources..total_header_and_sources + aux_data_len].to_vec();

        Ok((
            Igmpv3GroupRecord {
                record_type,
                multicast_address,
                source_addresses,
                auxiliary_data,
            },
            total_record_len,
        ))
    }
}

/// IGMPv3 Membership Report (RFC 3376 Section 4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igmpv3Report {
    pub group_records: Vec<Igmpv3GroupRecord>,
}

impl Igmpv3Report {
    pub fn new(records: Vec<Igmpv3GroupRecord>) -> Self {
        Igmpv3Report {
            group_records: records,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        buf[0] = IGMPV3_TYPE_MEMBERSHIP_REPORT;
        buf[1] = 0; // Reserved
        buf[2] = 0; // Checksum placeholder
        buf[3] = 0;
        buf[4] = 0; // Reserved
        buf[5] = 0;
        buf[6..8].copy_from_slice(&(self.group_records.len() as u16).to_be_bytes());

        for rec in &self.group_records {
            buf.extend_from_slice(&rec.serialize());
        }

        let csum = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8], verify_checksum: bool) -> Result<Self, IgmpError> {
        if data.len() < 8 {
            return Err(IgmpError::PacketTooShort(data.len()));
        }
        if data[0] != IGMPV3_TYPE_MEMBERSHIP_REPORT {
            return Err(IgmpError::PacketTooShort(data.len()));
        }
        if verify_checksum {
            let expected = compute_checksum(data);
            if expected != 0 {
                let current_csum = u16::from_be_bytes([data[2], data[3]]);
                return Err(IgmpError::InvalidChecksum {
                    computed: 0,
                    expected: current_csum,
                });
            }
        }

        let num_records = u16::from_be_bytes([data[6], data[7]]) as usize;
        let mut cursor = 8;
        let mut group_records = Vec::with_capacity(num_records);

        for _ in 0..num_records {
            if cursor >= data.len() {
                return Err(IgmpError::PacketTooShort(data.len()));
            }
            let (rec, consumed) = Igmpv3GroupRecord::parse(&data[cursor..])?;
            group_records.push(rec);
            cursor += consumed;
        }

        Ok(Igmpv3Report { group_records })
    }
}

/// IGMPv3 Membership Query (RFC 3376 Section 4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Igmpv3Query {
    pub max_resp_code: u8,
    pub group_address: Ipv4Address,
    pub s_flag: bool,
    pub qrv: u8,
    pub qqic: u8,
    pub source_addresses: Vec<Ipv4Address>,
}

impl Igmpv3Query {
    pub fn build_general_query(max_resp_code: u8, qrv: u8, qqic: u8) -> Self {
        Igmpv3Query {
            max_resp_code,
            group_address: Ipv4Address::UNSPECIFIED,
            s_flag: false,
            qrv,
            qqic,
            source_addresses: Vec::new(),
        }
    }

    pub fn build_group_specific(group: Ipv4Address, max_resp_code: u8) -> Self {
        Igmpv3Query {
            max_resp_code,
            group_address: group,
            s_flag: false,
            qrv: 2,
            qqic: 20,
            source_addresses: Vec::new(),
        }
    }

    pub fn build_group_and_source_specific(
        group: Ipv4Address,
        sources: Vec<Ipv4Address>,
        max_resp_code: u8,
    ) -> Self {
        Igmpv3Query {
            max_resp_code,
            group_address: group,
            s_flag: false,
            qrv: 2,
            qqic: 20,
            source_addresses: sources,
        }
    }

    pub fn is_general_query(&self) -> bool {
        self.group_address == Ipv4Address::UNSPECIFIED && self.source_addresses.is_empty()
    }

    pub fn is_group_specific(&self) -> bool {
        self.group_address != Ipv4Address::UNSPECIFIED && self.source_addresses.is_empty()
    }

    pub fn is_group_and_source_specific(&self) -> bool {
        self.group_address != Ipv4Address::UNSPECIFIED && !self.source_addresses.is_empty()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let total_len = 12 + self.source_addresses.len() * 4;
        let mut buf = vec![0u8; total_len];
        buf[0] = IGMPV3_TYPE_MEMBERSHIP_QUERY;
        buf[1] = self.max_resp_code;
        buf[2] = 0; // Checksum
        buf[3] = 0;
        buf[4..8].copy_from_slice(&self.group_address.0);

        let mut flags_qrv = self.qrv & 0x07;
        if self.s_flag {
            flags_qrv |= 0x08;
        }
        buf[8] = flags_qrv;
        buf[9] = self.qqic;
        buf[10..12].copy_from_slice(&(self.source_addresses.len() as u16).to_be_bytes());

        for (i, src) in self.source_addresses.iter().enumerate() {
            let off = 12 + i * 4;
            buf[off..off + 4].copy_from_slice(&src.0);
        }

        let csum = compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8], verify_checksum: bool) -> Result<Self, IgmpError> {
        if data.len() < 12 {
            return Err(IgmpError::PacketTooShort(data.len()));
        }
        if data[0] != IGMPV3_TYPE_MEMBERSHIP_QUERY {
            return Err(IgmpError::PacketTooShort(data.len()));
        }
        if verify_checksum {
            let expected = compute_checksum(data);
            if expected != 0 {
                let current_csum = u16::from_be_bytes([data[2], data[3]]);
                return Err(IgmpError::InvalidChecksum {
                    computed: 0,
                    expected: current_csum,
                });
            }
        }

        let max_resp_code = data[1];
        let group_address = Ipv4Address([data[4], data[5], data[6], data[7]]);
        let flags_qrv = data[8];
        let s_flag = (flags_qrv & 0x08) != 0;
        let qrv = flags_qrv & 0x07;
        let qqic = data[9];
        let num_sources = u16::from_be_bytes([data[10], data[11]]) as usize;

        if data.len() < 12 + num_sources * 4 {
            return Err(IgmpError::PacketTooShort(data.len()));
        }

        let mut source_addresses = Vec::with_capacity(num_sources);
        for i in 0..num_sources {
            let off = 12 + i * 4;
            source_addresses.push(Ipv4Address([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]));
        }

        Ok(Igmpv3Query {
            max_resp_code,
            group_address,
            s_flag,
            qrv,
            qqic,
            source_addresses,
        })
    }
}

/// Host-side SSM Channel and Group Subscription Manager.
#[derive(Debug, Clone, Default)]
pub struct Igmpv3HostState {
    pub subscriptions: HashMap<Ipv4Address, (FilterMode, HashSet<Ipv4Address>)>,
}

impl Igmpv3HostState {
    pub fn new() -> Self {
        Igmpv3HostState {
            subscriptions: HashMap::new(),
        }
    }

    /// Subscribes host to (S, G) in INCLUDE mode.
    pub fn join_ssm_channel(&mut self, source: Ipv4Address, group: Ipv4Address) -> Igmpv3Report {
        let entry = self
            .subscriptions
            .entry(group)
            .or_insert_with(|| (FilterMode::Include, HashSet::new()));
        entry.1.insert(source);

        let rec = Igmpv3GroupRecord::new(IGMPV3_ALLOW_NEW_SOURCES, group, vec![source]);
        Igmpv3Report::new(vec![rec])
    }

    /// Leaves an SSM channel (S, G).
    pub fn leave_ssm_channel(&mut self, source: Ipv4Address, group: Ipv4Address) -> Igmpv3Report {
        if let Some(entry) = self.subscriptions.get_mut(&group) {
            entry.1.remove(&source);
        }
        let rec = Igmpv3GroupRecord::new(IGMPV3_BLOCK_OLD_SOURCES, group, vec![source]);
        Igmpv3Report::new(vec![rec])
    }

    /// Checks if local host wants packet matching (source, group).
    pub fn should_receive(&self, source: Ipv4Address, group: Ipv4Address) -> bool {
        if let Some((mode, sources)) = self.subscriptions.get(&group) {
            match mode {
                FilterMode::Include => sources.contains(&source),
                FilterMode::Exclude => !sources.contains(&source),
            }
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_igmpv3_report_and_record_roundtrip() {
        let group = Ipv4Address([232, 1, 1, 1]);
        let src1 = Ipv4Address([192, 0, 2, 10]);
        let src2 = Ipv4Address([192, 0, 2, 20]);
        let rec = Igmpv3GroupRecord::new(IGMPV3_MODE_IS_INCLUDE, group, vec![src1, src2]);
        let report = Igmpv3Report::new(vec![rec]);

        let raw = report.serialize();
        let parsed = Igmpv3Report::parse(&raw, true).unwrap();
        assert_eq!(parsed.group_records.len(), 1);
        assert_eq!(parsed.group_records[0].record_type, IGMPV3_MODE_IS_INCLUDE);
        assert_eq!(parsed.group_records[0].multicast_address, group);
        assert_eq!(parsed.group_records[0].source_addresses.len(), 2);
    }

    #[test]
    fn test_igmpv3_query_types_and_codec() {
        let group = Ipv4Address([232, 5, 5, 5]);
        let src = Ipv4Address([198, 51, 100, 1]);
        let query = Igmpv3Query::build_group_and_source_specific(group, vec![src], 100);
        assert!(query.is_group_and_source_specific());
        assert!(!query.is_general_query());

        let raw = query.serialize();
        let parsed = Igmpv3Query::parse(&raw, true).unwrap();
        assert_eq!(parsed.group_address, group);
        assert_eq!(parsed.source_addresses, vec![src]);
        assert_eq!(parsed.max_resp_code, 100);
    }

    #[test]
    fn test_igmpv3_host_ssm_subscription() {
        let mut host = Igmpv3HostState::new();
        let group = Ipv4Address([232, 10, 10, 10]);
        let authorized_src = Ipv4Address([10, 0, 0, 1]);
        let unauthorized_src = Ipv4Address([10, 0, 0, 2]);

        let join_report = host.join_ssm_channel(authorized_src, group);
        assert_eq!(
            join_report.group_records[0].record_type,
            IGMPV3_ALLOW_NEW_SOURCES
        );

        assert!(host.should_receive(authorized_src, group));
        assert!(!host.should_receive(unauthorized_src, group));

        let leave_report = host.leave_ssm_channel(authorized_src, group);
        assert_eq!(
            leave_report.group_records[0].record_type,
            IGMPV3_BLOCK_OLD_SOURCES
        );
        assert!(!host.should_receive(authorized_src, group));
    }
}
