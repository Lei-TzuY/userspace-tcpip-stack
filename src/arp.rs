//! Layer 2.5: Address Resolution Protocol (ARP - RFC 826).
//!
//! ARP maps 32-bit IPv4 addresses to 48-bit Ethernet MAC addresses. The cache
//! also models the operational parts that matter to a real stack: dynamic-entry
//! ageing, permanent/static entries, RFC 5227 probes and gratuitous ARP, and a
//! learning result that exposes address conflicts instead of silently hiding them.

use crate::ethernet::MacAddress;
use std::collections::HashMap;
use std::fmt;

pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
pub const ARP_HLEN_ETHERNET: u8 = 6;
pub const ARP_PLEN_IPV4: u8 = 4;

pub const ARP_OP_REQUEST: u16 = 1;
pub const ARP_OP_REPLY: u16 = 2;

pub const ARP_PACKET_LEN: usize = 28;
/// Default lifetime for an explicitly timed dynamic cache entry.
pub const ARP_DEFAULT_DYNAMIC_TTL_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    Request,
    Reply,
    Unknown(u16),
}

impl ArpOpcode {
    pub fn from_u16(val: u16) -> Self {
        match val {
            ARP_OP_REQUEST => ArpOpcode::Request,
            ARP_OP_REPLY => ArpOpcode::Reply,
            other => ArpOpcode::Unknown(other),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            ArpOpcode::Request => ARP_OP_REQUEST,
            ArpOpcode::Reply => ARP_OP_REPLY,
            ArpOpcode::Unknown(val) => *val,
        }
    }
}

impl fmt::Display for ArpOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOpcode::Request => write!(f, "Request (1)"),
            ArpOpcode::Reply => write!(f, "Reply (2)"),
            ArpOpcode::Unknown(val) => write!(f, "Unknown ({})", val),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: ArpOpcode,
    pub sender_mac: MacAddress,
    pub sender_ip: [u8; 4],
    pub target_mac: MacAddress,
    pub target_ip: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpError {
    PacketTooShort(usize),
    InvalidHardwareType(u16),
    InvalidProtocolType(u16),
    InvalidAddressLengths(u8, u8),
}

impl fmt::Display for ArpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpError::PacketTooShort(len) => {
                write!(f, "ARP packet too short ({} bytes, min 28)", len)
            }
            ArpError::InvalidHardwareType(h) => write!(f, "Unsupported hardware type: {}", h),
            ArpError::InvalidProtocolType(p) => write!(f, "Unsupported protocol type: 0x{:04x}", p),
            ArpError::InvalidAddressLengths(h, p) => {
                write!(f, "Invalid address lengths: hlen={}, plen={}", h, p)
            }
        }
    }
}

impl std::error::Error for ArpError {}

impl ArpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, ArpError> {
        if data.len() < ARP_PACKET_LEN {
            return Err(ArpError::PacketTooShort(data.len()));
        }

        let htype = u16::from_be_bytes([data[0], data[1]]);
        let ptype = u16::from_be_bytes([data[2], data[3]]);
        let hlen = data[4];
        let plen = data[5];

        // This module implements Ethernet/IPv4 ARP specifically. The old parser
        // carried error variants for these mismatches but never used them, which
        // meant a packet for a different link/protocol family was decoded as if
        // its address layout were Ethernet + IPv4.
        if htype != ARP_HTYPE_ETHERNET {
            return Err(ArpError::InvalidHardwareType(htype));
        }
        if ptype != ARP_PTYPE_IPV4 {
            return Err(ArpError::InvalidProtocolType(ptype));
        }
        if hlen != ARP_HLEN_ETHERNET || plen != ARP_PLEN_IPV4 {
            return Err(ArpError::InvalidAddressLengths(hlen, plen));
        }

        let opcode_raw = u16::from_be_bytes([data[6], data[7]]);
        let opcode = ArpOpcode::from_u16(opcode_raw);

        let mut sender_mac = [0u8; 6];
        sender_mac.copy_from_slice(&data[8..14]);

        let mut sender_ip = [0u8; 4];
        sender_ip.copy_from_slice(&data[14..18]);

        let mut target_mac = [0u8; 6];
        target_mac.copy_from_slice(&data[18..24]);

        let mut target_ip = [0u8; 4];
        target_ip.copy_from_slice(&data[24..28]);

        Ok(ArpPacket {
            htype,
            ptype,
            hlen,
            plen,
            opcode,
            sender_mac: MacAddress(sender_mac),
            sender_ip,
            target_mac: MacAddress(target_mac),
            target_ip,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ARP_PACKET_LEN);
        buf.extend_from_slice(&self.htype.to_be_bytes());
        buf.extend_from_slice(&self.ptype.to_be_bytes());
        buf.push(self.hlen);
        buf.push(self.plen);
        buf.extend_from_slice(&self.opcode.to_u16().to_be_bytes());
        buf.extend_from_slice(&self.sender_mac.0);
        buf.extend_from_slice(&self.sender_ip);
        buf.extend_from_slice(&self.target_mac.0);
        buf.extend_from_slice(&self.target_ip);
        buf
    }

    pub fn build_request(sender_mac: MacAddress, sender_ip: [u8; 4], target_ip: [u8; 4]) -> Self {
        ArpPacket {
            htype: ARP_HTYPE_ETHERNET,
            ptype: ARP_PTYPE_IPV4,
            hlen: ARP_HLEN_ETHERNET,
            plen: ARP_PLEN_IPV4,
            opcode: ArpOpcode::Request,
            sender_mac,
            sender_ip,
            target_mac: MacAddress::ZERO,
            target_ip,
        }
    }

    pub fn build_reply(
        sender_mac: MacAddress,
        sender_ip: [u8; 4],
        target_mac: MacAddress,
        target_ip: [u8; 4],
    ) -> Self {
        ArpPacket {
            htype: ARP_HTYPE_ETHERNET,
            ptype: ARP_PTYPE_IPV4,
            hlen: ARP_HLEN_ETHERNET,
            plen: ARP_PLEN_IPV4,
            opcode: ArpOpcode::Reply,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        }
    }

    /// RFC 5227 address probe: sender protocol address is 0.0.0.0 while the
    /// address being tested appears as the target protocol address.
    pub fn build_probe(sender_mac: MacAddress, target_ip: [u8; 4]) -> Self {
        Self::build_request(sender_mac, [0, 0, 0, 0], target_ip)
    }

    /// RFC 5227 ARP Announcement, commonly called gratuitous ARP. It is a
    /// request whose sender and target protocol addresses are the same.
    pub fn build_announcement(sender_mac: MacAddress, ip: [u8; 4]) -> Self {
        Self::build_request(sender_mac, ip, ip)
    }

    pub fn is_ethernet_ipv4(&self) -> bool {
        self.htype == ARP_HTYPE_ETHERNET
            && self.ptype == ARP_PTYPE_IPV4
            && self.hlen == ARP_HLEN_ETHERNET
            && self.plen == ARP_PLEN_IPV4
    }

    /// True for an RFC 5227 probe. A probe must not create a cache entry for
    /// 0.0.0.0; its sender does not own the address it is testing yet.
    pub fn is_probe(&self) -> bool {
        self.opcode == ArpOpcode::Request && self.sender_ip == [0, 0, 0, 0]
    }

    /// True for a gratuitous ARP request or reply: the sender is talking about
    /// its own protocol address rather than resolving some other address.
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip != [0, 0, 0, 0] && self.sender_ip == self.target_ip
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpEntryKind {
    Dynamic,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpEntryMeta {
    pub kind: ArpEntryKind,
    /// Simulated time at which the dynamic mapping was most recently learned.
    /// `None` is used by the compatibility `insert` API, which is intentionally
    /// non-expiring because it has no clock argument.
    pub learned_at_ms: Option<u64>,
    /// Expiration time for a dynamic entry. Static and compatibility entries use
    /// `None` and therefore do not age out.
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpLearnOutcome {
    /// RFC 5227 probe; 0.0.0.0 was deliberately not learned.
    IgnoredProbe,
    /// Sender MAC was zero, broadcast, or multicast.
    IgnoredInvalidSender,
    /// Packet was not Ethernet/IPv4 ARP.
    IgnoredUnsupportedFormat,
    /// A new dynamic mapping was installed.
    Learned,
    /// The same dynamic mapping was seen again and its lifetime was refreshed.
    Refreshed,
    /// A dynamic address moved to a different MAC.
    Replaced { previous: MacAddress },
    /// A packet agreed with an operator-configured static mapping.
    StaticMatch,
    /// A packet contradicted a static mapping; the static entry was kept.
    StaticConflict {
        configured: MacAddress,
        advertised: MacAddress,
    },
}

/// ARP cache with backwards-compatible untimed lookups plus explicit ageing.
#[derive(Debug, Default, Clone)]
pub struct ArpTable {
    table: HashMap<[u8; 4], MacAddress>,
    meta: HashMap<[u8; 4], ArpEntryMeta>,
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable {
            table: HashMap::new(),
            meta: HashMap::new(),
        }
    }

    /// Compatibility insertion API. Because no clock is supplied, the entry is
    /// dynamic but non-expiring; callers that model time should use
    /// [`ArpTable::insert_dynamic`] instead.
    pub fn insert(&mut self, ip: [u8; 4], mac: MacAddress) {
        self.table.insert(ip, mac);
        self.meta.insert(
            ip,
            ArpEntryMeta {
                kind: ArpEntryKind::Dynamic,
                learned_at_ms: None,
                expires_at_ms: None,
            },
        );
    }

    pub fn insert_dynamic(&mut self, ip: [u8; 4], mac: MacAddress, now_ms: u64, ttl_ms: u64) {
        self.table.insert(ip, mac);
        self.meta.insert(
            ip,
            ArpEntryMeta {
                kind: ArpEntryKind::Dynamic,
                learned_at_ms: Some(now_ms),
                expires_at_ms: Some(now_ms.saturating_add(ttl_ms)),
            },
        );
    }

    pub fn insert_dynamic_default(&mut self, ip: [u8; 4], mac: MacAddress, now_ms: u64) {
        self.insert_dynamic(ip, mac, now_ms, ARP_DEFAULT_DYNAMIC_TTL_MS);
    }

    pub fn insert_static(&mut self, ip: [u8; 4], mac: MacAddress) {
        self.table.insert(ip, mac);
        self.meta.insert(
            ip,
            ArpEntryMeta {
                kind: ArpEntryKind::Static,
                learned_at_ms: None,
                expires_at_ms: None,
            },
        );
    }

    /// Legacy lookup that intentionally ignores ageing because it has no clock.
    pub fn lookup(&self, ip: &[u8; 4]) -> Option<MacAddress> {
        self.table.get(ip).copied()
    }

    /// Time-aware lookup. Expired dynamic entries are treated as absent without
    /// requiring a mutable table; call [`ArpTable::purge_expired`] to reclaim them.
    pub fn lookup_at(&self, ip: &[u8; 4], now_ms: u64) -> Option<MacAddress> {
        let mac = self.table.get(ip).copied()?;
        if self
            .meta
            .get(ip)
            .is_some_and(|m| m.expires_at_ms.is_some_and(|deadline| now_ms >= deadline))
        {
            return None;
        }
        Some(mac)
    }

    pub fn entry_meta(&self, ip: &[u8; 4]) -> Option<&ArpEntryMeta> {
        self.meta.get(ip)
    }

    pub fn remove(&mut self, ip: &[u8; 4]) -> Option<MacAddress> {
        self.meta.remove(ip);
        self.table.remove(ip)
    }

    /// Removes expired dynamic entries and returns how many mappings were aged out.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let expired: Vec<[u8; 4]> = self
            .meta
            .iter()
            .filter_map(|(ip, meta)| {
                meta.expires_at_ms
                    .filter(|deadline| now_ms >= *deadline)
                    .map(|_| *ip)
            })
            .collect();
        for ip in &expired {
            self.meta.remove(ip);
            self.table.remove(ip);
        }
        expired.len()
    }

    /// Learns the sender mapping from a valid ARP packet.
    ///
    /// Hosts are allowed to glean sender information from both requests and
    /// replies. Probes are deliberately ignored, while a contradiction of a
    /// static entry is reported and never overwrites operator configuration.
    pub fn learn_from_packet(
        &mut self,
        packet: &ArpPacket,
        now_ms: u64,
        ttl_ms: u64,
    ) -> ArpLearnOutcome {
        if !packet.is_ethernet_ipv4() {
            return ArpLearnOutcome::IgnoredUnsupportedFormat;
        }
        if packet.is_probe() {
            return ArpLearnOutcome::IgnoredProbe;
        }
        if packet.sender_mac == MacAddress::ZERO || !packet.sender_mac.is_unicast() {
            return ArpLearnOutcome::IgnoredInvalidSender;
        }

        let ip = packet.sender_ip;
        let advertised = packet.sender_mac;
        match (self.table.get(&ip).copied(), self.meta.get(&ip).copied()) {
            (Some(configured), Some(meta)) if meta.kind == ArpEntryKind::Static => {
                if configured == advertised {
                    ArpLearnOutcome::StaticMatch
                } else {
                    ArpLearnOutcome::StaticConflict {
                        configured,
                        advertised,
                    }
                }
            }
            (Some(previous), _) => {
                self.insert_dynamic(ip, advertised, now_ms, ttl_ms);
                if previous == advertised {
                    ArpLearnOutcome::Refreshed
                } else {
                    ArpLearnOutcome::Replaced { previous }
                }
            }
            (None, _) => {
                self.insert_dynamic(ip, advertised, now_ms, ttl_ms);
                ArpLearnOutcome::Learned
            }
        }
    }

    pub fn entries(&self) -> &HashMap<[u8; 4], MacAddress> {
        &self.table
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(last: u8) -> MacAddress {
        MacAddress([0x02, 0, 0, 0, 0, last])
    }

    #[test]
    fn test_arp_packet_roundtrip() {
        let req = ArpPacket::build_request(
            MacAddress([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]),
            [192, 168, 1, 10],
            [192, 168, 1, 1],
        );
        let raw = req.serialize();
        assert_eq!(raw.len(), ARP_PACKET_LEN);

        let parsed = ArpPacket::parse(&raw).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn test_parser_rejects_non_ethernet_or_non_ipv4_arp() {
        let mut raw = ArpPacket::build_request(mac(1), [10, 0, 0, 1], [10, 0, 0, 2]).serialize();
        raw[0..2].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(ArpPacket::parse(&raw), Err(ArpError::InvalidHardwareType(2)));

        let mut raw = ArpPacket::build_request(mac(1), [10, 0, 0, 1], [10, 0, 0, 2]).serialize();
        raw[2..4].copy_from_slice(&0x86ddu16.to_be_bytes());
        assert_eq!(
            ArpPacket::parse(&raw),
            Err(ArpError::InvalidProtocolType(0x86dd))
        );
    }

    #[test]
    fn test_probe_and_announcement_detection() {
        let probe = ArpPacket::build_probe(mac(1), [10, 0, 0, 7]);
        assert!(probe.is_probe());
        assert!(!probe.is_gratuitous());

        let announcement = ArpPacket::build_announcement(mac(1), [10, 0, 0, 7]);
        assert!(!announcement.is_probe());
        assert!(announcement.is_gratuitous());
    }

    #[test]
    fn test_arp_cache() {
        let mut table = ArpTable::new();
        let ip = [10, 0, 0, 1];
        let mac = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        assert_eq!(table.lookup(&ip), None);
        table.insert(ip, mac);
        assert_eq!(table.lookup(&ip), Some(mac));
    }

    #[test]
    fn test_dynamic_entries_expire_but_static_entries_do_not() {
        let mut table = ArpTable::new();
        let dynamic_ip = [10, 0, 0, 1];
        let static_ip = [10, 0, 0, 2];
        table.insert_dynamic(dynamic_ip, mac(1), 100, 50);
        table.insert_static(static_ip, mac(2));

        assert_eq!(table.lookup_at(&dynamic_ip, 149), Some(mac(1)));
        assert_eq!(table.lookup_at(&dynamic_ip, 150), None);
        assert_eq!(table.lookup_at(&static_ip, 10_000), Some(mac(2)));
        assert_eq!(table.purge_expired(150), 1);
        assert_eq!(table.lookup(&dynamic_ip), None);
        assert_eq!(table.lookup(&static_ip), Some(mac(2)));
    }

    #[test]
    fn test_learning_refreshes_dynamic_and_protects_static() {
        let mut table = ArpTable::new();
        let ip = [10, 0, 0, 9];
        let first = ArpPacket::build_request(mac(1), ip, [10, 0, 0, 1]);
        assert_eq!(
            table.learn_from_packet(&first, 100, 50),
            ArpLearnOutcome::Learned
        );
        assert_eq!(
            table.learn_from_packet(&first, 120, 50),
            ArpLearnOutcome::Refreshed
        );
        assert_eq!(table.lookup_at(&ip, 169), Some(mac(1)));

        let moved = ArpPacket::build_reply(mac(2), ip, mac(3), [10, 0, 0, 3]);
        assert_eq!(
            table.learn_from_packet(&moved, 130, 50),
            ArpLearnOutcome::Replaced { previous: mac(1) }
        );
        assert_eq!(table.lookup(&ip), Some(mac(2)));

        table.insert_static(ip, mac(4));
        assert_eq!(
            table.learn_from_packet(&moved, 140, 50),
            ArpLearnOutcome::StaticConflict {
                configured: mac(4),
                advertised: mac(2),
            }
        );
        assert_eq!(table.lookup(&ip), Some(mac(4)));
    }

    #[test]
    fn test_probe_is_never_learned() {
        let mut table = ArpTable::new();
        let probe = ArpPacket::build_probe(mac(1), [10, 0, 0, 44]);
        assert_eq!(
            table.learn_from_packet(&probe, 100, 50),
            ArpLearnOutcome::IgnoredProbe
        );
        assert!(table.is_empty());
    }
}
