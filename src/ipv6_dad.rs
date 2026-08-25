//! IPv6 Duplicate Address Detection (DAD) primitives (RFC 4862 section 5.4).
//!
//! This module deliberately keeps DAD deterministic and transport-independent so it can be
//! driven by the in-process lab or by a real I/O backend. It builds the special Neighbor
//! Solicitation used by DAD (source `::`, no Source Link-Layer Address option), tracks probe
//! timing, and consumes validated NS/NA messages that prove an address is duplicated.

use crate::ethernet::MacAddress;
use crate::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet,
    ipv6_multicast_mac,
};
use crate::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};

pub const DAD_HOP_LIMIT: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DadStatus {
    Tentative,
    Preferred,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DadProbe {
    pub target: Ipv6Address,
    pub destination: Ipv6Address,
    pub destination_mac: MacAddress,
    pub icmpv6: Vec<u8>,
    pub ipv6_packet: Vec<u8>,
}

/// RFC 4291 section 2.7.1 solicited-node multicast address for `target`.
pub fn solicited_node_multicast(target: Ipv6Address) -> Ipv6Address {
    let mut bytes = [0u8; 16];
    bytes[0] = 0xff;
    bytes[1] = 0x02;
    bytes[11] = 0x01;
    bytes[12] = 0xff;
    bytes[13] = target.0[13];
    bytes[14] = target.0[14];
    bytes[15] = target.0[15];
    Ipv6Address(bytes)
}

/// Builds the special Neighbor Solicitation used by Duplicate Address Detection.
///
/// RFC 4862 requires an unspecified IPv6 source address and forbids the Source Link-Layer
/// Address option in a DAD probe. The IPv6 Hop Limit is 255 as required by Neighbor Discovery.
pub fn build_dad_probe(target: Ipv6Address) -> DadProbe {
    let source = Ipv6Address::UNSPECIFIED;
    let destination = solicited_node_multicast(target);
    let destination_mac = ipv6_multicast_mac(destination)
        .expect("solicited-node destination is always IPv6 multicast");

    let mut icmpv6 = Vec::with_capacity(24);
    icmpv6.push(ICMPV6_TYPE_NEIGHBOR_SOLICIT);
    icmpv6.push(0);
    icmpv6.extend_from_slice(&[0, 0]);
    icmpv6.extend_from_slice(&[0, 0, 0, 0]);
    icmpv6.extend_from_slice(&target.0);
    let checksum =
        compute_ipv6_transport_checksum(source, destination, NEXT_HEADER_ICMPV6, &icmpv6);
    icmpv6[2..4].copy_from_slice(&checksum.to_be_bytes());

    let ipv6_packet = Ipv6Packet::serialize(
        source,
        destination,
        NEXT_HEADER_ICMPV6,
        DAD_HOP_LIMIT,
        &icmpv6,
    );

    DadProbe {
        target,
        destination,
        destination_mac,
        icmpv6,
        ipv6_packet,
    }
}

/// Deterministic RFC 4862 DAD state machine.
///
/// `transmits` models DupAddrDetectTransmits. A value of zero disables probing and immediately
/// makes the address Preferred. After the final probe, one retransmission interval must elapse
/// without a conflicting NS/NA before the tentative address becomes Preferred.
#[derive(Debug, Clone)]
pub struct DadState {
    target: Ipv6Address,
    transmits: u8,
    probes_sent: u8,
    retrans_timer_ms: u64,
    next_event_ms: u64,
    status: DadStatus,
}

impl DadState {
    pub fn new(
        target: Ipv6Address,
        transmits: u8,
        retrans_timer_ms: u64,
        now_ms: u64,
    ) -> Self {
        DadState {
            target,
            transmits,
            probes_sent: 0,
            retrans_timer_ms: retrans_timer_ms.max(1),
            next_event_ms: now_ms,
            status: if transmits == 0 {
                DadStatus::Preferred
            } else {
                DadStatus::Tentative
            },
        }
    }

    pub fn target(&self) -> Ipv6Address {
        self.target
    }

    pub fn status(&self) -> DadStatus {
        self.status
    }

    pub fn probes_sent(&self) -> u8 {
        self.probes_sent
    }

    /// Advances DAD at `now_ms`. Returns a probe exactly when one should be transmitted.
    pub fn poll(&mut self, now_ms: u64) -> Option<DadProbe> {
        if self.status != DadStatus::Tentative || now_ms < self.next_event_ms {
            return None;
        }

        if self.probes_sent < self.transmits {
            self.probes_sent += 1;
            self.next_event_ms = now_ms.saturating_add(self.retrans_timer_ms);
            return Some(build_dad_probe(self.target));
        }

        self.status = DadStatus::Preferred;
        None
    }

    /// Observes an on-link Neighbor Solicitation or Advertisement while the address is tentative.
    /// Returns `true` only when the observation transitions this DAD instance to Duplicate.
    ///
    /// The caller supplies the enclosing IPv6 addresses and Hop Limit so the ICMPv6 checksum and
    /// the mandatory NDP Hop Limit 255 rule can both be validated here.
    pub fn observe_neighbor_message(
        &mut self,
        hop_limit: u8,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        icmpv6_bytes: &[u8],
    ) -> bool {
        if self.status != DadStatus::Tentative || hop_limit != DAD_HOP_LIMIT {
            return false;
        }

        let Ok(packet) = Icmpv6Packet::parse(src_ip, dst_ip, icmpv6_bytes, true) else {
            return false;
        };
        if !matches!(
            packet.msg_type,
            ICMPV6_TYPE_NEIGHBOR_SOLICIT | ICMPV6_TYPE_NEIGHBOR_ADVERT
        ) || packet.code != 0
            || packet.payload.len() < 20
        {
            return false;
        }

        let mut target = [0u8; 16];
        target.copy_from_slice(&packet.payload[4..20]);
        if Ipv6Address(target) != self.target {
            return false;
        }

        self.status = DadStatus::Duplicate;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip6(value: &str) -> Ipv6Address {
        Ipv6Address::from_str(value).unwrap()
    }

    #[test]
    fn solicited_node_address_and_ethernet_mapping_use_low_24_bits() {
        let target = ip6("2001:db8::1234:5678");
        let multicast = solicited_node_multicast(target);
        assert_eq!(multicast, ip6("ff02::1:ff34:5678"));
        assert_eq!(
            ipv6_multicast_mac(multicast),
            Some(MacAddress([0x33, 0x33, 0xff, 0x34, 0x56, 0x78]))
        );
    }

    #[test]
    fn dad_probe_uses_unspecified_source_hop_limit_255_and_no_slla() {
        let target = ip6("2001:db8:1::abcd");
        let probe = build_dad_probe(target);
        assert_eq!(probe.icmpv6.len(), 24);

        let ip = Ipv6Packet::parse(&probe.ipv6_packet).unwrap();
        assert_eq!(ip.header.src_ip, Ipv6Address::UNSPECIFIED);
        assert_eq!(ip.header.dst_ip, ip6("ff02::1:ff00:abcd"));
        assert_eq!(ip.header.hop_limit, DAD_HOP_LIMIT);
        assert_eq!(ip.header.next_header, NEXT_HEADER_ICMPV6);

        let icmp = Icmpv6Packet::parse(
            ip.header.src_ip,
            ip.header.dst_ip,
            ip.payload,
            true,
        )
        .unwrap();
        assert_eq!(icmp.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
        assert_eq!(icmp.code, 0);
        assert_eq!(icmp.payload.len(), 20);
        assert_eq!(&icmp.payload[4..20], &target.0);
    }

    #[test]
    fn dad_becomes_preferred_only_after_final_retransmission_interval() {
        let target = ip6("2001:db8:1::2");
        let mut dad = DadState::new(target, 2, 1000, 10);
        assert_eq!(dad.status(), DadStatus::Tentative);
        assert!(dad.poll(9).is_none());
        assert!(dad.poll(10).is_some());
        assert_eq!(dad.probes_sent(), 1);
        assert!(dad.poll(1009).is_none());
        assert!(dad.poll(1010).is_some());
        assert_eq!(dad.probes_sent(), 2);
        assert!(dad.poll(2009).is_none());
        assert!(dad.poll(2010).is_none());
        assert_eq!(dad.status(), DadStatus::Preferred);
    }

    #[test]
    fn valid_neighbor_advertisement_marks_tentative_address_duplicate() {
        let target = ip6("2001:db8:1::2");
        let all_nodes = Ipv6Address::LINK_LOCAL_ALL_NODES;
        let mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let na = Icmpv6Packet::build_neighbor_advertisement(
            target,
            all_nodes,
            target,
            mac,
            false,
            false,
            true,
        );
        let mut dad = DadState::new(target, 1, 1000, 0);
        assert!(dad.observe_neighbor_message(DAD_HOP_LIMIT, target, all_nodes, &na));
        assert_eq!(dad.status(), DadStatus::Duplicate);
        assert!(dad.poll(2000).is_none());
    }

    #[test]
    fn wrong_hop_limit_does_not_poison_dad() {
        let target = ip6("2001:db8:1::2");
        let all_nodes = Ipv6Address::LINK_LOCAL_ALL_NODES;
        let mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let na = Icmpv6Packet::build_neighbor_advertisement(
            target,
            all_nodes,
            target,
            mac,
            false,
            false,
            true,
        );
        let mut dad = DadState::new(target, 1, 1000, 0);
        assert!(!dad.observe_neighbor_message(64, target, all_nodes, &na));
        assert_eq!(dad.status(), DadStatus::Tentative);
    }
}
