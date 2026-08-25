//! EVPN Proxy ARP / ND Suppression & Distributed Anycast Gateway (RFC 7432 Section 10 / RFC 9135 / RFC 8365).
//!
//! Eliminates broadcast ARP/ND flooding in VXLAN/EVPN datacenter fabrics by snooping local ARP/GARP requests,
//! populating proxy ARP caches from BGP EVPN Route Type 2 (MAC/IP Advertisement), and synthesizing local unicast
//! ARP replies directly at the Top-of-Rack (ToR) leaf switches.

use crate::arp::{ArpOpcode, ArpPacket, ARP_HLEN_ETHERNET, ARP_HTYPE_ETHERNET, ARP_PLEN_IPV4, ARP_PTYPE_IPV4};
use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// Proxy ARP Entry State.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyArpState {
    Active,
    Static,
    AnycastGateway,
}

/// A snooped or EVPN-learned Proxy ARP cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyArpEntry {
    pub vni: u32,
    pub ip: Ipv4Address,
    pub mac: MacAddress,
    pub state: ProxyArpState,
    pub is_local: bool,
}

/// Result of processing a local ARP frame through the suppression engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpSuppressionAction {
    /// ARP Request intercepted and answered locally with a synthesized unicast ARP Reply (Suppressed from overlay).
    SynthesizedReply(ArpPacket),
    /// ARP Request missed in cache -> Forward/Flood across VXLAN overlay.
    Flood,
    /// Local ARP Reply / GARP learned into cache -> No reply needed, learn only.
    LearnedOnly,
    /// Duplicate IP detected (IP conflict / host mobility flap).
    DuplicateIpDetected {
        ip: Ipv4Address,
        existing_mac: MacAddress,
        conflicting_mac: MacAddress,
    },
}

/// Distributed Anycast Gateway configuration per VNI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnycastGatewayConfig {
    pub vni: u32,
    pub gateway_ip: Ipv4Address,
    pub gateway_mac: MacAddress,
}

/// EVPN Proxy ARP / ND Suppression Engine.
#[derive(Debug, Clone)]
pub struct EvpnProxyArpEngine {
    pub table: HashMap<(u32, Ipv4Address), ProxyArpEntry>,
    pub anycast_gateways: HashMap<u32, AnycastGatewayConfig>,
    pub suppressed_requests_count: u64,
    pub flooded_requests_count: u64,
    pub learned_entries_count: u64,
}

impl EvpnProxyArpEngine {
    pub fn new() -> Self {
        EvpnProxyArpEngine {
            table: HashMap::new(),
            anycast_gateways: HashMap::new(),
            suppressed_requests_count: 0,
            flooded_requests_count: 0,
            learned_entries_count: 0,
        }
    }

    /// Configures a Distributed Anycast Gateway for a given VNI.
    pub fn add_anycast_gateway(&mut self, vni: u32, gateway_ip: Ipv4Address, gateway_mac: MacAddress) {
        self.anycast_gateways.insert(
            vni,
            AnycastGatewayConfig {
                vni,
                gateway_ip,
                gateway_mac,
            },
        );
        self.table.insert(
            (vni, gateway_ip),
            ProxyArpEntry {
                vni,
                ip: gateway_ip,
                mac: gateway_mac,
                state: ProxyArpState::AnycastGateway,
                is_local: true,
            },
        );
    }

    /// Learns a MAC-to-IP binding advertised via BGP EVPN Route Type 2 (MAC/IP Advertisement).
    pub fn learn_from_evpn_route_type2(&mut self, vni: u32, ip: Ipv4Address, mac: MacAddress) {
        self.table.insert(
            (vni, ip),
            ProxyArpEntry {
                vni,
                ip,
                mac,
                state: ProxyArpState::Active,
                is_local: false,
            },
        );
        self.learned_entries_count += 1;
    }

    /// Snoops a local ARP frame from an attached tenant VM and applies proxy suppression.
    pub fn process_local_arp(&mut self, vni: u32, arp: &ArpPacket) -> ArpSuppressionAction {
        let sender_ip = Ipv4Address(arp.sender_ip);
        let sender_mac = arp.sender_mac;
        let target_ip = Ipv4Address(arp.target_ip);

        // 1. Check for Duplicate IP / Host Mobility on sender
        if let Some(existing) = self.table.get(&(vni, sender_ip)) {
            if existing.mac != sender_mac && existing.state != ProxyArpState::AnycastGateway {
                return ArpSuppressionAction::DuplicateIpDetected {
                    ip: sender_ip,
                    existing_mac: existing.mac,
                    conflicting_mac: sender_mac,
                };
            }
        }

        // 2. Snooping & Learning local sender IP/MAC
        if sender_ip != Ipv4Address::new(0, 0, 0, 0) {
            self.table.insert(
                (vni, sender_ip),
                ProxyArpEntry {
                    vni,
                    ip: sender_ip,
                    mac: sender_mac,
                    state: ProxyArpState::Active,
                    is_local: true,
                },
            );
            self.learned_entries_count += 1;
        }

        match arp.opcode {
            ArpOpcode::Request => {
                // Check if target IP is in Proxy ARP table (or is Anycast Gateway)
                if let Some(target_entry) = self.table.get(&(vni, target_ip)) {
                    self.suppressed_requests_count += 1;

                    // Synthesize unicast ARP Reply directly to requesting VM
                    let reply = ArpPacket {
                        htype: ARP_HTYPE_ETHERNET,
                        ptype: ARP_PTYPE_IPV4,
                        hlen: ARP_HLEN_ETHERNET,
                        plen: ARP_PLEN_IPV4,
                        opcode: ArpOpcode::Reply,
                        sender_mac: target_entry.mac,
                        sender_ip: target_ip.0,
                        target_mac: sender_mac,
                        target_ip: sender_ip.0,
                    };
                    ArpSuppressionAction::SynthesizedReply(reply)
                } else {
                    // Cache miss -> Flood across overlay to discover host
                    self.flooded_requests_count += 1;
                    ArpSuppressionAction::Flood
                }
            }
            ArpOpcode::Reply => ArpSuppressionAction::LearnedOnly,
            _ => ArpSuppressionAction::Flood,
        }
    }

    /// Looks up a MAC address for an IP within a VNI.
    pub fn lookup(&self, vni: u32, ip: Ipv4Address) -> Option<MacAddress> {
        self.table.get(&(vni, ip)).map(|e| e.mac)
    }

    /// Clears expired remote learned entries.
    pub fn purge_remote_entries(&mut self) {
        self.table.retain(|_, v| v.is_local || v.state == ProxyArpState::Static);
    }
}
