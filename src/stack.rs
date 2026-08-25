//! Unified NetStack: Dual-Stack IPv4/IPv6 Layer 2 -> Layer 3 -> Layer 4 packet processing pipeline.

use crate::arp::{ArpOpcode, ArpPacket, ArpTable};
use crate::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, EtherType, EthernetFrame, MacAddress,
};
use crate::firewall::{Firewall, FirewallAction, FirewallChain};
use crate::icmp::{IcmpPacket, IcmpType};
use crate::icmpv6::{
    ICMPV6_TYPE_ECHO_REPLY, ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT,
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_PACKET_TOO_BIG, ICMPV6_TYPE_ROUTER_ADVERT,
    Icmpv6Packet, NdpTable, RouterAdvertisement, ipv6_multicast_mac, slaac_address,
};
use crate::ipv4::{IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, IpProtocol, Ipv4Address, Ipv4Packet};
use crate::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use crate::nat::NatTable;
use crate::router::{RouteSource, RoutingTable};
use crate::router_ipv6::Ipv6RoutingTable;
use crate::socket::{
    SocketError, SocketRuntime, TcpDiagnostics, TcpListenerHandle, TcpStreamHandle, UdpSocketHandle,
};
use crate::tcp::{SocketAddrV4, TcpManager, TcpSegment, TcpState, TcpStats};
use crate::udp::{UdpDatagram, UdpSocketTable};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct NetStackConfig {
    pub mac: MacAddress,
    pub ip: Ipv4Address,
    pub ipv6: Option<Ipv6Address>,
    pub subnet_mask: u8,
    pub gateway: Option<Ipv4Address>,
}

/// One DAD probe followed by one retransmission interval is the default RFC 4862
/// host behaviour modelled by this deterministic stack.
pub const IPV6_DAD_RETRANS_TIMER_MS: u64 = 1_000;
/// RFC 4861 section 10 constants for host Router Solicitation discovery.
pub const IPV6_MAX_RTR_SOLICITATIONS: u8 = 3;
pub const IPV6_RTR_SOLICITATION_INTERVAL_MS: u64 = 4_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6RouterDiscoveryStatus {
    Idle,
    Soliciting { solicitations_sent: u8 },
    Exhausted,
}

#[derive(Debug, Clone, Copy)]
struct Ipv6RouterDiscovery {
    solicitations_sent: u8,
    next_solicitation_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6DadStatus {
    Idle,
    Tentative(Ipv6Address),
    Duplicate(Ipv6Address),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6SlaacStatus {
    Unconfigured,
    Preferred(Ipv6Address),
    Deprecated(Ipv6Address),
}

const IPV6_SLAAC_TWO_HOURS_MS: u64 = 2 * 60 * 60 * 1_000;

#[derive(Debug, Clone, Copy)]
struct Ipv6SlaacLifetimes {
    address: Ipv6Address,
    preferred_until_ms: Option<u64>,
    valid_until_ms: Option<u64>,
    router: Option<Ipv6Address>,
    router_until_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct PendingIpv6Dad {
    address: Ipv6Address,
    prefix_len: u8,
    gateway: Option<Ipv6Address>,
    deadline_ms: u64,
    preferred_until_ms: Option<u64>,
    valid_until_ms: Option<u64>,
    router_until_ms: Option<u64>,
}

fn ipv6_lifetime_deadline(now_ms: u64, lifetime_secs: u32) -> Option<u64> {
    if lifetime_secs == u32::MAX {
        None
    } else {
        Some(now_ms.saturating_add((lifetime_secs as u64).saturating_mul(1_000)))
    }
}

fn ipv6_remaining_lifetime_ms(deadline: Option<u64>, now_ms: u64) -> u64 {
    deadline.map_or(u64::MAX, |deadline| deadline.saturating_sub(now_ms))
}

/// RFC 4862 section 5.5.3(e): unauthenticated RAs cannot collapse a long
/// remaining Valid Lifetime below two hours in one step.
fn refreshed_ipv6_valid_deadline(
    now_ms: u64,
    current_deadline: Option<u64>,
    advertised_secs: u32,
) -> Option<u64> {
    if advertised_secs == u32::MAX {
        return None;
    }
    let advertised_ms = (advertised_secs as u64).saturating_mul(1_000);
    let remaining_ms = ipv6_remaining_lifetime_ms(current_deadline, now_ms);
    if advertised_ms > IPV6_SLAAC_TWO_HOURS_MS || advertised_ms > remaining_ms {
        Some(now_ms.saturating_add(advertised_ms))
    } else if remaining_ms <= IPV6_SLAAC_TWO_HOURS_MS {
        current_deadline
    } else {
        Some(now_ms.saturating_add(IPV6_SLAAC_TWO_HOURS_MS))
    }
}

pub struct NetStack {
    pub config: NetStackConfig,
    pub arp_table: ArpTable,
    pub ndp_table: NdpTable,
    pub routing_table: RoutingTable,
    pub ipv6_routing_table: Ipv6RoutingTable,
    ipv6_prefix_len: Option<u8>,
    ipv6_gateway: Option<Ipv6Address>,
    ipv6_dad: Option<PendingIpv6Dad>,
    ipv6_dad_duplicate: Option<Ipv6Address>,
    ipv6_slaac_lifetimes: Option<Ipv6SlaacLifetimes>,
    ipv6_ra_on_link_prefixes: HashMap<(Ipv6Address, u8), Option<u64>>,
    ipv6_router_discovery: Option<Ipv6RouterDiscovery>,
    ipv6_router_discovery_exhausted: bool,
    ipv6_path_mtu_cache: HashMap<Ipv6Address, u32>,
    pub firewall: Firewall,
    pub nat: Option<NatTable>,
    pub udp_sockets: UdpSocketTable,
    pub tcp_manager: TcpManager,
    pub sockets: SocketRuntime,
    pub ip_id_counter: u16,
    pub current_time_ms: u64,
    pub pending_arp_packets: HashMap<Ipv4Address, Vec<Vec<u8>>>,
    pub pending_ndp_packets: HashMap<Ipv6Address, Vec<Vec<u8>>>,
    pub dhcp_server: Option<crate::dhcp::DhcpServer>,
    pub received_dhcp_offers: Vec<crate::dhcp::DhcpPacket>,
    pub received_dhcp_acks: Vec<crate::dhcp::DhcpPacket>,
    pub received_icmp_replies: Vec<(Ipv4Address, u16, u16)>,
    pub received_icmp_time_exceeded: Vec<(Ipv4Address, u8)>,
    pub received_icmp_unreachable: Vec<(Ipv4Address, u8)>,
    pub received_icmpv6_replies: Vec<(Ipv6Address, u16, u16)>,
    pub received_udp_payloads: Vec<(Ipv4Address, u16, u16, Vec<u8>)>,
}

impl NetStack {
    pub fn new(config: NetStackConfig) -> Self {
        let mut routing_table = RoutingTable::new();

        // Local subnet route
        let subnet_net = config.ip.mask(config.subnet_mask);
        routing_table.add_route(subnet_net, config.subnet_mask, None, "eth0");

        // Default gateway route
        if let Some(gw) = config.gateway {
            routing_table.add_route(Ipv4Address::UNSPECIFIED, 0, Some(gw), "eth0");
        }

        let sockets = SocketRuntime::new(config.ip);

        NetStack {
            config,
            arp_table: ArpTable::new(),
            ndp_table: NdpTable::new(),
            routing_table,
            ipv6_routing_table: Ipv6RoutingTable::new(),
            ipv6_prefix_len: None,
            ipv6_gateway: None,
            ipv6_dad: None,
            ipv6_dad_duplicate: None,
            ipv6_slaac_lifetimes: None,
            ipv6_ra_on_link_prefixes: HashMap::new(),
            ipv6_router_discovery: None,
            ipv6_router_discovery_exhausted: false,
            ipv6_path_mtu_cache: HashMap::new(),
            firewall: Firewall::new(),
            nat: None,
            udp_sockets: UdpSocketTable::new(),
            tcp_manager: TcpManager::new(),
            sockets,
            ip_id_counter: 1,
            current_time_ms: 0,
            pending_arp_packets: HashMap::new(),
            pending_ndp_packets: HashMap::new(),
            dhcp_server: None,
            received_dhcp_offers: Vec::new(),
            received_dhcp_acks: Vec::new(),
            received_icmp_replies: Vec::new(),
            received_icmp_time_exceeded: Vec::new(),
            received_icmp_unreachable: Vec::new(),
            received_icmpv6_replies: Vec::new(),
            received_udp_payloads: Vec::new(),
        }
    }

    /// Configures the single host-facing IPv6 interface and programs the routes
    /// that make on-link versus routed delivery unambiguous.
    ///
    /// The public `NetStackConfig` is intentionally left unchanged so existing
    /// struct-literal callers remain source-compatible. Reconfiguration removes
    /// only the connected/default routes previously owned by this method; other
    /// static or dynamically learned routes are preserved.
    pub fn configure_ipv6_interface(
        &mut self,
        address: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
    ) {
        // Explicit/manual configuration owns the interface until an RA explicitly
        // adopts the same address again. Successful DAD restores SLAAC metadata after
        // this helper returns.
        self.ipv6_dad = None;
        self.ipv6_dad_duplicate = None;
        self.ipv6_slaac_lifetimes = None;
        self.ipv6_path_mtu_cache.clear();
        if let (Some(old_address), Some(old_prefix_len)) = (self.config.ipv6, self.ipv6_prefix_len)
        {
            self.ipv6_routing_table.remove_route(
                old_address,
                old_prefix_len,
                RouteSource::Connected,
            );
        }
        if self.ipv6_gateway.is_some() {
            self.ipv6_routing_table
                .remove_route(Ipv6Address::UNSPECIFIED, 0, RouteSource::Static);
        }

        let prefix_len = prefix_len.min(128);
        self.config.ipv6 = Some(address);
        self.ipv6_prefix_len = Some(prefix_len);
        self.ipv6_gateway = gateway;
        self.ipv6_routing_table.add_route_from(
            address,
            prefix_len,
            None,
            "eth0",
            RouteSource::Connected,
        );
        if let Some(gateway) = gateway {
            self.ipv6_routing_table.add_route_from(
                Ipv6Address::UNSPECIFIED,
                0,
                Some(gateway),
                "eth0",
                RouteSource::Static,
            );
        }
    }

    pub fn ipv6_prefix_len(&self) -> Option<u8> {
        self.ipv6_prefix_len
    }

    pub fn ipv6_gateway(&self) -> Option<Ipv6Address> {
        self.ipv6_gateway
    }

    /// Returns the currently learned RFC 8201 Path MTU for a destination.
    pub fn ipv6_path_mtu(&self, destination: Ipv6Address) -> Option<u32> {
        self.ipv6_path_mtu_cache.get(&destination).copied()
    }

    /// Forgets a learned Path MTU so a caller can explicitly probe a larger path again.
    pub fn clear_ipv6_path_mtu(&mut self, destination: Ipv6Address) {
        self.ipv6_path_mtu_cache.remove(&destination);
    }

    pub fn clear_ipv6_interface(&mut self) {
        if let (Some(address), Some(prefix_len)) = (self.config.ipv6, self.ipv6_prefix_len) {
            self.ipv6_routing_table
                .remove_route(address, prefix_len, RouteSource::Connected);
        }
        if self.ipv6_gateway.is_some() {
            self.ipv6_routing_table
                .remove_route(Ipv6Address::UNSPECIFIED, 0, RouteSource::Static);
        }
        self.config.ipv6 = None;
        self.ipv6_prefix_len = None;
        self.ipv6_gateway = None;
        self.ipv6_dad = None;
        self.ipv6_dad_duplicate = None;
        self.ipv6_slaac_lifetimes = None;
        self.ipv6_path_mtu_cache.clear();
        self.pending_ndp_packets.clear();
    }

    pub fn ipv6_dad_status(&self) -> Ipv6DadStatus {
        if let Some(dad) = self.ipv6_dad {
            Ipv6DadStatus::Tentative(dad.address)
        } else if let Some(address) = self.ipv6_dad_duplicate {
            Ipv6DadStatus::Duplicate(address)
        } else {
            Ipv6DadStatus::Idle
        }
    }

    pub fn ipv6_slaac_status(&self) -> Ipv6SlaacStatus {
        let Some(lifetimes) = self.ipv6_slaac_lifetimes else {
            return Ipv6SlaacStatus::Unconfigured;
        };
        if lifetimes
            .valid_until_ms
            .is_some_and(|deadline| self.current_time_ms >= deadline)
        {
            return Ipv6SlaacStatus::Unconfigured;
        }
        if lifetimes
            .preferred_until_ms
            .is_some_and(|deadline| self.current_time_ms >= deadline)
        {
            Ipv6SlaacStatus::Deprecated(lifetimes.address)
        } else {
            Ipv6SlaacStatus::Preferred(lifetimes.address)
        }
    }

    fn set_ipv6_default_gateway(&mut self, gateway: Option<Ipv6Address>) {
        if self.ipv6_gateway.is_some() {
            self.ipv6_routing_table
                .remove_route(Ipv6Address::UNSPECIFIED, 0, RouteSource::Static);
        }
        self.ipv6_gateway = gateway;
        if let Some(gateway) = gateway {
            self.ipv6_routing_table.add_route_from(
                Ipv6Address::UNSPECIFIED,
                0,
                Some(gateway),
                "eth0",
                RouteSource::Static,
            );
        }
    }

    fn refresh_slaac_default_router(&mut self, router: Ipv6Address, lifetime_secs: u16) {
        let deadline = (lifetime_secs > 0).then(|| {
            self.current_time_ms
                .saturating_add((lifetime_secs as u64).saturating_mul(1_000))
        });

        let active_action = self.ipv6_slaac_lifetimes.map(|lifetimes| {
            if lifetime_secs == 0 {
                (lifetimes.router == Some(router), None)
            } else {
                (true, Some(router))
            }
        });
        if let Some((change_route, gateway)) = active_action
            && change_route
        {
            self.set_ipv6_default_gateway(gateway);
            if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {
                lifetimes.router = gateway;
                lifetimes.router_until_ms = gateway.and(deadline);
            }
        }

        if let Some(dad) = self.ipv6_dad.as_mut() {
            if lifetime_secs == 0 {
                if dad.gateway == Some(router) {
                    dad.gateway = None;
                    dad.router_until_ms = None;
                }
            } else {
                dad.gateway = Some(router);
                dad.router_until_ms = deadline;
            }
        }
    }

    fn refresh_ipv6_ra_on_link_prefix(
        &mut self,
        prefix: Ipv6Address,
        prefix_len: u8,
        valid_lifetime: u32,
    ) {
        let prefix_len = prefix_len.min(128);
        let prefix = prefix.mask(prefix_len);
        let key = (prefix, prefix_len);
        if valid_lifetime == 0 {
            self.ipv6_ra_on_link_prefixes.remove(&key);
            self.ipv6_routing_table
                .remove_route(prefix, prefix_len, RouteSource::Ra);
            return;
        }

        let valid_until_ms = ipv6_lifetime_deadline(self.current_time_ms, valid_lifetime);
        self.ipv6_ra_on_link_prefixes.insert(key, valid_until_ms);
        self.ipv6_routing_table
            .add_route_from(prefix, prefix_len, None, "eth0", RouteSource::Ra);
    }

    fn start_ipv6_dad(
        &mut self,
        address: Ipv6Address,
        prefix_len: u8,
        gateway: Option<Ipv6Address>,
        preferred_lifetime: u32,
        valid_lifetime: u32,
        router_lifetime: u16,
    ) -> Option<Vec<u8>> {
        if valid_lifetime == 0 {
            return None;
        }
        let now_ms = self.current_time_ms;
        let preferred_until_ms = ipv6_lifetime_deadline(now_ms, preferred_lifetime);
        let advertised_valid_until_ms = ipv6_lifetime_deadline(now_ms, valid_lifetime);
        let router_until_ms = (router_lifetime > 0)
            .then(|| now_ms.saturating_add((router_lifetime as u64).saturating_mul(1_000)));

        if self.config.ipv6 == Some(address) {
            self.set_ipv6_default_gateway(gateway);
            self.ipv6_slaac_lifetimes = Some(Ipv6SlaacLifetimes {
                address,
                preferred_until_ms,
                valid_until_ms: advertised_valid_until_ms,
                router: gateway,
                router_until_ms,
            });
            return None;
        }

        if let Some(dad) = self
            .ipv6_dad
            .as_mut()
            .filter(|dad| dad.address == address && dad.prefix_len == prefix_len)
        {
            dad.gateway = gateway;
            dad.preferred_until_ms = preferred_until_ms;
            dad.valid_until_ms =
                refreshed_ipv6_valid_deadline(now_ms, dad.valid_until_ms, valid_lifetime);
            dad.router_until_ms = router_until_ms;
            return None;
        }

        self.ipv6_dad_duplicate = None;
        self.ipv6_dad = Some(PendingIpv6Dad {
            address,
            prefix_len: prefix_len.min(128),
            gateway,
            deadline_ms: now_ms.saturating_add(IPV6_DAD_RETRANS_TIMER_MS),
            preferred_until_ms,
            valid_until_ms: advertised_valid_until_ms,
            router_until_ms,
        });

        let dst = address.solicited_node_multicast();
        let ns = Icmpv6Packet::build_dad_neighbor_solicitation(dst, address);
        let packet =
            Ipv6Packet::serialize(Ipv6Address::UNSPECIFIED, dst, NEXT_HEADER_ICMPV6, 255, &ns);
        let dst_mac = ipv6_multicast_mac(dst).unwrap_or(MacAddress::BROADCAST);
        Some(EthernetFrame::serialize(
            dst_mac,
            self.config.mac,
            ETHERTYPE_IPV6,
            &packet,
        ))
    }

    fn mark_ipv6_dad_duplicate(&mut self, address: Ipv6Address) {
        if self.ipv6_dad.is_some_and(|dad| dad.address == address) {
            self.ipv6_dad = None;
            self.ipv6_dad_duplicate = Some(address);
        }
    }

    pub fn ipv6_router_discovery_status(&self) -> Ipv6RouterDiscoveryStatus {
        if let Some(discovery) = self.ipv6_router_discovery {
            Ipv6RouterDiscoveryStatus::Soliciting {
                solicitations_sent: discovery.solicitations_sent,
            }
        } else if self.ipv6_router_discovery_exhausted {
            Ipv6RouterDiscoveryStatus::Exhausted
        } else {
            Ipv6RouterDiscoveryStatus::Idle
        }
    }

    /// Starts RFC 4861 Router Discovery and emits the first Router Solicitation.
    ///
    /// RFC 4861 allows a random initial delay of up to one second. The deterministic
    /// simulator chooses zero, then follows MAX_RTR_SOLICITATIONS=3 and a four-second
    /// RTR_SOLICITATION_INTERVAL. A valid Router Advertisement cancels the retry state.
    pub fn start_router_discovery(&mut self) -> Vec<u8> {
        self.ipv6_router_discovery_exhausted = false;
        self.ipv6_router_discovery = Some(Ipv6RouterDiscovery {
            solicitations_sent: 1,
            next_solicitation_ms: self
                .current_time_ms
                .saturating_add(IPV6_RTR_SOLICITATION_INTERVAL_MS),
        });
        self.router_solicitation()
    }

    pub fn cancel_router_discovery(&mut self) {
        self.ipv6_router_discovery = None;
        self.ipv6_router_discovery_exhausted = false;
    }

    /// Emits a Router Solicitation to ff02::2. An unconfigured host uses the
    /// unspecified IPv6 source and therefore omits the source-link-layer option.
    /// This is a stateless packet builder; use `start_router_discovery` to arm retries.
    pub fn router_solicitation(&self) -> Vec<u8> {
        let src = self.config.ipv6.unwrap_or(Ipv6Address::UNSPECIFIED);
        let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
        let source_mac = (!src.is_unspecified()).then_some(self.config.mac);
        let rs = Icmpv6Packet::build_router_solicitation(src, dst, source_mac);
        let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &rs);
        let dst_mac = ipv6_multicast_mac(dst).unwrap_or(MacAddress::BROADCAST);
        EthernetFrame::serialize(dst_mac, self.config.mac, ETHERTYPE_IPV6, &packet)
    }

    pub fn enable_nat(&mut self, public_ip: Ipv4Address) {
        self.nat = Some(NatTable::new(public_ip));
    }

    pub fn next_ip_id(&mut self) -> u16 {
        let id = self.ip_id_counter;
        self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
        id
    }

    pub fn send_ip_packet(&mut self, dst_ip: Ipv4Address, ip_bytes: Vec<u8>) -> Option<Vec<u8>> {
        let next_hop = if let Some(route) = self.routing_table.lookup(dst_ip) {
            route.next_hop(dst_ip)
        } else {
            dst_ip
        };

        if let Some(dst_mac) = self.arp_table.lookup(&next_hop.0) {
            Some(EthernetFrame::serialize(
                dst_mac,
                self.config.mac,
                ETHERTYPE_IPV4,
                &ip_bytes,
            ))
        } else {
            self.pending_arp_packets
                .entry(next_hop)
                .or_default()
                .push(ip_bytes);
            let arp_req = ArpPacket::build_request(self.config.mac, self.config.ip.0, next_hop.0);
            Some(EthernetFrame::serialize(
                MacAddress::BROADCAST,
                self.config.mac,
                ETHERTYPE_ARP,
                &arp_req.serialize(),
            ))
        }
    }

    pub fn send_ip6_packet(&mut self, dst_ip: Ipv6Address, ip6_bytes: Vec<u8>) -> Option<Vec<u8>> {
        if self
            .ipv6_path_mtu_cache
            .get(&dst_ip)
            .is_some_and(|mtu| ip6_bytes.len() > *mtu as usize)
        {
            // IPv6 routers never fragment. Until source fragmentation is modelled,
            // an RFC 8201 PMTU estimate is a hard upper bound on a source packet.
            return None;
        }

        // Preserve the historical on-link fallback when no IPv6 route exists, but
        // once a route is present resolve NDP against the route's next hop rather
        // than against the final destination. That is the IPv6 equivalent of the
        // ARP/gateway path used by `send_ip_packet`.
        let next_hop = self
            .ipv6_routing_table
            .lookup(dst_ip)
            .map(|route| route.next_hop(dst_ip))
            .unwrap_or(dst_ip);

        if let Some(dst_mac) = self.ndp_table.lookup(&next_hop) {
            Some(EthernetFrame::serialize(
                dst_mac,
                self.config.mac,
                ETHERTYPE_IPV6,
                &ip6_bytes,
            ))
        } else {
            self.pending_ndp_packets
                .entry(next_hop)
                .or_default()
                .push(ip6_bytes);
            let my_ip6 = self.config.ipv6.unwrap_or(Ipv6Address::LOOPBACK);
            let ns_dst = next_hop.solicited_node_multicast();
            let ns = Icmpv6Packet::build_neighbor_solicitation(
                my_ip6,
                ns_dst,
                next_hop,
                self.config.mac,
            );
            let ip6_ns = Ipv6Packet::serialize(my_ip6, ns_dst, NEXT_HEADER_ICMPV6, 255, &ns);
            Some(EthernetFrame::serialize(
                ipv6_multicast_mac(ns_dst).unwrap_or(MacAddress::BROADCAST),
                self.config.mac,
                ETHERTYPE_IPV6,
                &ip6_ns,
            ))
        }
    }

    pub fn ping4(
        &mut self,
        dst_ip: Ipv4Address,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let icmp = IcmpPacket::build_echo_request(id, seq, payload);
        let ip_id = self.next_ip_id();
        let ip_bytes =
            Ipv4Packet::serialize(self.config.ip, dst_ip, IP_PROTO_ICMP, ip_id, 64, &icmp);
        self.send_ip_packet(dst_ip, ip_bytes)
    }

    pub fn ping6(
        &mut self,
        dst_ip: Ipv6Address,
        id: u16,
        seq: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let my_ip6 = self.config.ipv6.unwrap_or(Ipv6Address::LOOPBACK);
        let icmp = Icmpv6Packet::build_echo_request(my_ip6, dst_ip, id, seq, payload);
        let ip6_bytes = Ipv6Packet::serialize(my_ip6, dst_ip, NEXT_HEADER_ICMPV6, 64, &icmp);
        self.send_ip6_packet(dst_ip, ip6_bytes)
    }

    pub fn send_udp(
        &mut self,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let udp = UdpDatagram::serialize(self.config.ip, dst_ip, src_port, dst_port, payload);
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(self.config.ip, dst_ip, IP_PROTO_UDP, ip_id, 64, &udp);
        self.send_ip_packet(dst_ip, ip_bytes)
    }

    /// Legacy raw-segment helper driving `TcpManager` directly, retained for the
    /// pre-socket `lab tcp-demo` walkthrough. Applications should use `tcp_connect`.
    pub fn tcp_connect_raw(
        &mut self,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        isn: u32,
    ) -> Option<Vec<u8>> {
        let local = SocketAddrV4 {
            ip: self.config.ip,
            port: src_port,
        };
        let remote = SocketAddrV4 {
            ip: dst_ip,
            port: dst_port,
        };
        let tcp_seg_bytes = self.tcp_manager.connect(local, remote, isn);
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(
            self.config.ip,
            dst_ip,
            IP_PROTO_TCP,
            ip_id,
            64,
            &tcp_seg_bytes,
        );
        self.send_ip_packet(dst_ip, ip_bytes)
    }

    /// Legacy raw-segment helper driving `TcpManager` directly. Use `tcp_write` instead.
    pub fn tcp_send_data_raw(
        &mut self,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        data: &[u8],
    ) -> Option<Vec<u8>> {
        let local = SocketAddrV4 {
            ip: self.config.ip,
            port: src_port,
        };
        let remote = SocketAddrV4 {
            ip: dst_ip,
            port: dst_port,
        };
        let tcp_seg_bytes = self.tcp_manager.send_data(local, remote, data)?;
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(
            self.config.ip,
            dst_ip,
            IP_PROTO_TCP,
            ip_id,
            64,
            &tcp_seg_bytes,
        );
        self.send_ip_packet(dst_ip, ip_bytes)
    }

    /// Legacy raw-segment helper driving `TcpManager` directly. Use `tcp_close` instead.
    pub fn tcp_close_raw(
        &mut self,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
    ) -> Option<Vec<u8>> {
        let local = SocketAddrV4 {
            ip: self.config.ip,
            port: src_port,
        };
        let remote = SocketAddrV4 {
            ip: dst_ip,
            port: dst_port,
        };
        let tcp_seg_bytes = self.tcp_manager.close(local, remote)?;
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(
            self.config.ip,
            dst_ip,
            IP_PROTO_TCP,
            ip_id,
            64,
            &tcp_seg_bytes,
        );
        self.send_ip_packet(dst_ip, ip_bytes)
    }

    pub fn dhcp_discover(&mut self, xid: u32) -> Vec<u8> {
        let disc = crate::dhcp::DhcpPacket::build_discover(self.config.mac, xid);
        let dhcp_bytes = disc.serialize();
        let udp_bytes = crate::udp::UdpDatagram::serialize(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::BROADCAST,
            68,
            67,
            &dhcp_bytes,
        );
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::BROADCAST,
            IP_PROTO_UDP,
            ip_id,
            64,
            &udp_bytes,
        );
        EthernetFrame::serialize(
            MacAddress::BROADCAST,
            self.config.mac,
            ETHERTYPE_IPV4,
            &ip_bytes,
        )
    }

    pub fn dhcp_request(
        &mut self,
        requested_ip: Ipv4Address,
        server_id: Ipv4Address,
        xid: u32,
    ) -> Vec<u8> {
        let req =
            crate::dhcp::DhcpPacket::build_request(self.config.mac, xid, requested_ip, server_id);
        let dhcp_bytes = req.serialize();
        let udp_bytes = crate::udp::UdpDatagram::serialize(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::BROADCAST,
            68,
            67,
            &dhcp_bytes,
        );
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(
            Ipv4Address::UNSPECIFIED,
            Ipv4Address::BROADCAST,
            IP_PROTO_UDP,
            ip_id,
            64,
            &udp_bytes,
        );
        EthernetFrame::serialize(
            MacAddress::BROADCAST,
            self.config.mac,
            ETHERTYPE_IPV4,
            &ip_bytes,
        )
    }

    pub fn apply_dhcp_ack(&mut self, ack: &crate::dhcp::DhcpPacket) {
        self.config.ip = ack.yiaddr;
        if let Some(mask) = ack.subnet_mask {
            let mask_u32 = mask.to_u32();
            self.config.subnet_mask = mask_u32.count_ones() as u8;
        }
        if let Some(gw) = ack.router {
            self.config.gateway = Some(gw);
        }

        // Rebuild routing table
        let mut rt = RoutingTable::new();
        let subnet_net = self.config.ip.mask(self.config.subnet_mask);
        rt.add_route(subnet_net, self.config.subnet_mask, None, "eth0");
        if let Some(gw) = self.config.gateway {
            rt.add_route(Ipv4Address::UNSPECIFIED, 0, Some(gw), "eth0");
        }
        self.routing_table = rt;
    }

    /// Advances internal simulation timers and generates scheduled/retransmission frames.
    pub fn step_timers(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        self.current_time_ms = now_ms;
        let mut out_frames = Vec::new();
        // Remember whether discovery was already active at the start of this timer
        // pump. If its third solicitation happens to exhaust on the same tick that
        // a default router expires, do not immediately open a fresh discovery cycle
        // and emit a second RS in the same pump.
        let router_discovery_was_active = self.ipv6_router_discovery.is_some();

        // RFC 4861 host Router Discovery sends at most three solicitations, four
        // seconds apart. A coarse simulator time jump emits at most one retry per
        // timer pump and schedules the next interval from the observed current time,
        // avoiding a burst of stale catch-up solicitations.
        if let Some(discovery) = self.ipv6_router_discovery
            && now_ms >= discovery.next_solicitation_ms
        {
            let solicitations_sent = discovery.solicitations_sent.saturating_add(1);
            out_frames.push(self.router_solicitation());
            if solicitations_sent >= IPV6_MAX_RTR_SOLICITATIONS {
                self.ipv6_router_discovery = None;
                self.ipv6_router_discovery_exhausted = true;
            } else {
                self.ipv6_router_discovery = Some(Ipv6RouterDiscovery {
                    solicitations_sent,
                    next_solicitation_ms: now_ms.saturating_add(IPV6_RTR_SOLICITATION_INTERVAL_MS),
                });
            }
        }

        // RFC 4861 Prefix List lifetimes are independent of SLAAC address
        // lifetimes. Expiry returns destinations to normal default-router selection.
        let expired_ra_prefixes: Vec<(Ipv6Address, u8)> = self
            .ipv6_ra_on_link_prefixes
            .iter()
            .filter_map(|(key, deadline)| {
                (*deadline)
                    .is_some_and(|deadline| now_ms >= deadline)
                    .then_some(*key)
            })
            .collect();
        for (prefix, prefix_len) in expired_ra_prefixes {
            self.ipv6_ra_on_link_prefixes.remove(&(prefix, prefix_len));
            self.ipv6_routing_table
                .remove_route(prefix, prefix_len, RouteSource::Ra);
        }

        // A tentative SLAAC address becomes usable only after its DAD interval
        // expires without a conflicting NS/NA.
        if self.ipv6_dad.is_some_and(|dad| now_ms >= dad.deadline_ms) {
            let dad = self.ipv6_dad.take().unwrap();
            let valid = dad.valid_until_ms.is_none_or(|deadline| now_ms < deadline);
            if valid {
                let gateway = dad.gateway.filter(|_| {
                    dad.router_until_ms
                        .is_some_and(|deadline| now_ms < deadline)
                });
                self.configure_ipv6_interface(dad.address, dad.prefix_len, gateway);
                // RFC 5942: SLAAC address assignment does not itself make the
                // address prefix on-link. PIO L-bit state is owned separately.
                self.ipv6_routing_table.remove_route(
                    dad.address,
                    dad.prefix_len,
                    RouteSource::Connected,
                );
                self.ipv6_slaac_lifetimes = Some(Ipv6SlaacLifetimes {
                    address: dad.address,
                    preferred_until_ms: dad.preferred_until_ms,
                    valid_until_ms: dad.valid_until_ms,
                    router: gateway,
                    router_until_ms: gateway.and(dad.router_until_ms),
                });
            }
        }

        let slaac_valid_expired = self
            .ipv6_slaac_lifetimes
            .and_then(|lifetimes| lifetimes.valid_until_ms)
            .is_some_and(|deadline| now_ms >= deadline);
        if slaac_valid_expired {
            self.clear_ipv6_interface();
        } else {
            let router_expired = self
                .ipv6_slaac_lifetimes
                .and_then(|lifetimes| lifetimes.router_until_ms)
                .is_some_and(|deadline| now_ms >= deadline);
            if router_expired {
                self.set_ipv6_default_gateway(None);
                if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {
                    lifetimes.router = None;
                    lifetimes.router_until_ms = None;
                }

                // The SLAAC address/prefix can remain perfectly valid after the
                // selected default router expires. Re-run Router Discovery so the
                // host can refresh that router or discover a replacement instead of
                // remaining indefinitely address-configured but gateway-less.
                //
                // An already active discovery cycle is left untouched. A previously
                // Exhausted cycle, however, represents an older discovery event and
                // is explicitly restarted by this new router-expiry event.
                if !router_discovery_was_active {
                    out_frames.push(self.start_router_discovery());
                }
            }
        }

        // 1. Socket runtime: newly segmented data, retransmissions, FINs, UDP datagrams.
        for tx in self.sockets.step_timers(now_ms) {
            let ip_id = self.next_ip_id();
            let ip_bytes = Ipv4Packet::serialize(
                tx.local.ip,
                tx.remote.ip,
                tx.protocol,
                ip_id,
                64,
                &tx.payload,
            );
            if let Some(frame) = self.send_ip_packet(tx.remote.ip, ip_bytes) {
                out_frames.push(frame);
            }
        }

        // 2. Legacy TcpManager timer pump, kept for the pre-socket TCP demos.
        let legacy_pkts = self.tcp_manager.step_timers(now_ms);
        for (local, remote, tcp_bytes) in legacy_pkts {
            let ip_id = self.next_ip_id();
            let ip_bytes =
                Ipv4Packet::serialize(local.ip, remote.ip, IP_PROTO_TCP, ip_id, 64, &tcp_bytes);
            if let Some(frame) = self.send_ip_packet(remote.ip, ip_bytes) {
                out_frames.push(frame);
            }
        }

        out_frames
    }

    // ==========================================================================
    // Application-facing socket API.
    //
    // Everything below encapsulates transport PDUs in IPv4 and Ethernet on the
    // application's behalf, resolving the next hop through the routing and ARP
    // tables. Applications call only these methods: they never build a segment,
    // datagram, packet, or frame, and never touch `TcpConnection` directly.
    // ==========================================================================

    /// Drains everything the socket runtime wants to transmit at the current simulated
    /// time and returns it as ready-to-send Ethernet frames. Idempotent: calling it with
    /// no pending work returns an empty vector.
    pub fn poll_transmit(&mut self) -> Vec<Vec<u8>> {
        let now = self.current_time_ms;
        self.step_timers(now)
    }

    /// Binds a UDP socket. A port of 0 allocates an ephemeral port.
    pub fn udp_bind(&mut self, port: u16) -> Result<UdpSocketHandle, SocketError> {
        self.sockets.udp_bind(SocketAddrV4 {
            ip: self.config.ip,
            port,
        })
    }

    /// Queues a datagram for transmission to `remote`.
    pub fn udp_send_to(
        &mut self,
        handle: UdpSocketHandle,
        data: &[u8],
        remote: SocketAddrV4,
    ) -> Result<usize, SocketError> {
        self.sockets.udp_send_to(handle, data, remote)
    }

    /// Pops the next received datagram and its sender.
    pub fn udp_recv_from(
        &mut self,
        handle: UdpSocketHandle,
    ) -> Result<(Vec<u8>, SocketAddrV4), SocketError> {
        self.sockets.udp_recv_from(handle)
    }

    /// Closes a UDP socket and releases its port.
    pub fn udp_close(&mut self, handle: UdpSocketHandle) -> Result<(), SocketError> {
        self.sockets.udp_close(handle)
    }

    /// Starts listening for inbound connections on `port`.
    pub fn tcp_listen(&mut self, port: u16) -> Result<TcpListenerHandle, SocketError> {
        self.sockets.tcp_listen(SocketAddrV4 {
            ip: self.config.ip,
            port,
        })
    }

    /// Starts listening on every local address (`0.0.0.0:port`).
    pub fn tcp_listen_any(&mut self, port: u16) -> Result<TcpListenerHandle, SocketError> {
        self.sockets.tcp_listen_any(port)
    }

    /// True while a stream still owns a usable connection.
    pub fn tcp_is_live(&self, handle: TcpStreamHandle) -> bool {
        self.sockets.tcp_is_live(handle)
    }

    /// Pops the next fully or partially established connection from the accept queue.
    /// Returns `WouldBlock` when no connection is pending.
    pub fn tcp_accept(
        &mut self,
        listener: TcpListenerHandle,
    ) -> Result<(TcpStreamHandle, SocketAddrV4), SocketError> {
        self.sockets.tcp_accept(listener)
    }

    /// Stops listening and releases the port.
    pub fn tcp_listener_close(&mut self, listener: TcpListenerHandle) -> Result<(), SocketError> {
        self.sockets.tcp_listener_close(listener)
    }

    /// Opens an active connection from an ephemeral local port. The SYN is queued and
    /// leaves on the next `poll_transmit`.
    pub fn tcp_connect(&mut self, remote: SocketAddrV4) -> Result<TcpStreamHandle, SocketError> {
        self.sockets.tcp_connect(remote)
    }

    /// Opens an active connection from a chosen local port with a chosen ISN. Used by
    /// tests that need a reproducible sequence space, including wraparound scenarios.
    pub fn tcp_connect_from(
        &mut self,
        local_port: u16,
        remote: SocketAddrV4,
        isn: u32,
    ) -> Result<TcpStreamHandle, SocketError> {
        let local = SocketAddrV4 {
            ip: self.config.ip,
            port: local_port,
        };
        self.sockets.tcp_connect_from(local, remote, isn)
    }

    /// Queues application bytes on a stream. Large writes are segmented to the negotiated
    /// MSS by the transport, not by the caller.
    pub fn tcp_write(
        &mut self,
        handle: TcpStreamHandle,
        data: &[u8],
    ) -> Result<usize, SocketError> {
        self.sockets.tcp_write(handle, data)
    }

    /// Reads received stream bytes. `Ok(0)` means end of stream.
    pub fn tcp_read(
        &mut self,
        handle: TcpStreamHandle,
        buf: &mut [u8],
    ) -> Result<usize, SocketError> {
        self.sockets.tcp_read(handle, buf)
    }

    /// Bytes readable on a stream right now.
    pub fn tcp_readable(&self, handle: TcpStreamHandle) -> usize {
        self.sockets.tcp_readable(handle)
    }

    /// Unused send-buffer capacity on a stream, in bytes. `tcp_write` accepts at most this
    /// much and reports a short write beyond it.
    pub fn tcp_writable(&self, handle: TcpStreamHandle) -> usize {
        self.sockets.tcp_writable(handle)
    }

    /// Half-closes the sending direction; the FIN follows any still-queued data.
    pub fn tcp_shutdown(&mut self, handle: TcpStreamHandle) -> Result<(), SocketError> {
        self.sockets.tcp_shutdown(handle)
    }

    /// Closes a stream gracefully.
    pub fn tcp_close(&mut self, handle: TcpStreamHandle) -> Result<(), SocketError> {
        self.sockets.tcp_close(handle)
    }

    /// Current finite-state-machine state of a stream.
    pub fn tcp_state(&self, handle: TcpStreamHandle) -> Result<TcpState, SocketError> {
        self.sockets.tcp_state(handle)
    }

    /// Byte, segment, and recovery counters for a stream.
    pub fn tcp_stats(&self, handle: TcpStreamHandle) -> Result<TcpStats, SocketError> {
        self.sockets.tcp_stats(handle)
    }

    /// Full transport diagnostics for a live stream.
    pub fn tcp_diagnostics(&self, handle: TcpStreamHandle) -> Result<TcpDiagnostics, SocketError> {
        self.sockets.tcp_diagnostics(handle)
    }

    /// Diagnostics for every live connection on this host.
    pub fn tcp_connections(&self) -> Vec<TcpDiagnostics> {
        self.sockets.all_tcp_diagnostics()
    }

    /// Sets the MSS advertised by connections opened after this call.
    pub fn set_tcp_mss(&mut self, mss: u16) {
        self.sockets.set_default_mss(mss);
    }

    /// Primary entry point: process incoming raw Ethernet frame bytes,
    /// demultiplex through all protocol layers, and return any outgoing reply frames.
    pub fn process_frame(&mut self, raw_frame: &[u8]) -> Vec<Vec<u8>> {
        let mut out_frames = Vec::new();

        let eth = match EthernetFrame::parse(raw_frame) {
            Ok(f) => f,
            Err(_) => return out_frames,
        };

        // Filter packets: accept if destination is our MAC or Broadcast / Multicast
        if !eth.dst_mac.is_broadcast()
            && !eth.dst_mac.is_multicast()
            && eth.dst_mac != self.config.mac
        {
            return out_frames;
        }

        match eth.ethertype {
            EtherType::Arp => {
                if let Ok(arp) = ArpPacket::parse(eth.payload) {
                    // Update ARP cache with sender
                    self.arp_table.insert(arp.sender_ip, arp.sender_mac);
                    let sender_ipv4 = Ipv4Address(arp.sender_ip);

                    // Drain any pending IP packets waiting for this ARP resolution
                    if let Some(queued_packets) = self.pending_arp_packets.remove(&sender_ipv4) {
                        for ip_pkt in queued_packets {
                            let eth_out = EthernetFrame::serialize(
                                arp.sender_mac,
                                self.config.mac,
                                ETHERTYPE_IPV4,
                                &ip_pkt,
                            );
                            out_frames.push(eth_out);
                        }
                    }

                    if arp.opcode == ArpOpcode::Request && arp.target_ip == self.config.ip.0 {
                        // Generate ARP Reply
                        let reply = ArpPacket::build_reply(
                            self.config.mac,
                            self.config.ip.0,
                            arp.sender_mac,
                            arp.sender_ip,
                        );
                        let eth_out = EthernetFrame::serialize(
                            arp.sender_mac,
                            self.config.mac,
                            ETHERTYPE_ARP,
                            &reply.serialize(),
                        );
                        out_frames.push(eth_out);
                    }
                }
            }

            EtherType::IPv4 => {
                if let Ok(ip_pkt) = Ipv4Packet::parse(eth.payload, true) {
                    // 1. Evaluate packet against INPUT firewall chain
                    if self.firewall.evaluate(FirewallChain::Input, &ip_pkt)
                        != FirewallAction::Accept
                    {
                        return out_frames; // Dropped by firewall!
                    }

                    // Cache sender MAC for source IP
                    self.arp_table.insert(ip_pkt.header.src_ip.0, eth.src_mac);

                    // Verify destination IP
                    let dst = ip_pkt.header.dst_ip;
                    if dst != self.config.ip && !dst.is_broadcast() && dst != Ipv4Address::BROADCAST
                    {
                        return out_frames;
                    }

                    match ip_pkt.header.protocol {
                        IpProtocol::Icmp => {
                            if let Ok(icmp) = IcmpPacket::parse(ip_pkt.payload, true) {
                                match icmp.icmp_type {
                                    IcmpType::EchoRequest => {
                                        let echo_reply = IcmpPacket::build_echo_reply(&icmp);
                                        let ip_id = self.next_ip_id();
                                        let ip_out = Ipv4Packet::serialize(
                                            self.config.ip,
                                            ip_pkt.header.src_ip,
                                            IP_PROTO_ICMP,
                                            ip_id,
                                            64,
                                            &echo_reply,
                                        );
                                        let eth_out = EthernetFrame::serialize(
                                            eth.src_mac,
                                            self.config.mac,
                                            ETHERTYPE_IPV4,
                                            &ip_out,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                    IcmpType::EchoReply => {
                                        self.received_icmp_replies.push((
                                            ip_pkt.header.src_ip,
                                            icmp.identifier,
                                            icmp.sequence_number,
                                        ));
                                    }
                                    IcmpType::TimeExceeded => {
                                        self.received_icmp_time_exceeded
                                            .push((ip_pkt.header.src_ip, icmp.code));
                                    }
                                    IcmpType::DestinationUnreachable => {
                                        self.received_icmp_unreachable
                                            .push((ip_pkt.header.src_ip, icmp.code));
                                    }
                                    _ => {}
                                }
                            }
                        }

                        IpProtocol::Udp => {
                            if let Ok(udp) = UdpDatagram::parse(
                                ip_pkt.header.src_ip,
                                ip_pkt.header.dst_ip,
                                ip_pkt.payload,
                                true,
                            ) {
                                self.received_udp_payloads.push((
                                    ip_pkt.header.src_ip,
                                    udp.src_port,
                                    udp.dst_port,
                                    udp.payload.to_vec(),
                                ));

                                // DHCP Server processing (port 67)
                                if udp.dst_port == 67 {
                                    let dhcp_reply_data =
                                        if let Some(ref mut srv) = self.dhcp_server {
                                            if let Ok(dhcp_in) =
                                                crate::dhcp::DhcpPacket::parse(udp.payload)
                                            {
                                                srv.handle_packet(&dhcp_in)
                                                    .map(|reply| (reply, srv.server_ip))
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        };

                                    if let Some((dhcp_reply, server_ip)) = dhcp_reply_data {
                                        let dhcp_raw = dhcp_reply.serialize();
                                        let udp_out = UdpDatagram::serialize(
                                            server_ip,
                                            Ipv4Address::BROADCAST,
                                            67,
                                            68,
                                            &dhcp_raw,
                                        );
                                        let ip_id = self.next_ip_id();
                                        let ip_out = Ipv4Packet::serialize(
                                            server_ip,
                                            Ipv4Address::BROADCAST,
                                            IP_PROTO_UDP,
                                            ip_id,
                                            64,
                                            &udp_out,
                                        );
                                        let eth_out = EthernetFrame::serialize(
                                            dhcp_reply.chaddr,
                                            self.config.mac,
                                            ETHERTYPE_IPV4,
                                            &ip_out,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                }

                                // DHCP Client processing (port 68)
                                if udp.dst_port == 68
                                    && let Ok(dhcp_in) = crate::dhcp::DhcpPacket::parse(udp.payload)
                                {
                                    match dhcp_in.msg_type {
                                        crate::dhcp::DhcpMessageType::Offer => {
                                            self.received_dhcp_offers.push(dhcp_in);
                                        }
                                        crate::dhcp::DhcpMessageType::Ack => {
                                            self.received_dhcp_acks.push(dhcp_in);
                                        }
                                        _ => {}
                                    }
                                }

                                // Dispatch into SocketRuntime queues
                                let src_addr = SocketAddrV4 {
                                    ip: ip_pkt.header.src_ip,
                                    port: udp.src_port,
                                };
                                let dst_addr = SocketAddrV4 {
                                    ip: ip_pkt.header.dst_ip,
                                    port: udp.dst_port,
                                };
                                self.sockets.dispatch_udp(src_addr, dst_addr, udp.payload);

                                // Legacy UdpSocketTable dispatch
                                if let Some(resp_payload) = self.udp_sockets.dispatch(
                                    ip_pkt.header.src_ip,
                                    udp.src_port,
                                    udp.dst_port,
                                    udp.payload,
                                ) {
                                    let udp_out = UdpDatagram::serialize(
                                        self.config.ip,
                                        ip_pkt.header.src_ip,
                                        udp.dst_port,
                                        udp.src_port,
                                        &resp_payload,
                                    );
                                    let ip_id = self.next_ip_id();
                                    let ip_out = Ipv4Packet::serialize(
                                        self.config.ip,
                                        ip_pkt.header.src_ip,
                                        IP_PROTO_UDP,
                                        ip_id,
                                        64,
                                        &udp_out,
                                    );
                                    let eth_out = EthernetFrame::serialize(
                                        eth.src_mac,
                                        self.config.mac,
                                        ETHERTYPE_IPV4,
                                        &ip_out,
                                    );
                                    out_frames.push(eth_out);
                                }
                            }
                        }

                        IpProtocol::Tcp => {
                            if let Ok(tcp) = TcpSegment::parse(
                                ip_pkt.header.src_ip,
                                ip_pkt.header.dst_ip,
                                ip_pkt.payload,
                                true,
                            ) {
                                if self.sockets.has_endpoint(
                                    ip_pkt.header.dst_ip,
                                    tcp.dst_port,
                                    ip_pkt.header.src_ip,
                                    tcp.src_port,
                                ) {
                                    let resp_segs = self.sockets.dispatch_tcp_segment(
                                        ip_pkt.header.src_ip,
                                        ip_pkt.header.dst_ip,
                                        &tcp,
                                        self.current_time_ms,
                                    );
                                    for resp_seg in resp_segs {
                                        let ip_id = self.next_ip_id();
                                        let ip_out = Ipv4Packet::serialize(
                                            self.config.ip,
                                            ip_pkt.header.src_ip,
                                            IP_PROTO_TCP,
                                            ip_id,
                                            64,
                                            &resp_seg,
                                        );
                                        let eth_out = EthernetFrame::serialize(
                                            eth.src_mac,
                                            self.config.mac,
                                            ETHERTYPE_IPV4,
                                            &ip_out,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                } else if self.tcp_manager.has_endpoint(
                                    ip_pkt.header.dst_ip,
                                    tcp.dst_port,
                                    ip_pkt.header.src_ip,
                                    tcp.src_port,
                                ) {
                                    if let Some(resp_seg) = self.tcp_manager.process_segment_at(
                                        ip_pkt.header.src_ip,
                                        ip_pkt.header.dst_ip,
                                        &tcp,
                                        self.current_time_ms,
                                    ) {
                                        let ip_id = self.next_ip_id();
                                        let ip_out = Ipv4Packet::serialize(
                                            self.config.ip,
                                            ip_pkt.header.src_ip,
                                            IP_PROTO_TCP,
                                            ip_id,
                                            64,
                                            &resp_seg,
                                        );
                                        let eth_out = EthernetFrame::serialize(
                                            eth.src_mac,
                                            self.config.mac,
                                            ETHERTYPE_IPV4,
                                            &ip_out,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                } else if !tcp.flags.rst {
                                    let rst_seq = if tcp.flags.ack { tcp.ack_num } else { 0 };
                                    let rst_ack = tcp.seq_num.wrapping_add(
                                        if tcp.flags.syn || tcp.flags.fin {
                                            1
                                        } else {
                                            tcp.payload.len() as u32
                                        },
                                    );
                                    let mut flags = crate::tcp::TcpFlags::rst();
                                    if !tcp.flags.ack {
                                        flags.ack = true;
                                    }
                                    let rst_bytes = TcpSegment::serialize(
                                        ip_pkt.header.dst_ip,
                                        ip_pkt.header.src_ip,
                                        tcp.dst_port,
                                        tcp.src_port,
                                        rst_seq,
                                        rst_ack,
                                        flags,
                                        0,
                                        &[],
                                    );
                                    let ip_id = self.next_ip_id();
                                    let ip_out = Ipv4Packet::serialize(
                                        self.config.ip,
                                        ip_pkt.header.src_ip,
                                        IP_PROTO_TCP,
                                        ip_id,
                                        64,
                                        &rst_bytes,
                                    );
                                    let eth_out = EthernetFrame::serialize(
                                        eth.src_mac,
                                        self.config.mac,
                                        ETHERTYPE_IPV4,
                                        &ip_out,
                                    );
                                    out_frames.push(eth_out);
                                }
                            }
                        }

                        _ => {}
                    }
                }
            }

            EtherType::IPv6 => {
                if let Ok(ip6_pkt) = Ipv6Packet::parse(eth.payload) {
                    // Validate Neighbor Discovery before using the source as a
                    // Neighbor Cache hint. In particular, Hop Limit 255 prevents
                    // off-link spoofed NS/NA from influencing local resolution.
                    if ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6 {
                        let raw_type = ip6_pkt.payload.first().copied();
                        match Icmpv6Packet::parse(
                            ip6_pkt.header.src_ip,
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.payload,
                            true,
                        ) {
                            Ok(icmp6) => {
                                let valid = match icmp6.msg_type {
                                    ICMPV6_TYPE_NEIGHBOR_SOLICIT => icmp6
                                        .validated_neighbor_solicitation_target(
                                            ip6_pkt.header.src_ip,
                                            ip6_pkt.header.dst_ip,
                                            ip6_pkt.header.hop_limit,
                                        )
                                        .is_some(),
                                    ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6
                                        .validated_neighbor_advertisement_target(
                                            ip6_pkt.header.dst_ip,
                                            ip6_pkt.header.hop_limit,
                                        )
                                        .is_some(),
                                    _ => true,
                                };
                                if !valid {
                                    return out_frames;
                                }
                            }
                            Err(_)
                                if matches!(
                                    raw_type,
                                    Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                        | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
                                ) =>
                            {
                                return out_frames;
                            }
                            Err(_) => {}
                        }
                    }

                    // The unspecified source is used by DAD and is never a
                    // neighbour-cache key (RFC 4861/4862).
                    if !ip6_pkt.header.src_ip.is_unspecified() {
                        self.ndp_table.insert(ip6_pkt.header.src_ip, eth.src_mac);
                    }

                    let my_ip6 = self.config.ipv6.unwrap_or(Ipv6Address::LOOPBACK);
                    let dst6 = ip6_pkt.header.dst_ip;

                    let is_for_me = dst6 == my_ip6
                        || dst6.is_multicast()
                        || dst6 == Ipv6Address::LINK_LOCAL_ALL_NODES;
                    if !is_for_me {
                        return out_frames;
                    }

                    if ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6
                        && let Ok(icmp6) = Icmpv6Packet::parse(
                            ip6_pkt.header.src_ip,
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.payload,
                            true,
                        )
                    {
                        match icmp6.msg_type {
                            ICMPV6_TYPE_PACKET_TOO_BIG => {
                                // RFC 8201: learn only from a syntactically valid PTB
                                // that quotes a packet this host actually originated.
                                // PTB can only lower an estimate; upward probing is an
                                // explicit lifecycle event via clear_ipv6_path_mtu().
                                if icmp6.code == 0 && icmp6.payload.len() >= 44 {
                                    let advertised_mtu = u32::from_be_bytes([
                                        icmp6.payload[0],
                                        icmp6.payload[1],
                                        icmp6.payload[2],
                                        icmp6.payload[3],
                                    ]);
                                    let quoted = &icmp6.payload[4..];
                                    if quoted[0] >> 4 == 6 {
                                        let mut quoted_src = [0u8; 16];
                                        quoted_src.copy_from_slice(&quoted[8..24]);
                                        let mut quoted_dst = [0u8; 16];
                                        quoted_dst.copy_from_slice(&quoted[24..40]);
                                        let quoted_src = Ipv6Address(quoted_src);
                                        let quoted_dst = Ipv6Address(quoted_dst);
                                        if self.config.ipv6 == Some(quoted_src)
                                            && !quoted_dst.is_multicast()
                                        {
                                            // This deterministic lab models only legal
                                            // IPv6 links, whose MTU is at least 1280.
                                            let learned = advertised_mtu.max(1280);
                                            self.ipv6_path_mtu_cache
                                                .entry(quoted_dst)
                                                .and_modify(|current| {
                                                    *current = (*current).min(learned);
                                                })
                                                .or_insert(learned);
                                        }
                                    }
                                }
                            }

                            ICMPV6_TYPE_ROUTER_ADVERT => {
                                if ip6_pkt.header.hop_limit == 255
                                    && ip6_pkt.header.src_ip.is_link_local()
                                    && let Some(ra) = RouterAdvertisement::parse(&icmp6)
                                {
                                    // Any valid RA is a Router Discovery response, even
                                    // when Router Lifetime is zero or no autonomous prefix
                                    // is present. Invalid RAs never cancel retransmission.
                                    self.cancel_router_discovery();
                                    self.refresh_slaac_default_router(
                                        ip6_pkt.header.src_ip,
                                        ra.router_lifetime,
                                    );

                                    // RFC 4861 section 6.3.4: L and A are independent.
                                    // Only L=1 updates the Prefix List; L=0 makes no
                                    // on-link/off-link statement and therefore cannot
                                    // withdraw or refresh prior on-link knowledge.
                                    for prefix in ra.prefixes.iter().filter(|prefix| {
                                        prefix.on_link && !prefix.prefix.is_link_local()
                                    }) {
                                        self.refresh_ipv6_ra_on_link_prefix(
                                            prefix.prefix,
                                            prefix.prefix_length,
                                            prefix.valid_lifetime,
                                        );
                                    }

                                    if let Some(prefix) = ra.prefixes.iter().find(|prefix| {
                                        prefix.autonomous && prefix.prefix_length == 64
                                    }) && let Some(address) = slaac_address(
                                        prefix.prefix,
                                        prefix.prefix_length,
                                        self.config.mac,
                                    ) {
                                        let gateway = (ra.router_lifetime > 0)
                                            .then_some(ip6_pkt.header.src_ip);
                                        let now_ms = self.current_time_ms;
                                        if self.config.ipv6 == Some(address) {
                                            let old_valid = self
                                                .ipv6_slaac_lifetimes
                                                .filter(|lifetimes| lifetimes.address == address)
                                                .map(|lifetimes| lifetimes.valid_until_ms);
                                            let valid_until_ms = old_valid.map_or_else(
                                                || {
                                                    ipv6_lifetime_deadline(
                                                        now_ms,
                                                        prefix.valid_lifetime,
                                                    )
                                                },
                                                |current| {
                                                    refreshed_ipv6_valid_deadline(
                                                        now_ms,
                                                        current,
                                                        prefix.valid_lifetime,
                                                    )
                                                },
                                            );
                                            let preferred_until_ms = ipv6_lifetime_deadline(
                                                now_ms,
                                                prefix.preferred_lifetime,
                                            );
                                            let router = if ra.router_lifetime > 0 {
                                                Some(ip6_pkt.header.src_ip)
                                            } else {
                                                None
                                            };
                                            let router_until_ms = router.map(|_| {
                                                now_ms.saturating_add(
                                                    (ra.router_lifetime as u64)
                                                        .saturating_mul(1_000),
                                                )
                                            });
                                            self.ipv6_slaac_lifetimes = Some(Ipv6SlaacLifetimes {
                                                address,
                                                preferred_until_ms,
                                                valid_until_ms,
                                                router,
                                                router_until_ms,
                                            });
                                        } else if let Some(dad_probe) = self.start_ipv6_dad(
                                            address,
                                            prefix.prefix_length,
                                            gateway,
                                            prefix.preferred_lifetime,
                                            prefix.valid_lifetime,
                                            ra.router_lifetime,
                                        ) {
                                            out_frames.push(dad_probe);
                                        }
                                    }
                                }
                            }

                            ICMPV6_TYPE_ECHO_REQUEST => {
                                if icmp6.payload.len() >= 4 {
                                    let id =
                                        u16::from_be_bytes([icmp6.payload[0], icmp6.payload[1]]);
                                    let seq =
                                        u16::from_be_bytes([icmp6.payload[2], icmp6.payload[3]]);
                                    let echo_reply = Icmpv6Packet::build_echo_reply(
                                        my_ip6,
                                        ip6_pkt.header.src_ip,
                                        id,
                                        seq,
                                        &icmp6.payload[4..],
                                    );
                                    let ip6_out = Ipv6Packet::serialize(
                                        my_ip6,
                                        ip6_pkt.header.src_ip,
                                        NEXT_HEADER_ICMPV6,
                                        64,
                                        &echo_reply,
                                    );
                                    let eth_out = EthernetFrame::serialize(
                                        eth.src_mac,
                                        self.config.mac,
                                        ETHERTYPE_IPV6,
                                        &ip6_out,
                                    );
                                    out_frames.push(eth_out);
                                }
                            }

                            ICMPV6_TYPE_ECHO_REPLY => {
                                if icmp6.payload.len() >= 4 {
                                    let id =
                                        u16::from_be_bytes([icmp6.payload[0], icmp6.payload[1]]);
                                    let seq =
                                        u16::from_be_bytes([icmp6.payload[2], icmp6.payload[3]]);
                                    self.received_icmpv6_replies.push((
                                        ip6_pkt.header.src_ip,
                                        id,
                                        seq,
                                    ));
                                }
                            }

                            ICMPV6_TYPE_NEIGHBOR_SOLICIT => {
                                if let Some(target_ip6) = icmp6
                                    .validated_neighbor_solicitation_target(
                                        ip6_pkt.header.src_ip,
                                        ip6_pkt.header.dst_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                {
                                    // A competing DAD probe for our tentative target is
                                    // itself evidence that the address is not unique.
                                    if eth.src_mac != self.config.mac
                                        && self
                                            .ipv6_dad
                                            .is_some_and(|dad| dad.address == target_ip6)
                                    {
                                        self.mark_ipv6_dad_duplicate(target_ip6);
                                    }

                                    if target_ip6 == my_ip6 {
                                        let dad_probe = ip6_pkt.header.src_ip.is_unspecified();
                                        let reply_dst = if dad_probe {
                                            Ipv6Address::LINK_LOCAL_ALL_NODES
                                        } else {
                                            ip6_pkt.header.src_ip
                                        };
                                        let na = Icmpv6Packet::build_neighbor_advertisement(
                                            my_ip6,
                                            reply_dst,
                                            my_ip6,
                                            self.config.mac,
                                            false,
                                            !dad_probe,
                                            true,
                                        );
                                        let ip6_out = Ipv6Packet::serialize(
                                            my_ip6,
                                            reply_dst,
                                            NEXT_HEADER_ICMPV6,
                                            255,
                                            &na,
                                        );
                                        let dst_mac = if dad_probe {
                                            ipv6_multicast_mac(reply_dst)
                                                .unwrap_or(MacAddress::BROADCAST)
                                        } else {
                                            eth.src_mac
                                        };
                                        let eth_out = EthernetFrame::serialize(
                                            dst_mac,
                                            self.config.mac,
                                            ETHERTYPE_IPV6,
                                            &ip6_out,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                }
                            }

                            ICMPV6_TYPE_NEIGHBOR_ADVERT => {
                                let Some(target_ip6) = icmp6
                                    .validated_neighbor_advertisement_target(
                                        ip6_pkt.header.dst_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                else {
                                    return out_frames;
                                };

                                if eth.src_mac != self.config.mac
                                    && self.ipv6_dad.is_some_and(|dad| dad.address == target_ip6)
                                {
                                    self.mark_ipv6_dad_duplicate(target_ip6);
                                }

                                if let Some(queued_packets) =
                                    self.pending_ndp_packets.remove(&target_ip6)
                                {
                                    for ip6_pkt_data in queued_packets {
                                        let eth_out = EthernetFrame::serialize(
                                            eth.src_mac,
                                            self.config.mac,
                                            ETHERTYPE_IPV6,
                                            &ip6_pkt_data,
                                        );
                                        out_frames.push(eth_out);
                                    }
                                }
                            }

                            _ => {}
                        }
                    }
                }
            }

            _ => {}
        }

        out_frames
    }
}
