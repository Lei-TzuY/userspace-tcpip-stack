//! Integrated Deterministic Virtual Network Lab.
//!
//! Provides a complete in-process virtual networking testbed supporting:
//! - Multi-node, multi-subnet topologies with virtual links, switches, and routers
//! - Deterministic link fault injection (MTU limits, packet drops, byte corruption, packet reordering)
//! - Multi-interface IPv4 routing, TTL decrementing, and ICMP Time Exceeded generation
//! - Full dual-stack protocol operation (Ethernet, ARP, IPv4, IPv6, ICMP, ICMPv6, NDP, UDP, TCP)
//! - Integrated PCAP capture tap per link with Wireshark compatibility
//! - Discrete event stepping, simulated logical clock advancement, and run-to-quiescence simulation

use crate::arp::{ArpOpcode, ArpPacket, ArpTable};
use crate::bgp::Ipv4Prefix;
use crate::bgp_caps::AfiSafi;
use crate::bgp_evpn::RouteTarget;
use crate::bgp_router::{BgpPeerMode, BgpRouter};
use crate::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_MPLS, EtherType, EthernetFrame,
    MacAddress,
};
use crate::evpn::RouteDistinguisher;
use crate::evpn_vtep::{OverlayDecision, Vtep};
use crate::firewall::{Firewall, FirewallAction, FirewallChain};
use crate::icmp::{IcmpPacket, IcmpType};
use crate::icmpv6::{
    ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable,
    PrefixInformationOption, ipv6_multicast_mac, link_local_address,
};
use crate::ipv4::{IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use crate::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use crate::mpls::{LfibAction, LfibTable, MplsHeader, MplsPacket};
use crate::nat::NatTable;
use crate::ospf::OspfLsdb;
use crate::pcap::{LINKTYPE_ETHERNET, PcapWriter};
use crate::rip::{RIP_PORT, RipEngine, RipPacket};
use crate::router::{RouteSource, RoutingTable};
use crate::router_ipv6::Ipv6RoutingTable;
use crate::socket::SocketRuntime;
use crate::stack::{NetStack, NetStackConfig};
use crate::tcp::TcpSegment;
use crate::udp::UdpDatagram;
use crate::vxlan::{VXLAN_UDP_PORT, VxlanPacket};
use std::collections::{HashMap, HashSet};

/// Fault injection configuration and frame accounting for a virtual point-to-point or broadcast link.
#[derive(Debug)]
pub struct VirtualLink {
    pub name: String,
    pub mtu: usize,
    pub drop_packet_indices: Vec<usize>,
    pub corrupt_packet_indices: Vec<usize>,
    pub reorder_packet_indices: Vec<(usize, usize)>, // (hold_index, release_after_index)
    pub held_frames: Vec<(usize, Vec<u8>)>,
    pub total_packets_seen: usize,
    pub frames_forwarded: usize,
    pub frames_dropped: usize,
    pub frames_corrupted: usize,
    pub in_flight_frames: Vec<Vec<u8>>,
    pub pcap_writer: Option<PcapWriter<Vec<u8>>>,
    /// When set, every frame entering the link is discarded. Models a cable cut or a
    /// far-side outage, which is how a live protocol session is made to fail without
    /// anyone reaching into the protocol state.
    pub blackhole: bool,
}

impl VirtualLink {
    pub fn new(name: &str) -> Self {
        VirtualLink {
            name: name.to_string(),
            mtu: 1500,
            drop_packet_indices: Vec::new(),
            corrupt_packet_indices: Vec::new(),
            reorder_packet_indices: Vec::new(),
            held_frames: Vec::new(),
            total_packets_seen: 0,
            frames_forwarded: 0,
            frames_dropped: 0,
            frames_corrupted: 0,
            in_flight_frames: Vec::new(),
            pcap_writer: None,
            blackhole: false,
        }
    }

    /// Cuts (or restores) the link. A blackholed link silently drops everything, so
    /// peers on it stop hearing each other and their hold timers eventually expire.
    pub fn set_blackhole(&mut self, down: bool) {
        self.blackhole = down;
    }

    pub fn with_mtu(mut self, mtu: usize) -> Self {
        self.mtu = mtu;
        self
    }

    pub fn with_drop_indices(mut self, indices: &[usize]) -> Self {
        self.drop_packet_indices.extend_from_slice(indices);
        self
    }

    pub fn with_corrupt_indices(mut self, indices: &[usize]) -> Self {
        self.corrupt_packet_indices.extend_from_slice(indices);
        self
    }

    /// Enables continuous PCAP capture tap on this link.
    pub fn enable_pcap(&mut self) {
        let buffer = Vec::new();
        let writer = PcapWriter::new(buffer, 65535, LINKTYPE_ETHERNET).expect("PcapWriter init");
        self.pcap_writer = Some(writer);
    }

    pub fn take_pcap_bytes(&mut self) -> Option<Vec<u8>> {
        self.pcap_writer.as_ref().map(|w| w.get_ref().clone())
    }

    /// Configures deterministic link MTU limit in bytes.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }

    /// Adds zero-indexed packet numbers that must be dropped.
    pub fn drop_packet_indices(&mut self, indices: &[usize]) {
        self.drop_packet_indices.extend_from_slice(indices);
    }

    /// Adds zero-indexed packet numbers whose payloads must be corrupted with bit inversion.
    pub fn corrupt_packet_indices(&mut self, indices: &[usize]) {
        self.corrupt_packet_indices.extend_from_slice(indices);
    }

    /// Processes a frame attempting to cross this link, returning all delivered frames.
    pub fn process_frames_transit(&mut self, mut raw_frame: Vec<u8>) -> Vec<Vec<u8>> {
        self.total_packets_seen += 1;
        let pkt_index = self.total_packets_seen;
        let mut delivered = Vec::new();

        // Check hold/reorder rule: (hold_idx, release_after_idx)
        for &(hold_idx, release_after) in &self.reorder_packet_indices {
            if pkt_index == hold_idx {
                self.held_frames.push((release_after, raw_frame));
                return delivered; // Held for reordering
            }
        }

        // 0. A cut link swallows everything.
        if self.blackhole {
            self.frames_dropped += 1;
            return delivered;
        }

        // 1. Check MTU
        if raw_frame.len() > self.mtu + 14 {
            // Frame payload + Ethernet header exceeds link capacity
            self.frames_dropped += 1;
            return delivered;
        }

        // 2. Check deterministic drop rule
        if self.drop_packet_indices.contains(&pkt_index) {
            self.frames_dropped += 1;
            return delivered;
        }

        // 3. Check deterministic corruption rule
        if self.corrupt_packet_indices.contains(&pkt_index) && raw_frame.len() > 20 {
            let corrupt_pos = raw_frame.len() - 1;
            raw_frame[corrupt_pos] ^= 0xFF;
            self.frames_corrupted += 1;
        }

        // 4. Capture in PCAP tap if enabled
        if let Some(ref mut writer) = self.pcap_writer {
            let ts_sec = (pkt_index as u32) / 10;
            let ts_usec = ((pkt_index as u32) % 10) * 100_000;
            let _ = writer.write_packet(ts_sec, ts_usec, &raw_frame);
        }

        self.frames_forwarded += 1;
        delivered.push(raw_frame);

        // Check if any held frames should now be released
        let mut remaining_held = Vec::new();
        for (release_after, held_frame) in std::mem::take(&mut self.held_frames) {
            if pkt_index == release_after {
                if let Some(ref mut writer) = self.pcap_writer {
                    let ts_sec = (pkt_index as u32) / 10;
                    let ts_usec = ((pkt_index as u32) % 10) * 100_000 + 50_000;
                    let _ = writer.write_packet(ts_sec, ts_usec, &held_frame);
                }
                self.frames_forwarded += 1;
                delivered.push(held_frame);
            } else {
                remaining_held.push((release_after, held_frame));
            }
        }
        self.held_frames = remaining_held;

        delivered
    }

    /// Single frame transit helper for legacy compatibility.
    pub fn process_frame_transit(&mut self, raw_frame: Vec<u8>) -> Option<Vec<u8>> {
        self.process_frames_transit(raw_frame).into_iter().next()
    }

    /// Enqueues a raw frame onto the virtual link for propagation.
    pub fn push_frame(&mut self, frame: Vec<u8>) {
        if let Some(delivered) = self.process_frame_transit(frame) {
            self.in_flight_frames.push(delivered);
        }
    }

    /// Drains all currently queued frames on the link.
    pub fn drain_frames(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.in_flight_frames)
    }
}

/// Simulated Host endpoint running a NetStack attached to a virtual link.
pub struct LabHost {
    pub name: String,
    pub link_name: String,
    pub stack: NetStack,
}

impl LabHost {
    pub fn new(name: &str, link_name: &str, config: NetStackConfig) -> Self {
        LabHost {
            name: name.to_string(),
            link_name: link_name.to_string(),
            stack: NetStack::new(config),
        }
    }
}

/// Single network interface on a virtual router.
#[derive(Debug, Clone)]
pub struct RouterInterface {
    pub name: String,
    pub mac: MacAddress,
    pub ip: Ipv4Address,
    pub subnet_mask: u8,
    /// Optional IPv6 address and prefix length on the same physical interface.
    pub ipv6: Option<(Ipv6Address, u8)>,
    pub link_name: String,
}

/// A multi-interface Router node with hardware-like packet forwarding, TTL decrementing,
/// NAT translation (SNAT & DNAT), dynamic routing (RIPv2 & OSPFv2), stateful firewalling,
/// VXLAN overlay bridging, MPLS label switching, and ICMP error generation.
pub struct LabRouter {
    pub name: String,
    pub interfaces: Vec<RouterInterface>,
    pub routing_table: RoutingTable,
    pub ipv6_routing_table: Ipv6RoutingTable,
    pub arp_tables: HashMap<String, ArpTable>,
    pub ndp_tables: HashMap<String, NdpTable>,
    pub pending_transit_packets: HashMap<(String, Ipv4Address), Vec<Vec<u8>>>,
    pub pending_ipv6_transit_packets: HashMap<(String, Ipv6Address), Vec<Vec<u8>>>,
    ipv6_interface_mtu: HashMap<String, u32>,
    pub nat_table: Option<NatTable>,
    pub nat_lan_iface: Option<String>,
    pub nat_wan_iface: Option<String>,
    pub rip_engine: Option<RipEngine>,
    pub firewall: Option<Firewall>,
    pub vxlan_tunnels: HashMap<String, (u32, Ipv4Address, String)>,
    pub vxlan_vni_to_access: HashMap<u32, String>,
    pub ospf_lsdb: Option<OspfLsdb>,
    pub lfib: Option<LfibTable>,
    pub mpls_push_routes: HashMap<Ipv4Address, (u32, String)>,
    pub ip_id_counter: u16,
    /// Transport endpoint table for traffic the router itself terminates. Present only
    /// once a control-plane protocol that needs sockets (currently BGP) is enabled.
    pub sockets: Option<SocketRuntime>,
    /// The BGP-4 speaker running on this router, if configured.
    pub bgp: Option<BgpRouter>,
    /// The VXLAN tunnel endpoint driven by MP-BGP EVPN, if this router is a leaf.
    /// Distinct from `vxlan_tunnels`, which is the older statically configured
    /// point-to-point overlay and stays available for topologies that use it.
    pub vtep: Option<Vtep>,
    /// Simulated clock, advanced by the lab.
    pub current_time_ms: u64,
}

/// RFC 4443 section 2.4(e) suppression rules shared by router-generated
/// ICMPv6 errors. The simulator cannot identify anycast sources, but it can
/// reject the explicitly non-unique unspecified and multicast source forms.
///
/// Packet Too Big (and Parameter Problem Code 2, if added later) are the only
/// error classes allowed in response to IPv6/link-layer multicast traffic, so
/// callers opt into that exception explicitly.
fn should_send_icmpv6_error(
    invoking: &Ipv6Packet<'_>,
    link_destination: MacAddress,
    allow_multicast_exception: bool,
) -> bool {
    if invoking.header.src_ip.is_unspecified() || invoking.header.src_ip.is_multicast() {
        return false;
    }

    let invoking_is_icmpv6_error = invoking.header.next_header == NEXT_HEADER_ICMPV6
        && invoking
            .payload
            .first()
            .is_some_and(|msg_type| *msg_type < 128);
    if invoking_is_icmpv6_error {
        return false;
    }

    allow_multicast_exception
        || (!invoking.header.dst_ip.is_multicast() && link_destination.is_unicast())
}

impl LabRouter {
    pub fn new(name: &str) -> Self {
        LabRouter {
            name: name.to_string(),
            interfaces: Vec::new(),
            routing_table: RoutingTable::new(),
            ipv6_routing_table: Ipv6RoutingTable::new(),
            arp_tables: HashMap::new(),
            ndp_tables: HashMap::new(),
            pending_transit_packets: HashMap::new(),
            pending_ipv6_transit_packets: HashMap::new(),
            ipv6_interface_mtu: HashMap::new(),
            nat_table: None,
            nat_lan_iface: None,
            nat_wan_iface: None,
            rip_engine: None,
            firewall: None,
            vxlan_tunnels: HashMap::new(),
            vxlan_vni_to_access: HashMap::new(),
            ospf_lsdb: None,
            lfib: None,
            mpls_push_routes: HashMap::new(),
            ip_id_counter: 100,
            sockets: None,
            bgp: None,
            vtep: None,
            current_time_ms: 0,
        }
    }

    /// Gives this router a transport endpoint table so it can terminate TCP and UDP
    /// addressed to its own interfaces, not merely forward through them.
    pub fn enable_sockets(&mut self) -> &mut SocketRuntime {
        if self.sockets.is_none() {
            let default_ip = self
                .interfaces
                .first()
                .map(|i| i.ip)
                .unwrap_or(Ipv4Address::UNSPECIFIED);
            self.sockets = Some(SocketRuntime::new(default_ip));
        }
        self.sockets.as_mut().unwrap()
    }

    /// Starts a BGP-4 speaker on this router. It listens on TCP port 179 across every
    /// interface and installs its selected routes into this router's real routing table.
    pub fn enable_bgp(&mut self, local_as: u32, router_id: Ipv4Address) -> &mut BgpRouter {
        self.enable_sockets();
        self.bgp = Some(BgpRouter::new(local_as, router_id));
        self.bgp.as_mut().unwrap()
    }

    /// Configures a BGP neighbour reachable through `local_addr`, one of this router's
    /// own interface addresses.
    pub fn add_bgp_peer(
        &mut self,
        peer_ip: Ipv4Address,
        peer_as: u32,
        local_addr: Ipv4Address,
        mode: BgpPeerMode,
    ) {
        if let Some(ref mut bgp) = self.bgp {
            bgp.add_peer(peer_ip, peer_as, local_addr, mode);
        }
    }

    /// Marks a configured neighbour as a route reflector client (RFC 4456).
    ///
    /// The role is what turns an ordinary iBGP speaker into a reflector; nothing
    /// about the topology implies it.
    pub fn set_bgp_route_reflector_client(&mut self, peer_ip: Ipv4Address, on: bool) -> bool {
        self.bgp
            .as_mut()
            .map(|b| b.set_route_reflector_client(peer_ip, on))
            .unwrap_or(false)
    }

    /// Sets the CLUSTER_LIST identifier this speaker prepends when it reflects.
    /// Two reflectors serving one set of clients should share it.
    pub fn set_bgp_cluster_id(&mut self, id: Ipv4Address) {
        if let Some(b) = self.bgp.as_mut() {
            b.set_cluster_id(id);
        }
    }

    /// Turns this speaker into an EVPN route reflector: it offers the L2VPN EVPN
    /// family so its clients can negotiate it, but configures no VTEP, no VNI and
    /// no import Route Target, so it can never become a tenant forwarding endpoint.
    pub fn enable_evpn_control_plane_only(&mut self) {
        if let Some(b) = self.bgp.as_mut() {
            b.enable_family(AfiSafi::L2VPN_EVPN);
        }
    }

    /// Originates a prefix into BGP from this router. The advertised next hop defaults
    /// to the interface address inside the prefix, falling back to the first interface.
    pub fn originate_bgp_prefix(&mut self, prefix: Ipv4Prefix) {
        let next_hop = self
            .interfaces
            .iter()
            .find(|i| prefix.contains(i.ip))
            .map(|i| i.ip)
            .or_else(|| self.interfaces.first().map(|i| i.ip))
            .unwrap_or(Ipv4Address::UNSPECIFIED);
        if let Some(ref mut bgp) = self.bgp {
            bgp.originate(prefix, next_hop);
        }
    }

    /// Administratively shuts a BGP neighbour down: NOTIFICATION, TCP teardown, and
    /// removal of every route learned from it.
    pub fn bgp_shutdown_peer(&mut self, peer_ip: Ipv4Address) {
        let now = self.current_time_ms;
        if let (Some(bgp), Some(sockets)) = (self.bgp.as_mut(), self.sockets.as_mut()) {
            bgp.shutdown_peer(peer_ip, now, sockets);
        }
    }

    /// Re-enables a neighbour that was administratively shut down.
    pub fn bgp_enable_peer(&mut self, peer_ip: Ipv4Address) {
        if let Some(ref mut bgp) = self.bgp {
            bgp.enable_peer(peer_ip);
        }
    }

    /// Stops originating a prefix, which propagates as a withdrawal.
    pub fn withdraw_bgp_prefix(&mut self, prefix: Ipv4Prefix) -> bool {
        self.bgp
            .as_mut()
            .map(|b| b.withdraw_originated(prefix))
            .unwrap_or(false)
    }

    pub fn bgp(&self) -> Option<&BgpRouter> {
        self.bgp.as_ref()
    }

    pub fn bgp_mut(&mut self) -> Option<&mut BgpRouter> {
        self.bgp.as_mut()
    }

    // ========================================================================
    // EVPN / VXLAN tunnel endpoint
    // ========================================================================

    /// Turns this router into a VXLAN tunnel endpoint driven by MP-BGP EVPN.
    ///
    /// `source_ip` is the address every VXLAN packet is sent from and the next
    /// hop this leaf advertises in its own EVPN routes, so it has to be an
    /// address the other leaves can route to. Enabling a VTEP also puts L2VPN
    /// EVPN into the capability set the BGP speaker offers, because a leaf with
    /// no EVPN capability could never learn a remote MAC.
    pub fn enable_vtep(&mut self, source_ip: Ipv4Address, underlay_iface: &str) -> &mut Vtep {
        self.vtep = Some(Vtep::new(source_ip, underlay_iface));
        if let Some(bgp) = self.bgp.as_mut() {
            bgp.enable_family(AfiSafi::L2VPN_EVPN);
        }
        self.vtep.as_mut().unwrap()
    }

    /// Configures a tenant EVPN instance on this VTEP.
    ///
    /// The import Route Targets are registered with the BGP speaker at the same
    /// time. That is what makes the Adj-RIB-In filter and the instance agree:
    /// a route no instance here asked for is dropped before it is even stored.
    pub fn add_evpn_instance(
        &mut self,
        vni: u32,
        rd: RouteDistinguisher,
        import_rts: &[RouteTarget],
        export_rts: &[RouteTarget],
    ) -> bool {
        let added = match self.vtep.as_mut() {
            Some(vtep) => vtep.add_instance(vni, rd, import_rts, export_rts),
            None => false,
        };
        // Only register the import targets if the instance actually exists.
        // Importing on behalf of an instance that was refused would fill the
        // Adj-RIB-In with routes nothing could ever program.
        if added && let Some(bgp) = self.bgp.as_mut() {
            for rt in import_rts {
                bgp.add_import_route_target(*rt);
            }
        }
        added
    }

    /// Puts one of this router's interfaces into a tenant instance as an access
    /// port. Frames arriving there are tenant traffic, not underlay traffic.
    pub fn attach_evpn_access_port(&mut self, vni: u32, iface: &str) {
        if let Some(vtep) = self.vtep.as_mut() {
            vtep.attach_access_port(vni, iface);
        }
    }

    pub fn vtep(&self) -> Option<&Vtep> {
        self.vtep.as_ref()
    }

    pub fn vtep_mut(&mut self) -> Option<&mut Vtep> {
        self.vtep.as_mut()
    }

    /// Pushes what the VTEP has learned locally into the BGP speaker as EVPN
    /// routes, and stops originating anything it no longer knows about.
    ///
    /// The originated set is made to equal the VTEP's view rather than being
    /// appended to, so a host that disappears withdraws itself.
    fn sync_evpn_origination(&mut self) {
        let Some(vtep) = self.vtep.as_ref() else {
            return;
        };
        let desired = vtep.routes_to_originate();
        let Some(bgp) = self.bgp.as_mut() else {
            return;
        };

        let desired_keys: HashSet<_> = desired.iter().map(|r| r.key()).collect();
        let stale: Vec<_> = bgp
            .evpn_originated_routes()
            .iter()
            .map(|r| r.key())
            .filter(|k| !desired_keys.contains(k))
            .collect();
        for key in stale {
            bgp.withdraw_evpn(&key);
        }
        for route in desired {
            bgp.originate_evpn(route);
        }
    }

    /// Rebuilds the VTEP's remote forwarding state from the EVPN Loc-RIB.
    ///
    /// The VTEP is moved out for the duration so the speaker can be borrowed
    /// immutably at the same time; cloning the Loc-RIB on every poll instead
    /// would make a steady state cost work proportional to its size.
    fn program_vtep_from_bgp(&mut self) {
        let Some(mut vtep) = self.vtep.take() else {
            return;
        };
        let withdraw = match self.bgp.as_ref() {
            Some(bgp) => vtep.program_from_rib(&bgp.evpn_loc_rib),
            None => Vec::new(),
        };
        self.vtep = Some(vtep);

        // A host that turned up behind another VTEP with a higher mobility
        // sequence is no longer ours to advertise.
        if !withdraw.is_empty()
            && let Some(bgp) = self.bgp.as_mut()
        {
            for key in withdraw {
                bgp.withdraw_evpn(&key);
            }
        }
    }

    /// Runs this router's control plane and transport timers at simulated time `now_ms`
    /// and returns `(egress_link, frame)` pairs for everything it wants to transmit.
    ///
    /// Order matters: the BGP speaker runs first so anything it decides to send is
    /// queued before the socket runtime drains its transmit path in the same step.
    pub fn step_timers(&mut self, now_ms: u64) -> Vec<(String, Vec<u8>)> {
        self.current_time_ms = now_ms;
        let mut out = Vec::new();

        // IPv6 Neighbor Unreachability Detection is a data-plane timer and must run
        // even on routers that do not terminate sockets or run a control plane.
        // Each interface owns an independent Neighbor Cache, so probes leave on the
        // same link and with the same source address that owns the cached mapping.
        let ndp_interfaces: Vec<String> = self.ndp_tables.keys().cloned().collect();
        for interface_name in ndp_interfaces {
            let probes = self
                .ndp_tables
                .get_mut(&interface_name)
                .map(|table| table.step_nud(now_ms))
                .unwrap_or_default();
            if probes.is_empty() {
                continue;
            }
            let Some(interface) = self
                .interfaces
                .iter()
                .find(|iface| iface.name == interface_name)
                .cloned()
            else {
                continue;
            };
            let Some((source, _)) = interface.ipv6 else {
                continue;
            };
            for (target, dst_mac) in probes {
                let ns = Icmpv6Packet::build_neighbor_solicitation(
                    source,
                    target,
                    target,
                    interface.mac,
                );
                let packet = Ipv6Packet::serialize(source, target, NEXT_HEADER_ICMPV6, 255, &ns);
                out.push((
                    interface.link_name.clone(),
                    EthernetFrame::serialize(dst_mac, interface.mac, ETHERTYPE_IPV6, &packet),
                ));
            }
        }

        if self.sockets.is_none() {
            return out;
        }

        // Local MAC learning becomes EVPN origination before the speaker runs, so
        // a host that appeared since the last step is advertised in this poll
        // rather than the next one.
        self.sync_evpn_origination();

        if let (Some(bgp), Some(sockets)) = (self.bgp.as_mut(), self.sockets.as_mut()) {
            bgp.poll_with_ipv6_fib(
                now_ms,
                sockets,
                &mut self.routing_table,
                &mut self.ipv6_routing_table,
            );
        }

        // ...and whatever the speaker decided is programmed into the data plane
        // immediately afterwards, so the overlay never lags the control plane by
        // a whole simulation step.
        self.program_vtep_from_bgp();

        let pending = match self.sockets.as_mut() {
            Some(s) => s.step_timers(now_ms),
            None => Vec::new(),
        };
        for tx in pending {
            let frames =
                self.emit_from_local_stack(tx.local.ip, tx.remote.ip, tx.protocol, &tx.payload);
            out.extend(frames);
        }
        out
    }

    /// Encapsulates a transport PDU this router originated in IPv4 and Ethernet,
    /// resolving the egress interface through its own routing table and ARP cache.
    /// Unresolved next hops queue the packet and emit an ARP request, exactly as the
    /// transit forwarding path does.
    fn emit_from_local_stack(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let Some(route) = self.routing_table.lookup(dst_ip).cloned() else {
            return out;
        };
        let Some(egress) = self
            .interfaces
            .iter()
            .find(|i| i.name == route.interface)
            .cloned()
        else {
            return out;
        };
        let next_hop = route.next_hop(dst_ip);
        let ip_id = self.next_ip_id();
        let ip_bytes = Ipv4Packet::serialize(src_ip, dst_ip, protocol, ip_id, 64, payload);

        let arp = self.arp_tables.entry(egress.name.clone()).or_default();
        if let Some(dst_mac) = arp.lookup(&next_hop.0) {
            out.push((
                egress.link_name.clone(),
                EthernetFrame::serialize(dst_mac, egress.mac, ETHERTYPE_IPV4, &ip_bytes),
            ));
        } else {
            self.pending_transit_packets
                .entry((egress.name.clone(), next_hop))
                .or_default()
                .push(ip_bytes);
            let arp_req = ArpPacket::build_request(egress.mac, egress.ip.0, next_hop.0);
            out.push((
                egress.link_name.clone(),
                EthernetFrame::serialize(
                    MacAddress::BROADCAST,
                    egress.mac,
                    ETHERTYPE_ARP,
                    &arp_req.serialize(),
                ),
            ));
        }
        out
    }

    pub fn set_firewall(&mut self, fw: Firewall) {
        self.firewall = Some(fw);
    }

    pub fn add_vxlan_tunnel(
        &mut self,
        access_iface: &str,
        vni: u32,
        remote_vtep_ip: Ipv4Address,
        underlay_iface: &str,
    ) {
        self.vxlan_tunnels.insert(
            access_iface.to_string(),
            (vni, remote_vtep_ip, underlay_iface.to_string()),
        );
        self.vxlan_vni_to_access
            .insert(vni, access_iface.to_string());
    }

    pub fn enable_ospf(&mut self) {
        self.ospf_lsdb = Some(OspfLsdb::new());
    }

    pub fn add_ospf_link(&mut self, from: Ipv4Address, to: Ipv4Address, cost: u32) {
        if let Some(ref mut lsdb) = self.ospf_lsdb {
            lsdb.add_link(from, to, cost);
        }
    }

    pub fn run_ospf_spf(
        &mut self,
        router_id: Ipv4Address,
        neighbor_subnets: &HashMap<Ipv4Address, (Ipv4Address, u8, String, Ipv4Address)>,
    ) {
        if let Some(ref lsdb) = self.ospf_lsdb {
            let shortest_paths = lsdb.compute_shortest_paths(router_id);
            for (dest_router, (_cost, next_hop_opt)) in shortest_paths {
                if let Some(next_hop_router) = next_hop_opt
                    && let Some((dest_net, mask, iface_name, next_hop_ip)) =
                        neighbor_subnets.get(&dest_router)
                {
                    let n_hop = if next_hop_router == dest_router {
                        *next_hop_ip
                    } else if let Some((_, _, _, nh_ip)) = neighbor_subnets.get(&next_hop_router) {
                        *nh_ip
                    } else {
                        *next_hop_ip
                    };
                    self.routing_table
                        .add_route(*dest_net, *mask, Some(n_hop), iface_name);
                }
            }
        }
    }

    pub fn enable_mpls(&mut self) {
        self.lfib = Some(LfibTable::new());
    }

    pub fn add_mpls_push_route(&mut self, dst_ip: Ipv4Address, label: u32, egress_iface: &str) {
        self.mpls_push_routes
            .insert(dst_ip, (label, egress_iface.to_string()));
    }

    pub fn add_mpls_swap_route(&mut self, in_label: u32, out_label: u32, egress_iface: &str) {
        let lfib = self.lfib.get_or_insert_with(LfibTable::new);
        lfib.insert(
            in_label,
            LfibAction::Swap(out_label, egress_iface.to_string()),
        );
    }

    pub fn add_mpls_pop_route(&mut self, in_label: u32) {
        let lfib = self.lfib.get_or_insert_with(LfibTable::new);
        lfib.insert(in_label, LfibAction::Pop);
    }

    pub fn enable_nat(&mut self, lan_iface: &str, wan_iface: &str, public_ip: Ipv4Address) {
        self.nat_table = Some(NatTable::new(public_ip));
        self.nat_lan_iface = Some(lan_iface.to_string());
        self.nat_wan_iface = Some(wan_iface.to_string());
    }

    pub fn add_port_forward(
        &mut self,
        ext_port: u16,
        int_ip: Ipv4Address,
        int_port: u16,
        proto: u8,
    ) {
        if let Some(ref mut nat) = self.nat_table {
            nat.add_port_forward(ext_port, int_ip, int_port, proto);
        }
    }

    pub fn enable_rip(&mut self) {
        let mut rip = RipEngine::new();
        for iface in &self.interfaces {
            let subnet_net = iface.ip.mask(iface.subnet_mask);
            rip.add_local_network(subnet_net, iface.subnet_mask, &iface.name);
        }
        self.routing_table = rip.routes.clone();
        self.rip_engine = Some(rip);
    }

    pub fn generate_rip_advertisements(&self) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        if let Some(ref rip) = self.rip_engine {
            let rip_pkt = rip.build_advertisement();
            let rip_bytes = rip_pkt.serialize();
            for iface in &self.interfaces {
                let udp_bytes = UdpDatagram::serialize(
                    iface.ip,
                    Ipv4Address([224, 0, 0, 9]),
                    RIP_PORT,
                    RIP_PORT,
                    &rip_bytes,
                );
                let ip_bytes = Ipv4Packet::serialize(
                    iface.ip,
                    Ipv4Address([224, 0, 0, 9]),
                    IP_PROTO_UDP,
                    100,
                    1,
                    &udp_bytes,
                );
                let eth_bytes = EthernetFrame::serialize(
                    MacAddress([0x01, 0x00, 0x5E, 0x00, 0x00, 0x09]),
                    iface.mac,
                    ETHERTYPE_IPV4,
                    &ip_bytes,
                );
                out.push((iface.link_name.clone(), eth_bytes));
            }
        }
        out
    }

    pub fn add_interface(
        &mut self,
        name: &str,
        mac: MacAddress,
        ip: Ipv4Address,
        subnet_mask: u8,
        link_name: &str,
    ) {
        let iface = RouterInterface {
            name: name.to_string(),
            mac,
            ip,
            subnet_mask,
            ipv6: None,
            link_name: link_name.to_string(),
        };
        self.arp_tables.insert(name.to_string(), ArpTable::new());
        self.ndp_tables.insert(name.to_string(), NdpTable::new());
        self.ipv6_interface_mtu.insert(name.to_string(), 1500);

        // Add local connected subnet route
        let subnet_net = ip.mask(subnet_mask);
        self.routing_table.add_route_from(
            subnet_net,
            subnet_mask,
            None,
            name,
            RouteSource::Connected,
        );
        self.interfaces.push(iface);
    }

    /// Assigns an IPv6 address to an existing router interface and installs its
    /// connected route into the IPv6 FIB.
    pub fn set_interface_ipv6(&mut self, name: &str, address: Ipv6Address, prefix_len: u8) -> bool {
        let Some(index) = self.interfaces.iter().position(|iface| iface.name == name) else {
            return false;
        };
        let prefix_len = prefix_len.min(128);
        self.interfaces[index].ipv6 = Some((address, prefix_len));
        self.ndp_tables.entry(name.to_string()).or_default();
        self.ipv6_routing_table.add_route_from(
            address,
            prefix_len,
            None,
            name,
            RouteSource::Connected,
        );
        true
    }

    /// Sets the IPv6 MTU used by the router forwarding plane on an interface.
    /// RFC 8200 requires every IPv6 link to support at least 1280 octets.
    pub fn set_interface_ipv6_mtu(&mut self, name: &str, mtu: u32) -> bool {
        if mtu < 1280 || !self.interfaces.iter().any(|iface| iface.name == name) {
            return false;
        }
        self.ipv6_interface_mtu.insert(name.to_string(), mtu);
        true
    }

    pub fn interface_ipv6_mtu(&self, name: &str) -> Option<u32> {
        self.interfaces
            .iter()
            .any(|iface| iface.name == name)
            .then(|| self.ipv6_interface_mtu.get(name).copied().unwrap_or(1500))
    }

    fn next_ip_id(&mut self) -> u16 {
        let id = self.ip_id_counter;
        self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
        id
    }

    /// Processes an incoming frame arriving on a specific virtual link.
    /// Returns a list of `(egress_link_name, frame_bytes)` to transmit.
    /// Handles a tenant frame arriving on an EVPN access port.
    ///
    /// Two things happen, in this order and for different reasons. The source
    /// MAC is learned locally, which is what turns a host plugging in into an
    /// EVPN Type 2 advertisement. Then the *destination* is looked up in the
    /// state MP-BGP built, which is what decides whether the frame is bridged
    /// locally, encapsulated to exactly one remote VTEP, or replicated to the
    /// VTEPs that signalled participation with a Type 3 route.
    fn evpn_access_ingress(
        &mut self,
        ingress: &RouterInterface,
        raw_frame: &[u8],
    ) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        let Ok(eth) = EthernetFrame::parse(raw_frame) else {
            return out;
        };

        let host_ip = Self::tenant_source_ip(&eth);
        if let Some(vtep) = self.vtep.as_mut() {
            vtep.learn_local(&ingress.name, eth.src_mac, host_ip);
        }

        let decision = match self.vtep.as_ref() {
            Some(v) => v.forward(&ingress.name, eth.dst_mac),
            None => OverlayDecision::Drop,
        };

        match decision {
            OverlayDecision::Local { access_interface } => {
                if let Some(iface) = self
                    .interfaces
                    .iter()
                    .find(|i| i.name == access_interface)
                    .cloned()
                {
                    out.push((iface.link_name, raw_frame.to_vec()));
                }
            }
            OverlayDecision::Unicast { vni, vtep } => {
                self.encapsulate_vxlan(vni, vtep, raw_frame, &mut out);
            }
            OverlayDecision::Flood { vni, vteps } => {
                // Ingress replication: one copy per participating VTEP, built
                // separately so each carries its own outer IP header.
                for remote in vteps {
                    self.encapsulate_vxlan(vni, remote, raw_frame, &mut out);
                }
            }
            OverlayDecision::Drop => {}
        }
        out
    }

    /// The tenant host address a frame reveals, used to fill in the IP field of
    /// an EVPN Type 2 route. An ARP sender address counts, because that is the
    /// first thing a host says and often the only thing it says about itself.
    fn tenant_source_ip(eth: &EthernetFrame<'_>) -> Option<Ipv4Address> {
        match eth.ethertype {
            EtherType::IPv4 => Ipv4Packet::parse(eth.payload, false)
                .ok()
                .map(|p| p.header.src_ip),
            EtherType::Arp => ArpPacket::parse(eth.payload)
                .ok()
                .map(|a| Ipv4Address(a.sender_ip)),
            _ => None,
        }
    }

    /// Wraps a tenant frame in VXLAN / UDP 4789 / IPv4 and hands it to the real
    /// underlay forwarding path: routing table lookup, ARP resolution, and the
    /// same pending-packet queue every other locally originated packet uses.
    fn encapsulate_vxlan(
        &mut self,
        vni: u32,
        remote_vtep: Ipv4Address,
        inner_frame: &[u8],
        out: &mut Vec<(String, Vec<u8>)>,
    ) {
        let Some(source_ip) = self.vtep.as_ref().map(|v| v.source_ip) else {
            return;
        };
        let Ok(vxlan_bytes) = VxlanPacket::encapsulate(vni, inner_frame) else {
            return;
        };
        let udp_bytes = UdpDatagram::serialize(
            source_ip,
            remote_vtep,
            VXLAN_UDP_PORT,
            VXLAN_UDP_PORT,
            &vxlan_bytes,
        );
        let ip_id = self.next_ip_id();
        let ip_bytes =
            Ipv4Packet::serialize(source_ip, remote_vtep, IP_PROTO_UDP, ip_id, 64, &udp_bytes);

        let Some(route) = self.routing_table.lookup(remote_vtep).cloned() else {
            return;
        };
        let Some(egress) = self
            .interfaces
            .iter()
            .find(|i| i.name == route.interface)
            .cloned()
        else {
            return;
        };
        let next_hop = route.next_hop(remote_vtep);
        let arp = self.arp_tables.entry(egress.name.clone()).or_default();
        if let Some(dst_mac) = arp.lookup(&next_hop.0) {
            out.push((
                egress.link_name.clone(),
                EthernetFrame::serialize(dst_mac, egress.mac, ETHERTYPE_IPV4, &ip_bytes),
            ));
        } else {
            self.pending_transit_packets
                .entry((egress.name.clone(), next_hop))
                .or_default()
                .push(ip_bytes);
            let arp_req = ArpPacket::build_request(egress.mac, egress.ip.0, next_hop.0);
            out.push((
                egress.link_name.clone(),
                EthernetFrame::serialize(
                    MacAddress::BROADCAST,
                    egress.mac,
                    ETHERTYPE_ARP,
                    &arp_req.serialize(),
                ),
            ));
        }
    }

    pub fn process_incoming_frame(
        &mut self,
        ingress_link: &str,
        raw_frame: &[u8],
    ) -> Vec<(String, Vec<u8>)> {
        let mut out_transmissions = Vec::new();

        let ingress_iface = match self.interfaces.iter().find(|i| i.link_name == ingress_link) {
            Some(i) => i.clone(),
            None => return out_transmissions,
        };

        // An EVPN access port carries tenant traffic, and where it goes is
        // decided by what MP-BGP taught this VTEP - never by a configured
        // destination. This is checked before the older static tunnel below, so
        // a router with both configured uses the control-plane path.
        if self
            .vtep
            .as_ref()
            .is_some_and(|v| v.vni_for_access(&ingress_iface.name).is_some())
        {
            return self.evpn_access_ingress(&ingress_iface, raw_frame);
        }

        // Check if this ingress interface is a VXLAN Access port
        if let Some(&(vni, remote_vtep_ip, ref underlay_iface_name)) =
            self.vxlan_tunnels.get(&ingress_iface.name)
        {
            if let Some(underlay_iface) = self
                .interfaces
                .iter()
                .find(|i| i.name == *underlay_iface_name)
                .cloned()
                && let Ok(vxlan_bytes) = VxlanPacket::encapsulate(vni, raw_frame)
            {
                let udp_bytes = UdpDatagram::serialize(
                    underlay_iface.ip,
                    remote_vtep_ip,
                    VXLAN_UDP_PORT,
                    VXLAN_UDP_PORT,
                    &vxlan_bytes,
                );
                let ip_id = self.next_ip_id();
                let ip_bytes = Ipv4Packet::serialize(
                    underlay_iface.ip,
                    remote_vtep_ip,
                    IP_PROTO_UDP,
                    ip_id,
                    64,
                    &udp_bytes,
                );

                if let Some(route) = self.routing_table.lookup(remote_vtep_ip)
                    && let Some(egress) = self.interfaces.iter().find(|i| i.name == route.interface)
                {
                    let next_hop = route.next_hop(remote_vtep_ip);
                    let egress_arp = self.arp_tables.entry(egress.name.clone()).or_default();
                    if let Some(dst_mac) = egress_arp.lookup(&next_hop.0) {
                        let eth_out = EthernetFrame::serialize(
                            dst_mac,
                            egress.mac,
                            ETHERTYPE_IPV4,
                            &ip_bytes,
                        );
                        out_transmissions.push((egress.link_name.clone(), eth_out));
                    } else {
                        let pending_key = (egress.name.clone(), next_hop);
                        self.pending_transit_packets
                            .entry(pending_key)
                            .or_default()
                            .push(ip_bytes);
                        let arp_req = ArpPacket::build_request(egress.mac, egress.ip.0, next_hop.0);
                        let eth_arp = EthernetFrame::serialize(
                            MacAddress::BROADCAST,
                            egress.mac,
                            ETHERTYPE_ARP,
                            &arp_req.serialize(),
                        );
                        out_transmissions.push((egress.link_name.clone(), eth_arp));
                    }
                }
            }
            return out_transmissions;
        }

        let eth = match EthernetFrame::parse(raw_frame) {
            Ok(f) => f,
            Err(_) => return out_transmissions,
        };

        // Filter: only accept if destination is ingress interface MAC, broadcast, or multicast
        if !eth.dst_mac.is_broadcast()
            && !eth.dst_mac.is_multicast()
            && eth.dst_mac != ingress_iface.mac
        {
            return out_transmissions;
        }

        match eth.ethertype {
            EtherType::Arp => {
                if let Ok(arp) = ArpPacket::parse(eth.payload) {
                    let arp_table = self
                        .arp_tables
                        .entry(ingress_iface.name.clone())
                        .or_default();
                    arp_table.insert(arp.sender_ip, arp.sender_mac);
                    let sender_ipv4 = Ipv4Address(arp.sender_ip);

                    // Check pending transit packets waiting for this ARP on this interface
                    let pending_key = (ingress_iface.name.clone(), sender_ipv4);
                    if let Some(queued) = self.pending_transit_packets.remove(&pending_key) {
                        for ip_data in queued {
                            let eth_out = EthernetFrame::serialize(
                                arp.sender_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV4,
                                &ip_data,
                            );
                            out_transmissions.push((ingress_link.to_string(), eth_out));
                        }
                    }

                    if arp.opcode == ArpOpcode::Request && arp.target_ip == ingress_iface.ip.0 {
                        // Generate ARP reply
                        let reply = ArpPacket::build_reply(
                            ingress_iface.mac,
                            ingress_iface.ip.0,
                            arp.sender_mac,
                            arp.sender_ip,
                        );
                        let eth_out = EthernetFrame::serialize(
                            arp.sender_mac,
                            ingress_iface.mac,
                            ETHERTYPE_ARP,
                            &reply.serialize(),
                        );
                        out_transmissions.push((ingress_link.to_string(), eth_out));
                    }
                }
            }

            EtherType::Mpls => {
                if let Ok(mpls_pkt) = MplsPacket::parse(eth.payload)
                    && let Some(top_hdr) = mpls_pkt.labels.first()
                    && let Some(ref lfib) = self.lfib
                {
                    match lfib.lookup(top_hdr.label) {
                        Some(LfibAction::Swap(out_label, egress_name)) => {
                            let mut new_labels = mpls_pkt.labels.clone();
                            new_labels[0].label = *out_label;
                            if new_labels[0].ttl > 1 {
                                new_labels[0].ttl -= 1;
                            }
                            let new_mpls = MplsPacket::new(new_labels, mpls_pkt.payload);
                            let mpls_bytes = new_mpls.serialize();

                            if let Some(egress_iface) =
                                self.interfaces.iter().find(|i| i.name == *egress_name)
                            {
                                let eth_out = EthernetFrame::serialize(
                                    MacAddress::BROADCAST,
                                    egress_iface.mac,
                                    ETHERTYPE_MPLS,
                                    &mpls_bytes,
                                );
                                out_transmissions.push((egress_iface.link_name.clone(), eth_out));
                            }
                        }
                        Some(LfibAction::Pop) => {
                            if top_hdr.bottom_of_stack
                                && let Ok(inner_ip) = Ipv4Packet::parse(&mpls_pkt.payload, false)
                                && let Some(route) =
                                    self.routing_table.lookup(inner_ip.header.dst_ip)
                                && let Some(egress_iface) =
                                    self.interfaces.iter().find(|i| i.name == route.interface)
                            {
                                let next_hop = route.next_hop(inner_ip.header.dst_ip);
                                let egress_arp = self
                                    .arp_tables
                                    .entry(egress_iface.name.clone())
                                    .or_default();
                                if let Some(dst_mac) = egress_arp.lookup(&next_hop.0) {
                                    let eth_out = EthernetFrame::serialize(
                                        dst_mac,
                                        egress_iface.mac,
                                        ETHERTYPE_IPV4,
                                        &mpls_pkt.payload,
                                    );
                                    out_transmissions
                                        .push((egress_iface.link_name.clone(), eth_out));
                                } else {
                                    let pending_key = (egress_iface.name.clone(), next_hop);
                                    self.pending_transit_packets
                                        .entry(pending_key)
                                        .or_default()
                                        .push(mpls_pkt.payload);
                                    let arp_req = ArpPacket::build_request(
                                        egress_iface.mac,
                                        egress_iface.ip.0,
                                        next_hop.0,
                                    );
                                    let eth_arp = EthernetFrame::serialize(
                                        MacAddress::BROADCAST,
                                        egress_iface.mac,
                                        ETHERTYPE_ARP,
                                        &arp_req.serialize(),
                                    );
                                    out_transmissions
                                        .push((egress_iface.link_name.clone(), eth_arp));
                                }
                            }
                        }
                        None | Some(LfibAction::Push(_)) => {}
                    }
                }
            }

            EtherType::IPv6 => {
                let Ok(ip6_pkt) = Ipv6Packet::parse(eth.payload) else {
                    return out_transmissions;
                };

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
                                ICMPV6_TYPE_ROUTER_SOLICIT => icmp6.is_valid_router_solicitation(
                                    ip6_pkt.header.src_ip,
                                    ip6_pkt.header.hop_limit,
                                ),
                                ICMPV6_TYPE_ROUTER_ADVERT => icmp6
                                    .validated_router_advertisement(
                                        ip6_pkt.header.src_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                    .is_some(),
                                _ => true,
                            };
                            if !valid {
                                return out_transmissions;
                            }
                        }
                        Err(_)
                            if matches!(
                                raw_type,
                                Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                    | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
                                    | Some(ICMPV6_TYPE_ROUTER_SOLICIT)
                                    | Some(ICMPV6_TYPE_ROUTER_ADVERT)
                            ) =>
                        {
                            return out_transmissions;
                        }
                        Err(_) => {}
                    }
                }

                // Learn L2 neighbors only from validated NDP control traffic. Ordinary
                // routed IPv6 data may carry a remote source behind the previous hop and
                // therefore must never create a directly-attached Neighbor Cache entry.
                // NS/RS contribute link-layer information only when SLLA is present;
                // that option creates a STALE dynamic entry rather than a static mapping.
                // NA processing follows RFC 4861 section 7.2.5 and never creates
                // a cache entry unless resolution is already INCOMPLETE.
                if ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6
                    && let Ok(icmp6) = Icmpv6Packet::parse(
                        ip6_pkt.header.src_ip,
                        ip6_pkt.header.dst_ip,
                        ip6_pkt.payload,
                        true,
                    )
                {
                    let learned_source = match icmp6.msg_type {
                        ICMPV6_TYPE_ROUTER_SOLICIT
                            if icmp6.is_valid_router_solicitation(
                                ip6_pkt.header.src_ip,
                                ip6_pkt.header.hop_limit,
                            ) && !ip6_pkt.header.src_ip.is_unspecified() =>
                        {
                            icmp6
                                .ndp_source_link_layer_address()
                                .map(|mac| (ip6_pkt.header.src_ip, mac))
                        }
                        ICMPV6_TYPE_NEIGHBOR_SOLICIT => icmp6
                            .validated_neighbor_solicitation_target(
                                ip6_pkt.header.src_ip,
                                ip6_pkt.header.dst_ip,
                                ip6_pkt.header.hop_limit,
                            )
                            .and_then(|_| {
                                (!ip6_pkt.header.src_ip.is_unspecified())
                                    .then_some(ip6_pkt.header.src_ip)
                            })
                            .and_then(|source| {
                                icmp6
                                    .ndp_source_link_layer_address()
                                    .map(|mac| (source, mac))
                            }),
                        _ => None,
                    };

                    if let Some((neighbor_ip, neighbor_mac)) = learned_source {
                        self.ndp_tables
                            .entry(ingress_iface.name.clone())
                            .or_default()
                            .learn_stale(neighbor_ip, neighbor_mac);

                        let pending_key = (ingress_iface.name.clone(), neighbor_ip);
                        if let Some(queued) = self.pending_ipv6_transit_packets.remove(&pending_key)
                        {
                            for packet in queued {
                                out_transmissions.push((
                                    ingress_link.to_string(),
                                    EthernetFrame::serialize(
                                        neighbor_mac,
                                        ingress_iface.mac,
                                        ETHERTYPE_IPV6,
                                        &packet,
                                    ),
                                ));
                            }
                        }
                    }

                    if icmp6.msg_type == ICMPV6_TYPE_NEIGHBOR_ADVERT
                        && let Some(target) = icmp6.validated_neighbor_advertisement_target(
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.header.hop_limit,
                        )
                    {
                        let table = self
                            .ndp_tables
                            .entry(ingress_iface.name.clone())
                            .or_default();
                        let cached_mac = table.lookup(&target);
                        let pending_key = (ingress_iface.name.clone(), target);
                        let resolving =
                            self.pending_ipv6_transit_packets.contains_key(&pending_key);
                        let advertised_mac =
                            icmp6.neighbor_advertisement_target_link_layer_address();
                        let solicited = icmp6.payload[0] & 0x40 != 0;
                        let override_flag = icmp6.payload[0] & 0x20 != 0;
                        let mut resolved_mac = None;

                        if let Some(current_mac) = cached_mac {
                            if advertised_mac.is_some_and(|mac| mac != current_mac)
                                && !override_flag
                            {
                                table.demote_reachable_preserving_mac(target);
                            } else {
                                let selected_mac = advertised_mac.unwrap_or(current_mac);
                                let address_changed = selected_mac != current_mac;
                                if solicited {
                                    table.confirm_reachable(
                                        target,
                                        selected_mac,
                                        self.current_time_ms,
                                    );
                                } else if address_changed {
                                    table.mark_stale(target, selected_mac);
                                }
                            }
                        } else if resolving {
                            // RFC 4861 section 7.2.5: on Ethernet an NA received for an
                            // INCOMPLETE entry cannot complete resolution without TLLA.
                            let Some(target_mac) = advertised_mac else {
                                return out_transmissions;
                            };
                            if solicited {
                                table.confirm_reachable(target, target_mac, self.current_time_ms);
                            } else {
                                table.mark_stale(target, target_mac);
                            }
                            resolved_mac = Some(target_mac);
                        }

                        if let Some(target_mac) = resolved_mac
                            && let Some(queued) =
                                self.pending_ipv6_transit_packets.remove(&pending_key)
                        {
                            for packet in queued {
                                out_transmissions.push((
                                    ingress_link.to_string(),
                                    EthernetFrame::serialize(
                                        target_mac,
                                        ingress_iface.mac,
                                        ETHERTYPE_IPV6,
                                        &packet,
                                    ),
                                ));
                            }
                        }
                    }
                }

                let own_destination = self.interfaces.iter().any(|iface| {
                    iface
                        .ipv6
                        .is_some_and(|(addr, _)| addr == ip6_pkt.header.dst_ip)
                        || (iface.ipv6.is_some()
                            && link_local_address(iface.mac) == ip6_pkt.header.dst_ip)
                });

                if ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6
                    && let Ok(icmp6) = Icmpv6Packet::parse(
                        ip6_pkt.header.src_ip,
                        ip6_pkt.header.dst_ip,
                        ip6_pkt.payload,
                        true,
                    )
                {
                    if icmp6.msg_type == ICMPV6_TYPE_ROUTER_SOLICIT
                        && icmp6.is_valid_router_solicitation(
                            ip6_pkt.header.src_ip,
                            ip6_pkt.header.hop_limit,
                        )
                        && ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS
                        && let Some((router_address, prefix_len)) = ingress_iface.ipv6
                    {
                        let ra_src = link_local_address(ingress_iface.mac);
                        let ra_dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
                        let prefix = PrefixInformationOption::new(
                            router_address.mask(prefix_len),
                            prefix_len,
                            true,
                            prefix_len == 64,
                            86_400,
                            14_400,
                        );
                        let ra = Icmpv6Packet::build_router_advertisement(
                            ra_src,
                            ra_dst,
                            64,
                            1_800,
                            &[prefix],
                            Some(ingress_iface.mac),
                        );
                        let packet =
                            Ipv6Packet::serialize(ra_src, ra_dst, NEXT_HEADER_ICMPV6, 255, &ra);
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                ipv6_multicast_mac(ra_dst).unwrap_or(MacAddress::BROADCAST),
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &packet,
                            ),
                        ));
                        return out_transmissions;
                    }

                    if icmp6.msg_type == ICMPV6_TYPE_NEIGHBOR_SOLICIT
                        && let Some(target) = icmp6.validated_neighbor_solicitation_target(
                            ip6_pkt.header.src_ip,
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.header.hop_limit,
                        )
                    {
                        let owns_target =
                            ingress_iface.ipv6.is_some_and(|(addr, _)| addr == target)
                                || (ingress_iface.ipv6.is_some()
                                    && link_local_address(ingress_iface.mac) == target);
                        if owns_target {
                            let dad_probe = ip6_pkt.header.src_ip.is_unspecified();
                            if dad_probe
                                && ip6_pkt.header.dst_ip != target.solicited_node_multicast()
                            {
                                return out_transmissions;
                            }

                            // RFC 4862 DAD probes have source ::. The owner defends the
                            // address with an unsolicited NA to all-nodes multicast;
                            // replying to :: would create an invalid IPv6 destination.
                            let (na_dst, solicited, dst_mac) = if dad_probe {
                                let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
                                (
                                    dst,
                                    false,
                                    ipv6_multicast_mac(dst).unwrap_or(MacAddress::BROADCAST),
                                )
                            } else {
                                (ip6_pkt.header.src_ip, true, eth.src_mac)
                            };
                            let na = Icmpv6Packet::build_neighbor_advertisement(
                                target,
                                na_dst,
                                target,
                                ingress_iface.mac,
                                true,
                                solicited,
                                true,
                            );
                            let reply =
                                Ipv6Packet::serialize(target, na_dst, NEXT_HEADER_ICMPV6, 255, &na);
                            out_transmissions.push((
                                ingress_link.to_string(),
                                EthernetFrame::serialize(
                                    dst_mac,
                                    ingress_iface.mac,
                                    ETHERTYPE_IPV6,
                                    &reply,
                                ),
                            ));
                            return out_transmissions;
                        }
                    }

                    if own_destination
                        && icmp6.msg_type == ICMPV6_TYPE_ECHO_REQUEST
                        && icmp6.payload.len() >= 4
                    {
                        let id = u16::from_be_bytes([icmp6.payload[0], icmp6.payload[1]]);
                        let seq = u16::from_be_bytes([icmp6.payload[2], icmp6.payload[3]]);
                        let reply_payload = Icmpv6Packet::build_echo_reply(
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.header.src_ip,
                            id,
                            seq,
                            &icmp6.payload[4..],
                        );
                        let reply = Ipv6Packet::serialize(
                            ip6_pkt.header.dst_ip,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &reply_payload,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                        return out_transmissions;
                    }
                }

                if own_destination {
                    return out_transmissions;
                }

                // Routers decrement Hop Limit exactly once. IPv6 has no header
                // checksum, so mutating byte 7 preserves traffic class, flow label,
                // extension headers and the transport payload byte-for-byte.
                if ip6_pkt.header.hop_limit <= 1 {
                    if should_send_icmpv6_error(&ip6_pkt, eth.dst_mac, false)
                        && let Some((src, _)) = ingress_iface.ipv6
                    {
                        let exceeded = Icmpv6Packet::build_time_exceeded(
                            src,
                            ip6_pkt.header.src_ip,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &exceeded,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }

                let Some(route) = self
                    .ipv6_routing_table
                    .lookup(ip6_pkt.header.dst_ip)
                    .cloned()
                else {
                    // RFC 4443 section 3.1 Code 0: a router that has no route to
                    // a unicast destination reports that failure to the source.
                    // The common suppression guard prevents error loops and
                    // multicast/non-unique-source amplification.
                    if should_send_icmpv6_error(&ip6_pkt, eth.dst_mac, false) {
                        let unreachable_src = ingress_iface
                            .ipv6
                            .map(|(address, _)| address)
                            .unwrap_or_else(|| link_local_address(ingress_iface.mac));
                        let unreachable = Icmpv6Packet::build_destination_unreachable(
                            unreachable_src,
                            ip6_pkt.header.src_ip,
                            0,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            unreachable_src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &unreachable,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                };
                let Some(egress_iface) = self
                    .interfaces
                    .iter()
                    .find(|iface| iface.name == route.interface)
                    .cloned()
                else {
                    return out_transmissions;
                };
                let Some((egress_ip6, _)) = egress_iface.ipv6 else {
                    return out_transmissions;
                };

                let egress_mtu = self
                    .ipv6_interface_mtu
                    .get(&egress_iface.name)
                    .copied()
                    .unwrap_or(1500);
                if eth.payload.len() > egress_mtu as usize {
                    // RFC 4443 permits Packet Too Big for IPv6/link-layer multicast,
                    // but all other generic suppression rules still apply.
                    if should_send_icmpv6_error(&ip6_pkt, eth.dst_mac, true) {
                        let ptb_src = ingress_iface
                            .ipv6
                            .map(|(address, _)| address)
                            .unwrap_or_else(|| link_local_address(ingress_iface.mac));
                        let ptb = Icmpv6Packet::build_packet_too_big(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            egress_mtu,
                            eth.payload,
                        );
                        let reply = Ipv6Packet::serialize(
                            ptb_src,
                            ip6_pkt.header.src_ip,
                            NEXT_HEADER_ICMPV6,
                            64,
                            &ptb,
                        );
                        out_transmissions.push((
                            ingress_link.to_string(),
                            EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV6,
                                &reply,
                            ),
                        ));
                    }
                    return out_transmissions;
                }

                let next_hop = route.next_hop(ip6_pkt.header.dst_ip);

                // RFC 4861 section 8.2: when a packet from an on-link neighbor would
                // leave through the same interface, tell the sender the better first
                // hop while still forwarding the original packet. The Redirect target
                // is either the destination itself or a link-local router.
                let source_on_ingress_link = ip6_pkt.header.src_ip.is_link_local()
                    || ingress_iface.ipv6.is_some_and(|(address, prefix_len)| {
                        ip6_pkt.header.src_ip.mask(prefix_len) == address.mask(prefix_len)
                    });
                let redirect_target_is_legal =
                    next_hop == ip6_pkt.header.dst_ip || next_hop.is_link_local();
                if ingress_iface.name == egress_iface.name
                    && source_on_ingress_link
                    && !ip6_pkt.header.src_ip.is_unspecified()
                    && !ip6_pkt.header.src_ip.is_multicast()
                    && !ip6_pkt.header.dst_ip.is_multicast()
                    && next_hop != ip6_pkt.header.src_ip
                    && redirect_target_is_legal
                {
                    let target_mac = self
                        .ndp_tables
                        .get(&egress_iface.name)
                        .and_then(|table| table.lookup(&next_hop));
                    let redirect_src = link_local_address(ingress_iface.mac);
                    let redirect = Icmpv6Packet::build_redirect(
                        redirect_src,
                        ip6_pkt.header.src_ip,
                        next_hop,
                        ip6_pkt.header.dst_ip,
                        target_mac,
                        eth.payload,
                    );
                    let redirect_packet = Ipv6Packet::serialize(
                        redirect_src,
                        ip6_pkt.header.src_ip,
                        NEXT_HEADER_ICMPV6,
                        255,
                        &redirect,
                    );
                    out_transmissions.push((
                        ingress_link.to_string(),
                        EthernetFrame::serialize(
                            eth.src_mac,
                            ingress_iface.mac,
                            ETHERTYPE_IPV6,
                            &redirect_packet,
                        ),
                    ));
                }

                let mut forwarded = eth.payload.to_vec();
                forwarded[7] = ip6_pkt.header.hop_limit - 1;

                let ndp = self
                    .ndp_tables
                    .entry(egress_iface.name.clone())
                    .or_default();
                if let Some(dst_mac) = ndp.lookup_for_transmit(&next_hop, self.current_time_ms) {
                    out_transmissions.push((
                        egress_iface.link_name.clone(),
                        EthernetFrame::serialize(
                            dst_mac,
                            egress_iface.mac,
                            ETHERTYPE_IPV6,
                            &forwarded,
                        ),
                    ));
                } else {
                    self.pending_ipv6_transit_packets
                        .entry((egress_iface.name.clone(), next_hop))
                        .or_default()
                        .push(forwarded);
                    let ns_dst = next_hop.solicited_node_multicast();
                    let ns = Icmpv6Packet::build_neighbor_solicitation(
                        egress_ip6,
                        ns_dst,
                        next_hop,
                        egress_iface.mac,
                    );
                    let ns_packet =
                        Ipv6Packet::serialize(egress_ip6, ns_dst, NEXT_HEADER_ICMPV6, 255, &ns);
                    out_transmissions.push((
                        egress_iface.link_name.clone(),
                        EthernetFrame::serialize(
                            ipv6_multicast_mac(ns_dst).unwrap_or(MacAddress::BROADCAST),
                            egress_iface.mac,
                            ETHERTYPE_IPV6,
                            &ns_packet,
                        ),
                    ));
                }
                return out_transmissions;
            }

            EtherType::IPv4 => {
                if let Ok(ip_pkt) = Ipv4Packet::parse(eth.payload, true) {
                    let is_for_router =
                        self.interfaces.iter().any(|i| i.ip == ip_pkt.header.dst_ip);

                    // 1. Evaluate Firewall Input or Forward Chain
                    if let Some(ref fw) = self.firewall {
                        let chain = if is_for_router {
                            FirewallChain::Input
                        } else {
                            FirewallChain::Forward
                        };
                        if fw.evaluate(chain, &ip_pkt) != FirewallAction::Accept {
                            return out_transmissions; // Dropped by firewall!
                        }
                    }

                    // Update ARP table on ingress interface with sender
                    let arp_table = self
                        .arp_tables
                        .entry(ingress_iface.name.clone())
                        .or_default();
                    arp_table.insert(ip_pkt.header.src_ip.0, eth.src_mac);

                    // Check for RIPv2 multicast or direct UDP packets
                    if ip_pkt.header.protocol == crate::ipv4::IpProtocol::Udp
                        && let Ok(udp) = UdpDatagram::parse(
                            ip_pkt.header.src_ip,
                            ip_pkt.header.dst_ip,
                            ip_pkt.payload,
                            false,
                        )
                    {
                        // RIPv2
                        if udp.dst_port == RIP_PORT {
                            if let Some(ref mut rip) = self.rip_engine
                                && let Ok(rip_pkt) = RipPacket::parse(udp.payload)
                            {
                                rip.process_advertisement(
                                    ip_pkt.header.src_ip,
                                    &rip_pkt,
                                    &ingress_iface.name,
                                );
                                self.routing_table = rip.routes.clone();
                            }
                            return out_transmissions;
                        }

                        // VXLAN Decapsulation (UDP 4789), EVPN-driven.
                        //
                        // Nothing is learned from the inner frame. In EVPN the
                        // only way a MAC becomes reachable is a Type 2 route, so
                        // data-plane learning here would quietly reintroduce the
                        // flood-and-learn behaviour the control plane replaces -
                        // and would install state no withdrawal could remove.
                        if udp.dst_port == VXLAN_UDP_PORT
                            && is_for_router
                            && let Ok(vxlan) = VxlanPacket::parse(udp.payload)
                            && self
                                .vtep
                                .as_ref()
                                .is_some_and(|v| v.has_vni(vxlan.header.vni))
                        {
                            let inner_dst = EthernetFrame::parse(&vxlan.inner_frame)
                                .map(|f| f.dst_mac)
                                .unwrap_or(MacAddress::BROADCAST);
                            let ports = self
                                .vtep
                                .as_ref()
                                .map(|v| v.access_ports_for(vxlan.header.vni, inner_dst))
                                .unwrap_or_default();
                            for port in ports {
                                if let Some(access) =
                                    self.interfaces.iter().find(|i| i.name == port)
                                {
                                    out_transmissions.push((
                                        access.link_name.clone(),
                                        vxlan.inner_frame.clone(),
                                    ));
                                }
                            }
                            return out_transmissions;
                        }

                        // VXLAN Decapsulation for the older statically configured
                        // point-to-point overlay.
                        if udp.dst_port == VXLAN_UDP_PORT
                            && is_for_router
                            && let Ok(vxlan) = VxlanPacket::parse(udp.payload)
                            && let Some(access_name) =
                                self.vxlan_vni_to_access.get(&vxlan.header.vni)
                            && let Some(access_iface) =
                                self.interfaces.iter().find(|i| i.name == *access_name)
                        {
                            out_transmissions
                                .push((access_iface.link_name.clone(), vxlan.inner_frame));
                            return out_transmissions;
                        }
                    }

                    if is_for_router {
                        // Check if Inbound NAT (DNAT) translates this WAN packet for a LAN host
                        if let Some(ref mut nat) = self.nat_table
                            && self.nat_wan_iface.as_deref() == Some(&ingress_iface.name)
                        {
                            let mut ip_buf = eth.payload.to_vec();
                            if nat.translate_inbound(&mut ip_buf)
                                && let Ok(trans_ip) = Ipv4Packet::parse(&ip_buf, true)
                                && let Some(route) =
                                    self.routing_table.lookup(trans_ip.header.dst_ip)
                                && let Some(egress_iface) =
                                    self.interfaces.iter().find(|i| i.name == route.interface)
                            {
                                let egress_link = egress_iface.link_name.clone();
                                let next_hop = route.next_hop(trans_ip.header.dst_ip);
                                let egress_arp = self
                                    .arp_tables
                                    .entry(egress_iface.name.clone())
                                    .or_default();
                                if let Some(dst_mac) = egress_arp.lookup(&next_hop.0) {
                                    let eth_out = EthernetFrame::serialize(
                                        dst_mac,
                                        egress_iface.mac,
                                        ETHERTYPE_IPV4,
                                        &ip_buf,
                                    );
                                    out_transmissions.push((egress_link, eth_out));
                                    return out_transmissions;
                                } else {
                                    let pending_key = (egress_iface.name.clone(), next_hop);
                                    self.pending_transit_packets
                                        .entry(pending_key)
                                        .or_default()
                                        .push(ip_buf);
                                    let arp_req = ArpPacket::build_request(
                                        egress_iface.mac,
                                        egress_iface.ip.0,
                                        next_hop.0,
                                    );
                                    let eth_arp = EthernetFrame::serialize(
                                        MacAddress::BROADCAST,
                                        egress_iface.mac,
                                        ETHERTYPE_ARP,
                                        &arp_req.serialize(),
                                    );
                                    out_transmissions.push((egress_link, eth_arp));
                                    return out_transmissions;
                                }
                            }
                        }

                        // TCP addressed to one of our own interfaces: hand it to the
                        // socket runtime, which owns port 179 when BGP is enabled and
                        // answers anything else with a RST.
                        if ip_pkt.header.protocol == crate::ipv4::IpProtocol::Tcp
                            && self.sockets.is_some()
                        {
                            let src_ip = ip_pkt.header.src_ip;
                            let dst_ip = ip_pkt.header.dst_ip;
                            let now = self.current_time_ms;
                            let responses =
                                match TcpSegment::parse(src_ip, dst_ip, ip_pkt.payload, true) {
                                    Ok(seg) => self
                                        .sockets
                                        .as_mut()
                                        .map(|s| s.dispatch_tcp_segment(src_ip, dst_ip, &seg, now))
                                        .unwrap_or_default(),
                                    Err(_) => Vec::new(),
                                };
                            for resp in responses {
                                let frames =
                                    self.emit_from_local_stack(dst_ip, src_ip, IP_PROTO_TCP, &resp);
                                out_transmissions.extend(frames);
                            }
                            return out_transmissions;
                        }

                        // Direct packet to router's own IP (e.g. pinging the router)
                        if ip_pkt.header.protocol == crate::ipv4::IpProtocol::Icmp
                            && let Ok(icmp) = IcmpPacket::parse(ip_pkt.payload, true)
                            && icmp.icmp_type == IcmpType::EchoRequest
                        {
                            let echo_reply = IcmpPacket::build_echo_reply(&icmp);
                            let ip_id = self.next_ip_id();
                            let ip_out = Ipv4Packet::serialize(
                                ip_pkt.header.dst_ip,
                                ip_pkt.header.src_ip,
                                IP_PROTO_ICMP,
                                ip_id,
                                64,
                                &echo_reply,
                            );
                            let eth_out = EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV4,
                                &ip_out,
                            );
                            out_transmissions.push((ingress_link.to_string(), eth_out));
                        }
                    } else {
                        // Forwarding data plane path
                        // 1. Check TTL
                        if ip_pkt.header.ttl <= 1 {
                            // TTL expired in transit -> Generate ICMP Time Exceeded (Type 11 Code 0)
                            let time_exceeded_payload =
                                IcmpPacket::build_time_exceeded(0, eth.payload);
                            let ip_id = self.next_ip_id();
                            let ip_out = Ipv4Packet::serialize(
                                ingress_iface.ip,
                                ip_pkt.header.src_ip,
                                IP_PROTO_ICMP,
                                ip_id,
                                64,
                                &time_exceeded_payload,
                            );
                            let eth_out = EthernetFrame::serialize(
                                eth.src_mac,
                                ingress_iface.mac,
                                ETHERTYPE_IPV4,
                                &ip_out,
                            );
                            out_transmissions.push((ingress_link.to_string(), eth_out));
                            return out_transmissions;
                        }

                        // Check MPLS Ingress Push route
                        if let Some(&(push_label, ref egress_name)) =
                            self.mpls_push_routes.get(&ip_pkt.header.dst_ip)
                            && let Some(egress_iface) =
                                self.interfaces.iter().find(|i| i.name == *egress_name)
                        {
                            let mpls_hdr = MplsHeader::new(push_label, 0, true, 64);
                            let mpls_pkt = MplsPacket::new(vec![mpls_hdr], eth.payload.to_vec());
                            let mpls_bytes = mpls_pkt.serialize();
                            let eth_out = EthernetFrame::serialize(
                                MacAddress::BROADCAST,
                                egress_iface.mac,
                                ETHERTYPE_MPLS,
                                &mpls_bytes,
                            );
                            out_transmissions.push((egress_iface.link_name.clone(), eth_out));
                            return out_transmissions;
                        }

                        // 2. Decrement TTL and recompute checksum
                        let new_ttl = ip_pkt.header.ttl - 1;

                        // 3. Routing Table Lookup (LPM)
                        if let Some(route) = self.routing_table.lookup(ip_pkt.header.dst_ip) {
                            let egress_iface_name = route.interface.clone();
                            let next_hop = route.next_hop(ip_pkt.header.dst_ip);

                            if let Some(egress_iface) =
                                self.interfaces.iter().find(|i| i.name == egress_iface_name)
                            {
                                let egress_link = egress_iface.link_name.clone();
                                let ip_id = ip_pkt.header.identification;
                                let mut forwarded_ip_bytes = Ipv4Packet::serialize(
                                    ip_pkt.header.src_ip,
                                    ip_pkt.header.dst_ip,
                                    ip_pkt.header.protocol.to_u8(),
                                    ip_id,
                                    new_ttl,
                                    ip_pkt.payload,
                                );

                                // Check if Outbound NAT (SNAT) applies for LAN -> WAN
                                if let Some(ref mut nat) = self.nat_table
                                    && self.nat_lan_iface.as_deref() == Some(&ingress_iface.name)
                                    && self.nat_wan_iface.as_deref() == Some(&egress_iface.name)
                                {
                                    nat.translate_outbound(&mut forwarded_ip_bytes);
                                }

                                let egress_arp = self
                                    .arp_tables
                                    .entry(egress_iface.name.clone())
                                    .or_default();
                                if let Some(dst_mac) = egress_arp.lookup(&next_hop.0) {
                                    let eth_out = EthernetFrame::serialize(
                                        dst_mac,
                                        egress_iface.mac,
                                        ETHERTYPE_IPV4,
                                        &forwarded_ip_bytes,
                                    );
                                    out_transmissions.push((egress_link, eth_out));
                                } else {
                                    // Queue transit packet and broadcast ARP Request on egress link
                                    let pending_key = (egress_iface.name.clone(), next_hop);
                                    self.pending_transit_packets
                                        .entry(pending_key)
                                        .or_default()
                                        .push(forwarded_ip_bytes);

                                    let arp_req = ArpPacket::build_request(
                                        egress_iface.mac,
                                        egress_iface.ip.0,
                                        next_hop.0,
                                    );
                                    let eth_arp = EthernetFrame::serialize(
                                        MacAddress::BROADCAST,
                                        egress_iface.mac,
                                        ETHERTYPE_ARP,
                                        &arp_req.serialize(),
                                    );
                                    out_transmissions.push((egress_link, eth_arp));
                                }
                            }
                        }
                    }
                }
            }

            _ => {}
        }

        out_transmissions
    }
}

/// Builds the canned three-autonomous-system BGP fabric the shell diagnostics run on:
///
/// ```text
/// host_a 10.1.0.2 - r1 (AS65001) - r2 (AS65002) - r3 (AS65003) - host_c 10.3.0.2
/// ```
///
/// R1 originates 10.1.0.0/24 and R3 originates 10.3.0.0/24. Nothing else is configured,
/// so every route the routers end up with was learned over a real BGP session on TCP
/// port 179 and installed by the decision process.
pub fn build_bgp_demo_fabric() -> VirtualLab {
    fn mac(a: u8, b: u8) -> MacAddress {
        MacAddress([0x02, 0x00, 0x00, 0x00, a, b])
    }
    let addr = Ipv4Address::new;

    let mut lab = VirtualLab::new();
    for link in ["lan1", "r1r2", "r2r3", "lan3"] {
        lab.add_link(link);
    }

    lab.add_host(
        "host_a",
        "lan1",
        NetStackConfig {
            mac: mac(0x0A, 0x02),
            ip: addr(10, 1, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: Some(addr(10, 1, 0, 1)),
        },
    );
    lab.add_host(
        "host_c",
        "lan3",
        NetStackConfig {
            mac: mac(0x0C, 0x02),
            ip: addr(10, 3, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: Some(addr(10, 3, 0, 1)),
        },
    );

    let mut r1 = LabRouter::new("r1");
    r1.add_interface("eth0", mac(0x01, 0x00), addr(10, 1, 0, 1), 24, "lan1");
    r1.add_interface("eth1", mac(0x01, 0x01), addr(10, 12, 0, 1), 30, "r1r2");
    r1.enable_bgp(65001, addr(1, 1, 1, 1)).set_hold_time(9);
    r1.add_bgp_peer(
        addr(10, 12, 0, 2),
        65002,
        addr(10, 12, 0, 1),
        BgpPeerMode::Active,
    );
    r1.originate_bgp_prefix(Ipv4Prefix::new(addr(10, 1, 0, 0), 24));

    let mut r2 = LabRouter::new("r2");
    r2.add_interface("eth0", mac(0x02, 0x00), addr(10, 12, 0, 2), 30, "r1r2");
    r2.add_interface("eth1", mac(0x02, 0x01), addr(10, 23, 0, 2), 30, "r2r3");
    r2.enable_bgp(65002, addr(2, 2, 2, 2)).set_hold_time(9);
    r2.add_bgp_peer(
        addr(10, 12, 0, 1),
        65001,
        addr(10, 12, 0, 2),
        BgpPeerMode::Passive,
    );
    r2.add_bgp_peer(
        addr(10, 23, 0, 3),
        65003,
        addr(10, 23, 0, 2),
        BgpPeerMode::Active,
    );

    let mut r3 = LabRouter::new("r3");
    r3.add_interface("eth0", mac(0x03, 0x00), addr(10, 23, 0, 3), 30, "r2r3");
    r3.add_interface("eth1", mac(0x03, 0x01), addr(10, 3, 0, 1), 24, "lan3");
    r3.enable_bgp(65003, addr(3, 3, 3, 3)).set_hold_time(9);
    r3.add_bgp_peer(
        addr(10, 23, 0, 2),
        65002,
        addr(10, 23, 0, 3),
        BgpPeerMode::Passive,
    );
    r3.originate_bgp_prefix(Ipv4Prefix::new(addr(10, 3, 0, 0), 24));

    lab.add_router(r1);
    lab.add_router(r2);
    lab.add_router(r3);
    lab
}

/// Route Target for a VNI in the usual `AS:VNI` form.
pub fn evpn_rt(asn: u16, vni: u32) -> RouteTarget {
    RouteTarget::as2(asn, vni)
}

/// Builds the leaf-spine-leaf EVPN/VXLAN fabric:
///
/// ```text
///  host_a 192.168.10.11            host_b 192.168.10.22
///  MAC 02:..:0A                    MAC 02:..:0B
///        |  tenant1                      |  tenant2
///      leaf1                           leaf2
///      VTEP 10.0.0.1                   VTEP 10.0.0.2
///        \  10.1.0.1/30      10.2.0.2/30  /
///         \-------- spine (IP underlay) -/
///                 10.1.0.2      10.2.0.1
/// ```
///
/// The two tenant hosts sit in one /24 with no gateway: as far as they can tell
/// they share a wire, and every packet between them has to cross the overlay for
/// that to be true.
///
/// The spine forwards IP and nothing else - it runs no BGP and knows no VNI. The
/// leaves peer directly, loopback to loopback, so the TCP session carrying the
/// EVPN routes is itself multihop traffic the spine forwards. Nothing about the
/// overlay is configured on either leaf beyond its own instance: no remote MAC,
/// no remote VTEP, no tunnel destination. Every one of those has to arrive as an
/// EVPN route or the fabric does not work at all.
///
/// `leaf_as` gives the two leaves their ASNs, so a caller can run the same fabric
/// on 16-bit or 32-bit autonomous system numbers.
pub fn build_evpn_fabric(leaf1_as: u32, leaf2_as: u32) -> VirtualLab {
    fn mac(a: u8, b: u8) -> MacAddress {
        MacAddress([0x02, 0x00, 0x00, 0x00, a, b])
    }
    let addr = Ipv4Address::new;

    const VNI: u32 = 5001;
    let vtep1 = addr(10, 0, 0, 1);
    let vtep2 = addr(10, 0, 0, 2);

    let mut lab = VirtualLab::new();
    for link in [
        "tenant1",
        "tenant2",
        "leaf1spine",
        "leaf2spine",
        "lo1",
        "lo2",
    ] {
        lab.add_link(link);
    }

    // Tenant hosts: same subnet, no gateway. Anything that reaches the far side
    // did so as a bridged Ethernet frame, not as a routed packet.
    lab.add_host(
        "host_a",
        "tenant1",
        NetStackConfig {
            mac: mac(0x0A, 0x0A),
            ip: addr(192, 168, 10, 11),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "host_b",
        "tenant2",
        NetStackConfig {
            mac: mac(0x0B, 0x0B),
            ip: addr(192, 168, 10, 22),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );

    let mut leaf1 = LabRouter::new("leaf1");
    leaf1.add_interface(
        "eth0",
        mac(0x01, 0x00),
        addr(192, 168, 10, 1),
        24,
        "tenant1",
    );
    leaf1.add_interface("eth1", mac(0x01, 0x01), addr(10, 1, 0, 1), 30, "leaf1spine");
    // The VTEP address lives on a loopback, exactly as it would on a real leaf:
    // it must stay up when any one underlay link does not.
    leaf1.add_interface("lo0", mac(0x01, 0xFF), vtep1, 32, "lo1");
    leaf1.routing_table.add_route_from(
        vtep2,
        32,
        Some(addr(10, 1, 0, 2)),
        "eth1",
        RouteSource::Static,
    );
    leaf1
        .enable_bgp(leaf1_as, addr(1, 1, 1, 1))
        .set_hold_time(9);
    leaf1.add_bgp_peer(vtep2, leaf2_as, vtep1, BgpPeerMode::Active);
    leaf1.enable_vtep(vtep1, "eth1");
    leaf1.add_evpn_instance(
        VNI,
        RouteDistinguisher::new(vtep1, VNI as u16),
        &[evpn_rt(65001, VNI)],
        &[evpn_rt(65001, VNI)],
    );
    leaf1.attach_evpn_access_port(VNI, "eth0");

    let mut spine = LabRouter::new("spine");
    spine.add_interface("eth0", mac(0x02, 0x00), addr(10, 1, 0, 2), 30, "leaf1spine");
    spine.add_interface("eth1", mac(0x02, 0x01), addr(10, 2, 0, 1), 30, "leaf2spine");
    spine.routing_table.add_route_from(
        vtep1,
        32,
        Some(addr(10, 1, 0, 1)),
        "eth0",
        RouteSource::Static,
    );
    spine.routing_table.add_route_from(
        vtep2,
        32,
        Some(addr(10, 2, 0, 2)),
        "eth1",
        RouteSource::Static,
    );

    let mut leaf2 = LabRouter::new("leaf2");
    leaf2.add_interface(
        "eth0",
        mac(0x03, 0x00),
        addr(192, 168, 10, 2),
        24,
        "tenant2",
    );
    leaf2.add_interface("eth1", mac(0x03, 0x01), addr(10, 2, 0, 2), 30, "leaf2spine");
    leaf2.add_interface("lo0", mac(0x03, 0xFF), vtep2, 32, "lo2");
    leaf2.routing_table.add_route_from(
        vtep1,
        32,
        Some(addr(10, 2, 0, 1)),
        "eth1",
        RouteSource::Static,
    );
    leaf2
        .enable_bgp(leaf2_as, addr(3, 3, 3, 3))
        .set_hold_time(9);
    leaf2.add_bgp_peer(vtep1, leaf1_as, vtep2, BgpPeerMode::Passive);
    leaf2.enable_vtep(vtep2, "eth1");
    leaf2.add_evpn_instance(
        VNI,
        RouteDistinguisher::new(vtep2, VNI as u16),
        &[evpn_rt(65001, VNI)],
        &[evpn_rt(65001, VNI)],
    );
    leaf2.attach_evpn_access_port(VNI, "eth0");

    lab.add_router(leaf1);
    lab.add_router(spine);
    lab.add_router(leaf2);
    lab
}

// ============================================================================
// EVPN route reflector fabrics
// ============================================================================

/// The autonomous system every speaker in the route reflector fabrics belongs
/// to. Route reflection is an iBGP mechanism, so there is only one.
pub const RR_FABRIC_AS: u32 = 65000;
/// The tenant VNI carried across the route reflector fabrics.
pub const RR_FABRIC_VNI: u32 = 5001;

/// Builds the single route reflector EVPN fabric:
///
/// ```text
///  host_a 192.168.10.11              host_b 192.168.10.22
///        |  tenant1                        |  tenant2
///      leaf1                             leaf2
///      VTEP 10.0.0.1                     VTEP 10.0.0.2
///        \  10.1.0.1/30        10.2.0.2/30  /
///         \------------ rr1 --------------/
///                 VTEP-less, 10.0.0.254
/// ```
///
/// `rr1` is the whole point of the topology. It is the IP underlay between the
/// two leaves *and* the only BGP peer either of them has, but it is configured
/// with:
///
/// * no VTEP,
/// * no EVPN instance and no VNI,
/// * no import Route Target.
///
/// It offers the L2VPN EVPN family so its clients can negotiate it, and both
/// leaves are marked route reflector clients. Every EVPN route that reaches a
/// leaf therefore has to have been retained and reflected by a router that owns
/// no part of the tenant it is carrying - which is exactly what an EVPN route
/// reflector is for, and what the old Route-Target-filter-on-import design made
/// impossible.
///
/// There is no leaf-to-leaf BGP session.
pub fn build_evpn_rr_fabric() -> VirtualLab {
    let mut lab = VirtualLab::new();
    for link in [
        "tenant1", "tenant2", "leaf1rr1", "leaf2rr1", "lo1", "lo2", "lorr1",
    ] {
        lab.add_link(link);
    }
    add_rr_tenant_hosts(&mut lab);

    let mut leaf1 = rr_leaf(
        "leaf1",
        1,
        LEAF1_VTEP,
        ip(1, 1, 1, 1),
        "tenant1",
        ip(192, 168, 10, 1),
    );
    leaf1.add_interface("eth1", rr_mac(0x01, 0x01), ip(10, 1, 0, 1), 30, "leaf1rr1");
    leaf1.add_interface("lo0", rr_mac(0x01, 0xFF), LEAF1_VTEP, 32, "lo1");
    for dst in [RR1_ID, LEAF2_VTEP] {
        leaf1.routing_table.add_route_from(
            dst,
            32,
            Some(ip(10, 1, 0, 2)),
            "eth1",
            RouteSource::Static,
        );
    }
    leaf1.add_bgp_peer(RR1_ID, RR_FABRIC_AS, LEAF1_VTEP, BgpPeerMode::Active);
    finish_rr_leaf(&mut leaf1, LEAF1_VTEP);

    let mut leaf2 = rr_leaf(
        "leaf2",
        3,
        LEAF2_VTEP,
        ip(3, 3, 3, 3),
        "tenant2",
        ip(192, 168, 10, 2),
    );
    leaf2.add_interface("eth1", rr_mac(0x03, 0x01), ip(10, 2, 0, 2), 30, "leaf2rr1");
    leaf2.add_interface("lo0", rr_mac(0x03, 0xFF), LEAF2_VTEP, 32, "lo2");
    for dst in [RR1_ID, LEAF1_VTEP] {
        leaf2.routing_table.add_route_from(
            dst,
            32,
            Some(ip(10, 2, 0, 1)),
            "eth1",
            RouteSource::Static,
        );
    }
    leaf2.add_bgp_peer(RR1_ID, RR_FABRIC_AS, LEAF2_VTEP, BgpPeerMode::Active);
    finish_rr_leaf(&mut leaf2, LEAF2_VTEP);

    let mut rr1 = LabRouter::new("rr1");
    rr1.add_interface("eth0", rr_mac(0x09, 0x00), ip(10, 1, 0, 2), 30, "leaf1rr1");
    rr1.add_interface("eth1", rr_mac(0x09, 0x01), ip(10, 2, 0, 1), 30, "leaf2rr1");
    rr1.add_interface("lo0", rr_mac(0x09, 0xFF), RR1_ID, 32, "lorr1");
    rr1.routing_table.add_route_from(
        LEAF1_VTEP,
        32,
        Some(ip(10, 1, 0, 1)),
        "eth0",
        RouteSource::Static,
    );
    rr1.routing_table.add_route_from(
        LEAF2_VTEP,
        32,
        Some(ip(10, 2, 0, 2)),
        "eth1",
        RouteSource::Static,
    );
    rr1.enable_bgp(RR_FABRIC_AS, RR1_ID).set_hold_time(9);
    rr1.enable_evpn_control_plane_only();
    for leaf in [LEAF1_VTEP, LEAF2_VTEP] {
        rr1.add_bgp_peer(leaf, RR_FABRIC_AS, RR1_ID, BgpPeerMode::Passive);
        rr1.set_bgp_route_reflector_client(leaf, true);
    }

    lab.add_router(leaf1);
    lab.add_router(rr1);
    lab.add_router(leaf2);
    lab
}

/// Builds the redundant two-reflector EVPN fabric:
///
/// ```text
///                    rr1  10.0.0.254
///                  /     \
///              leaf1     leaf2
///                  \     /
///                    rr2  10.0.0.253
/// ```
///
/// Both leaves peer with both reflectors and with neither each other. The two
/// reflectors also peer with one another as ordinary non-client iBGP neighbours,
/// which is what makes this topology a loop test as well as a redundancy one: a
/// route from leaf1 reaches rr2 twice over, directly and through rr1, and comes
/// back towards leaf1 from a reflector leaf1 never gave it to.
///
/// The reflectors keep *distinct* cluster identifiers, so each accepts what the
/// other reflects and both paths genuinely exist. Nothing stops them from being
/// given the same one - and `set_bgp_cluster_id` is how - but then each would
/// discard the other's reflections as its own cluster coming back, which is a
/// different design with only one live path.
pub fn build_evpn_dual_rr_fabric() -> VirtualLab {
    dual_rr_fabric(ip(1, 1, 1, 1), ip(3, 3, 3, 3))
}

/// The same two-reflector fabric with the leaves' BGP identifiers numbered
/// *above* both reflectors'.
///
/// The topology is identical and nothing about it is misconfigured; a fabric
/// whose loopbacks happen to number that way is ordinary. What it is for is a
/// regression: the decision process ends in a comparison of the advertising
/// speaker's identifier, so a high leaf identifier is exactly the condition under
/// which each reflector would otherwise prefer the *other* reflector's reflected
/// copy of a leaf's route over the copy the leaf advertised to it directly.
///
/// Each reflector would then see its best path as coming from its peer, withdraw
/// from it under split horizon, immediately lose the path that withdrawal
/// removed, and re-advertise - for ever. The fabric stays correct throughout and
/// never goes quiet. RFC 4456 section 9's shortest-CLUSTER_LIST tie-break is what
/// stops it, and this fabric is how that stays true.
pub fn build_evpn_rr_oscillation_fabric() -> VirtualLab {
    dual_rr_fabric(ip(200, 1, 1, 1), ip(200, 3, 3, 3))
}

fn dual_rr_fabric(leaf1_id: Ipv4Address, leaf2_id: Ipv4Address) -> VirtualLab {
    let mut lab = VirtualLab::new();
    for link in [
        "tenant1", "tenant2", "leaf1rr1", "leaf2rr1", "leaf1rr2", "leaf2rr2", "rr1rr2", "lo1",
        "lo2", "lorr1", "lorr2",
    ] {
        lab.add_link(link);
    }
    add_rr_tenant_hosts(&mut lab);

    // Leaf 1: one underlay link to each reflector, and a session to each.
    let mut leaf1 = rr_leaf(
        "leaf1",
        1,
        LEAF1_VTEP,
        leaf1_id,
        "tenant1",
        ip(192, 168, 10, 1),
    );
    leaf1.add_interface("eth1", rr_mac(0x01, 0x01), ip(10, 1, 0, 1), 30, "leaf1rr1");
    leaf1.add_interface("eth2", rr_mac(0x01, 0x02), ip(10, 3, 0, 1), 30, "leaf1rr2");
    leaf1.add_interface("lo0", rr_mac(0x01, 0xFF), LEAF1_VTEP, 32, "lo1");
    leaf1.routing_table.add_route_from(
        RR1_ID,
        32,
        Some(ip(10, 1, 0, 2)),
        "eth1",
        RouteSource::Static,
    );
    leaf1.routing_table.add_route_from(
        RR2_ID,
        32,
        Some(ip(10, 3, 0, 2)),
        "eth2",
        RouteSource::Static,
    );
    // The far leaf is reachable through either reflector; rr1 is the primary
    // underlay path, which is deliberate: it means killing rr1's *sessions* does
    // not by itself kill the VXLAN path, so a failover test measures the control
    // plane rather than the wire.
    leaf1.routing_table.add_route_from(
        LEAF2_VTEP,
        32,
        Some(ip(10, 3, 0, 2)),
        "eth2",
        RouteSource::Static,
    );
    leaf1.add_bgp_peer(RR1_ID, RR_FABRIC_AS, LEAF1_VTEP, BgpPeerMode::Active);
    leaf1.add_bgp_peer(RR2_ID, RR_FABRIC_AS, LEAF1_VTEP, BgpPeerMode::Active);
    finish_rr_leaf(&mut leaf1, LEAF1_VTEP);

    let mut leaf2 = rr_leaf(
        "leaf2",
        3,
        LEAF2_VTEP,
        leaf2_id,
        "tenant2",
        ip(192, 168, 10, 2),
    );
    leaf2.add_interface("eth1", rr_mac(0x03, 0x01), ip(10, 2, 0, 2), 30, "leaf2rr1");
    leaf2.add_interface("eth2", rr_mac(0x03, 0x02), ip(10, 4, 0, 2), 30, "leaf2rr2");
    leaf2.add_interface("lo0", rr_mac(0x03, 0xFF), LEAF2_VTEP, 32, "lo2");
    leaf2.routing_table.add_route_from(
        RR1_ID,
        32,
        Some(ip(10, 2, 0, 1)),
        "eth1",
        RouteSource::Static,
    );
    leaf2.routing_table.add_route_from(
        RR2_ID,
        32,
        Some(ip(10, 4, 0, 1)),
        "eth2",
        RouteSource::Static,
    );
    leaf2.routing_table.add_route_from(
        LEAF1_VTEP,
        32,
        Some(ip(10, 4, 0, 1)),
        "eth2",
        RouteSource::Static,
    );
    leaf2.add_bgp_peer(RR1_ID, RR_FABRIC_AS, LEAF2_VTEP, BgpPeerMode::Active);
    leaf2.add_bgp_peer(RR2_ID, RR_FABRIC_AS, LEAF2_VTEP, BgpPeerMode::Active);
    finish_rr_leaf(&mut leaf2, LEAF2_VTEP);

    let mut rr1 = LabRouter::new("rr1");
    rr1.add_interface("eth0", rr_mac(0x09, 0x00), ip(10, 1, 0, 2), 30, "leaf1rr1");
    rr1.add_interface("eth1", rr_mac(0x09, 0x01), ip(10, 2, 0, 1), 30, "leaf2rr1");
    rr1.add_interface("eth2", rr_mac(0x09, 0x02), ip(10, 5, 0, 1), 30, "rr1rr2");
    rr1.add_interface("lo0", rr_mac(0x09, 0xFF), RR1_ID, 32, "lorr1");
    rr1.routing_table.add_route_from(
        LEAF1_VTEP,
        32,
        Some(ip(10, 1, 0, 1)),
        "eth0",
        RouteSource::Static,
    );
    rr1.routing_table.add_route_from(
        LEAF2_VTEP,
        32,
        Some(ip(10, 2, 0, 2)),
        "eth1",
        RouteSource::Static,
    );
    rr1.routing_table.add_route_from(
        RR2_ID,
        32,
        Some(ip(10, 5, 0, 2)),
        "eth2",
        RouteSource::Static,
    );
    rr1.enable_bgp(RR_FABRIC_AS, RR1_ID).set_hold_time(9);
    rr1.enable_evpn_control_plane_only();
    for leaf in [LEAF1_VTEP, LEAF2_VTEP] {
        rr1.add_bgp_peer(leaf, RR_FABRIC_AS, RR1_ID, BgpPeerMode::Passive);
        rr1.set_bgp_route_reflector_client(leaf, true);
    }
    // The reflectors are ordinary non-client peers to each other.
    rr1.add_bgp_peer(RR2_ID, RR_FABRIC_AS, RR1_ID, BgpPeerMode::Active);

    let mut rr2 = LabRouter::new("rr2");
    rr2.add_interface("eth0", rr_mac(0x08, 0x00), ip(10, 3, 0, 2), 30, "leaf1rr2");
    rr2.add_interface("eth1", rr_mac(0x08, 0x01), ip(10, 4, 0, 1), 30, "leaf2rr2");
    rr2.add_interface("eth2", rr_mac(0x08, 0x02), ip(10, 5, 0, 2), 30, "rr1rr2");
    rr2.add_interface("lo0", rr_mac(0x08, 0xFF), RR2_ID, 32, "lorr2");
    rr2.routing_table.add_route_from(
        LEAF1_VTEP,
        32,
        Some(ip(10, 3, 0, 1)),
        "eth0",
        RouteSource::Static,
    );
    rr2.routing_table.add_route_from(
        LEAF2_VTEP,
        32,
        Some(ip(10, 4, 0, 2)),
        "eth1",
        RouteSource::Static,
    );
    rr2.routing_table.add_route_from(
        RR1_ID,
        32,
        Some(ip(10, 5, 0, 1)),
        "eth2",
        RouteSource::Static,
    );
    rr2.enable_bgp(RR_FABRIC_AS, RR2_ID).set_hold_time(9);
    rr2.enable_evpn_control_plane_only();
    for leaf in [LEAF1_VTEP, LEAF2_VTEP] {
        rr2.add_bgp_peer(leaf, RR_FABRIC_AS, RR2_ID, BgpPeerMode::Passive);
        rr2.set_bgp_route_reflector_client(leaf, true);
    }
    rr2.add_bgp_peer(RR1_ID, RR_FABRIC_AS, RR2_ID, BgpPeerMode::Passive);

    lab.add_router(leaf1);
    lab.add_router(rr1);
    lab.add_router(rr2);
    lab.add_router(leaf2);
    lab
}

/// Builds a deterministic control-plane scale fabric: two route reflectors and
/// `leaf_count` leaves, all on one underlay subnet, with `vnis` tenants on every
/// leaf.
///
/// ```text
///   rr1 10.20.0.254 ----+----+----+---- ... ----+---- rr2 10.20.0.253
///                       |    |    |             |
///                    leaf1 leaf2 leaf3   ...  leafN     10.20.0.1 .. 10.20.0.N
/// ```
///
/// Every leaf peers with both reflectors and with no other leaf; the reflectors
/// peer with each other as non-clients. Neither reflector has a VTEP, an EVPN
/// instance, or an import Route Target, so every route in the fabric is one a
/// reflector is carrying purely on somebody else's behalf.
///
/// One shared subnet is what keeps this a *control-plane* test: every VTEP
/// address is directly reachable, so nothing that happens depends on underlay
/// routing, and a route that fails to arrive failed in BGP.
///
/// The tenants are VNIs `6001 ..= 6000 + vnis`, each with Route Target
/// `65000:<vni>`, imported and exported by every leaf. Local MACs are learned
/// with [`Vtep::learn_local`] on a logical access port per tenant, which is the
/// same path a frame arriving on a real access port takes; what is skipped is
/// generating the frames, because this test is about how many routes the control
/// plane can carry correctly and not about the data plane.
pub fn build_evpn_rr_scale_fabric(leaf_count: u8, vnis: u32) -> VirtualLab {
    assert!(
        (1..=200).contains(&leaf_count),
        "leaf_count must fit the last octet of the underlay subnet"
    );
    let mut lab = VirtualLab::new();
    lab.add_link("underlay");

    let rr1 = ip(10, 20, 0, 254);
    let rr2 = ip(10, 20, 0, 253);

    let mut reflectors = Vec::new();
    for (name, addr, id, tag) in [
        ("rr1", rr1, ip(9, 9, 9, 1), 0xF1u8),
        ("rr2", rr2, ip(9, 9, 9, 2), 0xF2u8),
    ] {
        let mut r = LabRouter::new(name);
        r.add_interface("eth0", rr_mac(tag, 0x00), addr, 24, "underlay");
        r.enable_bgp(RR_FABRIC_AS, id).set_hold_time(9);
        r.enable_evpn_control_plane_only();
        reflectors.push((name, addr, r));
    }

    for n in 1..=leaf_count {
        let addr = ip(10, 20, 0, n);
        let mut leaf = LabRouter::new(&format!("leaf{}", n));
        leaf.add_interface("eth0", rr_mac(n, 0x00), addr, 24, "underlay");
        leaf.enable_bgp(RR_FABRIC_AS, ip(1, 1, 1, n))
            .set_hold_time(9);
        leaf.add_bgp_peer(rr1, RR_FABRIC_AS, addr, BgpPeerMode::Active);
        leaf.add_bgp_peer(rr2, RR_FABRIC_AS, addr, BgpPeerMode::Active);
        leaf.enable_vtep(addr, "eth0");
        for v in 0..vnis {
            let vni = SCALE_BASE_VNI + v;
            leaf.add_evpn_instance(
                vni,
                RouteDistinguisher::new(addr, vni as u16),
                &[evpn_rt(65000, vni)],
                &[evpn_rt(65000, vni)],
            );
            leaf.attach_evpn_access_port(vni, &scale_access_port(vni));
        }
        lab.add_router(leaf);

        for (_, _, r) in reflectors.iter_mut() {
            r.add_bgp_peer(addr, RR_FABRIC_AS, r.interfaces[0].ip, BgpPeerMode::Passive);
            r.set_bgp_route_reflector_client(addr, true);
        }
    }

    // The reflectors peer with each other as ordinary non-clients.
    let mut it = reflectors.into_iter();
    let (_, addr1, mut r1) = it.next().unwrap();
    let (_, addr2, mut r2) = it.next().unwrap();
    r1.add_bgp_peer(addr2, RR_FABRIC_AS, addr1, BgpPeerMode::Active);
    r2.add_bgp_peer(addr1, RR_FABRIC_AS, addr2, BgpPeerMode::Passive);
    lab.add_router(r1);
    lab.add_router(r2);
    lab
}

/// First VNI of the scale fabric's tenant range.
pub const SCALE_BASE_VNI: u32 = 6001;

/// The logical access port a scale-fabric tenant is attached to.
pub fn scale_access_port(vni: u32) -> String {
    format!("acc{}", vni)
}

/// A deterministic tenant MAC for leaf `leaf`, tenant `vni`, host `host`.
///
/// The leaf number is in the address, so a MAC that turns up behind the wrong
/// VTEP is obvious, and the VNI is in it too, so a route that leaks between
/// tenants is equally obvious.
pub fn scale_mac(leaf: u8, vni: u32, host: u8) -> MacAddress {
    MacAddress([0x02, 0x00, leaf, (vni >> 8) as u8, vni as u8, host])
}

/// Teaches every leaf `hosts` local MACs in every tenant, exactly as an access
/// port would. Returns how many Type 2 routes that should produce fabric-wide.
pub fn populate_scale_fabric(lab: &mut VirtualLab, leaf_count: u8, vnis: u32, hosts: u8) -> usize {
    let mut total = 0usize;
    for n in 1..=leaf_count {
        let name = format!("leaf{}", n);
        let Some(router) = lab.router_mut(&name) else {
            continue;
        };
        let Some(vtep) = router.vtep_mut() else {
            continue;
        };
        for v in 0..vnis {
            let vni = SCALE_BASE_VNI + v;
            let port = scale_access_port(vni);
            for h in 1..=hosts {
                if vtep.learn_local(&port, scale_mac(n, vni, h), None) {
                    total += 1;
                }
            }
        }
    }
    total
}

/// VTEP address of `leaf1` in the route reflector fabrics.
pub const LEAF1_VTEP: Ipv4Address = Ipv4Address([10, 0, 0, 1]);
/// VTEP address of `leaf2` in the route reflector fabrics.
pub const LEAF2_VTEP: Ipv4Address = Ipv4Address([10, 0, 0, 2]);
/// BGP identifier and session address of `rr1`. It is not a VTEP.
pub const RR1_ID: Ipv4Address = Ipv4Address([10, 0, 0, 254]);
/// BGP identifier and session address of `rr2`. It is not a VTEP.
pub const RR2_ID: Ipv4Address = Ipv4Address([10, 0, 0, 253]);

fn rr_mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0x00, 0x00, 0x00, a, b])
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Address {
    Ipv4Address::new(a, b, c, d)
}

/// The two tenant hosts. They share a /24 and have no gateway, so nothing but the
/// overlay can carry a packet between them.
fn add_rr_tenant_hosts(lab: &mut VirtualLab) {
    lab.add_host(
        "host_a",
        "tenant1",
        NetStackConfig {
            mac: rr_mac(0x0A, 0x0A),
            ip: ip(192, 168, 10, 11),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    lab.add_host(
        "host_b",
        "tenant2",
        NetStackConfig {
            mac: rr_mac(0x0B, 0x0B),
            ip: ip(192, 168, 10, 22),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
}

/// A leaf with its access interface and BGP speaker, before its underlay links.
fn rr_leaf(
    name: &str,
    tag: u8,
    _vtep: Ipv4Address,
    router_id: Ipv4Address,
    tenant_link: &str,
    access_ip: Ipv4Address,
) -> LabRouter {
    let mut leaf = LabRouter::new(name);
    leaf.add_interface("eth0", rr_mac(tag, 0x00), access_ip, 24, tenant_link);
    leaf.enable_bgp(RR_FABRIC_AS, router_id).set_hold_time(9);
    leaf
}

/// Gives a leaf its VTEP and its one tenant instance.
fn finish_rr_leaf(leaf: &mut LabRouter, vtep: Ipv4Address) {
    leaf.enable_vtep(vtep, "eth1");
    leaf.add_evpn_instance(
        RR_FABRIC_VNI,
        RouteDistinguisher::new(vtep, RR_FABRIC_VNI as u16),
        &[evpn_rt(65000, RR_FABRIC_VNI)],
        &[evpn_rt(65000, RR_FABRIC_VNI)],
    );
    leaf.attach_evpn_access_port(RR_FABRIC_VNI, "eth0");
}

/// Drives `lab` until every BGP session carries EVPN and every VTEP has learned
/// at least one remote MAC, or the simulated deadline passes.
///
/// Routers with no VTEP - the route reflectors - are held to the session half of
/// that condition only. A reflector that had learned a remote MAC would be a bug,
/// not progress.
pub fn converge_rr_fabric(lab: &mut VirtualLab, max_sim_ms: u64) -> bool {
    lab.run_until(250, max_sim_ms, |l| {
        l.routers.values().all(|r| match (r.bgp(), r.vtep()) {
            (Some(b), Some(v)) => {
                b.peers().iter().all(|p| p.carries_evpn()) && v.remote_mac_count() > 0
            }
            (Some(b), None) => b.peers().iter().all(|p| p.carries_evpn()),
            _ => true,
        })
    })
}

/// Drives `lab` until every configured BGP session is ESTABLISHED and every VTEP
/// has been told about at least one remote MAC, or the simulated deadline passes.
///
/// The second half of that condition is the point: a session that is up but has
/// exchanged no EVPN route has not converged the overlay.
pub fn converge_evpn(lab: &mut VirtualLab, max_sim_ms: u64) -> bool {
    lab.run_until(250, max_sim_ms, |l| {
        l.routers.values().all(|r| match (r.bgp(), r.vtep()) {
            (Some(b), Some(v)) => {
                b.peers().iter().all(|p| p.carries_evpn()) && v.remote_mac_count() > 0
            }
            _ => true,
        })
    })
}

/// Drives `lab` until every configured BGP session is ESTABLISHED and every speaker has
/// installed at least one learned route, or the simulated deadline passes. Purely
/// simulated time: no thread sleeps.
pub fn converge_bgp(lab: &mut VirtualLab, max_sim_ms: u64) -> bool {
    lab.run_until(250, max_sim_ms, |l| {
        l.routers.values().all(|r| match r.bgp() {
            Some(b) => {
                b.peers()
                    .iter()
                    .all(|p| p.state == crate::bgp_router::BgpState::Established)
                    && !b.loc_rib.is_empty()
            }
            None => true,
        })
    })
}

/// Deterministic Virtual Network Lab orchestrator.
#[derive(Default)]
pub struct VirtualLab {
    pub links: HashMap<String, VirtualLink>,
    pub hosts: HashMap<String, LabHost>,
    pub routers: HashMap<String, LabRouter>,
    pub in_flight_frames: Vec<(String, String, Vec<u8>)>, // (sender_node, link_name, frame)
    pub total_steps_executed: usize,
    pub total_frames_delivered: usize,
    pub current_time_ms: u64,
}

impl VirtualLab {
    pub fn new() -> Self {
        VirtualLab {
            links: HashMap::new(),
            hosts: HashMap::new(),
            routers: HashMap::new(),
            in_flight_frames: Vec::new(),
            total_steps_executed: 0,
            total_frames_delivered: 0,
            current_time_ms: 0,
        }
    }

    pub fn add_link(&mut self, name: &str) {
        self.links.insert(name.to_string(), VirtualLink::new(name));
    }

    pub fn add_link_with_mtu(&mut self, name: &str, mtu: usize) {
        self.links
            .insert(name.to_string(), VirtualLink::new(name).with_mtu(mtu));
    }

    pub fn add_host(&mut self, name: &str, link_name: &str, config: NetStackConfig) {
        if !self.links.contains_key(link_name) {
            self.add_link(link_name);
        }
        let host = LabHost::new(name, link_name, config);
        self.hosts.insert(name.to_string(), host);
    }

    pub fn add_router(&mut self, router: LabRouter) {
        for iface in &router.interfaces {
            if !self.links.contains_key(&iface.link_name) {
                self.add_link(&iface.link_name);
            }
        }
        self.routers.insert(router.name.clone(), router);
    }

    pub fn host(&self, name: &str) -> Option<&LabHost> {
        self.hosts.get(name)
    }

    pub fn host_mut(&mut self, name: &str) -> Option<&mut LabHost> {
        self.hosts.get_mut(name)
    }

    pub fn router(&self, name: &str) -> Option<&LabRouter> {
        self.routers.get(name)
    }

    pub fn router_mut(&mut self, name: &str) -> Option<&mut LabRouter> {
        self.routers.get_mut(name)
    }

    pub fn link(&self, name: &str) -> Option<&VirtualLink> {
        self.links.get(name)
    }

    pub fn link_mut(&mut self, name: &str) -> Option<&mut VirtualLink> {
        self.links.get_mut(name)
    }

    pub fn enable_pcap(&mut self, link_name: &str) {
        if let Some(link) = self.links.get_mut(link_name) {
            link.enable_pcap();
        }
    }

    pub fn export_pcap(&mut self, link_name: &str) -> Option<Vec<u8>> {
        self.links
            .get_mut(link_name)
            .and_then(|l| l.take_pcap_bytes())
    }

    /// Queues a raw frame transmission originating from a host.
    pub fn send_from_host(&mut self, host_name: &str, frame: Vec<u8>) {
        if let Some(host) = self.hosts.get(host_name) {
            self.in_flight_frames
                .push((host_name.to_string(), host.link_name.clone(), frame));
        }
    }

    /// Collects everything every host's socket runtime wants to transmit at the current
    /// simulated time and queues it on the owning link, without advancing the clock.
    ///
    /// This is what turns an application-level `tcp_write` into frames on the wire: the
    /// application never touches a packet, the lab pumps the stack instead.
    pub fn pump(&mut self) -> usize {
        let mut queued = 0;
        let mut host_names: Vec<String> = self.hosts.keys().cloned().collect();
        host_names.sort();
        for h_name in host_names {
            let host = self.hosts.get_mut(&h_name).unwrap();
            let link_name = host.link_name.clone();
            for f in host.stack.poll_transmit() {
                self.in_flight_frames
                    .push((h_name.clone(), link_name.clone(), f));
                queued += 1;
            }
        }
        queued += self.pump_routers();
        queued
    }

    /// Runs every router's control plane and socket runtime at the current simulated
    /// time and queues whatever they emit. Routers with no socket runtime produce
    /// nothing, so a topology without a routing process is unaffected.
    fn pump_routers(&mut self) -> usize {
        let mut queued = 0;
        let now = self.current_time_ms;
        let mut router_names: Vec<String> = self.routers.keys().cloned().collect();
        router_names.sort();
        for r_name in router_names {
            let router = self.routers.get_mut(&r_name).unwrap();
            if router.sockets.is_none() {
                continue;
            }
            for (link_name, frame) in router.step_timers(now) {
                self.in_flight_frames
                    .push((r_name.clone(), link_name, frame));
                queued += 1;
            }
        }
        queued
    }

    /// Advances simulated logical time by `ms` and runs every host's timers, queueing any
    /// resulting frames (retransmissions, deferred FINs, window probes, new data).
    pub fn advance_time(&mut self, ms: u64) -> usize {
        self.current_time_ms += ms;
        let mut queued = 0;
        let mut host_names: Vec<String> = self.hosts.keys().cloned().collect();
        host_names.sort();
        for h_name in host_names {
            let host = self.hosts.get_mut(&h_name).unwrap();
            let link_name = host.link_name.clone();
            let frames = host.stack.step_timers(self.current_time_ms);
            for f in frames {
                self.in_flight_frames
                    .push((h_name.clone(), link_name.clone(), f));
                queued += 1;
            }
        }
        // Routers run their BGP timers off the same logical clock, so a hold timer
        // expires because simulated time passed, never because a thread slept.
        queued += self.pump_routers();
        queued
    }

    /// Runs the network to quiescence at the current time, pumping host sockets between
    /// steps so application writes turn into frames without needing the clock to move.
    pub fn run_pumped(&mut self, max_rounds: usize) -> usize {
        let mut steps = 0;
        for _ in 0..max_rounds {
            let queued = self.pump();
            if queued == 0 && self.in_flight_frames.is_empty() {
                break;
            }
            steps += self.run_until_quiescent(200);
        }
        steps
    }

    /// Drives the simulation until `predicate` holds or the simulated deadline passes.
    ///
    /// Each round pumps every host, runs the network to quiescence, then advances the
    /// clock by `tick_ms` so retransmission timers can fire. Returns true if the
    /// predicate was satisfied. Purely simulated time: no thread ever sleeps.
    pub fn run_until<F>(&mut self, tick_ms: u64, max_sim_ms: u64, mut predicate: F) -> bool
    where
        F: FnMut(&VirtualLab) -> bool,
    {
        let deadline = self.current_time_ms + max_sim_ms;
        self.run_pumped(50);
        if predicate(self) {
            return true;
        }
        while self.current_time_ms < deadline {
            self.advance_time(tick_ms.max(1));
            self.run_pumped(50);
            if predicate(self) {
                return true;
            }
        }
        false
    }

    /// Executes one discrete simulation step:
    /// Drains current in-flight frames, passes each through the corresponding link fault model,
    /// delivers ready frames to connected hosts and routers on that link, and collects newly
    /// generated reply or transit frames into the in-flight queue.
    pub fn step(&mut self) -> usize {
        // Give every host's socket runtime a chance to emit before draining the wire, so a
        // plain `step()` loop carries application data without an explicit pump.
        self.pump();

        if self.in_flight_frames.is_empty() {
            return 0;
        }

        self.total_steps_executed += 1;
        let current_batch = std::mem::take(&mut self.in_flight_frames);
        let mut next_batch = Vec::new();
        let mut frames_processed = 0;

        for (sender, link_name, raw_frame) in current_batch {
            frames_processed += 1;

            // 1. Traverse Link (applies MTU, Drops, Corruption, Reordering, PCAP Tap)
            let delivered_frames = match self.links.get_mut(&link_name) {
                Some(link) => link.process_frames_transit(raw_frame),
                None => vec![raw_frame],
            };

            for delivered_frame in delivered_frames {
                self.total_frames_delivered += 1;

                // 2. Deliver to all other Hosts on this link
                let host_names: Vec<String> = self.hosts.keys().cloned().collect();
                for h_name in host_names {
                    if h_name == sender {
                        continue;
                    }
                    let host = self.hosts.get_mut(&h_name).unwrap();
                    if host.link_name == link_name {
                        let replies = host.stack.process_frame(&delivered_frame);
                        for reply in replies {
                            next_batch.push((h_name.clone(), link_name.clone(), reply));
                        }
                    }
                }

                // 3. Deliver to all Routers with an interface attached to this link
                let router_names: Vec<String> = self.routers.keys().cloned().collect();
                for r_name in router_names {
                    if r_name == sender {
                        continue;
                    }
                    let router = self.routers.get_mut(&r_name).unwrap();
                    let outgoing = router.process_incoming_frame(&link_name, &delivered_frame);
                    for (egress_link, frame) in outgoing {
                        next_batch.push((r_name.clone(), egress_link, frame));
                    }
                }
            }
        }

        self.in_flight_frames = next_batch;
        frames_processed
    }

    /// Runs simulation steps until no frames remain in-flight or `max_steps` is reached.
    /// Returns the total number of steps executed.
    pub fn run_until_quiescent(&mut self, max_steps: usize) -> usize {
        let mut steps = 0;
        while !self.in_flight_frames.is_empty() && steps < max_steps {
            self.step();
            steps += 1;
        }
        steps
    }

    /// Triggers all RIPv2-enabled routers in the lab to generate and transmit periodic routing updates.
    pub fn broadcast_rip_advertisements(&mut self) {
        let router_names: Vec<String> = self.routers.keys().cloned().collect();
        for r_name in router_names {
            let router = self.routers.get(&r_name).unwrap();
            let updates = router.generate_rip_advertisements();
            for (link_name, frame) in updates {
                self.in_flight_frames
                    .push((r_name.clone(), link_name, frame));
            }
        }
    }

    /// Advances simulated time in discrete ticks of `step_dt_ms` up to `max_sim_ms`,
    /// running each step to quiescence until the network is idle.
    pub fn run_until_idle_or_timeout(&mut self, max_sim_ms: u64, step_dt_ms: u64) -> u64 {
        let start = self.current_time_ms;
        let limit = start + max_sim_ms;
        while self.current_time_ms < limit {
            self.run_until_quiescent(50);
            let queued = self.advance_time(step_dt_ms);
            self.run_until_quiescent(50);
            if queued == 0 && self.in_flight_frames.is_empty() {
                // If quiescent and no new timer events triggered, jump ahead or complete
                break;
            }
        }
        self.current_time_ms - start
    }
}
