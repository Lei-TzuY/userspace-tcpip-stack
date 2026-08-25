//! Unified NetStack: Dual-Stack IPv4/IPv6 Layer 2 -> Layer 3 -> Layer 4 packet processing pipeline.

use crate::arp::{ArpOpcode, ArpPacket, ArpTable};
use crate::ethernet::{
    ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, EtherType, EthernetFrame, MacAddress,
};
use crate::firewall::{Firewall, FirewallAction, FirewallChain};
use crate::icmp::{IcmpPacket, IcmpType};
use crate::icmpv6::{
    ICMPV6_TYPE_ECHO_REPLY, ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT,
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_ROUTER_ADVERT, Icmpv6Packet, NdpTable,
    RouterAdvertisement, ipv6_multicast_mac, slaac_address,
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

pub struct NetStack {
    pub config: NetStackConfig,
    pub arp_table: ArpTable,
    pub ndp_table: NdpTable,
    pub routing_table: RoutingTable,
    pub ipv6_routing_table: Ipv6RoutingTable,
    ipv6_prefix_len: Option<u8>,
    ipv6_gateway: Option<Ipv6Address>,
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
        self.pending_ndp_packets.clear();
    }

    /// Emits a Router Solicitation to ff02::2. An unconfigured host uses the
    /// unspecified IPv6 source and therefore omits the source-link-layer option.
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
            let ns = Icmpv6Packet::build_neighbor_solicitation(
                my_ip6,
                next_hop,
                next_hop,
                self.config.mac,
            );
            let ip6_ns = Ipv6Packet::serialize(my_ip6, next_hop, NEXT_HEADER_ICMPV6, 255, &ns);
            Some(EthernetFrame::serialize(
                MacAddress::BROADCAST,
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
                    // Update NDP Cache with sender
                    self.ndp_table.insert(ip6_pkt.header.src_ip, eth.src_mac);

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
                            ICMPV6_TYPE_ROUTER_ADVERT => {
                                if ip6_pkt.header.hop_limit == 255
                                    && ip6_pkt.header.src_ip.is_link_local()
                                    && let Some(ra) = RouterAdvertisement::parse(&icmp6)
                                    && let Some(prefix) = ra.prefixes.iter().find(|prefix| {
                                        prefix.autonomous
                                            && prefix.prefix_length == 64
                                            && prefix.valid_lifetime > 0
                                    })
                                    && let Some(address) = slaac_address(
                                        prefix.prefix,
                                        prefix.prefix_length,
                                        self.config.mac,
                                    )
                                {
                                    let gateway =
                                        (ra.router_lifetime > 0).then_some(ip6_pkt.header.src_ip);
                                    self.configure_ipv6_interface(
                                        address,
                                        prefix.prefix_length,
                                        gateway,
                                    );
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
                                if icmp6.payload.len() >= 20 {
                                    let mut target_bytes = [0u8; 16];
                                    target_bytes.copy_from_slice(&icmp6.payload[4..20]);
                                    let target_ip6 = Ipv6Address(target_bytes);

                                    if target_ip6 == my_ip6 {
                                        let na = Icmpv6Packet::build_neighbor_advertisement(
                                            my_ip6,
                                            ip6_pkt.header.src_ip,
                                            my_ip6,
                                            self.config.mac,
                                            false,
                                            true,
                                            true,
                                        );
                                        let ip6_out = Ipv6Packet::serialize(
                                            my_ip6,
                                            ip6_pkt.header.src_ip,
                                            NEXT_HEADER_ICMPV6,
                                            64,
                                            &na,
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
                            }

                            ICMPV6_TYPE_NEIGHBOR_ADVERT if icmp6.payload.len() >= 20 => {
                                let mut target_bytes = [0u8; 16];
                                target_bytes.copy_from_slice(&icmp6.payload[4..20]);
                                let target_ip6 = Ipv6Address(target_bytes);

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
