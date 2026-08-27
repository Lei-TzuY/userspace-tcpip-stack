from pathlib import Path

lab = Path("src/lab.rs")
text = lab.read_text()

next_id = '''    fn next_ip_id(&mut self) -> u16 {
        let id = self.ip_id_counter;
        self.ip_id_counter = self.ip_id_counter.wrapping_add(1);
        id
    }
'''
if text.count(next_id) != 1:
    raise SystemExit("next_ip_id marker mismatch")
helper = next_id + r'''

    fn is_ipv4_directed_broadcast(&self, address: Ipv4Address) -> bool {
        self.interfaces.iter().any(|iface| {
            let prefix_len = iface.subnet_mask.min(32);
            if prefix_len >= 31 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            let network = iface.ip.to_u32() & mask;
            let broadcast = network | !mask;
            address.to_u32() == broadcast
        })
    }

    /// RFC 1812 section 4.3.2.7: generic suppression rules for router-generated
    /// IPv4 ICMP errors. These rules take precedence over requirements to emit a
    /// particular error such as Time Exceeded or Network Unreachable.
    fn should_send_icmpv4_error(
        &self,
        invoking: &Ipv4Packet<'_>,
        link_destination: MacAddress,
    ) -> bool {
        let src = invoking.header.src_ip;
        let dst = invoking.header.dst_ip;

        let invalid_source = src.0[0] == 0
            || src.is_loopback()
            || src.is_multicast()
            || src.is_broadcast()
            || src.0[0] >= 240
            || self.is_ipv4_directed_broadcast(src);
        if invalid_source {
            return false;
        }

        if dst.is_broadcast()
            || dst.is_multicast()
            || self.is_ipv4_directed_broadcast(dst)
            || !link_destination.is_unicast()
            || invoking.header.fragment_offset != 0
        {
            return false;
        }

        if invoking.header.protocol == crate::ipv4::IpProtocol::Icmp
            && invoking.payload.first().is_some_and(|icmp_type| {
                matches!(*icmp_type, 3 | 4 | 5 | 11 | 12)
            })
        {
            return false;
        }

        true
    }
'''
text = text.replace(next_id, helper, 1)

old_ttl = '''                        if ip_pkt.header.ttl <= 1 {
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
'''
new_ttl = '''                        if ip_pkt.header.ttl <= 1 {
                            // RFC 1812 sections 4.3.2.7 and 5.2.7.3: emit Time
                            // Exceeded only when the invoking packet is eligible
                            // to receive an ICMP error.
                            if self.should_send_icmpv4_error(&ip_pkt, eth.dst_mac) {
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
                            }
                            return out_transmissions;
                        }
'''
if text.count(old_ttl) != 1:
    raise SystemExit("TTL block mismatch")
text = text.replace(old_ttl, new_ttl, 1)

old_route = '''                        // 3. Routing Table Lookup (LPM)
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
'''
new_route = '''                        // 3. Routing Table Lookup (LPM)
                        let Some(route) = self.routing_table.lookup(ip_pkt.header.dst_ip).cloned()
                        else {
                            // RFC 1812 section 4.3.3.1: no route at all requires
                            // Destination Unreachable, Code 0 (Network Unreachable),
                            // subject to the generic ICMP error suppression rules.
                            if self.should_send_icmpv4_error(&ip_pkt, eth.dst_mac) {
                                let unreachable =
                                    IcmpPacket::build_destination_unreachable(0, 0, eth.payload);
                                let ip_id = self.next_ip_id();
                                let ip_out = Ipv4Packet::serialize(
                                    ingress_iface.ip,
                                    ip_pkt.header.src_ip,
                                    IP_PROTO_ICMP,
                                    ip_id,
                                    64,
                                    &unreachable,
                                );
                                out_transmissions.push((
                                    ingress_link.to_string(),
                                    EthernetFrame::serialize(
                                        eth.src_mac,
                                        ingress_iface.mac,
                                        ETHERTYPE_IPV4,
                                        &ip_out,
                                    ),
                                ));
                            }
                            return out_transmissions;
                        };
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
'''
if text.count(old_route) != 1:
    raise SystemExit("route block mismatch")
text = text.replace(old_route, new_route, 1)
lab.write_text(text)

Path("tests/test_ipv4_icmp_error_suppression.rs").write_text(r'''use toy_tcpip::checksum::compute_checksum;
use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EthernetFrame, MacAddress};
use toy_tcpip::icmp::{
    ICMP_TYPE_DEST_UNREACHABLE, ICMP_TYPE_TIME_EXCEEDED, IcmpPacket, IcmpType,
};
use toy_tcpip::ipv4::{IP_PROTO_ICMP, IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use toy_tcpip::lab::LabRouter;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Address {
    Ipv4Address::new(a, b, c, d)
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn make_router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", mac(0x10), ip(192, 0, 2, 1), 24, "lan1");
    router.add_interface("eth1", mac(0x20), ip(198, 51, 100, 1), 24, "lan2");
    router
}

fn frame(
    src: Ipv4Address,
    dst: Ipv4Address,
    protocol: u8,
    ttl: u8,
    payload: &[u8],
    frame_dst: MacAddress,
) -> Vec<u8> {
    let packet = Ipv4Packet::serialize(src, dst, protocol, 0x1234, ttl, payload);
    EthernetFrame::serialize(frame_dst, mac(0x11), ETHERTYPE_IPV4, &packet)
}

fn parse_icmp_output(raw: &[u8]) -> IcmpPacket<'_> {
    let eth = EthernetFrame::parse(raw).unwrap();
    let packet = Ipv4Packet::parse(eth.payload, true).unwrap();
    IcmpPacket::parse(packet.payload, true).unwrap()
}

#[test]
fn ordinary_unicast_ttl_expiry_still_returns_time_exceeded() {
    let mut router = make_router();
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_UDP,
        1,
        b"udp",
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let icmp = parse_icmp_output(&out[0].1);
    assert_eq!(icmp.icmp_type, IcmpType::TimeExceeded);
    assert_eq!(icmp.icmp_type.to_u8(), ICMP_TYPE_TIME_EXCEEDED);
    assert_eq!(icmp.code, 0);
}

#[test]
fn no_route_returns_network_unreachable() {
    let mut router = make_router();
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(203, 0, 113, 9),
        IP_PROTO_UDP,
        64,
        b"udp",
        mac(0x10),
    );

    let out = router.process_incoming_frame("lan1", &raw);
    assert_eq!(out.len(), 1);
    let icmp = parse_icmp_output(&out[0].1);
    assert_eq!(icmp.icmp_type, IcmpType::DestinationUnreachable);
    assert_eq!(icmp.icmp_type.to_u8(), ICMP_TYPE_DEST_UNREACHABLE);
    assert_eq!(icmp.code, 0);
}

#[test]
fn ttl_expiry_is_suppressed_for_icmp_error_input() {
    let mut router = make_router();
    let quoted = Ipv4Packet::serialize(
        ip(198, 51, 100, 2),
        ip(192, 0, 2, 2),
        IP_PROTO_UDP,
        7,
        64,
        b"quoted",
    );
    let invoking_error = IcmpPacket::build_destination_unreachable(0, 0, &quoted);
    let raw = frame(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_ICMP,
        1,
        &invoking_error,
        mac(0x10),
    );

    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}

#[test]
fn icmp_errors_are_suppressed_for_ip_and_link_layer_broadcast_or_multicast() {
    let source = ip(192, 0, 2, 2);
    let cases = [
        (ip(224, 0, 0, 9), mac(0x10)),
        (Ipv4Address::BROADCAST, MacAddress::BROADCAST),
        (ip(192, 0, 2, 255), MacAddress::BROADCAST),
        (ip(198, 51, 100, 2), MacAddress([0x01, 0, 0x5e, 0, 0, 1])),
    ];

    for (destination, frame_dst) in cases {
        let mut router = make_router();
        let raw = frame(source, destination, IP_PROTO_UDP, 1, b"udp", frame_dst);
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "destination {destination} / L2 {frame_dst} must not provoke ICMP"
        );
    }
}

#[test]
fn icmp_errors_are_suppressed_for_invalid_sources() {
    for source in [
        ip(0, 1, 2, 3),
        ip(127, 0, 0, 1),
        ip(224, 0, 0, 1),
        ip(240, 0, 0, 1),
        Ipv4Address::BROADCAST,
    ] {
        let mut router = make_router();
        let raw = frame(
            source,
            ip(198, 51, 100, 2),
            IP_PROTO_UDP,
            1,
            b"udp",
            mac(0x10),
        );
        assert!(
            router.process_incoming_frame("lan1", &raw).is_empty(),
            "source {source} must not receive ICMP error"
        );
    }
}

#[test]
fn icmp_errors_are_suppressed_for_non_initial_fragments() {
    let packet = Ipv4Packet::serialize(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        IP_PROTO_UDP,
        0x1234,
        1,
        b"fragment",
    );
    let mut packet = packet;
    // Fragment offset = 1 (8-byte units), with no MF requirement for this regression.
    packet[6] = 0;
    packet[7] = 1;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = compute_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    let raw = EthernetFrame::serialize(mac(0x10), mac(0x11), ETHERTYPE_IPV4, &packet);

    let mut router = make_router();
    assert!(router.process_incoming_frame("lan1", &raw).is_empty());
}
''')
