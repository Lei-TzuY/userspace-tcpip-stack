from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one marker, found {count}")
    file.write_text(text.replace(old, new, 1))


replace_once(
    "src/icmpv6.rs",
    "\nimpl<'a> Icmpv6Packet<'a> {\n",
    """

/// Extracts an Ethernet Source/Target Link-Layer Address option from an already
/// validated NDP option list. RFC 2464 fixes Ethernet LLA options at one 8-octet
/// unit; malformed or truncated lists deliberately yield no cache hint.
fn ndp_ethernet_link_layer_address(options: &[u8], option_type: u8) -> Option<MacAddress> {
    let mut offset = 0usize;
    while offset < options.len() {
        if options.len() - offset < 2 {
            return None;
        }
        let units = options[offset + 1] as usize;
        if units == 0 {
            return None;
        }
        let option_len = units.checked_mul(8)?;
        let end = offset.checked_add(option_len)?;
        if end > options.len() {
            return None;
        }
        if options[offset] == option_type {
            if option_len != 8 {
                return None;
            }
            return Some(MacAddress([
                options[offset + 2],
                options[offset + 3],
                options[offset + 4],
                options[offset + 5],
                options[offset + 6],
                options[offset + 7],
            ]));
        }
        offset = end;
    }
    None
}

impl<'a> Icmpv6Packet<'a> {
""",
)

replace_once(
    "src/icmpv6.rs",
    """    /// Returns the Ethernet Target Link-Layer Address carried by a Neighbor
    /// Advertisement, if present. Callers should validate the advertisement
    /// before using this accessor.
    pub fn neighbor_advertisement_target_link_layer_address(&self) -> Option<MacAddress> {
        if self.msg_type != ICMPV6_TYPE_NEIGHBOR_ADVERT || self.payload.len() < 20 {
            return None;
        }

        let options = &self.payload[20..];
        let mut offset = 0usize;
        while offset < options.len() {
            if options.len() - offset < 2 {
                return None;
            }
            let units = options[offset + 1] as usize;
            if units == 0 {
                return None;
            }
            let option_len = units.checked_mul(8)?;
            let end = offset.checked_add(option_len)?;
            if end > options.len() {
                return None;
            }

            if options[offset] == NDP_OPT_TARGET_LINK_LAYER_ADDR {
                // RFC 4861 section 4.6.1 notes that IEEE 802 addresses use
                // one 8-octet option unit: type, length, then six MAC octets.
                if option_len != 8 {
                    return None;
                }
                return Some(MacAddress([
                    options[offset + 2],
                    options[offset + 3],
                    options[offset + 4],
                    options[offset + 5],
                    options[offset + 6],
                    options[offset + 7],
                ]));
            }
            offset = end;
        }
        None
    }
""",
    """    /// Returns the Ethernet Target Link-Layer Address carried by a Neighbor
    /// Advertisement, if present. Callers should validate the advertisement
    /// before using this accessor.
    pub fn neighbor_advertisement_target_link_layer_address(&self) -> Option<MacAddress> {
        if self.msg_type != ICMPV6_TYPE_NEIGHBOR_ADVERT || self.payload.len() < 20 {
            return None;
        }
        ndp_ethernet_link_layer_address(
            &self.payload[20..],
            NDP_OPT_TARGET_LINK_LAYER_ADDR,
        )
    }

    /// Returns the Ethernet Source Link-Layer Address option carried by an NS,
    /// RS, or RA. Absence is meaningful: RFC 4861 does not permit callers to
    /// synthesize a Neighbor Cache mapping from the enclosing Ethernet header.
    pub fn ndp_source_link_layer_address(&self) -> Option<MacAddress> {
        let options = match self.msg_type {
            ICMPV6_TYPE_NEIGHBOR_SOLICIT if self.payload.len() >= 20 => &self.payload[20..],
            ICMPV6_TYPE_ROUTER_SOLICIT if self.payload.len() >= 4 => &self.payload[4..],
            ICMPV6_TYPE_ROUTER_ADVERT if self.payload.len() >= 12 => &self.payload[12..],
            _ => return None,
        };
        ndp_ethernet_link_layer_address(options, NDP_OPT_SRC_LINK_LAYER_ADDR)
    }
""",
)

replace_once(
    "src/stack.rs",
    """                                    // Only validated on-link NDP control traffic may create
                                    // Neighbor Cache state. Ordinary routed IPv6 data must not
                                    // make its remote source appear directly attached.
                                    self.ndp_table
                                        .learn_stale(ip6_pkt.header.src_ip, eth.src_mac);
""",
    """                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may
                                    // update the Neighbor Cache only when it actually carries
                                    // SLLA. The enclosing Ethernet source is not a substitute.
                                    if let Some(source_mac) =
                                        icmp6.ndp_source_link_layer_address()
                                    {
                                        self.ndp_table
                                            .learn_stale(ip6_pkt.header.src_ip, source_mac);
                                    }
""",
)

replace_once(
    "src/stack.rs",
    """                                    // A non-DAD NS is direct on-link evidence for its source.
                                    // DAD uses the unspecified source and deliberately teaches
                                    // no Neighbor Cache entry.
                                    if !ip6_pkt.header.src_ip.is_unspecified() {
                                        self.ndp_table
                                            .learn_stale(ip6_pkt.header.src_ip, eth.src_mac);
                                    }
""",
    """                                    // RFC 4861 section 7.2.3: a non-DAD NS updates the
                                    // Neighbor Cache only when SLLA is present, and the option's
                                    // address is the cache hint. Ethernet source MAC is not.
                                    if !ip6_pkt.header.src_ip.is_unspecified()
                                        && let Some(source_mac) =
                                            icmp6.ndp_source_link_layer_address()
                                    {
                                        self.ndp_table
                                            .learn_stale(ip6_pkt.header.src_ip, source_mac);
                                    }
""",
)

replace_once(
    "src/lab.rs",
    """                // NS/RS provide link-layer information but no positive reachability
                // confirmation, so they create STALE dynamic entries rather than static
                // mappings. NA processing follows RFC 4861 section 7.2.5 and never creates
""",
    """                // NS/RS contribute link-layer information only when SLLA is present;
                // that option creates a STALE dynamic entry rather than a static mapping.
                // NA processing follows RFC 4861 section 7.2.5 and never creates
""",
)

replace_once(
    "src/lab.rs",
    """                    let learned_source = match icmp6.msg_type {
                        ICMPV6_TYPE_ROUTER_SOLICIT
                            if icmp6.is_valid_router_solicitation(
                                ip6_pkt.header.src_ip,
                                ip6_pkt.header.hop_limit,
                            ) && !ip6_pkt.header.src_ip.is_unspecified() =>
                        {
                            Some(ip6_pkt.header.src_ip)
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
                            }),
                        _ => None,
                    };

                    if let Some(neighbor_ip) = learned_source {
                        self.ndp_tables
                            .entry(ingress_iface.name.clone())
                            .or_default()
                            .learn_stale(neighbor_ip, eth.src_mac);

                        let pending_key = (ingress_iface.name.clone(), neighbor_ip);
                        if let Some(queued) = self.pending_ipv6_transit_packets.remove(&pending_key)
                        {
                            for packet in queued {
                                out_transmissions.push((
                                    ingress_link.to_string(),
                                    EthernetFrame::serialize(
                                        eth.src_mac,
                                        ingress_iface.mac,
                                        ETHERTYPE_IPV6,
                                        &packet,
                                    ),
                                ));
                            }
                        }
                    }
""",
    """                    let learned_source = match icmp6.msg_type {
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
""",
)

replace_once(
    "src/lab.rs",
    """                        let solicited = icmp6.payload[0] & 0x40 != 0;
                        let override_flag = icmp6.payload[0] & 0x20 != 0;
                        let mut resolved = false;

                        if let Some(current_mac) = cached_mac {
                            if current_mac != eth.src_mac && !override_flag {
                                table.demote_reachable_preserving_mac(target);
                            } else if solicited {
                                table.confirm_reachable(target, eth.src_mac, self.current_time_ms);
                            } else if current_mac != eth.src_mac {
                                table.mark_stale(target, eth.src_mac);
                            }
                        } else if resolving {
                            if solicited {
                                table.confirm_reachable(target, eth.src_mac, self.current_time_ms);
                            } else {
                                table.mark_stale(target, eth.src_mac);
                            }
                            resolved = true;
                        }

                        if resolved
                            && let Some(queued) =
                                self.pending_ipv6_transit_packets.remove(&pending_key)
                        {
                            for packet in queued {
                                out_transmissions.push((
                                    ingress_link.to_string(),
                                    EthernetFrame::serialize(
                                        eth.src_mac,
                                        ingress_iface.mac,
                                        ETHERTYPE_IPV6,
                                        &packet,
                                    ),
                                ));
                            }
                        }
""",
    """                        let advertised_mac =
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
                                table.confirm_reachable(
                                    target,
                                    target_mac,
                                    self.current_time_ms,
                                );
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
""",
)

Path("tests/test_ipv6_ndp_link_layer_options.rs").write_text(r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{Icmpv6Packet, ipv6_multicast_mac, link_local_address};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn host(host_mac: MacAddress, host_ip: Ipv6Address) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(host_ip, 64, None);
    stack
}

fn router() -> LabRouter {
    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        mac(0x10),
        Ipv4Address::new(192, 0, 2, 1),
        24,
        "lan1",
    );
    assert!(router.set_interface_ipv6("eth0", ip6("2001:db8:1::1"), 64));
    router
}

fn without_ethernet_lla_option(
    mut message: Vec<u8>,
    src: Ipv6Address,
    dst: Ipv6Address,
) -> Vec<u8> {
    assert!(message.len() >= 32);
    message.truncate(24);
    message[2] = 0;
    message[3] = 0;
    let checksum = compute_ipv6_transport_checksum(src, dst, NEXT_HEADER_ICMPV6, &message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn ipv6_frame(
    frame_src: MacAddress,
    frame_dst: MacAddress,
    src: Ipv6Address,
    dst: Ipv6Address,
    icmp: &[u8],
) -> Vec<u8> {
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, icmp);
    EthernetFrame::serialize(frame_dst, frame_src, ETHERTYPE_IPV6, &packet)
}

#[test]
fn host_ns_without_slla_replies_but_does_not_learn_ethernet_source() {
    let host_mac = mac(0x10);
    let wire_mac = mac(0x21);
    let host_ip = ip6("2001:db8:1::1");
    let peer_ip = ip6("2001:db8:1::2");
    let dst = host_ip.solicited_node_multicast();
    let mut stack = host(host_mac, host_ip);
    let ns = Icmpv6Packet::build_neighbor_solicitation(peer_ip, dst, host_ip, wire_mac);
    let ns = without_ethernet_lla_option(ns, peer_ip, dst);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        peer_ip,
        dst,
        &ns,
    );

    let replies = stack.process_frame(&frame);
    assert_eq!(replies.len(), 1, "a valid NS still receives an NA");
    assert_eq!(stack.ndp_table.lookup(&peer_ip), None);
}

#[test]
fn host_ns_learns_slla_instead_of_enclosing_ethernet_source() {
    let host_mac = mac(0x10);
    let wire_mac = mac(0x21);
    let advertised_mac = mac(0x22);
    let host_ip = ip6("2001:db8:1::1");
    let peer_ip = ip6("2001:db8:1::2");
    let dst = host_ip.solicited_node_multicast();
    let mut stack = host(host_mac, host_ip);
    let ns =
        Icmpv6Packet::build_neighbor_solicitation(peer_ip, dst, host_ip, advertised_mac);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        peer_ip,
        dst,
        &ns,
    );

    assert_eq!(stack.process_frame(&frame).len(), 1);
    assert_eq!(stack.ndp_table.lookup(&peer_ip), Some(advertised_mac));
}

#[test]
fn host_ra_without_slla_is_accepted_without_neighbor_learning() {
    let host_mac = mac(0x30);
    let wire_mac = mac(0x31);
    let host_ip = ip6("2001:db8:1::30");
    let router_ip = ip6("fe80::31");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut stack = host(host_mac, host_ip);
    let _first_rs = stack.start_router_discovery();
    let ra = Icmpv6Packet::build_router_advertisement(router_ip, dst, 64, 0, &[], None);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        router_ip,
        dst,
        &ra,
    );

    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle,
        "the valid RA must still complete Router Discovery"
    );
    assert_eq!(stack.ndp_table.lookup(&router_ip), None);
}

#[test]
fn host_ra_learns_advertised_slla_instead_of_ethernet_source() {
    let host_mac = mac(0x30);
    let wire_mac = mac(0x31);
    let advertised_mac = mac(0x32);
    let host_ip = ip6("2001:db8:1::30");
    let router_ip = ip6("fe80::32");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut stack = host(host_mac, host_ip);
    let ra = Icmpv6Packet::build_router_advertisement(
        router_ip,
        dst,
        64,
        0,
        &[],
        Some(advertised_mac),
    );
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        router_ip,
        dst,
        &ra,
    );

    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&router_ip), Some(advertised_mac));
}

#[test]
fn router_rs_without_slla_replies_but_does_not_learn_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x41);
    let source = ip6("fe80::41");
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(source, dst, None);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        source,
        dst,
        &rs,
    );

    let replies = router.process_incoming_frame("lan1", &frame);
    assert_eq!(replies.len(), 1, "the valid RS must still receive an RA");
    assert_eq!(router.ndp_tables["eth0"].lookup(&source), None);
}

#[test]
fn router_rs_learns_advertised_slla_instead_of_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x41);
    let advertised_mac = mac(0x42);
    let source = ip6("fe80::42");
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(source, dst, Some(advertised_mac));
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        source,
        dst,
        &rs,
    );

    assert_eq!(router.process_incoming_frame("lan1", &frame).len(), 1);
    assert_eq!(
        router.ndp_tables["eth0"].lookup(&source),
        Some(advertised_mac)
    );
}

#[test]
fn router_ns_without_slla_replies_but_does_not_learn_ethernet_source() {
    let mut router = router();
    let wire_mac = mac(0x51);
    let source = ip6("2001:db8:1::51");
    let target = ip6("2001:db8:1::1");
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(source, dst, target, wire_mac);
    let ns = without_ethernet_lla_option(ns, source, dst);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        source,
        dst,
        &ns,
    );

    let replies = router.process_incoming_frame("lan1", &frame);
    assert_eq!(replies.len(), 1, "the valid NS must still receive an NA");
    assert_eq!(router.ndp_tables["eth0"].lookup(&source), None);
}

#[test]
fn router_na_resolution_uses_tlla_for_cache_and_queued_frame() {
    let mut router = router();
    let router_ip = ip6("2001:db8:1::1");
    let target = ip6("2001:db8:1::61");
    let wire_mac = mac(0x61);
    let advertised_mac = mac(0x62);
    let queued = Ipv6Packet::serialize(router_ip, target, 59, 64, b"queued");
    router
        .pending_ipv6_transit_packets
        .insert(("eth0".to_string(), target), vec![queued]);

    let na = Icmpv6Packet::build_neighbor_advertisement(
        target,
        router_ip,
        target,
        advertised_mac,
        false,
        true,
        true,
    );
    let frame = ipv6_frame(wire_mac, mac(0x10), target, router_ip, &na);
    let released = router.process_incoming_frame("lan1", &frame);

    assert_eq!(router.ndp_tables["eth0"].lookup(&target), Some(advertised_mac));
    assert!(!router
        .pending_ipv6_transit_packets
        .contains_key(&("eth0".to_string(), target)));
    assert_eq!(released.len(), 1);
    assert_eq!(
        EthernetFrame::parse(&released[0].1).unwrap().dst_mac,
        advertised_mac
    );
}

#[test]
fn router_na_without_tlla_cannot_complete_incomplete_resolution() {
    let mut router = router();
    let router_ip = ip6("2001:db8:1::1");
    let target = ip6("2001:db8:1::71");
    let wire_mac = mac(0x71);
    let queued = Ipv6Packet::serialize(router_ip, target, 59, 64, b"queued");
    router
        .pending_ipv6_transit_packets
        .insert(("eth0".to_string(), target), vec![queued]);

    let na = Icmpv6Packet::build_neighbor_advertisement(
        target,
        router_ip,
        target,
        wire_mac,
        false,
        true,
        true,
    );
    let na = without_ethernet_lla_option(na, target, router_ip);
    let frame = ipv6_frame(wire_mac, mac(0x10), target, router_ip, &na);
    let released = router.process_incoming_frame("lan1", &frame);

    assert!(released.is_empty());
    assert_eq!(router.ndp_tables["eth0"].lookup(&target), None);
    assert_eq!(
        router
            .pending_ipv6_transit_packets
            .get(&("eth0".to_string(), target))
            .map(Vec::len),
        Some(1)
    );
}

#[test]
fn router_link_local_source_accessor_uses_ndp_option_not_interface_mac() {
    let mut router = router();
    let wire_mac = mac(0x81);
    let advertised_mac = mac(0x82);
    let source = link_local_address(advertised_mac);
    let target = ip6("2001:db8:1::1");
    let dst = target.solicited_node_multicast();
    let ns = Icmpv6Packet::build_neighbor_solicitation(source, dst, target, advertised_mac);
    let frame = ipv6_frame(
        wire_mac,
        ipv6_multicast_mac(dst).unwrap(),
        source,
        dst,
        &ns,
    );

    assert_eq!(router.process_incoming_frame("lan1", &frame).len(), 1);
    assert_eq!(
        router.ndp_tables["eth0"].lookup(&source),
        Some(advertised_mac)
    );
}
''')
