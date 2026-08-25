from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"anchor count for {path}: expected 1, got {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


# ICMPv6: Router Discovery validators and RFC 4862 invalid-PIO handling.
icmp = "src/icmpv6.rs"
replace_once(
    icmp,
    '''    /// Builds an ICMPv6 Echo Request (Ping6)\n    pub fn build_echo_request(\n''',
    '''    /// Validates an RFC 4861 Router Solicitation before Neighbor Cache learning\n    /// or generation of a Router Advertisement.\n    pub fn is_valid_router_solicitation(&self, src_ip: Ipv6Address, hop_limit: u8) -> bool {\n        if self.msg_type != ICMPV6_TYPE_ROUTER_SOLICIT\n            || self.code != 0\n            || hop_limit != 255\n            || self.payload.len() < 4\n            || !ndp_options_well_formed(&self.payload[4..])\n        {\n            return false;\n        }\n\n        !(src_ip.is_unspecified()\n            && ndp_options_contain(&self.payload[4..], NDP_OPT_SRC_LINK_LAYER_ADDR))\n    }\n\n    /// Validates an RFC 4861 Router Advertisement and returns its parsed body.\n    pub fn validated_router_advertisement(\n        &self,\n        src_ip: Ipv6Address,\n        hop_limit: u8,\n    ) -> Option<RouterAdvertisement> {\n        if self.msg_type != ICMPV6_TYPE_ROUTER_ADVERT\n            || self.code != 0\n            || hop_limit != 255\n            || !src_ip.is_link_local()\n            || self.payload.len() < 12\n            || !ndp_options_well_formed(&self.payload[12..])\n        {\n            return None;\n        }\n        RouterAdvertisement::parse(self)\n    }\n\n    /// Builds an ICMPv6 Echo Request (Ping6)\n    pub fn build_echo_request(\n''',
)
replace_once(
    icmp,
    '''                let preferred_lifetime = u32::from_be_bytes(option[8..12].try_into().ok()?);\n                let mut prefix_bytes = [0u8; 16];\n''',
    '''                let preferred_lifetime = u32::from_be_bytes(option[8..12].try_into().ok()?);\n                if preferred_lifetime > valid_lifetime {\n                    offset += option_len;\n                    continue;\n                }\n                let mut prefix_bytes = [0u8; 16];\n''',
)

# NetStack: validate RS/RA at the same pre-cache gate as NS/NA.
stack = "src/stack.rs"
replace_once(
    stack,
    '''    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_PACKET_TOO_BIG, ICMPV6_TYPE_ROUTER_ADVERT,\n    Icmpv6Packet, NdpTable, RouterAdvertisement, ipv6_multicast_mac, slaac_address,\n''',
    '''    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_PACKET_TOO_BIG, ICMPV6_TYPE_ROUTER_ADVERT,\n    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, ipv6_multicast_mac, slaac_address,\n''',
)
replace_once(
    stack,
    '''                                    ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6\n                                        .validated_neighbor_advertisement_target(\n                                            ip6_pkt.header.dst_ip,\n                                            ip6_pkt.header.hop_limit,\n                                        )\n                                        .is_some(),\n                                    _ => true,\n''',
    '''                                    ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6\n                                        .validated_neighbor_advertisement_target(\n                                            ip6_pkt.header.dst_ip,\n                                            ip6_pkt.header.hop_limit,\n                                        )\n                                        .is_some(),\n                                    ICMPV6_TYPE_ROUTER_SOLICIT => false,\n                                    ICMPV6_TYPE_ROUTER_ADVERT => icmp6\n                                        .validated_router_advertisement(\n                                            ip6_pkt.header.src_ip,\n                                            ip6_pkt.header.hop_limit,\n                                        )\n                                        .is_some(),\n                                    _ => true,\n''',
)
replace_once(
    stack,
    '''                                    Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)\n                                        | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)\n''',
    '''                                    Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)\n                                        | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)\n                                        | Some(ICMPV6_TYPE_ROUTER_SOLICIT)\n                                        | Some(ICMPV6_TYPE_ROUTER_ADVERT)\n''',
)
replace_once(
    stack,
    '''                            ICMPV6_TYPE_ROUTER_ADVERT => {\n                                if ip6_pkt.header.hop_limit == 255\n                                    && ip6_pkt.header.src_ip.is_link_local()\n                                    && let Some(ra) = RouterAdvertisement::parse(&icmp6)\n                                {\n''',
    '''                            ICMPV6_TYPE_ROUTER_ADVERT => {\n                                if let Some(ra) = icmp6.validated_router_advertisement(\n                                    ip6_pkt.header.src_ip,\n                                    ip6_pkt.header.hop_limit,\n                                ) {\n''',
)

# LabRouter: validate Router Discovery and never learn ordinary routed sources.
lab = "src/lab.rs"
replace_once(
    lab,
    '''    ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,\n    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, PrefixInformationOption,\n    ipv6_multicast_mac, link_local_address,\n''',
    '''    ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,\n    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable,\n    PrefixInformationOption, ipv6_multicast_mac, link_local_address,\n''',
)
replace_once(
    lab,
    '''                                ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6\n                                    .validated_neighbor_advertisement_target(\n                                        ip6_pkt.header.dst_ip,\n                                        ip6_pkt.header.hop_limit,\n                                    )\n                                    .is_some(),\n                                _ => true,\n''',
    '''                                ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6\n                                    .validated_neighbor_advertisement_target(\n                                        ip6_pkt.header.dst_ip,\n                                        ip6_pkt.header.hop_limit,\n                                    )\n                                    .is_some(),\n                                ICMPV6_TYPE_ROUTER_SOLICIT => icmp6\n                                    .is_valid_router_solicitation(\n                                        ip6_pkt.header.src_ip,\n                                        ip6_pkt.header.hop_limit,\n                                    ),\n                                ICMPV6_TYPE_ROUTER_ADVERT => icmp6\n                                    .validated_router_advertisement(\n                                        ip6_pkt.header.src_ip,\n                                        ip6_pkt.header.hop_limit,\n                                    )\n                                    .is_some(),\n                                _ => true,\n''',
)
replace_once(
    lab,
    '''                                Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)\n                                    | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)\n''',
    '''                                Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)\n                                    | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)\n                                    | Some(ICMPV6_TYPE_ROUTER_SOLICIT)\n                                    | Some(ICMPV6_TYPE_ROUTER_ADVERT)\n''',
)
replace_once(
    lab,
    '''                // The unspecified IPv6 source is used by initial Router\n                // Solicitations and Duplicate Address Detection. It is never a\n                // neighbour-cache key and cannot satisfy queued next-hop resolution.\n                if !ip6_pkt.header.src_ip.is_unspecified() {\n                    self.ndp_tables\n                        .entry(ingress_iface.name.clone())\n                        .or_default()\n                        .insert(ip6_pkt.header.src_ip, eth.src_mac);\n\n                    // Learning a real next hop releases packets that were waiting for NDP.\n                    let pending_key = (ingress_iface.name.clone(), ip6_pkt.header.src_ip);\n                    if let Some(queued) = self.pending_ipv6_transit_packets.remove(&pending_key) {\n                        for packet in queued {\n                            out_transmissions.push((\n                                ingress_link.to_string(),\n                                EthernetFrame::serialize(\n                                    eth.src_mac,\n                                    ingress_iface.mac,\n                                    ETHERTYPE_IPV6,\n                                    &packet,\n                                ),\n                            ));\n                        }\n                    }\n                }\n''',
    '''                // Only validated NDP control traffic proves that an IPv6 address is\n                // directly attached. Ordinary routed data can carry a remote source.\n                if ip6_pkt.header.next_header == NEXT_HEADER_ICMPV6\n                    && let Ok(icmp6) = Icmpv6Packet::parse(\n                        ip6_pkt.header.src_ip,\n                        ip6_pkt.header.dst_ip,\n                        ip6_pkt.payload,\n                        true,\n                    )\n                {\n                    let neighbor_ip = match icmp6.msg_type {\n                        ICMPV6_TYPE_ROUTER_SOLICIT\n                            if ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS\n                                && icmp6.is_valid_router_solicitation(\n                                    ip6_pkt.header.src_ip,\n                                    ip6_pkt.header.hop_limit,\n                                )\n                                && !ip6_pkt.header.src_ip.is_unspecified() =>\n                        {\n                            Some(ip6_pkt.header.src_ip)\n                        }\n                        ICMPV6_TYPE_NEIGHBOR_SOLICIT => icmp6\n                            .validated_neighbor_solicitation_target(\n                                ip6_pkt.header.src_ip,\n                                ip6_pkt.header.dst_ip,\n                                ip6_pkt.header.hop_limit,\n                            )\n                            .and_then(|_| {\n                                (!ip6_pkt.header.src_ip.is_unspecified())\n                                    .then_some(ip6_pkt.header.src_ip)\n                            }),\n                        ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6\n                            .validated_neighbor_advertisement_target(\n                                ip6_pkt.header.dst_ip,\n                                ip6_pkt.header.hop_limit,\n                            ),\n                        _ => None,\n                    };\n\n                    if let Some(neighbor_ip) = neighbor_ip {\n                        let ndp = self\n                            .ndp_tables\n                            .entry(ingress_iface.name.clone())\n                            .or_default();\n                        if icmp6.msg_type == ICMPV6_TYPE_NEIGHBOR_ADVERT {\n                            let cached = ndp.lookup(&neighbor_ip);\n                            let resolving = self\n                                .pending_ipv6_transit_packets\n                                .contains_key(&(ingress_iface.name.clone(), neighbor_ip));\n                            if cached.is_some() || resolving {\n                                let solicited = icmp6.payload[0] & 0x40 != 0;\n                                if solicited {\n                                    ndp.confirm_reachable(\n                                        neighbor_ip,\n                                        eth.src_mac,\n                                        self.current_time_ms,\n                                    );\n                                } else if cached != Some(eth.src_mac) {\n                                    ndp.mark_stale(neighbor_ip, eth.src_mac);\n                                }\n                            }\n                        } else {\n                            ndp.learn_stale(neighbor_ip, eth.src_mac);\n                        }\n\n                        let pending_key = (ingress_iface.name.clone(), neighbor_ip);\n                        if ndp.lookup(&neighbor_ip).is_some()\n                            && let Some(queued) =\n                                self.pending_ipv6_transit_packets.remove(&pending_key)\n                        {\n                            for packet in queued {\n                                out_transmissions.push((\n                                    ingress_link.to_string(),\n                                    EthernetFrame::serialize(\n                                        eth.src_mac,\n                                        ingress_iface.mac,\n                                        ETHERTYPE_IPV6,\n                                        &packet,\n                                    ),\n                                ));\n                            }\n                        }\n                    }\n                }\n''',
)
replace_once(
    lab,
    '''                    if icmp6.msg_type == ICMPV6_TYPE_ROUTER_SOLICIT\n                        && ip6_pkt.header.hop_limit == 255\n                        && ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS\n''',
    '''                    if icmp6.msg_type == ICMPV6_TYPE_ROUTER_SOLICIT\n                        && icmp6.is_valid_router_solicitation(\n                            ip6_pkt.header.src_ip,\n                            ip6_pkt.header.hop_limit,\n                        )\n                        && ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS\n''',
)
