from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, found {count}")
    return text.replace(old, new, 1)


icmp_path = Path("src/icmpv6.rs")
icmp = icmp_path.read_text()

icmp = replace_once(
    icmp,
    "#[derive(Debug, Clone, PartialEq, Eq)]\npub struct RouterAdvertisement {\n",
    "#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]\n"
    "pub enum RouterPreference {\n"
    "    Low,\n"
    "    Medium,\n"
    "    High,\n"
    "}\n\n"
    "impl RouterPreference {\n"
    "    fn from_ra_flags(flags: u8) -> Self {\n"
    "        match (flags >> 3) & 0x03 {\n"
    "            0x01 => Self::High,\n"
    "            0x03 => Self::Low,\n"
    "            // RFC 4191: the reserved 10 value MUST be treated as Medium.\n"
    "            _ => Self::Medium,\n"
    "        }\n"
    "    }\n\n"
    "    fn ra_flags(self) -> u8 {\n"
    "        match self {\n"
    "            Self::High => 0x08,\n"
    "            Self::Medium => 0x00,\n"
    "            Self::Low => 0x18,\n"
    "        }\n"
    "    }\n"
    "}\n\n"
    "#[derive(Debug, Clone, PartialEq, Eq)]\n"
    "pub struct RouterAdvertisement {\n",
    "insert RouterPreference",
)

icmp = replace_once(
    icmp,
    "    pub other_config: bool,\n    pub router_lifetime: u16,\n",
    "    pub other_config: bool,\n    pub preference: RouterPreference,\n    pub router_lifetime: u16,\n",
    "RouterAdvertisement.preference field",
)

start = icmp.index("    /// Builds an NDP Router Advertisement")
end = icmp.index("    /// Builds an NDP Neighbor Solicitation", start)
new_builder = '''    /// Builds an NDP Router Advertisement (RFC 4861, Type 134) carrying one or
    /// more Prefix Information Options (RFC 4861 section 4.6.2).
    pub fn build_router_advertisement(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        prefixes: &[PrefixInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        Self::build_router_advertisement_with_preference(
            src_ip,
            dst_ip,
            current_hop_limit,
            router_lifetime,
            RouterPreference::Medium,
            prefixes,
            source_mac,
        )
    }

    /// RFC 4191-aware Router Advertisement builder. The legacy builder above
    /// remains source-compatible and advertises the default Medium preference.
    pub fn build_router_advertisement_with_preference(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(16 + prefixes.len() * 32 + usize::from(source_mac.is_some()) * 8);
        buf.push(ICMPV6_TYPE_ROUTER_ADVERT);
        buf.push(0);
        buf.extend_from_slice(&[0, 0]);
        buf.push(current_hop_limit);
        buf.push(preference.ra_flags()); // M=0, O=0, RFC 4191 Prf in bits 4..3
        buf.extend_from_slice(&router_lifetime.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // Reachable Time
        buf.extend_from_slice(&0u32.to_be_bytes()); // Retrans Timer

        if let Some(mac) = source_mac {
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }

        for prefix in prefixes {
            buf.push(NDP_OPT_PREFIX_INFORMATION);
            buf.push(4); // 32 octets
            buf.push(prefix.prefix_length);
            let mut flags = 0u8;
            if prefix.on_link {
                flags |= 0x80;
            }
            if prefix.autonomous {
                flags |= 0x40;
            }
            buf.push(flags);
            buf.extend_from_slice(&prefix.valid_lifetime.to_be_bytes());
            buf.extend_from_slice(&prefix.preferred_lifetime.to_be_bytes());
            buf.extend_from_slice(&0u32.to_be_bytes());
            buf.extend_from_slice(&prefix.prefix.mask(prefix.prefix_length).0);
        }

        let csum = compute_ipv6_transport_checksum(src_ip, dst_ip, NEXT_HEADER_ICMPV6, &buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());
        buf
    }

'''
icmp = icmp[:start] + new_builder + icmp[end:]

icmp = replace_once(
    icmp,
    "        let flags = payload[1];\n        let router_lifetime = u16::from_be_bytes([payload[2], payload[3]]);\n",
    "        let flags = payload[1];\n        let preference = RouterPreference::from_ra_flags(flags);\n        let router_lifetime = u16::from_be_bytes([payload[2], payload[3]]);\n",
    "parse preference",
)

icmp = replace_once(
    icmp,
    "            managed: flags & 0x80 != 0,\n            other_config: flags & 0x40 != 0,\n            router_lifetime,\n",
    "            managed: flags & 0x80 != 0,\n            other_config: flags & 0x40 != 0,\n            preference,\n            router_lifetime,\n",
    "return parsed preference",
)

icmp_path.write_text(icmp)

stack_path = Path("src/stack.rs")
stack = stack_path.read_text()

stack = replace_once(
    stack,
    "    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, NeighborState, ipv6_multicast_mac,\n    slaac_address,\n",
    "    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, NeighborState, RouterPreference,\n    ipv6_multicast_mac, slaac_address,\n",
    "import RouterPreference",
)

stack = replace_once(
    stack,
    "    // RFC 4861 Default Router List, in discovery order. `None` is an infinite lifetime.\n    ipv6_default_routers: Vec<(Ipv6Address, Option<u64>)>,\n",
    "    // RFC 4861 / RFC 4191 Default Router List, in discovery order.\n    // `None` is an infinite lifetime; preference is High/Medium/Low.\n    ipv6_default_routers: Vec<(Ipv6Address, Option<u64>, RouterPreference)>,\n",
    "default router tuple",
)

old_block_start = stack.index("    fn default_router_deadline(&self, router: Ipv6Address)")
old_block_end = stack.index("    fn refresh_ipv6_ra_on_link_prefix", old_block_start)
new_block = '''    fn default_router_deadline(&self, router: Ipv6Address) -> Option<Option<u64>> {
        self.ipv6_default_routers
            .iter()
            .find_map(|(address, deadline, _)| (*address == router).then_some(*deadline))
    }

    fn default_router_preference(&self, router: Ipv6Address) -> Option<RouterPreference> {
        self.ipv6_default_routers
            .iter()
            .find_map(|(address, _, preference)| (*address == router).then_some(*preference))
    }

    fn default_router_reachability_rank(&self, router: Ipv6Address) -> u8 {
        match self.ndp_table.state(&router) {
            Some(NeighborState::Reachable) => 2,
            Some(NeighborState::Stale | NeighborState::Delay | NeighborState::Probe) => 1,
            None => 0,
        }
    }

    fn select_ipv6_default_router(&mut self) {
        let is_valid =
            |deadline: Option<u64>| deadline.is_none_or(|deadline| self.current_time_ms < deadline);
        let active = self
            .ipv6_gateway
            .filter(|router| self.default_router_deadline(*router).is_some_and(is_valid));

        // RFC 4861 section 6.3.6 makes reachability the primary selector; RFC 4191
        // uses Router Preference as the secondary selector. Keep the current router
        // stable when it ties for the best score so equal RAs do not cause churn.
        let best_score = self
            .ipv6_default_routers
            .iter()
            .filter(|(_, deadline, _)| is_valid(*deadline))
            .map(|(router, _, preference)| {
                (self.default_router_reachability_rank(*router), *preference)
            })
            .max();

        let active_is_best = active.is_some_and(|router| {
            best_score
                == self.default_router_preference(router).map(|preference| {
                    (self.default_router_reachability_rank(router), preference)
                })
        });
        let selected = if active_is_best {
            active
        } else {
            best_score.and_then(|best| {
                self.ipv6_default_routers.iter().find_map(|(router, deadline, preference)| {
                    (is_valid(*deadline)
                        && (self.default_router_reachability_rank(*router), *preference) == best)
                        .then_some(*router)
                })
            })
        };
        let selected_deadline =
            selected.and_then(|router| self.default_router_deadline(router).flatten());

        if self.ipv6_gateway != selected {
            self.set_ipv6_default_gateway(selected);
        }
        if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {
            lifetimes.router = selected;
            lifetimes.router_until_ms = selected_deadline;
        }
        if let Some(dad) = self.ipv6_dad.as_mut() {
            dad.gateway = selected;
            dad.router_until_ms = selected_deadline;
        }
    }

    fn refresh_slaac_default_router(
        &mut self,
        router: Ipv6Address,
        lifetime_secs: u16,
        preference: RouterPreference,
    ) {
        if lifetime_secs == 0 {
            self.ipv6_default_routers
                .retain(|(address, _, _)| *address != router);
        } else {
            let deadline = Some(
                self.current_time_ms
                    .saturating_add((lifetime_secs as u64).saturating_mul(1_000)),
            );
            if let Some((_, current_deadline, current_preference)) = self
                .ipv6_default_routers
                .iter_mut()
                .find(|(address, _, _)| *address == router)
            {
                *current_deadline = deadline;
                *current_preference = preference;
            } else {
                self.ipv6_default_routers.push((router, deadline, preference));
            }
        }
        self.select_ipv6_default_router();
    }

    fn expire_ipv6_default_routers(&mut self, now_ms: u64) -> bool {
        let had_router = !self.ipv6_default_routers.is_empty();
        self.ipv6_default_routers
            .retain(|(_, deadline, _)| deadline.is_none_or(|deadline| now_ms < deadline));
        self.select_ipv6_default_router();
        had_router && self.ipv6_default_routers.is_empty()
    }

'''
stack = stack[:old_block_start] + new_block + stack[old_block_end:]

stack = replace_once(
    stack,
    ".retain(|(address, _)| *address != router);",
    ".retain(|(address, _, _)| *address != router);",
    "NUD removal tuple",
)

stack = replace_once(
    stack,
    "                                    self.refresh_slaac_default_router(\n                                        ip6_pkt.header.src_ip,\n                                        ra.router_lifetime,\n                                    );\n",
    "                                    self.refresh_slaac_default_router(\n                                        ip6_pkt.header.src_ip,\n                                        ra.router_lifetime,\n                                        ra.preference,\n                                    );\n",
    "RA preference refresh call",
)

stack_path.write_text(stack)

test_path = Path("tests/test_ipv6_default_router_list.rs")
test = test_path.read_text()
test = replace_once(
    test,
    "    Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac, link_local_address,\n",
    "    Icmpv6Packet, PrefixInformationOption, RouterPreference, ipv6_multicast_mac,\n    link_local_address,\n",
    "test import RouterPreference",
)

helper_marker = "#[test]\nfn active_router_expiry_fails_over_without_new_router_solicitation()"
helper = '''fn ra_frame_with_preference(
    router_mac: MacAddress,
    prefix: Ipv6Address,
    lifetime: u16,
    preference: RouterPreference,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 600, 300);
    let ra = Icmpv6Packet::build_router_advertisement_with_preference(
        src,
        dst,
        64,
        lifetime,
        preference,
        &[pio],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

'''
test = replace_once(test, helper_marker, helper + helper_marker, "insert preference RA helper")

test += '''

#[test]
fn higher_router_preference_preempts_equal_reachability() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x96]);
    let medium_mac = MacAddress([0x02, 0, 0, 0, 6, 1]);
    let high_mac = MacAddress([0x02, 0, 0, 0, 6, 2]);
    let medium = link_local_address(medium_mac);
    let high = link_local_address(high_mac);
    let prefix = ip6("2001:db8:96::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame_with_preference(
        medium_mac,
        prefix,
        30,
        RouterPreference::Medium,
    ));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(medium));

    s.process_frame(&ra_frame_with_preference(
        high_mac,
        prefix,
        30,
        RouterPreference::High,
    ));
    assert_eq!(s.ipv6_gateway(), Some(high));
}

#[test]
fn nud_reachability_outranks_router_preference() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x97]);
    let high_mac = MacAddress([0x02, 0, 0, 0, 7, 1]);
    let low_mac = MacAddress([0x02, 0, 0, 0, 7, 2]);
    let high = link_local_address(high_mac);
    let low = link_local_address(low_mac);
    let prefix = ip6("2001:db8:97::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame_with_preference(
        high_mac,
        prefix,
        30,
        RouterPreference::High,
    ));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame_with_preference(
        low_mac,
        prefix,
        30,
        RouterPreference::Low,
    ));
    assert_eq!(s.ipv6_gateway(), Some(high));

    let host = s.config.ipv6.unwrap();
    s.process_frame(&solicited_router_na(low_mac, low, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(low));
}

#[test]
fn router_advertisement_builder_and_parser_preserve_preference() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 8, 1]);
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let raw = Icmpv6Packet::build_router_advertisement_with_preference(
        src,
        dst,
        64,
        30,
        RouterPreference::High,
        &[],
        Some(router_mac),
    );
    let icmp = Icmpv6Packet::parse(src, dst, &raw, true).unwrap();
    let ra = icmp.validated_router_advertisement(src, 255).unwrap();
    assert_eq!(ra.preference, RouterPreference::High);
}
'''

test_path.write_text(test)
