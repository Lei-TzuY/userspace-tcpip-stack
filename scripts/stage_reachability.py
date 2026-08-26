from pathlib import Path

stack = Path('src/stack.rs')
text = stack.read_text()

old_import = """    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, ipv6_multicast_mac, slaac_address,\n"""
new_import = """    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, NeighborState, ipv6_multicast_mac,\n    slaac_address,\n"""
assert old_import in text
text = text.replace(old_import, new_import, 1)

old_select = """    fn select_ipv6_default_router(&mut self) {\n        let active = self.ipv6_gateway.filter(|router| {\n            self.default_router_deadline(*router)\n                .is_some_and(|deadline| {\n                    deadline.is_none_or(|deadline| self.current_time_ms < deadline)\n                })\n        });\n        let selected = active.or_else(|| {\n            self.ipv6_default_routers\n                .iter()\n                .find_map(|(router, deadline)| {\n                    deadline\n                        .is_none_or(|deadline| self.current_time_ms < deadline)\n                        .then_some(*router)\n                })\n        });\n        let selected_deadline =\n            selected.and_then(|router| self.default_router_deadline(router).flatten());\n\n        if self.ipv6_gateway != selected {\n            self.set_ipv6_default_gateway(selected);\n        }\n        if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {\n            lifetimes.router = selected;\n            lifetimes.router_until_ms = selected_deadline;\n        }\n        if let Some(dad) = self.ipv6_dad.as_mut() {\n            dad.gateway = selected;\n            dad.router_until_ms = selected_deadline;\n        }\n    }\n"""
new_select = """    fn select_ipv6_default_router(&mut self) {\n        let is_valid = |deadline: Option<u64>| {\n            deadline.is_none_or(|deadline| self.current_time_ms < deadline)\n        };\n        let active = self.ipv6_gateway.filter(|router| {\n            self.default_router_deadline(*router)\n                .is_some_and(is_valid)\n        });\n\n        // RFC 4861 section 6.3.6 prefers routers known reachable by NUD. Preserve\n        // the active router when it is itself REACHABLE; otherwise let another\n        // valid REACHABLE router preempt a STALE/DELAY/PROBE or unresolved active\n        // router. If no router is known reachable, keep the active router stable\n        // and finally fall back to discovery order.\n        let reachable = self\n            .ipv6_default_routers\n            .iter()\n            .find_map(|(router, deadline)| {\n                (is_valid(*deadline)\n                    && self.ndp_table.state(router) == Some(NeighborState::Reachable))\n                    .then_some(*router)\n            });\n        let active_reachable = active.is_some_and(|router| {\n            self.ndp_table.state(&router) == Some(NeighborState::Reachable)\n        });\n        let selected = if active_reachable {\n            active\n        } else {\n            reachable.or(active).or_else(|| {\n                self.ipv6_default_routers\n                    .iter()\n                    .find_map(|(router, deadline)| is_valid(*deadline).then_some(*router))\n            })\n        };\n        let selected_deadline =\n            selected.and_then(|router| self.default_router_deadline(router).flatten());\n\n        if self.ipv6_gateway != selected {\n            self.set_ipv6_default_gateway(selected);\n        }\n        if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {\n            lifetimes.router = selected;\n            lifetimes.router_until_ms = selected_deadline;\n        }\n        if let Some(dad) = self.ipv6_dad.as_mut() {\n            dad.gateway = selected;\n            dad.router_until_ms = selected_deadline;\n        }\n    }\n"""
assert old_select in text
text = text.replace(old_select, new_select, 1)

old_router_flag = """                                    if icmp6.payload[0] & 0x80 == 0 {\n                                        self.refresh_slaac_default_router(target_ip6, 0);\n                                    }\n"""
new_router_flag = """                                    if icmp6.payload[0] & 0x80 == 0 {\n                                        self.refresh_slaac_default_router(target_ip6, 0);\n                                    } else if self.default_router_deadline(target_ip6).is_some() {\n                                        self.select_ipv6_default_router();\n                                    }\n"""
assert old_router_flag in text
text = text.replace(old_router_flag, new_router_flag, 1)

old_resolving = """                                    if solicited {\n                                        self.ndp_table.confirm_reachable(\n                                            target_ip6,\n                                            target_mac,\n                                            self.current_time_ms,\n                                        );\n                                    } else {\n                                        self.ndp_table.mark_stale(target_ip6, target_mac);\n                                    }\n\n                                    if let Some(queued_packets) =\n"""
new_resolving = """                                    if solicited {\n                                        self.ndp_table.confirm_reachable(\n                                            target_ip6,\n                                            target_mac,\n                                            self.current_time_ms,\n                                        );\n                                    } else {\n                                        self.ndp_table.mark_stale(target_ip6, target_mac);\n                                    }\n                                    if icmp6.payload[0] & 0x80 != 0\n                                        && self.default_router_deadline(target_ip6).is_some()\n                                    {\n                                        self.select_ipv6_default_router();\n                                    }\n\n                                    if let Some(queued_packets) =\n"""
assert old_resolving in text
text = text.replace(old_resolving, new_resolving, 1)
stack.write_text(text)

test = Path('tests/test_ipv6_default_router_list.rs')
t = test.read_text()
append = r'''

fn solicited_router_na(
    router_mac: MacAddress,
    router: Ipv6Address,
    host_mac: MacAddress,
    host: Ipv6Address,
) -> Vec<u8> {
    let na = Icmpv6Packet::build_neighbor_advertisement(
        router,
        host,
        router,
        router_mac,
        true,
        true,
        true,
    );
    let packet = Ipv6Packet::serialize(router, host, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn reachable_router_preempts_non_reachable_active_router() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x94]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 4, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 4, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:94::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    let host = s.config.ipv6.unwrap();
    assert!(s
        .process_frame(&solicited_router_na(r2_mac, r2, host_mac, host))
        .is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r2));
}

#[test]
fn reachable_active_router_remains_stable_when_peer_becomes_reachable() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x95]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 5, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 5, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:95::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    let host = s.config.ipv6.unwrap();

    s.process_frame(&solicited_router_na(r2_mac, r2, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(r2));
    s.process_frame(&solicited_router_na(r1_mac, r1, host_mac, host));
    assert_eq!(s.ipv6_gateway(), Some(r2));
}
'''
assert 'reachable_router_preempts_non_reachable_active_router' not in t
test.write_text(t + append)
