from pathlib import Path

stack = Path('src/stack.rs')
s = stack.read_text()

s = s.replace(
"    ipv6_ra_on_link_prefixes: HashMap<(Ipv6Address, u8), Option<u64>>,\n",
"    ipv6_ra_on_link_prefixes: HashMap<(Ipv6Address, u8), Option<u64>>,\n    // RFC 4191 Route Information Options keyed by (prefix, prefix_len, advertising router).\n    // `None` is an infinite lifetime. The routing table exposes only the currently\n    // best candidate per prefix; retained candidates provide deterministic fallback.\n    ipv6_ra_routes: HashMap<(Ipv6Address, u8, Ipv6Address), (Option<u64>, RouterPreference)>,\n")
s = s.replace(
"            ipv6_ra_on_link_prefixes: HashMap::new(),\n",
"            ipv6_ra_on_link_prefixes: HashMap::new(),\n            ipv6_ra_routes: HashMap::new(),\n")
s = s.replace(
"        self.ipv6_slaac_lifetimes = None;\n        self.ipv6_path_mtu_cache.clear();\n",
"        self.ipv6_slaac_lifetimes = None;\n        self.ipv6_ra_routes.clear();\n        self.ipv6_routing_table.remove_all_from(RouteSource::RaRoute);\n        self.ipv6_path_mtu_cache.clear();\n",
1)

needle = "    fn start_ipv6_dad(\n"
insert = r'''    fn select_ipv6_ra_route(&mut self, prefix: Ipv6Address, prefix_len: u8) {
        let prefix_len = prefix_len.min(128);
        let prefix = prefix.mask(prefix_len);
        let current_gateway = self
            .ipv6_routing_table
            .find_exact(prefix, prefix_len)
            .filter(|route| route.source == RouteSource::RaRoute)
            .and_then(|route| route.gateway);
        self.ipv6_routing_table
            .remove_route(prefix, prefix_len, RouteSource::RaRoute);

        let best_preference = self
            .ipv6_ra_routes
            .iter()
            .filter(|((candidate_prefix, candidate_len, _), (deadline, _))| {
                *candidate_prefix == prefix
                    && *candidate_len == prefix_len
                    && deadline.is_none_or(|deadline| self.current_time_ms < deadline)
            })
            .map(|(_, (_, preference))| *preference)
            .max();
        let Some(best_preference) = best_preference else {
            return;
        };

        let current_is_best = current_gateway.is_some_and(|gateway| {
            self.ipv6_ra_routes
                .get(&(prefix, prefix_len, gateway))
                .is_some_and(|(deadline, preference)| {
                    *preference == best_preference
                        && deadline.is_none_or(|deadline| self.current_time_ms < deadline)
                })
        });
        let selected = if current_is_best {
            current_gateway
        } else {
            self.ipv6_ra_routes
                .iter()
                .filter_map(|((candidate_prefix, candidate_len, router), (deadline, preference))| {
                    (*candidate_prefix == prefix
                        && *candidate_len == prefix_len
                        && *preference == best_preference
                        && deadline.is_none_or(|deadline| self.current_time_ms < deadline))
                    .then_some(*router)
                })
                .min_by_key(|router| router.0)
        };
        if let Some(router) = selected {
            self.ipv6_routing_table.add_route_from(
                prefix,
                prefix_len,
                Some(router),
                "eth0",
                RouteSource::RaRoute,
            );
        }
    }

    fn refresh_ipv6_ra_route(
        &mut self,
        router: Ipv6Address,
        prefix: Ipv6Address,
        prefix_len: u8,
        preference: RouterPreference,
        route_lifetime: u32,
    ) {
        let prefix_len = prefix_len.min(128);
        let prefix = prefix.mask(prefix_len);
        let key = (prefix, prefix_len, router);
        if route_lifetime == 0 {
            self.ipv6_ra_routes.remove(&key);
        } else {
            self.ipv6_ra_routes.insert(
                key,
                (ipv6_lifetime_deadline(self.current_time_ms, route_lifetime), preference),
            );
        }
        self.select_ipv6_ra_route(prefix, prefix_len);
    }

'''
assert needle in s
s = s.replace(needle, insert + needle, 1)

needle = "        // A tentative SLAAC address becomes usable only after its DAD interval\n"
insert = r'''        // RFC 4191 learned routes have independent lifetimes. Expiring one
        // candidate immediately re-selects the best retained advertiser for that prefix.
        let expired_ra_routes: Vec<(Ipv6Address, u8, Ipv6Address)> = self
            .ipv6_ra_routes
            .iter()
            .filter_map(|(key, (deadline, _))| {
                deadline
                    .is_some_and(|deadline| now_ms >= deadline)
                    .then_some(*key)
            })
            .collect();
        let mut affected_ra_prefixes = Vec::new();
        for (prefix, prefix_len, router) in expired_ra_routes {
            self.ipv6_ra_routes.remove(&(prefix, prefix_len, router));
            if !affected_ra_prefixes.contains(&(prefix, prefix_len)) {
                affected_ra_prefixes.push((prefix, prefix_len));
            }
        }
        for (prefix, prefix_len) in affected_ra_prefixes {
            self.select_ipv6_ra_route(prefix, prefix_len);
        }

'''
assert needle in s
s = s.replace(needle, insert + needle, 1)

needle = "                                    // RFC 4861 section 6.3.4: L and A are independent.\n"
insert = r'''                                    // RFC 4191 section 3: RIOs install more-specific
                                    // routes through the advertising router. Route Lifetime=0
                                    // withdraws only that router's candidate; retained peers can
                                    // immediately become the selected next hop.
                                    for route in &ra.routes {
                                        self.refresh_ipv6_ra_route(
                                            ip6_pkt.header.src_ip,
                                            route.prefix,
                                            route.prefix_length,
                                            route.preference,
                                            route.route_lifetime,
                                        );
                                    }

'''
assert needle in s
s = s.replace(needle, insert + needle, 1)
stack.write_text(s)

router = Path('src/router.rs')
r = router.read_text()
r = r.replace(
"    /// Operator-configured route (the default for `add_route`).\n    #[default]\n    Static,\n",
"    /// Route learned from an RFC 4191 Route Information Option.\n    RaRoute,\n    /// Operator-configured route (the default for `add_route`).\n    #[default]\n    Static,\n")
r = r.replace(
"            RouteSource::Ra => 0,\n            RouteSource::Static => 1,\n",
"            RouteSource::Ra => 0,\n            RouteSource::Static => 1,\n            RouteSource::RaRoute => 10,\n")
r = r.replace(
"            RouteSource::Ra => \"ra\",\n            RouteSource::Static => \"static\",\n",
"            RouteSource::Ra => \"ra\",\n            RouteSource::RaRoute => \"ra-route\",\n            RouteSource::Static => \"static\",\n")
router.write_text(r)

test = Path('tests/test_ipv6_rio_routing.rs')
test.write_text(r'''use std::str::FromStr;
use userspace_tcpip_stack::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use userspace_tcpip_stack::icmpv6::{
    Icmpv6Packet, RouteInformationOption, RouterPreference,
};
use userspace_tcpip_stack::ipv4::Ipv4Address;
use userspace_tcpip_stack::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use userspace_tcpip_stack::router::RouteSource;
use userspace_tcpip_stack::stack::{NetStack, NetStackConfig};

fn ip(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn stack() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        ip: Ipv4Address::UNSPECIFIED,
        ipv6: Some(ip("2001:db8:1::10")),
        subnet_mask: 0,
        gateway: None,
    })
}

fn ra_frame(router: Ipv6Address, route: RouteInformationOption) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        1800,
        RouterPreference::Medium,
        &[],
        &[route],
        Some(MacAddress([0x02, 0, 0, 0, 0, router.0[15]])),
    );
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
        MacAddress([0x02, 0, 0, 0, 0, router.0[15]]),
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn rio_installs_and_zero_lifetime_withdraws_route() {
    let mut stack = stack();
    let router = ip("fe80::1");
    let prefix = ip("2001:db8:42::");
    stack.process_ethernet_frame(&ra_frame(
        router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 30),
    ));

    let route = stack.ipv6_routing_table.find_exact(prefix, 64).unwrap();
    assert_eq!(route.source, RouteSource::RaRoute);
    assert_eq!(route.gateway, Some(router));

    stack.process_ethernet_frame(&ra_frame(
        router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 0),
    ));
    assert!(stack.ipv6_routing_table.find_exact(prefix, 64).is_none());
}

#[test]
fn rio_prefers_high_and_falls_back_on_expiry() {
    let mut stack = stack();
    let low_router = ip("fe80::1");
    let high_router = ip("fe80::2");
    let prefix = ip("2001:db8:99::");

    stack.process_ethernet_frame(&ra_frame(
        low_router,
        RouteInformationOption::new(prefix, 64, RouterPreference::Low, 30),
    ));
    stack.process_ethernet_frame(&ra_frame(
        high_router,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 2),
    ));
    assert_eq!(
        stack.ipv6_routing_table.find_exact(prefix, 64).unwrap().gateway,
        Some(high_router)
    );

    stack.step_timers(2_000);
    assert_eq!(
        stack.ipv6_routing_table.find_exact(prefix, 64).unwrap().gateway,
        Some(low_router)
    );
}

#[test]
fn on_link_pio_route_still_outranks_rio_candidate() {
    use userspace_tcpip_stack::icmpv6::PrefixInformationOption;

    let mut stack = stack();
    let router = ip("fe80::1");
    let prefix = ip("2001:db8:77::");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, false, 60, 0);
    let rio = RouteInformationOption::new(prefix, 64, RouterPreference::High, 60);
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        1800,
        RouterPreference::Medium,
        &[pio],
        &[rio],
        None,
    );
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        MacAddress([0x33, 0x33, 0, 0, 0, 1]),
        MacAddress([0x02, 0, 0, 0, 0, 1]),
        ETHERTYPE_IPV6,
        &packet,
    );
    stack.process_ethernet_frame(&frame);

    let route = stack.ipv6_routing_table.lookup(ip("2001:db8:77::1234")).unwrap();
    assert_eq!(route.source, RouteSource::Ra);
    assert_eq!(route.gateway, None);
}
''')
