from pathlib import Path

stack_path = Path('src/stack.rs')
text = stack_path.read_text()

old = '''    fn default_router_deadline(&self, router: Ipv6Address) -> Option<Option<u64>> {
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
                == self
                    .default_router_preference(router)
                    .map(|preference| (self.default_router_reachability_rank(router), preference))
        });
        let selected = if active_is_best {
            active
        } else {
            best_score.and_then(|best| {
                self.ipv6_default_routers
                    .iter()
                    .find_map(|(router, deadline, preference)| {
                        (is_valid(*deadline)
                            && (self.default_router_reachability_rank(*router), *preference)
                                == best)
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
'''
new = '''    fn ipv6_default_route_candidates(
        &self,
    ) -> Vec<(Ipv6Address, Option<u64>, RouterPreference)> {
        let mut candidates = self.ipv6_default_routers.clone();
        for ((prefix, prefix_len, router), (deadline, preference)) in &self.ipv6_ra_routes {
            if *prefix_len != 0 || *prefix != Ipv6Address::UNSPECIFIED {
                continue;
            }
            if let Some(candidate) = candidates
                .iter_mut()
                .find(|(address, _, _)| *address == *router)
            {
                *candidate = (*router, *deadline, *preference);
            } else {
                candidates.push((*router, *deadline, *preference));
            }
        }
        candidates
    }

    fn default_router_deadline(&self, router: Ipv6Address) -> Option<Option<u64>> {
        self.ipv6_default_route_candidates()
            .into_iter()
            .find_map(|(address, deadline, _)| (address == router).then_some(deadline))
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
        let candidates = self.ipv6_default_route_candidates();
        let active = self.ipv6_gateway.filter(|router| {
            candidates.iter().any(|(candidate, deadline, _)| {
                *candidate == *router && is_valid(*deadline)
            })
        });

        // RFC 4861 section 6.3.6 makes reachability the primary selector; RFC 4191
        // uses Router/Route Preference as the secondary selector. A ::/0 RIO is a
        // default-route candidate and overrides the RA-header lifetime/preference
        // for the same advertising router.
        let best_score = candidates
            .iter()
            .filter(|(_, deadline, _)| is_valid(*deadline))
            .map(|(router, _, preference)| {
                (self.default_router_reachability_rank(*router), *preference)
            })
            .max();

        let active_is_best = active.is_some_and(|router| {
            best_score
                == candidates
                    .iter()
                    .find(|(candidate, deadline, _)| {
                        *candidate == router && is_valid(*deadline)
                    })
                    .map(|(_, _, preference)| {
                        (self.default_router_reachability_rank(router), *preference)
                    })
        });
        let selected = if active_is_best {
            active
        } else {
            best_score.and_then(|best| {
                candidates
                    .iter()
                    .find_map(|(router, deadline, preference)| {
                        (is_valid(*deadline)
                            && (self.default_router_reachability_rank(*router), *preference)
                                == best)
                            .then_some(*router)
                    })
            })
        };
        let selected_deadline = selected.and_then(|router| {
            candidates
                .iter()
                .find_map(|(candidate, deadline, _)| (*candidate == router).then_some(*deadline))
                .flatten()
        });

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
'''
assert old in text, 'default-router selection block changed'
text = text.replace(old, new)

old = '''    fn expire_ipv6_default_routers(&mut self, now_ms: u64) -> bool {
        let had_router = !self.ipv6_default_routers.is_empty();
        self.ipv6_default_routers
            .retain(|(_, deadline, _)| deadline.is_none_or(|deadline| now_ms < deadline));
        self.select_ipv6_default_router();
        had_router && self.ipv6_default_routers.is_empty()
    }
'''
new = '''    fn expire_ipv6_default_routers(&mut self, now_ms: u64) -> bool {
        let had_router = self.ipv6_gateway.is_some();
        self.ipv6_default_routers
            .retain(|(_, deadline, _)| deadline.is_none_or(|deadline| now_ms < deadline));
        self.select_ipv6_default_router();
        had_router && self.ipv6_gateway.is_none()
    }
'''
assert old in text, 'default-router expiry block changed'
text = text.replace(old, new)

old = '''    fn select_ipv6_ra_route(&mut self, prefix: Ipv6Address, prefix_len: u8) {
        let prefix_len = prefix_len.min(128);
        let prefix = prefix.mask(prefix_len);
        let current_gateway = self
'''
new = '''    fn select_ipv6_ra_route(&mut self, prefix: Ipv6Address, prefix_len: u8) {
        let prefix_len = prefix_len.min(128);
        let prefix = prefix.mask(prefix_len);
        if prefix_len == 0 {
            // RFC 4191 section 3.1: ::/0 RIOs are default routes. They participate
            // in the same reachability/preference selection as RA-header defaults
            // instead of being hidden behind the selected Static /0 route.
            self.ipv6_routing_table
                .remove_route(prefix, prefix_len, RouteSource::RaRoute);
            self.select_ipv6_default_router();
            return;
        }
        let current_gateway = self
'''
assert old in text, 'RIO selection function changed'
text = text.replace(old, new)

old = '''                                    self.cancel_router_discovery();
                                    self.refresh_slaac_default_router(
                                        ip6_pkt.header.src_ip,
                                        ra.router_lifetime,
                                        ra.preference,
                                    );

                                    // RFC 4191 section 3: RIOs install more-specific
'''
new = '''                                    self.cancel_router_discovery();
                                    let has_default_rio =
                                        ra.routes.iter().any(|route| route.prefix_length == 0);
                                    if has_default_rio {
                                        // RFC 4191 section 3.1: a ::/0 RIO in this RA
                                        // overrides the header's default-route lifetime and
                                        // preference for this router, including lifetime=0.
                                        self.ipv6_default_routers.retain(|(router, _, _)| {
                                            *router != ip6_pkt.header.src_ip
                                        });
                                        self.select_ipv6_default_router();
                                    } else {
                                        self.refresh_slaac_default_router(
                                            ip6_pkt.header.src_ip,
                                            ra.router_lifetime,
                                            ra.preference,
                                        );
                                    }

                                    // RFC 4191 section 3: RIOs install more-specific
'''
assert old in text, 'RA default-router processing block changed'
text = text.replace(old, new)

old = '''            if active_router_was_cached && self.ndp_table.lookup(&router).is_none() {
                let had_router = !self.ipv6_default_routers.is_empty();
                self.ipv6_default_routers
                    .retain(|(address, _, _)| *address != router);
                self.select_ipv6_default_router();
                lost_last_router_to_nud = had_router && self.ipv6_default_routers.is_empty();
            }
'''
new = '''            if active_router_was_cached && self.ndp_table.lookup(&router).is_none() {
                let had_router = self.ipv6_gateway.is_some();
                self.ipv6_default_routers
                    .retain(|(address, _, _)| *address != router);
                self.ipv6_ra_routes.retain(
                    |(prefix, prefix_len, advertising_router), _| {
                        !(*prefix_len == 0
                            && *prefix == Ipv6Address::UNSPECIFIED
                            && *advertising_router == router)
                    },
                );
                self.select_ipv6_default_router();
                lost_last_router_to_nud = had_router && self.ipv6_gateway.is_none();
            }
'''
assert old in text, 'NUD default-router failure block changed'
text = text.replace(old, new)

old = '''        // RFC 4191 learned routes have independent lifetimes. Expiring one
        // candidate immediately re-selects the best retained advertiser for that prefix.
        let expired_ra_routes: Vec<(Ipv6Address, u8, Ipv6Address)> = self
'''
new = '''        // RFC 4191 learned routes have independent lifetimes. Expiring one
        // candidate immediately re-selects the best retained advertiser for that prefix.
        let had_default_route_before_ra_expiry = self.ipv6_gateway.is_some();
        let expired_ra_routes: Vec<(Ipv6Address, u8, Ipv6Address)> = self
'''
assert old in text, 'RIO expiry prelude changed'
text = text.replace(old, new)

old = '''        for (prefix, prefix_len) in affected_ra_prefixes {
            self.select_ipv6_ra_route(prefix, prefix_len);
        }

        // A tentative SLAAC address becomes usable only after its DAD interval
'''
new = '''        for (prefix, prefix_len) in affected_ra_prefixes {
            self.select_ipv6_ra_route(prefix, prefix_len);
        }
        let lost_last_router_to_rio =
            had_default_route_before_ra_expiry && self.ipv6_gateway.is_none();

        // A tentative SLAAC address becomes usable only after its DAD interval
'''
assert old in text, 'RIO expiry epilogue changed'
text = text.replace(old, new)

old = '''            if (lost_last_router || lost_last_router_to_nud) && !router_discovery_was_active {
'''
new = '''            if (lost_last_router || lost_last_router_to_nud || lost_last_router_to_rio)
                && !router_discovery_was_active
            {
'''
assert old in text, 'router discovery restart condition changed'
text = text.replace(old, new)

stack_path.write_text(text)

test_path = Path('tests/test_ipv6_rio_routing.rs')
tests = test_path.read_text()
append = r'''

fn ra_frame_with_default_route(
    router: Ipv6Address,
    header_preference: RouterPreference,
    router_lifetime: u16,
    route_preference: RouterPreference,
    route_lifetime: u32,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let route = RouteInformationOption::new(
        Ipv6Address::UNSPECIFIED,
        0,
        route_preference,
        route_lifetime,
    );
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        router_lifetime,
        header_preference,
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

fn ra_frame_without_routes(
    router: Ipv6Address,
    preference: RouterPreference,
    router_lifetime: u16,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement_with_routes(
        router,
        dst,
        64,
        router_lifetime,
        preference,
        &[],
        &[],
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
fn zero_prefix_rio_overrides_ra_header_default_preference() {
    let mut stack = stack();
    let router_a = ip("fe80::1");
    let router_b = ip("fe80::2");

    stack.process_frame(&ra_frame_without_routes(
        router_a,
        RouterPreference::Medium,
        1800,
    ));
    stack.process_frame(&ra_frame_with_default_route(
        router_b,
        RouterPreference::Low,
        1800,
        RouterPreference::High,
        30,
    ));

    assert_eq!(stack.ipv6_gateway(), Some(router_b));
    let route = stack
        .ipv6_routing_table
        .lookup(ip("2001:4860:4860::8888"))
        .unwrap();
    assert_eq!(route.gateway, Some(router_b));
    assert_eq!(route.source, RouteSource::Static);
    assert!(
        stack
            .ipv6_routing_table
            .routes_from(RouteSource::RaRoute)
            .iter()
            .all(|route| route.prefix_len != 0)
    );
}

#[test]
fn zero_prefix_rio_lifetime_expiry_falls_back_to_other_default_router() {
    let mut stack = stack();
    let fallback = ip("fe80::1");
    let preferred = ip("fe80::2");

    stack.process_frame(&ra_frame_without_routes(
        fallback,
        RouterPreference::Medium,
        1800,
    ));
    stack.process_frame(&ra_frame_with_default_route(
        preferred,
        RouterPreference::Low,
        1800,
        RouterPreference::High,
        2,
    ));
    assert_eq!(stack.ipv6_gateway(), Some(preferred));

    stack.step_timers(2_000);
    assert_eq!(stack.ipv6_gateway(), Some(fallback));
    assert_eq!(
        stack
            .ipv6_routing_table
            .lookup(ip("2001:4860:4860::8888"))
            .unwrap()
            .gateway,
        Some(fallback)
    );
}

#[test]
fn zero_lifetime_zero_prefix_rio_withdraws_header_default_for_same_ra() {
    let mut stack = stack();
    let fallback = ip("fe80::1");
    let router = ip("fe80::2");

    stack.process_frame(&ra_frame_without_routes(
        fallback,
        RouterPreference::Medium,
        1800,
    ));
    stack.process_frame(&ra_frame_with_default_route(
        router,
        RouterPreference::Low,
        1800,
        RouterPreference::High,
        30,
    ));
    assert_eq!(stack.ipv6_gateway(), Some(router));

    stack.process_frame(&ra_frame_with_default_route(
        router,
        RouterPreference::High,
        1800,
        RouterPreference::Low,
        0,
    ));
    assert_eq!(stack.ipv6_gateway(), Some(fallback));
}
'''
if 'zero_prefix_rio_overrides_ra_header_default_preference' not in tests:
    tests += append
    test_path.write_text(tests)
