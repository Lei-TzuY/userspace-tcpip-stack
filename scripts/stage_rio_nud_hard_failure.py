from pathlib import Path

stack = Path("src/stack.rs")
text = stack.read_text()
old = '''        let active_router_before_nud = self.ipv6_gateway;
        let active_router_was_cached = active_router_before_nud.is_some_and(|router| {
            self.default_router_deadline(router).is_some()
                && self.ndp_table.lookup(&router).is_some()
        });
        for (target, dst_mac) in self.ndp_table.step_nud(now_ms) {
'''
new = '''        let active_router_before_nud = self.ipv6_gateway;
        let active_router_was_cached = active_router_before_nud.is_some_and(|router| {
            self.default_router_deadline(router).is_some()
                && self.ndp_table.lookup(&router).is_some()
        });
        // Track learned RFC 4191 next hops that had a real Neighbor Cache entry
        // before NUD runs. If one disappears during this pump, NUD has positively
        // declared it unreachable; that is different from a router that has never
        // been resolved and must remain eligible as a retained fallback.
        let mut cached_rio_routers_before_nud = Vec::new();
        for (_, _, router) in self.ipv6_ra_routes.keys().copied() {
            if self.ndp_table.lookup(&router).is_some()
                && !cached_rio_routers_before_nud.contains(&router)
            {
                cached_rio_routers_before_nud.push(router);
            }
        }
        for (target, dst_mac) in self.ndp_table.step_nud(now_ms) {
'''
assert old in text
text = text.replace(old, new, 1)
old = '''        // NUD state changes can alter the RFC 4191 Type C next-hop choice even
        // when no RIO lifetime changed (for example REACHABLE -> STALE).
        self.reselect_ipv6_ra_routes();
'''
new = '''        // RFC 4191 Type C routes must not immediately resurrect a router that
        // NUD just proved unreachable merely because its Neighbor Cache entry was
        // deleted. Remove that advertiser's retained RIO candidates; a later RA can
        // explicitly advertise them again. Routers that were never resolved are not
        // touched and remain valid fallbacks.
        let failed_rio_routers: Vec<Ipv6Address> = cached_rio_routers_before_nud
            .into_iter()
            .filter(|router| self.ndp_table.lookup(router).is_none())
            .collect();
        if !failed_rio_routers.is_empty() {
            self.ipv6_ra_routes.retain(|(_, prefix_len, router), _| {
                *prefix_len == 0 || !failed_rio_routers.contains(router)
            });
        }

        // NUD state changes can alter the RFC 4191 Type C next-hop choice even
        // when no RIO lifetime changed (for example REACHABLE -> STALE).
        self.reselect_ipv6_ra_routes();
'''
assert old in text
text = text.replace(old, new, 1)
stack.write_text(text)

test = Path("tests/test_ipv6_rio_routing.rs")
text = test.read_text()
old = '''use toy_tcpip::icmpv6::{
    Icmpv6Packet, NDP_REACHABLE_TIME_MS, RouteInformationOption, RouterPreference,
};
'''
new = '''use toy_tcpip::icmpv6::{
    Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS, NDP_REACHABLE_TIME_MS, NDP_RETRANS_TIMER_MS,
    RouteInformationOption, RouterPreference,
};
'''
assert old in text
text = text.replace(old, new, 1)
text += r'''

#[test]
fn more_specific_rio_nud_failure_falls_back_without_resurrecting_failed_router() {
    let mut stack = stack();
    let fallback = ip("fe80::1");
    let preferred = ip("fe80::2");
    let prefix = ip("2001:db8:90::");
    let destination = ip("2001:db8:90::1234");

    stack.process_frame(&ra_frame(
        fallback,
        RouteInformationOption::new(prefix, 64, RouterPreference::Low, 120),
    ));
    stack.process_frame(&ra_frame(
        preferred,
        RouteInformationOption::new(prefix, 64, RouterPreference::High, 120),
    ));
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(preferred)
    );

    // First transmission through the preferred router consumes its STALE cache
    // entry and enters DELAY, arming NUD. The fallback remains merely unresolved/
    // unused from the route-selection perspective.
    let packet = Ipv6Packet::serialize(
        stack.config.ipv6.unwrap(),
        destination,
        59,
        64,
        b"nud-rio",
    );
    let frame = stack.send_ip6_packet(destination, packet).unwrap();
    assert_eq!(
        EthernetFrame::parse(&frame).unwrap().dst_mac,
        MacAddress([0x02, 0, 0, 0, 0, 2])
    );

    for now in [
        NDP_DELAY_FIRST_PROBE_TIME_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + NDP_RETRANS_TIMER_MS,
        NDP_DELAY_FIRST_PROBE_TIME_MS + 2 * NDP_RETRANS_TIMER_MS,
    ] {
        assert_eq!(stack.step_timers(now).len(), 1);
    }
    assert!(
        stack
            .step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(stack.ndp_table.lookup(&preferred), None);
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(fallback)
    );

    // A later timer pump must keep the fallback selected instead of treating the
    // now-missing preferred Neighbor Cache entry as a fresh unresolved candidate.
    stack.step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS + 4 * NDP_RETRANS_TIMER_MS);
    assert_eq!(
        stack
            .ipv6_routing_table
            .find_exact(prefix, 64)
            .unwrap()
            .gateway,
        Some(fallback)
    );
}
'''
test.write_text(text)
