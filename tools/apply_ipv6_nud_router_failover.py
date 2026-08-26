from pathlib import Path

stack = Path("src/stack.rs")
text = stack.read_text()

old = '''        // RFC 4861 NUD probes a STALE neighbor only after first use and
        // DELAY_FIRST_PROBE_TIME. PROBE retransmissions are unicast and the cached
        // link-layer address remains usable while reachability is revalidated.
        for (target, dst_mac) in self.ndp_table.step_nud(now_ms) {
'''
new = '''        // RFC 4861 NUD probes a STALE neighbor only after first use and
        // DELAY_FIRST_PROBE_TIME. PROBE retransmissions are unicast and the cached
        // link-layer address remains usable while reachability is revalidated.
        // Remember whether the active learned default router had a Neighbor Cache
        // entry before this pump so a NUD timeout can be distinguished from a router
        // that simply has not been resolved yet.
        let active_router_before_nud = self.ipv6_gateway;
        let active_router_was_cached = active_router_before_nud.is_some_and(|router| {
            self.default_router_deadline(router).is_some() && self.ndp_table.lookup(&router).is_some()
        });
        for (target, dst_mac) in self.ndp_table.step_nud(now_ms) {
'''
if old not in text:
    raise SystemExit("first stack replacement anchor not found")
text = text.replace(old, new, 1)

old = '''        }
        // RFC 4861 Prefix List lifetimes are independent of SLAAC address
        // lifetimes. Expiry returns destinations to normal default-router selection.
'''
new = '''        }

        // RFC 4861 section 6.3.6: when NUD determines that the active default
        // router is unreachable, remove it from the Default Router List and select
        // another retained router immediately. If that was the last router, Router
        // Discovery is restarted below rather than waiting for its advertised
        // lifetime to expire.
        let mut lost_last_router_to_nud = false;
        if let Some(router) = active_router_before_nud {
            if active_router_was_cached && self.ndp_table.lookup(&router).is_none() {
                let had_router = !self.ipv6_default_routers.is_empty();
                self.ipv6_default_routers
                    .retain(|(address, _)| *address != router);
                self.select_ipv6_default_router();
                lost_last_router_to_nud = had_router && self.ipv6_default_routers.is_empty();
            }
        }

        // RFC 4861 Prefix List lifetimes are independent of SLAAC address
        // lifetimes. Expiry returns destinations to normal default-router selection.
'''
if old not in text:
    raise SystemExit("second stack replacement anchor not found")
text = text.replace(old, new, 1)

old = '''            let lost_last_router = self.expire_ipv6_default_routers(now_ms);
            if lost_last_router && !router_discovery_was_active {
'''
new = '''            let lost_last_router = self.expire_ipv6_default_routers(now_ms);
            if (lost_last_router || lost_last_router_to_nud) && !router_discovery_was_active {
'''
if old not in text:
    raise SystemExit("third stack replacement anchor not found")
text = text.replace(old, new, 1)
stack.write_text(text)

test = Path("tests/test_ipv6_default_router_list.rs")
text = test.read_text()
append = r'''

#[test]
fn nud_unreachable_active_router_fails_over_without_new_router_solicitation() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x92]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:92::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // RAs learn routers as STALE. Using R1 starts DELAY without changing the
    // active default router, then three unanswered unicast probes exhaust NUD.
    assert!(s.ping6(ip6("2001:db8:ffff::1"), 0x9200, 1, b"nud").is_some());
    assert_eq!(s.step_timers(6_000).len(), 1);
    assert_eq!(s.step_timers(7_000).len(), 1);
    assert_eq!(s.step_timers(8_000).len(), 1);

    let frames = s.step_timers(9_000);
    assert_eq!(s.ipv6_gateway(), Some(r2));
    assert!(frames.is_empty());
}

#[test]
fn nud_unreachable_last_router_restarts_router_discovery() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x93]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 3, 1]);
    let router = link_local_address(router_mac);
    let prefix = ip6("2001:db8:93::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(router_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(router));

    assert!(s.ping6(ip6("2001:db8:ffff::2"), 0x9300, 1, b"nud").is_some());
    assert_eq!(s.step_timers(6_000).len(), 1);
    assert_eq!(s.step_timers(7_000).len(), 1);
    assert_eq!(s.step_timers(8_000).len(), 1);

    let frames = s.step_timers(9_000);
    assert_eq!(s.ipv6_gateway(), None);
    assert_eq!(frames.len(), 1, "last-router loss should emit a fresh RS");
}
'''
if "nud_unreachable_active_router_fails_over_without_new_router_solicitation" in text:
    raise SystemExit("tests already present")
test.write_text(text + append)
