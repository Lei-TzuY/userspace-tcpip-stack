from pathlib import Path

p = Path('src/stack.rs')
s = p.read_text()

def rep(old, new):
    global s
    if old not in s:
        raise SystemExit(f'missing pattern:\n{old[:200]}')
    s = s.replace(old, new, 1)

rep(
"    ipv6_gateway: Option<Ipv6Address>,\n    ipv6_dad: Option<PendingIpv6Dad>,",
"    ipv6_gateway: Option<Ipv6Address>,\n    // RFC 4861 Default Router List, in discovery order. `None` is an infinite lifetime.\n    ipv6_default_routers: Vec<(Ipv6Address, Option<u64>)>,\n    ipv6_dad: Option<PendingIpv6Dad>,"
)
rep(
"            ipv6_gateway: None,\n            ipv6_dad: None,",
"            ipv6_gateway: None,\n            ipv6_default_routers: Vec::new(),\n            ipv6_dad: None,"
)
rep(
"        self.ipv6_gateway = None;\n        self.ipv6_dad = None;",
"        self.ipv6_gateway = None;\n        self.ipv6_default_routers.clear();\n        self.ipv6_dad = None;"
)

old = '''    fn refresh_slaac_default_router(&mut self, router: Ipv6Address, lifetime_secs: u16) {
        let deadline = (lifetime_secs > 0).then(|| {
            self.current_time_ms
                .saturating_add((lifetime_secs as u64).saturating_mul(1_000))
        });

        let active_action = self.ipv6_slaac_lifetimes.map(|lifetimes| {
            if lifetime_secs == 0 {
                (lifetimes.router == Some(router), None)
            } else {
                (true, Some(router))
            }
        });
        if let Some((change_route, gateway)) = active_action
            && change_route
        {
            self.set_ipv6_default_gateway(gateway);
            if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {
                lifetimes.router = gateway;
                lifetimes.router_until_ms = gateway.and(deadline);
            }
        }

        if let Some(dad) = self.ipv6_dad.as_mut() {
            if lifetime_secs == 0 {
                if dad.gateway == Some(router) {
                    dad.gateway = None;
                    dad.router_until_ms = None;
                }
            } else {
                dad.gateway = Some(router);
                dad.router_until_ms = deadline;
            }
        }
    }
'''
new = '''    fn default_router_deadline(&self, router: Ipv6Address) -> Option<Option<u64>> {
        self.ipv6_default_routers
            .iter()
            .find_map(|(address, deadline)| (*address == router).then_some(*deadline))
    }

    fn select_ipv6_default_router(&mut self) {
        let active = self.ipv6_gateway.filter(|router| {
            self.default_router_deadline(*router)
                .is_some_and(|deadline| deadline.is_none_or(|deadline| self.current_time_ms < deadline))
        });
        let selected = active.or_else(|| {
            self.ipv6_default_routers.iter().find_map(|(router, deadline)| {
                deadline
                    .is_none_or(|deadline| self.current_time_ms < deadline)
                    .then_some(*router)
            })
        });
        let selected_deadline = selected.and_then(|router| self.default_router_deadline(router).flatten());

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

    fn refresh_slaac_default_router(&mut self, router: Ipv6Address, lifetime_secs: u16) {
        if lifetime_secs == 0 {
            self.ipv6_default_routers
                .retain(|(address, _)| *address != router);
        } else {
            let deadline = Some(
                self.current_time_ms
                    .saturating_add((lifetime_secs as u64).saturating_mul(1_000)),
            );
            if let Some((_, current_deadline)) = self
                .ipv6_default_routers
                .iter_mut()
                .find(|(address, _)| *address == router)
            {
                *current_deadline = deadline;
            } else {
                self.ipv6_default_routers.push((router, deadline));
            }
        }
        self.select_ipv6_default_router();
    }

    fn expire_ipv6_default_routers(&mut self, now_ms: u64) -> bool {
        let had_router = !self.ipv6_default_routers.is_empty();
        self.ipv6_default_routers
            .retain(|(_, deadline)| deadline.is_none_or(|deadline| now_ms < deadline));
        self.select_ipv6_default_router();
        had_router && self.ipv6_default_routers.is_empty()
    }
'''
rep(old, new)

rep(
"                                        let gateway = (ra.router_lifetime > 0)\n                                            .then_some(ip6_pkt.header.src_ip);",
"                                        let gateway = self.ipv6_gateway;"
)

old_timer = '''            let router_expired = self
                .ipv6_slaac_lifetimes
                .and_then(|lifetimes| lifetimes.router_until_ms)
                .is_some_and(|deadline| now_ms >= deadline);
            if router_expired {
                self.set_ipv6_default_gateway(None);
                if let Some(lifetimes) = self.ipv6_slaac_lifetimes.as_mut() {
                    lifetimes.router = None;
                    lifetimes.router_until_ms = None;
                }

                // The SLAAC address/prefix can remain perfectly valid after the
                // selected default router expires. Re-run Router Discovery so the
                // host can refresh that router or discover a replacement instead of
                // remaining indefinitely address-configured but gateway-less.
                //
                // An already active discovery cycle is left untouched. A previously
                // Exhausted cycle, however, represents an older discovery event and
                // is explicitly restarted by this new router-expiry event.
                if !router_discovery_was_active {
                    out_frames.push(self.start_router_discovery());
                }
            }
'''
new_timer = '''            let lost_last_router = self.expire_ipv6_default_routers(now_ms);
            if lost_last_router && !router_discovery_was_active {
                // RFC 4861: only restart discovery when the Default Router List has
                // become empty. If another learned router is still valid, fail over
                // immediately without emitting a new Router Solicitation.
                out_frames.push(self.start_router_discovery());
            }
'''
rep(old_timer, new_timer)

# When an already configured SLAAC address is refreshed by a PIO, keep the router
# selected from the Default Router List instead of blindly replacing it with the
# source of the most recent RA.
old_ra = '''                                            let router = if ra.router_lifetime > 0 {
                                                Some(ip6_pkt.header.src_ip)
                                            } else {
                                                None
                                            };
                                            let router_until_ms = router.map(|_| {
                                                now_ms.saturating_add(
                                                    (ra.router_lifetime as u64)
                                                        .saturating_mul(1_000),
                                                )
                                            });
'''
new_ra = '''                                            let router = self.ipv6_gateway;
                                            let router_until_ms = router.and_then(|router| {
                                                self.default_router_deadline(router).flatten()
                                            });
'''
rep(old_ra, new_ra)

p.write_text(s)

# Add focused integration coverage.
t = Path('tests/test_ipv6_default_router_list.rs')
t.write_text(r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac, link_local_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address { Ipv6Address::from_str(text).unwrap() }

fn stack(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(router_mac: MacAddress, prefix: Ipv6Address, lifetime: u16) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 600, 300);
    let ra = Icmpv6Packet::build_router_advertisement(src, dst, 64, lifetime, &[pio], Some(router_mac));
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(ipv6_multicast_mac(dst).unwrap(), router_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn active_router_expiry_fails_over_without_new_router_solicitation() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x90]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 0, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:90::");
    let mut s = stack(host_mac);

    assert_eq!(s.process_frame(&ra_frame(r1_mac, prefix, 2)).len(), 1);
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // A later RA adds a fallback but must not preempt the current router.
    assert!(s.process_frame(&ra_frame(r2_mac, prefix, 10)).is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r1));

    // R1 expires at t=2s. R2 is selected immediately; no RS is emitted.
    let frames = s.step_timers(2_000);
    assert_eq!(s.ipv6_gateway(), Some(r2));
    assert!(frames.is_empty());
}

#[test]
fn zero_lifetime_withdraws_active_router_and_uses_fallback() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x91]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 1, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:91::");
    let mut s = stack(host_mac);

    s.process_frame(&ra_frame(r1_mac, prefix, 30));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30));
    assert_eq!(s.ipv6_gateway(), Some(r1));

    assert!(s.process_frame(&ra_frame(r1_mac, prefix, 0)).is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r2));
}
''')
