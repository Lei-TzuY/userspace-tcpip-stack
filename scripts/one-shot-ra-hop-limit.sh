#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path

stack = Path('src/stack.rs')
text = stack.read_text()

def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'expected one stack.rs replacement, found {count}: {old[:100]!r}')
    text = text.replace(old, new, 1)

replace_once(
    'pub const IPV6_RTR_SOLICITATION_INTERVAL_MS: u64 = 4_000;\n',
    'pub const IPV6_RTR_SOLICITATION_INTERVAL_MS: u64 = 4_000;\n'
    '/// Implementation default used until a valid RA advertises a non-zero Cur Hop Limit.\n'
    'pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;\n',
)

replace_once(
    '    ipv6_router_discovery_exhausted: bool,\n    ipv6_path_mtu_cache: HashMap<Ipv6Address, u32>,\n',
    '    ipv6_router_discovery_exhausted: bool,\n'
    '    // RFC 4861 section 6.3.4 per-interface CurHopLimit. Zero in an RA means\n'
    '    // unspecified, so the currently learned/default value is preserved.\n'
    '    ipv6_default_hop_limit: u8,\n'
    '    ipv6_path_mtu_cache: HashMap<Ipv6Address, u32>,\n',
)

replace_once(
    '            ipv6_router_discovery_exhausted: false,\n            ipv6_path_mtu_cache: HashMap::new(),\n',
    '            ipv6_router_discovery_exhausted: false,\n'
    '            ipv6_default_hop_limit: IPV6_DEFAULT_HOP_LIMIT,\n'
    '            ipv6_path_mtu_cache: HashMap::new(),\n',
)

replace_once(
    '    pub fn ipv6_gateway(&self) -> Option<Ipv6Address> {\n'
    '        self.ipv6_gateway\n'
    '    }\n\n'
    '    /// Returns the currently learned RFC 8201 Path MTU for a destination.\n',
    '    pub fn ipv6_gateway(&self) -> Option<Ipv6Address> {\n'
    '        self.ipv6_gateway\n'
    '    }\n\n'
    '    /// Returns the current RFC 4861 CurHopLimit used for ordinary host-originated IPv6.\n'
    '    pub fn ipv6_default_hop_limit(&self) -> u8 {\n'
    '        self.ipv6_default_hop_limit\n'
    '    }\n\n'
    '    /// Returns the currently learned RFC 8201 Path MTU for a destination.\n',
)

replace_once(
    '        self.ipv6_path_mtu_cache.clear();\n'
    '        self.ipv6_redirect_cache.clear();\n'
    '        self.pending_ndp_packets.clear();\n',
    '        self.ipv6_path_mtu_cache.clear();\n'
    '        self.ipv6_redirect_cache.clear();\n'
    '        self.ipv6_default_hop_limit = IPV6_DEFAULT_HOP_LIMIT;\n'
    '        self.pending_ndp_packets.clear();\n',
)

replace_once(
    '                                    self.ndp_table.apply_router_advertisement_timers(\n'
    '                                        ra.reachable_time,\n'
    '                                        ra.retrans_timer,\n'
    '                                    );\n\n'
    '                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may\n',
    '                                    self.ndp_table.apply_router_advertisement_timers(\n'
    '                                        ra.reachable_time,\n'
    '                                        ra.retrans_timer,\n'
    '                                    );\n'
    '                                    if ra.current_hop_limit != 0 {\n'
    '                                        self.ipv6_default_hop_limit = ra.current_hop_limit;\n'
    '                                    }\n\n'
    '                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may\n',
)

replace_once(
    '        let ip6_bytes = Ipv6Packet::serialize(my_ip6, dst_ip, NEXT_HEADER_ICMPV6, 64, &icmp);\n',
    '        let ip6_bytes = Ipv6Packet::serialize(\n'
    '            my_ip6,\n'
    '            dst_ip,\n'
    '            NEXT_HEADER_ICMPV6,\n'
    '            self.ipv6_default_hop_limit,\n'
    '            &icmp,\n'
    '        );\n',
)

replace_once(
    '                                        NEXT_HEADER_ICMPV6,\n'
    '                                        64,\n'
    '                                        &echo_reply,\n',
    '                                        NEXT_HEADER_ICMPV6,\n'
    '                                        self.ipv6_default_hop_limit,\n'
    '                                        &echo_reply,\n',
)

stack.write_text(text)

Path('tests/test_ipv6_ra_hop_limit.rs').write_text(r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, NDP_DELAY_FIRST_PROBE_TIME_MS, ipv6_multicast_mac,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{IPV6_DEFAULT_HOP_LIMIT, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn host() -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac: mac(0x10),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(ip6("2001:db8:1::10"), 64, None);
    stack
}

fn ra_frame(stack: &NetStack, current_hop_limit: u8, outer_hop_limit: u8) -> Vec<u8> {
    let router_ip = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(
        router_ip,
        dst,
        current_hop_limit,
        1800,
        &[],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(
        router_ip,
        dst,
        NEXT_HEADER_ICMPV6,
        outer_hop_limit,
        &ra,
    );
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn ipv6_from_frame(frame: &[u8]) -> Ipv6Packet<'_> {
    let eth = EthernetFrame::parse(frame).unwrap();
    Ipv6Packet::parse(eth.payload).unwrap()
}

#[test]
fn valid_ra_cur_hop_limit_drives_subsequent_ping6() {
    let mut stack = host();
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);

    assert!(stack.process_frame(&ra_frame(&stack, 37, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 37);

    let peer = ip6("2001:db8:1::20");
    stack.ndp_table.insert(peer, mac(0x20));
    let frame = stack.ping6(peer, 0x4861, 1, b"hop-limit").unwrap();
    assert_eq!(ipv6_from_frame(&frame).header.hop_limit, 37);
}

#[test]
fn zero_cur_hop_limit_preserves_previously_learned_value() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 41, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 41);

    assert!(stack.process_frame(&ra_frame(&stack, 0, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 41);
}

#[test]
fn invalid_ra_cannot_change_default_hop_limit() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 22, 64)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);
}

#[test]
fn echo_reply_uses_ra_learned_default_hop_limit() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 39, 255)).is_empty());

    let host_ip = ip6("2001:db8:1::10");
    let peer_ip = ip6("2001:db8:1::20");
    let peer_mac = mac(0x20);
    let echo = Icmpv6Packet::build_echo_request(peer_ip, host_ip, 7, 9, b"reply");
    let packet = Ipv6Packet::serialize(peer_ip, host_ip, NEXT_HEADER_ICMPV6, 64, &echo);
    let frame = EthernetFrame::serialize(
        stack.config.mac,
        peer_mac,
        ETHERTYPE_IPV6,
        &packet,
    );

    let replies = stack.process_frame(&frame);
    assert_eq!(replies.len(), 1);
    assert_eq!(ipv6_from_frame(&replies[0]).header.hop_limit, 39);
}

#[test]
fn ndp_control_packets_remain_hop_limit_255_after_ra_update() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 33, 255)).is_empty());

    let peer = ip6("2001:db8:1::30");
    let peer_mac = mac(0x30);
    stack.ndp_table.mark_stale(peer, peer_mac);
    let data = stack.ping6(peer, 1, 1, b"nud").unwrap();
    assert_eq!(ipv6_from_frame(&data).header.hop_limit, 33);

    let probes = stack.step_timers(NDP_DELAY_FIRST_PROBE_TIME_MS);
    assert_eq!(probes.len(), 1);
    assert_eq!(ipv6_from_frame(&probes[0]).header.hop_limit, 255);
}

#[test]
fn clearing_ipv6_interface_restores_implementation_default() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(&stack, 31, 255)).is_empty());
    assert_eq!(stack.ipv6_default_hop_limit(), 31);

    stack.clear_ipv6_interface();
    assert_eq!(stack.ipv6_default_hop_limit(), IPV6_DEFAULT_HOP_LIMIT);
}
''')
PY

cargo fmt --all
cargo fmt --all -- --check
cargo test --test test_ipv6_ra_hop_limit --verbose
cargo test --all-targets --verbose
cargo build --release --verbose
git diff --check

rm .github/workflows/one-shot-ra-hop-limit.yml scripts/one-shot-ra-hop-limit.sh
git add -A
git config user.name 'LeiZ'
git config user.email '52287354+Lei-TzuY@users.noreply.github.com'
git commit -m 'fix(ipv6): honor RA current hop limit'
git push origin HEAD:fix/ipv6-ra-hop-limit
