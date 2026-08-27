#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PY'
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f'{path}: expected one replacement, found {count}: {old[:120]!r}')
    p.write_text(text.replace(old, new, 1))

# --- ICMPv6 / RA codec ----------------------------------------------------
replace_once(
    'src/icmpv6.rs',
    'pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;\n'
    'pub const NDP_OPT_ROUTE_INFORMATION: u8 = 24;\n'
    'pub const NDP_OPT_REDIRECTED_HEADER: u8 = 4;\n',
    'pub const NDP_OPT_PREFIX_INFORMATION: u8 = 3;\n'
    'pub const NDP_OPT_REDIRECTED_HEADER: u8 = 4;\n'
    'pub const NDP_OPT_MTU: u8 = 5;\n'
    'pub const NDP_OPT_ROUTE_INFORMATION: u8 = 24;\n',
)

replace_once(
    'src/icmpv6.rs',
    '    pub retrans_timer: u32,\n'
    '    pub prefixes: Vec<PrefixInformationOption>,\n',
    '    pub retrans_timer: u32,\n'
    '    /// RFC 4861 MTU option, when present. Link-specific validity is applied\n'
    '    /// by the receiving interface rather than by the wire parser.\n'
    '    pub mtu: Option<u32>,\n'
    '    pub prefixes: Vec<PrefixInformationOption>,\n',
)

old_builder = '''    /// Builds an RFC 4191 Router Advertisement with Route Information Options.
    /// RIOs are encoded with the shortest valid option length for their prefix.
    pub fn build_router_advertisement_with_routes(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        routes: &[RouteInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        let route_bytes: usize = routes
            .iter()
            .copied()
            .map(|route| usize::from(route.length_units()) * 8)
            .sum();
        let mut buf = Vec::with_capacity(
            16 + prefixes.len() * 32 + route_bytes + usize::from(source_mac.is_some()) * 8,
        );
'''
new_builder = '''    /// Builds an RFC 4191 Router Advertisement with Route Information Options.
    /// RIOs are encoded with the shortest valid option length for their prefix.
    pub fn build_router_advertisement_with_routes(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        routes: &[RouteInformationOption],
        source_mac: Option<MacAddress>,
    ) -> Vec<u8> {
        Self::build_router_advertisement_with_routes_and_mtu(
            src_ip,
            dst_ip,
            current_hop_limit,
            router_lifetime,
            preference,
            prefixes,
            routes,
            source_mac,
            None,
        )
    }

    /// Builds a Router Advertisement with RFC 4191 RIOs and an optional RFC 4861
    /// MTU option. Existing builder APIs delegate here with no MTU option.
    pub fn build_router_advertisement_with_routes_and_mtu(
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        current_hop_limit: u8,
        router_lifetime: u16,
        preference: RouterPreference,
        prefixes: &[PrefixInformationOption],
        routes: &[RouteInformationOption],
        source_mac: Option<MacAddress>,
        mtu: Option<u32>,
    ) -> Vec<u8> {
        let route_bytes: usize = routes
            .iter()
            .copied()
            .map(|route| usize::from(route.length_units()) * 8)
            .sum();
        let mut buf = Vec::with_capacity(
            16 + prefixes.len() * 32
                + route_bytes
                + usize::from(source_mac.is_some()) * 8
                + usize::from(mtu.is_some()) * 8,
        );
'''
replace_once('src/icmpv6.rs', old_builder, new_builder)

replace_once(
    'src/icmpv6.rs',
    '''        if let Some(mac) = source_mac {
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }

        for prefix in prefixes {
''',
    '''        if let Some(mac) = source_mac {
            buf.push(NDP_OPT_SRC_LINK_LAYER_ADDR);
            buf.push(1);
            buf.extend_from_slice(&mac.0);
        }

        if let Some(mtu) = mtu {
            buf.push(NDP_OPT_MTU);
            buf.push(1);
            buf.extend_from_slice(&[0, 0]); // Reserved
            buf.extend_from_slice(&mtu.to_be_bytes());
        }

        for prefix in prefixes {
''',
)

replace_once(
    'src/icmpv6.rs',
    '        let mut prefixes = Vec::new();\n        let mut routes = Vec::new();\n',
    '        let mut mtu = None;\n        let mut prefixes = Vec::new();\n        let mut routes = Vec::new();\n',
)

replace_once(
    'src/icmpv6.rs',
    '''            } else if option_type == NDP_OPT_ROUTE_INFORMATION {
                let option = &payload[offset..offset + option_len];
''',
    '''            } else if option_type == NDP_OPT_MTU {
                // RFC 4861 defines MTU as exactly one 8-octet unit. The RA
                // validity rules require only non-zero option lengths, so a
                // malformed MTU option is ignored without discarding otherwise
                // usable information from the advertisement.
                if option_len == 8 {
                    let option = &payload[offset..offset + option_len];
                    mtu = Some(u32::from_be_bytes(option[4..8].try_into().ok()?));
                }
            } else if option_type == NDP_OPT_ROUTE_INFORMATION {
                let option = &payload[offset..offset + option_len];
''',
)

replace_once(
    'src/icmpv6.rs',
    '            retrans_timer,\n            prefixes,\n',
    '            retrans_timer,\n            mtu,\n            prefixes,\n',
)

# --- Host LinkMTU state / enforcement ------------------------------------
replace_once(
    'src/stack.rs',
    'pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;\n',
    'pub const IPV6_DEFAULT_HOP_LIMIT: u8 = 64;\n'
    '/// RFC 2464 default and maximum Router-Advertisement-controlled IPv6 MTU\n'
    '/// for this Ethernet-only host interface.\n'
    'pub const IPV6_ETHERNET_LINK_MTU: u32 = 1_500;\n',
)

replace_once(
    'src/stack.rs',
    '    ipv6_default_hop_limit: u8,\n    ipv6_path_mtu_cache: HashMap<Ipv6Address, u32>,\n',
    '    ipv6_default_hop_limit: u8,\n'
    '    // RFC 4861 LinkMTU for the Ethernet interface. RFC 2464 permits a valid\n'
    '    // RA to reduce this from 1500, but not below IPv6 minimum MTU 1280.\n'
    '    ipv6_link_mtu: u32,\n'
    '    ipv6_path_mtu_cache: HashMap<Ipv6Address, u32>,\n',
)

replace_once(
    'src/stack.rs',
    '            ipv6_default_hop_limit: IPV6_DEFAULT_HOP_LIMIT,\n            ipv6_path_mtu_cache: HashMap::new(),\n',
    '            ipv6_default_hop_limit: IPV6_DEFAULT_HOP_LIMIT,\n'
    '            ipv6_link_mtu: IPV6_ETHERNET_LINK_MTU,\n'
    '            ipv6_path_mtu_cache: HashMap::new(),\n',
)

replace_once(
    'src/stack.rs',
    '''    pub fn ipv6_default_hop_limit(&self) -> u8 {
        self.ipv6_default_hop_limit
    }

    /// Returns the currently learned RFC 8201 Path MTU for a destination.
''',
    '''    pub fn ipv6_default_hop_limit(&self) -> u8 {
        self.ipv6_default_hop_limit
    }

    /// Returns the current RFC 4861 LinkMTU for the Ethernet interface.
    pub fn ipv6_link_mtu(&self) -> u32 {
        self.ipv6_link_mtu
    }

    /// Returns the currently learned RFC 8201 Path MTU for a destination.
''',
)

replace_once(
    'src/stack.rs',
    '        self.ipv6_default_hop_limit = IPV6_DEFAULT_HOP_LIMIT;\n        self.pending_ndp_packets.clear();\n',
    '        self.ipv6_default_hop_limit = IPV6_DEFAULT_HOP_LIMIT;\n'
    '        self.ipv6_link_mtu = IPV6_ETHERNET_LINK_MTU;\n'
    '        self.pending_ndp_packets.clear();\n',
)

replace_once(
    'src/stack.rs',
    '''    pub fn send_ip6_packet(&mut self, dst_ip: Ipv6Address, ip6_bytes: Vec<u8>) -> Option<Vec<u8>> {
        if self
            .ipv6_path_mtu_cache
            .get(&dst_ip)
            .is_some_and(|mtu| ip6_bytes.len() > *mtu as usize)
        {
            // IPv6 routers never fragment. Until source fragmentation is modelled,
            // an RFC 8201 PMTU estimate is a hard upper bound on a source packet.
            return None;
        }
''',
    '''    pub fn send_ip6_packet(&mut self, dst_ip: Ipv6Address, ip6_bytes: Vec<u8>) -> Option<Vec<u8>> {
        let effective_mtu = self
            .ipv6_path_mtu_cache
            .get(&dst_ip)
            .copied()
            .unwrap_or(self.ipv6_link_mtu)
            .min(self.ipv6_link_mtu);
        if ip6_bytes.len() > effective_mtu as usize {
            // IPv6 source fragmentation is not modelled. Both the interface LinkMTU
            // and any smaller RFC 8201 PMTU estimate are therefore hard upper bounds.
            return None;
        }
''',
)

replace_once(
    'src/stack.rs',
    '''                                    if ra.current_hop_limit != 0 {
                                        self.ipv6_default_hop_limit = ra.current_hop_limit;
                                    }

                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may
''',
    '''                                    if ra.current_hop_limit != 0 {
                                        self.ipv6_default_hop_limit = ra.current_hop_limit;
                                    }
                                    if let Some(mtu) = ra.mtu
                                        && (1280..=IPV6_ETHERNET_LINK_MTU).contains(&mtu)
                                    {
                                        self.ipv6_link_mtu = mtu;
                                        // A packet queued while the old LinkMTU was in force must
                                        // not escape after address resolution if a later RA lowers
                                        // the interface MTU in the meantime.
                                        for queued in self.pending_ndp_packets.values_mut() {
                                            queued.retain(|packet| packet.len() <= mtu as usize);
                                        }
                                        self.pending_ndp_packets
                                            .retain(|_, queued| !queued.is_empty());
                                    }

                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may
''',
)

# --- Integration regressions ---------------------------------------------
Path('tests/test_ipv6_ra_mtu.rs').write_text(r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, RouterAdvertisement, RouterPreference, ipv6_multicast_mac,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{
    Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6, compute_ipv6_transport_checksum,
};
use toy_tcpip::stack::{IPV6_ETHERNET_LINK_MTU, NetStack, NetStackConfig};

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

fn ra_bytes(current_hop_limit: u8, mtu: Option<u32>) -> Vec<u8> {
    let router = ip6("fe80::1");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    Icmpv6Packet::build_router_advertisement_with_routes_and_mtu(
        router,
        dst,
        current_hop_limit,
        1800,
        RouterPreference::Medium,
        &[],
        &[],
        Some(mac(0x01)),
        mtu,
    )
}

fn ra_frame(current_hop_limit: u8, mtu: Option<u32>, outer_hop_limit: u8) -> Vec<u8> {
    let router = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = ra_bytes(current_hop_limit, mtu);
    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, outer_hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn mtu_option_builder_and_parser_round_trip() {
    let router = ip6("fe80::1");
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let raw = ra_bytes(64, Some(1400));
    let icmp = Icmpv6Packet::parse(router, dst, &raw, true).unwrap();
    let ra = RouterAdvertisement::parse(&icmp).unwrap();
    assert_eq!(ra.mtu, Some(1400));
}

#[test]
fn valid_ra_mtu_sets_link_mtu_and_enforces_exact_boundary() {
    let mut stack = host();
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
    assert!(stack.process_frame(&ra_frame(64, Some(1400), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    let peer = ip6("2001:db8:1::20");
    stack.ndp_table.insert(peer, mac(0x20));

    // IPv6 header (40) + ICMPv6 Echo header (8) + 1352 payload = exactly 1400.
    let exact = stack.ping6(peer, 1, 1, &vec![0x5a; 1352]).unwrap();
    let eth = EthernetFrame::parse(&exact).unwrap();
    assert_eq!(eth.payload.len(), 1400);

    // One byte larger is rejected at the source; IPv6 source fragmentation is
    // intentionally not modelled by this deterministic stack.
    assert!(stack.ping6(peer, 1, 2, &vec![0x5a; 1353]).is_none());
}

#[test]
fn ethernet_out_of_range_ra_mtu_values_are_ignored() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(64, Some(1400), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    assert!(stack.process_frame(&ra_frame(64, Some(1279), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1400);

    assert!(stack.process_frame(&ra_frame(64, Some(1501), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1400);
}

#[test]
fn absent_mtu_option_preserves_current_link_mtu() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(64, Some(1380), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1380);

    assert!(stack.process_frame(&ra_frame(64, None, 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1380);
}

#[test]
fn invalid_ra_cannot_change_link_mtu() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(64, Some(1300), 64)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
}

#[test]
fn malformed_mtu_option_is_ignored_without_discarding_other_ra_parameters() {
    let router = ip6("fe80::1");
    let router_mac = mac(0x01);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut ra = ra_bytes(37, None);

    // Type 5 with a non-zero but wrong Length=2. RFC 4861 RA validation rejects
    // zero-length options; this malformed parameter itself is ignored.
    ra.extend_from_slice(&[5, 2]);
    ra.extend_from_slice(&[0; 14]);
    ra[2..4].copy_from_slice(&[0, 0]);
    let checksum = compute_ipv6_transport_checksum(router, dst, NEXT_HEADER_ICMPV6, &ra);
    ra[2..4].copy_from_slice(&checksum.to_be_bytes());

    let packet = Ipv6Packet::serialize(router, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    let mut stack = host();
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
    assert_eq!(stack.ipv6_default_hop_limit(), 37);
}

#[test]
fn lowering_link_mtu_discards_oversized_packets_waiting_on_ndp() {
    let mut stack = host();
    let peer = ip6("2001:db8:1::30");

    // 1450-byte packet is legal under the Ethernet default but queues while NDP
    // resolves the peer.
    let ns = stack.ping6(peer, 7, 1, &vec![0x33; 1402]).unwrap();
    let ns_eth = EthernetFrame::parse(&ns).unwrap();
    assert_ne!(ns_eth.ethertype, 0);
    assert_eq!(stack.pending_ndp_packets.get(&peer).map(Vec::len), Some(1));

    assert!(stack.process_frame(&ra_frame(64, Some(1400), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1400);
    assert!(stack.pending_ndp_packets.get(&peer).is_none());
}

#[test]
fn clearing_ipv6_interface_restores_ethernet_link_mtu() {
    let mut stack = host();
    assert!(stack.process_frame(&ra_frame(64, Some(1280), 255)).is_empty());
    assert_eq!(stack.ipv6_link_mtu(), 1280);

    stack.clear_ipv6_interface();
    assert_eq!(stack.ipv6_link_mtu(), IPV6_ETHERNET_LINK_MTU);
}
''')
PY

cargo fmt --all
cargo fmt --all -- --check
cargo test --test test_ipv6_ra_mtu --verbose
cargo test --test test_ipv6_pmtud --verbose
cargo test --all-targets --verbose
cargo build --release --verbose
git diff --check

rm .github/workflows/one-shot-ra-mtu.yml scripts/one-shot-ra-mtu.sh
git add -A
git config user.name 'LeiZ'
git config user.email '52287354+Lei-TzuY@users.noreply.github.com'
git commit -m 'feat(ipv6): honor RA MTU option'
git push origin HEAD:feat/ipv6-ra-mtu-option
