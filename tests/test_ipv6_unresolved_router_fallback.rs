use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac, link_local_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn stack(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(
    router_mac: MacAddress,
    prefix: Ipv6Address,
    lifetime: u16,
    include_slla: bool,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 600, 300);
    let ra = Icmpv6Packet::build_router_advertisement(
        src,
        dst,
        64,
        lifetime,
        &[pio],
        include_slla.then_some(router_mac),
    );
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn nud_failure_preserves_unresolved_default_router_as_fallback() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x94]);
    let r1_mac = MacAddress([0x02, 0, 0, 0, 4, 1]);
    let r2_mac = MacAddress([0x02, 0, 0, 0, 4, 2]);
    let r1 = link_local_address(r1_mac);
    let r2 = link_local_address(r2_mac);
    let prefix = ip6("2001:db8:94::");
    let mut s = stack(host_mac);

    // R1 is learned with an SLLA, while R2 is retained in the Default Router
    // List without a Neighbor Cache entry. The unresolved fallback must not be
    // mistaken for a failed NUD neighbor.
    s.process_frame(&ra_frame(r1_mac, prefix, 30, true));
    s.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    s.process_frame(&ra_frame(r2_mac, prefix, 30, false));
    assert_eq!(s.ipv6_gateway(), Some(r1));
    assert_eq!(s.ndp_table.lookup(&r2), None);

    assert!(
        s.ping6(ip6("2001:db8:ffff::4"), 0x9400, 1, b"nud")
            .is_some()
    );
    assert_eq!(s.step_timers(6_000).len(), 1);
    assert_eq!(s.step_timers(7_000).len(), 1);
    assert_eq!(s.step_timers(8_000).len(), 1);

    let frames = s.step_timers(9_000);
    assert!(frames.is_empty());
    assert_eq!(s.ipv6_gateway(), Some(r2));
    assert_eq!(s.ndp_table.lookup(&r2), None);
}
