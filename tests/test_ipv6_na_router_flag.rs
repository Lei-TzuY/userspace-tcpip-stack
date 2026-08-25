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

fn configured_stack(host_mac: MacAddress, router_mac: MacAddress) -> (NetStack, Ipv6Address) {
    let mut stack = NetStack::new(NetStackConfig {
        mac: host_mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    let prefix = ip6("2001:db8:55::");
    let router_ip = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 3_600, 1_800);
    let ra = Icmpv6Packet::build_router_advertisement(
        router_ip,
        dst,
        64,
        1_800,
        &[pio],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(router_ip, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    assert_eq!(stack.process_frame(&frame).len(), 1);
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);
    assert_eq!(stack.ipv6_gateway(), Some(router_ip));
    (stack, router_ip)
}

fn router_na(
    host_mac: MacAddress,
    host_ip: Ipv6Address,
    router_mac: MacAddress,
    router_ip: Ipv6Address,
    is_router: bool,
) -> Vec<u8> {
    let na = Icmpv6Packet::build_neighbor_advertisement(
        router_ip, host_ip, router_ip, router_mac, is_router, true, true,
    );
    let packet = Ipv6Packet::serialize(router_ip, host_ip, NEXT_HEADER_ICMPV6, 255, &na);
    EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn na_router_flag_clear_withdraws_current_default_router() {
    let host_mac = MacAddress([0x00, 0x55, 0x22, 0x33, 0x44, 0x01]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 0x55, 0x01]);
    let (mut stack, router_ip) = configured_stack(host_mac, router_mac);
    let host_ip = stack.config.ipv6.unwrap();

    assert!(
        stack
            .process_frame(&router_na(host_mac, host_ip, router_mac, router_ip, false))
            .is_empty()
    );

    assert_eq!(stack.ipv6_gateway(), None);
    assert_eq!(stack.config.ipv6, Some(host_ip));
    assert_eq!(stack.ndp_table.lookup(&router_ip), Some(router_mac));
}

#[test]
fn na_router_flag_set_preserves_current_default_router() {
    let host_mac = MacAddress([0x00, 0x56, 0x22, 0x33, 0x44, 0x01]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 0x56, 0x01]);
    let (mut stack, router_ip) = configured_stack(host_mac, router_mac);
    let host_ip = stack.config.ipv6.unwrap();

    assert!(
        stack
            .process_frame(&router_na(host_mac, host_ip, router_mac, router_ip, true))
            .is_empty()
    );

    assert_eq!(stack.ipv6_gateway(), Some(router_ip));
}
