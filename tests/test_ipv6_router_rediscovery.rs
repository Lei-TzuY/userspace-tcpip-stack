use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, PrefixInformationOption, ipv6_multicast_mac,
    link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::{LabRouter, VirtualLab};
use toy_tcpip::stack::{
    IPV6_DAD_RETRANS_TIMER_MS, Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig,
};

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
    router_lifetime: u16,
    preferred_lifetime: u32,
    valid_lifetime: u32,
) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio =
        PrefixInformationOption::new(prefix, 64, true, true, valid_lifetime, preferred_lifetime);
    let ra = Icmpv6Packet::build_router_advertisement(
        src,
        dst,
        64,
        router_lifetime,
        &[pio],
        Some(router_mac),
    );
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn configure_short_lived_router(
    stack: &mut NetStack,
    router_mac: MacAddress,
    prefix: Ipv6Address,
) -> Ipv6Address {
    let expected = slaac_address(prefix, 64, stack.config.mac).unwrap();
    let frames = stack.process_frame(&ra_frame(router_mac, prefix, 2, 30, 40));
    assert_eq!(frames.len(), 1, "initial RA must start DAD");
    assert!(stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS).is_empty());
    assert_eq!(stack.config.ipv6, Some(expected));
    assert_eq!(stack.ipv6_gateway(), Some(link_local_address(router_mac)));
    expected
}

fn assert_router_solicitation(frame: &[u8], expected_src: Ipv6Address) {
    let eth = EthernetFrame::parse(frame).unwrap();
    assert_eq!(eth.ethertype, toy_tcpip::ethernet::EtherType::IPv6);
    assert_eq!(
        eth.dst_mac,
        ipv6_multicast_mac(Ipv6Address::LINK_LOCAL_ALL_ROUTERS).unwrap()
    );
    let packet = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(packet.header.src_ip, expected_src);
    assert_eq!(packet.header.dst_ip, Ipv6Address::LINK_LOCAL_ALL_ROUTERS);
    assert_eq!(packet.header.hop_limit, 255);
    let icmp = Icmpv6Packet::parse(
        packet.header.src_ip,
        packet.header.dst_ip,
        packet.payload,
        true,
    )
    .unwrap();
    assert_eq!(icmp.msg_type, ICMPV6_TYPE_ROUTER_SOLICIT);
    assert!(
        icmp.payload.len() > 4,
        "an already configured host should include its source link-layer option"
    );
}

#[test]
fn default_router_expiry_immediately_starts_rediscovery_and_keeps_address() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:11::");
    let mut stack = stack(host_mac);
    let address = configure_short_lived_router(&mut stack, router_mac, prefix);

    assert!(stack.step_timers(1_999).is_empty());
    assert!(stack.ipv6_gateway().is_some());

    let frames = stack.step_timers(2_000);
    assert_eq!(
        frames.len(),
        1,
        "router expiry must immediately solicit a replacement"
    );
    assert_router_solicitation(&frames[0], address);
    assert_eq!(stack.ipv6_gateway(), None);
    assert_eq!(stack.config.ipv6, Some(address));
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );
}

#[test]
fn router_expiry_does_not_restart_an_already_active_discovery_cycle() {
    let host_mac = MacAddress([0x00, 0x21, 0x22, 0x23, 0x24, 0x25]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 2, 1]);
    let prefix = ip6("2001:db8:12::");
    let mut stack = stack(host_mac);
    configure_short_lived_router(&mut stack, router_mac, prefix);

    stack.step_timers(1_500);
    let _manual_first = stack.start_router_discovery();
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );

    let frames = stack.step_timers(2_000);
    assert!(
        frames.is_empty(),
        "router expiry must not duplicate an already active discovery cycle"
    );
    assert_eq!(stack.ipv6_gateway(), None);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );
}

#[test]
fn virtual_lab_router_expiry_rediscovery_restores_default_route_end_to_end() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan");

    let host_mac = MacAddress([0x00, 0x31, 0x32, 0x33, 0x34, 0x35]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 3, 1]);
    let router_ip = ip6("2001:db8:13::1");
    let prefix = router_ip.mask(64);
    let router_ll = link_local_address(router_mac);

    lab.add_host(
        "host",
        "lan",
        NetStackConfig {
            mac: host_mac,
            ip: Ipv4Address::new(10, 0, 0, 2),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        },
    );
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));
    lab.add_router(router);

    // Seed a deliberately short-lived default router. Feed the RA directly to the
    // host, then put its DAD probe onto the virtual link so the rest of the setup is
    // exercised by the real LabRouter data plane.
    let initial = lab
        .host_mut("host")
        .unwrap()
        .stack
        .process_frame(&ra_frame(router_mac, prefix, 2, 30, 40));
    assert_eq!(initial.len(), 1);
    for frame in initial {
        lab.send_from_host("host", frame);
    }
    lab.run_until_quiescent(30);
    lab.advance_time(IPV6_DAD_RETRANS_TIMER_MS);
    lab.run_until_quiescent(30);

    let address = slaac_address(prefix, 64, host_mac).unwrap();
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, Some(address));
    assert_eq!(
        lab.host("host").unwrap().stack.ipv6_gateway(),
        Some(router_ll)
    );

    // At t=2s the original default-router lifetime expires. advance_time pumps the
    // host timer, emits its new RS onto the link, and the LabRouter answers with its
    // normal long-lived RA. run_until_quiescent delivers that RA back to the host.
    assert_eq!(lab.advance_time(1_000), 1);
    assert_eq!(lab.host("host").unwrap().stack.ipv6_gateway(), None);
    assert_eq!(
        lab.host("host")
            .unwrap()
            .stack
            .ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );
    lab.run_until_quiescent(30);

    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, Some(address));
    assert_eq!(
        lab.host("host").unwrap().stack.ipv6_gateway(),
        Some(router_ll)
    );
    assert_eq!(
        lab.host("host")
            .unwrap()
            .stack
            .ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle
    );
}
