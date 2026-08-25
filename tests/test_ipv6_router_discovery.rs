use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, PrefixInformationOption,
    ipv6_multicast_mac, link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::{LabRouter, VirtualLab};
use toy_tcpip::stack::{
    IPV6_RTR_SOLICITATION_INTERVAL_MS, Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig,
};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn host_stack(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(10, 0, 0, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
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
    if expected_src.is_unspecified() {
        assert_eq!(
            icmp.payload.len(),
            4,
            "DAD-style unspecified RS must omit SLLA"
        );
    }
}

fn router_advertisement_frame(router_mac: MacAddress, hop_limit: u8) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(src, dst, 64, 1800, &[], Some(router_mac));
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn router_discovery_retries_every_four_seconds_and_exhausts_after_three() {
    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let mut stack = host_stack(mac);

    let first = stack.start_router_discovery();
    assert_router_solicitation(&first, Ipv6Address::UNSPECIFIED);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );

    assert!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS - 1)
            .is_empty()
    );
    let second = stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS);
    assert_eq!(second.len(), 1);
    assert_router_solicitation(&second[0], Ipv6Address::UNSPECIFIED);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 2
        }
    );

    assert!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2 - 1)
            .is_empty()
    );
    let third = stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2);
    assert_eq!(third.len(), 1);
    assert_router_solicitation(&third[0], Ipv6Address::UNSPECIFIED);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Exhausted
    );
    assert!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 3)
            .is_empty()
    );
}

#[test]
fn only_a_valid_router_advertisement_cancels_pending_retries() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let mut stack = host_stack(host_mac);
    stack.start_router_discovery();

    let invalid = router_advertisement_frame(router_mac, 64);
    let responses = stack.process_frame(&invalid);
    assert!(responses.is_empty());
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );

    let retry = stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS);
    assert_eq!(retry.len(), 1);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 2
        }
    );

    let valid = router_advertisement_frame(router_mac, 255);
    let responses = stack.process_frame(&valid);
    assert!(responses.is_empty(), "RA with no PIO should not begin DAD");
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle
    );
    assert!(
        stack
            .step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2)
            .is_empty()
    );
}

#[test]
fn exhausted_router_discovery_can_be_explicitly_restarted() {
    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let mut stack = host_stack(mac);
    stack.start_router_discovery();
    stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS);
    stack.step_timers(IPV6_RTR_SOLICITATION_INTERVAL_MS * 2);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Exhausted
    );

    let frame = stack.start_router_discovery();
    assert_router_solicitation(&frame, Ipv6Address::UNSPECIFIED);
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting {
            solicitations_sent: 1
        }
    );
}

#[test]
fn virtual_lab_recovers_when_initial_router_solicitation_is_lost() {
    let mut lab = VirtualLab::new();
    lab.add_link("lan");

    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let router_ip = ip6("2001:db8:1::1");
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

    lab.links.get_mut("lan").unwrap().set_blackhole(true);
    let first = lab.host_mut("host").unwrap().stack.start_router_discovery();
    lab.send_from_host("host", first);
    lab.run_until_quiescent(10);
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, None);

    lab.links.get_mut("lan").unwrap().set_blackhole(false);
    assert_eq!(lab.advance_time(IPV6_RTR_SOLICITATION_INTERVAL_MS), 1);
    lab.run_until_quiescent(30);
    assert_eq!(
        lab.host("host")
            .unwrap()
            .stack
            .ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle,
        "the retry must receive a valid RA and stop discovery"
    );

    lab.advance_time(1_000);
    lab.run_until_quiescent(30);
    let expected = slaac_address(ip6("2001:db8:1::"), 64, host_mac).unwrap();
    assert_eq!(lab.host("host").unwrap().stack.config.ipv6, Some(expected));
}

#[test]
fn router_advertisement_codec_used_by_discovery_test_is_valid() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(ip6("2001:db8:7::"), 64, true, true, 30, 20);
    let ra = Icmpv6Packet::build_router_advertisement(src, dst, 64, 30, &[pio], Some(router_mac));
    let parsed = Icmpv6Packet::parse(src, dst, &ra, true).unwrap();
    assert_eq!(parsed.msg_type, ICMPV6_TYPE_ROUTER_ADVERT);
}
