use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, PrefixInformationOption,
    RouterAdvertisement, ipv6_multicast_mac, link_local_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, a, b])
}

fn host() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: mac(1, 2),
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(
    router_mac: MacAddress,
    source: Ipv6Address,
    hop_limit: u8,
    prefix: PrefixInformationOption,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(
        source,
        dst,
        64,
        1800,
        &[prefix],
        Some(router_mac),
    );
    let ip = Ipv6Packet::serialize(source, dst, NEXT_HEADER_ICMPV6, hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &ip,
    )
}

#[test]
fn invalid_ra_is_rejected_before_host_neighbor_cache_learning() {
    let router_mac = mac(9, 1);
    let router = link_local_address(router_mac);
    let prefix = PrefixInformationOption::new(ip6("2001:db8:44::"), 64, true, true, 3600, 1800);
    let mut stack = host();
    let _ = stack.start_router_discovery();

    let offlink = ra_frame(router_mac, router, 64, prefix);
    assert!(stack.process_frame(&offlink).is_empty());
    assert_eq!(stack.ndp_table.lookup(&router), None);
    assert!(matches!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting { .. }
    ));
    assert_eq!(stack.config.ipv6, None);

    let global_source = ip6("2001:db8::1");
    let wrong_source = ra_frame(router_mac, global_source, 255, prefix);
    assert!(stack.process_frame(&wrong_source).is_empty());
    assert_eq!(stack.ndp_table.lookup(&global_source), None);
    assert!(matches!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting { .. }
    ));
}

#[test]
fn valid_ra_still_learns_router_and_enters_slaac_dad() {
    let router_mac = mac(9, 2);
    let router = link_local_address(router_mac);
    let prefix = PrefixInformationOption::new(ip6("2001:db8:45::"), 64, true, true, 3600, 1800);
    let mut stack = host();
    let _ = stack.start_router_discovery();

    let valid = ra_frame(router_mac, router, 255, prefix);
    let out = stack.process_frame(&valid);
    assert_eq!(out.len(), 1, "a valid autonomous PIO should start DAD");
    assert_eq!(stack.ndp_table.lookup(&router), Some(router_mac));
    assert_eq!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Idle
    );
}

#[test]
fn lab_router_rejects_invalid_rs_before_cache_learning_and_reply() {
    let router_mac = mac(1, 1);
    let host_mac = mac(2, 2);
    let router_ip = ip6("2001:db8:1::1");
    let host_ll = link_local_address(host_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));

    let rs = Icmpv6Packet::build_router_solicitation(host_ll, dst, Some(host_mac));
    let bad_ip = Ipv6Packet::serialize(host_ll, dst, NEXT_HEADER_ICMPV6, 64, &rs);
    let bad_frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &bad_ip,
    );
    assert!(router.process_incoming_frame("lan", &bad_frame).is_empty());
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&host_ll),
        None
    );

    let good_ip = Ipv6Packet::serialize(host_ll, dst, NEXT_HEADER_ICMPV6, 255, &rs);
    let good_frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &good_ip,
    );
    assert_eq!(router.process_incoming_frame("lan", &good_frame).len(), 1);
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&host_ll),
        Some(host_mac)
    );
}

#[test]
fn router_discovery_semantic_validators_reject_malformed_messages() {
    let mut rs_payload = vec![0u8; 4];
    rs_payload.extend_from_slice(&[1, 0]); // SLLA with illegal zero length
    let rs = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &rs_payload,
    };
    assert!(!rs.is_valid_router_solicitation(ip6("fe80::2"), 255));

    let unspecified_with_slla = [0, 0, 0, 0, 1, 1, 0x02, 0, 0, 0, 1, 2];
    let rs = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &unspecified_with_slla,
    };
    assert!(!rs.is_valid_router_solicitation(Ipv6Address::UNSPECIFIED, 255));
    assert!(rs.is_valid_router_solicitation(ip6("fe80::2"), 255));
    assert!(!rs.is_valid_router_solicitation(ip6("fe80::2"), 64));

    let ra_payload = [0u8; 12];
    let bad_code = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
        code: 1,
        checksum: 0,
        payload: &ra_payload,
    };
    assert!(
        bad_code
            .validated_router_advertisement(ip6("fe80::1"), 255)
            .is_none()
    );

    let mut malformed_ra_payload = vec![0u8; 12];
    malformed_ra_payload.extend_from_slice(&[1, 0]);
    let malformed_ra = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
        code: 0,
        checksum: 0,
        payload: &malformed_ra_payload,
    };
    assert!(
        malformed_ra
            .validated_router_advertisement(ip6("fe80::1"), 255)
            .is_none()
    );
    assert!(
        malformed_ra
            .validated_router_advertisement(ip6("2001:db8::1"), 255)
            .is_none()
    );
}

#[test]
fn pio_with_preferred_lifetime_above_valid_is_ignored_not_clamped() {
    let mut payload = vec![0u8; 12];
    payload.extend_from_slice(&[3, 4, 64, 0xc0, 0, 0, 0, 10, 0, 0, 0, 20, 0, 0, 0, 0]);
    payload.extend_from_slice(&ip6("2001:db8:46::").0);
    let ra = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };
    let parsed = RouterAdvertisement::parse(&ra).expect("RA framing itself remains valid");
    assert!(
        parsed.prefixes.is_empty(),
        "RFC 4862 requires ignoring this PIO"
    );
}

#[test]
fn host_silently_discards_router_solicitations_before_cache_learning() {
    let mut stack = host();
    let peer_mac = mac(7, 7);
    let peer = link_local_address(peer_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(peer, dst, Some(peer_mac));
    let ip = Ipv6Packet::serialize(peer, dst, NEXT_HEADER_ICMPV6, 255, &rs);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        peer_mac,
        ETHERTYPE_IPV6,
        &ip,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer), None);
}

#[test]
fn lab_router_does_not_learn_remote_routed_source_from_ordinary_ipv6_data() {
    let router_mac = mac(3, 1);
    let upstream_mac = mac(3, 9);
    let router_ip = ip6("2001:db8:10::1");
    let remote = ip6("2001:db8:ffff::9");
    let mut router = LabRouter::new("r-data");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));

    let echo = Icmpv6Packet::build_echo_request(remote, router_ip, 0x600d, 9, b"routed-source");
    let packet = Ipv6Packet::serialize(remote, router_ip, NEXT_HEADER_ICMPV6, 63, &echo);
    let frame = EthernetFrame::serialize(router_mac, upstream_mac, ETHERTYPE_IPV6, &packet);
    let replies = router.process_incoming_frame("lan", &frame);

    assert_eq!(replies.len(), 1, "ordinary IPv6 delivery must still work");
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&remote),
        None,
        "a routed IPv6 source must not become a directly attached neighbor"
    );
    assert_eq!(
        EthernetFrame::parse(&replies[0].1).unwrap().dst_mac,
        upstream_mac
    );
}
