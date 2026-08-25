use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT, Icmpv6Packet,
    PrefixInformationOption, ipv6_multicast_mac, link_local_address, slaac_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{IPV6_DAD_RETRANS_TIMER_MS, Ipv6DadStatus, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn host(mac: MacAddress) -> NetStack {
    NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(router_mac: MacAddress, prefix: Ipv6Address) -> Vec<u8> {
    let src = link_local_address(router_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let pio = PrefixInformationOption::new(prefix, 64, true, true, 3600, 1800);
    let ra = Icmpv6Packet::build_router_advertisement(src, dst, 64, 1800, &[pio], Some(router_mac));
    let packet = Ipv6Packet::serialize(src, dst, NEXT_HEADER_ICMPV6, 255, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

#[test]
fn slaac_address_stays_tentative_until_dad_timer_expires() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:1::");
    let expected = slaac_address(prefix, 64, host_mac).unwrap();
    let mut stack = host(host_mac);

    let responses = stack.process_frame(&ra_frame(router_mac, prefix));
    assert_eq!(
        responses.len(),
        1,
        "RA should trigger exactly one DAD probe"
    );
    assert_eq!(
        stack.config.ipv6, None,
        "tentative address must not be usable"
    );
    assert_eq!(stack.ipv6_dad_status(), Ipv6DadStatus::Tentative(expected));
    assert!(
        stack
            .ipv6_routing_table
            .routes_from(RouteSource::Connected)
            .is_empty()
    );

    let eth = EthernetFrame::parse(&responses[0]).unwrap();
    assert_eq!(eth.ethertype, EtherType::IPv6);
    let expected_dst = expected.solicited_node_multicast();
    assert_eq!(eth.dst_mac, ipv6_multicast_mac(expected_dst).unwrap());
    let packet = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(packet.header.src_ip, Ipv6Address::UNSPECIFIED);
    assert_eq!(packet.header.dst_ip, expected_dst);
    assert_eq!(packet.header.hop_limit, 255);
    let ns = Icmpv6Packet::parse(
        packet.header.src_ip,
        packet.header.dst_ip,
        packet.payload,
        true,
    )
    .unwrap();
    assert_eq!(ns.msg_type, ICMPV6_TYPE_NEIGHBOR_SOLICIT);
    assert_eq!(
        ns.payload.len(),
        20,
        "DAD NS must not carry a source L2 option"
    );
    assert_eq!(stack.ndp_table.lookup(&Ipv6Address::UNSPECIFIED), None);

    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS - 1);
    assert_eq!(stack.config.ipv6, None);
    stack.step_timers(IPV6_DAD_RETRANS_TIMER_MS);

    assert_eq!(stack.config.ipv6, Some(expected));
    assert_eq!(stack.ipv6_dad_status(), Ipv6DadStatus::Idle);
    assert_eq!(stack.ipv6_prefix_len(), Some(64));
    assert_eq!(stack.ipv6_gateway(), Some(link_local_address(router_mac)));
    assert_eq!(
        stack
            .ipv6_routing_table
            .lookup(ip6("2001:db8:1::beef"))
            .unwrap()
            .source,
        RouteSource::Ra
    );
}

#[test]
fn existing_address_holder_answers_dad_probe_and_claimant_rejects_duplicate() {
    let claimant_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let holder_mac = MacAddress([0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:7::");
    let candidate = slaac_address(prefix, 64, claimant_mac).unwrap();

    let mut claimant = host(claimant_mac);
    let dad_probe = claimant
        .process_frame(&ra_frame(router_mac, prefix))
        .remove(0);
    assert_eq!(
        claimant.ipv6_dad_status(),
        Ipv6DadStatus::Tentative(candidate)
    );

    let mut holder = host(holder_mac);
    holder.configure_ipv6_interface(candidate, 64, None);
    let holder_responses = holder.process_frame(&dad_probe);
    assert_eq!(holder.ndp_table.lookup(&Ipv6Address::UNSPECIFIED), None);
    assert_eq!(
        holder_responses.len(),
        1,
        "configured holder must defend its address"
    );

    let eth = EthernetFrame::parse(&holder_responses[0]).unwrap();
    assert_eq!(
        eth.dst_mac,
        ipv6_multicast_mac(Ipv6Address::LINK_LOCAL_ALL_NODES).unwrap()
    );
    let ip = Ipv6Packet::parse(eth.payload).unwrap();
    assert_eq!(ip.header.src_ip, candidate);
    assert_eq!(ip.header.dst_ip, Ipv6Address::LINK_LOCAL_ALL_NODES);
    assert_eq!(ip.header.hop_limit, 255);
    let na = Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
    assert_eq!(na.msg_type, ICMPV6_TYPE_NEIGHBOR_ADVERT);

    claimant.process_frame(&holder_responses[0]);
    assert_eq!(
        claimant.ipv6_dad_status(),
        Ipv6DadStatus::Duplicate(candidate)
    );
    claimant.step_timers(IPV6_DAD_RETRANS_TIMER_MS * 2);
    assert_eq!(claimant.config.ipv6, None);
    assert!(
        claimant
            .ipv6_routing_table
            .routes_from(RouteSource::Connected)
            .is_empty()
    );
}

#[test]
fn competing_dad_neighbor_solicitation_marks_tentative_address_duplicate() {
    let claimant_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let other_mac = MacAddress([0x00, 0x66, 0x77, 0x88, 0x99, 0xaa]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let prefix = ip6("2001:db8:8::");
    let candidate = slaac_address(prefix, 64, claimant_mac).unwrap();
    let mut claimant = host(claimant_mac);
    claimant.process_frame(&ra_frame(router_mac, prefix));

    let dst = candidate.solicited_node_multicast();
    let ns = Icmpv6Packet::build_dad_neighbor_solicitation(dst, candidate);
    let packet = Ipv6Packet::serialize(Ipv6Address::UNSPECIFIED, dst, NEXT_HEADER_ICMPV6, 255, &ns);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        other_mac,
        ETHERTYPE_IPV6,
        &packet,
    );
    claimant.process_frame(&frame);

    assert_eq!(
        claimant.ipv6_dad_status(),
        Ipv6DadStatus::Duplicate(candidate)
    );
    claimant.step_timers(IPV6_DAD_RETRANS_TIMER_MS * 2);
    assert_eq!(claimant.config.ipv6, None);
}
