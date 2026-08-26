use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{ICMPV6_TYPE_REDIRECT, Icmpv6Packet, NdpTable, link_local_address};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn host_stack(mac: MacAddress, address: Ipv6Address, router: Ipv6Address) -> NetStack {
    let mut stack = NetStack::new(NetStackConfig {
        mac,
        ip: Ipv4Address::new(10, 0, 0, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    stack.configure_ipv6_interface(address, 64, Some(router));
    stack
}

fn redirect_frame(
    router_mac: MacAddress,
    router: Ipv6Address,
    host_mac: MacAddress,
    host: Ipv6Address,
    target: Ipv6Address,
    destination: Ipv6Address,
    target_mac: Option<MacAddress>,
    quote: &[u8],
) -> Vec<u8> {
    let redirect =
        Icmpv6Packet::build_redirect(router, host, target, destination, target_mac, quote);
    let packet = Ipv6Packet::serialize(router, host, NEXT_HEADER_ICMPV6, 255, &redirect);
    EthernetFrame::serialize(host_mac, router_mac, ETHERTYPE_IPV6, &packet)
}

#[test]
fn redirect_codec_validates_target_and_quoted_ipv6_header() {
    let router = ip6("fe80::1");
    let host = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:99::9");
    let destination_mac = MacAddress([0x02, 0, 0, 0, 9, 9]);
    let echo = Icmpv6Packet::build_echo_request(host, destination, 7, 1, b"redirect-quote");
    let quoted = Ipv6Packet::serialize(host, destination, NEXT_HEADER_ICMPV6, 64, &echo);

    let raw = Icmpv6Packet::build_redirect(
        router,
        host,
        destination,
        destination,
        Some(destination_mac),
        &quoted,
    );
    let parsed = Icmpv6Packet::parse(router, host, &raw, true).unwrap();
    assert_eq!(parsed.msg_type, ICMPV6_TYPE_REDIRECT);
    let redirect = parsed.validated_redirect(router, host, 255).unwrap();
    assert_eq!(redirect.target, destination);
    assert_eq!(redirect.destination, destination);
    assert_eq!(redirect.target_link_layer_address, Some(destination_mac));
    assert_eq!(redirect.redirected_source, Some(host));
    assert_eq!(redirect.redirected_destination, Some(destination));
    assert!(parsed.validated_redirect(router, host, 64).is_none());

    // A non-destination Redirect target must be a link-local router.
    let invalid_target = ip6("2001:db8:1234::1");
    let raw =
        Icmpv6Packet::build_redirect(router, host, invalid_target, destination, None, &quoted);
    let parsed = Icmpv6Packet::parse(router, host, &raw, true).unwrap();
    assert!(parsed.validated_redirect(router, host, 255).is_none());
}

#[test]
fn valid_redirect_changes_only_that_destinations_next_hop() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let better_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let host = ip6("2001:db8:1::2");
    let router = ip6("fe80::1");
    let better = ip6("fe80::2");
    let destination = ip6("2001:db8:99::9");
    let other_destination = ip6("2001:db8:88::8");
    let mut stack = host_stack(host_mac, host, router);
    stack.ndp_table.insert(router, router_mac);
    stack.ndp_table.insert(better, better_mac);

    let first = stack.ping6(destination, 0x137, 1, b"before").unwrap();
    let first_eth = EthernetFrame::parse(&first).unwrap();
    assert_eq!(first_eth.dst_mac, router_mac);
    let quote = first_eth.payload.to_vec();

    let redirect = redirect_frame(
        router_mac,
        router,
        host_mac,
        host,
        better,
        destination,
        Some(better_mac),
        &quote,
    );
    assert!(stack.process_frame(&redirect).is_empty());
    assert_eq!(stack.ipv6_redirect_next_hop(destination), Some(better));

    let second = stack.ping6(destination, 0x137, 2, b"after").unwrap();
    assert_eq!(EthernetFrame::parse(&second).unwrap().dst_mac, better_mac);

    // Redirects are per-destination, not a replacement for the Default Router List.
    let other = stack
        .ping6(other_destination, 0x137, 3, b"unrelated")
        .unwrap();
    assert_eq!(EthernetFrame::parse(&other).unwrap().dst_mac, router_mac);
}

#[test]
fn forged_redirect_from_non_first_hop_is_ignored() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let rogue_mac = MacAddress([0x02, 0, 0, 0, 3, 3]);
    let target_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let host = ip6("2001:db8:1::2");
    let router = ip6("fe80::1");
    let rogue = ip6("fe80::3");
    let target = ip6("fe80::2");
    let destination = ip6("2001:db8:99::9");
    let mut stack = host_stack(host_mac, host, router);
    stack.ndp_table.insert(router, router_mac);
    stack.ndp_table.insert(target, target_mac);

    let first = stack.ping6(destination, 0x137, 1, b"quote").unwrap();
    let quote = EthernetFrame::parse(&first).unwrap().payload.to_vec();
    let forged = redirect_frame(
        rogue_mac,
        rogue,
        host_mac,
        host,
        target,
        destination,
        Some(target_mac),
        &quote,
    );
    stack.process_frame(&forged);

    assert_eq!(stack.ipv6_redirect_next_hop(destination), None);
    let next = stack.ping6(destination, 0x137, 2, b"still-router").unwrap();
    assert_eq!(EthernetFrame::parse(&next).unwrap().dst_mac, router_mac);
}

#[test]
fn redirect_can_mark_an_off_prefix_destination_as_directly_on_link() {
    let host_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x77]);
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let destination_mac = MacAddress([0x02, 0, 0, 0, 9, 9]);
    let host = ip6("2001:db8:1::2");
    let router = ip6("fe80::1");
    let destination = ip6("2001:db8:99::9");
    let mut stack = host_stack(host_mac, host, router);
    stack.ndp_table.insert(router, router_mac);

    let first = stack.ping6(destination, 0x137, 1, b"quote").unwrap();
    let quote = EthernetFrame::parse(&first).unwrap().payload.to_vec();
    let redirect = redirect_frame(
        router_mac,
        router,
        host_mac,
        host,
        destination,
        destination,
        Some(destination_mac),
        &quote,
    );
    stack.process_frame(&redirect);

    assert_eq!(stack.ipv6_redirect_next_hop(destination), Some(destination));
    let next = stack.ping6(destination, 0x137, 2, b"direct").unwrap();
    assert_eq!(
        EthernetFrame::parse(&next).unwrap().dst_mac,
        destination_mac
    );
}

#[test]
fn router_emits_redirect_when_forwarding_back_out_the_ingress_link() {
    let router_mac = MacAddress([0x02, 0, 0, 0, 1, 1]);
    let source_mac = MacAddress([0x02, 0, 0, 0, 2, 2]);
    let destination_mac = MacAddress([0x02, 0, 0, 0, 3, 3]);
    let router_address = ip6("2001:db8:1::1");
    let source = ip6("2001:db8:1::2");
    let destination = ip6("2001:db8:1::3");

    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", router_mac, Ipv4Address::new(10, 0, 0, 1), 24, "lan");
    assert!(router.set_interface_ipv6("eth0", router_address, 64));
    router
        .ndp_tables
        .entry("eth0".to_string())
        .or_insert_with(NdpTable::new)
        .insert(destination, destination_mac);

    let echo = Icmpv6Packet::build_echo_request(source, destination, 9, 1, b"same-link");
    let packet = Ipv6Packet::serialize(source, destination, NEXT_HEADER_ICMPV6, 64, &echo);
    let frame = EthernetFrame::serialize(router_mac, source_mac, ETHERTYPE_IPV6, &packet);
    let output = router.process_incoming_frame("lan", &frame);
    assert_eq!(output.len(), 2, "Redirect plus forwarded original packet");

    let mut saw_redirect = false;
    let mut saw_forward = false;
    for (link, raw) in output {
        assert_eq!(link, "lan");
        let eth = EthernetFrame::parse(&raw).unwrap();
        let ip = Ipv6Packet::parse(eth.payload).unwrap();
        if ip.header.next_header == NEXT_HEADER_ICMPV6
            && ip.payload.first() == Some(&ICMPV6_TYPE_REDIRECT)
        {
            saw_redirect = true;
            assert_eq!(eth.dst_mac, source_mac);
            assert_eq!(ip.header.src_ip, link_local_address(router_mac));
            assert_eq!(ip.header.dst_ip, source);
            assert_eq!(ip.header.hop_limit, 255);
            let icmp =
                Icmpv6Packet::parse(ip.header.src_ip, ip.header.dst_ip, ip.payload, true).unwrap();
            let redirect = icmp
                .validated_redirect(ip.header.src_ip, ip.header.dst_ip, ip.header.hop_limit)
                .unwrap();
            assert_eq!(redirect.target, destination);
            assert_eq!(redirect.destination, destination);
            assert_eq!(redirect.target_link_layer_address, Some(destination_mac));
            assert_eq!(redirect.redirected_source, Some(source));
            assert_eq!(redirect.redirected_destination, Some(destination));
        } else {
            saw_forward = true;
            assert_eq!(eth.dst_mac, destination_mac);
            assert_eq!(ip.header.src_ip, source);
            assert_eq!(ip.header.dst_ip, destination);
            assert_eq!(ip.header.hop_limit, 63);
        }
    }
    assert!(saw_redirect && saw_forward);
}
