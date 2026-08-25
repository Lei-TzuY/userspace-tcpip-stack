use std::str::FromStr;

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn stack() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

#[test]
fn configured_ipv6_prefers_connected_prefix_over_default_gateway() {
    let mut stack = stack();
    let me = ip6("2001:db8:1::10");
    let gw = ip6("2001:db8:1::1");
    let neighbor = ip6("2001:db8:1::20");
    let remote = ip6("2001:db8:2::20");

    stack.configure_ipv6_interface(me, 64, Some(gw));

    let on_link = stack.ipv6_routing_table.lookup(neighbor).unwrap();
    assert_eq!(on_link.source, RouteSource::Connected);
    assert_eq!(on_link.gateway, None);
    assert_eq!(on_link.prefix_len, 64);

    let routed = stack.ipv6_routing_table.lookup(remote).unwrap();
    assert_eq!(routed.source, RouteSource::Static);
    assert_eq!(routed.gateway, Some(gw));
    assert_eq!(routed.prefix_len, 0);

    let local_packet = Ipv6Packet::serialize(me, neighbor, NEXT_HEADER_ICMPV6, 64, b"local");
    stack.send_ip6_packet(neighbor, local_packet).unwrap();
    assert!(stack.pending_ndp_packets.contains_key(&neighbor));
    assert!(!stack.pending_ndp_packets.contains_key(&gw));

    let remote_packet = Ipv6Packet::serialize(me, remote, NEXT_HEADER_ICMPV6, 64, b"remote");
    stack.send_ip6_packet(remote, remote_packet).unwrap();
    assert!(stack.pending_ndp_packets.contains_key(&gw));
}

#[test]
fn reconfiguration_replaces_owned_ipv6_routes_without_touching_other_static_routes() {
    let mut stack = stack();
    let old_address = ip6("2001:db8:1::10");
    let old_gateway = ip6("2001:db8:1::1");
    let new_address = ip6("2001:db8:10::10");
    let new_gateway = ip6("2001:db8:10::1");
    let preserved = ip6("2001:db8:ffff::");

    stack.configure_ipv6_interface(old_address, 64, Some(old_gateway));
    stack
        .ipv6_routing_table
        .add_route(preserved, 48, Some(old_gateway), "eth0");
    stack.configure_ipv6_interface(new_address, 48, Some(new_gateway));

    assert!(
        stack
            .ipv6_routing_table
            .find_exact(old_address, 64)
            .is_none()
    );
    let connected = stack
        .ipv6_routing_table
        .find_exact(new_address, 48)
        .unwrap();
    assert_eq!(connected.source, RouteSource::Connected);

    let default = stack
        .ipv6_routing_table
        .find_exact(Ipv6Address::UNSPECIFIED, 0)
        .unwrap();
    assert_eq!(default.gateway, Some(new_gateway));
    assert_eq!(stack.ipv6_prefix_len(), Some(48));
    assert_eq!(stack.ipv6_gateway(), Some(new_gateway));

    assert!(stack.ipv6_routing_table.find_exact(preserved, 48).is_some());
}

#[test]
fn clearing_ipv6_configuration_removes_only_owned_routes_and_pending_ndp() {
    let mut stack = stack();
    let me = ip6("2001:db8:1::10");
    let gw = ip6("2001:db8:1::1");
    let remote = ip6("2001:db8:2::20");
    let preserved = ip6("2001:db8:aaaa::");

    stack.configure_ipv6_interface(me, 64, Some(gw));
    stack
        .ipv6_routing_table
        .add_route(preserved, 48, Some(gw), "eth0");
    let packet = Ipv6Packet::serialize(me, remote, NEXT_HEADER_ICMPV6, 64, b"queued");
    stack.send_ip6_packet(remote, packet).unwrap();
    assert!(!stack.pending_ndp_packets.is_empty());

    stack.clear_ipv6_interface();

    assert_eq!(stack.config.ipv6, None);
    assert_eq!(stack.ipv6_prefix_len(), None);
    assert_eq!(stack.ipv6_gateway(), None);
    assert!(stack.pending_ndp_packets.is_empty());
    assert!(
        stack
            .ipv6_routing_table
            .routes_from(RouteSource::Connected)
            .is_empty()
    );
    assert!(
        stack
            .ipv6_routing_table
            .find_exact(Ipv6Address::UNSPECIFIED, 0)
            .is_none()
    );
    assert!(stack.ipv6_routing_table.find_exact(preserved, 48).is_some());
}
