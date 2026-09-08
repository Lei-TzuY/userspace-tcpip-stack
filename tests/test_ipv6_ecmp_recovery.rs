use std::str::FromStr;

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_UDP};
use toy_tcpip::router::RouteSource;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

fn destination_selecting(stack: &NetStack, gateway: Ipv6Address) -> Ipv6Address {
    (1..=256)
        .map(|host| ip6(&format!("2001:db8:88::{host:x}")))
        .find(|destination| {
            stack
                .ipv6_routing_table
                .lookup(*destination)
                .and_then(|route| route.gateway)
                == Some(gateway)
        })
        .expect("ECMP hash should select every member across the sampled destinations")
}

#[test]
fn netstack_ipv6_ecmp_withdrawal_fails_over_and_recovery_reenters_forwarding() {
    let local = ip6("2001:db8:1::10");
    let prefix = ip6("2001:db8:88::");
    let gateway_a = ip6("fe80::1");
    let gateway_b = ip6("fe80::2");
    let gateway_mac_a = MacAddress([0x02, 0, 0, 0, 0, 1]);
    let gateway_mac_b = MacAddress([0x02, 0, 0, 0, 0, 2]);
    let mut stack = NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 10]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: Some(local),
        subnet_mask: 24,
        gateway: None,
    });

    stack.ipv6_routing_table.add_multipath_route_from(
        prefix,
        64,
        Some(gateway_a),
        "eth0",
        RouteSource::Static,
    );
    stack.ipv6_routing_table.add_multipath_route_from(
        prefix,
        64,
        Some(gateway_b),
        "eth0",
        RouteSource::Static,
    );
    stack.ndp_table.insert(gateway_a, gateway_mac_a);
    stack.ndp_table.insert(gateway_b, gateway_mac_b);

    let destination_a = destination_selecting(&stack, gateway_a);
    let packet = Ipv6Packet::serialize(local, destination_a, NEXT_HEADER_UDP, 64, b"before");
    let frame = stack.send_ip6_packet(destination_a, packet).unwrap();
    assert_eq!(&frame[..6], &gateway_mac_a.0);

    assert!(stack.ipv6_routing_table.remove_route_via(
        prefix,
        64,
        Some(gateway_a),
        "eth0",
        RouteSource::Static,
    ));
    let packet = Ipv6Packet::serialize(local, destination_a, NEXT_HEADER_UDP, 64, b"failover");
    let frame = stack.send_ip6_packet(destination_a, packet).unwrap();
    assert_eq!(&frame[..6], &gateway_mac_b.0);

    stack.ipv6_routing_table.add_multipath_route_from(
        prefix,
        64,
        Some(gateway_a),
        "eth0",
        RouteSource::Static,
    );
    assert_eq!(stack.ipv6_routing_table.lookup_best_routes(destination_a).len(), 2);

    let recovered_destination = destination_selecting(&stack, gateway_a);
    let packet = Ipv6Packet::serialize(
        local,
        recovered_destination,
        NEXT_HEADER_UDP,
        64,
        b"recovered",
    );
    let frame = stack
        .send_ip6_packet(recovered_destination, packet)
        .unwrap();
    assert_eq!(&frame[..6], &gateway_mac_a.0);
}
