use std::str::FromStr;

use toy_tcpip::bgp::Ipv4Prefix;
use toy_tcpip::bgp_ipv6::{Ipv6Path, Ipv6Prefix};
use toy_tcpip::bgp_rib::PathSource;
use toy_tcpip::bgp_router::BgpRouter;
use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_UDP};
use toy_tcpip::router::RouteSource;
use toy_tcpip::router_ipv6::Ipv6RoutingTable;
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn ip6(s: &str) -> Ipv6Address {
    Ipv6Address::from_str(s).unwrap()
}

#[test]
fn netstack_ipv6_send_uses_route_next_hop_for_ndp() {
    let local = ip6("2001:db8:1::10");
    let gateway = ip6("fe80::1");
    let destination = ip6("2001:db8:99::7");
    let gateway_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
    let mut stack = NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 10]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: Some(local),
        subnet_mask: 24,
        gateway: None,
    });
    stack
        .ipv6_routing_table
        .add_route(ip6("2001:db8:99::"), 48, Some(gateway), "eth0");
    stack.ndp_table.insert(gateway, gateway_mac);

    let packet = Ipv6Packet::serialize(local, destination, NEXT_HEADER_UDP, 64, b"payload");
    let frame = stack.send_ip6_packet(destination, packet).unwrap();
    assert_eq!(&frame[..6], &gateway_mac.0);
    assert!(stack.pending_ndp_packets.is_empty());
}

#[test]
fn netstack_ipv6_no_route_preserves_direct_on_link_behavior() {
    let local = ip6("2001:db8:1::10");
    let destination = ip6("2001:db8:1::20");
    let destination_mac = MacAddress([0x02, 0, 0, 0, 0, 20]);
    let mut stack = NetStack::new(NetStackConfig {
        mac: MacAddress([0x02, 0, 0, 0, 0, 10]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: Some(local),
        subnet_mask: 24,
        gateway: None,
    });
    stack.ndp_table.insert(destination, destination_mac);

    let packet = Ipv6Packet::serialize(local, destination, NEXT_HEADER_UDP, 64, b"payload");
    let frame = stack.send_ip6_packet(destination, packet).unwrap();
    assert_eq!(&frame[..6], &destination_mac.0);
}

#[test]
fn bgp_ipv6_fib_waits_for_recursive_next_hop_then_installs_and_withdraws() {
    let mut bgp = BgpRouter::new(65000, Ipv4Address::new(1, 1, 1, 1));
    let prefix = Ipv6Prefix::new(ip6("2001:db8:100::"), 48);
    let next_hop = ip6("2001:db8:12::2");
    let mut path = Ipv6Path::local(prefix, next_hop, Ipv4Address::new(2, 2, 2, 2));
    path.source = PathSource::Ebgp;
    path.peer_addr = Ipv4Address::new(10, 12, 0, 2);
    path.peer_as = 65100;
    bgp.ipv6_loc_rib.insert(path);

    let mut fib = Ipv6RoutingTable::new();
    bgp.sync_ipv6_fib(100, &mut fib);
    assert_eq!(bgp.ipv6_unresolved_prefixes(), vec![prefix]);
    assert!(fib.routes_from(RouteSource::Bgp).is_empty());

    fib.add_route_from(
        ip6("2001:db8:12::"),
        64,
        None,
        "eth1",
        RouteSource::Connected,
    );
    bgp.sync_ipv6_fib(200, &mut fib);
    assert!(bgp.ipv6_unresolved_prefixes().is_empty());
    assert_eq!(bgp.ipv6_installed_prefixes(), vec![prefix]);
    let installed = fib.find_exact(prefix.address, prefix.length).unwrap();
    assert_eq!(installed.gateway, Some(next_hop));
    assert_eq!(installed.interface, "eth1");

    bgp.ipv6_loc_rib.remove(&prefix);
    bgp.sync_ipv6_fib(300, &mut fib);
    assert!(fib.routes_from(RouteSource::Bgp).is_empty());
    assert!(bgp.ipv6_installed_prefixes().is_empty());

    // Keep the IPv4 type in scope so the test also guards that the new API did not
    // replace or alias the existing IPv4 route model.
    let _ = Ipv4Prefix::new(Ipv4Address::new(10, 0, 0, 0), 8);
}
