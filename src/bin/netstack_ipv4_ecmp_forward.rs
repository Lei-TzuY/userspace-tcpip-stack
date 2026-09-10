use std::cmp::Ordering;

use toy_tcpip::arp::ArpPacket;
use toy_tcpip::ethernet::{EthernetFrame, MacAddress, ETHERTYPE_ARP, ETHERTYPE_IPV4};
use toy_tcpip::ipv4::{IpProtocol, Ipv4Address, Ipv4Packet};
use toy_tcpip::router::{Ipv4FlowKey, RouteEntry};
use toy_tcpip::stack::NetStack;

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a_extend(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(FNV_PRIME);
    }
    hash
}

fn route_score(flow_hash: u64, route: &RouteEntry) -> u64 {
    let mut hash = fnv1a_extend(FNV_OFFSET_BASIS, &flow_hash.to_be_bytes());
    hash = fnv1a_extend(
        hash,
        &route
            .destination
            .mask(route.prefix_len)
            .to_u32()
            .to_be_bytes(),
    );
    hash = fnv1a_extend(hash, &[route.prefix_len]);
    match route.gateway {
        Some(gateway) => {
            hash = fnv1a_extend(hash, &[1]);
            hash = fnv1a_extend(hash, &gateway.to_u32().to_be_bytes());
        }
        None => hash = fnv1a_extend(hash, &[0]),
    }
    hash = fnv1a_extend(hash, route.interface.as_bytes());
    fnv1a_extend(hash, route.source.as_str().as_bytes())
}

fn route_identity_cmp(left: &RouteEntry, right: &RouteEntry) -> Ordering {
    left.destination
        .to_u32()
        .cmp(&right.destination.to_u32())
        .then(left.prefix_len.cmp(&right.prefix_len))
        .then(
            left.gateway
                .map(|gateway| gateway.to_u32())
                .cmp(&right.gateway.map(|gateway| gateway.to_u32())),
        )
        .then(left.interface.cmp(&right.interface))
        .then(left.source.as_str().cmp(right.source.as_str()))
}

fn transport_ports(packet: &Ipv4Packet<'_>) -> (u16, u16) {
    if packet.header.fragment_offset != 0 {
        return (0, 0);
    }
    match packet.header.protocol {
        IpProtocol::Tcp | IpProtocol::Udp if packet.payload.len() >= 4 => (
            u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
            u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
        ),
        _ => (0, 0),
    }
}

fn flow_key(packet: &Ipv4Packet<'_>) -> Ipv4FlowKey {
    let (source_port, destination_port) = transport_ports(packet);
    Ipv4FlowKey::new(
        packet.header.src_ip,
        packet.header.dst_ip,
        packet.header.protocol.to_u8(),
        source_port,
        destination_port,
    )
}

fn resilient_route<'a>(stack: &'a NetStack, packet: &Ipv4Packet<'_>) -> Option<&'a RouteEntry> {
    let flow_hash = flow_key(packet).stable_hash();
    stack
        .routing_table
        .lookup_best_routes(packet.header.dst_ip)
        .into_iter()
        .max_by(|left, right| {
            route_score(flow_hash, left)
                .cmp(&route_score(flow_hash, right))
                .then_with(|| route_identity_cmp(left, right))
        })
}

fn send_resilient_ipv4(stack: &mut NetStack, ip_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let packet = Ipv4Packet::parse(&ip_bytes, true).map_err(|error| error.to_string())?;
    let next_hop = resilient_route(stack, &packet)
        .map(|route| route.next_hop(packet.header.dst_ip))
        .unwrap_or(packet.header.dst_ip);

    if let Some(dst_mac) = stack.arp_table.lookup(&next_hop.0) {
        return Ok(EthernetFrame::serialize(
            dst_mac,
            stack.config.mac,
            ETHERTYPE_IPV4,
            &ip_bytes,
        ));
    }

    stack
        .pending_arp_packets
        .entry(next_hop)
        .or_default()
        .push(ip_bytes);
    let request = ArpPacket::build_request(stack.config.mac, stack.config.ip.0, next_hop.0);
    Ok(EthernetFrame::serialize(
        MacAddress::BROADCAST,
        stack.config.mac,
        ETHERTYPE_ARP,
        &request.serialize(),
    ))
}

fn main() {
    eprintln!(
        "netstack_ipv4_ecmp_forward is an executable integration probe; run its tests to validate resilient NetStack-backed forwarding"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use toy_tcpip::router::RouteSource;
    use toy_tcpip::stack::NetStackConfig;

    fn stack() -> NetStack {
        let mut stack = NetStack::new(NetStackConfig {
            mac: MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            ip: Ipv4Address::new(192, 0, 2, 10),
            ipv6: None,
            subnet_mask: 24,
            gateway: None,
        });
        for (octet, interface) in [(1, "wan-a"), (2, "wan-b"), (3, "wan-c")] {
            let gateway = Ipv4Address::new(192, 0, 2, octet);
            stack.routing_table.add_multipath_route_from(
                Ipv4Address::new(203, 0, 113, 0),
                24,
                Some(gateway),
                interface,
                RouteSource::Static,
            );
            stack
                .arp_table
                .insert(gateway.0, MacAddress::new([0x02, 0, 0, 0, 1, octet]));
        }
        stack
    }

    fn packet(source_port: u16) -> Vec<u8> {
        let payload = [
            source_port.to_be_bytes()[0],
            source_port.to_be_bytes()[1],
            0x01,
            0xbb,
            0,
            8,
            0,
            0,
        ];
        Ipv4Packet::serialize(
            Ipv4Address::new(198, 51, 100, 9),
            Ipv4Address::new(203, 0, 113, 7),
            toy_tcpip::ipv4::IP_PROTO_UDP,
            7,
            64,
            &payload,
        )
    }

    #[test]
    fn surviving_flow_keeps_next_hop_after_unrelated_member_withdrawal() {
        let mut stack = stack();
        let packet = packet(40_000);
        let parsed = Ipv4Packet::parse(&packet, true).unwrap();
        let selected = resilient_route(&stack, &parsed).unwrap().clone();
        let selected_gateway = selected.gateway.unwrap();

        let withdrawn = [
            Ipv4Address::new(192, 0, 2, 1),
            Ipv4Address::new(192, 0, 2, 2),
            Ipv4Address::new(192, 0, 2, 3),
        ]
        .into_iter()
        .find(|gateway| *gateway != selected_gateway)
        .unwrap();

        assert!(stack.routing_table.remove_route_via(
            Ipv4Address::new(203, 0, 113, 0),
            24,
            Some(withdrawn),
            match withdrawn.0[3] {
                1 => "wan-a",
                2 => "wan-b",
                _ => "wan-c",
            },
            RouteSource::Static,
        ));

        let reparsed = Ipv4Packet::parse(&packet, true).unwrap();
        assert_eq!(
            resilient_route(&stack, &reparsed).unwrap().gateway,
            Some(selected_gateway)
        );

        let frame = send_resilient_ipv4(&mut stack, packet).unwrap();
        let ethernet = EthernetFrame::parse(&frame).unwrap();
        assert_eq!(ethernet.ethertype, ETHERTYPE_IPV4);
    }

    #[test]
    fn invalid_ipv4_checksum_fails_closed_before_arp_or_l2_state_changes() {
        let mut stack = stack();
        let mut packet = packet(40_001);
        packet[10] ^= 0xff;
        let pending_before = stack.pending_arp_packets.len();

        assert!(send_resilient_ipv4(&mut stack, packet).is_err());
        assert_eq!(stack.pending_arp_packets.len(), pending_before);
    }
}
