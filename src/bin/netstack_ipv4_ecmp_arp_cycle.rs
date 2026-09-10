use std::cmp::Ordering;

use toy_tcpip::arp::ArpPacket;
use toy_tcpip::ethernet::{ETHERTYPE_ARP, ETHERTYPE_IPV4, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::{IpProtocol, Ipv4Address, Ipv4Packet};
use toy_tcpip::router::{Ipv4FlowKey, RouteEntry, RouteSource};
use toy_tcpip::stack::{NetStack, NetStackConfig};

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

fn flow_key(packet: &Ipv4Packet<'_>) -> Ipv4FlowKey {
    let (source_port, destination_port) = if packet.header.fragment_offset == 0
        && matches!(packet.header.protocol, IpProtocol::Tcp | IpProtocol::Udp)
        && packet.payload.len() >= 4
    {
        (
            u16::from_be_bytes([packet.payload[0], packet.payload[1]]),
            u16::from_be_bytes([packet.payload[2], packet.payload[3]]),
        )
    } else {
        (0, 0)
    };
    Ipv4FlowKey::new(
        packet.header.src_ip,
        packet.header.dst_ip,
        packet.header.protocol.to_u8(),
        source_port,
        destination_port,
    )
}

fn resilient_next_hop(stack: &NetStack, packet: &Ipv4Packet<'_>) -> Ipv4Address {
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
        .map(|route| route.next_hop(packet.header.dst_ip))
        .unwrap_or(packet.header.dst_ip)
}

fn send_resilient(stack: &mut NetStack, ip_bytes: Vec<u8>) -> Result<Vec<u8>, String> {
    let packet = Ipv4Packet::parse(&ip_bytes, true).map_err(|error| error.to_string())?;
    let next_hop = resilient_next_hop(stack, &packet);
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

fn fixture() -> (NetStack, Vec<u8>) {
    let mut stack = NetStack::new(NetStackConfig {
        mac: MacAddress::new([0x02, 0, 0, 0, 0, 1]),
        ip: Ipv4Address::new(192, 0, 2, 10),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    });
    for (octet, interface) in [(1, "wan-a"), (2, "wan-b"), (3, "wan-c")] {
        stack.routing_table.add_multipath_route_from(
            Ipv4Address::new(203, 0, 113, 0),
            24,
            Some(Ipv4Address::new(192, 0, 2, octet)),
            interface,
            RouteSource::Static,
        );
    }
    let udp = [0x9c, 0x40, 0x01, 0xbb, 0, 8, 0, 0];
    let packet = Ipv4Packet::serialize(
        Ipv4Address::new(198, 51, 100, 9),
        Ipv4Address::new(203, 0, 113, 7),
        toy_tcpip::ipv4::IP_PROTO_UDP,
        7,
        64,
        &udp,
    );
    (stack, packet)
}

fn run_cycle() -> Result<(), String> {
    let (mut stack, packet) = fixture();
    let parsed = Ipv4Packet::parse(&packet, true).map_err(|error| error.to_string())?;
    let next_hop = resilient_next_hop(&stack, &parsed);
    let arp_request = send_resilient(&mut stack, packet.clone())?;
    let ethernet = EthernetFrame::parse(&arp_request).map_err(|error| error.to_string())?;
    if ethernet.ethertype != EtherType::Arp {
        return Err("unresolved ECMP gateway did not trigger ARP".into());
    }
    if stack.pending_arp_packets.get(&next_hop).map(Vec::len) != Some(1) {
        return Err("IPv4 packet was not queued behind the selected ECMP gateway".into());
    }

    let gateway_mac = MacAddress::new([0x02, 0, 0, 0, 2, next_hop.0[3]]);
    let reply = ArpPacket::build_reply(
        gateway_mac,
        next_hop.0,
        stack.config.mac,
        stack.config.ip.0,
    );
    let reply_frame = EthernetFrame::serialize(
        stack.config.mac,
        gateway_mac,
        ETHERTYPE_ARP,
        &reply.serialize(),
    );
    let drained = stack.process_frame(&reply_frame);
    if stack.pending_arp_packets.contains_key(&next_hop) {
        return Err("ARP reply did not drain the ECMP pending queue".into());
    }
    let forwarded = drained
        .iter()
        .find_map(|frame| EthernetFrame::parse(frame).ok())
        .filter(|frame| frame.ethertype == EtherType::IPv4)
        .ok_or_else(|| "ARP resolution did not emit the queued IPv4 frame".to_string())?;
    if forwarded.dst_mac != gateway_mac || forwarded.payload != packet.as_slice() {
        return Err("drained IPv4 frame did not preserve selected gateway/payload".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run_cycle() {
        eprintln!("resilient ECMP ARP-cycle interop failed: {error}");
        std::process::exit(1);
    }
    println!("resilient ECMP ARP-cycle interop: ok");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_ecmp_gateway_queues_then_drains_on_arp_reply() {
        run_cycle().unwrap();
    }

    #[test]
    fn invalid_checksum_does_not_mutate_pending_arp_state() {
        let (mut stack, mut packet) = fixture();
        packet[10] ^= 0xff;
        assert!(send_resilient(&mut stack, packet).is_err());
        assert!(stack.pending_arp_packets.is_empty());
    }
}
