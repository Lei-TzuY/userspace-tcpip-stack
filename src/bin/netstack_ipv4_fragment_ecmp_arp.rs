use toy_tcpip::arp::ArpPacket;
use toy_tcpip::checksum::compute_checksum;
use toy_tcpip::ethernet::{ETHERTYPE_ARP, EtherType, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::{IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use toy_tcpip::router::{Ipv4FlowKey, RouteSource};
use toy_tcpip::stack::{NetStack, NetStackConfig};

fn fragment_packet(
    src: Ipv4Address,
    dst: Ipv4Address,
    identification: u16,
    fragment_offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Ipv4Packet::serialize(src, dst, IP_PROTO_UDP, identification, 64, payload);
    let flags_and_offset = (if more_fragments { 0x2000 } else { 0 }) | (fragment_offset & 0x1fff);
    packet[6..8].copy_from_slice(&flags_and_offset.to_be_bytes());
    packet[10] = 0;
    packet[11] = 0;
    let checksum = compute_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet
}

fn fixture() -> NetStack {
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
    stack
}

fn run_fragment_arp_cycle() -> Result<(), String> {
    let mut stack = fixture();
    let src = Ipv4Address::new(198, 51, 100, 9);
    let dst = Ipv4Address::new(203, 0, 113, 7);
    let identification = 0x4242;

    // The first fragment begins with bytes that look like UDP ports. Production
    // routing must ignore them because later fragments do not carry those ports.
    let first_payload = [0x9c, 0x40, 0x01, 0xbb, 0, 24, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
    let later_payload = [9, 10, 11, 12, 13, 14, 15, 16];
    let first = fragment_packet(src, dst, identification, 0, true, &first_payload);
    let later = fragment_packet(src, dst, identification, 2, false, &later_payload);

    let flow = Ipv4FlowKey::new(src, dst, IP_PROTO_UDP, 0, 0);
    let next_hop = stack
        .routing_table
        .lookup_resilient_route_for_flow(flow)
        .map(|route| route.next_hop(dst))
        .ok_or_else(|| "missing resilient ECMP route".to_string())?;

    for fragment in [&first, &later] {
        let arp_request = stack
            .send_ip_packet(dst, fragment.clone())
            .ok_or_else(|| "fragment transmission produced no frame".to_string())?;
        let ethernet = EthernetFrame::parse(&arp_request).map_err(|error| error.to_string())?;
        if ethernet.ethertype != EtherType::Arp {
            return Err("unresolved fragmented flow did not trigger ARP".into());
        }
        let request = ArpPacket::parse(ethernet.payload).map_err(|error| error.to_string())?;
        if request.target_ip != next_hop.0 {
            return Err("fragment selected a different ECMP next hop".into());
        }
    }

    let queued = stack
        .pending_arp_packets
        .get(&next_hop)
        .ok_or_else(|| "fragmented flow was not queued behind ECMP next hop".to_string())?;
    if queued.as_slice() != [first.clone(), later.clone()] {
        return Err("fragment queue lost datagram order or affinity".into());
    }
    if stack.pending_arp_packets.len() != 1 {
        return Err("fragments escaped into multiple unresolved-ARP queues".into());
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
        return Err("ARP reply did not drain fragmented-flow queue".into());
    }
    let forwarded: Vec<Vec<u8>> = drained
        .iter()
        .filter_map(|frame| EthernetFrame::parse(frame).ok())
        .filter(|frame| frame.ethertype == EtherType::IPv4)
        .map(|frame| {
            if frame.dst_mac != gateway_mac {
                return Err("drained fragment used wrong ECMP gateway MAC".to_string());
            }
            Ok(frame.payload.to_vec())
        })
        .collect::<Result<_, _>>()?;
    if forwarded != [first, later] {
        return Err("ARP resolution did not flush both fragments in queue order".into());
    }

    Ok(())
}

fn main() {
    if let Err(error) = run_fragment_arp_cycle() {
        eprintln!("IPv4 fragment ECMP/ARP affinity interop failed: {error}");
        std::process::exit(1);
    }
    println!("IPv4 fragment ECMP/ARP affinity interop: ok");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_share_ecmp_next_hop_and_arp_queue() {
        run_fragment_arp_cycle().unwrap();
    }
}
