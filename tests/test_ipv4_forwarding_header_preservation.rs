use toy_tcpip::checksum::compute_checksum;
use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EthernetFrame, MacAddress};
use toy_tcpip::ipv4::{IP_PROTO_UDP, Ipv4Address, Ipv4Packet};
use toy_tcpip::lab::LabRouter;

fn ip(a: u8, b: u8, c: u8, d: u8) -> Ipv4Address {
    Ipv4Address::new(a, b, c, d)
}

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

fn packet_with_options_and_fragment_metadata(
    src: Ipv4Address,
    dst: Ipv4Address,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    const HEADER_LEN: usize = 24;
    let total_len = HEADER_LEN + payload.len();
    let mut packet = Vec::with_capacity(total_len);
    packet.push(0x46); // Version 4, IHL 6 (one 32-bit option word).
    packet.push(0xab); // Non-default DSCP/ECN must survive forwarding.
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&0x5a5au16.to_be_bytes());
    // MF=1, DF=0, fragment offset=3. The old forwarding path rewrote this as DF=1, offset=0.
    packet.extend_from_slice(&(0x2000u16 | 0x0003).to_be_bytes());
    packet.push(ttl);
    packet.push(IP_PROTO_UDP);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src.0);
    packet.extend_from_slice(&dst.0);
    packet.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]); // NOP, NOP, NOP, EOL.
    let checksum = compute_checksum(&packet[..HEADER_LEN]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[test]
fn router_decrements_ttl_without_reserializing_ipv4_header() {
    let source = ip(192, 0, 2, 2);
    let destination = ip(198, 51, 100, 2);
    let mut router = LabRouter::new("r1");
    router.add_interface("eth0", mac(0x10), ip(192, 0, 2, 1), 24, "lan1");
    router.add_interface("eth1", mac(0x20), ip(198, 51, 100, 1), 24, "lan2");
    router
        .arp_tables
        .get_mut("eth1")
        .unwrap()
        .insert(destination.0, mac(0x22));

    let packet =
        packet_with_options_and_fragment_metadata(source, destination, 9, b"fragment-body");
    let frame = EthernetFrame::serialize(mac(0x10), mac(0x11), ETHERTYPE_IPV4, &packet);

    let out = router.process_incoming_frame("lan1", &frame);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].0, "lan2");
    let ethernet = EthernetFrame::parse(&out[0].1).unwrap();
    assert_eq!(ethernet.dst_mac, mac(0x22));

    let mut expected = packet.clone();
    expected[8] = 8;
    expected[10..12].copy_from_slice(&[0, 0]);
    let checksum = compute_checksum(&expected[..24]);
    expected[10..12].copy_from_slice(&checksum.to_be_bytes());
    assert_eq!(ethernet.payload, expected.as_slice());

    let forwarded = Ipv4Packet::parse(ethernet.payload, true).unwrap();
    assert_eq!(forwarded.header.ihl, 6);
    assert_eq!(forwarded.header.dscp_ecn, 0xab);
    assert!(!forwarded.header.dont_fragment);
    assert!(forwarded.header.more_fragments);
    assert_eq!(forwarded.header.fragment_offset, 3);
    assert_eq!(forwarded.header.identification, 0x5a5a);
    assert_eq!(forwarded.header.ttl, 8);
    assert_eq!(&ethernet.payload[20..24], &[0x01, 0x01, 0x01, 0x00]);
    assert_eq!(forwarded.payload, b"fragment-body");
}

#[test]
fn ttl_helper_refuses_to_forward_expired_datagram_without_mutating_it() {
    let mut packet = packet_with_options_and_fragment_metadata(
        ip(192, 0, 2, 2),
        ip(198, 51, 100, 2),
        1,
        b"expired",
    );
    let before = packet.clone();
    assert_eq!(Ipv4Packet::decrement_ttl_in_place(&mut packet), Ok(false));
    assert_eq!(packet, before);
}
