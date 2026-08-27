from pathlib import Path
import re

ipv4_path = Path('src/ipv4.rs')
ipv4 = ipv4_path.read_text()
marker = '''    pub fn serialize(\n        src_ip: Ipv4Address,\n'''
helper = '''    /// Decrements the TTL of an already-serialized IPv4 datagram while preserving\n    /// every other header field, including options and fragmentation metadata.\n    /// Returns `Ok(false)` when the packet has no forwardable TTL remaining.\n    pub fn decrement_ttl_in_place(data: &mut [u8]) -> Result<bool, Ipv4Error> {\n        let (header_len, ttl) = {\n            let parsed = Ipv4Packet::parse(data, true)?;\n            (parsed.header.header_len_bytes(), parsed.header.ttl)\n        };\n\n        if ttl <= 1 {\n            return Ok(false);\n        }\n\n        data[8] = ttl - 1;\n        data[10..12].copy_from_slice(&[0, 0]);\n        let checksum = compute_checksum(&data[..header_len]);\n        data[10..12].copy_from_slice(&checksum.to_be_bytes());\n        Ok(true)\n    }\n\n'''
if 'pub fn decrement_ttl_in_place' not in ipv4:
    if marker not in ipv4:
        raise SystemExit('ipv4 serialize marker not found')
    ipv4 = ipv4.replace(marker, helper + marker, 1)
ipv4_path.write_text(ipv4)

lab_path = Path('src/lab.rs')
lab = lab_path.read_text()
lab = lab.replace(
    '''                        // 2. Decrement TTL and recompute checksum\n                        let new_ttl = ip_pkt.header.ttl - 1;\n\n                        // 3. Routing Table Lookup (LPM)\n''',
    '''                        // 2. Routing Table Lookup (LPM)\n''',
    1,
)
pattern = re.compile(
    r'''(?P<indent>\s*)let egress_link = egress_iface\.link_name\.clone\(\);\n'''
    r'''(?P=indent)let ip_id = ip_pkt\.header\.identification;\n'''
    r'''(?P=indent)let mut forwarded_ip_bytes = Ipv4Packet::serialize\(\n'''
    r'''(?P=indent)    ip_pkt\.header\.src_ip,\n'''
    r'''(?P=indent)    ip_pkt\.header\.dst_ip,\n'''
    r'''(?P=indent)    ip_pkt\.header\.protocol\.to_u8\(\),\n'''
    r'''(?P=indent)    ip_id,\n'''
    r'''(?P=indent)    new_ttl,\n'''
    r'''(?P=indent)    ip_pkt\.payload,\n'''
    r'''(?P=indent)\);'''
)
match = pattern.search(lab)
if not match:
    raise SystemExit('IPv4 forwarding reserialization block not found')
indent = match.group('indent')
replacement = (
    f'{indent}let egress_link = egress_iface.link_name.clone();\n'
    f'{indent}let total_length = usize::from(ip_pkt.header.total_length);\n'
    f'{indent}let mut forwarded_ip_bytes = eth.payload[..total_length].to_vec();\n'
    f'{indent}if !matches!(\n'
    f'{indent}    Ipv4Packet::decrement_ttl_in_place(&mut forwarded_ip_bytes),\n'
    f'{indent}    Ok(true)\n'
    f'{indent}) {{\n'
    f'{indent}    return out_transmissions;\n'
    f'{indent}}}'
)
lab = pattern.sub(replacement, lab, count=1)
lab_path.write_text(lab)

Path('tests/test_ipv4_forwarding_header_preservation.rs').write_text(r'''use toy_tcpip::checksum::compute_checksum;
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

    let packet = packet_with_options_and_fragment_metadata(source, destination, 9, b"fragment-body");
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
''')
