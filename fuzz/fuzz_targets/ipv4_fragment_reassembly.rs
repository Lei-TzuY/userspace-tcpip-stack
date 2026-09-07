#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::fragment::{fragment_payload, IpReassemblyBuffer};
use toy_tcpip::ipv4::{Ipv4Address, Ipv4Packet};

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }

    let src = Ipv4Address::new(data[0], data[1], data[2], data[3]);
    let dst = Ipv4Address::new(data[4], data[5], data[6], data[7]);
    let mtu_seed = u16::from_be_bytes([data[8], data[9]]) as usize;
    let mtu = 68 + (mtu_seed % (1500 - 68 + 1));
    let identification = u16::from_be_bytes([data[10], data[11]]);
    let protocol = data[12];
    let ttl = data[13];
    let flags = data[14];
    let payload = &data[15..];

    if payload.is_empty() {
        return;
    }

    let fragments = fragment_payload(src, dst, protocol, identification, ttl, mtu, payload);
    assert!(!fragments.is_empty());
    assert!(fragments.iter().all(|fragment| fragment.len() <= mtu));

    let mut order: Vec<usize> = (0..fragments.len()).collect();
    if flags & 0x01 != 0 {
        order.reverse();
    }

    // Optionally replay one exact fragment before the normal sequence. Exact
    // duplicates are legal overlap and must not corrupt the eventual payload.
    if flags & 0x02 != 0 && !order.is_empty() {
        order.insert(0, order[(flags as usize >> 2) % order.len()]);
    }

    let mut reassembly = IpReassemblyBuffer::new();
    let mut assembled = None;

    for index in order {
        let packet = Ipv4Packet::parse(&fragments[index], true)
            .expect("fragment_payload must emit checksum-valid IPv4 packets");
        assert_eq!(packet.header.src_ip, src);
        assert_eq!(packet.header.dst_ip, dst);
        assert_eq!(packet.header.protocol, protocol);
        assert_eq!(packet.header.identification, identification);

        if let Some(payload) = reassembly.add_fragment(
            packet.header.src_ip,
            packet.header.dst_ip,
            packet.header.protocol,
            packet.header.identification,
            packet.header.fragment_offset,
            packet.header.more_fragments,
            packet.payload,
        ) {
            assembled = Some(payload);
            break;
        }
    }

    assert_eq!(assembled.as_deref(), Some(payload));
});
