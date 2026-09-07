#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::fragment::IpReassemblyBuffer;
use toy_tcpip::ipv4::Ipv4Address;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }

    let src = Ipv4Address::new(data[0], data[1], data[2], data[3]);
    let dst = Ipv4Address::new(data[4], data[5], data[6], data[7]);
    let protocol = data[8];
    let identification = u16::from_be_bytes([data[9], data[10]]);
    let mut cursor = 11;
    let mut reassembly = IpReassemblyBuffer::new();

    // Decode a stream of hostile fragment records. Each record controls its
    // offset, terminal flag, and payload length independently, so libFuzzer can
    // explore gaps, conflicting overlaps, duplicate terminals, truncation, and
    // out-of-range datagram ends without first constructing valid IPv4 frames.
    while cursor + 4 <= data.len() {
        let offset = u16::from_be_bytes([data[cursor], data[cursor + 1]]) & 0x1fff;
        let more_fragments = data[cursor + 2] & 1 != 0;
        let declared_len = data[cursor + 3] as usize;
        cursor += 4;

        let available = data.len() - cursor;
        let payload_len = declared_len.min(available);
        let payload = &data[cursor..cursor + payload_len];
        cursor += payload_len;

        let _ = reassembly.add_fragment(
            src,
            dst,
            protocol,
            identification,
            offset,
            more_fragments,
            payload,
        );
    }

    // Hostile state for one key must not damage an independent reassembly key.
    // A tiny valid two-fragment datagram provides a deterministic recovery
    // oracle after every arbitrary fragment sequence above.
    let recovery_id = identification ^ 0xffff;
    assert!(
        reassembly
            .add_fragment(src, dst, protocol, recovery_id, 0, true, b"12345678")
            .is_none()
    );
    assert_eq!(
        reassembly.add_fragment(src, dst, protocol, recovery_id, 1, false, b"recover"),
        Some(b"12345678recover".to_vec())
    );
});
