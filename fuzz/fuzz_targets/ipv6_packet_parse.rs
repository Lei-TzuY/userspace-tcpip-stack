#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv6::{Ipv6Error, Ipv6Packet, IPV6_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = Ipv6Packet::parse(data) else {
        return;
    };

    let declared_len = packet.header.payload_length as usize;
    assert_eq!(packet.payload.len(), declared_len);
    assert!(data.len() >= IPV6_HEADER_LEN + declared_len);

    // Bytes after the IPv6-declared frame are not part of the parsed payload.
    assert_eq!(packet.payload, &data[IPV6_HEADER_LEN..IPV6_HEADER_LEN + declared_len]);

    // A successfully parsed non-empty declared payload must fail closed when
    // the declared frame is truncated by one byte.
    if declared_len > 0 {
        let truncated_len = IPV6_HEADER_LEN + declared_len - 1;
        let truncated = &data[..truncated_len];
        assert!(matches!(
            Ipv6Packet::parse(truncated),
            Err(Ipv6Error::PayloadLengthMismatch { .. })
        ));
    }
});
