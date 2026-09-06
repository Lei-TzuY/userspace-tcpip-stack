#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv4::{Ipv4Error, Ipv4Packet, IPV4_MIN_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    let checksum_checked = Ipv4Packet::parse(data, true);

    if let Ok(packet) = Ipv4Packet::parse(data, false) {
        let header_len = packet.header.header_len_bytes();
        let total_len = packet.header.total_length as usize;

        assert!(header_len >= IPV4_MIN_HEADER_LEN);
        assert!(total_len >= header_len);
        assert!(total_len <= data.len());
        assert_eq!(packet.payload.len(), total_len - header_len);

        // Parsing exactly the declared IPv4 frame must preserve the packet and
        // must not depend on any transport bytes trailing the declared length.
        let frame = &data[..total_len];
        let reparsed = Ipv4Packet::parse(frame, false).expect("declared IPv4 frame must reparse");
        assert_eq!(reparsed, packet);

        // Once a packet parsed successfully, removing any byte from a non-empty
        // declared payload must make the declared total length exceed the input.
        if total_len > header_len {
            let truncated = &data[..total_len - 1];
            assert!(matches!(
                Ipv4Packet::parse(truncated, false),
                Err(Ipv4Error::TotalLengthMismatch { .. })
            ));
        }
    }

    if let Ok(packet) = checksum_checked {
        let total_len = packet.header.total_length as usize;
        let frame = &data[..total_len];
        let reparsed = Ipv4Packet::parse(frame, true)
            .expect("checksum-valid declared IPv4 frame must reparse");
        assert_eq!(reparsed, packet);
    }
});
