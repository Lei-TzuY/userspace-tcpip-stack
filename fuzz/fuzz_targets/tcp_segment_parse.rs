#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tcp::{TcpSegment, TCP_MIN_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    let src_ip = Ipv4Address::new(192, 0, 2, 1);
    let dst_ip = Ipv4Address::new(198, 51, 100, 1);

    let _ = TcpSegment::parse(src_ip, dst_ip, data, true);

    if let Ok(segment) = TcpSegment::parse(src_ip, dst_ip, data, false) {
        let encoded = TcpSegment::serialize(
            src_ip,
            dst_ip,
            segment.src_port,
            segment.dst_port,
            segment.seq_num,
            segment.ack_num,
            segment.flags,
            segment.window_size,
            segment.payload,
        );

        let reparsed = TcpSegment::parse(src_ip, dst_ip, &encoded, true)
            .expect("serialized TCP segment must parse with checksum verification");
        assert_eq!(reparsed.src_port, segment.src_port);
        assert_eq!(reparsed.dst_port, segment.dst_port);
        assert_eq!(reparsed.seq_num, segment.seq_num);
        assert_eq!(reparsed.ack_num, segment.ack_num);
        assert_eq!(reparsed.flags, segment.flags);
        assert_eq!(reparsed.window_size, segment.window_size);
        assert_eq!(reparsed.payload, segment.payload);
        assert_eq!(reparsed.data_offset, (TCP_MIN_HEADER_LEN / 4) as u8);

        if encoded.len() > TCP_MIN_HEADER_LEN {
            let truncated = &encoded[..encoded.len() - 1];
            let truncated_parsed = TcpSegment::parse(src_ip, dst_ip, truncated, false)
                .expect("TCP has no payload length field; truncating payload remains a valid segment");
            assert_eq!(truncated_parsed.payload.len() + 1, reparsed.payload.len());
        }
    }
});
