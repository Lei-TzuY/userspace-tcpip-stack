#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ptp::PtpPacket;

fuzz_target!(|data: &[u8]| {
    if let Ok(packet) = PtpPacket::parse(data) {
        let encoded = packet.serialize();
        let reparsed = PtpPacket::parse(&encoded)
            .expect("serialized PTP packet must parse again");
        assert_eq!(reparsed, packet);

        if !encoded.is_empty() {
            assert!(PtpPacket::parse(&encoded[..encoded.len() - 1]).is_err());
        }

        let mut with_trailing = encoded.clone();
        with_trailing.push(0xA5);
        let reparsed_with_trailing = PtpPacket::parse(&with_trailing)
            .expect("transport bytes beyond declared PTP length must be ignored");
        assert_eq!(reparsed_with_trailing, packet);
    }
});
