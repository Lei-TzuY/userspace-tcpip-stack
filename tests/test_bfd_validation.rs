use toy_tcpip::bfd::{BFD_MIN_PACKET_LEN, BfdControlPacket, BfdError, BfdState};

#[test]
fn zero_detect_multiplier_is_rejected() {
    let mut packet =
        BfdControlPacket::build_control(BfdState::Down, 0x0102_0304, 0, 100_000).serialize();
    packet[2] = 0;

    assert_eq!(
        BfdControlPacket::parse(&packet),
        Err(BfdError::ZeroDetectMultiplier)
    );
}

#[test]
fn nonzero_detect_multiplier_at_minimum_packet_length_still_parses() {
    let mut packet =
        BfdControlPacket::build_control(BfdState::Down, 0x0102_0304, 0, 100_000).serialize();
    assert_eq!(packet.len(), BFD_MIN_PACKET_LEN);
    packet[2] = 1;

    let parsed = BfdControlPacket::parse(&packet).unwrap();
    assert_eq!(parsed.detect_mult, 1);
}
