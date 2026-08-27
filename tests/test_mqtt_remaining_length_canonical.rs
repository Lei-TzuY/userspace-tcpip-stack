use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType};

fn connect_with_remaining_length(encoded: &[u8], payload_len: usize) -> Vec<u8> {
    let mut raw = vec![(MqttPacketType::Connect as u8) << 4];
    raw.extend_from_slice(encoded);
    raw.resize(raw.len() + payload_len, 0);
    raw
}

#[test]
fn rejects_overlong_zero() {
    let raw = [(MqttPacketType::Pingreq as u8) << 4, 0x80, 0x00];
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}

#[test]
fn rejects_overlong_127() {
    let raw = connect_with_remaining_length(&[0xff, 0x00], 127);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}

#[test]
fn rejects_overlong_128() {
    let raw = connect_with_remaining_length(&[0x80, 0x81, 0x00], 128);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}

#[test]
fn rejects_overlong_16383() {
    let raw = connect_with_remaining_length(&[0xff, 0xff, 0x00], 16_383);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}

#[test]
fn rejects_overlong_16384() {
    let raw = connect_with_remaining_length(&[0x80, 0x80, 0x81, 0x00], 16_384);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}

#[test]
fn accepts_canonical_zero() {
    let raw = [(MqttPacketType::Pingreq as u8) << 4, 0x00];
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.packet_type, MqttPacketType::Pingreq);
    assert!(parsed.payload.is_empty());
}

#[test]
fn accepts_canonical_127() {
    let raw = connect_with_remaining_length(&[0x7f], 127);
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.payload.len(), 127);
}

#[test]
fn accepts_canonical_128() {
    let raw = connect_with_remaining_length(&[0x80, 0x01], 128);
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.payload.len(), 128);
}

#[test]
fn four_continuation_bytes_remain_invalid() {
    let raw = [(MqttPacketType::Connect as u8) << 4, 0x80, 0x80, 0x80, 0x80];
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidRemainingLength)
    );
}
