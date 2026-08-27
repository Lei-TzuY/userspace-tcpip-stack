use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType};

fn wire(packet_type: MqttPacketType, flags: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![
        ((packet_type as u8) << 4) | (flags & 0x0f),
        payload.len() as u8,
    ];
    raw.extend_from_slice(payload);
    raw
}

#[test]
fn publish_requires_topic_length_field() {
    let raw = wire(MqttPacketType::Publish, 0, &[0]);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn publish_rejects_topic_length_overrun() {
    let raw = wire(MqttPacketType::Publish, 0, &[0, 3, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn publish_rejects_invalid_utf8_topic() {
    let raw = wire(MqttPacketType::Publish, 0, &[0, 1, 0xff]);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::MalformedUtf8String));
}

#[test]
fn qos_publish_requires_packet_identifier() {
    let raw = wire(MqttPacketType::Publish, 0x02, &[0, 1, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn qos_publish_extracts_packet_identifier() {
    let raw = wire(
        MqttPacketType::Publish,
        0x02,
        &[0, 1, b'a', 0x12, 0x34, b'x'],
    );
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.topic.as_deref(), Some("a"));
    assert_eq!(parsed.packet_id, Some(0x1234));
}

#[test]
fn subscribe_requires_first_topic_qos_byte() {
    let raw = wire(MqttPacketType::Subscribe, 0x02, &[0x12, 0x34, 0, 1, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn subscribe_rejects_invalid_utf8_topic() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, 0xff, 0],
    );
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::MalformedUtf8String));
}

#[test]
fn valid_subscribe_still_extracts_required_fields() {
    let raw = MqttPacket::build_subscribe(0x4567, "sensor/temp", 1).serialize();
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.packet_id, Some(0x4567));
    assert_eq!(parsed.topic.as_deref(), Some("sensor/temp"));
}
