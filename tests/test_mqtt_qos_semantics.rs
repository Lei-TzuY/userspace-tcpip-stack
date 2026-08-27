use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

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
fn publish_builder_rejects_reserved_qos() {
    assert_eq!(
        MqttPacket::try_build_publish("a", b"x", 3, Some(1)),
        Err(MqttSerializeError::InvalidQos(3))
    );
}

#[test]
fn publish_builder_requires_identifier_for_qos_one_and_two() {
    for qos in [1, 2] {
        assert_eq!(
            MqttPacket::try_build_publish("a", b"x", qos, None),
            Err(MqttSerializeError::MissingPacketIdentifier)
        );
    }
}

#[test]
fn publish_builder_rejects_identifier_for_qos_zero() {
    assert_eq!(
        MqttPacket::try_build_publish("a", b"x", 0, Some(7)),
        Err(MqttSerializeError::UnexpectedPacketIdentifier)
    );
}

#[test]
fn publish_builder_rejects_zero_identifier() {
    assert_eq!(
        MqttPacket::try_build_publish("a", b"x", 1, Some(0)),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn qos_one_publish_roundtrips_identifier() {
    let raw = MqttPacket::try_build_publish("a", b"x", 1, Some(0x1234))
        .unwrap()
        .serialize();
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.packet_id, Some(0x1234));
    assert_eq!((parsed.flags >> 1) & 0x03, 1);
}

#[test]
fn publish_parser_rejects_reserved_qos() {
    let raw = wire(MqttPacketType::Publish, 0x06, &[0, 1, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::InvalidQos(3)));
}

#[test]
fn publish_parser_rejects_zero_identifier() {
    let raw = wire(MqttPacketType::Publish, 0x02, &[0, 1, b'a', 0, 0]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn subscribe_builder_rejects_invalid_qos_and_zero_identifier() {
    assert_eq!(
        MqttPacket::try_build_subscribe(1, "a", 3),
        Err(MqttSerializeError::InvalidQos(3))
    );
    assert_eq!(
        MqttPacket::try_build_subscribe(0, "a", 1),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn subscribe_parser_rejects_invalid_first_requested_qos() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, b'a', 3],
    );
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::InvalidQos(3)));
}

#[test]
fn subscribe_parser_rejects_invalid_later_requested_qos() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, b'a', 0, 0, 1, b'b', 3],
    );
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::InvalidQos(3)));
}

#[test]
fn subscribe_parser_rejects_zero_identifier() {
    let raw = wire(MqttPacketType::Subscribe, 0x02, &[0, 0, 0, 1, b'a', 0]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn valid_multi_topic_subscribe_preserves_first_required_fields() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, b'a', 0, 0, 1, b'b', 2],
    );
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.packet_id, Some(0x1234));
    assert_eq!(parsed.topic.as_deref(), Some("a"));
}
