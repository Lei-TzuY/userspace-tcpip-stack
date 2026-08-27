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

fn invalid_flags(packet_type: MqttPacketType, flags: u8) -> MqttError {
    MqttError::InvalidFixedHeaderFlags { packet_type, flags }
}

#[test]
fn parser_rejects_reserved_connect_flags() {
    let raw = wire(MqttPacketType::Connect, 0x01, &[]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(invalid_flags(MqttPacketType::Connect, 1))
    );
}

#[test]
fn parser_requires_subscribe_flags_two() {
    let payload = [0x12, 0x34, 0, 1, b'a', 0];
    let raw = wire(MqttPacketType::Subscribe, 0, &payload);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(invalid_flags(MqttPacketType::Subscribe, 0))
    );
}

#[test]
fn parser_requires_unsubscribe_flags_two() {
    let raw = wire(MqttPacketType::Unsubscribe, 0, &[]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(invalid_flags(MqttPacketType::Unsubscribe, 0))
    );
}

#[test]
fn parser_rejects_reserved_pingreq_flags() {
    let raw = wire(MqttPacketType::Pingreq, 0x08, &[]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(invalid_flags(MqttPacketType::Pingreq, 8))
    );
}

#[test]
fn parser_accepts_valid_fixed_flags() {
    assert!(MqttPacket::parse(&wire(MqttPacketType::Pingreq, 0, &[])).is_ok());
    let unsubscribe_payload = [0x12, 0x34, 0, 1, b'a'];
    assert!(
        MqttPacket::parse(&wire(MqttPacketType::Unsubscribe, 2, &unsubscribe_payload,)).is_ok()
    );
}

#[test]
fn publish_dynamic_flags_remain_valid() {
    let raw = wire(MqttPacketType::Publish, 0x0b, &[0, 1, b'a', 0, 1, b'x']);
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.flags, 0x0b);
    assert_eq!(parsed.packet_id, Some(1));
}

#[test]
fn serializer_rejects_invalid_fixed_flags() {
    let packet = MqttPacket {
        packet_type: MqttPacketType::Pingreq,
        flags: 1,
        topic: None,
        packet_id: None,
        payload: vec![],
    };
    assert_eq!(
        packet.try_serialize(),
        Err(MqttSerializeError::InvalidFixedHeaderFlags {
            packet_type: MqttPacketType::Pingreq,
            flags: 1,
        })
    );
}

#[test]
fn serializer_rejects_unrepresentable_flag_bits() {
    let packet = MqttPacket {
        packet_type: MqttPacketType::Publish,
        flags: 0x10,
        topic: None,
        packet_id: None,
        payload: vec![],
    };
    assert_eq!(
        packet.try_serialize(),
        Err(MqttSerializeError::InvalidFixedHeaderFlags {
            packet_type: MqttPacketType::Publish,
            flags: 0x10,
        })
    );
}

#[test]
fn serializer_rejects_manual_publish_qos_three() {
    let packet = MqttPacket {
        packet_type: MqttPacketType::Publish,
        flags: 0x06,
        topic: Some("a".to_string()),
        packet_id: Some(1),
        payload: vec![0, 1, b'a', 0, 1],
    };
    assert_eq!(
        packet.try_serialize(),
        Err(MqttSerializeError::InvalidQos(3))
    );
}
