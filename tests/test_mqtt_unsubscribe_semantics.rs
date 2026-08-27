use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0xa2, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn packet(payload: &[u8]) -> MqttPacket {
    MqttPacket {
        packet_type: MqttPacketType::Unsubscribe,
        flags: 0x02,
        topic: None,
        packet_id: None,
        payload: payload.to_vec(),
    }
}

#[test]
fn parser_rejects_missing_or_truncated_topic_filters() {
    for payload in [
        &[][..],
        &[0x12][..],
        &[0x12, 0x34][..],
        &[0x12, 0x34, 0x00][..],
        &[0x12, 0x34, 0x00, 0x03, b'a'][..],
    ] {
        assert_eq!(
            MqttPacket::parse(&wire(payload)),
            Err(MqttError::InvalidUnsubscribePayloadLength(payload.len()))
        );
    }
}

#[test]
fn parser_rejects_zero_packet_identifier() {
    assert_eq!(
        MqttPacket::parse(&wire(&[0, 0, 0, 1, b'a'])),
        Err(MqttError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn parser_rejects_empty_and_malformed_topic_filters() {
    assert_eq!(
        MqttPacket::parse(&wire(&[0x12, 0x34, 0, 0])),
        Err(MqttError::InvalidUnsubscribeTopicFilter)
    );
    assert_eq!(
        MqttPacket::parse(&wire(&[0x12, 0x34, 0, 1, 0xff])),
        Err(MqttError::MalformedUtf8String)
    );
}

#[test]
fn parser_consumes_multiple_topic_filters() {
    let payload = [0x12, 0x34, 0, 3, b'a', b'/', b'b', 0, 3, b'c', b'/', b'd'];
    let parsed = MqttPacket::parse(&wire(&payload)).unwrap();
    assert_eq!(parsed.packet_type, MqttPacketType::Unsubscribe);
    assert_eq!(parsed.packet_id, Some(0x1234));
    assert_eq!(parsed.topic.as_deref(), Some("a/b"));
    assert_eq!(parsed.payload, payload);
}

#[test]
fn serializer_rejects_malformed_unsubscribe_payloads() {
    assert_eq!(
        packet(&[0x12, 0x34]).try_serialize(),
        Err(MqttSerializeError::InvalidUnsubscribePayloadLength(2))
    );
    assert_eq!(
        packet(&[0, 0, 0, 1, b'a']).try_serialize(),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
    assert_eq!(
        packet(&[0x12, 0x34, 0, 0]).try_serialize(),
        Err(MqttSerializeError::InvalidUnsubscribeTopicFilter)
    );
    assert_eq!(
        packet(&[0x12, 0x34, 0, 1, 0xff]).try_serialize(),
        Err(MqttSerializeError::InvalidUnsubscribeTopicFilter)
    );
}

#[test]
fn serializer_preserves_multiple_topic_filters() {
    let payload = [0x12, 0x34, 0, 3, b'a', b'/', b'b', 0, 3, b'c', b'/', b'd'];
    assert_eq!(packet(&payload).try_serialize().unwrap(), wire(&payload));
}

#[test]
fn checked_builder_enforces_unsubscribe_semantics() {
    assert_eq!(
        MqttPacket::try_build_unsubscribe(0, "a/b"),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
    assert_eq!(
        MqttPacket::try_build_unsubscribe(1, ""),
        Err(MqttSerializeError::InvalidUnsubscribeTopicFilter)
    );

    let packet = MqttPacket::try_build_unsubscribe(0x1234, "a/b").unwrap();
    assert_eq!(packet.packet_id, Some(0x1234));
    assert_eq!(packet.topic.as_deref(), Some("a/b"));
    assert_eq!(
        packet.try_serialize().unwrap(),
        wire(&[0x12, 0x34, 0, 3, b'a', b'/', b'b'])
    );
}

#[test]
fn checked_builder_uses_utf8_byte_length() {
    let packet = MqttPacket::try_build_unsubscribe(7, "溫度").unwrap();
    let raw = packet.try_serialize().unwrap();
    assert_eq!(&raw[4..6], &[0, 6]);
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.topic.as_deref(), Some("溫度"));
}
