use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x90, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn packet(payload: &[u8]) -> MqttPacket {
    MqttPacket {
        packet_type: MqttPacketType::Suback,
        flags: 0,
        topic: None,
        packet_id: None,
        payload: payload.to_vec(),
    }
}

#[test]
fn parser_rejects_suback_without_return_code() {
    for payload in [&[][..], &[0x12][..], &[0x12, 0x34][..]] {
        assert_eq!(
            MqttPacket::parse(&wire(payload)),
            Err(MqttError::InvalidSubackPayloadLength(payload.len()))
        );
    }
}

#[test]
fn parser_rejects_zero_suback_packet_identifier() {
    assert_eq!(
        MqttPacket::parse(&wire(&[0, 0, 0])),
        Err(MqttError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn parser_rejects_reserved_suback_return_codes() {
    for code in [0x03, 0x7f, 0x81, 0xff] {
        assert_eq!(
            MqttPacket::parse(&wire(&[0x12, 0x34, code])),
            Err(MqttError::InvalidSubackReturnCode(code))
        );
    }
}

#[test]
fn parser_accepts_all_defined_suback_return_codes() {
    let payload = [0x12, 0x34, 0x00, 0x01, 0x02, 0x80];
    let parsed = MqttPacket::parse(&wire(&payload)).unwrap();
    assert_eq!(parsed.packet_type, MqttPacketType::Suback);
    assert_eq!(parsed.packet_id, Some(0x1234));
    assert_eq!(parsed.payload, payload);
}

#[test]
fn serializer_rejects_suback_without_return_code() {
    for payload in [&[][..], &[0x12][..], &[0x12, 0x34][..]] {
        assert_eq!(
            packet(payload).try_serialize(),
            Err(MqttSerializeError::InvalidSubackPayloadLength(
                payload.len()
            ))
        );
    }
}

#[test]
fn serializer_rejects_zero_suback_packet_identifier() {
    assert_eq!(
        packet(&[0, 0, 0]).try_serialize(),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
}

#[test]
fn serializer_rejects_reserved_suback_return_codes() {
    for code in [0x03, 0x7f, 0x81, 0xff] {
        assert_eq!(
            packet(&[0x12, 0x34, code]).try_serialize(),
            Err(MqttSerializeError::InvalidSubackReturnCode(code))
        );
    }
}

#[test]
fn checked_suback_builder_enforces_semantics() {
    assert_eq!(
        MqttPacket::try_build_suback(0, &[0]),
        Err(MqttSerializeError::InvalidPacketIdentifier(0))
    );
    assert_eq!(
        MqttPacket::try_build_suback(1, &[]),
        Err(MqttSerializeError::InvalidSubackPayloadLength(2))
    );
    assert_eq!(
        MqttPacket::try_build_suback(1, &[0x03]),
        Err(MqttSerializeError::InvalidSubackReturnCode(0x03))
    );

    let packet = MqttPacket::try_build_suback(0x1234, &[0x00, 0x01, 0x02, 0x80]).unwrap();
    assert_eq!(packet.packet_id, Some(0x1234));
    assert_eq!(
        packet.try_serialize().unwrap(),
        wire(&[0x12, 0x34, 0x00, 0x01, 0x02, 0x80])
    );
}
