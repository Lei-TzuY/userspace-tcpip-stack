use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(acknowledge_flags: u8, return_code: u8) -> [u8; 4] {
    [0x20, 0x02, acknowledge_flags, return_code]
}

fn packet(acknowledge_flags: u8, return_code: u8) -> MqttPacket {
    MqttPacket {
        packet_type: MqttPacketType::Connack,
        flags: 0,
        topic: None,
        packet_id: None,
        payload: vec![acknowledge_flags, return_code],
    }
}

#[test]
fn parser_rejects_reserved_connack_acknowledge_flags() {
    for flags in [0x02, 0x80, 0xff] {
        assert_eq!(
            MqttPacket::parse(&wire(flags, 0)),
            Err(MqttError::InvalidConnackAcknowledgeFlags(flags))
        );
    }
}

#[test]
fn parser_rejects_reserved_connack_return_codes() {
    for code in [6, 7, 255] {
        assert_eq!(
            MqttPacket::parse(&wire(0, code)),
            Err(MqttError::InvalidConnackReturnCode(code))
        );
    }
}

#[test]
fn parser_rejects_session_present_on_failed_connection() {
    for code in 1..=5 {
        assert_eq!(
            MqttPacket::parse(&wire(1, code)),
            Err(MqttError::InvalidConnackSessionPresent { return_code: code })
        );
    }
}

#[test]
fn parser_accepts_valid_connack_combinations() {
    for (flags, code) in [(0, 0), (1, 0), (0, 1), (0, 5)] {
        let parsed = MqttPacket::parse(&wire(flags, code)).unwrap();
        assert_eq!(parsed.payload, vec![flags, code]);
    }
}

#[test]
fn serializer_rejects_invalid_connack_semantics() {
    assert_eq!(
        packet(0x02, 0).try_serialize(),
        Err(MqttSerializeError::InvalidConnackAcknowledgeFlags(0x02))
    );
    assert_eq!(
        packet(0, 6).try_serialize(),
        Err(MqttSerializeError::InvalidConnackReturnCode(6))
    );
    assert_eq!(
        packet(1, 1).try_serialize(),
        Err(MqttSerializeError::InvalidConnackSessionPresent { return_code: 1 })
    );
}

#[test]
fn serializer_preserves_valid_connack_combinations() {
    for (flags, code) in [(0, 0), (1, 0), (0, 5)] {
        assert_eq!(
            packet(flags, code).try_serialize().unwrap(),
            wire(flags, code)
        );
    }
}

#[test]
fn checked_connack_builder_rejects_reserved_return_codes() {
    for code in [6, 255] {
        assert_eq!(
            MqttPacket::try_build_connack(code),
            Err(MqttSerializeError::InvalidConnackReturnCode(code))
        );
    }
}

#[test]
fn checked_connack_builder_preserves_defined_return_codes() {
    for code in 0..=5 {
        let packet = MqttPacket::try_build_connack(code).unwrap();
        assert_eq!(packet.payload, vec![0, code]);
        assert_eq!(packet.try_serialize().unwrap(), wire(0, code));
    }
}
