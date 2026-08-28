use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x10, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn connect_payload(connect_flags: u8) -> Vec<u8> {
    vec![
        0x00,
        0x04,
        b'M',
        b'Q',
        b'T',
        b'T',
        0x04,
        connect_flags,
        0x00,
        0x3c,
        0x00,
        0x01,
        b'a',
    ]
}

fn packet(payload: &[u8]) -> MqttPacket {
    MqttPacket {
        packet_type: MqttPacketType::Connect,
        flags: 0,
        topic: None,
        packet_id: None,
        payload: payload.to_vec(),
    }
}

#[test]
fn parser_rejects_truncated_connect_variable_header() {
    for length in [0usize, 1, 5, 9] {
        let payload = &connect_payload(0)[..length];
        assert_eq!(
            MqttPacket::parse(&wire(payload)),
            Err(MqttError::InvalidConnectPayloadLength(length))
        );
    }
}

#[test]
fn parser_requires_mqtt_protocol_name() {
    let mut payload = connect_payload(0);
    payload[5] = b'X';
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectProtocolName)
    );

    let mut payload = connect_payload(0);
    payload[1] = 3;
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectProtocolName)
    );
}

#[test]
fn parser_requires_mqtt_v311_protocol_level() {
    for level in [3u8, 5] {
        let mut payload = connect_payload(0);
        payload[6] = level;
        assert_eq!(
            MqttPacket::parse(&wire(&payload)),
            Err(MqttError::InvalidConnectProtocolLevel(level))
        );
    }
}

#[test]
fn parser_rejects_invalid_connect_flag_combinations() {
    for flags in [0x01u8, 0x08, 0x20, 0x1c] {
        let payload = connect_payload(flags);
        assert_eq!(
            MqttPacket::parse(&wire(&payload)),
            Err(MqttError::InvalidConnectFlags(flags))
        );
    }
}

#[test]
fn checked_serializer_enforces_connect_variable_header_semantics() {
    let mut payload = connect_payload(0);
    payload[6] = 5;
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectProtocolLevel(5))
    );

    let payload = connect_payload(0x01);
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectFlags(0x01))
    );
}

#[test]
fn checked_builder_emits_valid_v311_connect_variable_header() {
    for clean_session in [false, true] {
        let packet = MqttPacket::try_build_connect("client", clean_session).unwrap();
        let raw = packet.try_serialize().unwrap();
        let parsed = MqttPacket::parse(&raw).unwrap();
        assert_eq!(parsed.packet_type, MqttPacketType::Connect);
        assert_eq!(&parsed.payload[..7], &[0, 4, b'M', b'Q', b'T', b'T', 4]);
        assert_eq!(parsed.payload[7], if clean_session { 0x02 } else { 0x00 });
    }
}
