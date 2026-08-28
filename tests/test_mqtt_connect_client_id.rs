use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x10, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn connect_payload(clean_session: bool, client_id: &[u8]) -> Vec<u8> {
    let mut payload = vec![
        0x00,
        0x04,
        b'M',
        b'Q',
        b'T',
        b'T',
        0x04,
        if clean_session { 0x02 } else { 0x00 },
        0x00,
        0x3c,
    ];
    payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
    payload.extend_from_slice(client_id);
    payload
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
fn parser_requires_client_id_length_field() {
    for length in [10usize, 11] {
        let payload = &connect_payload(false, b"a")[..length];
        assert_eq!(
            MqttPacket::parse(&wire(payload)),
            Err(MqttError::InvalidConnectPayloadLength(length))
        );
    }
}

#[test]
fn parser_rejects_truncated_declared_client_id() {
    let mut payload = connect_payload(false, b"a");
    payload[10..12].copy_from_slice(&3u16.to_be_bytes());
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn parser_rejects_malformed_client_id_utf8() {
    let payload = connect_payload(false, &[0xff]);
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::MalformedUtf8String)
    );
}

#[test]
fn zero_length_client_id_requires_clean_session() {
    let payload = connect_payload(false, b"");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectClientId)
    );

    let payload = connect_payload(true, b"");
    assert!(MqttPacket::parse(&wire(&payload)).is_ok());
}

#[test]
fn checked_serializer_enforces_client_id_semantics() {
    let payload = connect_payload(false, b"");
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectClientId)
    );

    let payload = connect_payload(false, &[0xff]);
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectClientId)
    );
}

#[test]
fn checked_builder_rejects_empty_persistent_client_id() {
    assert_eq!(
        MqttPacket::try_build_connect("", false),
        Err(MqttSerializeError::InvalidConnectClientId)
    );

    let packet = MqttPacket::try_build_connect("", true).unwrap();
    let raw = packet.try_serialize().unwrap();
    assert!(MqttPacket::parse(&raw).is_ok());
}

#[test]
fn checked_builder_uses_utf8_byte_length_for_client_id() {
    let packet = MqttPacket::try_build_connect("節點", false).unwrap();
    assert_eq!(&packet.payload[10..12], &[0, 6]);
    assert_eq!(&packet.payload[12..18], "節點".as_bytes());
    assert!(MqttPacket::parse(&packet.try_serialize().unwrap()).is_ok());
}
