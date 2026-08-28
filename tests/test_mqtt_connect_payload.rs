use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x10, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn connect_payload(flags: u8) -> Vec<u8> {
    let mut payload = vec![0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, flags, 0x00, 0x3c];
    append_field(&mut payload, b"client");
    payload
}

fn append_field(payload: &mut Vec<u8>, field: &[u8]) {
    payload.extend_from_slice(&(field.len() as u16).to_be_bytes());
    payload.extend_from_slice(field);
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
fn parser_rejects_truncated_will_topic() {
    let mut payload = connect_payload(0x06);
    payload.extend_from_slice(&3u16.to_be_bytes());
    payload.extend_from_slice(b"ab");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn parser_rejects_truncated_will_message() {
    let mut payload = connect_payload(0x06);
    append_field(&mut payload, b"status/offline");
    payload.extend_from_slice(&3u16.to_be_bytes());
    payload.extend_from_slice(b"ab");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn parser_rejects_truncated_username() {
    let mut payload = connect_payload(0x82);
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(b"usr");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn parser_rejects_truncated_password() {
    let mut payload = connect_payload(0xc2);
    append_field(&mut payload, b"user");
    payload.extend_from_slice(&4u16.to_be_bytes());
    payload.extend_from_slice(b"pwd");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn parser_rejects_payload_not_declared_by_flags() {
    let mut payload = connect_payload(0x02);
    append_field(&mut payload, b"unexpected");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectPayloadLength(payload.len()))
    );
}

#[test]
fn password_flag_requires_username_flag() {
    let mut payload = connect_payload(0x42);
    append_field(&mut payload, b"password");
    assert_eq!(
        MqttPacket::parse(&wire(&payload)),
        Err(MqttError::InvalidConnectFlags(0x42))
    );
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectFlags(0x42))
    );
}

#[test]
fn checked_serializer_rejects_trailing_connect_payload() {
    let mut payload = connect_payload(0x02);
    payload.push(0);
    assert_eq!(
        packet(&payload).try_serialize(),
        Err(MqttSerializeError::InvalidConnectPayloadLength(
            payload.len()
        ))
    );
}

#[test]
fn all_declared_optional_fields_are_consumed_in_order() {
    let mut payload = connect_payload(0xc6);
    append_field(&mut payload, b"status/offline");
    append_field(&mut payload, &[0x00, 0xff, 0x7f]);
    append_field(&mut payload, b"device-user");
    append_field(&mut payload, &[0x00, 0x01, 0xfe, 0xff]);

    let raw = wire(&payload);
    assert!(MqttPacket::parse(&raw).is_ok());
    assert_eq!(packet(&payload).try_serialize().unwrap(), raw);
}
