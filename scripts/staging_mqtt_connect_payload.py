from pathlib import Path

mqtt = Path("src/mqtt.rs")
text = mqtt.read_text()

old_flags = '''    let connect_flags = payload[7];
    let will_flag = connect_flags & 0x04 != 0;
    let will_qos = (connect_flags >> 3) & 0x03;
    let will_retain = connect_flags & 0x20 != 0;
    if connect_flags & 0x01 != 0
        || (!will_flag && (will_qos != 0 || will_retain))
        || (will_flag && will_qos == 3)
    {
        return Err(ConnectSemanticError::InvalidFlags(connect_flags));
    }
'''
new_flags = '''    let connect_flags = payload[7];
    let will_flag = connect_flags & 0x04 != 0;
    let will_qos = (connect_flags >> 3) & 0x03;
    let will_retain = connect_flags & 0x20 != 0;
    let username_flag = connect_flags & 0x80 != 0;
    let password_flag = connect_flags & 0x40 != 0;
    if connect_flags & 0x01 != 0
        || (!will_flag && (will_qos != 0 || will_retain))
        || (will_flag && will_qos == 3)
        || (password_flag && !username_flag)
    {
        return Err(ConnectSemanticError::InvalidFlags(connect_flags));
    }
'''
if old_flags not in text:
    raise SystemExit("CONNECT flag validation anchor not found")
text = text.replace(old_flags, new_flags, 1)

old_semantics = '''fn validate_connect_semantics(payload: &[u8]) -> Result<(), ConnectSemanticError> {
    validate_connect_variable_header(payload)?;
    if payload.len() < 12 {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }

    let client_id_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;
    let client_id_end = 12usize
        .checked_add(client_id_len)
        .ok_or(ConnectSemanticError::PayloadTooShort(payload.len()))?;
    if client_id_end > payload.len() {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }
    std::str::from_utf8(&payload[12..client_id_end])
        .map_err(|_| ConnectSemanticError::MalformedUtf8)?;

    let clean_session = payload[7] & 0x02 != 0;
    if client_id_len == 0 && !clean_session {
        return Err(ConnectSemanticError::InvalidClientId);
    }

    Ok(())
}
'''
new_semantics = '''fn consume_connect_field<'a>(
    payload: &'a [u8],
    cursor: &mut usize,
) -> Result<&'a [u8], ConnectSemanticError> {
    if payload.len().saturating_sub(*cursor) < 2 {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }
    let field_len = u16::from_be_bytes([payload[*cursor], payload[*cursor + 1]]) as usize;
    let field_start = *cursor + 2;
    let field_end = field_start
        .checked_add(field_len)
        .ok_or(ConnectSemanticError::PayloadTooShort(payload.len()))?;
    if field_end > payload.len() {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }
    *cursor = field_end;
    Ok(&payload[field_start..field_end])
}

fn validate_connect_semantics(payload: &[u8]) -> Result<(), ConnectSemanticError> {
    validate_connect_variable_header(payload)?;

    let connect_flags = payload[7];
    let mut cursor = 10usize;
    let client_id = consume_connect_field(payload, &mut cursor)?;
    std::str::from_utf8(client_id).map_err(|_| ConnectSemanticError::MalformedUtf8)?;

    let clean_session = connect_flags & 0x02 != 0;
    if client_id.is_empty() && !clean_session {
        return Err(ConnectSemanticError::InvalidClientId);
    }

    if connect_flags & 0x04 != 0 {
        consume_connect_field(payload, &mut cursor)?; // Will Topic
        consume_connect_field(payload, &mut cursor)?; // Will Message
    }
    if connect_flags & 0x80 != 0 {
        consume_connect_field(payload, &mut cursor)?; // User Name
    }
    if connect_flags & 0x40 != 0 {
        consume_connect_field(payload, &mut cursor)?; // Password
    }
    if cursor != payload.len() {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }

    Ok(())
}
'''
if old_semantics not in text:
    raise SystemExit("CONNECT semantics anchor not found")
text = text.replace(old_semantics, new_semantics, 1)
mqtt.write_text(text)

tests = r'''use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x10, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn connect_payload(flags: u8) -> Vec<u8> {
    let mut payload = vec![
        0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, flags, 0x00, 0x3c,
    ];
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
        Err(MqttSerializeError::InvalidConnectPayloadLength(payload.len()))
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
'''
Path("tests/test_mqtt_connect_payload.rs").write_text(tests)
