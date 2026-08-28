from pathlib import Path

src = Path("src/mqtt.rs")
text = src.read_text()


def replace_once(old: str, new: str) -> None:
    global text
    if old not in text:
        raise SystemExit(f"anchor not found: {old[:120]!r}")
    text = text.replace(old, new, 1)


replace_once(
    """    InvalidConnectProtocolLevel(u8),\n    InvalidConnectFlags(u8),\n}\n\nimpl fmt::Display for MqttError {\n""",
    """    InvalidConnectProtocolLevel(u8),\n    InvalidConnectFlags(u8),\n    InvalidConnectClientId,\n}\n\nimpl fmt::Display for MqttError {\n""",
)

replace_once(
    """            MqttError::InvalidConnectPayloadLength(length) => write!(\n                f,\n                \"Invalid MQTT CONNECT payload length {}; expected at least 10 bytes for the variable header\",\n                length\n            ),\n""",
    """            MqttError::InvalidConnectPayloadLength(length) => write!(\n                f,\n                \"Invalid MQTT CONNECT payload length or framing: {}\",\n                length\n            ),\n""",
)

replace_once(
    """            MqttError::InvalidConnectFlags(flags) => {\n                write!(f, \"Invalid MQTT CONNECT flags: 0x{:02x}\", flags)\n            }\n        }\n""",
    """            MqttError::InvalidConnectFlags(flags) => {\n                write!(f, \"Invalid MQTT CONNECT flags: 0x{:02x}\", flags)\n            }\n            MqttError::InvalidConnectClientId => {\n                write!(f, \"Invalid MQTT CONNECT Client Identifier\")\n            }\n        }\n""",
)

replace_once(
    """    InvalidConnectProtocolLevel(u8),\n    InvalidConnectFlags(u8),\n}\n\nimpl fmt::Display for MqttSerializeError {\n""",
    """    InvalidConnectProtocolLevel(u8),\n    InvalidConnectFlags(u8),\n    InvalidConnectClientId,\n}\n\nimpl fmt::Display for MqttSerializeError {\n""",
)

replace_once(
    """            MqttSerializeError::InvalidConnectPayloadLength(length) => write!(\n                f,\n                \"Invalid MQTT CONNECT payload length {}; expected at least 10 bytes for the variable header\",\n                length\n            ),\n""",
    """            MqttSerializeError::InvalidConnectPayloadLength(length) => write!(\n                f,\n                \"Invalid MQTT CONNECT payload length or framing: {}\",\n                length\n            ),\n""",
)

replace_once(
    """            MqttSerializeError::InvalidConnectFlags(flags) => {\n                write!(f, \"Invalid MQTT CONNECT flags: 0x{:02x}\", flags)\n            }\n        }\n""",
    """            MqttSerializeError::InvalidConnectFlags(flags) => {\n                write!(f, \"Invalid MQTT CONNECT flags: 0x{:02x}\", flags)\n            }\n            MqttSerializeError::InvalidConnectClientId => {\n                write!(f, \"Invalid MQTT CONNECT Client Identifier\")\n            }\n        }\n""",
)

replace_once(
    """enum ConnectSemanticError {\n    PayloadTooShort(usize),\n    InvalidProtocolName,\n    InvalidProtocolLevel(u8),\n    InvalidFlags(u8),\n}\n""",
    """enum ConnectSemanticError {\n    PayloadTooShort(usize),\n    InvalidProtocolName,\n    InvalidProtocolLevel(u8),\n    InvalidFlags(u8),\n    InvalidClientId,\n    MalformedUtf8,\n}\n""",
)

replace_once(
    """    Ok(())\n}\n\nimpl MqttPacket {\n    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {\n""",
    """    Ok(())\n}\n\nfn validate_connect_semantics(payload: &[u8]) -> Result<(), ConnectSemanticError> {\n    validate_connect_variable_header(payload)?;\n    if payload.len() < 12 {\n        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));\n    }\n\n    let client_id_len = u16::from_be_bytes([payload[10], payload[11]]) as usize;\n    let client_id_end = 12usize\n        .checked_add(client_id_len)\n        .ok_or(ConnectSemanticError::PayloadTooShort(payload.len()))?;\n    if client_id_end > payload.len() {\n        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));\n    }\n    std::str::from_utf8(&payload[12..client_id_end])\n        .map_err(|_| ConnectSemanticError::MalformedUtf8)?;\n\n    let clean_session = payload[7] & 0x02 != 0;\n    if client_id_len == 0 && !clean_session {\n        return Err(ConnectSemanticError::InvalidClientId);\n    }\n\n    Ok(())\n}\n\nimpl MqttPacket {\n    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {\n""",
)

replace_once(
    """        Self::try_build_connect(client_id, clean_session)\n            .expect(\"MQTT client ID must fit its 16-bit UTF-8 length field\")\n""",
    """        Self::try_build_connect(client_id, clean_session)\n            .expect(\"MQTT client ID must satisfy CONNECT wire requirements\")\n""",
)

replace_once(
    """    ) -> Result<Self, MqttSerializeError> {\n        let client_id_len = client_id.len();\n        validate_utf8_string_len(\"client ID\", client_id_len)?;\n""",
    """    ) -> Result<Self, MqttSerializeError> {\n        let client_id_len = client_id.len();\n        if client_id_len == 0 && !clean_session {\n            return Err(MqttSerializeError::InvalidConnectClientId);\n        }\n        validate_utf8_string_len(\"client ID\", client_id_len)?;\n""",
)

text = text.replace(
    "match validate_connect_variable_header(&self.payload) {",
    "match validate_connect_semantics(&self.payload) {",
    1,
)
replace_once(
    """                Err(ConnectSemanticError::InvalidFlags(flags)) => {\n                    return Err(MqttSerializeError::InvalidConnectFlags(flags));\n                }\n            }\n""",
    """                Err(ConnectSemanticError::InvalidFlags(flags)) => {\n                    return Err(MqttSerializeError::InvalidConnectFlags(flags));\n                }\n                Err(ConnectSemanticError::InvalidClientId)\n                | Err(ConnectSemanticError::MalformedUtf8) => {\n                    return Err(MqttSerializeError::InvalidConnectClientId);\n                }\n            }\n""",
)

text = text.replace(
    "MqttPacketType::Connect => match validate_connect_variable_header(&payload) {",
    "MqttPacketType::Connect => match validate_connect_semantics(&payload) {",
    1,
)
replace_once(
    """                Err(ConnectSemanticError::InvalidFlags(flags)) => {\n                    return Err(MqttError::InvalidConnectFlags(flags));\n                }\n            },\n""",
    """                Err(ConnectSemanticError::InvalidFlags(flags)) => {\n                    return Err(MqttError::InvalidConnectFlags(flags));\n                }\n                Err(ConnectSemanticError::InvalidClientId) => {\n                    return Err(MqttError::InvalidConnectClientId);\n                }\n                Err(ConnectSemanticError::MalformedUtf8) => {\n                    return Err(MqttError::MalformedUtf8String);\n                }\n            },\n""",
)

src.write_text(text)

Path("tests/test_mqtt_connect_client_id.rs").write_text(r'''use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![0x10, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn connect_payload(clean_session: bool, client_id: &[u8]) -> Vec<u8> {
    let mut payload = vec![
        0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04,
        if clean_session { 0x02 } else { 0x00 },
        0x00, 0x3c,
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
''')
