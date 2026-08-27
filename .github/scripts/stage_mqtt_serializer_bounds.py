from pathlib import Path

path = Path("src/mqtt.rs")
text = path.read_text()

const_anchor = "pub const MQTTS_PORT: u16 = 8883;\n"
const_block = """
pub const MQTT_MAX_UTF8_STRING_LEN: usize = u16::MAX as usize;
pub const MQTT_MAX_REMAINING_LENGTH: usize = 268_435_455;
"""
if "MQTT_MAX_REMAINING_LENGTH" not in text:
    if const_anchor not in text:
        raise SystemExit("missing constants anchor")
    text = text.replace(const_anchor, const_anchor + const_block, 1)

error_anchor = "impl std::error::Error for MqttError {}\n\n"
error_block = '''#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttSerializeError {
    Utf8StringTooLong {
        field: &'static str,
        length: usize,
        max: usize,
    },
    RemainingLengthTooLarge {
        length: usize,
        max: usize,
    },
}

impl fmt::Display for MqttSerializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttSerializeError::Utf8StringTooLong { field, length, max } => write!(
                f,
                "MQTT {} requires {} UTF-8 bytes, exceeding the {}-byte string length field limit",
                field, length, max
            ),
            MqttSerializeError::RemainingLengthTooLarge { length, max } => write!(
                f,
                "MQTT Remaining Length {} exceeds the four-byte maximum {}",
                length, max
            ),
        }
    }
}

impl std::error::Error for MqttSerializeError {}

fn validate_utf8_string_len(
    field: &'static str,
    length: usize,
) -> Result<(), MqttSerializeError> {
    if length > MQTT_MAX_UTF8_STRING_LEN {
        return Err(MqttSerializeError::Utf8StringTooLong {
            field,
            length,
            max: MQTT_MAX_UTF8_STRING_LEN,
        });
    }
    Ok(())
}

fn validate_remaining_length(length: usize) -> Result<(), MqttSerializeError> {
    if length > MQTT_MAX_REMAINING_LENGTH {
        return Err(MqttSerializeError::RemainingLengthTooLarge {
            length,
            max: MQTT_MAX_REMAINING_LENGTH,
        });
    }
    Ok(())
}

'''
if "pub enum MqttSerializeError" not in text:
    if error_anchor not in text:
        raise SystemExit("missing error anchor")
    text = text.replace(error_anchor, error_anchor + error_block, 1)

connect_old = '''    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {
        let mut payload = Vec::new();
        // Protocol Name: "MQTT" (Length 4 + "MQTT")
        payload.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        // Protocol Level: 4 (MQTT v3.1.1)
        payload.push(0x04);
        // Connect Flags
        let flags = if clean_session { 0x02 } else { 0x00 };
        payload.push(flags);
        // Keep Alive (60 seconds)
        payload.extend_from_slice(&60u16.to_be_bytes());
        // Client ID String (Length + Bytes)
        payload.extend_from_slice(&(client_id.len() as u16).to_be_bytes());
        payload.extend_from_slice(client_id.as_bytes());

        MqttPacket {
            packet_type: MqttPacketType::Connect,
            flags: 0,
            topic: None,
            packet_id: None,
            payload,
        }
    }
'''
connect_new = '''    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {
        Self::try_build_connect(client_id, clean_session)
            .expect("MQTT client ID must fit its 16-bit UTF-8 length field")
    }

    pub fn try_build_connect(
        client_id: &str,
        clean_session: bool,
    ) -> Result<Self, MqttSerializeError> {
        let client_id_len = client_id.len();
        validate_utf8_string_len("client ID", client_id_len)?;
        let payload_len = 12usize.checked_add(client_id_len).unwrap_or(usize::MAX);
        validate_remaining_length(payload_len)?;

        let mut payload = Vec::with_capacity(payload_len);
        // Protocol Name: "MQTT" (Length 4 + "MQTT")
        payload.extend_from_slice(&[0x00, 0x04, b'M', b'Q', b'T', b'T']);
        // Protocol Level: 4 (MQTT v3.1.1)
        payload.push(0x04);
        // Connect Flags
        let flags = if clean_session { 0x02 } else { 0x00 };
        payload.push(flags);
        // Keep Alive (60 seconds)
        payload.extend_from_slice(&60u16.to_be_bytes());
        // Client ID String (Length + Bytes)
        payload.extend_from_slice(&(client_id_len as u16).to_be_bytes());
        payload.extend_from_slice(client_id.as_bytes());

        Ok(MqttPacket {
            packet_type: MqttPacketType::Connect,
            flags: 0,
            topic: None,
            packet_id: None,
            payload,
        })
    }
'''
if connect_old in text:
    text = text.replace(connect_old, connect_new, 1)
elif "pub fn try_build_connect" not in text:
    raise SystemExit("missing connect builder anchor")

publish_old = '''    pub fn build_publish(topic: &str, msg: &[u8], qos: u8, packet_id: Option<u16>) -> Self {
        let flags = (qos << 1) & 0x06;
        let mut body = Vec::new();
        // Topic Name
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        // Packet ID if QoS > 0
        if qos > 0
            && let Some(pid) = packet_id
        {
            body.extend_from_slice(&pid.to_be_bytes());
        }
        body.extend_from_slice(msg);

        MqttPacket {
            packet_type: MqttPacketType::Publish,
            flags,
            topic: Some(topic.to_string()),
            packet_id,
            payload: body,
        }
    }
'''
publish_new = '''    pub fn build_publish(topic: &str, msg: &[u8], qos: u8, packet_id: Option<u16>) -> Self {
        Self::try_build_publish(topic, msg, qos, packet_id)
            .expect("MQTT PUBLISH fields must fit their wire length encodings")
    }

    pub fn try_build_publish(
        topic: &str,
        msg: &[u8],
        qos: u8,
        packet_id: Option<u16>,
    ) -> Result<Self, MqttSerializeError> {
        let topic_len = topic.len();
        validate_utf8_string_len("topic name", topic_len)?;
        let packet_id_len = if qos > 0 && packet_id.is_some() { 2 } else { 0 };
        let body_len = 2usize
            .checked_add(topic_len)
            .and_then(|len| len.checked_add(packet_id_len))
            .and_then(|len| len.checked_add(msg.len()))
            .unwrap_or(usize::MAX);
        validate_remaining_length(body_len)?;

        let flags = (qos << 1) & 0x06;
        let mut body = Vec::with_capacity(body_len);
        // Topic Name
        body.extend_from_slice(&(topic_len as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        // Packet ID if QoS > 0
        if qos > 0
            && let Some(pid) = packet_id
        {
            body.extend_from_slice(&pid.to_be_bytes());
        }
        body.extend_from_slice(msg);

        Ok(MqttPacket {
            packet_type: MqttPacketType::Publish,
            flags,
            topic: Some(topic.to_string()),
            packet_id,
            payload: body,
        })
    }
'''
if publish_old in text:
    text = text.replace(publish_old, publish_new, 1)
elif "pub fn try_build_publish" not in text:
    raise SystemExit("missing publish builder anchor")

subscribe_old = '''    pub fn build_subscribe(packet_id: u16, topic: &str, qos: u8) -> Self {
        let mut body = Vec::new();
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.push(qos);

        MqttPacket {
            packet_type: MqttPacketType::Subscribe,
            flags: 0x02, // Required bit 1 set for SUBSCRIBE
            topic: Some(topic.to_string()),
            packet_id: Some(packet_id),
            payload: body,
        }
    }
'''
subscribe_new = '''    pub fn build_subscribe(packet_id: u16, topic: &str, qos: u8) -> Self {
        Self::try_build_subscribe(packet_id, topic, qos)
            .expect("MQTT SUBSCRIBE topic must fit its 16-bit UTF-8 length field")
    }

    pub fn try_build_subscribe(
        packet_id: u16,
        topic: &str,
        qos: u8,
    ) -> Result<Self, MqttSerializeError> {
        let topic_len = topic.len();
        validate_utf8_string_len("topic filter", topic_len)?;
        let body_len = 5usize.checked_add(topic_len).unwrap_or(usize::MAX);
        validate_remaining_length(body_len)?;

        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(&packet_id.to_be_bytes());
        body.extend_from_slice(&(topic_len as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.push(qos);

        Ok(MqttPacket {
            packet_type: MqttPacketType::Subscribe,
            flags: 0x02, // Required bit 1 set for SUBSCRIBE
            topic: Some(topic.to_string()),
            packet_id: Some(packet_id),
            payload: body,
        })
    }
'''
if subscribe_old in text:
    text = text.replace(subscribe_old, subscribe_new, 1)
elif "pub fn try_build_subscribe" not in text:
    raise SystemExit("missing subscribe builder anchor")

serialize_old = '''    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header_byte = ((self.packet_type as u8) << 4) | (self.flags & 0x0F);
        out.push(header_byte);

        // Encode Remaining Length
        encode_remaining_length(&mut out, self.payload.len());
        out.extend_from_slice(&self.payload);

        out
    }
'''
serialize_new = '''    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("MQTT payload must fit the four-byte Remaining Length field")
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, MqttSerializeError> {
        validate_remaining_length(self.payload.len())?;
        let mut out = Vec::new();
        let header_byte = ((self.packet_type as u8) << 4) | (self.flags & 0x0F);
        out.push(header_byte);

        // Encode Remaining Length
        encode_remaining_length(&mut out, self.payload.len())?;
        out.extend_from_slice(&self.payload);

        Ok(out)
    }
'''
if serialize_old in text:
    text = text.replace(serialize_old, serialize_new, 1)
elif "pub fn try_serialize(&self) -> Result<Vec<u8>, MqttSerializeError>" not in text:
    raise SystemExit("missing serialize anchor")

encode_old = '''fn encode_remaining_length(buf: &mut Vec<u8>, mut length: usize) {
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if length == 0 {
            break;
        }
    }
}
'''
encode_new = '''fn encode_remaining_length(
    buf: &mut Vec<u8>,
    mut length: usize,
) -> Result<(), MqttSerializeError> {
    validate_remaining_length(length)?;
    loop {
        let mut byte = (length % 128) as u8;
        length /= 128;
        if length > 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if length == 0 {
            break;
        }
    }
    Ok(())
}
'''
if encode_old in text:
    text = text.replace(encode_old, encode_new, 1)
elif "fn encode_remaining_length(" not in text or "Result<(), MqttSerializeError>" not in text:
    raise SystemExit("missing remaining length encoder anchor")

test_anchor = '''        assert!(recips.contains(&"MobileAppClient".to_string()));
    }
}'''
test_replacement = '''        assert!(recips.contains(&"MobileAppClient".to_string()));
    }

    #[test]
    fn test_remaining_length_maximum_uses_four_bytes() {
        let mut encoded = Vec::new();
        encode_remaining_length(&mut encoded, MQTT_MAX_REMAINING_LENGTH).unwrap();
        assert_eq!(encoded, vec![0xff, 0xff, 0xff, 0x7f]);
    }

    #[test]
    fn test_remaining_length_above_maximum_is_rejected() {
        let mut encoded = Vec::new();
        assert_eq!(
            encode_remaining_length(&mut encoded, MQTT_MAX_REMAINING_LENGTH + 1),
            Err(MqttSerializeError::RemainingLengthTooLarge {
                length: MQTT_MAX_REMAINING_LENGTH + 1,
                max: MQTT_MAX_REMAINING_LENGTH,
            })
        );
        assert!(encoded.is_empty());
    }
}'''
if "test_remaining_length_above_maximum_is_rejected" not in text:
    if test_anchor not in text:
        raise SystemExit("missing unit test anchor")
    text = text.replace(test_anchor, test_replacement, 1)

path.write_text(text)

integration = r'''use toy_tcpip::mqtt::{
    MQTT_MAX_UTF8_STRING_LEN, MqttPacket, MqttSerializeError,
};

#[test]
fn maximum_length_client_id_uses_exact_u16_prefix() {
    let client_id = "a".repeat(MQTT_MAX_UTF8_STRING_LEN);
    let packet = MqttPacket::try_build_connect(&client_id, true).unwrap();

    assert_eq!(
        u16::from_be_bytes([packet.payload[10], packet.payload[11]]) as usize,
        MQTT_MAX_UTF8_STRING_LEN
    );
    assert_eq!(&packet.payload[12..], client_id.as_bytes());
}

#[test]
fn client_id_above_u16_length_is_rejected() {
    let client_id = "a".repeat(MQTT_MAX_UTF8_STRING_LEN + 1);
    assert_eq!(
        MqttPacket::try_build_connect(&client_id, true),
        Err(MqttSerializeError::Utf8StringTooLong {
            field: "client ID",
            length: MQTT_MAX_UTF8_STRING_LEN + 1,
            max: MQTT_MAX_UTF8_STRING_LEN,
        })
    );
}

#[test]
fn publish_topic_uses_utf8_byte_length_limit() {
    let topic = "é".repeat(32_768);
    assert_eq!(topic.len(), MQTT_MAX_UTF8_STRING_LEN + 1);
    assert_eq!(
        MqttPacket::try_build_publish(&topic, b"payload", 0, None),
        Err(MqttSerializeError::Utf8StringTooLong {
            field: "topic name",
            length: MQTT_MAX_UTF8_STRING_LEN + 1,
            max: MQTT_MAX_UTF8_STRING_LEN,
        })
    );
}

#[test]
fn maximum_length_publish_topic_roundtrips() {
    let topic = "a".repeat(MQTT_MAX_UTF8_STRING_LEN);
    let packet = MqttPacket::try_build_publish(&topic, b"", 0, None).unwrap();
    let raw = packet.try_serialize().unwrap();
    let parsed = MqttPacket::parse(&raw).unwrap();

    assert_eq!(parsed.topic.as_deref(), Some(topic.as_str()));
}

#[test]
fn subscribe_topic_above_u16_length_is_rejected() {
    let topic = "a".repeat(MQTT_MAX_UTF8_STRING_LEN + 1);
    assert_eq!(
        MqttPacket::try_build_subscribe(7, &topic, 0),
        Err(MqttSerializeError::Utf8StringTooLong {
            field: "topic filter",
            length: MQTT_MAX_UTF8_STRING_LEN + 1,
            max: MQTT_MAX_UTF8_STRING_LEN,
        })
    );
}
'''
Path("tests/test_mqtt_serializer_bounds.rs").write_text(integration)
