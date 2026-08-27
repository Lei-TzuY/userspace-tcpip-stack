from pathlib import Path

src = Path("src/mqtt.rs")
text = src.read_text()
old = '''        if packet_type == MqttPacketType::Publish && payload.len() >= 2 {
            let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
            if payload.len() >= 2 + topic_len
                && let Ok(t) = std::str::from_utf8(&payload[2..2 + topic_len])
            {
                topic = Some(t.to_string());
            }
        } else if packet_type == MqttPacketType::Subscribe && payload.len() >= 4 {
            packet_id = Some(u16::from_be_bytes([payload[0], payload[1]]));
            let topic_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
            if payload.len() >= 4 + topic_len
                && let Ok(t) = std::str::from_utf8(&payload[4..4 + topic_len])
            {
                topic = Some(t.to_string());
            }
        }
'''
new = '''        match packet_type {
            MqttPacketType::Publish => {
                if payload.len() < 2 {
                    return Err(MqttError::PacketTooShort);
                }
                let topic_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                let topic_end = 2usize
                    .checked_add(topic_len)
                    .ok_or(MqttError::PacketTooShort)?;
                if payload.len() < topic_end {
                    return Err(MqttError::PacketTooShort);
                }
                let topic_str = std::str::from_utf8(&payload[2..topic_end])
                    .map_err(|_| MqttError::MalformedUtf8String)?;
                topic = Some(topic_str.to_string());

                let qos = (flags >> 1) & 0x03;
                if qos > 0 {
                    let packet_id_end = topic_end
                        .checked_add(2)
                        .ok_or(MqttError::PacketTooShort)?;
                    if payload.len() < packet_id_end {
                        return Err(MqttError::PacketTooShort);
                    }
                    packet_id = Some(u16::from_be_bytes([
                        payload[topic_end],
                        payload[topic_end + 1],
                    ]));
                }
            }
            MqttPacketType::Subscribe => {
                if payload.len() < 4 {
                    return Err(MqttError::PacketTooShort);
                }
                packet_id = Some(u16::from_be_bytes([payload[0], payload[1]]));
                let topic_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
                let topic_end = 4usize
                    .checked_add(topic_len)
                    .ok_or(MqttError::PacketTooShort)?;
                let first_subscription_end = topic_end
                    .checked_add(1)
                    .ok_or(MqttError::PacketTooShort)?;
                if payload.len() < first_subscription_end {
                    return Err(MqttError::PacketTooShort);
                }
                let topic_str = std::str::from_utf8(&payload[4..topic_end])
                    .map_err(|_| MqttError::MalformedUtf8String)?;
                topic = Some(topic_str.to_string());
            }
            _ => {}
        }
'''
if old not in text:
    raise SystemExit("expected MQTT parse block not found")
src.write_text(text.replace(old, new, 1))

tests = r'''use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType};

fn wire(packet_type: MqttPacketType, flags: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![((packet_type as u8) << 4) | (flags & 0x0f), payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

#[test]
fn publish_requires_topic_length_field() {
    let raw = wire(MqttPacketType::Publish, 0, &[0]);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn publish_rejects_topic_length_overrun() {
    let raw = wire(MqttPacketType::Publish, 0, &[0, 3, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn publish_rejects_invalid_utf8_topic() {
    let raw = wire(MqttPacketType::Publish, 0, &[0, 1, 0xff]);
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::MalformedUtf8String)
    );
}

#[test]
fn qos_publish_requires_packet_identifier() {
    let raw = wire(MqttPacketType::Publish, 0x02, &[0, 1, b'a']);
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn qos_publish_extracts_packet_identifier() {
    let raw = wire(
        MqttPacketType::Publish,
        0x02,
        &[0, 1, b'a', 0x12, 0x34, b'x'],
    );
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.topic.as_deref(), Some("a"));
    assert_eq!(parsed.packet_id, Some(0x1234));
}

#[test]
fn subscribe_requires_first_topic_qos_byte() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, b'a'],
    );
    assert_eq!(MqttPacket::parse(&raw), Err(MqttError::PacketTooShort));
}

#[test]
fn subscribe_rejects_invalid_utf8_topic() {
    let raw = wire(
        MqttPacketType::Subscribe,
        0x02,
        &[0x12, 0x34, 0, 1, 0xff, 0],
    );
    assert_eq!(
        MqttPacket::parse(&raw),
        Err(MqttError::MalformedUtf8String)
    );
}

#[test]
fn valid_subscribe_still_extracts_required_fields() {
    let raw = MqttPacket::build_subscribe(0x4567, "sensor/temp", 1).serialize();
    let parsed = MqttPacket::parse(&raw).unwrap();
    assert_eq!(parsed.packet_id, Some(0x4567));
    assert_eq!(parsed.topic.as_deref(), Some("sensor/temp"));
}
'''
Path("tests/test_mqtt_required_fields.rs").write_text(tests)
