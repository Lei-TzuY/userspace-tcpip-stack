use toy_tcpip::mqtt::{MQTT_MAX_UTF8_STRING_LEN, MqttPacket, MqttSerializeError};

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
