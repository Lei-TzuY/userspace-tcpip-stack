//! Message Queuing Telemetry Transport (MQTT - ISO/IEC 20922 / OASIS).
//!
//! Lightweight IoT publish/subscribe telemetry messaging protocol over TCP port 1883.

use std::collections::HashMap;
use std::fmt;

pub const MQTT_PORT: u16 = 1883;
pub const MQTTS_PORT: u16 = 8883;

pub const MQTT_MAX_UTF8_STRING_LEN: usize = u16::MAX as usize;
pub const MQTT_MAX_REMAINING_LENGTH: usize = 268_435_455;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MqttPacketType {
    Connect = 1,
    Connack = 2,
    Publish = 3,
    Puback = 4,
    Subscribe = 8,
    Suback = 9,
    Unsubscribe = 10,
    Unsuback = 11,
    Pingreq = 12,
    Pingresp = 13,
    Disconnect = 14,
}

impl MqttPacketType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            1 => Some(MqttPacketType::Connect),
            2 => Some(MqttPacketType::Connack),
            3 => Some(MqttPacketType::Publish),
            4 => Some(MqttPacketType::Puback),
            8 => Some(MqttPacketType::Subscribe),
            9 => Some(MqttPacketType::Suback),
            10 => Some(MqttPacketType::Unsubscribe),
            11 => Some(MqttPacketType::Unsuback),
            12 => Some(MqttPacketType::Pingreq),
            13 => Some(MqttPacketType::Pingresp),
            14 => Some(MqttPacketType::Disconnect),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MqttPacket {
    pub packet_type: MqttPacketType,
    pub flags: u8,
    pub topic: Option<String>,
    pub packet_id: Option<u16>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MqttError {
    PacketTooShort,
    InvalidPacketType(u8),
    InvalidRemainingLength,
    MalformedUtf8String,
    InvalidQos(u8),
    InvalidPacketIdentifier(u16),
}

impl fmt::Display for MqttError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MqttError::PacketTooShort => write!(f, "MQTT packet too short"),
            MqttError::InvalidPacketType(t) => write!(f, "Invalid MQTT packet type: {}", t),
            MqttError::InvalidRemainingLength => {
                write!(f, "Malformed MQTT variable-length integer")
            }
            MqttError::MalformedUtf8String => write!(f, "Malformed UTF-8 string in MQTT packet"),
            MqttError::InvalidQos(qos) => write!(f, "Invalid MQTT QoS value: {}", qos),
            MqttError::InvalidPacketIdentifier(id) => {
                write!(f, "Invalid MQTT Packet Identifier: {}", id)
            }
        }
    }
}

impl std::error::Error for MqttError {}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    InvalidQos(u8),
    MissingPacketIdentifier,
    UnexpectedPacketIdentifier,
    InvalidPacketIdentifier(u16),
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
            MqttSerializeError::InvalidQos(qos) => {
                write!(f, "Invalid MQTT QoS value: {}", qos)
            }
            MqttSerializeError::MissingPacketIdentifier => {
                write!(f, "MQTT QoS 1/2 PUBLISH requires a Packet Identifier")
            }
            MqttSerializeError::UnexpectedPacketIdentifier => {
                write!(f, "MQTT QoS 0 PUBLISH must not carry a Packet Identifier")
            }
            MqttSerializeError::InvalidPacketIdentifier(id) => {
                write!(f, "Invalid MQTT Packet Identifier: {}", id)
            }
        }
    }
}

impl std::error::Error for MqttSerializeError {}

fn validate_utf8_string_len(field: &'static str, length: usize) -> Result<(), MqttSerializeError> {
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

impl MqttPacket {
    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {
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

    pub fn build_connack(return_code: u8) -> Self {
        MqttPacket {
            packet_type: MqttPacketType::Connack,
            flags: 0,
            topic: None,
            packet_id: None,
            payload: vec![0x00, return_code], // Session Present = 0, Return Code
        }
    }

    pub fn build_publish(topic: &str, msg: &[u8], qos: u8, packet_id: Option<u16>) -> Self {
        Self::try_build_publish(topic, msg, qos, packet_id)
            .expect("MQTT PUBLISH fields must satisfy wire and QoS requirements")
    }

    pub fn try_build_publish(
        topic: &str,
        msg: &[u8],
        qos: u8,
        packet_id: Option<u16>,
    ) -> Result<Self, MqttSerializeError> {
        if qos > 2 {
            return Err(MqttSerializeError::InvalidQos(qos));
        }
        match (qos, packet_id) {
            (0, Some(_)) => return Err(MqttSerializeError::UnexpectedPacketIdentifier),
            (1 | 2, None) => return Err(MqttSerializeError::MissingPacketIdentifier),
            (1 | 2, Some(0)) => {
                return Err(MqttSerializeError::InvalidPacketIdentifier(0));
            }
            _ => {}
        }

        let topic_len = topic.len();
        validate_utf8_string_len("topic name", topic_len)?;
        let packet_id_len = if qos > 0 { 2 } else { 0 };
        let body_len = 2usize
            .checked_add(topic_len)
            .and_then(|len| len.checked_add(packet_id_len))
            .and_then(|len| len.checked_add(msg.len()))
            .unwrap_or(usize::MAX);
        validate_remaining_length(body_len)?;

        let flags = qos << 1;
        let mut body = Vec::with_capacity(body_len);
        body.extend_from_slice(&(topic_len as u16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
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

    pub fn build_subscribe(packet_id: u16, topic: &str, qos: u8) -> Self {
        Self::try_build_subscribe(packet_id, topic, qos)
            .expect("MQTT SUBSCRIBE fields must satisfy wire and QoS requirements")
    }

    pub fn try_build_subscribe(
        packet_id: u16,
        topic: &str,
        qos: u8,
    ) -> Result<Self, MqttSerializeError> {
        if packet_id == 0 {
            return Err(MqttSerializeError::InvalidPacketIdentifier(packet_id));
        }
        if qos > 2 {
            return Err(MqttSerializeError::InvalidQos(qos));
        }

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

    pub fn serialize(&self) -> Vec<u8> {
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

    pub fn parse(data: &[u8]) -> Result<Self, MqttError> {
        if data.len() < 2 {
            return Err(MqttError::PacketTooShort);
        }

        let p_type_val = data[0] >> 4;
        let flags = data[0] & 0x0F;
        let packet_type =
            MqttPacketType::from_u8(p_type_val).ok_or(MqttError::InvalidPacketType(p_type_val))?;

        let (rem_len, offset) = decode_remaining_length(data, 1)?;
        if data.len() < offset + rem_len {
            return Err(MqttError::PacketTooShort);
        }

        let payload = data[offset..offset + rem_len].to_vec();
        let mut topic = None;
        let mut packet_id = None;

        match packet_type {
            MqttPacketType::Publish => {
                let qos = (flags >> 1) & 0x03;
                if qos > 2 {
                    return Err(MqttError::InvalidQos(qos));
                }
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

                if qos > 0 {
                    let packet_id_end =
                        topic_end.checked_add(2).ok_or(MqttError::PacketTooShort)?;
                    if payload.len() < packet_id_end {
                        return Err(MqttError::PacketTooShort);
                    }
                    let id = u16::from_be_bytes([payload[topic_end], payload[topic_end + 1]]);
                    if id == 0 {
                        return Err(MqttError::InvalidPacketIdentifier(id));
                    }
                    packet_id = Some(id);
                }
            }
            MqttPacketType::Subscribe => {
                if payload.len() < 2 {
                    return Err(MqttError::PacketTooShort);
                }
                let id = u16::from_be_bytes([payload[0], payload[1]]);
                if id == 0 {
                    return Err(MqttError::InvalidPacketIdentifier(id));
                }
                packet_id = Some(id);

                let mut cursor = 2usize;
                let mut first_topic = None;
                while cursor < payload.len() {
                    if payload.len() - cursor < 2 {
                        return Err(MqttError::PacketTooShort);
                    }
                    let topic_len =
                        u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
                    let topic_start = cursor + 2;
                    let topic_end = topic_start
                        .checked_add(topic_len)
                        .ok_or(MqttError::PacketTooShort)?;
                    if topic_end >= payload.len() {
                        return Err(MqttError::PacketTooShort);
                    }
                    let topic_str = std::str::from_utf8(&payload[topic_start..topic_end])
                        .map_err(|_| MqttError::MalformedUtf8String)?;
                    let requested_qos = payload[topic_end];
                    if requested_qos > 2 {
                        return Err(MqttError::InvalidQos(requested_qos));
                    }
                    if first_topic.is_none() {
                        first_topic = Some(topic_str.to_string());
                    }
                    cursor = topic_end + 1;
                }
                topic = Some(first_topic.ok_or(MqttError::PacketTooShort)?);
            }
            _ => {}
        }

        Ok(MqttPacket {
            packet_type,
            flags,
            topic,
            packet_id,
            payload,
        })
    }
}

fn encode_remaining_length(buf: &mut Vec<u8>, mut length: usize) -> Result<(), MqttSerializeError> {
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

fn decode_remaining_length(data: &[u8], mut offset: usize) -> Result<(usize, usize), MqttError> {
    let mut multiplier = 1;
    let mut value = 0;
    loop {
        if offset >= data.len() {
            return Err(MqttError::InvalidRemainingLength);
        }
        let encoded_byte = data[offset];
        offset += 1;
        value += ((encoded_byte & 0x7F) as usize) * multiplier;
        multiplier *= 128;
        if (encoded_byte & 0x80) == 0 {
            break;
        }
        if multiplier > 128 * 128 * 128 {
            return Err(MqttError::InvalidRemainingLength);
        }
    }
    Ok((value, offset))
}

/// In-Memory Virtual MQTT Telemetry Broker
#[derive(Debug, Default)]
pub struct MqttBroker {
    // Topic -> List of Subscribed Client IDs
    pub subscriptions: HashMap<String, Vec<String>>,
}

impl MqttBroker {
    pub fn new() -> Self {
        let mut broker = MqttBroker::default();
        broker.subscribe("sensor/temperature", "DashboardApp");
        broker.subscribe("sensor/humidity", "DashboardApp");
        broker.subscribe("actuator/relay", "RelayNode1");
        broker
    }

    pub fn subscribe(&mut self, topic: &str, client_id: &str) {
        let list = self.subscriptions.entry(topic.to_string()).or_default();
        if !list.contains(&client_id.to_string()) {
            list.push(client_id.to_string());
        }
    }

    pub fn publish(&self, topic: &str) -> Vec<String> {
        self.subscriptions.get(topic).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mqtt_publish_subscribe_roundtrip() {
        let connect = MqttPacket::build_connect("SensorNode01", true);
        let raw_connect = connect.serialize();
        let parsed_connect = MqttPacket::parse(&raw_connect).unwrap();
        assert_eq!(parsed_connect.packet_type, MqttPacketType::Connect);

        let pub_pkt = MqttPacket::build_publish("home/livingroom/temp", b"23.5 C", 0, None);
        let raw_pub = pub_pkt.serialize();
        let parsed_pub = MqttPacket::parse(&raw_pub).unwrap();
        assert_eq!(parsed_pub.packet_type, MqttPacketType::Publish);
        assert_eq!(parsed_pub.topic.as_deref(), Some("home/livingroom/temp"));

        let mut broker = MqttBroker::new();
        broker.subscribe("home/livingroom/temp", "MobileAppClient");
        let recips = broker.publish("home/livingroom/temp");
        assert!(recips.contains(&"MobileAppClient".to_string()));
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
}
