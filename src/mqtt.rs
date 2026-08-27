//! Message Queuing Telemetry Transport (MQTT - ISO/IEC 20922 / OASIS).
//!
//! Lightweight IoT publish/subscribe telemetry messaging protocol over TCP port 1883.

use std::collections::HashMap;
use std::fmt;

pub const MQTT_PORT: u16 = 1883;
pub const MQTTS_PORT: u16 = 8883;

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
        }
    }
}

impl std::error::Error for MqttError {}

impl MqttPacket {
    pub fn build_connect(client_id: &str, clean_session: bool) -> Self {
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

    pub fn build_subscribe(packet_id: u16, topic: &str, qos: u8) -> Self {
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

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let header_byte = ((self.packet_type as u8) << 4) | (self.flags & 0x0F);
        out.push(header_byte);

        // Encode Remaining Length
        encode_remaining_length(&mut out, self.payload.len());
        out.extend_from_slice(&self.payload);

        out
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
                    let packet_id_end =
                        topic_end.checked_add(2).ok_or(MqttError::PacketTooShort)?;
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
                let first_subscription_end =
                    topic_end.checked_add(1).ok_or(MqttError::PacketTooShort)?;
                if payload.len() < first_subscription_end {
                    return Err(MqttError::PacketTooShort);
                }
                let topic_str = std::str::from_utf8(&payload[4..topic_end])
                    .map_err(|_| MqttError::MalformedUtf8String)?;
                topic = Some(topic_str.to_string());
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

fn encode_remaining_length(buf: &mut Vec<u8>, mut length: usize) {
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
}
