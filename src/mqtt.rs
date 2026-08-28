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
    InvalidFixedHeaderFlags {
        packet_type: MqttPacketType,
        flags: u8,
    },
    InvalidPayloadLength {
        packet_type: MqttPacketType,
        length: usize,
        expected: usize,
    },
    InvalidConnackAcknowledgeFlags(u8),
    InvalidConnackReturnCode(u8),
    InvalidConnackSessionPresent {
        return_code: u8,
    },
    InvalidSubackPayloadLength(usize),
    InvalidSubackReturnCode(u8),
    InvalidUnsubscribePayloadLength(usize),
    InvalidUnsubscribeTopicFilter,
    InvalidConnectPayloadLength(usize),
    InvalidConnectProtocolName,
    InvalidConnectProtocolLevel(u8),
    InvalidConnectFlags(u8),
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
            MqttError::InvalidFixedHeaderFlags { packet_type, flags } => write!(
                f,
                "Invalid MQTT fixed-header flags 0x{:x} for {:?}",
                flags, packet_type
            ),
            MqttError::InvalidPayloadLength {
                packet_type,
                length,
                expected,
            } => write!(
                f,
                "Invalid MQTT payload length {} for {:?}; expected {}",
                length, packet_type, expected
            ),
            MqttError::InvalidConnackAcknowledgeFlags(flags) => {
                write!(f, "Invalid MQTT CONNACK acknowledge flags: 0x{:02x}", flags)
            }
            MqttError::InvalidConnackReturnCode(code) => {
                write!(f, "Invalid MQTT CONNACK return code: {}", code)
            }
            MqttError::InvalidConnackSessionPresent { return_code } => write!(
                f,
                "MQTT CONNACK Session Present must be zero for return code {}",
                return_code
            ),
            MqttError::InvalidSubackPayloadLength(length) => write!(
                f,
                "Invalid MQTT SUBACK payload length {}; expected at least 3",
                length
            ),
            MqttError::InvalidSubackReturnCode(code) => {
                write!(f, "Invalid MQTT SUBACK return code: 0x{:02x}", code)
            }
            MqttError::InvalidUnsubscribePayloadLength(length) => write!(
                f,
                "Invalid MQTT UNSUBSCRIBE payload length or framing: {}",
                length
            ),
            MqttError::InvalidUnsubscribeTopicFilter => {
                write!(f, "Invalid MQTT UNSUBSCRIBE topic filter")
            }
            MqttError::InvalidConnectPayloadLength(length) => write!(
                f,
                "Invalid MQTT CONNECT payload length {}; expected at least 10 bytes for the variable header",
                length
            ),
            MqttError::InvalidConnectProtocolName => {
                write!(f, "Invalid MQTT CONNECT protocol name; expected MQTT")
            }
            MqttError::InvalidConnectProtocolLevel(level) => write!(
                f,
                "Invalid MQTT CONNECT protocol level {}; expected 4 for MQTT v3.1.1",
                level
            ),
            MqttError::InvalidConnectFlags(flags) => {
                write!(f, "Invalid MQTT CONNECT flags: 0x{:02x}", flags)
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
    InvalidFixedHeaderFlags {
        packet_type: MqttPacketType,
        flags: u8,
    },
    InvalidPayloadLength {
        packet_type: MqttPacketType,
        length: usize,
        expected: usize,
    },
    InvalidConnackAcknowledgeFlags(u8),
    InvalidConnackReturnCode(u8),
    InvalidConnackSessionPresent {
        return_code: u8,
    },
    InvalidSubackPayloadLength(usize),
    InvalidSubackReturnCode(u8),
    InvalidUnsubscribePayloadLength(usize),
    InvalidUnsubscribeTopicFilter,
    InvalidConnectPayloadLength(usize),
    InvalidConnectProtocolName,
    InvalidConnectProtocolLevel(u8),
    InvalidConnectFlags(u8),
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
            MqttSerializeError::InvalidFixedHeaderFlags { packet_type, flags } => write!(
                f,
                "Invalid MQTT fixed-header flags 0x{:x} for {:?}",
                flags, packet_type
            ),
            MqttSerializeError::InvalidPayloadLength {
                packet_type,
                length,
                expected,
            } => write!(
                f,
                "Invalid MQTT payload length {} for {:?}; expected {}",
                length, packet_type, expected
            ),
            MqttSerializeError::InvalidConnackAcknowledgeFlags(flags) => {
                write!(f, "Invalid MQTT CONNACK acknowledge flags: 0x{:02x}", flags)
            }
            MqttSerializeError::InvalidConnackReturnCode(code) => {
                write!(f, "Invalid MQTT CONNACK return code: {}", code)
            }
            MqttSerializeError::InvalidConnackSessionPresent { return_code } => write!(
                f,
                "MQTT CONNACK Session Present must be zero for return code {}",
                return_code
            ),
            MqttSerializeError::InvalidSubackPayloadLength(length) => write!(
                f,
                "Invalid MQTT SUBACK payload length {}; expected at least 3",
                length
            ),
            MqttSerializeError::InvalidSubackReturnCode(code) => {
                write!(f, "Invalid MQTT SUBACK return code: 0x{:02x}", code)
            }
            MqttSerializeError::InvalidUnsubscribePayloadLength(length) => write!(
                f,
                "Invalid MQTT UNSUBSCRIBE payload length or framing: {}",
                length
            ),
            MqttSerializeError::InvalidUnsubscribeTopicFilter => {
                write!(f, "Invalid MQTT UNSUBSCRIBE topic filter")
            }
            MqttSerializeError::InvalidConnectPayloadLength(length) => write!(
                f,
                "Invalid MQTT CONNECT payload length {}; expected at least 10 bytes for the variable header",
                length
            ),
            MqttSerializeError::InvalidConnectProtocolName => {
                write!(f, "Invalid MQTT CONNECT protocol name; expected MQTT")
            }
            MqttSerializeError::InvalidConnectProtocolLevel(level) => write!(
                f,
                "Invalid MQTT CONNECT protocol level {}; expected 4 for MQTT v3.1.1",
                level
            ),
            MqttSerializeError::InvalidConnectFlags(flags) => {
                write!(f, "Invalid MQTT CONNECT flags: 0x{:02x}", flags)
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

fn fixed_header_flags_are_valid(packet_type: MqttPacketType, flags: u8) -> bool {
    if flags > 0x0f {
        return false;
    }
    match packet_type {
        MqttPacketType::Publish => true,
        MqttPacketType::Subscribe | MqttPacketType::Unsubscribe => flags == 0x02,
        _ => flags == 0,
    }
}

fn fixed_payload_length(packet_type: MqttPacketType) -> Option<usize> {
    match packet_type {
        MqttPacketType::Connack | MqttPacketType::Puback | MqttPacketType::Unsuback => Some(2),
        MqttPacketType::Pingreq | MqttPacketType::Pingresp | MqttPacketType::Disconnect => Some(0),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnackSemanticError {
    InvalidAcknowledgeFlags(u8),
    InvalidReturnCode(u8),
    SessionPresentWithError(u8),
}

fn validate_connack_semantics(payload: &[u8]) -> Result<(), ConnackSemanticError> {
    let acknowledge_flags = payload[0];
    let return_code = payload[1];

    if acknowledge_flags & 0xfe != 0 {
        return Err(ConnackSemanticError::InvalidAcknowledgeFlags(
            acknowledge_flags,
        ));
    }
    if return_code > 5 {
        return Err(ConnackSemanticError::InvalidReturnCode(return_code));
    }
    if return_code != 0 && acknowledge_flags & 0x01 != 0 {
        return Err(ConnackSemanticError::SessionPresentWithError(return_code));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubackSemanticError {
    PayloadTooShort(usize),
    InvalidPacketIdentifier(u16),
    InvalidReturnCode(u8),
}

fn validate_suback_semantics(payload: &[u8]) -> Result<u16, SubackSemanticError> {
    if payload.len() < 3 {
        return Err(SubackSemanticError::PayloadTooShort(payload.len()));
    }

    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return Err(SubackSemanticError::InvalidPacketIdentifier(packet_id));
    }

    for &code in &payload[2..] {
        if !matches!(code, 0x00 | 0x01 | 0x02 | 0x80) {
            return Err(SubackSemanticError::InvalidReturnCode(code));
        }
    }

    Ok(packet_id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsubscribeSemanticError {
    PayloadTooShort(usize),
    InvalidPacketIdentifier(u16),
    InvalidTopicFilter,
    MalformedUtf8,
}

fn validate_unsubscribe_semantics(payload: &[u8]) -> Result<(u16, &str), UnsubscribeSemanticError> {
    if payload.len() < 2 {
        return Err(UnsubscribeSemanticError::PayloadTooShort(payload.len()));
    }

    let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
    if packet_id == 0 {
        return Err(UnsubscribeSemanticError::InvalidPacketIdentifier(packet_id));
    }

    let mut cursor = 2usize;
    let mut first_topic = None;
    while cursor < payload.len() {
        if payload.len() - cursor < 2 {
            return Err(UnsubscribeSemanticError::PayloadTooShort(payload.len()));
        }
        let topic_len = u16::from_be_bytes([payload[cursor], payload[cursor + 1]]) as usize;
        if topic_len == 0 {
            return Err(UnsubscribeSemanticError::InvalidTopicFilter);
        }
        let topic_start = cursor + 2;
        let topic_end = topic_start
            .checked_add(topic_len)
            .ok_or(UnsubscribeSemanticError::PayloadTooShort(payload.len()))?;
        if topic_end > payload.len() {
            return Err(UnsubscribeSemanticError::PayloadTooShort(payload.len()));
        }
        let topic = std::str::from_utf8(&payload[topic_start..topic_end])
            .map_err(|_| UnsubscribeSemanticError::MalformedUtf8)?;
        if first_topic.is_none() {
            first_topic = Some(topic);
        }
        cursor = topic_end;
    }

    let first_topic =
        first_topic.ok_or(UnsubscribeSemanticError::PayloadTooShort(payload.len()))?;
    Ok((packet_id, first_topic))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectSemanticError {
    PayloadTooShort(usize),
    InvalidProtocolName,
    InvalidProtocolLevel(u8),
    InvalidFlags(u8),
}

fn validate_connect_variable_header(payload: &[u8]) -> Result<(), ConnectSemanticError> {
    if payload.len() < 10 {
        return Err(ConnectSemanticError::PayloadTooShort(payload.len()));
    }

    if &payload[..6] != b"\x00\x04MQTT" {
        return Err(ConnectSemanticError::InvalidProtocolName);
    }

    let protocol_level = payload[6];
    if protocol_level != 4 {
        return Err(ConnectSemanticError::InvalidProtocolLevel(protocol_level));
    }

    let connect_flags = payload[7];
    let will_flag = connect_flags & 0x04 != 0;
    let will_qos = (connect_flags >> 3) & 0x03;
    let will_retain = connect_flags & 0x20 != 0;
    if connect_flags & 0x01 != 0
        || (!will_flag && (will_qos != 0 || will_retain))
        || (will_flag && will_qos == 3)
    {
        return Err(ConnectSemanticError::InvalidFlags(connect_flags));
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
        Self::try_build_connack(return_code)
            .expect("MQTT CONNACK return code must be defined by MQTT v3.1.1")
    }

    pub fn try_build_connack(return_code: u8) -> Result<Self, MqttSerializeError> {
        if return_code > 5 {
            return Err(MqttSerializeError::InvalidConnackReturnCode(return_code));
        }
        Ok(MqttPacket {
            packet_type: MqttPacketType::Connack,
            flags: 0,
            topic: None,
            packet_id: None,
            payload: vec![0x00, return_code], // Session Present = 0, Return Code
        })
    }

    pub fn build_suback(packet_id: u16, return_codes: &[u8]) -> Self {
        Self::try_build_suback(packet_id, return_codes)
            .expect("MQTT SUBACK requires a nonzero Packet Identifier and valid return codes")
    }

    pub fn try_build_suback(
        packet_id: u16,
        return_codes: &[u8],
    ) -> Result<Self, MqttSerializeError> {
        if packet_id == 0 {
            return Err(MqttSerializeError::InvalidPacketIdentifier(packet_id));
        }
        let payload_len = 2usize.checked_add(return_codes.len()).unwrap_or(usize::MAX);
        if return_codes.is_empty() {
            return Err(MqttSerializeError::InvalidSubackPayloadLength(payload_len));
        }
        for &code in return_codes {
            if !matches!(code, 0x00 | 0x01 | 0x02 | 0x80) {
                return Err(MqttSerializeError::InvalidSubackReturnCode(code));
            }
        }
        validate_remaining_length(payload_len)?;

        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&packet_id.to_be_bytes());
        payload.extend_from_slice(return_codes);
        Ok(MqttPacket {
            packet_type: MqttPacketType::Suback,
            flags: 0,
            topic: None,
            packet_id: Some(packet_id),
            payload,
        })
    }

    pub fn build_unsubscribe(packet_id: u16, topic: &str) -> Self {
        Self::try_build_unsubscribe(packet_id, topic)
            .expect("MQTT UNSUBSCRIBE fields must satisfy wire requirements")
    }

    pub fn try_build_unsubscribe(packet_id: u16, topic: &str) -> Result<Self, MqttSerializeError> {
        if packet_id == 0 {
            return Err(MqttSerializeError::InvalidPacketIdentifier(packet_id));
        }
        let topic_len = topic.len();
        if topic_len == 0 {
            return Err(MqttSerializeError::InvalidUnsubscribeTopicFilter);
        }
        validate_utf8_string_len("topic filter", topic_len)?;
        let payload_len = 4usize.checked_add(topic_len).unwrap_or(usize::MAX);
        validate_remaining_length(payload_len)?;

        let mut payload = Vec::with_capacity(payload_len);
        payload.extend_from_slice(&packet_id.to_be_bytes());
        payload.extend_from_slice(&(topic_len as u16).to_be_bytes());
        payload.extend_from_slice(topic.as_bytes());
        Ok(MqttPacket {
            packet_type: MqttPacketType::Unsubscribe,
            flags: 0x02,
            topic: Some(topic.to_string()),
            packet_id: Some(packet_id),
            payload,
        })
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
        if !fixed_header_flags_are_valid(self.packet_type, self.flags) {
            return Err(MqttSerializeError::InvalidFixedHeaderFlags {
                packet_type: self.packet_type,
                flags: self.flags,
            });
        }
        if self.packet_type == MqttPacketType::Connect {
            match validate_connect_variable_header(&self.payload) {
                Ok(()) => {}
                Err(ConnectSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttSerializeError::InvalidConnectPayloadLength(length));
                }
                Err(ConnectSemanticError::InvalidProtocolName) => {
                    return Err(MqttSerializeError::InvalidConnectProtocolName);
                }
                Err(ConnectSemanticError::InvalidProtocolLevel(level)) => {
                    return Err(MqttSerializeError::InvalidConnectProtocolLevel(level));
                }
                Err(ConnectSemanticError::InvalidFlags(flags)) => {
                    return Err(MqttSerializeError::InvalidConnectFlags(flags));
                }
            }
        }
        if self.packet_type == MqttPacketType::Publish {
            let qos = (self.flags >> 1) & 0x03;
            if qos > 2 {
                return Err(MqttSerializeError::InvalidQos(qos));
            }
        }
        if let Some(expected) = fixed_payload_length(self.packet_type)
            && self.payload.len() != expected
        {
            return Err(MqttSerializeError::InvalidPayloadLength {
                packet_type: self.packet_type,
                length: self.payload.len(),
                expected,
            });
        }
        if self.packet_type == MqttPacketType::Connack {
            match validate_connack_semantics(&self.payload) {
                Ok(()) => {}
                Err(ConnackSemanticError::InvalidAcknowledgeFlags(flags)) => {
                    return Err(MqttSerializeError::InvalidConnackAcknowledgeFlags(flags));
                }
                Err(ConnackSemanticError::InvalidReturnCode(code)) => {
                    return Err(MqttSerializeError::InvalidConnackReturnCode(code));
                }
                Err(ConnackSemanticError::SessionPresentWithError(return_code)) => {
                    return Err(MqttSerializeError::InvalidConnackSessionPresent { return_code });
                }
            }
        }
        if self.packet_type == MqttPacketType::Suback {
            match validate_suback_semantics(&self.payload) {
                Ok(_) => {}
                Err(SubackSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttSerializeError::InvalidSubackPayloadLength(length));
                }
                Err(SubackSemanticError::InvalidPacketIdentifier(id)) => {
                    return Err(MqttSerializeError::InvalidPacketIdentifier(id));
                }
                Err(SubackSemanticError::InvalidReturnCode(code)) => {
                    return Err(MqttSerializeError::InvalidSubackReturnCode(code));
                }
            }
        }
        if self.packet_type == MqttPacketType::Unsubscribe {
            match validate_unsubscribe_semantics(&self.payload) {
                Ok(_) => {}
                Err(UnsubscribeSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttSerializeError::InvalidUnsubscribePayloadLength(length));
                }
                Err(UnsubscribeSemanticError::InvalidPacketIdentifier(id)) => {
                    return Err(MqttSerializeError::InvalidPacketIdentifier(id));
                }
                Err(UnsubscribeSemanticError::InvalidTopicFilter)
                | Err(UnsubscribeSemanticError::MalformedUtf8) => {
                    return Err(MqttSerializeError::InvalidUnsubscribeTopicFilter);
                }
            }
        }
        if matches!(
            self.packet_type,
            MqttPacketType::Puback | MqttPacketType::Unsuback
        ) {
            let id = u16::from_be_bytes([self.payload[0], self.payload[1]]);
            if id == 0 {
                return Err(MqttSerializeError::InvalidPacketIdentifier(id));
            }
        }
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
        if !fixed_header_flags_are_valid(packet_type, flags) {
            return Err(MqttError::InvalidFixedHeaderFlags { packet_type, flags });
        }

        let (rem_len, offset) = decode_remaining_length(data, 1)?;
        if data.len() < offset + rem_len {
            return Err(MqttError::PacketTooShort);
        }

        let payload = data[offset..offset + rem_len].to_vec();
        if let Some(expected) = fixed_payload_length(packet_type)
            && payload.len() != expected
        {
            return Err(MqttError::InvalidPayloadLength {
                packet_type,
                length: payload.len(),
                expected,
            });
        }
        let mut topic = None;
        let mut packet_id = None;

        match packet_type {
            MqttPacketType::Connect => match validate_connect_variable_header(&payload) {
                Ok(()) => {}
                Err(ConnectSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttError::InvalidConnectPayloadLength(length));
                }
                Err(ConnectSemanticError::InvalidProtocolName) => {
                    return Err(MqttError::InvalidConnectProtocolName);
                }
                Err(ConnectSemanticError::InvalidProtocolLevel(level)) => {
                    return Err(MqttError::InvalidConnectProtocolLevel(level));
                }
                Err(ConnectSemanticError::InvalidFlags(flags)) => {
                    return Err(MqttError::InvalidConnectFlags(flags));
                }
            },
            MqttPacketType::Connack => match validate_connack_semantics(&payload) {
                Ok(()) => {}
                Err(ConnackSemanticError::InvalidAcknowledgeFlags(flags)) => {
                    return Err(MqttError::InvalidConnackAcknowledgeFlags(flags));
                }
                Err(ConnackSemanticError::InvalidReturnCode(code)) => {
                    return Err(MqttError::InvalidConnackReturnCode(code));
                }
                Err(ConnackSemanticError::SessionPresentWithError(return_code)) => {
                    return Err(MqttError::InvalidConnackSessionPresent { return_code });
                }
            },
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
            MqttPacketType::Suback => match validate_suback_semantics(&payload) {
                Ok(id) => packet_id = Some(id),
                Err(SubackSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttError::InvalidSubackPayloadLength(length));
                }
                Err(SubackSemanticError::InvalidPacketIdentifier(id)) => {
                    return Err(MqttError::InvalidPacketIdentifier(id));
                }
                Err(SubackSemanticError::InvalidReturnCode(code)) => {
                    return Err(MqttError::InvalidSubackReturnCode(code));
                }
            },
            MqttPacketType::Unsubscribe => match validate_unsubscribe_semantics(&payload) {
                Ok((id, first_topic)) => {
                    packet_id = Some(id);
                    topic = Some(first_topic.to_string());
                }
                Err(UnsubscribeSemanticError::PayloadTooShort(length)) => {
                    return Err(MqttError::InvalidUnsubscribePayloadLength(length));
                }
                Err(UnsubscribeSemanticError::InvalidPacketIdentifier(id)) => {
                    return Err(MqttError::InvalidPacketIdentifier(id));
                }
                Err(UnsubscribeSemanticError::InvalidTopicFilter) => {
                    return Err(MqttError::InvalidUnsubscribeTopicFilter);
                }
                Err(UnsubscribeSemanticError::MalformedUtf8) => {
                    return Err(MqttError::MalformedUtf8String);
                }
            },
            MqttPacketType::Puback | MqttPacketType::Unsuback => {
                let id = u16::from_be_bytes([payload[0], payload[1]]);
                if id == 0 {
                    return Err(MqttError::InvalidPacketIdentifier(id));
                }
                packet_id = Some(id);
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
    let start_offset = offset;
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

    let encoded_len = offset - start_offset;
    let minimum_len = if value < 128 {
        1
    } else if value < 128 * 128 {
        2
    } else if value < 128 * 128 * 128 {
        3
    } else {
        4
    };
    if encoded_len != minimum_len {
        return Err(MqttError::InvalidRemainingLength);
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
