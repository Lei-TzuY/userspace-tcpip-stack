use toy_tcpip::mqtt::{MqttError, MqttPacket, MqttPacketType, MqttSerializeError};

fn wire(packet_type: MqttPacketType, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut raw = vec![(packet_type as u8) << 4, payload.len() as u8];
    raw.extend_from_slice(payload);
    raw
}

fn packet(packet_type: MqttPacketType, payload: &[u8]) -> MqttPacket {
    MqttPacket {
        packet_type,
        flags: 0,
        topic: None,
        packet_id: None,
        payload: payload.to_vec(),
    }
}

fn parse_length_error(packet_type: MqttPacketType, length: usize, expected: usize) -> MqttError {
    MqttError::InvalidPayloadLength {
        packet_type,
        length,
        expected,
    }
}

fn serialize_length_error(
    packet_type: MqttPacketType,
    length: usize,
    expected: usize,
) -> MqttSerializeError {
    MqttSerializeError::InvalidPayloadLength {
        packet_type,
        length,
        expected,
    }
}

#[test]
fn parser_rejects_payload_on_zero_length_control_packets() {
    for packet_type in [
        MqttPacketType::Pingreq,
        MqttPacketType::Pingresp,
        MqttPacketType::Disconnect,
    ] {
        assert_eq!(
            MqttPacket::parse(&wire(packet_type, &[0xaa])),
            Err(parse_length_error(packet_type, 1, 0))
        );
    }
}

#[test]
fn parser_requires_two_byte_ack_payloads() {
    for packet_type in [
        MqttPacketType::Connack,
        MqttPacketType::Puback,
        MqttPacketType::Unsuback,
    ] {
        assert_eq!(
            MqttPacket::parse(&wire(packet_type, &[])),
            Err(parse_length_error(packet_type, 0, 2))
        );
        assert_eq!(
            MqttPacket::parse(&wire(packet_type, &[0, 1, 2])),
            Err(parse_length_error(packet_type, 3, 2))
        );
    }
}

#[test]
fn parser_accepts_valid_fixed_control_lengths() {
    assert!(MqttPacket::parse(&wire(MqttPacketType::Connack, &[0, 0])).is_ok());
    assert!(MqttPacket::parse(&wire(MqttPacketType::Pingreq, &[])).is_ok());
    assert!(MqttPacket::parse(&wire(MqttPacketType::Pingresp, &[])).is_ok());
    assert!(MqttPacket::parse(&wire(MqttPacketType::Disconnect, &[])).is_ok());
}

#[test]
fn parser_extracts_ack_packet_identifiers() {
    let puback = MqttPacket::parse(&wire(MqttPacketType::Puback, &[0x12, 0x34])).unwrap();
    assert_eq!(puback.packet_id, Some(0x1234));
    let unsuback = MqttPacket::parse(&wire(MqttPacketType::Unsuback, &[0xab, 0xcd])).unwrap();
    assert_eq!(unsuback.packet_id, Some(0xabcd));
}

#[test]
fn parser_rejects_zero_ack_packet_identifiers() {
    for packet_type in [MqttPacketType::Puback, MqttPacketType::Unsuback] {
        assert_eq!(
            MqttPacket::parse(&wire(packet_type, &[0, 0])),
            Err(MqttError::InvalidPacketIdentifier(0))
        );
    }
}

#[test]
fn serializer_rejects_invalid_fixed_control_lengths() {
    for packet_type in [
        MqttPacketType::Pingreq,
        MqttPacketType::Pingresp,
        MqttPacketType::Disconnect,
    ] {
        assert_eq!(
            packet(packet_type, &[1]).try_serialize(),
            Err(serialize_length_error(packet_type, 1, 0))
        );
    }
    for packet_type in [
        MqttPacketType::Connack,
        MqttPacketType::Puback,
        MqttPacketType::Unsuback,
    ] {
        assert_eq!(
            packet(packet_type, &[0]).try_serialize(),
            Err(serialize_length_error(packet_type, 1, 2))
        );
    }
}

#[test]
fn serializer_rejects_zero_ack_packet_identifiers() {
    for packet_type in [MqttPacketType::Puback, MqttPacketType::Unsuback] {
        assert_eq!(
            packet(packet_type, &[0, 0]).try_serialize(),
            Err(MqttSerializeError::InvalidPacketIdentifier(0))
        );
    }
}

#[test]
fn serializer_preserves_valid_fixed_control_packets() {
    assert_eq!(
        packet(MqttPacketType::Pingreq, &[])
            .try_serialize()
            .unwrap(),
        vec![0xc0, 0]
    );
    assert_eq!(
        packet(MqttPacketType::Puback, &[0x12, 0x34])
            .try_serialize()
            .unwrap(),
        vec![0x40, 2, 0x12, 0x34]
    );
}
