use toy_tcpip::lldp::{
    LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS,
    LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME, LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS, LLDP_TLV_CHASSIS_ID,
    LLDP_TLV_PORT_ID, LldpError, LldpPacket, LldpTlv,
};

fn mandatory_tail() -> Vec<u8> {
    let mut raw = LldpTlv {
        tlv_type: LLDP_TLV_PORT_ID,
        value: [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
    }
    .serialize();
    raw.extend(
        LldpTlv {
            tlv_type: 3,
            value: 120u16.to_be_bytes().to_vec(),
        }
        .serialize(),
    );
    raw.extend_from_slice(&[0, 0]);
    raw
}

fn packet_with_identifiers(chassis_value: Vec<u8>, port_value: Vec<u8>) -> Vec<u8> {
    let mut raw = LldpTlv {
        tlv_type: LLDP_TLV_CHASSIS_ID,
        value: chassis_value,
    }
    .serialize();
    raw.extend(
        LldpTlv {
            tlv_type: LLDP_TLV_PORT_ID,
            value: port_value,
        }
        .serialize(),
    );
    raw.extend(
        LldpTlv {
            tlv_type: 3,
            value: 120u16.to_be_bytes().to_vec(),
        }
        .serialize(),
    );
    raw.extend_from_slice(&[0, 0]);
    raw
}

#[test]
fn packet_serialization_emits_identifier_subtypes() {
    let packet = LldpPacket {
        chassis_id: "switch-a".to_string(),
        port_id: "eth0".to_string(),
        ttl: 120,
        system_name: None,
    };

    let raw = packet.serialize();
    let (chassis, used) = LldpTlv::parse(&raw).unwrap();
    assert_eq!(chassis.tlv_type, LLDP_TLV_CHASSIS_ID);
    assert_eq!(chassis.value[0], LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED);
    assert_eq!(&chassis.value[1..], b"switch-a");

    let (port, _) = LldpTlv::parse(&raw[used..]).unwrap();
    assert_eq!(port.tlv_type, LLDP_TLV_PORT_ID);
    assert_eq!(port.value[0], LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME);
    assert_eq!(&port.value[1..], b"eth0");
}

#[test]
fn packet_parsing_strips_supported_text_subtypes() {
    let raw = packet_with_identifiers(
        [
            vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
            b"switch-a".to_vec(),
        ]
        .concat(),
        [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
    );

    let packet = LldpPacket::parse(&raw).unwrap();
    assert_eq!(packet.chassis_id, "switch-a");
    assert_eq!(packet.port_id, "eth0");
}

#[test]
fn packet_parses_chassis_mac_address_subtype() {
    let raw = packet_with_identifiers(
        vec![
            LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS,
            0x00,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
        ],
        [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
    );

    let packet = LldpPacket::parse(&raw).unwrap();
    assert_eq!(packet.chassis_id, "00:11:22:33:44:55");
}

#[test]
fn packet_parses_port_mac_address_subtype() {
    let raw = packet_with_identifiers(
        [
            vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
            b"switch-a".to_vec(),
        ]
        .concat(),
        vec![
            LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS,
            0xaa,
            0xbb,
            0xcc,
            0xdd,
            0xee,
            0xff,
        ],
    );

    let packet = LldpPacket::parse(&raw).unwrap();
    assert_eq!(packet.port_id, "aa:bb:cc:dd:ee:ff");
}

#[test]
fn packet_rejects_malformed_chassis_mac_length() {
    let raw = packet_with_identifiers(
        vec![LLDP_CHASSIS_ID_SUBTYPE_MAC_ADDRESS, 0x00, 0x11, 0x22],
        [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
    );

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidTlvLength {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            length: 4,
        })
    );
}

#[test]
fn packet_rejects_malformed_port_mac_length() {
    let raw = packet_with_identifiers(
        [
            vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
            b"switch-a".to_vec(),
        ]
        .concat(),
        vec![LLDP_PORT_ID_SUBTYPE_MAC_ADDRESS, 0xaa, 0xbb],
    );

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidTlvLength {
            tlv_type: LLDP_TLV_PORT_ID,
            length: 3,
        })
    );
}

#[test]
fn packet_rejects_unsupported_chassis_id_subtype() {
    let mut raw = LldpTlv {
        tlv_type: LLDP_TLV_CHASSIS_ID,
        value: [vec![5], b"192.0.2.1".to_vec()].concat(),
    }
    .serialize();
    raw.extend(mandatory_tail());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::UnsupportedIdentifierSubtype {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            subtype: 5,
            expected: LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED,
        })
    );
}

#[test]
fn packet_rejects_unsupported_port_id_subtype() {
    let raw = packet_with_identifiers(
        [
            vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
            b"switch-a".to_vec(),
        ]
        .concat(),
        [vec![1], b"uplink".to_vec()].concat(),
    );

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::UnsupportedIdentifierSubtype {
            tlv_type: LLDP_TLV_PORT_ID,
            subtype: 1,
            expected: LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME,
        })
    );
}

#[test]
fn packet_rejects_invalid_utf8_chassis_identifier() {
    let raw = packet_with_identifiers(
        vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, 0xff],
        [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
    );

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidUtf8Identifier {
            tlv_type: LLDP_TLV_CHASSIS_ID,
        })
    );
}

#[test]
fn packet_rejects_invalid_utf8_port_identifier() {
    let raw = packet_with_identifiers(
        [
            vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
            b"switch-a".to_vec(),
        ]
        .concat(),
        vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME, 0xff],
    );

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidUtf8Identifier {
            tlv_type: LLDP_TLV_PORT_ID,
        })
    );
}

#[test]
fn packet_roundtrips_multibyte_utf8_identifiers() {
    let packet = LldpPacket {
        chassis_id: "機櫃-一".to_string(),
        port_id: "乙太網路0".to_string(),
        ttl: 120,
        system_name: None,
    };

    let raw = packet.serialize();
    assert_eq!(LldpPacket::parse(&raw).unwrap(), packet);
}

#[test]
fn packet_rejects_chassis_id_without_identifier() {
    for value in [Vec::new(), vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED]] {
        let mut raw = LldpTlv {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            value: value.clone(),
        }
        .serialize();
        raw.extend(mandatory_tail());

        assert_eq!(
            LldpPacket::parse(&raw),
            Err(LldpError::InvalidTlvLength {
                tlv_type: LLDP_TLV_CHASSIS_ID,
                length: value.len(),
            })
        );
    }
}

#[test]
fn packet_rejects_port_id_without_identifier() {
    for value in [Vec::new(), vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME]] {
        let mut raw = LldpTlv {
            tlv_type: LLDP_TLV_CHASSIS_ID,
            value: [
                vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED],
                b"switch-a".to_vec(),
            ]
            .concat(),
        }
        .serialize();
        raw.extend(
            LldpTlv {
                tlv_type: LLDP_TLV_PORT_ID,
                value: value.clone(),
            }
            .serialize(),
        );
        raw.extend(
            LldpTlv {
                tlv_type: 3,
                value: 120u16.to_be_bytes().to_vec(),
            }
            .serialize(),
        );
        raw.extend_from_slice(&[0, 0]);

        assert_eq!(
            LldpPacket::parse(&raw),
            Err(LldpError::InvalidTlvLength {
                tlv_type: LLDP_TLV_PORT_ID,
                length: value.len(),
            })
        );
    }
}
