use toy_tcpip::lldp::{
    LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME,
    LLDP_TLV_CHASSIS_ID, LLDP_TLV_PORT_ID, LldpError, LldpPacket, LldpTlv,
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
fn packet_parsing_strips_identifier_subtypes() {
    let mut raw = LldpTlv {
        tlv_type: LLDP_TLV_CHASSIS_ID,
        value: [vec![4], b"00:11:22:33:44:55".to_vec()].concat(),
    }
    .serialize();
    raw.extend(mandatory_tail());

    let packet = LldpPacket::parse(&raw).unwrap();
    assert_eq!(packet.chassis_id, "00:11:22:33:44:55");
    assert_eq!(packet.port_id, "eth0");
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
