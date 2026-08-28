use toy_tcpip::lldp::{
    LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME,
    LLDP_TLV_CHASSIS_ID, LLDP_TLV_PORT_ID, LLDP_TLV_SYSTEM_NAME, LLDP_TLV_TTL, LldpError,
    LldpPacket, LldpTlv,
};

fn packet_with_system_name(value: Vec<u8>) -> Vec<u8> {
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
            value: [vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME], b"eth0".to_vec()].concat(),
        }
        .serialize(),
    );
    raw.extend(
        LldpTlv {
            tlv_type: LLDP_TLV_TTL,
            value: 120u16.to_be_bytes().to_vec(),
        }
        .serialize(),
    );
    raw.extend(
        LldpTlv {
            tlv_type: LLDP_TLV_SYSTEM_NAME,
            value,
        }
        .serialize(),
    );
    raw.extend_from_slice(&[0, 0]);
    raw
}

#[test]
fn packet_rejects_invalid_utf8_system_name() {
    let raw = packet_with_system_name(vec![0xff, 0xfe]);
    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidUtf8Identifier {
            tlv_type: LLDP_TLV_SYSTEM_NAME,
        })
    );
}

#[test]
fn packet_roundtrips_multibyte_utf8_system_name() {
    let packet = LldpPacket {
        chassis_id: "switch-a".to_string(),
        port_id: "eth0".to_string(),
        ttl: 120,
        system_name: Some("核心交換器-一".to_string()),
    };
    let raw = packet.serialize();
    let parsed = LldpPacket::parse(&raw).unwrap();
    assert_eq!(parsed.system_name, packet.system_name);
}
