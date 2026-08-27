use toy_tcpip::lldp::{
    LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED, LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME,
    LLDP_TLV_CHASSIS_ID, LLDP_TLV_END_OF_LLDPDU, LLDP_TLV_PORT_ID, LLDP_TLV_SYSTEM_NAME,
    LLDP_TLV_TTL, LldpError, LldpPacket, LldpTlv,
};

fn tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
    LldpTlv {
        tlv_type,
        value: value.to_vec(),
    }
    .serialize()
}

fn chassis() -> Vec<u8> {
    let mut value = vec![LLDP_CHASSIS_ID_SUBTYPE_LOCALLY_ASSIGNED];
    value.extend_from_slice(b"switch-a");
    tlv(LLDP_TLV_CHASSIS_ID, &value)
}

fn port() -> Vec<u8> {
    let mut value = vec![LLDP_PORT_ID_SUBTYPE_INTERFACE_NAME];
    value.extend_from_slice(b"eth0");
    tlv(LLDP_TLV_PORT_ID, &value)
}

fn ttl() -> Vec<u8> {
    tlv(LLDP_TLV_TTL, &120u16.to_be_bytes())
}

fn end() -> Vec<u8> {
    tlv(LLDP_TLV_END_OF_LLDPDU, &[])
}

#[test]
fn valid_mandatory_sequence_with_optional_tlv_is_accepted() {
    let mut raw = chassis();
    raw.extend(port());
    raw.extend(ttl());
    raw.extend(tlv(LLDP_TLV_SYSTEM_NAME, b"edge-a"));
    raw.extend(end());

    let parsed = LldpPacket::parse(&raw).unwrap();
    assert_eq!(parsed.chassis_id, "switch-a");
    assert_eq!(parsed.port_id, "eth0");
    assert_eq!(parsed.ttl, 120);
    assert_eq!(parsed.system_name.as_deref(), Some("edge-a"));
}

#[test]
fn port_id_before_chassis_id_is_rejected() {
    let mut raw = port();
    raw.extend(chassis());
    raw.extend(ttl());
    raw.extend(end());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidMandatoryTlvOrder {
            expected: "Chassis ID",
            found: LLDP_TLV_PORT_ID,
        })
    );
}

#[test]
fn ttl_before_port_id_is_rejected() {
    let mut raw = chassis();
    raw.extend(ttl());
    raw.extend(port());
    raw.extend(end());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidMandatoryTlvOrder {
            expected: "Port ID",
            found: LLDP_TLV_TTL,
        })
    );
}

#[test]
fn optional_tlv_before_mandatory_prefix_is_complete_is_rejected() {
    let mut raw = chassis();
    raw.extend(tlv(LLDP_TLV_SYSTEM_NAME, b"edge-a"));
    raw.extend(port());
    raw.extend(ttl());
    raw.extend(end());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidMandatoryTlvOrder {
            expected: "Port ID",
            found: LLDP_TLV_SYSTEM_NAME,
        })
    );
}

#[test]
fn duplicate_mandatory_tlv_is_rejected() {
    let mut raw = chassis();
    raw.extend(chassis());
    raw.extend(port());
    raw.extend(ttl());
    raw.extend(end());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidMandatoryTlvOrder {
            expected: "Port ID",
            found: LLDP_TLV_CHASSIS_ID,
        })
    );
}

#[test]
fn end_before_all_mandatory_tlvs_reports_missing_next_tlv() {
    let mut raw = chassis();
    raw.extend(port());
    raw.extend(end());

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::MissingMandatoryTlv("TTL"))
    );
}

#[test]
fn packet_without_end_of_lldpdu_is_rejected() {
    let mut raw = chassis();
    raw.extend(port());
    raw.extend(ttl());

    assert_eq!(LldpPacket::parse(&raw), Err(LldpError::MissingEndOfLldpdu));
}

#[test]
fn ethernet_padding_after_end_remains_accepted() {
    let mut raw = chassis();
    raw.extend(port());
    raw.extend(ttl());
    raw.extend(end());
    raw.extend_from_slice(&[0, 0, 0, 0, 0, 0]);

    assert!(LldpPacket::parse(&raw).is_ok());
}
