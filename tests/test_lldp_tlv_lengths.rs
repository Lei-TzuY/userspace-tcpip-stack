use toy_tcpip::lldp::{
    LLDP_TLV_CHASSIS_ID, LLDP_TLV_END_OF_LLDPDU, LLDP_TLV_PORT_ID, LLDP_TLV_TTL, LldpError,
    LldpPacket, LldpTlv,
};

fn tlv(tlv_type: u8, value: &[u8]) -> Vec<u8> {
    LldpTlv {
        tlv_type,
        value: value.to_vec(),
    }
    .serialize()
}

fn mandatory_prefix() -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend(tlv(LLDP_TLV_CHASSIS_ID, b"chassis-1"));
    raw.extend(tlv(LLDP_TLV_PORT_ID, b"port-1"));
    raw
}

#[test]
fn exact_two_byte_ttl_is_accepted() {
    let mut raw = mandatory_prefix();
    raw.extend(tlv(LLDP_TLV_TTL, &120u16.to_be_bytes()));
    raw.extend(tlv(LLDP_TLV_END_OF_LLDPDU, &[]));

    let parsed = LldpPacket::parse(&raw).unwrap();
    assert_eq!(parsed.ttl, 120);
}

#[test]
fn one_byte_ttl_is_rejected() {
    let mut raw = mandatory_prefix();
    raw.extend(tlv(LLDP_TLV_TTL, &[120]));
    raw.extend(tlv(LLDP_TLV_END_OF_LLDPDU, &[]));

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidTlvLength {
            tlv_type: LLDP_TLV_TTL,
            length: 1,
        })
    );
}

#[test]
fn overlong_ttl_is_rejected_instead_of_truncating_value() {
    let mut raw = mandatory_prefix();
    raw.extend(tlv(LLDP_TLV_TTL, &[0, 120, 0xaa]));
    raw.extend(tlv(LLDP_TLV_END_OF_LLDPDU, &[]));

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidTlvLength {
            tlv_type: LLDP_TLV_TTL,
            length: 3,
        })
    );
}

#[test]
fn end_of_lldpdu_requires_zero_length() {
    let mut raw = mandatory_prefix();
    raw.extend(tlv(LLDP_TLV_TTL, &120u16.to_be_bytes()));
    raw.extend(tlv(LLDP_TLV_END_OF_LLDPDU, &[0xaa]));

    assert_eq!(
        LldpPacket::parse(&raw),
        Err(LldpError::InvalidTlvLength {
            tlv_type: LLDP_TLV_END_OF_LLDPDU,
            length: 1,
        })
    );
}

#[test]
fn zero_length_end_still_allows_ethernet_padding() {
    let mut raw = mandatory_prefix();
    raw.extend(tlv(LLDP_TLV_TTL, &120u16.to_be_bytes()));
    raw.extend(tlv(LLDP_TLV_END_OF_LLDPDU, &[]));
    raw.extend_from_slice(&[0, 0, 0, 0]);

    let parsed = LldpPacket::parse(&raw).unwrap();
    assert_eq!(parsed.ttl, 120);
}
