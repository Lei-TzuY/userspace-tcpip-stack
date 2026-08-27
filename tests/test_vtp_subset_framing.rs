use toy_tcpip::vtp::{VtpError, VtpPacket, VtpVlanInfo};

fn empty_subset() -> Vec<u8> {
    VtpPacket::build_subset("LAB", 7, &[]).serialize()
}

#[test]
fn empty_subset_remains_valid() {
    let raw = empty_subset();
    let parsed = VtpPacket::parse(&raw).unwrap();
    match parsed {
        VtpPacket::Subset(sub) => assert!(sub.vlans.is_empty()),
        _ => panic!("expected subset"),
    }
}

#[test]
fn declared_vlan_record_without_body_is_rejected() {
    let mut raw = empty_subset();
    raw.push(39);
    assert_eq!(VtpPacket::parse(&raw), Err(VtpError::InvalidLength));
}

#[test]
fn vlan_record_shorter_than_fixed_fields_is_rejected() {
    let mut raw = empty_subset();
    raw.extend_from_slice(&[6, 0, 1, 0, 10, 0, 0]);
    assert_eq!(VtpPacket::parse(&raw), Err(VtpError::InvalidLength));
}

#[test]
fn vlan_name_length_cannot_escape_its_record() {
    let mut raw = empty_subset();
    raw.extend_from_slice(&[7, 0, 1, 0, 10, 0x05, 0xdc, 1]);
    assert_eq!(VtpPacket::parse(&raw), Err(VtpError::InvalidLength));
}

#[test]
fn malformed_second_record_does_not_return_partial_subset() {
    let vlan = VtpVlanInfo {
        vlan_id: 10,
        vlan_name: "Sales".to_string(),
        status: 0,
    };
    let mut raw = VtpPacket::build_subset("LAB", 7, &[vlan]).serialize();
    raw.push(39);
    assert_eq!(VtpPacket::parse(&raw), Err(VtpError::InvalidLength));
}

#[test]
fn long_vlan_names_declare_only_the_32_bytes_written_on_wire() {
    let vlan = VtpVlanInfo {
        vlan_id: 20,
        vlan_name: "x".repeat(40),
        status: 0,
    };
    let raw = VtpPacket::build_subset("LAB", 8, &[vlan]).serialize();
    assert_eq!(raw[47], 32);

    let parsed = VtpPacket::parse(&raw).unwrap();
    match parsed {
        VtpPacket::Subset(sub) => {
            assert_eq!(sub.vlans.len(), 1);
            assert_eq!(sub.vlans[0].vlan_name, "x".repeat(32));
        }
        _ => panic!("expected subset"),
    }
}
