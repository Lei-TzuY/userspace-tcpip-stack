from pathlib import Path

p = Path('src/vtp.rs')
s = p.read_text()

old = '''pub enum VtpError {
    PacketTooShort(usize),
    InvalidCode(u8),
}'''
new = '''pub enum VtpError {
    PacketTooShort(usize),
    InvalidCode(u8),
    InvalidLength,
}'''
assert old in s
s = s.replace(old, new, 1)

old = '''            VtpError::InvalidCode(c) => write!(f, "Unknown VTP message code: {}", c),'''
new = '''            VtpError::InvalidCode(c) => write!(f, "Unknown VTP message code: {}", c),
            VtpError::InvalidLength => write!(f, "Invalid VTP subset record length"),'''
assert old in s
s = s.replace(old, new, 1)

old = '''                    v_buf.push(v.vlan_name.len() as u8);
                    let mut name_bytes = [0u8; 32];
                    let n_len = v.vlan_name.len().min(32);
                    name_bytes[..n_len].copy_from_slice(&v.vlan_name.as_bytes()[..n_len]);'''
new = '''                    let mut name_bytes = [0u8; 32];
                    let n_len = v.vlan_name.len().min(32);
                    v_buf.push(n_len as u8);
                    name_bytes[..n_len].copy_from_slice(&v.vlan_name.as_bytes()[..n_len]);'''
assert old in s
s = s.replace(old, new, 1)

old = '''                while offset < data.len() {
                    let v_len = data[offset] as usize;
                    if offset + 1 + v_len > data.len() || v_len < 7 {
                        break;
                    }

                    let status = data[offset + 1];
                    let vlan_id = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
                    let name_len = (data[offset + 7] as usize).min(32);

                    let name_str = if offset + 8 + name_len <= offset + 1 + v_len {
                        String::from_utf8_lossy(&data[offset + 8..offset + 8 + name_len])
                            .to_string()
                    } else {
                        format!("VLAN{:04}", vlan_id)
                    };

                    vlans.push(VtpVlanInfo {
                        vlan_id,
                        vlan_name: name_str,
                        status,
                    });

                    offset += 1 + v_len;
                }'''
new = '''                while offset < data.len() {
                    let v_len = data[offset] as usize;
                    let record_end = offset
                        .checked_add(1 + v_len)
                        .ok_or(VtpError::InvalidLength)?;
                    if v_len < 7 || record_end > data.len() {
                        return Err(VtpError::InvalidLength);
                    }

                    let status = data[offset + 1];
                    let vlan_id = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
                    let name_len = data[offset + 7] as usize;
                    let name_end = offset
                        .checked_add(8 + name_len)
                        .ok_or(VtpError::InvalidLength)?;
                    if name_len > 32 || name_end > record_end {
                        return Err(VtpError::InvalidLength);
                    }
                    let name_str =
                        String::from_utf8_lossy(&data[offset + 8..name_end]).to_string();

                    vlans.push(VtpVlanInfo {
                        vlan_id,
                        vlan_name: name_str,
                        status,
                    });

                    offset = record_end;
                }'''
assert old in s
s = s.replace(old, new, 1)
p.write_text(s)

Path('tests/test_vtp_subset_framing.rs').write_text(r'''use toy_tcpip::vtp::{VtpError, VtpPacket, VtpVlanInfo};

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
''')
