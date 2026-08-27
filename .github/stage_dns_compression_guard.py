from pathlib import Path

path = Path('src/dns.rs')
text = path.read_text()

old_enum = '''pub enum DnsError {
    PacketTooShort(usize),
    InvalidLabel(String),
    UnsupportedFormat,
}
'''
new_enum = '''pub enum DnsError {
    PacketTooShort(usize),
    InvalidLabel(String),
    InvalidCompressionPointer(usize),
    CompressionLoop,
    ReservedLabelType(u8),
    NameTooLong,
    UnsupportedFormat,
}
'''
assert old_enum in text
text = text.replace(old_enum, new_enum, 1)

old_display = '''            DnsError::InvalidLabel(l) => write!(f, "Invalid DNS label format: {}", l),
            DnsError::UnsupportedFormat => write!(f, "Unsupported DNS record format"),
'''
new_display = '''            DnsError::InvalidLabel(l) => write!(f, "Invalid DNS label format: {}", l),
            DnsError::InvalidCompressionPointer(offset) => {
                write!(f, "DNS compression pointer {} is outside the packet", offset)
            }
            DnsError::CompressionLoop => write!(f, "DNS compression pointer loop detected"),
            DnsError::ReservedLabelType(value) => {
                write!(f, "Reserved DNS label type 0x{:02x}", value)
            }
            DnsError::NameTooLong => write!(f, "Expanded DNS name exceeds 255 octets"),
            DnsError::UnsupportedFormat => write!(f, "Unsupported DNS record format"),
'''
assert old_display in text
text = text.replace(old_display, new_display, 1)

old_decode = '''fn decode_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;

    let mut hops = 0;
    while offset < data.len() && hops < 20 {
        hops += 1;
        let len = data[offset];
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        // Pointer compression: 0b11xxxxxx
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= data.len() {
                return Err(DnsError::PacketTooShort(data.len()));
            }
            let ptr_offset = (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
            if !jumped {
                return_offset = offset + 2;
                jumped = true;
            }
            offset = ptr_offset;
            continue;
        }

        offset += 1;
        let end = offset + (len as usize);
        if end > data.len() {
            return Err(DnsError::PacketTooShort(data.len()));
        }

        let label = String::from_utf8_lossy(&data[offset..end]).to_string();
        labels.push(label);
        offset = end;
    }

    Ok((labels.join("."), return_offset))
}
'''
new_decode = '''fn decode_qname(data: &[u8], mut offset: usize) -> Result<(String, usize), DnsError> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut return_offset = offset;
    let mut visited_offsets = std::collections::HashSet::new();
    // RFC 1035 section 2.3.4 limits a complete domain name, including label
    // length octets and the root terminator, to 255 octets.
    let mut expanded_wire_len = 1usize;

    loop {
        if offset >= data.len() {
            return Err(DnsError::PacketTooShort(data.len()));
        }
        if !visited_offsets.insert(offset) {
            return Err(DnsError::CompressionLoop);
        }

        let len = data[offset];
        if len == 0 {
            if !jumped {
                return_offset = offset + 1;
            }
            break;
        }

        match len & 0xC0 {
            // Pointer compression: 0b11xxxxxx
            0xC0 => {
                if offset + 1 >= data.len() {
                    return Err(DnsError::PacketTooShort(data.len()));
                }
                let ptr_offset =
                    (((len & 0x3F) as usize) << 8) | (data[offset + 1] as usize);
                if ptr_offset >= data.len() {
                    return Err(DnsError::InvalidCompressionPointer(ptr_offset));
                }
                if !jumped {
                    return_offset = offset + 2;
                    jumped = true;
                }
                offset = ptr_offset;
                continue;
            }
            // Ordinary RFC 1035 label. The top two bits must be zero, which
            // also caps the label payload at 63 octets.
            0x00 => {}
            reserved => return Err(DnsError::ReservedLabelType(reserved)),
        }

        let label_len = len as usize;
        expanded_wire_len = expanded_wire_len
            .checked_add(1 + label_len)
            .ok_or(DnsError::NameTooLong)?;
        if expanded_wire_len > 255 {
            return Err(DnsError::NameTooLong);
        }

        offset += 1;
        let end = offset + label_len;
        if end > data.len() {
            return Err(DnsError::PacketTooShort(data.len()));
        }

        let label = String::from_utf8_lossy(&data[offset..end]).to_string();
        labels.push(label);
        offset = end;
    }

    Ok((labels.join("."), return_offset))
}
'''
assert old_decode in text
text = text.replace(old_decode, new_decode, 1)

marker = '''    #[test]
    fn test_dns_query_and_response_roundtrip() {
'''
insert = '''    fn query_header() -> Vec<u8> {
        let mut raw = vec![0u8; 12];
        raw[4..6].copy_from_slice(&1u16.to_be_bytes());
        raw
    }

    #[test]
    fn rejects_self_referential_compression_pointer() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0x0c]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::CompressionLoop));
    }

    #[test]
    fn rejects_multi_pointer_compression_cycle() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0x0e, 0xc0, 0x0c]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::CompressionLoop));
    }

    #[test]
    fn rejects_compression_pointer_outside_packet() {
        let mut raw = query_header();
        raw.extend_from_slice(&[0xc0, 0xff]);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(
            DnsMessage::parse(&raw),
            Err(DnsError::InvalidCompressionPointer(255))
        );
    }

    #[test]
    fn rejects_reserved_dns_label_type() {
        let mut raw = query_header();
        raw.push(0x40);
        raw.extend_from_slice(&[0u8; 64]);
        raw.push(0);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());

        assert_eq!(
            DnsMessage::parse(&raw),
            Err(DnsError::ReservedLabelType(0x40))
        );
    }

    fn query_with_label_lengths(lengths: &[usize]) -> Vec<u8> {
        let mut raw = query_header();
        for &len in lengths {
            raw.push(len as u8);
            raw.extend(std::iter::repeat_n(b'a', len));
        }
        raw.push(0);
        raw.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        raw.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        raw
    }

    #[test]
    fn rejects_expanded_name_over_255_octets() {
        let raw = query_with_label_lengths(&[63, 63, 63, 62]);
        assert_eq!(DnsMessage::parse(&raw), Err(DnsError::NameTooLong));
    }

    #[test]
    fn accepts_expanded_name_at_255_octet_boundary() {
        let raw = query_with_label_lengths(&[63, 63, 63, 61]);
        let parsed = DnsMessage::parse(&raw).unwrap();
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name.len(), 63 + 1 + 63 + 1 + 63 + 1 + 61);
    }

'''
assert marker in text
text = text.replace(marker, insert + marker, 1)

path.write_text(text)
