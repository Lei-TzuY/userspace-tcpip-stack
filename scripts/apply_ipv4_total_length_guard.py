from pathlib import Path

path = Path('src/ipv4.rs')
text = path.read_text()

old_variant = '''    TotalLengthMismatch { declared: usize, available: usize },\n    InvalidChecksum { computed: u16, found: u16 },\n'''
new_variant = '''    TotalLengthMismatch { declared: usize, available: usize },\n    TotalLengthSmallerThanHeader {\n        total_length: usize,\n        header_length: usize,\n    },\n    InvalidChecksum { computed: u16, found: u16 },\n'''
if 'TotalLengthSmallerThanHeader' not in text:
    if old_variant not in text:
        raise SystemExit('Ipv4Error variant marker not found')
    text = text.replace(old_variant, new_variant, 1)

old_display = '''            Ipv4Error::TotalLengthMismatch {\n                declared,\n                available,\n            } => {\n                write!(\n                    f,\n                    "IPv4 total length {} exceeds available data {}",\n                    declared, available\n                )\n            }\n            Ipv4Error::InvalidChecksum { computed, found } => {\n'''
new_display = '''            Ipv4Error::TotalLengthMismatch {\n                declared,\n                available,\n            } => {\n                write!(\n                    f,\n                    "IPv4 total length {} exceeds available data {}",\n                    declared, available\n                )\n            }\n            Ipv4Error::TotalLengthSmallerThanHeader {\n                total_length,\n                header_length,\n            } => {\n                write!(\n                    f,\n                    "IPv4 total length {} is smaller than header length {}",\n                    total_length, header_length\n                )\n            }\n            Ipv4Error::InvalidChecksum { computed, found } => {\n'''
if old_display in text:
    text = text.replace(old_display, new_display, 1)
elif 'total length {} is smaller than header length {}' not in text:
    raise SystemExit('Ipv4Error Display marker not found')

old_length = '''        let dscp_ecn = data[1];\n        let total_length = u16::from_be_bytes([data[2], data[3]]);\n        if (total_length as usize) > data.len() {\n            return Err(Ipv4Error::TotalLengthMismatch {\n                declared: total_length as usize,\n                available: data.len(),\n            });\n        }\n\n        let identification = u16::from_be_bytes([data[4], data[5]]);\n'''
new_length = '''        let dscp_ecn = data[1];\n        let total_length = u16::from_be_bytes([data[2], data[3]]);\n        if (total_length as usize) < header_len {\n            return Err(Ipv4Error::TotalLengthSmallerThanHeader {\n                total_length: total_length as usize,\n                header_length: header_len,\n            });\n        }\n        if (total_length as usize) > data.len() {\n            return Err(Ipv4Error::TotalLengthMismatch {\n                declared: total_length as usize,\n                available: data.len(),\n            });\n        }\n\n        let identification = u16::from_be_bytes([data[4], data[5]]);\n'''
if 'if (total_length as usize) < header_len' not in text:
    if old_length not in text:
        raise SystemExit('total-length validation marker not found')
    text = text.replace(old_length, new_length, 1)

insert_before = '''    #[test]\n    fn test_ipv4_packet_build_and_parse() {\n'''
tests = '''    #[test]\n    fn parse_rejects_total_length_smaller_than_minimum_header() {\n        let mut raw = vec![0u8; IPV4_MIN_HEADER_LEN];\n        raw[0] = 0x45;\n        raw[2..4].copy_from_slice(&19u16.to_be_bytes());\n\n        assert_eq!(\n            Ipv4Packet::parse(&raw, false),\n            Err(Ipv4Error::TotalLengthSmallerThanHeader {\n                total_length: 19,\n                header_length: IPV4_MIN_HEADER_LEN,\n            })\n        );\n    }\n\n    #[test]\n    fn parse_rejects_total_length_smaller_than_options_header() {\n        let mut raw = vec![0u8; 24];\n        raw[0] = 0x46;\n        raw[2..4].copy_from_slice(&20u16.to_be_bytes());\n\n        assert_eq!(\n            Ipv4Packet::parse(&raw, false),\n            Err(Ipv4Error::TotalLengthSmallerThanHeader {\n                total_length: 20,\n                header_length: 24,\n            })\n        );\n    }\n\n    #[test]\n    fn parse_accepts_total_length_equal_to_options_header() {\n        let mut raw = vec![0u8; 24];\n        raw[0] = 0x46;\n        raw[2..4].copy_from_slice(&24u16.to_be_bytes());\n        raw[8] = 64;\n        raw[9] = IP_PROTO_UDP;\n        raw[12..16].copy_from_slice(&Ipv4Address::new(192, 0, 2, 1).0);\n        raw[16..20].copy_from_slice(&Ipv4Address::new(198, 51, 100, 1).0);\n        raw[20..24].copy_from_slice(&[1, 1, 1, 0]);\n        let checksum = compute_checksum(&raw[..24]);\n        raw[10..12].copy_from_slice(&checksum.to_be_bytes());\n\n        let parsed = Ipv4Packet::parse(&raw, true).unwrap();\n        assert_eq!(parsed.header.ihl, 6);\n        assert_eq!(parsed.header.total_length, 24);\n        assert!(parsed.payload.is_empty());\n    }\n\n'''
if 'parse_rejects_total_length_smaller_than_minimum_header' not in text:
    if insert_before not in text:
        raise SystemExit('test insertion marker not found')
    text = text.replace(insert_before, tests + insert_before, 1)

path.write_text(text)
