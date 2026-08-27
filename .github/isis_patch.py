from pathlib import Path

p = Path("src/isis.rs")
s = p.read_text()

old = """    InvalidPduType(u8),\n    InvalidTlvLength,\n"""
new = """    InvalidPduType(u8),\n    InvalidPduLength(u16),\n    InvalidTlvLength,\n"""
if s.count(old) != 1:
    raise SystemExit("error enum anchor mismatch")
s = s.replace(old, new)

old = """            IsisError::InvalidPduType(t) => write!(f, \"Unsupported IS-IS PDU type: {}\", t),\n            IsisError::InvalidTlvLength => write!(f, \"Invalid IS-IS TLV length field\"),\n"""
new = """            IsisError::InvalidPduType(t) => write!(f, \"Unsupported IS-IS PDU type: {}\", t),\n            IsisError::InvalidPduLength(l) => write!(f, \"Invalid IS-IS PDU length: {}\", l),\n            IsisError::InvalidTlvLength => write!(f, \"Invalid IS-IS TLV length field\"),\n"""
if s.count(old) != 1:
    raise SystemExit("display anchor mismatch")
s = s.replace(old, new)

old = """        let holding_time = u16::from_be_bytes([data[15], data[16]]);\n        let _pdu_length = u16::from_be_bytes([data[17], data[18]]);\n        let priority = data[19] & 0x7F;\n\n        let mut lan_id = [0u8; 7];\n        lan_id.copy_from_slice(&data[20..27]);\n\n        let mut tlvs = Vec::new();\n        let mut offset = 27;\n        while offset < data.len() {\n            if offset + 2 > data.len() {\n                break;\n            }\n            let tlv_type = data[offset];\n            let tlv_len = data[offset + 1] as usize;\n            if offset + 2 + tlv_len > data.len() {\n                return Err(IsisError::InvalidTlvLength);\n            }\n            let value = data[offset + 2..offset + 2 + tlv_len].to_vec();\n"""
new = """        let holding_time = u16::from_be_bytes([data[15], data[16]]);\n        let pdu_length = u16::from_be_bytes([data[17], data[18]]);\n        let pdu_len = pdu_length as usize;\n        if pdu_len < min_len || pdu_len > data.len() {\n            return Err(IsisError::InvalidPduLength(pdu_length));\n        }\n        let pdu = &data[..pdu_len];\n        let priority = pdu[19] & 0x7F;\n\n        let mut lan_id = [0u8; 7];\n        lan_id.copy_from_slice(&pdu[20..27]);\n\n        let mut tlvs = Vec::new();\n        let mut offset = 27;\n        while offset < pdu.len() {\n            if offset + 2 > pdu.len() {\n                return Err(IsisError::InvalidTlvLength);\n            }\n            let tlv_type = pdu[offset];\n            let tlv_len = pdu[offset + 1] as usize;\n            if offset + 2 + tlv_len > pdu.len() {\n                return Err(IsisError::InvalidTlvLength);\n            }\n            let value = pdu[offset + 2..offset + 2 + tlv_len].to_vec();\n"""
if s.count(old) != 1:
    raise SystemExit("parse framing anchor mismatch")
s = s.replace(old, new)

marker = """    #[test]\n    fn test_isis_lan_hello_roundtrip() {\n"""
if s.count(marker) != 1:
    raise SystemExit("test marker mismatch")
tests = r'''    #[test]
    fn test_isis_rejects_declared_pdu_length_below_fixed_header() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw[17..19].copy_from_slice(&26u16.to_be_bytes());
        assert_eq!(IsisHelloPacket::parse(&raw), Err(IsisError::InvalidPduLength(26)));
    }

    #[test]
    fn test_isis_rejects_declared_pdu_length_beyond_packet() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        let declared = raw.len() as u16 + 1;
        raw[17..19].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(
            IsisHelloPacket::parse(&raw),
            Err(IsisError::InvalidPduLength(declared))
        );
    }

    #[test]
    fn test_isis_ignores_bytes_after_declared_pdu_length() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        let parsed = IsisHelloPacket::parse(&raw).expect("Ethernet padding must be outside PDU");
        assert_eq!(parsed.tlvs, hello.tlvs);
    }

    #[test]
    fn test_isis_rejects_partial_tlv_header_within_declared_pdu() {
        let hello = IsisHelloPacket::build_l1_lan_hello(
            [0, 0, 0, 0, 0, 1],
            &[0x49, 0x00, 0x01],
            Ipv4Address::new(192, 0, 2, 1),
        );
        let mut raw = hello.serialize();
        raw.push(ISIS_TLV_PROTOCOLS_SUPPORTED);
        let declared = raw.len() as u16;
        raw[17..19].copy_from_slice(&declared.to_be_bytes());
        assert_eq!(IsisHelloPacket::parse(&raw), Err(IsisError::InvalidTlvLength));
    }

'''
s = s.replace(marker, tests + marker)
p.write_text(s)
