from pathlib import Path

path = Path("src/lldp.rs")
text = path.read_text()

old = "const LLDP_TLV_MAX_VALUE_LEN: usize = 0x01FF;\n"
new = "const LLDP_TLV_MAX_TYPE: u8 = 0x7F;\nconst LLDP_TLV_MAX_VALUE_LEN: usize = 0x01FF;\n"
assert old in text
text = text.replace(old, new, 1)

old = '''    pub fn serialize(&self) -> Vec<u8> {\n        self.try_serialize()\n            .expect("LLDP TLV value must fit the 9-bit length field")\n    }\n\n    pub fn try_serialize(&self) -> Result<Vec<u8>, LldpSerializeError> {\n        let len = self.value.len();\n'''
new = '''    pub fn serialize(&self) -> Vec<u8> {\n        self.try_serialize()\n            .expect("LLDP TLV type and value must fit the wire header")\n    }\n\n    pub fn try_serialize(&self) -> Result<Vec<u8>, LldpSerializeError> {\n        if self.tlv_type > LLDP_TLV_MAX_TYPE {\n            return Err(LldpSerializeError::TlvTypeOutOfRange {\n                tlv_type: self.tlv_type,\n                max: LLDP_TLV_MAX_TYPE,\n            });\n        }\n\n        let len = self.value.len();\n'''
assert old in text
text = text.replace(old, new, 1)

old = "        let hdr = (((self.tlv_type as u16) & 0x7F) << 9) | (len as u16);\n"
new = "        let hdr = ((self.tlv_type as u16) << 9) | (len as u16);\n"
assert old in text
text = text.replace(old, new, 1)

old = '''pub enum LldpSerializeError {\n    TlvValueTooLong {\n'''
new = '''pub enum LldpSerializeError {\n    TlvTypeOutOfRange {\n        tlv_type: u8,\n        max: u8,\n    },\n    TlvValueTooLong {\n'''
assert old in text
text = text.replace(old, new, 1)

old = '''        match self {\n            LldpSerializeError::TlvValueTooLong {\n'''
new = '''        match self {\n            LldpSerializeError::TlvTypeOutOfRange { tlv_type, max } => write!(\n                f,\n                "LLDP TLV type {} exceeds the {} maximum representable by the 7-bit type field",\n                tlv_type, max\n            ),\n            LldpSerializeError::TlvValueTooLong {\n'''
assert old in text
text = text.replace(old, new, 1)

marker = '''    #[test]\n    fn test_tlv_511_byte_value_roundtrips() {\n'''
tests = '''    #[test]\n    fn test_tlv_type_127_roundtrips() {\n        let tlv = LldpTlv {\n            tlv_type: LLDP_TLV_MAX_TYPE,\n            value: vec![0x5a],\n        };\n\n        let raw = tlv.try_serialize().unwrap();\n        assert_eq!((u16::from_be_bytes([raw[0], raw[1]]) >> 9) as u8, LLDP_TLV_MAX_TYPE);\n\n        let (parsed, consumed) = LldpTlv::parse(&raw).unwrap();\n        assert_eq!(consumed, raw.len());\n        assert_eq!(parsed, tlv);\n    }\n\n    #[test]\n    fn test_tlv_type_128_is_rejected() {\n        let tlv = LldpTlv {\n            tlv_type: LLDP_TLV_MAX_TYPE + 1,\n            value: Vec::new(),\n        };\n\n        assert_eq!(\n            tlv.try_serialize(),\n            Err(LldpSerializeError::TlvTypeOutOfRange {\n                tlv_type: LLDP_TLV_MAX_TYPE + 1,\n                max: LLDP_TLV_MAX_TYPE,\n            })\n        );\n    }\n\n    #[test]\n    fn test_tlv_type_255_is_rejected_instead_of_wrapping() {\n        let tlv = LldpTlv {\n            tlv_type: u8::MAX,\n            value: vec![0x01],\n        };\n\n        assert_eq!(\n            tlv.try_serialize(),\n            Err(LldpSerializeError::TlvTypeOutOfRange {\n                tlv_type: u8::MAX,\n                max: LLDP_TLV_MAX_TYPE,\n            })\n        );\n    }\n\n'''
assert marker in text
text = text.replace(marker, tests + marker, 1)

path.write_text(text)
