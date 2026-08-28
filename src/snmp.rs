//! Simple Network Management Protocol Version 2c (SNMPv2c - RFC 1901 / RFC 3416).
//!
//! Features ASN.1 / BER (Basic Encoding Rules) TLV parser & serializer,
//! SNMP message framing, and an in-memory MIB-II management instrumentation store.

use std::collections::HashMap;
use std::fmt;

pub const SNMP_PORT: u16 = 161;
pub const SNMP_TRAP_PORT: u16 = 162;
pub const SNMP_VERSION_2C: i32 = 1;

// BER Tags
pub const BER_TAG_INTEGER: u8 = 0x02;
pub const BER_TAG_OCTET_STRING: u8 = 0x04;
pub const BER_TAG_NULL: u8 = 0x05;
pub const BER_TAG_OID: u8 = 0x06;
pub const BER_TAG_SEQUENCE: u8 = 0x30;

// SNMP PDU Tags
pub const SNMP_PDU_GET_REQUEST: u8 = 0xA0;
pub const SNMP_PDU_GET_NEXT_REQUEST: u8 = 0xA1;
pub const SNMP_PDU_RESPONSE: u8 = 0xA2;
pub const SNMP_PDU_SET_REQUEST: u8 = 0xA3;

fn is_supported_pdu_type(tag: u8) -> bool {
    matches!(
        tag,
        SNMP_PDU_GET_REQUEST | SNMP_PDU_GET_NEXT_REQUEST | SNMP_PDU_RESPONSE | SNMP_PDU_SET_REQUEST
    )
}

fn is_request_pdu_type(tag: u8) -> bool {
    matches!(
        tag,
        SNMP_PDU_GET_REQUEST | SNMP_PDU_GET_NEXT_REQUEST | SNMP_PDU_SET_REQUEST
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpValue {
    Integer(i32),
    OctetString(Vec<u8>),
    Null,
    Oid(String),
}

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpValue::Integer(i) => write!(f, "INTEGER: {}", i),
            SnmpValue::OctetString(s) => write!(f, "STRING: \"{}\"", String::from_utf8_lossy(s)),
            SnmpValue::Null => write!(f, "NULL"),
            SnmpValue::Oid(o) => write!(f, "OID: {}", o),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpVarbind {
    pub oid: String,
    pub value: SnmpValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpPdu {
    pub pdu_type: u8,
    pub request_id: i32,
    pub error_status: i32,
    pub error_index: i32,
    pub varbinds: Vec<SnmpVarbind>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpMessage {
    pub version: i32,
    pub community: String,
    pub pdu: SnmpPdu,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpError {
    PacketTooShort,
    InvalidBerEncoding,
    UnsupportedTag(u8),
}

impl fmt::Display for SnmpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpError::PacketTooShort => write!(f, "SNMP packet too short"),
            SnmpError::InvalidBerEncoding => write!(f, "Invalid ASN.1 BER TLV encoding"),
            SnmpError::UnsupportedTag(t) => write!(f, "Unsupported BER tag 0x{:02x}", t),
        }
    }
}

impl std::error::Error for SnmpError {}

// --- BER TLV Helpers ---

pub fn encode_ber_length(len: usize) -> Vec<u8> {
    if len < 128 {
        return vec![len as u8];
    }

    let bytes = len.to_be_bytes();
    let first_significant = bytes
        .iter()
        .position(|&byte| byte != 0)
        .unwrap_or(bytes.len() - 1);
    let significant = &bytes[first_significant..];

    let mut encoded = Vec::with_capacity(1 + significant.len());
    encoded.push(0x80 | significant.len() as u8);
    encoded.extend_from_slice(significant);
    encoded
}

pub fn decode_ber_tlv(data: &[u8]) -> Result<(u8, &[u8], usize), SnmpError> {
    if data.len() < 2 {
        return Err(SnmpError::PacketTooShort);
    }
    let tag = data[0];
    let len_byte = data[1];

    let (len, header_len) = if (len_byte & 0x80) == 0 {
        (len_byte as usize, 2)
    } else {
        let num_octets = (len_byte & 0x7F) as usize;
        if num_octets == 0 || num_octets > std::mem::size_of::<usize>() {
            return Err(SnmpError::InvalidBerEncoding);
        }
        if data.len() < 2 + num_octets {
            return Err(SnmpError::PacketTooShort);
        }
        if data[2] == 0 {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let mut l = 0usize;
        for i in 0..num_octets {
            l = (l << 8) | (data[2 + i] as usize);
        }
        if l < 128 {
            return Err(SnmpError::InvalidBerEncoding);
        }
        (l, 2 + num_octets)
    };

    if data.len() < header_len + len {
        return Err(SnmpError::PacketTooShort);
    }

    Ok((tag, &data[header_len..header_len + len], header_len + len))
}

pub fn decode_ber_integer(bytes: &[u8]) -> Result<i32, SnmpError> {
    if bytes.is_empty() {
        return Err(SnmpError::InvalidBerEncoding);
    }
    if bytes.len() > 1
        && ((bytes[0] == 0x00 && bytes[1] & 0x80 == 0)
            || (bytes[0] == 0xff && bytes[1] & 0x80 != 0))
    {
        return Err(SnmpError::InvalidBerEncoding);
    }
    if bytes.len() > std::mem::size_of::<i32>() {
        return Err(SnmpError::InvalidBerEncoding);
    }

    let mut value = if bytes[0] & 0x80 != 0 { -1i32 } else { 0i32 };
    for &byte in bytes {
        value = (value << 8) | i32::from(byte);
    }
    Ok(value)
}

pub fn encode_ber_integer(val: i32) -> Vec<u8> {
    let bytes = val.to_be_bytes();
    let mut start = 0usize;
    while start < bytes.len() - 1
        && ((bytes[start] == 0x00 && bytes[start + 1] & 0x80 == 0)
            || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0))
    {
        start += 1;
    }

    let content = &bytes[start..];
    let mut out = Vec::with_capacity(2 + content.len());
    out.push(BER_TAG_INTEGER);
    out.extend(encode_ber_length(content.len()));
    out.extend_from_slice(content);
    out
}

pub fn encode_ber_string(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(BER_TAG_OCTET_STRING);
    out.extend(encode_ber_length(s.len()));
    out.extend_from_slice(s.as_bytes());
    out
}

pub fn encode_ber_null() -> Vec<u8> {
    vec![BER_TAG_NULL, 0]
}

fn encode_oid_subidentifier(mut value: u64, out: &mut Vec<u8>) {
    let mut buf = [0u8; 10];
    let mut pos = buf.len();
    pos -= 1;
    buf[pos] = (value & 0x7f) as u8;
    value >>= 7;
    while value != 0 {
        pos -= 1;
        buf[pos] = ((value & 0x7f) as u8) | 0x80;
        value >>= 7;
    }
    out.extend_from_slice(&buf[pos..]);
}

pub fn encode_ber_oid(oid: &str) -> Result<Vec<u8>, SnmpError> {
    let arcs = oid
        .split('.')
        .map(|arc| {
            arc.parse::<u64>()
                .map_err(|_| SnmpError::InvalidBerEncoding)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if arcs.len() < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] >= 40) {
        return Err(SnmpError::InvalidBerEncoding);
    }

    let first = arcs[0]
        .checked_mul(40)
        .and_then(|base| base.checked_add(arcs[1]))
        .ok_or(SnmpError::InvalidBerEncoding)?;
    let mut body = Vec::new();
    encode_oid_subidentifier(first, &mut body);
    for &arc in &arcs[2..] {
        encode_oid_subidentifier(arc, &mut body);
    }

    let mut out = Vec::with_capacity(1 + encode_ber_length(body.len()).len() + body.len());
    out.push(BER_TAG_OID);
    out.extend(encode_ber_length(body.len()));
    out.extend(body);
    Ok(out)
}

pub fn decode_ber_oid(bytes: &[u8]) -> Result<String, SnmpError> {
    if bytes.is_empty() {
        return Err(SnmpError::InvalidBerEncoding);
    }

    let mut subids = Vec::new();
    let mut value = 0u64;
    let mut at_start = true;
    for &byte in bytes {
        if at_start && byte == 0x80 {
            return Err(SnmpError::InvalidBerEncoding);
        }
        if value > (u64::MAX >> 7) {
            return Err(SnmpError::InvalidBerEncoding);
        }
        value = (value << 7) | u64::from(byte & 0x7f);
        at_start = false;
        if byte & 0x80 == 0 {
            subids.push(value);
            value = 0;
            at_start = true;
        }
    }
    if !at_start || subids.is_empty() {
        return Err(SnmpError::InvalidBerEncoding);
    }

    let first = subids[0];
    let (first_arc, second_arc) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut arcs = vec![first_arc, second_arc];
    arcs.extend_from_slice(&subids[1..]);
    Ok(arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

impl SnmpMessage {
    pub fn parse(data: &[u8]) -> Result<Self, SnmpError> {
        let (root_tag, root_body, root_len) = decode_ber_tlv(data)?;
        if root_tag != BER_TAG_SEQUENCE || root_len != data.len() {
            return Err(SnmpError::InvalidBerEncoding);
        }

        // 1. Version
        let (v_tag, v_body, v_len) = decode_ber_tlv(root_body)?;
        if v_tag != BER_TAG_INTEGER {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let version = decode_ber_integer(v_body)?;
        if version != SNMP_VERSION_2C {
            return Err(SnmpError::InvalidBerEncoding);
        }

        // 2. Community
        let rem1 = &root_body[v_len..];
        let (c_tag, c_body, c_len) = decode_ber_tlv(rem1)?;
        if c_tag != BER_TAG_OCTET_STRING {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let community = String::from_utf8_lossy(c_body).to_string();

        // 3. PDU
        let rem2 = &rem1[c_len..];
        let (pdu_tag, pdu_body, pdu_len) = decode_ber_tlv(rem2)?;
        if pdu_len != rem2.len() {
            return Err(SnmpError::InvalidBerEncoding);
        }
        if !is_supported_pdu_type(pdu_tag) {
            return Err(SnmpError::UnsupportedTag(pdu_tag));
        }

        let (req_tag, req_body, req_len) = decode_ber_tlv(pdu_body)?;
        if req_tag != BER_TAG_INTEGER {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let request_id = decode_ber_integer(req_body)?;

        let rem_pdu1 = &pdu_body[req_len..];
        let (err_tag, err_body, err_len) = decode_ber_tlv(rem_pdu1)?;
        if err_tag != BER_TAG_INTEGER {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let error_status = decode_ber_integer(err_body)?;

        let rem_pdu2 = &rem_pdu1[err_len..];
        let (idx_tag, idx_body, idx_len) = decode_ber_tlv(rem_pdu2)?;
        if idx_tag != BER_TAG_INTEGER {
            return Err(SnmpError::InvalidBerEncoding);
        }
        let error_index = decode_ber_integer(idx_body)?;
        if is_request_pdu_type(pdu_tag) && (error_status != 0 || error_index != 0) {
            return Err(SnmpError::InvalidBerEncoding);
        }

        let rem_pdu3 = &rem_pdu2[idx_len..];
        let (vb_list_tag, mut vb_list_body, vb_list_len) = decode_ber_tlv(rem_pdu3)?;
        if vb_list_tag != BER_TAG_SEQUENCE || vb_list_len != rem_pdu3.len() {
            return Err(SnmpError::InvalidBerEncoding);
        }

        let mut varbinds = Vec::new();
        while !vb_list_body.is_empty() {
            let (vb_tag, vb_body, vb_len) = decode_ber_tlv(vb_list_body)?;
            if vb_tag != BER_TAG_SEQUENCE {
                return Err(SnmpError::InvalidBerEncoding);
            }

            let (oid_tag, oid_body, oid_len) = decode_ber_tlv(vb_body)?;
            if oid_tag != BER_TAG_OID {
                return Err(SnmpError::InvalidBerEncoding);
            }
            let oid_str = decode_ber_oid(oid_body)?;

            let val_rem = &vb_body[oid_len..];
            let (v_tag, v_body, v_len) = decode_ber_tlv(val_rem)?;
            if v_len != val_rem.len() {
                return Err(SnmpError::InvalidBerEncoding);
            }
            let value = match v_tag {
                BER_TAG_INTEGER => SnmpValue::Integer(decode_ber_integer(v_body)?),
                BER_TAG_OCTET_STRING => SnmpValue::OctetString(v_body.to_vec()),
                BER_TAG_OID => SnmpValue::Oid(decode_ber_oid(v_body)?),
                BER_TAG_NULL if v_body.is_empty() => SnmpValue::Null,
                BER_TAG_NULL => return Err(SnmpError::InvalidBerEncoding),
                tag => return Err(SnmpError::UnsupportedTag(tag)),
            };

            varbinds.push(SnmpVarbind {
                oid: oid_str,
                value,
            });
            vb_list_body = &vb_list_body[vb_len..];
        }

        Ok(SnmpMessage {
            version,
            community,
            pdu: SnmpPdu {
                pdu_type: pdu_tag,
                request_id,
                error_status,
                error_index,
                varbinds,
            },
        })
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, SnmpError> {
        if self.version != SNMP_VERSION_2C {
            return Err(SnmpError::InvalidBerEncoding);
        }
        if !is_supported_pdu_type(self.pdu.pdu_type) {
            return Err(SnmpError::UnsupportedTag(self.pdu.pdu_type));
        }
        if is_request_pdu_type(self.pdu.pdu_type)
            && (self.pdu.error_status != 0 || self.pdu.error_index != 0)
        {
            return Err(SnmpError::InvalidBerEncoding);
        }

        // Encode Varbinds
        let mut vb_list_bytes = Vec::new();
        for vb in &self.pdu.varbinds {
            let mut vb_bytes = Vec::new();
            vb_bytes.extend(encode_ber_oid(&vb.oid)?);

            match &vb.value {
                SnmpValue::Integer(i) => vb_bytes.extend(encode_ber_integer(*i)),
                SnmpValue::OctetString(s) => {
                    vb_bytes.push(BER_TAG_OCTET_STRING);
                    vb_bytes.extend(encode_ber_length(s.len()));
                    vb_bytes.extend_from_slice(s);
                }
                SnmpValue::Null => vb_bytes.extend(encode_ber_null()),
                SnmpValue::Oid(o) => vb_bytes.extend(encode_ber_oid(o)?),
            }

            let mut seq_vb = Vec::new();
            seq_vb.push(BER_TAG_SEQUENCE);
            seq_vb.extend(encode_ber_length(vb_bytes.len()));
            seq_vb.extend(vb_bytes);
            vb_list_bytes.extend(seq_vb);
        }

        let mut vb_seq = Vec::new();
        vb_seq.push(BER_TAG_SEQUENCE);
        vb_seq.extend(encode_ber_length(vb_list_bytes.len()));
        vb_seq.extend(vb_list_bytes);

        // Encode PDU
        let mut pdu_bytes = Vec::new();
        pdu_bytes.extend(encode_ber_integer(self.pdu.request_id));
        pdu_bytes.extend(encode_ber_integer(self.pdu.error_status));
        pdu_bytes.extend(encode_ber_integer(self.pdu.error_index));
        pdu_bytes.extend(vb_seq);

        let mut pdu_wrapper = Vec::new();
        pdu_wrapper.push(self.pdu.pdu_type);
        pdu_wrapper.extend(encode_ber_length(pdu_bytes.len()));
        pdu_wrapper.extend(pdu_bytes);

        // Encode Message
        let mut msg_body = Vec::new();
        msg_body.extend(encode_ber_integer(self.version));
        msg_body.extend(encode_ber_string(&self.community));
        msg_body.extend(pdu_wrapper);

        let mut msg = Vec::new();
        msg.push(BER_TAG_SEQUENCE);
        msg.extend(encode_ber_length(msg_body.len()));
        msg.extend(msg_body);

        Ok(msg)
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("SNMP message contains an invalid object identifier")
    }

    pub fn build_get_request(community: &str, request_id: i32, oids: &[&str]) -> Self {
        let varbinds = oids
            .iter()
            .map(|&o| SnmpVarbind {
                oid: o.to_string(),
                value: SnmpValue::Null,
            })
            .collect();

        SnmpMessage {
            version: SNMP_VERSION_2C,
            community: community.to_string(),
            pdu: SnmpPdu {
                pdu_type: SNMP_PDU_GET_REQUEST,
                request_id,
                error_status: 0,
                error_index: 0,
                varbinds,
            },
        }
    }

    pub fn build_response(req: &SnmpMessage, results: Vec<SnmpVarbind>) -> Self {
        SnmpMessage {
            version: req.version,
            community: req.community.clone(),
            pdu: SnmpPdu {
                pdu_type: SNMP_PDU_RESPONSE,
                request_id: req.pdu.request_id,
                error_status: 0,
                error_index: 0,
                varbinds: results,
            },
        }
    }
}

/// In-Memory Management Information Base (MIB-II) Store
pub struct SnmpMib {
    objects: HashMap<String, SnmpValue>,
}

impl Default for SnmpMib {
    fn default() -> Self {
        Self::new()
    }
}

impl SnmpMib {
    pub fn new() -> Self {
        let mut mib = SnmpMib {
            objects: HashMap::new(),
        };
        mib.set(
            "1.3.6.1.2.1.1.1.0",
            SnmpValue::OctetString(b"Toy TCP/IP Stack on Safe Rust".to_vec()),
        );
        mib.set("1.3.6.1.2.1.1.3.0", SnmpValue::Integer(360000)); // sysUpTime (1 hr)
        mib.set(
            "1.3.6.1.2.1.1.5.0",
            SnmpValue::OctetString(b"toy-router.local".to_vec()),
        );
        mib.set("1.3.6.1.2.1.2.2.1.10.1", SnmpValue::Integer(1048576)); // ifInOctets (1MB)
        mib
    }

    pub fn get(&self, oid: &str) -> Option<&SnmpValue> {
        self.objects.get(oid)
    }

    pub fn set(&mut self, oid: &str, val: SnmpValue) {
        self.objects.insert(oid.to_string(), val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snmp_get_request_and_response_roundtrip() {
        let req = SnmpMessage::build_get_request("public", 42, &["1.3.6.1.2.1.1.1.0"]);
        let raw = req.serialize();

        let parsed = SnmpMessage::parse(&raw).unwrap();
        assert_eq!(parsed.version, SNMP_VERSION_2C);
        assert_eq!(parsed.community, "public");
        assert_eq!(parsed.pdu.request_id, 42);
        assert_eq!(parsed.pdu.varbinds.len(), 1);
        assert_eq!(parsed.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn test_ber_length_encoding_boundaries() {
        assert_eq!(encode_ber_length(127), vec![0x7f]);
        assert_eq!(encode_ber_length(128), vec![0x81, 0x80]);
        assert_eq!(encode_ber_length(255), vec![0x81, 0xff]);
        assert_eq!(encode_ber_length(256), vec![0x82, 0x01, 0x00]);
        assert_eq!(encode_ber_length(65_535), vec![0x82, 0xff, 0xff]);
        assert_eq!(encode_ber_length(65_536), vec![0x83, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn test_ber_length_encoding_supports_full_usize_width() {
        let encoded = encode_ber_length(usize::MAX);
        assert_eq!(encoded[0], 0x80 | std::mem::size_of::<usize>() as u8);
        assert!(encoded[1..].iter().all(|&byte| byte == 0xff));
    }

    #[test]
    fn test_ber_indefinite_length_is_rejected() {
        assert_eq!(
            decode_ber_tlv(&[BER_TAG_OCTET_STRING, 0x80, 0x00, 0x00]),
            Err(SnmpError::InvalidBerEncoding)
        );
    }

    #[test]
    fn test_ber_oversized_length_of_length_is_rejected() {
        let num_octets = std::mem::size_of::<usize>() + 1;
        let mut raw = vec![BER_TAG_OCTET_STRING, 0x80 | num_octets as u8];
        raw.resize(2 + num_octets, 0);

        assert_eq!(decode_ber_tlv(&raw), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_ber_non_minimal_long_form_lengths_are_rejected() {
        let mut short_value = vec![BER_TAG_OCTET_STRING, 0x81, 0x7f];
        short_value.resize(3 + 127, 0);
        assert_eq!(
            decode_ber_tlv(&short_value),
            Err(SnmpError::InvalidBerEncoding)
        );

        let mut leading_zero = vec![BER_TAG_OCTET_STRING, 0x82, 0x00, 0x80];
        leading_zero.resize(4 + 128, 0);
        assert_eq!(
            decode_ber_tlv(&leading_zero),
            Err(SnmpError::InvalidBerEncoding)
        );

        let mut canonical = vec![BER_TAG_OCTET_STRING, 0x81, 0x80];
        canonical.resize(3 + 128, 0);
        let (_, body, used) = decode_ber_tlv(&canonical).unwrap();
        assert_eq!(body.len(), 128);
        assert_eq!(used, canonical.len());
    }

    #[test]
    fn test_ber_integer_encoding_is_minimal_and_signed() {
        let cases = [
            (-129, vec![0x02, 0x02, 0xff, 0x7f]),
            (-128, vec![0x02, 0x01, 0x80]),
            (-1, vec![0x02, 0x01, 0xff]),
            (0, vec![0x02, 0x01, 0x00]),
            (127, vec![0x02, 0x01, 0x7f]),
            (128, vec![0x02, 0x02, 0x00, 0x80]),
        ];

        for (value, expected) in cases {
            assert_eq!(encode_ber_integer(value), expected);
        }
    }

    #[test]
    fn test_ber_integer_decoding_requires_minimal_signed_encoding() {
        assert_eq!(decode_ber_integer(&[0x80]), Ok(-128));
        assert_eq!(decode_ber_integer(&[0xff]), Ok(-1));
        assert_eq!(decode_ber_integer(&[0x00, 0x80]), Ok(128));
        assert_eq!(decode_ber_integer(&[0xff, 0x7f]), Ok(-129));
        assert_eq!(decode_ber_integer(&[]), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(
            decode_ber_integer(&[0x00, 0x7f]),
            Err(SnmpError::InvalidBerEncoding)
        );
        assert_eq!(
            decode_ber_integer(&[0xff, 0x80]),
            Err(SnmpError::InvalidBerEncoding)
        );
        assert_eq!(
            decode_ber_integer(&[0x00, 0x80, 0x00, 0x00, 0x00]),
            Err(SnmpError::InvalidBerEncoding)
        );
    }

    #[test]
    fn test_ber_oid_encoding_and_decoding() {
        assert_eq!(
            encode_ber_oid("1.3.6.1.2.1.1.1.0"),
            Ok(vec![
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00
            ])
        );
        assert_eq!(
            encode_ber_oid("2.100.3"),
            Ok(vec![0x06, 0x03, 0x81, 0x34, 0x03])
        );
        assert_eq!(
            decode_ber_oid(&[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]),
            Ok("1.3.6.1.2.1.1.1.0".to_string())
        );
        assert_eq!(
            decode_ber_oid(&[0x81, 0x34, 0x03]),
            Ok("2.100.3".to_string())
        );
    }

    #[test]
    fn test_ber_oid_rejects_malformed_encodings() {
        assert_eq!(encode_ber_oid("1"), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(encode_ber_oid("3.1"), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(encode_ber_oid("1.40.1"), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(encode_ber_oid("1.x.1"), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(decode_ber_oid(&[]), Err(SnmpError::InvalidBerEncoding));
        assert_eq!(
            decode_ber_oid(&[0x80, 0x2b]),
            Err(SnmpError::InvalidBerEncoding)
        );
        assert_eq!(decode_ber_oid(&[0x81]), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_snmp_oid_varbind_roundtrip_uses_ber_oid_tag() {
        let mut msg = SnmpMessage::build_get_request("public", 7, &["1.3.6.1.2.1.1.1.0"]);
        msg.pdu.varbinds[0].value = SnmpValue::Oid("2.100.3".to_string());
        let raw = msg.try_serialize().unwrap();
        assert!(
            raw.windows(10)
                .any(|w| w == [0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])
        );
        let parsed = SnmpMessage::parse(&raw).unwrap();
        assert_eq!(parsed.pdu.varbinds[0].oid, "1.3.6.1.2.1.1.1.0");
        assert_eq!(
            parsed.pdu.varbinds[0].value,
            SnmpValue::Oid("2.100.3".to_string())
        );
    }

    #[test]
    fn test_snmp_try_serialize_rejects_invalid_oid() {
        let msg = SnmpMessage::build_get_request("public", 1, &["1.40.0"]);
        assert_eq!(msg.try_serialize(), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_snmp_negative_integer_roundtrip() {
        let mut msg = SnmpMessage::build_get_request("public", -129, &["1.3.6.1.2.1.1.1.0"]);
        msg.pdu.varbinds[0].value = SnmpValue::Integer(-128);

        let parsed = SnmpMessage::parse(&msg.serialize()).unwrap();
        assert_eq!(parsed.pdu.request_id, -129);
        assert_eq!(parsed.pdu.varbinds[0].value, SnmpValue::Integer(-128));
    }

    #[test]
    fn test_snmp_rejects_root_trailing_bytes() {
        let mut raw = SnmpMessage::build_get_request("public", 1, &[]).serialize();
        raw.push(0);

        assert_eq!(SnmpMessage::parse(&raw), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_snmp_rejects_malformed_varbind_instead_of_truncating_list() {
        let mut raw = SnmpMessage::build_get_request("public", 1, &[]).serialize();
        let pdu_offset = raw
            .iter()
            .position(|&byte| byte == SNMP_PDU_GET_REQUEST)
            .unwrap();
        let vb_list_offset = raw.len() - 2;

        raw[1] += 3;
        raw[pdu_offset + 1] += 3;
        raw[vb_list_offset + 1] = 3;
        raw.extend_from_slice(&[BER_TAG_SEQUENCE, 1, 0]);

        assert!(SnmpMessage::parse(&raw).is_err());
    }

    #[test]
    fn test_snmp_rejects_unsupported_varbind_value_tag() {
        let mut raw =
            SnmpMessage::build_get_request("public", 1, &["1.3.6.1.2.1.1.1.0"]).serialize();
        let value_offset = raw
            .windows(2)
            .rposition(|window| window == [BER_TAG_NULL, 0])
            .unwrap();
        raw[value_offset] = 0x40;

        assert_eq!(
            SnmpMessage::parse(&raw),
            Err(SnmpError::UnsupportedTag(0x40))
        );
    }

    #[test]
    fn test_snmp_rejects_unsupported_version() {
        let mut msg = SnmpMessage::build_get_request("public", 1, &[]);
        msg.version = 0;
        assert_eq!(msg.try_serialize(), Err(SnmpError::InvalidBerEncoding));

        let mut raw = SnmpMessage::build_get_request("public", 1, &[]).serialize();
        let version_offset = raw
            .windows(3)
            .position(|window| window == [BER_TAG_INTEGER, 1, SNMP_VERSION_2C as u8])
            .unwrap();
        raw[version_offset + 2] = 0;
        assert_eq!(SnmpMessage::parse(&raw), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_snmp_rejects_unsupported_pdu_type() {
        let mut msg = SnmpMessage::build_get_request("public", 1, &[]);
        msg.pdu.pdu_type = 0xa5;
        assert_eq!(msg.try_serialize(), Err(SnmpError::UnsupportedTag(0xa5)));

        let mut raw = SnmpMessage::build_get_request("public", 1, &[]).serialize();
        let pdu_offset = raw
            .iter()
            .position(|&byte| byte == SNMP_PDU_GET_REQUEST)
            .unwrap();
        raw[pdu_offset] = 0xa5;
        assert_eq!(
            SnmpMessage::parse(&raw),
            Err(SnmpError::UnsupportedTag(0xa5))
        );
    }

    #[test]
    fn test_snmp_supported_pdu_types_roundtrip() {
        for pdu_type in [
            SNMP_PDU_GET_REQUEST,
            SNMP_PDU_GET_NEXT_REQUEST,
            SNMP_PDU_RESPONSE,
            SNMP_PDU_SET_REQUEST,
        ] {
            let mut msg = SnmpMessage::build_get_request("public", 1, &[]);
            msg.pdu.pdu_type = pdu_type;
            let parsed = SnmpMessage::parse(&msg.try_serialize().unwrap()).unwrap();
            assert_eq!(parsed.pdu.pdu_type, pdu_type);
        }
    }

    #[test]
    fn test_snmp_request_pdus_require_zero_error_fields() {
        for pdu_type in [
            SNMP_PDU_GET_REQUEST,
            SNMP_PDU_GET_NEXT_REQUEST,
            SNMP_PDU_SET_REQUEST,
        ] {
            let mut msg = SnmpMessage::build_get_request("public", 1, &[]);
            msg.pdu.pdu_type = pdu_type;
            msg.pdu.error_status = 1;
            assert_eq!(msg.try_serialize(), Err(SnmpError::InvalidBerEncoding));

            msg.pdu.error_status = 0;
            msg.pdu.error_index = 1;
            assert_eq!(msg.try_serialize(), Err(SnmpError::InvalidBerEncoding));
        }
    }

    #[test]
    fn test_snmp_parser_rejects_request_error_fields() {
        let mut raw = SnmpMessage::build_get_request("public", 1, &[]).serialize();
        let fields = [
            BER_TAG_INTEGER,
            1,
            1,
            BER_TAG_INTEGER,
            1,
            0,
            BER_TAG_INTEGER,
            1,
            0,
        ];
        let fields_offset = raw
            .windows(fields.len())
            .position(|window| window == fields)
            .unwrap();
        raw[fields_offset + 5] = 1;

        assert_eq!(SnmpMessage::parse(&raw), Err(SnmpError::InvalidBerEncoding));
    }

    #[test]
    fn test_snmp_response_allows_error_fields() {
        let mut msg = SnmpMessage::build_get_request("public", 1, &[]);
        msg.pdu.pdu_type = SNMP_PDU_RESPONSE;
        msg.pdu.error_status = 5;
        msg.pdu.error_index = 1;

        let parsed = SnmpMessage::parse(&msg.try_serialize().unwrap()).unwrap();
        assert_eq!(parsed.pdu.error_status, 5);
        assert_eq!(parsed.pdu.error_index, 1);
    }

    #[test]
    fn test_snmp_mib_store() {
        let mib = SnmpMib::new();
        let sys_descr = mib.get("1.3.6.1.2.1.1.1.0").unwrap();
        if let SnmpValue::OctetString(s) = sys_descr {
            assert!(String::from_utf8_lossy(s).contains("Toy TCP/IP Stack"));
        } else {
            panic!("Expected OctetString");
        }
    }
}
