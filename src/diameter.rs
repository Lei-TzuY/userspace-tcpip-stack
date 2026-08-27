//! Diameter Base AAA Protocol (RFC 6733).
//!
//! Next-generation carrier 4G/5G mobile core, IMS, and policy AAA protocol over TCP/SCTP port 3868.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const DIAMETER_PORT: u16 = 3868;
pub const DIAMETER_VERSION_1: u8 = 1;

// Command Flags
pub const DIAMETER_FLAG_REQUEST: u8 = 0x80;
pub const DIAMETER_FLAG_PROXIABLE: u8 = 0x40;
pub const DIAMETER_FLAG_ERROR: u8 = 0x20;
pub const DIAMETER_FLAG_RETRANSMITTED: u8 = 0x10;

// AVP Flags
pub const DIAMETER_FLAG_VENDOR_SPECIFIC: u8 = 0x80;
pub const DIAMETER_FLAG_MANDATORY: u8 = 0x40;

// Command Codes
pub const DIAMETER_CMD_CAPABILITIES_EXCHANGE: u32 = 257; // CER / CEA
pub const DIAMETER_CMD_DEVICE_WATCHDOG: u32 = 280; // DWR / DWA
pub const DIAMETER_CMD_ACCOUNTING: u32 = 271; // ACR / ACA

// AVP Codes
pub const DIAMETER_AVP_HOST_IP_ADDRESS: u32 = 257;
pub const DIAMETER_AVP_AUTH_APPLICATION_ID: u32 = 258;
pub const DIAMETER_AVP_ORIGIN_HOST: u32 = 264;
pub const DIAMETER_AVP_VENDOR_ID: u32 = 266;
pub const DIAMETER_AVP_RESULT_CODE: u32 = 268;
pub const DIAMETER_AVP_PRODUCT_NAME: u32 = 269;
pub const DIAMETER_AVP_ORIGIN_REALM: u32 = 296;

// Result Codes
pub const DIAMETER_SUCCESS: u32 = 2001;
pub const DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterHeader {
    pub version: u8,
    pub length: u32, // 24-bit
    pub flags: u8,
    pub command_code: u32, // 24-bit
    pub application_id: u32,
    pub hop_by_hop_id: u32,
    pub end_to_end_id: u32,
}

impl DiameterHeader {
    pub fn is_request(&self) -> bool {
        (self.flags & DIAMETER_FLAG_REQUEST) != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterAvp {
    pub code: u32,
    pub flags: u8,
    pub vendor_id: Option<u32>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiameterMessage {
    pub header: DiameterHeader,
    pub avps: Vec<DiameterAvp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiameterError {
    PacketTooShort(usize),
    UnsupportedVersion(u8),
    InvalidLength,
}

impl fmt::Display for DiameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiameterError::PacketTooShort(l) => {
                write!(f, "Diameter message too short ({} bytes)", l)
            }
            DiameterError::UnsupportedVersion(v) => {
                write!(f, "Unsupported Diameter version: {}", v)
            }
            DiameterError::InvalidLength => write!(f, "Invalid Diameter message length"),
        }
    }
}

impl std::error::Error for DiameterError {}

impl DiameterAvp {
    pub fn new(code: u32, data: &[u8]) -> Self {
        DiameterAvp {
            code,
            flags: 0x40, // Mandatory bit set (M-bit)
            vendor_id: None,
            data: data.to_vec(),
        }
    }

    pub fn new_with_flags(code: u32, flags: u8, data: Vec<u8>) -> Self {
        DiameterAvp {
            code,
            flags,
            vendor_id: None,
            data,
        }
    }

    pub fn new_u32(code: u32, val: u32) -> Self {
        Self::new(code, &val.to_be_bytes())
    }

    pub fn new_utf8(code: u32, text: &str) -> Self {
        Self::new(code, text.as_bytes())
    }

    pub fn new_string(code: u32, text: &str) -> Self {
        Self::new_utf8(code, text)
    }

    pub fn new_ipv4(code: u32, ip: Ipv4Address) -> Self {
        let mut data = vec![0x00, 0x01]; // Address Family 1 = IPv4
        data.extend_from_slice(&ip.0);
        Self::new(code, &data)
    }

    pub fn new_vendor(code: u32, flags: u8, vendor_id: u32, data: &[u8]) -> Self {
        DiameterAvp {
            code,
            flags,
            vendor_id: Some(vendor_id),
            data: data.to_vec(),
        }
    }

    pub fn parse_all(mut data: &[u8]) -> Vec<DiameterAvp> {
        let mut list = Vec::new();
        while !data.is_empty() {
            if let Some((avp, consumed)) = DiameterAvp::parse(data) {
                if consumed == 0 {
                    break;
                }
                list.push(avp);
                data = &data[consumed..];
            } else {
                break;
            }
        }
        list
    }

    pub fn as_u32(&self) -> Option<u32> {
        if self.data.len() >= 4 {
            Some(u32::from_be_bytes(self.data[..4].try_into().ok()?))
        } else {
            None
        }
    }

    pub fn as_string(&self) -> Option<String> {
        String::from_utf8(self.data.clone()).ok()
    }

    pub fn serialize(&self) -> Vec<u8> {
        let hdr_len = if self.vendor_id.is_some() { 12 } else { 8 };
        let total_len = (hdr_len + self.data.len()) as u32;

        let mut buf = Vec::new();
        buf.extend_from_slice(&self.code.to_be_bytes());

        let mut b_flags = self.flags;
        if self.vendor_id.is_some() {
            b_flags |= 0x80; // V-bit
        }
        buf.push(b_flags);

        let len_bytes = total_len.to_be_bytes();
        buf.extend_from_slice(&len_bytes[1..4]); // 24-bit length

        if let Some(vid) = self.vendor_id {
            buf.extend_from_slice(&vid.to_be_bytes());
        }

        buf.extend_from_slice(&self.data);
        while buf.len() % 4 != 0 {
            buf.push(0x00); // 4-byte word padding
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }

        let code = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let flags = data[4];
        let length = u32::from_be_bytes([0, data[5], data[6], data[7]]) as usize;

        if length < 8 || length > data.len() {
            return None;
        }

        let has_vendor_id = (flags & DIAMETER_FLAG_VENDOR_SPECIFIC) != 0;
        if has_vendor_id && length < 12 {
            return None;
        }

        let (vendor_id, data_start) = if has_vendor_id {
            let vid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            (Some(vid), 12)
        } else {
            (None, 8)
        };

        let padded_len = (length + 3) & !3;
        if padded_len > data.len() {
            return None;
        }

        let avp_data = data[data_start..length].to_vec();

        Some((
            DiameterAvp {
                code,
                flags,
                vendor_id,
                data: avp_data,
            },
            padded_len,
        ))
    }
}

impl DiameterMessage {
    pub fn new_request(
        command_code: u32,
        application_id: u32,
        hop_by_hop_id: u32,
        end_to_end_id: u32,
    ) -> Self {
        DiameterMessage {
            header: DiameterHeader {
                version: DIAMETER_VERSION_1,
                length: 0,
                flags: DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_PROXIABLE,
                command_code,
                application_id,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps: Vec::new(),
        }
    }

    pub fn new_answer(
        command_code: u32,
        application_id: u32,
        hop_by_hop_id: u32,
        end_to_end_id: u32,
    ) -> Self {
        DiameterMessage {
            header: DiameterHeader {
                version: DIAMETER_VERSION_1,
                length: 0,
                flags: DIAMETER_FLAG_PROXIABLE,
                command_code,
                application_id,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps: Vec::new(),
        }
    }

    pub fn add_avp(&mut self, avp: DiameterAvp) {
        self.avps.push(avp);
    }

    pub fn get_avp(&self, code: u32) -> Option<&DiameterAvp> {
        self.avps.iter().find(|a| a.code == code)
    }

    pub fn build_cer(
        origin_host: &str,
        origin_realm: &str,
        host_ip: Ipv4Address,
        vendor_id: u32,
        product_name: &str,
        hop_id: u32,
        end_id: u32,
    ) -> Self {
        let header = DiameterHeader {
            version: DIAMETER_VERSION_1,
            length: 0,
            flags: DIAMETER_FLAG_REQUEST | DIAMETER_FLAG_PROXIABLE,
            command_code: DIAMETER_CMD_CAPABILITIES_EXCHANGE,
            application_id: 0,
            hop_by_hop_id: hop_id,
            end_to_end_id: end_id,
        };

        let avps = vec![
            DiameterAvp::new_utf8(DIAMETER_AVP_ORIGIN_HOST, origin_host),
            DiameterAvp::new_utf8(DIAMETER_AVP_ORIGIN_REALM, origin_realm),
            DiameterAvp::new_ipv4(DIAMETER_AVP_HOST_IP_ADDRESS, host_ip),
            DiameterAvp::new_u32(DIAMETER_AVP_VENDOR_ID, vendor_id),
            DiameterAvp::new_utf8(DIAMETER_AVP_PRODUCT_NAME, product_name),
            DiameterAvp::new_u32(DIAMETER_AVP_AUTH_APPLICATION_ID, 0),
        ];

        DiameterMessage { header, avps }
    }

    pub fn build_cea(
        req: &DiameterMessage,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
    ) -> Self {
        let header = DiameterHeader {
            version: DIAMETER_VERSION_1,
            length: 0,
            flags: DIAMETER_FLAG_PROXIABLE, // Request bit cleared = Answer
            command_code: req.header.command_code,
            application_id: req.header.application_id,
            hop_by_hop_id: req.header.hop_by_hop_id,
            end_to_end_id: req.header.end_to_end_id,
        };

        let avps = vec![
            DiameterAvp::new_u32(DIAMETER_AVP_RESULT_CODE, result_code),
            DiameterAvp::new_utf8(DIAMETER_AVP_ORIGIN_HOST, origin_host),
            DiameterAvp::new_utf8(DIAMETER_AVP_ORIGIN_REALM, origin_realm),
        ];

        DiameterMessage { header, avps }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut avp_bytes = Vec::new();
        for a in &self.avps {
            avp_bytes.extend_from_slice(&a.serialize());
        }

        let total_len = (20 + avp_bytes.len()) as u32;
        let mut buf = Vec::new();
        buf.push(self.header.version);

        let len_bytes = total_len.to_be_bytes();
        buf.extend_from_slice(&len_bytes[1..4]); // 24-bit Length

        buf.push(self.header.flags);

        let cmd_bytes = self.header.command_code.to_be_bytes();
        buf.extend_from_slice(&cmd_bytes[1..4]); // 24-bit Command Code

        buf.extend_from_slice(&self.header.application_id.to_be_bytes());
        buf.extend_from_slice(&self.header.hop_by_hop_id.to_be_bytes());
        buf.extend_from_slice(&self.header.end_to_end_id.to_be_bytes());
        buf.extend_from_slice(&avp_bytes);

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, DiameterError> {
        if data.len() < 20 {
            return Err(DiameterError::PacketTooShort(data.len()));
        }

        let version = data[0];
        if version != DIAMETER_VERSION_1 {
            return Err(DiameterError::UnsupportedVersion(version));
        }

        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if length < 20 || length > data.len() {
            return Err(DiameterError::InvalidLength);
        }

        let flags = data[4];
        let command_code = u32::from_be_bytes([0, data[5], data[6], data[7]]);
        let application_id = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let hop_by_hop_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let end_to_end_id = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);

        let mut avps = Vec::new();
        let mut offset = 20;

        while offset < length {
            if let Some((avp, consumed)) = DiameterAvp::parse(&data[offset..length]) {
                avps.push(avp);
                offset += consumed;
            } else {
                return Err(DiameterError::InvalidLength);
            }
        }

        Ok(DiameterMessage {
            header: DiameterHeader {
                version,
                length: length as u32,
                flags,
                command_code,
                application_id,
                hop_by_hop_id,
                end_to_end_id,
            },
            avps,
        })
    }
}

/// Simulated in-memory Diameter Base Protocol Server
#[derive(Debug, Clone, Default)]
pub struct DiameterServer {
    pub origin_host: String,
    pub origin_realm: String,
}

impl DiameterServer {
    pub fn new(origin_host: &str, origin_realm: &str) -> Self {
        DiameterServer {
            origin_host: origin_host.to_string(),
            origin_realm: origin_realm.to_string(),
        }
    }

    pub fn handle_request(&self, req: &DiameterMessage) -> DiameterMessage {
        match req.header.command_code {
            DIAMETER_CMD_CAPABILITIES_EXCHANGE => DiameterMessage::build_cea(
                req,
                &self.origin_host,
                &self.origin_realm,
                DIAMETER_SUCCESS,
            ),
            DIAMETER_CMD_DEVICE_WATCHDOG => DiameterMessage::build_cea(
                req,
                &self.origin_host,
                &self.origin_realm,
                DIAMETER_SUCCESS,
            ),
            _ => DiameterMessage::build_cea(
                req,
                &self.origin_host,
                &self.origin_realm,
                DIAMETER_COMMAND_UNSUPPORTED,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_cer_cea_handshake() {
        let cer = DiameterMessage::build_cer(
            "mme01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            Ipv4Address::new(10, 100, 0, 1),
            10415, // 3GPP Vendor ID
            "ToyStack-4G-Core",
            0x11223344,
            0x55667788,
        );

        let raw_cer = cer.serialize();
        assert!(raw_cer.len() >= 20);

        let parsed_cer = DiameterMessage::parse(&raw_cer).unwrap();
        assert_eq!(
            parsed_cer.header.command_code,
            DIAMETER_CMD_CAPABILITIES_EXCHANGE
        );
        assert!(parsed_cer.header.flags & DIAMETER_FLAG_REQUEST != 0);
        assert_eq!(parsed_cer.avps.len(), 6);

        let server = DiameterServer::new(
            "hss01.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );
        let cea = server.handle_request(&parsed_cer);
        let raw_cea = cea.serialize();

        let parsed_cea = DiameterMessage::parse(&raw_cea).unwrap();
        assert_eq!(
            parsed_cea.header.command_code,
            DIAMETER_CMD_CAPABILITIES_EXCHANGE
        );
        assert!(parsed_cea.header.flags & DIAMETER_FLAG_REQUEST == 0);
        assert_eq!(parsed_cea.avps[0].code, DIAMETER_AVP_RESULT_CODE);
        assert_eq!(
            u32::from_be_bytes([
                parsed_cea.avps[0].data[0],
                parsed_cea.avps[0].data[1],
                parsed_cea.avps[0].data[2],
                parsed_cea.avps[0].data[3]
            ]),
            DIAMETER_SUCCESS
        );
        assert_eq!(DIAMETER_PORT, 3868);
    }

    fn empty_diameter_message() -> Vec<u8> {
        DiameterMessage::new_request(DIAMETER_CMD_DEVICE_WATCHDOG, 0, 1, 2).serialize()
    }

    fn set_message_length(raw: &mut [u8], length: usize) {
        let bytes = (length as u32).to_be_bytes();
        raw[1..4].copy_from_slice(&bytes[1..4]);
    }

    #[test]
    fn test_diameter_rejects_declared_length_below_header() {
        let mut raw = empty_diameter_message();
        set_message_length(&mut raw, 19);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_trailing_partial_avp_header() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&[0, 0, 0, 1]);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_vendor_avp_shorter_than_vendor_header() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&123u32.to_be_bytes());
        raw.push(DIAMETER_FLAG_VENDOR_SPECIFIC);
        raw.extend_from_slice(&[0, 0, 8]);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_missing_avp_padding() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&123u32.to_be_bytes());
        raw.push(DIAMETER_FLAG_MANDATORY);
        raw.extend_from_slice(&[0, 0, 9]);
        raw.push(0xaa);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_empty_message_and_padded_avp_remain_valid() {
        let raw = empty_diameter_message();
        let parsed = DiameterMessage::parse(&raw).unwrap();
        assert!(parsed.avps.is_empty());
        assert_eq!(parsed.header.length, 20);

        let mut message = DiameterMessage::new_request(DIAMETER_CMD_DEVICE_WATCHDOG, 0, 1, 2);
        message.add_avp(DiameterAvp::new(123, &[0xaa]));
        let raw = message.serialize();
        assert_eq!(raw.len(), 32);
        let parsed = DiameterMessage::parse(&raw).unwrap();
        assert_eq!(parsed.avps.len(), 1);
        assert_eq!(parsed.avps[0].data, vec![0xaa]);
    }
}
