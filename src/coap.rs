//! Constrained Application Protocol (CoAP - RFC 7252).
//!
//! Binary RESTful web transfer protocol over UDP port 5683 designed for embedded IoT devices.

use std::fmt;

pub const COAP_UDP_PORT: u16 = 5683;
pub const COAPS_UDP_PORT: u16 = 5684;
pub const COAP_HEADER_LEN: usize = 4;
pub const COAP_PAYLOAD_MARKER: u8 = 0xFF;

// CoAP Message Types
pub const COAP_TYPE_CON: u8 = 0; // Confirmable
pub const COAP_TYPE_NON: u8 = 1; // Non-confirmable
pub const COAP_TYPE_ACK: u8 = 2; // Acknowledgement
pub const COAP_TYPE_RST: u8 = 3; // Reset

// CoAP Request Codes (Class 0)
pub const COAP_CODE_GET: u8 = 1; // 0.01 GET
pub const COAP_CODE_POST: u8 = 2; // 0.02 POST
pub const COAP_CODE_PUT: u8 = 3; // 0.03 PUT
pub const COAP_CODE_DELETE: u8 = 4; // 0.04 DELETE

// CoAP Response Codes
pub const COAP_CODE_205_CONTENT: u8 = 69; // 2.05 Content (2*32 + 5)
pub const COAP_CODE_404_NOT_FOUND: u8 = 132; // 4.04 Not Found (4*32 + 4)

// CoAP Option Numbers
pub const COAP_OPT_URI_PATH: u16 = 11;
pub const COAP_OPT_CONTENT_FORMAT: u16 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    pub number: u16,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapPacket {
    pub version: u8,
    pub msg_type: u8,
    pub code: u8,
    pub message_id: u16,
    pub token: Vec<u8>,
    pub options: Vec<CoapOption>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoapError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidTokenLength(u8),
    EmptyPayloadMarker,
    OptionNumberOverflow,
    InvalidOptionEncoding,
}

impl fmt::Display for CoapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoapError::PacketTooShort(l) => write!(f, "CoAP packet too short ({} bytes)", l),
            CoapError::InvalidVersion(v) => write!(f, "Invalid CoAP version: {}", v),
            CoapError::InvalidTokenLength(tkl) => {
                write!(f, "Invalid CoAP token length: {} (max 8)", tkl)
            }
            CoapError::EmptyPayloadMarker => {
                write!(f, "CoAP payload marker must be followed by payload data")
            }
            CoapError::OptionNumberOverflow => {
                write!(f, "CoAP option number exceeds 16-bit range")
            }
            CoapError::InvalidOptionEncoding => write!(f, "Malformed CoAP option delta/length"),
        }
    }
}

impl std::error::Error for CoapError {}

impl CoapPacket {
    pub fn build_get(message_id: u16, path: &str, token: &[u8]) -> Self {
        let options = vec![CoapOption {
            number: COAP_OPT_URI_PATH,
            value: path.as_bytes().to_vec(),
        }];

        CoapPacket {
            version: 1,
            msg_type: COAP_TYPE_CON,
            code: COAP_CODE_GET,
            message_id,
            token: token.to_vec(),
            options,
            payload: Vec::new(),
        }
    }

    pub fn build_response(req: &CoapPacket, code: u8, payload: &[u8]) -> Self {
        CoapPacket {
            version: 1,
            msg_type: COAP_TYPE_ACK,
            code,
            message_id: req.message_id,
            token: req.token.clone(),
            options: vec![CoapOption {
                number: COAP_OPT_CONTENT_FORMAT,
                value: vec![0],
            }], // 0 = text/plain
            payload: payload.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let tkl = (self.token.len() & 0x0F) as u8;
        let b0 = (self.version << 6) | ((self.msg_type & 0x03) << 4) | tkl;
        buf.push(b0);
        buf.push(self.code);
        buf.extend_from_slice(&self.message_id.to_be_bytes());
        buf.extend_from_slice(&self.token);

        let mut last_opt_num = 0u16;
        for opt in &self.options {
            let delta = opt.number.saturating_sub(last_opt_num);
            last_opt_num = opt.number;
            let len = opt.value.len();

            let (d_nibble, d_ext) = encode_nibble(delta as usize);
            let (l_nibble, l_ext) = encode_nibble(len);

            buf.push((d_nibble << 4) | l_nibble);
            if let Some(ext) = d_ext {
                buf.push(ext);
            }
            if let Some(ext) = l_ext {
                buf.push(ext);
            }
            buf.extend_from_slice(&opt.value);
        }

        if !self.payload.is_empty() {
            buf.push(COAP_PAYLOAD_MARKER);
            buf.extend_from_slice(&self.payload);
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, CoapError> {
        if data.len() < COAP_HEADER_LEN {
            return Err(CoapError::PacketTooShort(data.len()));
        }

        let version = data[0] >> 6;
        if version != 1 {
            return Err(CoapError::InvalidVersion(version));
        }

        let msg_type = (data[0] >> 4) & 0x03;
        let tkl = (data[0] & 0x0F) as usize;
        if tkl > 8 {
            return Err(CoapError::InvalidTokenLength(tkl as u8));
        }
        let code = data[1];
        let message_id = u16::from_be_bytes([data[2], data[3]]);

        let mut offset = COAP_HEADER_LEN;
        if data.len() < offset + tkl {
            return Err(CoapError::PacketTooShort(data.len()));
        }

        let token = data[offset..offset + tkl].to_vec();
        offset += tkl;

        let mut options = Vec::new();
        let mut current_opt_num = 0u16;

        while offset < data.len() {
            if data[offset] == COAP_PAYLOAD_MARKER {
                if offset + 1 >= data.len() {
                    return Err(CoapError::EmptyPayloadMarker);
                }
                offset += 1;
                break;
            }

            let opt_header = data[offset];
            offset += 1;

            let (delta, new_off) = decode_nibble(opt_header >> 4, data, offset)?;
            offset = new_off;
            let (len, new_off2) = decode_nibble(opt_header & 0x0F, data, offset)?;
            offset = new_off2;

            if offset + len > data.len() {
                return Err(CoapError::InvalidOptionEncoding);
            }

            let delta = u16::try_from(delta).map_err(|_| CoapError::OptionNumberOverflow)?;
            current_opt_num = current_opt_num
                .checked_add(delta)
                .ok_or(CoapError::OptionNumberOverflow)?;
            let value = data[offset..offset + len].to_vec();
            offset += len;

            options.push(CoapOption {
                number: current_opt_num,
                value,
            });
        }

        let payload = if offset <= data.len() {
            data[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(CoapPacket {
            version,
            msg_type,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }
}

fn encode_nibble(val: usize) -> (u8, Option<u8>) {
    if val < 13 {
        (val as u8, None)
    } else if val < 269 {
        (13, Some((val - 13) as u8))
    } else {
        (14, Some(255))
    }
}

fn decode_nibble(nibble: u8, data: &[u8], mut offset: usize) -> Result<(usize, usize), CoapError> {
    match nibble {
        0..=12 => Ok((nibble as usize, offset)),
        13 => {
            if offset >= data.len() {
                return Err(CoapError::InvalidOptionEncoding);
            }
            let val = data[offset] as usize + 13;
            offset += 1;
            Ok((val, offset))
        }
        14 => {
            if offset + 1 >= data.len() {
                return Err(CoapError::InvalidOptionEncoding);
            }
            let val = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize + 269;
            offset += 2;
            Ok((val, offset))
        }
        _ => Err(CoapError::InvalidOptionEncoding),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_coap_get_and_content_response_roundtrip() {
        let req = CoapPacket::build_get(0x1337, "sensors/temperature", &[0xAA, 0xBB]);
        let raw = req.serialize();

        let parsed = CoapPacket::parse(&raw).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.msg_type, COAP_TYPE_CON);
        assert_eq!(parsed.code, COAP_CODE_GET);
        assert_eq!(parsed.message_id, 0x1337);
        assert_eq!(parsed.token, vec![0xAA, 0xBB]);
        assert_eq!(parsed.options.len(), 1);
        assert_eq!(parsed.options[0].number, COAP_OPT_URI_PATH);
        assert_eq!(parsed.options[0].value, b"sensors/temperature");

        let resp = CoapPacket::build_response(&parsed, COAP_CODE_205_CONTENT, b"24.8 C");
        let resp_raw = resp.serialize();
        let parsed_resp = CoapPacket::parse(&resp_raw).unwrap();

        assert_eq!(parsed_resp.msg_type, COAP_TYPE_ACK);
        assert_eq!(parsed_resp.code, COAP_CODE_205_CONTENT);
        assert_eq!(parsed_resp.payload, b"24.8 C");
    }

    #[test]
    fn test_coap_rejects_token_length_above_eight() {
        let raw = [0x49, COAP_CODE_GET, 0x12, 0x34, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(
            CoapPacket::parse(&raw),
            Err(CoapError::InvalidTokenLength(9))
        );
    }

    #[test]
    fn test_coap_rejects_empty_payload_marker() {
        let raw = [0x40, COAP_CODE_GET, 0x12, 0x34, COAP_PAYLOAD_MARKER];
        assert_eq!(CoapPacket::parse(&raw), Err(CoapError::EmptyPayloadMarker));
    }

    #[test]
    fn test_coap_rejects_option_number_overflow() {
        let raw = [0x40, COAP_CODE_GET, 0x12, 0x34, 0xE0, 0xFF, 0xFF];
        assert_eq!(
            CoapPacket::parse(&raw),
            Err(CoapError::OptionNumberOverflow)
        );
    }

    #[test]
    fn test_coap_payload_marker_with_data_remains_valid() {
        let raw = [
            0x40,
            COAP_CODE_205_CONTENT,
            0x12,
            0x34,
            COAP_PAYLOAD_MARKER,
            0xAB,
        ];
        let parsed = CoapPacket::parse(&raw).unwrap();
        assert!(parsed.options.is_empty());
        assert_eq!(parsed.payload, vec![0xAB]);
    }
}
