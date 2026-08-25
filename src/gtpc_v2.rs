//! 3GPP TS 29.274 — GTPv2-C (GTP Control Plane version 2).
//!
//! GTPv2-C is the control-plane signalling protocol used in 4G/LTE EPC and
//! 5G Non-Standalone (NSA) deployments between MME, SGW, PGW (and SMF in
//! 5G SA interworking) for session management.
//!
//! This module implements:
//! * GTPv2-C header codec (Version 2, Piggyback flag, TEID flag).
//! * Information Element (IE) TLV codec.
//! * Create Session Request (Message Type 32) / Response (Message Type 33).
//! * Key IEs:
//!   - IMSI (IE Type 1)
//!   - MSISDN (IE Type 76)
//!   - APN (Access Point Name, IE Type 71)
//!   - Fully Qualified TEID (F-TEID, IE Type 87)
//!   - Bearer Context (IE Type 93, Grouped)
//!   - EPS Bearer ID (EBI, IE Type 73)
//!   - Cause (IE Type 2)

/// GTPv2-C message types.
pub const GTPV2C_CREATE_SESSION_REQ: u8 = 32;
pub const GTPV2C_CREATE_SESSION_RSP: u8 = 33;

/// IE types.
pub const IE_IMSI: u8 = 1;
pub const IE_CAUSE: u8 = 2;
pub const IE_APN: u8 = 71;
pub const IE_EBI: u8 = 73;
pub const IE_MSISDN: u8 = 76;
pub const IE_FTEID: u8 = 87;
pub const IE_BEARER_CONTEXT: u8 = 93;

/// GTPv2-C Cause values.
pub const CAUSE_REQUEST_ACCEPTED: u8 = 16;
pub const CAUSE_NO_RESOURCES: u8 = 73;
pub const CAUSE_CONTEXT_NOT_FOUND: u8 = 64;

/// F-TEID Interface types (selection).
pub const FTEID_S11_MME: u8 = 10;
pub const FTEID_S11_SGW: u8 = 11;
pub const FTEID_S5_S8_SGW: u8 = 6;
pub const FTEID_S5_S8_PGW: u8 = 7;

// ── GTPv2-C Header ──────────────────────────────────────────────────────

/// GTPv2-C fixed header (8 or 12 bytes depending on TEID presence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cHeader {
    /// Version (always 2).
    pub version: u8,
    /// Piggyback flag.
    pub piggyback: bool,
    /// TEID flag — when set, the TEID field is present.
    pub teid_flag: bool,
    /// Message type.
    pub msg_type: u8,
    /// Tunnel Endpoint Identifier (present when teid_flag is set).
    pub teid: u32,
    /// Sequence number (24 bits).
    pub sequence: u32,
}

impl Gtpv2cHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut flags: u8 = (self.version & 0x07) << 5;
        if self.piggyback {
            flags |= 0x10;
        }
        if self.teid_flag {
            flags |= 0x08;
        }
        buf.push(flags);
        buf.push(self.msg_type);
        // Length placeholder (will be filled by caller)
        buf.extend_from_slice(&0u16.to_be_bytes());
        if self.teid_flag {
            buf.extend_from_slice(&self.teid.to_be_bytes());
        }
        // Sequence number (3 bytes) + spare
        buf.push(((self.sequence >> 16) & 0xFF) as u8);
        buf.push(((self.sequence >> 8) & 0xFF) as u8);
        buf.push((self.sequence & 0xFF) as u8);
        buf.push(0); // spare
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }
        let flags = data[0];
        let version = (flags >> 5) & 0x07;
        if version != 2 {
            return None;
        }
        let piggyback = (flags & 0x10) != 0;
        let teid_flag = (flags & 0x08) != 0;
        let msg_type = data[1];
        let _length = u16::from_be_bytes([data[2], data[3]]);

        let (teid, seq_offset) = if teid_flag {
            if data.len() < 12 {
                return None;
            }
            let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            (teid, 8)
        } else {
            (0, 4)
        };

        if data.len() < seq_offset + 4 {
            return None;
        }
        let sequence = ((data[seq_offset] as u32) << 16)
            | ((data[seq_offset + 1] as u32) << 8)
            | (data[seq_offset + 2] as u32);

        let header_len = seq_offset + 4;
        Some((
            Gtpv2cHeader {
                version,
                piggyback,
                teid_flag,
                msg_type,
                teid,
                sequence,
            },
            header_len,
        ))
    }
}

// ── Information Elements ─────────────────────────────────────────────────

/// A GTPv2-C Information Element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cIe {
    pub ie_type: u8,
    pub instance: u8,
    pub data: Vec<u8>,
}

impl Gtpv2cIe {
    pub fn new(ie_type: u8, instance: u8, data: Vec<u8>) -> Self {
        Gtpv2cIe {
            ie_type,
            instance,
            data,
        }
    }

    /// Serialize to wire format: [1B type][2B length][1B CR+instance][data...]
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.data.len());
        buf.push(self.ie_type);
        buf.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        buf.push(self.instance & 0x0F); // CR=0, instance in lower 4 bits
        buf.extend_from_slice(&self.data);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let ie_type = data[0];
        let length = u16::from_be_bytes([data[1], data[2]]) as usize;
        let instance = data[3] & 0x0F;
        if data.len() < 4 + length {
            return None;
        }
        let ie_data = data[4..4 + length].to_vec();
        Some((
            Gtpv2cIe {
                ie_type,
                instance,
                data: ie_data,
            },
            4 + length,
        ))
    }
}

// ── Helper IE constructors ───────────────────────────────────────────────

/// Encodes IMSI as TBCD (Telephony Binary Coded Decimal).
pub fn encode_imsi_tbcd(imsi: &str) -> Vec<u8> {
    let digits: Vec<u8> = imsi
        .bytes()
        .filter_map(|b| {
            if b.is_ascii_digit() {
                Some(b - b'0')
            } else {
                None
            }
        })
        .collect();

    let mut buf = Vec::new();
    let mut i = 0;
    while i < digits.len() {
        let lo = digits[i];
        let hi = if i + 1 < digits.len() {
            digits[i + 1]
        } else {
            0x0F
        };
        buf.push((hi << 4) | lo);
        i += 2;
    }
    buf
}

/// Decodes TBCD-encoded IMSI to string.
pub fn decode_imsi_tbcd(data: &[u8]) -> String {
    let mut s = String::new();
    for &b in data {
        let lo = b & 0x0F;
        let hi = (b >> 4) & 0x0F;
        if lo < 10 {
            s.push((b'0' + lo) as char);
        }
        if hi < 10 {
            s.push((b'0' + hi) as char);
        }
    }
    s
}

/// Creates an IMSI IE.
pub fn ie_imsi(imsi: &str) -> Gtpv2cIe {
    Gtpv2cIe::new(IE_IMSI, 0, encode_imsi_tbcd(imsi))
}

/// Creates an APN IE (label-length encoding).
pub fn ie_apn(apn: &str) -> Gtpv2cIe {
    let mut data = Vec::new();
    for label in apn.split('.') {
        data.push(label.len() as u8);
        data.extend_from_slice(label.as_bytes());
    }
    Gtpv2cIe::new(IE_APN, 0, data)
}

/// Creates an F-TEID IE.
pub fn ie_fteid(interface_type: u8, teid: u32, ipv4: [u8; 4]) -> Gtpv2cIe {
    let mut data = Vec::with_capacity(9);
    // Flags: V4=1, V6=0, Interface Type in lower 5 bits
    data.push(0x80 | (interface_type & 0x1F));
    data.extend_from_slice(&teid.to_be_bytes());
    data.extend_from_slice(&ipv4);
    Gtpv2cIe::new(IE_FTEID, 0, data)
}

/// Creates an EBI (EPS Bearer ID) IE.
pub fn ie_ebi(ebi: u8) -> Gtpv2cIe {
    Gtpv2cIe::new(IE_EBI, 0, vec![ebi & 0x0F])
}

/// Creates a Cause IE.
pub fn ie_cause(cause: u8) -> Gtpv2cIe {
    Gtpv2cIe::new(IE_CAUSE, 0, vec![cause, 0]) // cause + spare
}

// ── GTPv2-C Message ──────────────────────────────────────────────────────

/// A complete GTPv2-C message (header + IEs).
#[derive(Debug, Clone)]
pub struct Gtpv2cMessage {
    pub header: Gtpv2cHeader,
    pub ies: Vec<Gtpv2cIe>,
}

impl Gtpv2cMessage {
    /// Creates a Create Session Request.
    pub fn create_session_request(
        teid: u32,
        sequence: u32,
        imsi: &str,
        apn: &str,
        sender_fteid_teid: u32,
        sender_fteid_ip: [u8; 4],
        ebi: u8,
    ) -> Self {
        let header = Gtpv2cHeader {
            version: 2,
            piggyback: false,
            teid_flag: true,
            msg_type: GTPV2C_CREATE_SESSION_REQ,
            teid,
            sequence,
        };

        let ies = vec![
            ie_imsi(imsi),
            ie_apn(apn),
            ie_fteid(FTEID_S11_MME, sender_fteid_teid, sender_fteid_ip),
            ie_ebi(ebi),
        ];

        Gtpv2cMessage { header, ies }
    }

    /// Creates a Create Session Response.
    pub fn create_session_response(
        req: &Gtpv2cMessage,
        cause: u8,
        sgw_fteid_teid: u32,
        sgw_fteid_ip: [u8; 4],
    ) -> Self {
        let header = Gtpv2cHeader {
            version: 2,
            piggyback: false,
            teid_flag: true,
            msg_type: GTPV2C_CREATE_SESSION_RSP,
            teid: req.header.teid,
            sequence: req.header.sequence,
        };

        let ies = vec![
            ie_cause(cause),
            ie_fteid(FTEID_S11_SGW, sgw_fteid_teid, sgw_fteid_ip),
        ];

        Gtpv2cMessage { header, ies }
    }

    /// Serializes the complete message.
    pub fn serialize(&self) -> Vec<u8> {
        let mut hdr = self.header.serialize();
        let mut ie_buf = Vec::new();
        for ie in &self.ies {
            ie_buf.extend_from_slice(&ie.serialize());
        }
        // Fill in length field (bytes 2-3): length of everything after
        // the first 4 bytes (flags + type + length).
        let body_len = (hdr.len() - 4 + ie_buf.len()) as u16;
        hdr[2] = (body_len >> 8) as u8;
        hdr[3] = (body_len & 0xFF) as u8;

        let mut buf = Vec::with_capacity(hdr.len() + ie_buf.len());
        buf.extend_from_slice(&hdr);
        buf.extend_from_slice(&ie_buf);
        buf
    }

    /// Parses a GTPv2-C message from wire bytes.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let (header, hdr_len) = Gtpv2cHeader::parse(data)?;
        let mut offset = hdr_len;
        let mut ies = Vec::new();
        while offset < data.len() {
            let (ie, ie_len) = Gtpv2cIe::parse(&data[offset..])?;
            ies.push(ie);
            offset += ie_len;
        }
        Some(Gtpv2cMessage { header, ies })
    }

    /// Finds the first IE of a given type.
    pub fn find_ie(&self, ie_type: u8) -> Option<&Gtpv2cIe> {
        self.ies.iter().find(|ie| ie.ie_type == ie_type)
    }
}

// ── SGW Session Engine ───────────────────────────────────────────────────

/// Represents an active GTP-C session at the SGW.
#[derive(Debug, Clone)]
pub struct GtpcSession {
    pub imsi: String,
    pub apn: String,
    pub mme_teid: u32,
    pub sgw_teid: u32,
    pub ebi: u8,
}

/// Simple SGW engine processing Create Session Requests.
#[derive(Debug, Clone)]
pub struct SgwEngine {
    pub sessions: Vec<GtpcSession>,
    pub next_teid: u32,
}

impl SgwEngine {
    pub fn new() -> Self {
        SgwEngine {
            sessions: Vec::new(),
            next_teid: 0x1000,
        }
    }

    /// Processes a Create Session Request and returns a Response.
    pub fn process_create_session(&mut self, req: &Gtpv2cMessage) -> Gtpv2cMessage {
        let imsi_ie = req.find_ie(IE_IMSI);
        let apn_ie = req.find_ie(IE_APN);
        let fteid_ie = req.find_ie(IE_FTEID);
        let ebi_ie = req.find_ie(IE_EBI);

        let imsi = imsi_ie
            .map(|ie| decode_imsi_tbcd(&ie.data))
            .unwrap_or_default();
        let apn = apn_ie
            .map(|ie| {
                // Decode label-length APN
                let mut s = String::new();
                let mut i = 0;
                let d = &ie.data;
                while i < d.len() {
                    let label_len = d[i] as usize;
                    i += 1;
                    if i + label_len > d.len() {
                        break;
                    }
                    if !s.is_empty() {
                        s.push('.');
                    }
                    s.push_str(&String::from_utf8_lossy(&d[i..i + label_len]));
                    i += label_len;
                }
                s
            })
            .unwrap_or_default();

        let mme_teid = fteid_ie
            .map(|ie| {
                if ie.data.len() >= 5 {
                    u32::from_be_bytes([ie.data[1], ie.data[2], ie.data[3], ie.data[4]])
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let ebi = ebi_ie
            .map(|ie| ie.data.first().copied().unwrap_or(5))
            .unwrap_or(5);

        let sgw_teid = self.next_teid;
        self.next_teid += 1;

        self.sessions.push(GtpcSession {
            imsi: imsi.clone(),
            apn,
            mme_teid,
            sgw_teid,
            ebi,
        });

        let sgw_ip = [10, 0, 1, 1];
        Gtpv2cMessage::create_session_response(req, CAUSE_REQUEST_ACCEPTED, sgw_teid, sgw_ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_imsi_tbcd_roundtrip() {
        let imsi = "310260123456789";
        let encoded = encode_imsi_tbcd(imsi);
        let decoded = decode_imsi_tbcd(&encoded);
        assert_eq!(decoded, imsi);
    }

    #[test]
    fn test_gtpv2c_header_roundtrip() {
        let hdr = Gtpv2cHeader {
            version: 2,
            piggyback: false,
            teid_flag: true,
            msg_type: GTPV2C_CREATE_SESSION_REQ,
            teid: 0xDEADBEEF,
            sequence: 0x00ABCD,
        };
        let buf = hdr.serialize();
        let (parsed, _) = Gtpv2cHeader::parse(&buf).unwrap();
        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.teid, 0xDEADBEEF);
        assert_eq!(parsed.sequence, 0x00ABCD);
        assert_eq!(parsed.msg_type, GTPV2C_CREATE_SESSION_REQ);
    }

    #[test]
    fn test_create_session_flow() {
        let req = Gtpv2cMessage::create_session_request(
            0,                  // TEID (0 for initial)
            1,                  // Sequence
            "310260123456789",  // IMSI
            "internet.lte.com", // APN
            0x0001,             // MME F-TEID
            [10, 0, 0, 1],      // MME IP
            5,                  // EBI
        );

        assert_eq!(req.header.msg_type, GTPV2C_CREATE_SESSION_REQ);
        assert!(req.find_ie(IE_IMSI).is_some());
        assert!(req.find_ie(IE_APN).is_some());

        // Serialize and re-parse
        let wire = req.serialize();
        let parsed = Gtpv2cMessage::parse(&wire).unwrap();
        assert_eq!(parsed.header.msg_type, GTPV2C_CREATE_SESSION_REQ);
        assert_eq!(parsed.ies.len(), req.ies.len());

        // SGW processes
        let mut sgw = SgwEngine::new();
        let rsp = sgw.process_create_session(&parsed);
        assert_eq!(rsp.header.msg_type, GTPV2C_CREATE_SESSION_RSP);

        let cause_ie = rsp.find_ie(IE_CAUSE).unwrap();
        assert_eq!(cause_ie.data[0], CAUSE_REQUEST_ACCEPTED);
        assert_eq!(sgw.sessions.len(), 1);
        assert_eq!(sgw.sessions[0].imsi, "310260123456789");
    }

    #[test]
    fn test_ie_roundtrip() {
        let ie = ie_fteid(FTEID_S11_MME, 0x12345678, [192, 168, 1, 1]);
        let wire = ie.serialize();
        let (parsed, consumed) = Gtpv2cIe::parse(&wire).unwrap();
        assert_eq!(consumed, wire.len());
        assert_eq!(parsed.ie_type, IE_FTEID);
        assert_eq!(parsed.data, ie.data);
    }
}
