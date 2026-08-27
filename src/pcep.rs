//! Path Computation Element Communication Protocol (PCEP - RFC 5440 / RFC 8664 SR-MPLS).
//!
//! Centralized SDN controller path computation and Segment Routing label stack signaling over TCP port 4189.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const PCEP_PORT: u16 = 4189;

// PCEP Message Types
pub const PCEP_MSG_OPEN: u8 = 1;
pub const PCEP_MSG_KEEPALIVE: u8 = 2;
pub const PCEP_MSG_PCREQ: u8 = 3;
pub const PCEP_MSG_PCREP: u8 = 4;
pub const PCEP_MSG_PCRPT: u8 = 10;
pub const PCEP_MSG_PCUPD: u8 = 11;

// PCEP Object Classes
pub const PCEP_CLASS_OPEN: u8 = 1;
pub const PCEP_CLASS_RP: u8 = 2;
pub const PCEP_CLASS_END_POINTS: u8 = 4;
pub const PCEP_CLASS_ERO: u8 = 7;
pub const PCEP_CLASS_LSP: u8 = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcepHeader {
    pub version: u8,
    pub flags: u8,
    pub msg_type: u8,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcepObject {
    Open {
        version: u8,
        keepalive_s: u8,
        deadtimer_s: u8,
        sid: u8,
    },
    Rp {
        request_id: u32,
        priority: u8,
        is_strict: bool,
    },
    EndPointsIpv4 {
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
    },
    Lsp {
        plsp_id: u32,
        is_delegated: bool,
        is_operational: bool,
    },
    SrEro {
        sids: Vec<u32>, // Segment Routing Node / Adjacency SIDs
    },
    Raw {
        class_num: u8,
        ot: u8,
        body: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcepMessage {
    pub header: PcepHeader,
    pub objects: Vec<PcepObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcepError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidLength,
    InvalidObjectFraming,
}

impl fmt::Display for PcepError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PcepError::PacketTooShort(l) => write!(f, "PCEP message too short ({} bytes)", l),
            PcepError::InvalidVersion(v) => write!(f, "Unsupported PCEP version: {}", v),
            PcepError::InvalidLength => write!(f, "Invalid PCEP length"),
            PcepError::InvalidObjectFraming => write!(f, "Malformed PCEP object framing"),
        }
    }
}

impl std::error::Error for PcepError {}

impl PcepObject {
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let (class_num, ot) = match self {
            PcepObject::Open {
                version,
                keepalive_s,
                deadtimer_s,
                sid,
            } => {
                body.push(version << 5);
                body.push(*keepalive_s);
                body.push(*deadtimer_s);
                body.push(*sid);
                (PCEP_CLASS_OPEN, 1)
            }
            PcepObject::Rp {
                request_id,
                priority,
                is_strict,
            } => {
                body.extend_from_slice(&[0, 0, 0, 0]); // Reserved + Flags
                let mut f = *priority & 0x07;
                if *is_strict {
                    f |= 0x08;
                }
                body[3] = f;
                body.extend_from_slice(&request_id.to_be_bytes());
                (PCEP_CLASS_RP, 1)
            }
            PcepObject::EndPointsIpv4 { src_ip, dst_ip } => {
                body.extend_from_slice(&src_ip.0);
                body.extend_from_slice(&dst_ip.0);
                (PCEP_CLASS_END_POINTS, 1)
            }
            PcepObject::Lsp {
                plsp_id,
                is_delegated,
                is_operational,
            } => {
                let mut flags: u32 = 0;
                if *is_delegated {
                    flags |= 0x01; // D-flag
                }
                if *is_operational {
                    flags |= 0x08; // O-flag (Up)
                }
                let w = (plsp_id << 12) | (flags & 0xFFF);
                body.extend_from_slice(&w.to_be_bytes());
                (PCEP_CLASS_LSP, 1)
            }
            PcepObject::SrEro { sids } => {
                for &sid in sids {
                    body.push(36); // SR-ERO Subobject Type
                    body.push(8); // Subobject Length
                    body.extend_from_slice(&[0, 0]); // Flags
                    body.extend_from_slice(&sid.to_be_bytes()); // 32-bit SID / Label
                }
                (PCEP_CLASS_ERO, 1)
            }
            PcepObject::Raw {
                class_num,
                ot,
                body: b,
            } => {
                body.extend_from_slice(b);
                (*class_num, *ot)
            }
        };

        let obj_len = (4 + body.len()) as u16;
        let mut buf = Vec::new();
        buf.push(class_num);
        buf.push((ot << 4) & 0xF0);
        buf.extend_from_slice(&obj_len.to_be_bytes());
        buf.extend_from_slice(&body);
        while buf.len() % 4 != 0 {
            buf.push(0x00);
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }

        let class_num = data[0];
        let ot = data[1] >> 4;
        let obj_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        if obj_len < 4 || obj_len > data.len() {
            return None;
        }

        let body = &data[4..obj_len];
        let obj = match (class_num, ot) {
            (PCEP_CLASS_OPEN, 1) if body.len() >= 4 => {
                let version = body[0] >> 5;
                let keepalive_s = body[1];
                let deadtimer_s = body[2];
                let sid = body[3];
                PcepObject::Open {
                    version,
                    keepalive_s,
                    deadtimer_s,
                    sid,
                }
            }
            (PCEP_CLASS_RP, 1) if body.len() >= 8 => {
                let priority = body[3] & 0x07;
                let is_strict = (body[3] & 0x08) != 0;
                let request_id = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                PcepObject::Rp {
                    request_id,
                    priority,
                    is_strict,
                }
            }
            (PCEP_CLASS_END_POINTS, 1) if body.len() >= 8 => {
                let src_ip = Ipv4Address([body[0], body[1], body[2], body[3]]);
                let dst_ip = Ipv4Address([body[4], body[5], body[6], body[7]]);
                PcepObject::EndPointsIpv4 { src_ip, dst_ip }
            }
            (PCEP_CLASS_LSP, 1) if body.len() >= 4 => {
                let w = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let plsp_id = w >> 12;
                let is_delegated = (w & 0x01) != 0;
                let is_operational = (w & 0x08) != 0;
                PcepObject::Lsp {
                    plsp_id,
                    is_delegated,
                    is_operational,
                }
            }
            (PCEP_CLASS_ERO, 1) => {
                let mut sids = Vec::new();
                let mut offset = 0;
                while offset < body.len() {
                    if offset + 2 > body.len() {
                        return None;
                    }

                    let sub_type = body[offset] & 0x7F;
                    let sub_len = body[offset + 1] as usize;
                    if sub_len < 2 || offset + sub_len > body.len() {
                        return None;
                    }

                    if sub_type == 36 {
                        if sub_len < 8 || sub_len % 4 != 0 {
                            return None;
                        }
                        let sid = u32::from_be_bytes([
                            body[offset + 4],
                            body[offset + 5],
                            body[offset + 6],
                            body[offset + 7],
                        ]);
                        sids.push(sid);
                    }
                    offset += sub_len;
                }
                PcepObject::SrEro { sids }
            }
            _ => PcepObject::Raw {
                class_num,
                ot,
                body: body.to_vec(),
            },
        };

        let consumed = (obj_len + 3) & !3;
        if consumed > data.len() {
            return None;
        }
        Some((obj, consumed))
    }
}

impl PcepMessage {
    pub fn build_open(keepalive_s: u8, deadtimer_s: u8, sid: u8) -> Self {
        let header = PcepHeader {
            version: 1,
            flags: 0,
            msg_type: PCEP_MSG_OPEN,
            length: 0,
        };

        let objects = vec![PcepObject::Open {
            version: 1,
            keepalive_s,
            deadtimer_s,
            sid,
        }];

        PcepMessage { header, objects }
    }

    pub fn build_pcreq(req_id: u32, src_ip: Ipv4Address, dst_ip: Ipv4Address) -> Self {
        let header = PcepHeader {
            version: 1,
            flags: 0,
            msg_type: PCEP_MSG_PCREQ,
            length: 0,
        };

        let objects = vec![
            PcepObject::Rp {
                request_id: req_id,
                priority: 1,
                is_strict: true,
            },
            PcepObject::EndPointsIpv4 { src_ip, dst_ip },
        ];

        PcepMessage { header, objects }
    }

    pub fn build_pcrep_sr(req_id: u32, segment_list_sids: &[u32]) -> Self {
        let header = PcepHeader {
            version: 1,
            flags: 0,
            msg_type: PCEP_MSG_PCREP,
            length: 0,
        };

        let objects = vec![
            PcepObject::Rp {
                request_id: req_id,
                priority: 1,
                is_strict: true,
            },
            PcepObject::SrEro {
                sids: segment_list_sids.to_vec(),
            },
        ];

        PcepMessage { header, objects }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut obj_bytes = Vec::new();
        for obj in &self.objects {
            obj_bytes.extend_from_slice(&obj.serialize());
        }

        let total_len = (4 + obj_bytes.len()) as u16;
        let mut buf = Vec::new();
        let b0 = (self.header.version << 5) | (self.header.flags & 0x1F);
        buf.push(b0);
        buf.push(self.header.msg_type);
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&obj_bytes);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, PcepError> {
        if data.len() < 4 {
            return Err(PcepError::PacketTooShort(data.len()));
        }

        let version = data[0] >> 5;
        if version != 1 {
            return Err(PcepError::InvalidVersion(version));
        }

        let flags = data[0] & 0x1F;
        let msg_type = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]) as usize;

        if length < 4 || length > data.len() {
            return Err(PcepError::InvalidLength);
        }

        let mut objects = Vec::new();
        let mut offset = 4;

        while offset < length {
            let (obj, consumed) =
                PcepObject::parse(&data[offset..length]).ok_or(PcepError::InvalidObjectFraming)?;
            objects.push(obj);
            offset += consumed;
        }

        Ok(PcepMessage {
            header: PcepHeader {
                version,
                flags,
                msg_type,
                length: length as u16,
            },
            objects,
        })
    }
}

/// Simulated in-memory Path Computation Element (PCE) Session
#[derive(Debug, Clone, Default)]
pub struct PcepSession {
    pub is_open: bool,
    pub computed_srs: Vec<(u32, Vec<u32>)>, // (req_id, SIDs)
}

impl PcepSession {
    pub fn new() -> Self {
        PcepSession {
            is_open: true,
            computed_srs: Vec::new(),
        }
    }

    pub fn compute_path(&mut self, req: &PcepMessage) -> Option<PcepMessage> {
        if req.header.msg_type != PCEP_MSG_PCREQ {
            return None;
        }

        let mut req_id = 1;
        for obj in &req.objects {
            if let PcepObject::Rp { request_id, .. } = obj {
                req_id = *request_id;
            }
        }

        // Return computed Segment Routing MPLS Label Stack (e.g. Node-SID 16001 -> Adj-SID 24001 -> Node-SID 16004)
        let sids = vec![16001, 24001, 16004];
        self.computed_srs.push((req_id, sids.clone()));
        Some(PcepMessage::build_pcrep_sr(req_id, &sids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcep_sr_path_computation_request_and_reply() {
        let src = Ipv4Address::new(10, 0, 0, 1);
        let dst = Ipv4Address::new(10, 0, 0, 4);

        let req = PcepMessage::build_pcreq(101, src, dst);
        let raw_req = req.serialize();
        assert!(raw_req.len() >= 4);

        let parsed_req = PcepMessage::parse(&raw_req).unwrap();
        assert_eq!(parsed_req.header.msg_type, PCEP_MSG_PCREQ);
        assert_eq!(parsed_req.objects.len(), 2);

        let mut session = PcepSession::new();
        let rep = session.compute_path(&parsed_req).unwrap();
        let raw_rep = rep.serialize();

        let parsed_rep = PcepMessage::parse(&raw_rep).unwrap();
        assert_eq!(parsed_rep.header.msg_type, PCEP_MSG_PCREP);

        if let PcepObject::SrEro { sids } = &parsed_rep.objects[1] {
            assert_eq!(sids, &[16001, 24001, 16004]);
        } else {
            panic!("Expected SR-ERO object");
        }

        assert_eq!(PCEP_PORT, 4189);
    }

    #[test]
    fn test_pcep_rejects_message_length_below_header() {
        let raw = [0x20, PCEP_MSG_KEEPALIVE, 0, 3];
        assert_eq!(PcepMessage::parse(&raw), Err(PcepError::InvalidLength));
    }

    #[test]
    fn test_pcep_rejects_trailing_partial_object_header() {
        let raw = [0x20, PCEP_MSG_KEEPALIVE, 0, 5, 0xAA];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_rejects_object_overrun() {
        let raw = [0x20, PCEP_MSG_KEEPALIVE, 0, 8, 99, 0x10, 0, 8];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_rejects_missing_object_alignment_padding() {
        let raw = [0x20, PCEP_MSG_KEEPALIVE, 0, 9, 99, 0x10, 0, 5, 0xAA];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_header_only_message_remains_valid() {
        let raw = [0x20, PCEP_MSG_KEEPALIVE, 0, 4];
        let parsed = PcepMessage::parse(&raw).unwrap();
        assert_eq!(parsed.header.length, 4);
        assert!(parsed.objects.is_empty());
    }

    #[test]
    fn test_pcep_padded_raw_object_remains_valid() {
        let raw = [
            0x20,
            PCEP_MSG_KEEPALIVE,
            0,
            12,
            99,
            0x10,
            0,
            5,
            0xAA,
            0,
            0,
            0,
        ];
        let parsed = PcepMessage::parse(&raw).unwrap();
        assert_eq!(parsed.objects.len(), 1);
        assert_eq!(
            parsed.objects[0],
            PcepObject::Raw {
                class_num: 99,
                ot: 1,
                body: vec![0xAA],
            }
        );
    }

    #[test]
    fn test_pcep_rejects_sr_ero_subobject_overrun() {
        let raw = [
            0x20,
            PCEP_MSG_PCREP,
            0,
            16,
            PCEP_CLASS_ERO,
            0x10,
            0,
            12,
            36,
            12,
            0,
            0,
            0,
            0,
            0,
            1,
        ];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_rejects_short_sr_ero_subobject() {
        let raw = [
            0x20,
            PCEP_MSG_PCREP,
            0,
            16,
            PCEP_CLASS_ERO,
            0x10,
            0,
            12,
            36,
            7,
            0,
            0,
            0,
            0,
            0,
            1,
        ];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_rejects_unaligned_sr_ero_subobject_length() {
        let raw = [
            0x20,
            PCEP_MSG_PCREP,
            0,
            20,
            PCEP_CLASS_ERO,
            0x10,
            0,
            14,
            36,
            10,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(
            PcepMessage::parse(&raw),
            Err(PcepError::InvalidObjectFraming)
        );
    }

    #[test]
    fn test_pcep_sr_ero_loose_hop_type_is_recognized() {
        let raw = [
            0x20,
            PCEP_MSG_PCREP,
            0,
            16,
            PCEP_CLASS_ERO,
            0x10,
            0,
            12,
            0x80 | 36,
            8,
            0,
            0,
            0,
            0,
            0,
            42,
        ];
        let parsed = PcepMessage::parse(&raw).unwrap();
        assert_eq!(parsed.objects, vec![PcepObject::SrEro { sids: vec![42] }]);
    }
}
