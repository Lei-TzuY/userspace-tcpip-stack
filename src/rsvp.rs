//! Resource Reservation Protocol with Traffic Engineering (RSVP-TE - RFC 3209).
//!
//! MPLS-TE Explicit Route LSP signaling and QoS bandwidth reservation over IP Protocol 46.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const IP_PROTO_RSVP: u8 = 46;

// RSVP Message Types
pub const RSVP_MSG_PATH: u8 = 1;
pub const RSVP_MSG_RESV: u8 = 2;
pub const RSVP_MSG_PATH_ERR: u8 = 3;
pub const RSVP_MSG_RESV_ERR: u8 = 4;
pub const RSVP_MSG_PATH_TEAR: u8 = 5;
pub const RSVP_MSG_RESV_TEAR: u8 = 6;

// RSVP Object Classes
pub const RSVP_CLASS_SESSION: u8 = 1;
pub const RSVP_CLASS_RESV_CONFIRM: u8 = 15;
pub const RSVP_CLASS_LABEL: u8 = 16;
pub const RSVP_CLASS_LABEL_REQUEST: u8 = 19;
pub const RSVP_CLASS_EXPLICIT_ROUTE: u8 = 20;
pub const RSVP_CLASS_SENDER_TEMPLATE: u8 = 11;
pub const RSVP_CLASS_SENDER_TSPEC: u8 = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsvpHeader {
    pub version: u8,
    pub flags: u8,
    pub msg_type: u8,
    pub checksum: u16,
    pub send_ttl: u8,
    pub length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsvpObject {
    Session {
        dest_ip: Ipv4Address,
        tunnel_id: u16,
        ext_tunnel_id: Ipv4Address,
    },
    ExplicitRoute {
        hops: Vec<(bool, Ipv4Address)>, // (is_loose, hop_ip)
    },
    LabelRequest {
        l3pid: u16, // EtherType (e.g., 0x0800 IPv4)
    },
    Label {
        label: u32,
    },
    SenderTemplate {
        src_ip: Ipv4Address,
        lsp_id: u16,
    },
    SenderTspec {
        bandwidth_bps: u32,
        peak_rate_bps: u32,
    },
    Raw {
        class_num: u8,
        c_type: u8,
        body: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsvpPacket {
    pub header: RsvpHeader,
    pub objects: Vec<RsvpObject>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsvpError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidLength,
}

impl fmt::Display for RsvpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RsvpError::PacketTooShort(l) => write!(f, "RSVP packet too short ({} bytes)", l),
            RsvpError::InvalidVersion(v) => write!(f, "Unsupported RSVP version: {}", v),
            RsvpError::InvalidLength => write!(f, "Invalid RSVP length"),
        }
    }
}

impl std::error::Error for RsvpError {}

impl RsvpObject {
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        let (class_num, c_type) = match self {
            RsvpObject::Session {
                dest_ip,
                tunnel_id,
                ext_tunnel_id,
            } => {
                body.extend_from_slice(&dest_ip.0);
                body.extend_from_slice(&tunnel_id.to_be_bytes());
                body.extend_from_slice(&[0, 0]); // Must be zero
                body.extend_from_slice(&ext_tunnel_id.0);
                (RSVP_CLASS_SESSION, 7) // LSP_TUNNEL_IPv4
            }
            RsvpObject::ExplicitRoute { hops } => {
                for &(loose, hop_ip) in hops {
                    let mut b0 = 1u8; // IPv4 prefix subobject
                    if loose {
                        b0 |= 0x80;
                    }
                    body.push(b0);
                    body.push(8); // subobject length
                    body.extend_from_slice(&hop_ip.0);
                    body.push(32); // Prefix length = 32
                    body.push(0x00); // Padding
                }
                (RSVP_CLASS_EXPLICIT_ROUTE, 1)
            }
            RsvpObject::LabelRequest { l3pid } => {
                body.extend_from_slice(&[0, 0]); // Reserved
                body.extend_from_slice(&l3pid.to_be_bytes());
                (RSVP_CLASS_LABEL_REQUEST, 1)
            }
            RsvpObject::Label { label } => {
                body.extend_from_slice(&label.to_be_bytes());
                (RSVP_CLASS_LABEL, 1)
            }
            RsvpObject::SenderTemplate { src_ip, lsp_id } => {
                body.extend_from_slice(&src_ip.0);
                body.extend_from_slice(&lsp_id.to_be_bytes());
                body.extend_from_slice(&[0, 0]);
                (RSVP_CLASS_SENDER_TEMPLATE, 7)
            }
            RsvpObject::SenderTspec {
                bandwidth_bps,
                peak_rate_bps,
            } => {
                body.extend_from_slice(&bandwidth_bps.to_be_bytes());
                body.extend_from_slice(&peak_rate_bps.to_be_bytes());
                (RSVP_CLASS_SENDER_TSPEC, 2)
            }
            RsvpObject::Raw {
                class_num,
                c_type,
                body: b,
            } => {
                body.extend_from_slice(b);
                (*class_num, *c_type)
            }
        };

        while body.len() % 4 != 0 {
            body.push(0x00);
        }
        let obj_len = (body.len() + 4) as u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&obj_len.to_be_bytes());
        buf.push(class_num);
        buf.push(c_type);
        buf.extend_from_slice(&body);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let obj_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        if obj_len < 4 || obj_len > data.len() || obj_len % 4 != 0 {
            return None;
        }

        let class_num = data[2];
        let c_type = data[3];
        let body = &data[4..obj_len];

        let obj = match (class_num, c_type) {
            (RSVP_CLASS_SESSION, 7) if body.len() >= 12 => {
                let dest_ip = Ipv4Address([body[0], body[1], body[2], body[3]]);
                let tunnel_id = u16::from_be_bytes([body[4], body[5]]);
                let ext_tunnel_id = Ipv4Address([body[8], body[9], body[10], body[11]]);
                RsvpObject::Session {
                    dest_ip,
                    tunnel_id,
                    ext_tunnel_id,
                }
            }
            (RSVP_CLASS_EXPLICIT_ROUTE, 1) => {
                let mut hops = Vec::new();
                let mut offset = 0;
                let mut has_unsupported_subobject = false;

                while offset < body.len() {
                    if body.len() - offset < 4 {
                        return None;
                    }

                    let sub_type = body[offset] & 0x7f;
                    let sub_len = body[offset + 1] as usize;
                    if sub_len < 4 || sub_len % 4 != 0 || sub_len > body.len() - offset {
                        return None;
                    }

                    if sub_type == 1 {
                        if sub_len != 8 || body[offset + 6] > 32 {
                            return None;
                        }
                        let loose = (body[offset] & 0x80) != 0;
                        let hop_ip = Ipv4Address([
                            body[offset + 2],
                            body[offset + 3],
                            body[offset + 4],
                            body[offset + 5],
                        ]);
                        hops.push((loose, hop_ip));
                    } else {
                        has_unsupported_subobject = true;
                    }

                    offset += sub_len;
                }

                if has_unsupported_subobject {
                    RsvpObject::Raw {
                        class_num,
                        c_type,
                        body: body.to_vec(),
                    }
                } else {
                    RsvpObject::ExplicitRoute { hops }
                }
            }
            (RSVP_CLASS_LABEL_REQUEST, 1) if body.len() >= 4 => {
                let l3pid = u16::from_be_bytes([body[2], body[3]]);
                RsvpObject::LabelRequest { l3pid }
            }
            (RSVP_CLASS_LABEL, 1) if body.len() >= 4 => {
                let label = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                RsvpObject::Label { label }
            }
            (RSVP_CLASS_SENDER_TEMPLATE, 7) if body.len() >= 8 => {
                let src_ip = Ipv4Address([body[0], body[1], body[2], body[3]]);
                let lsp_id = u16::from_be_bytes([body[4], body[5]]);
                RsvpObject::SenderTemplate { src_ip, lsp_id }
            }
            (RSVP_CLASS_SENDER_TSPEC, 2) if body.len() >= 8 => {
                let bandwidth_bps = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let peak_rate_bps = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                RsvpObject::SenderTspec {
                    bandwidth_bps,
                    peak_rate_bps,
                }
            }
            _ => RsvpObject::Raw {
                class_num,
                c_type,
                body: body.to_vec(),
            },
        };

        Some((obj, obj_len))
    }
}

impl RsvpPacket {
    pub fn build_path(
        src_ip: Ipv4Address,
        dest_ip: Ipv4Address,
        tunnel_id: u16,
        lsp_id: u16,
        bandwidth_bps: u32,
        ero_hops: &[(bool, Ipv4Address)],
    ) -> Self {
        let header = RsvpHeader {
            version: 1,
            flags: 0,
            msg_type: RSVP_MSG_PATH,
            checksum: 0,
            send_ttl: 64,
            length: 0,
        };

        let objects = vec![
            RsvpObject::Session {
                dest_ip,
                tunnel_id,
                ext_tunnel_id: src_ip,
            },
            RsvpObject::SenderTemplate { src_ip, lsp_id },
            RsvpObject::SenderTspec {
                bandwidth_bps,
                peak_rate_bps: bandwidth_bps * 2,
            },
            RsvpObject::LabelRequest { l3pid: 0x0800 },
            RsvpObject::ExplicitRoute {
                hops: ero_hops.to_vec(),
            },
        ];

        RsvpPacket { header, objects }
    }

    pub fn build_resv(
        src_ip: Ipv4Address,
        dest_ip: Ipv4Address,
        tunnel_id: u16,
        allocated_label: u32,
    ) -> Self {
        let header = RsvpHeader {
            version: 1,
            flags: 0,
            msg_type: RSVP_MSG_RESV,
            checksum: 0,
            send_ttl: 64,
            length: 0,
        };

        let objects = vec![
            RsvpObject::Session {
                dest_ip,
                tunnel_id,
                ext_tunnel_id: src_ip,
            },
            RsvpObject::Label {
                label: allocated_label,
            },
        ];

        RsvpPacket { header, objects }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut obj_bytes = Vec::new();
        for obj in &self.objects {
            obj_bytes.extend_from_slice(&obj.serialize());
        }

        let total_len = (8 + obj_bytes.len()) as u16;
        let mut buf = Vec::new();
        let b0 = (self.header.version << 4) | (self.header.flags & 0x0F);
        buf.push(b0);
        buf.push(self.header.msg_type);
        buf.extend_from_slice(&0u16.to_be_bytes()); // Checksum placeholder
        buf.push(self.header.send_ttl);
        buf.push(0); // Reserved
        buf.extend_from_slice(&total_len.to_be_bytes());
        buf.extend_from_slice(&obj_bytes);

        // Compute 16-bit Internet checksum
        let csum = crate::checksum::compute_checksum(&buf);
        buf[2..4].copy_from_slice(&csum.to_be_bytes());

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, RsvpError> {
        if data.len() < 8 {
            return Err(RsvpError::PacketTooShort(data.len()));
        }

        let version = data[0] >> 4;
        if version != 1 {
            return Err(RsvpError::InvalidVersion(version));
        }

        let flags = data[0] & 0x0F;
        let msg_type = data[1];
        let checksum = u16::from_be_bytes([data[2], data[3]]);
        let send_ttl = data[4];
        let length = u16::from_be_bytes([data[6], data[7]]) as usize;

        if length < 8 || length > data.len() {
            return Err(RsvpError::InvalidLength);
        }

        let mut objects = Vec::new();
        let mut offset = 8;

        while offset < length {
            if let Some((obj, consumed)) = RsvpObject::parse(&data[offset..length]) {
                objects.push(obj);
                offset += consumed;
            } else {
                return Err(RsvpError::InvalidLength);
            }
        }

        Ok(RsvpPacket {
            header: RsvpHeader {
                version,
                flags,
                msg_type,
                checksum,
                send_ttl,
                length: length as u16,
            },
            objects,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ero_object(body: &[u8]) -> Vec<u8> {
        let obj_len = (body.len() + 4) as u16;
        let mut data = Vec::with_capacity(obj_len as usize);
        data.extend_from_slice(&obj_len.to_be_bytes());
        data.push(RSVP_CLASS_EXPLICIT_ROUTE);
        data.push(1);
        data.extend_from_slice(body);
        data
    }

    #[test]
    fn test_rsvp_path_and_resv_signaling() {
        let src = Ipv4Address::new(10, 0, 0, 1);
        let dst = Ipv4Address::new(10, 0, 0, 4);
        let ero = vec![
            (false, Ipv4Address::new(10, 0, 0, 2)),
            (false, Ipv4Address::new(10, 0, 0, 3)),
            (false, dst),
        ];

        let path = RsvpPacket::build_path(src, dst, 101, 1, 100_000_000, &ero);
        let raw_path = path.serialize();

        let parsed_path = RsvpPacket::parse(&raw_path).unwrap();
        assert_eq!(parsed_path.header.msg_type, RSVP_MSG_PATH);
        assert_eq!(parsed_path.objects.len(), 5);

        // Verify ERO object
        if let RsvpObject::ExplicitRoute { hops } = &parsed_path.objects[4] {
            assert_eq!(hops.len(), 3);
            assert_eq!(hops[0].1, Ipv4Address::new(10, 0, 0, 2));
        } else {
            panic!("Expected ERO object");
        }

        // RESV response with allocated label 500
        let resv = RsvpPacket::build_resv(src, dst, 101, 500);
        let raw_resv = resv.serialize();
        let parsed_resv = RsvpPacket::parse(&raw_resv).unwrap();
        assert_eq!(parsed_resv.header.msg_type, RSVP_MSG_RESV);
        if let RsvpObject::Label { label } = &parsed_resv.objects[1] {
            assert_eq!(*label, 500);
        } else {
            panic!("Expected Label object");
        }
    }

    #[test]
    fn test_rsvp_ero_rejects_ipv4_subobject_length_below_eight() {
        let raw = ero_object(&[1, 4, 10, 0, 0, 1, 32, 0]);
        assert!(RsvpObject::parse(&raw).is_none());
    }

    #[test]
    fn test_rsvp_ero_rejects_non_word_aligned_subobject_length() {
        let raw = ero_object(&[1, 6, 10, 0, 0, 1, 32, 0]);
        assert!(RsvpObject::parse(&raw).is_none());
    }

    #[test]
    fn test_rsvp_ero_rejects_subobject_length_beyond_object_body() {
        let raw = ero_object(&[1, 12, 10, 0, 0, 1, 32, 0]);
        assert!(RsvpObject::parse(&raw).is_none());
    }

    #[test]
    fn test_rsvp_ero_rejects_trailing_partial_subobject() {
        let raw = ero_object(&[1, 8, 10, 0, 0, 1, 32, 0, 1, 8, 10, 0]);
        assert!(RsvpObject::parse(&raw).is_none());
    }

    #[test]
    fn test_rsvp_ero_rejects_invalid_ipv4_prefix_length() {
        let raw = ero_object(&[1, 8, 10, 0, 0, 1, 33, 0]);
        assert!(RsvpObject::parse(&raw).is_none());
    }

    #[test]
    fn test_rsvp_ero_preserves_unsupported_subobjects_as_raw() {
        let body = vec![2, 8, 0, 0, 0, 0, 0, 0];
        let raw = ero_object(&body);
        let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();

        assert_eq!(consumed, raw.len());
        assert_eq!(
            parsed,
            RsvpObject::Raw {
                class_num: RSVP_CLASS_EXPLICIT_ROUTE,
                c_type: 1,
                body,
            }
        );
    }

    #[test]
    fn test_rsvp_ero_valid_ipv4_subobjects_preserve_loose_bit() {
        let raw = ero_object(&[1, 8, 10, 0, 0, 1, 32, 0, 0x81, 8, 10, 0, 0, 2, 32, 0]);
        let (parsed, consumed) = RsvpObject::parse(&raw).unwrap();

        assert_eq!(consumed, raw.len());
        assert_eq!(
            parsed,
            RsvpObject::ExplicitRoute {
                hops: vec![
                    (false, Ipv4Address::new(10, 0, 0, 1)),
                    (true, Ipv4Address::new(10, 0, 0, 2)),
                ],
            }
        );
    }
}
