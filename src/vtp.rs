//! Cisco VLAN Trunking Protocol (VTP).
//!
//! Layer 2 multi-switch VLAN database synchronization over trunk links using Cisco SNAP framing.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::collections::BTreeMap;
use std::fmt;

pub const VTP_MULTICAST_MAC: MacAddress = MacAddress([0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC]);
pub const VTP_SNAP_HEADER: [u8; 8] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x0C, 0x20, 0x03];

// VTP Message Types
pub const VTP_MSG_SUMMARY_ADV: u8 = 1;
pub const VTP_MSG_SUBSET_ADV: u8 = 2;
pub const VTP_MSG_ADV_REQUEST: u8 = 3;
pub const VTP_MSG_JOIN: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VtpMode {
    Server,
    Client,
    Transparent,
}

impl fmt::Display for VtpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtpMode::Server => write!(f, "Server"),
            VtpMode::Client => write!(f, "Client"),
            VtpMode::Transparent => write!(f, "Transparent"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpVlanInfo {
    pub vlan_id: u16,
    pub vlan_name: String,
    pub status: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpSummaryAdv {
    pub version: u8,
    pub domain: String,
    pub revision: u32,
    pub updater_ip: Ipv4Address,
    pub md5_digest: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtpSubsetAdv {
    pub version: u8,
    pub domain: String,
    pub revision: u32,
    pub vlans: Vec<VtpVlanInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtpPacket {
    Summary(VtpSummaryAdv),
    Subset(VtpSubsetAdv),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VtpError {
    PacketTooShort(usize),
    InvalidCode(u8),
    InvalidLength,
}

impl fmt::Display for VtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VtpError::PacketTooShort(l) => write!(f, "VTP packet too short ({} bytes)", l),
            VtpError::InvalidCode(c) => write!(f, "Unknown VTP message code: {}", c),
            VtpError::InvalidLength => write!(f, "Invalid VTP subset record length"),
        }
    }
}

impl std::error::Error for VtpError {}

impl VtpPacket {
    pub fn build_summary(domain: &str, revision: u32, updater_ip: Ipv4Address) -> Self {
        VtpPacket::Summary(VtpSummaryAdv {
            version: 2,
            domain: domain.to_string(),
            revision,
            updater_ip,
            md5_digest: [0x55; 16],
        })
    }

    pub fn build_subset(domain: &str, revision: u32, vlans: &[VtpVlanInfo]) -> Self {
        VtpPacket::Subset(VtpSubsetAdv {
            version: 2,
            domain: domain.to_string(),
            revision,
            vlans: vlans.to_vec(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            VtpPacket::Summary(s) => {
                buf.push(s.version);
                buf.push(VTP_MSG_SUMMARY_ADV);
                buf.push(0x01); // Followers = 1
                buf.push(s.domain.len() as u8);

                let mut dom_bytes = [0u8; 32];
                let copy_len = s.domain.len().min(32);
                dom_bytes[..copy_len].copy_from_slice(&s.domain.as_bytes()[..copy_len]);
                buf.extend_from_slice(&dom_bytes);

                buf.extend_from_slice(&s.revision.to_be_bytes());
                buf.extend_from_slice(&s.updater_ip.0);
                buf.extend_from_slice(&[0u8; 12]); // Update timestamp
                buf.extend_from_slice(&s.md5_digest);
            }
            VtpPacket::Subset(sub) => {
                buf.push(sub.version);
                buf.push(VTP_MSG_SUBSET_ADV);
                buf.push(0x01); // Seq num = 1
                buf.push(sub.domain.len() as u8);

                let mut dom_bytes = [0u8; 32];
                let copy_len = sub.domain.len().min(32);
                dom_bytes[..copy_len].copy_from_slice(&sub.domain.as_bytes()[..copy_len]);
                buf.extend_from_slice(&dom_bytes);

                buf.extend_from_slice(&sub.revision.to_be_bytes());

                for v in &sub.vlans {
                    let mut v_buf = Vec::new();
                    v_buf.push(v.status);
                    v_buf.push(0x01); // Type = Ethernet
                    v_buf.extend_from_slice(&v.vlan_id.to_be_bytes());
                    v_buf.extend_from_slice(&1500u16.to_be_bytes()); // MTU
                    let mut name_bytes = [0u8; 32];
                    let n_len = v.vlan_name.len().min(32);
                    v_buf.push(n_len as u8);
                    name_bytes[..n_len].copy_from_slice(&v.vlan_name.as_bytes()[..n_len]);
                    v_buf.extend_from_slice(&name_bytes);

                    buf.push(v_buf.len() as u8); // VLAN info length
                    buf.extend_from_slice(&v_buf);
                }
            }
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, VtpError> {
        if data.len() < 40 {
            return Err(VtpError::PacketTooShort(data.len()));
        }

        let version = data[0];
        let code = data[1];
        let dom_len = (data[3] as usize).min(32);
        let domain = String::from_utf8_lossy(&data[4..4 + dom_len]).to_string();
        let revision = u32::from_be_bytes([data[36], data[37], data[38], data[39]]);

        match code {
            VTP_MSG_SUMMARY_ADV => {
                if data.len() < 72 {
                    return Err(VtpError::PacketTooShort(data.len()));
                }
                let updater_ip = Ipv4Address([data[40], data[41], data[42], data[43]]);
                let mut md5_digest = [0u8; 16];
                md5_digest.copy_from_slice(&data[56..72]);

                Ok(VtpPacket::Summary(VtpSummaryAdv {
                    version,
                    domain,
                    revision,
                    updater_ip,
                    md5_digest,
                }))
            }
            VTP_MSG_SUBSET_ADV => {
                let mut vlans = Vec::new();
                let mut offset = 40;

                while offset < data.len() {
                    let v_len = data[offset] as usize;
                    let record_end = offset
                        .checked_add(1 + v_len)
                        .ok_or(VtpError::InvalidLength)?;
                    if v_len < 7 || record_end > data.len() {
                        return Err(VtpError::InvalidLength);
                    }

                    let status = data[offset + 1];
                    let vlan_id = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
                    let name_len = data[offset + 7] as usize;
                    let name_end = offset
                        .checked_add(8 + name_len)
                        .ok_or(VtpError::InvalidLength)?;
                    if name_len > 32 || name_end > record_end {
                        return Err(VtpError::InvalidLength);
                    }
                    let name_str = String::from_utf8_lossy(&data[offset + 8..name_end]).to_string();

                    vlans.push(VtpVlanInfo {
                        vlan_id,
                        vlan_name: name_str,
                        status,
                    });

                    offset = record_end;
                }

                Ok(VtpPacket::Subset(VtpSubsetAdv {
                    version,
                    domain,
                    revision,
                    vlans,
                }))
            }
            _ => Err(VtpError::InvalidCode(code)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VtpEngine {
    pub domain: String,
    pub mode: VtpMode,
    pub revision: u32,
    pub vlans: BTreeMap<u16, String>, // VLAN ID -> Name
}

impl VtpEngine {
    pub fn new(domain: &str, mode: VtpMode) -> Self {
        let mut vlans = BTreeMap::new();
        vlans.insert(1, "default".to_string());
        vlans.insert(10, "Engineering".to_string());
        vlans.insert(20, "Management".to_string());

        VtpEngine {
            domain: domain.to_string(),
            mode,
            revision: 5,
            vlans,
        }
    }

    pub fn add_vlan(&mut self, id: u16, name: &str) -> bool {
        if self.mode == VtpMode::Client {
            return false; // Clients cannot modify VLAN database directly
        }
        self.vlans.insert(id, name.to_string());
        self.revision += 1;
        true
    }

    pub fn sync_subset(&mut self, subset: &VtpSubsetAdv) -> bool {
        if self.mode == VtpMode::Transparent {
            return false;
        }
        if subset.domain == self.domain && subset.revision > self.revision {
            self.revision = subset.revision;
            self.vlans.clear();
            for v in &subset.vlans {
                self.vlans.insert(v.vlan_id, v.vlan_name.clone());
            }
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vtp_summary_and_subset_roundtrip() {
        let updater = Ipv4Address::new(192, 168, 1, 1);
        let summary = VtpPacket::build_summary("EnterpriseCorp", 12, updater);
        let raw_sum = summary.serialize();

        let parsed_sum = VtpPacket::parse(&raw_sum).unwrap();
        if let VtpPacket::Summary(s) = parsed_sum {
            assert_eq!(s.domain, "EnterpriseCorp");
            assert_eq!(s.revision, 12);
            assert_eq!(s.updater_ip, updater);
        } else {
            panic!("Expected summary adv");
        }

        let vlans = vec![
            VtpVlanInfo {
                vlan_id: 10,
                vlan_name: "Sales".to_string(),
                status: 0,
            },
            VtpVlanInfo {
                vlan_id: 20,
                vlan_name: "Dev".to_string(),
                status: 0,
            },
        ];
        let subset = VtpPacket::build_subset("EnterpriseCorp", 12, &vlans);
        let raw_sub = subset.serialize();

        let parsed_sub = VtpPacket::parse(&raw_sub).unwrap();
        if let VtpPacket::Subset(sub) = parsed_sub {
            assert_eq!(sub.domain, "EnterpriseCorp");
            assert_eq!(sub.revision, 12);
            assert_eq!(sub.vlans.len(), 2);
            assert_eq!(sub.vlans[0].vlan_id, 10);
            assert_eq!(sub.vlans[0].vlan_name, "Sales");
        } else {
            panic!("Expected subset adv");
        }
    }
}
