//! Application Layer: Dynamic Host Configuration Protocol (DHCP - RFC 2131).
//!
//! Handles DHCP client/server negotiation (Discover -> Offer -> Request -> ACK) over UDP ports 67 & 68.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;
use std::fmt;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

pub const DHCP_OP_BOOTREQUEST: u8 = 1;
pub const DHCP_OP_BOOTREPLY: u8 = 2;

pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

pub const DHCP_OPT_PAD: u8 = 0;
pub const DHCP_OPT_SUBNET_MASK: u8 = 1;
pub const DHCP_OPT_ROUTER: u8 = 3;
pub const DHCP_OPT_DNS: u8 = 6;
pub const DHCP_OPT_LEASE_TIME: u8 = 51;
pub const DHCP_OPT_MSG_TYPE: u8 = 53;
pub const DHCP_OPT_SERVER_ID: u8 = 54;
pub const DHCP_OPT_END: u8 = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Ack,
    Nak,
    Release,
    Unknown(u8),
}

impl DhcpMessageType {
    pub fn from_u8(val: u8) -> Self {
        match val {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            other => DhcpMessageType::Unknown(other),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            DhcpMessageType::Discover => 1,
            DhcpMessageType::Offer => 2,
            DhcpMessageType::Request => 3,
            DhcpMessageType::Ack => 5,
            DhcpMessageType::Nak => 6,
            DhcpMessageType::Release => 7,
            DhcpMessageType::Unknown(v) => *v,
        }
    }
}

impl fmt::Display for DhcpMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpMessageType::Discover => write!(f, "DHCP Discover (1)"),
            DhcpMessageType::Offer => write!(f, "DHCP Offer (2)"),
            DhcpMessageType::Request => write!(f, "DHCP Request (3)"),
            DhcpMessageType::Ack => write!(f, "DHCP ACK (5)"),
            DhcpMessageType::Nak => write!(f, "DHCP NAK (6)"),
            DhcpMessageType::Release => write!(f, "DHCP Release (7)"),
            DhcpMessageType::Unknown(v) => write!(f, "DHCP Type ({})", v),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpPacket {
    pub op: u8,
    pub xid: u32,
    pub ciaddr: Ipv4Address,
    pub yiaddr: Ipv4Address,
    pub siaddr: Ipv4Address,
    pub chaddr: MacAddress,
    pub msg_type: DhcpMessageType,
    pub subnet_mask: Option<Ipv4Address>,
    pub router: Option<Ipv4Address>,
    pub dns: Option<Ipv4Address>,
    pub server_id: Option<Ipv4Address>,
    pub lease_time: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpError {
    PacketTooShort(usize),
    InvalidMagicCookie,
    InvalidOptionLength,
}

impl fmt::Display for DhcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DhcpError::PacketTooShort(len) => {
                write!(f, "DHCP packet too short ({} bytes, min 240)", len)
            }
            DhcpError::InvalidMagicCookie => write!(f, "Invalid DHCP magic cookie"),
            DhcpError::InvalidOptionLength => write!(f, "Invalid DHCP option length"),
        }
    }
}

impl std::error::Error for DhcpError {}

impl DhcpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, DhcpError> {
        if data.len() < 240 {
            return Err(DhcpError::PacketTooShort(data.len()));
        }

        let op = data[0];
        let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);

        let mut ciaddr_raw = [0u8; 4];
        ciaddr_raw.copy_from_slice(&data[12..16]);
        let ciaddr = Ipv4Address(ciaddr_raw);

        let mut yiaddr_raw = [0u8; 4];
        yiaddr_raw.copy_from_slice(&data[16..20]);
        let yiaddr = Ipv4Address(yiaddr_raw);

        let mut siaddr_raw = [0u8; 4];
        siaddr_raw.copy_from_slice(&data[20..24]);
        let siaddr = Ipv4Address(siaddr_raw);

        let mut chaddr_raw = [0u8; 6];
        chaddr_raw.copy_from_slice(&data[28..34]);
        let chaddr = MacAddress(chaddr_raw);

        if data[236..240] != DHCP_MAGIC_COOKIE {
            return Err(DhcpError::InvalidMagicCookie);
        }

        let mut msg_type = DhcpMessageType::Unknown(0);
        let mut subnet_mask = None;
        let mut router = None;
        let mut dns = None;
        let mut server_id = None;
        let mut lease_time = None;

        let mut offset = 240;
        while offset < data.len() {
            let opt = data[offset];
            if opt == DHCP_OPT_END {
                break;
            }
            if opt == DHCP_OPT_PAD {
                offset += 1;
                continue;
            }

            if offset + 1 >= data.len() {
                return Err(DhcpError::InvalidOptionLength);
            }
            let len = data[offset + 1] as usize;
            offset += 2;

            if offset + len > data.len() {
                return Err(DhcpError::InvalidOptionLength);
            }

            let val = &data[offset..offset + len];
            match opt {
                DHCP_OPT_MSG_TYPE if len == 1 => {
                    msg_type = DhcpMessageType::from_u8(val[0]);
                }
                DHCP_OPT_SUBNET_MASK if len == 4 => {
                    subnet_mask = Some(Ipv4Address([val[0], val[1], val[2], val[3]]));
                }
                DHCP_OPT_ROUTER if len >= 4 => {
                    router = Some(Ipv4Address([val[0], val[1], val[2], val[3]]));
                }
                DHCP_OPT_DNS if len >= 4 => {
                    dns = Some(Ipv4Address([val[0], val[1], val[2], val[3]]));
                }
                DHCP_OPT_SERVER_ID if len == 4 => {
                    server_id = Some(Ipv4Address([val[0], val[1], val[2], val[3]]));
                }
                DHCP_OPT_LEASE_TIME if len == 4 => {
                    lease_time = Some(u32::from_be_bytes([val[0], val[1], val[2], val[3]]));
                }
                _ => {}
            }

            offset += len;
        }

        Ok(DhcpPacket {
            op,
            xid,
            ciaddr,
            yiaddr,
            siaddr,
            chaddr,
            msg_type,
            subnet_mask,
            router,
            dns,
            server_id,
            lease_time,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 236];
        buf[0] = self.op;
        buf[1] = 1; // Ethernet
        buf[2] = 6; // MAC len
        buf[3] = 0; // Hops

        buf[4..8].copy_from_slice(&self.xid.to_be_bytes());
        buf[12..16].copy_from_slice(&self.ciaddr.0);
        buf[16..20].copy_from_slice(&self.yiaddr.0);
        buf[20..24].copy_from_slice(&self.siaddr.0);
        buf[28..34].copy_from_slice(&self.chaddr.0);

        // Magic Cookie
        buf.extend_from_slice(&DHCP_MAGIC_COOKIE);

        // Option 53: Message Type
        buf.push(DHCP_OPT_MSG_TYPE);
        buf.push(1);
        buf.push(self.msg_type.to_u8());

        // Option 54: Server Identifier
        if let Some(srv) = self.server_id {
            buf.push(DHCP_OPT_SERVER_ID);
            buf.push(4);
            buf.extend_from_slice(&srv.0);
        }

        // Option 1: Subnet Mask
        if let Some(mask) = self.subnet_mask {
            buf.push(DHCP_OPT_SUBNET_MASK);
            buf.push(4);
            buf.extend_from_slice(&mask.0);
        }

        // Option 3: Router
        if let Some(gw) = self.router {
            buf.push(DHCP_OPT_ROUTER);
            buf.push(4);
            buf.extend_from_slice(&gw.0);
        }

        // Option 6: DNS
        if let Some(d) = self.dns {
            buf.push(DHCP_OPT_DNS);
            buf.push(4);
            buf.extend_from_slice(&d.0);
        }

        // Option 51: Lease Time
        if let Some(lt) = self.lease_time {
            buf.push(DHCP_OPT_LEASE_TIME);
            buf.push(4);
            buf.extend_from_slice(&lt.to_be_bytes());
        }

        // End Option
        buf.push(DHCP_OPT_END);
        buf
    }

    pub fn build_discover(chaddr: MacAddress, xid: u32) -> Self {
        DhcpPacket {
            op: DHCP_OP_BOOTREQUEST,
            xid,
            ciaddr: Ipv4Address::UNSPECIFIED,
            yiaddr: Ipv4Address::UNSPECIFIED,
            siaddr: Ipv4Address::UNSPECIFIED,
            chaddr,
            msg_type: DhcpMessageType::Discover,
            subnet_mask: None,
            router: None,
            dns: None,
            server_id: None,
            lease_time: None,
        }
    }

    pub fn build_offer(
        chaddr: MacAddress,
        xid: u32,
        offered_ip: Ipv4Address,
        server_ip: Ipv4Address,
        subnet_mask: Ipv4Address,
        router: Ipv4Address,
        dns: Ipv4Address,
        lease_secs: u32,
    ) -> Self {
        DhcpPacket {
            op: DHCP_OP_BOOTREPLY,
            xid,
            ciaddr: Ipv4Address::UNSPECIFIED,
            yiaddr: offered_ip,
            siaddr: server_ip,
            chaddr,
            msg_type: DhcpMessageType::Offer,
            subnet_mask: Some(subnet_mask),
            router: Some(router),
            dns: Some(dns),
            server_id: Some(server_ip),
            lease_time: Some(lease_secs),
        }
    }
    pub fn build_request(
        chaddr: MacAddress,
        xid: u32,
        requested_ip: Ipv4Address,
        server_id: Ipv4Address,
    ) -> Self {
        DhcpPacket {
            op: DHCP_OP_BOOTREQUEST,
            xid,
            ciaddr: Ipv4Address::UNSPECIFIED,
            yiaddr: requested_ip,
            siaddr: server_id,
            chaddr,
            msg_type: DhcpMessageType::Request,
            subnet_mask: None,
            router: None,
            dns: None,
            server_id: Some(server_id),
            lease_time: None,
        }
    }

    pub fn build_ack(
        chaddr: MacAddress,
        xid: u32,
        assigned_ip: Ipv4Address,
        server_ip: Ipv4Address,
        subnet_mask: Ipv4Address,
        router: Ipv4Address,
        dns: Ipv4Address,
        lease_secs: u32,
    ) -> Self {
        DhcpPacket {
            op: DHCP_OP_BOOTREPLY,
            xid,
            ciaddr: Ipv4Address::UNSPECIFIED,
            yiaddr: assigned_ip,
            siaddr: server_ip,
            chaddr,
            msg_type: DhcpMessageType::Ack,
            subnet_mask: Some(subnet_mask),
            router: Some(router),
            dns: Some(dns),
            server_id: Some(server_ip),
            lease_time: Some(lease_secs),
        }
    }
}

/// Dynamic Host Configuration Protocol (DHCP) Server
#[derive(Debug, Clone)]
pub struct DhcpServer {
    pub server_ip: Ipv4Address,
    pub subnet_mask: Ipv4Address,
    pub router: Ipv4Address,
    pub dns: Ipv4Address,
    pub start_ip: Ipv4Address,
    pub end_ip: Ipv4Address,
    pub next_alloc_u32: u32,
    pub lease_time_secs: u32,
    pub leases: std::collections::HashMap<MacAddress, Ipv4Address>,
}

impl DhcpServer {
    pub fn new(
        server_ip: Ipv4Address,
        subnet_mask: Ipv4Address,
        router: Ipv4Address,
        dns: Ipv4Address,
        start_ip: Ipv4Address,
        end_ip: Ipv4Address,
        lease_time_secs: u32,
    ) -> Self {
        let next_alloc_u32 = start_ip.to_u32();
        DhcpServer {
            server_ip,
            subnet_mask,
            router,
            dns,
            start_ip,
            end_ip,
            next_alloc_u32,
            lease_time_secs,
            leases: std::collections::HashMap::new(),
        }
    }

    fn allocate_ip(&mut self, mac: MacAddress) -> Ipv4Address {
        if let Some(&existing) = self.leases.get(&mac) {
            return existing;
        }

        let allocated = Ipv4Address::from_u32(self.next_alloc_u32);
        if self.next_alloc_u32 < self.end_ip.to_u32() {
            self.next_alloc_u32 += 1;
        }
        self.leases.insert(mac, allocated);
        allocated
    }

    pub fn handle_packet(&mut self, pkt: &DhcpPacket) -> Option<DhcpPacket> {
        match pkt.msg_type {
            DhcpMessageType::Discover => {
                let offered_ip = self.allocate_ip(pkt.chaddr);
                Some(DhcpPacket::build_offer(
                    pkt.chaddr,
                    pkt.xid,
                    offered_ip,
                    self.server_ip,
                    self.subnet_mask,
                    self.router,
                    self.dns,
                    self.lease_time_secs,
                ))
            }
            DhcpMessageType::Request => {
                let assigned_ip = if pkt.yiaddr != Ipv4Address::UNSPECIFIED {
                    pkt.yiaddr
                } else {
                    self.allocate_ip(pkt.chaddr)
                };
                self.leases.insert(pkt.chaddr, assigned_ip);

                Some(DhcpPacket::build_ack(
                    pkt.chaddr,
                    pkt.xid,
                    assigned_ip,
                    self.server_ip,
                    self.subnet_mask,
                    self.router,
                    self.dns,
                    self.lease_time_secs,
                ))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_full_dora_negotiation() {
        let client_mac = MacAddress([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        let xid = 0xdeadbeef;
        let mut server = DhcpServer::new(
            Ipv4Address::new(192, 168, 1, 1),
            Ipv4Address::new(255, 255, 255, 0),
            Ipv4Address::new(192, 168, 1, 1),
            Ipv4Address::new(8, 8, 8, 8),
            Ipv4Address::new(192, 168, 1, 100),
            Ipv4Address::new(192, 168, 1, 200),
            86400,
        );

        // 1. Discover -> Offer
        let disc = DhcpPacket::build_discover(client_mac, xid);
        let offer = server.handle_packet(&disc).expect("DHCP Offer");
        assert_eq!(offer.msg_type, DhcpMessageType::Offer);
        assert_eq!(offer.yiaddr, Ipv4Address::new(192, 168, 1, 100));

        // 2. Request -> ACK
        let req = DhcpPacket::build_request(client_mac, xid, offer.yiaddr, server.server_ip);
        let ack = server.handle_packet(&req).expect("DHCP ACK");
        assert_eq!(ack.msg_type, DhcpMessageType::Ack);
        assert_eq!(ack.yiaddr, Ipv4Address::new(192, 168, 1, 100));
        assert_eq!(ack.router, Some(Ipv4Address::new(192, 168, 1, 1)));
        assert_eq!(ack.subnet_mask, Some(Ipv4Address::new(255, 255, 255, 0)));
    }
}
