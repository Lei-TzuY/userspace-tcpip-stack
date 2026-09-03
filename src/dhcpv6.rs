//! Dynamic Host Configuration Protocol for IPv6 (DHCPv6 - RFC 8415 / RFC 3633).
//!
//! Stateful and stateless IPv6 host autoconfiguration and prefix delegation
//! over UDP ports 546 (Client) and 547 (Server).

use crate::ethernet::MacAddress;
use crate::ipv6::Ipv6Address;
use std::collections::HashMap;
use std::fmt;

pub const DHCPV6_CLIENT_PORT: u16 = 546;
pub const DHCPV6_SERVER_PORT: u16 = 547;
pub const DHCPV6_HEADER_LEN: usize = 4;

// DHCPv6 Message Types
pub const DHCPV6_MSG_SOLICIT: u8 = 1;
pub const DHCPV6_MSG_ADVERTISE: u8 = 2;
pub const DHCPV6_MSG_REQUEST: u8 = 3;
pub const DHCPV6_MSG_CONFIRM: u8 = 4;
pub const DHCPV6_MSG_RENEW: u8 = 5;
pub const DHCPV6_MSG_REBIND: u8 = 6;
pub const DHCPV6_MSG_REPLY: u8 = 7;
pub const DHCPV6_MSG_RELEASE: u8 = 8;
pub const DHCPV6_MSG_DECLINE: u8 = 9;
pub const DHCPV6_MSG_RECONFIGURE: u8 = 10;
pub const DHCPV6_MSG_INFO_REQUEST: u8 = 11;
pub const DHCPV6_MSG_RELAY_FORW: u8 = 12;
pub const DHCPV6_MSG_RELAY_REPL: u8 = 13;

// DHCPv6 Option Codes
pub const DHCPV6_OPT_CLIENTID: u16 = 1;
pub const DHCPV6_OPT_SERVERID: u16 = 2;
pub const DHCPV6_OPT_IA_NA: u16 = 3;
pub const DHCPV6_OPT_IA_TA: u16 = 4;
pub const DHCPV6_OPT_IAADDR: u16 = 5;
pub const DHCPV6_OPT_ORO: u16 = 6;
pub const DHCPV6_OPT_PREFERENCE: u16 = 7;
pub const DHCPV6_OPT_ELAPSED_TIME: u16 = 8;
pub const DHCPV6_OPT_RELAY_MSG: u16 = 9;
pub const DHCPV6_OPT_AUTH: u16 = 11;
pub const DHCPV6_OPT_SERVER_UNICAST: u16 = 12;
pub const DHCPV6_OPT_STATUS_CODE: u16 = 13;
pub const DHCPV6_OPT_RAPID_COMMIT: u16 = 14;
pub const DHCPV6_OPT_USER_CLASS: u16 = 15;
pub const DHCPV6_OPT_VENDOR_CLASS: u16 = 16;
pub const DHCPV6_OPT_VENDOR_OPTS: u16 = 17;
pub const DHCPV6_OPT_INTERFACE_ID: u16 = 18;
pub const DHCPV6_OPT_RECONF_MSG: u16 = 19;
pub const DHCPV6_OPT_RECONF_ACCEPT: u16 = 20;
pub const DHCPV6_OPT_SIP_SERVER_D: u16 = 21;
pub const DHCPV6_OPT_SIP_SERVER_A: u16 = 22;
pub const DHCPV6_OPT_DNS_SERVERS: u16 = 23;
pub const DHCPV6_OPT_DNSSL: u16 = 24;
pub const DHCPV6_OPT_IA_PD: u16 = 25;
pub const DHCPV6_OPT_IAPREFIX: u16 = 26;

// DHCPv6 Status Codes (RFC 8415 / RFC 3633)
pub const DHCPV6_STATUS_SUCCESS: u16 = 0;
pub const DHCPV6_STATUS_UNSPEC_FAIL: u16 = 1;
pub const DHCPV6_STATUS_NO_ADDRS_AVAIL: u16 = 2;
pub const DHCPV6_STATUS_NO_BINDING: u16 = 3;
pub const DHCPV6_STATUS_NOT_ON_LINK: u16 = 4;
pub const DHCPV6_STATUS_USE_MULTICAST: u16 = 5;
pub const DHCPV6_STATUS_NO_PREFIX_AVAIL: u16 = 6;

/// DHCP Unique Identifier (DUID - RFC 8415 Section 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Duid {
    /// DUID-LLT: Link-Layer Address Plus Time (Type 1)
    Llt {
        hw_type: u16,
        time: u32,
        ll_addr: MacAddress,
    },
    /// DUID-EN: Enterprise Number (Type 2)
    En {
        enterprise_num: u32,
        identifier: Vec<u8>,
    },
    /// DUID-LL: Link-Layer Address (Type 3)
    Ll { hw_type: u16, ll_addr: MacAddress },
    /// DUID-UUID: UUID-based (Type 4)
    Uuid([u8; 16]),
    /// Raw unparsed DUID
    Raw(Vec<u8>),
}

impl Duid {
    pub fn new_ll(mac: MacAddress) -> Self {
        Duid::Ll {
            hw_type: 1, // Ethernet
            ll_addr: mac,
        }
    }

    pub fn new_llt(mac: MacAddress, time: u32) -> Self {
        Duid::Llt {
            hw_type: 1,
            time,
            ll_addr: mac,
        }
    }

    pub fn new_uuid(uuid: [u8; 16]) -> Self {
        Duid::Uuid(uuid)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Duid::Llt {
                hw_type,
                time,
                ll_addr,
            } => {
                buf.extend_from_slice(&1u16.to_be_bytes());
                buf.extend_from_slice(&hw_type.to_be_bytes());
                buf.extend_from_slice(&time.to_be_bytes());
                buf.extend_from_slice(&ll_addr.0);
            }
            Duid::En {
                enterprise_num,
                identifier,
            } => {
                buf.extend_from_slice(&2u16.to_be_bytes());
                buf.extend_from_slice(&enterprise_num.to_be_bytes());
                buf.extend_from_slice(identifier);
            }
            Duid::Ll { hw_type, ll_addr } => {
                buf.extend_from_slice(&3u16.to_be_bytes());
                buf.extend_from_slice(&hw_type.to_be_bytes());
                buf.extend_from_slice(&ll_addr.0);
            }
            Duid::Uuid(uuid) => {
                buf.extend_from_slice(&4u16.to_be_bytes());
                buf.extend_from_slice(uuid);
            }
            Duid::Raw(bytes) => {
                buf.extend_from_slice(bytes);
            }
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let duid_type = u16::from_be_bytes([data[0], data[1]]);
        match duid_type {
            1 if data.len() >= 8 => {
                let hw_type = u16::from_be_bytes([data[2], data[3]]);
                let time = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if data.len() == 14 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&data[8..14]);
                    Some(Duid::Llt {
                        hw_type,
                        time,
                        ll_addr: MacAddress(mac),
                    })
                } else {
                    Some(Duid::Raw(data.to_vec()))
                }
            }
            2 if data.len() >= 6 => {
                let enterprise_num = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
                let identifier = data[6..].to_vec();
                Some(Duid::En {
                    enterprise_num,
                    identifier,
                })
            }
            3 if data.len() >= 4 => {
                let hw_type = u16::from_be_bytes([data[2], data[3]]);
                if data.len() == 10 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&data[4..10]);
                    Some(Duid::Ll {
                        hw_type,
                        ll_addr: MacAddress(mac),
                    })
                } else {
                    Some(Duid::Raw(data.to_vec()))
                }
            }
            4 if data.len() == 18 => {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&data[2..18]);
                Some(Duid::Uuid(uuid))
            }
            _ => Some(Duid::Raw(data.to_vec())),
        }
    }
}

/// IA Address Option (RFC 8415 Section 21.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaAddressOption {
    pub address: Ipv6Address,
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
}

/// IA Prefix Option (RFC 3633 / RFC 8415 Section 21.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IaPrefixOption {
    pub preferred_lifetime: u32,
    pub valid_lifetime: u32,
    pub prefix_len: u8,
    pub prefix: Ipv6Address,
}

/// Identity Association for Non-temporary Addresses (IA_NA - RFC 8415 Section 21.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaNaOption {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub addresses: Vec<IaAddressOption>,
}

/// Identity Association for Prefix Delegation (IA_PD - RFC 3633 / RFC 8415 Section 21.21).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IaPdOption {
    pub iaid: u32,
    pub t1: u32,
    pub t2: u32,
    pub prefixes: Vec<IaPrefixOption>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6Option {
    pub code: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcpv6Message {
    pub msg_type: u8,
    pub transaction_id: u32, // 24-bit integer
    pub options: Vec<Dhcpv6Option>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dhcpv6Error {
    PacketTooShort(usize),
    InvalidLength,
}

impl fmt::Display for Dhcpv6Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Dhcpv6Error::PacketTooShort(l) => write!(f, "DHCPv6 message too short ({} bytes)", l),
            Dhcpv6Error::InvalidLength => write!(f, "Invalid DHCPv6 option length"),
        }
    }
}

impl std::error::Error for Dhcpv6Error {}

impl Dhcpv6Message {
    /// Builds a standard DHCPv6 Solicit message.
    pub fn build_solicit(transaction_id: u32, client_duid: &[u8]) -> Self {
        Self::build_solicit_full(transaction_id, client_duid, false, false)
    }

    /// Builds a DHCPv6 Solicit message with optional Rapid Commit and Prefix Delegation.
    pub fn build_solicit_full(
        transaction_id: u32,
        client_duid: &[u8],
        rapid_commit: bool,
        request_pd: bool,
    ) -> Self {
        let mut options = Vec::new();
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_CLIENTID,
            data: client_duid.to_vec(),
        });

        if rapid_commit {
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_RAPID_COMMIT,
                data: Vec::new(),
            });
        }

        // Elapsed time option (0 ms)
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_ELAPSED_TIME,
            data: vec![0x00, 0x00],
        });

        // IA_NA request (IAID = 1)
        let mut ia_na_bytes = Vec::new();
        ia_na_bytes.extend_from_slice(&1u32.to_be_bytes()); // IAID
        ia_na_bytes.extend_from_slice(&0u32.to_be_bytes()); // T1 = 0 (hint)
        ia_na_bytes.extend_from_slice(&0u32.to_be_bytes()); // T2 = 0 (hint)
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_IA_NA,
            data: ia_na_bytes,
        });

        // IA_PD request if requested
        if request_pd {
            let mut ia_pd_bytes = Vec::new();
            ia_pd_bytes.extend_from_slice(&2u32.to_be_bytes()); // IAID = 2
            ia_pd_bytes.extend_from_slice(&0u32.to_be_bytes()); // T1 = 0
            ia_pd_bytes.extend_from_slice(&0u32.to_be_bytes()); // T2 = 0
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_IA_PD,
                data: ia_pd_bytes,
            });
        }

        // Option Request Option (DNS Servers 23, DNSSL 24)
        let mut oro_bytes = Vec::new();
        oro_bytes.extend_from_slice(&DHCPV6_OPT_DNS_SERVERS.to_be_bytes());
        oro_bytes.extend_from_slice(&DHCPV6_OPT_DNSSL.to_be_bytes());
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_ORO,
            data: oro_bytes,
        });

        Dhcpv6Message {
            msg_type: DHCPV6_MSG_SOLICIT,
            transaction_id: transaction_id & 0x00FF_FFFF,
            options,
        }
    }

    /// Builds a DHCPv6 Advertise message.
    pub fn build_advertise(
        transaction_id: u32,
        client_duid: &[u8],
        server_duid: &[u8],
        assigned_ip: Ipv6Address,
        dns_server: Ipv6Address,
    ) -> Self {
        Self::build_advertise_full(
            transaction_id,
            client_duid,
            server_duid,
            Some(assigned_ip),
            None,
            &[dns_server],
            &[],
        )
    }

    /// Builds a full DHCPv6 Advertise message with IA_NA, IA_PD, DNS Servers, and DNSSL.
    pub fn build_advertise_full(
        transaction_id: u32,
        client_duid: &[u8],
        server_duid: &[u8],
        assigned_ip: Option<Ipv6Address>,
        delegated_prefix: Option<(Ipv6Address, u8)>,
        dns_servers: &[Ipv6Address],
        search_list: &[String],
    ) -> Self {
        let mut options = Vec::new();
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_CLIENTID,
            data: client_duid.to_vec(),
        });
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_SERVERID,
            data: server_duid.to_vec(),
        });

        if let Some(ip) = assigned_ip {
            let mut iaaddr_bytes = Vec::new();
            iaaddr_bytes.extend_from_slice(&ip.0);
            iaaddr_bytes.extend_from_slice(&3600u32.to_be_bytes()); // Preferred 1h
            iaaddr_bytes.extend_from_slice(&7200u32.to_be_bytes()); // Valid 2h

            let mut ia_na_bytes = Vec::new();
            ia_na_bytes.extend_from_slice(&1u32.to_be_bytes()); // IAID
            ia_na_bytes.extend_from_slice(&1800u32.to_be_bytes()); // T1
            ia_na_bytes.extend_from_slice(&2880u32.to_be_bytes()); // T2
            ia_na_bytes.extend_from_slice(&DHCPV6_OPT_IAADDR.to_be_bytes());
            ia_na_bytes.extend_from_slice(&(iaaddr_bytes.len() as u16).to_be_bytes());
            ia_na_bytes.extend_from_slice(&iaaddr_bytes);

            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_IA_NA,
                data: ia_na_bytes,
            });
        }

        if let Some((prefix, prefix_len)) = delegated_prefix {
            let mut iaprefix_bytes = Vec::new();
            iaprefix_bytes.extend_from_slice(&3600u32.to_be_bytes()); // Preferred
            iaprefix_bytes.extend_from_slice(&7200u32.to_be_bytes()); // Valid
            iaprefix_bytes.push(prefix_len);
            iaprefix_bytes.extend_from_slice(&prefix.0);

            let mut ia_pd_bytes = Vec::new();
            ia_pd_bytes.extend_from_slice(&2u32.to_be_bytes()); // IAID = 2
            ia_pd_bytes.extend_from_slice(&1800u32.to_be_bytes()); // T1
            ia_pd_bytes.extend_from_slice(&2880u32.to_be_bytes()); // T2
            ia_pd_bytes.extend_from_slice(&DHCPV6_OPT_IAPREFIX.to_be_bytes());
            ia_pd_bytes.extend_from_slice(&(iaprefix_bytes.len() as u16).to_be_bytes());
            ia_pd_bytes.extend_from_slice(&iaprefix_bytes);

            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_IA_PD,
                data: ia_pd_bytes,
            });
        }

        if !dns_servers.is_empty() {
            let mut dns_bytes = Vec::new();
            for s in dns_servers {
                dns_bytes.extend_from_slice(&s.0);
            }
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_DNS_SERVERS,
                data: dns_bytes,
            });
        }

        if !search_list.is_empty() {
            let mut dnssl_bytes = Vec::new();
            for domain in search_list {
                for label in domain.split('.') {
                    if !label.is_empty() {
                        dnssl_bytes.push(label.len() as u8);
                        dnssl_bytes.extend_from_slice(label.as_bytes());
                    }
                }
                dnssl_bytes.push(0x00);
            }
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_DNSSL,
                data: dnssl_bytes,
            });
        }

        Dhcpv6Message {
            msg_type: DHCPV6_MSG_ADVERTISE,
            transaction_id: transaction_id & 0x00FF_FFFF,
            options,
        }
    }

    /// Builds a DHCPv6 Request message.
    pub fn build_request(
        transaction_id: u32,
        client_duid: &[u8],
        server_duid: &[u8],
        ia_na: Option<&IaNaOption>,
        ia_pd: Option<&IaPdOption>,
    ) -> Self {
        let mut options = Vec::new();
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_CLIENTID,
            data: client_duid.to_vec(),
        });
        options.push(Dhcpv6Option {
            code: DHCPV6_OPT_SERVERID,
            data: server_duid.to_vec(),
        });

        if let Some(na) = ia_na {
            let mut ia_na_bytes = Vec::new();
            ia_na_bytes.extend_from_slice(&na.iaid.to_be_bytes());
            ia_na_bytes.extend_from_slice(&na.t1.to_be_bytes());
            ia_na_bytes.extend_from_slice(&na.t2.to_be_bytes());
            for addr in &na.addresses {
                let mut addr_bytes = Vec::new();
                addr_bytes.extend_from_slice(&addr.address.0);
                addr_bytes.extend_from_slice(&addr.preferred_lifetime.to_be_bytes());
                addr_bytes.extend_from_slice(&addr.valid_lifetime.to_be_bytes());
                ia_na_bytes.extend_from_slice(&DHCPV6_OPT_IAADDR.to_be_bytes());
                ia_na_bytes.extend_from_slice(&(addr_bytes.len() as u16).to_be_bytes());
                ia_na_bytes.extend_from_slice(&addr_bytes);
            }
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_IA_NA,
                data: ia_na_bytes,
            });
        }

        if let Some(pd) = ia_pd {
            let mut ia_pd_bytes = Vec::new();
            ia_pd_bytes.extend_from_slice(&pd.iaid.to_be_bytes());
            ia_pd_bytes.extend_from_slice(&pd.t1.to_be_bytes());
            ia_pd_bytes.extend_from_slice(&pd.t2.to_be_bytes());
            for p in &pd.prefixes {
                let mut p_bytes = Vec::new();
                p_bytes.extend_from_slice(&p.preferred_lifetime.to_be_bytes());
                p_bytes.extend_from_slice(&p.valid_lifetime.to_be_bytes());
                p_bytes.push(p.prefix_len);
                p_bytes.extend_from_slice(&p.prefix.0);
                ia_pd_bytes.extend_from_slice(&DHCPV6_OPT_IAPREFIX.to_be_bytes());
                ia_pd_bytes.extend_from_slice(&(p_bytes.len() as u16).to_be_bytes());
                ia_pd_bytes.extend_from_slice(&p_bytes);
            }
            options.push(Dhcpv6Option {
                code: DHCPV6_OPT_IA_PD,
                data: ia_pd_bytes,
            });
        }

        Dhcpv6Message {
            msg_type: DHCPV6_MSG_REQUEST,
            transaction_id: transaction_id & 0x00FF_FFFF,
            options,
        }
    }

    /// Builds a DHCPv6 Reply message.
    pub fn build_reply(
        transaction_id: u32,
        client_duid: &[u8],
        server_duid: &[u8],
        assigned_ip: Option<Ipv6Address>,
        delegated_prefix: Option<(Ipv6Address, u8)>,
        dns_servers: &[Ipv6Address],
        search_list: &[String],
        rapid_commit: bool,
    ) -> Self {
        let mut msg = Self::build_advertise_full(
            transaction_id,
            client_duid,
            server_duid,
            assigned_ip,
            delegated_prefix,
            dns_servers,
            search_list,
        );
        msg.msg_type = DHCPV6_MSG_REPLY;
        if rapid_commit {
            msg.options.push(Dhcpv6Option {
                code: DHCPV6_OPT_RAPID_COMMIT,
                data: Vec::new(),
            });
        }
        msg
    }

    /// Builds a DHCPv6 Release message.
    pub fn build_release(
        transaction_id: u32,
        client_duid: &[u8],
        server_duid: &[u8],
        ia_na: Option<&IaNaOption>,
        ia_pd: Option<&IaPdOption>,
    ) -> Self {
        let mut msg = Self::build_request(transaction_id, client_duid, server_duid, ia_na, ia_pd);
        msg.msg_type = DHCPV6_MSG_RELEASE;
        msg
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.msg_type);
        let tid_bytes = (self.transaction_id & 0x00FF_FFFF).to_be_bytes();
        buf.extend_from_slice(&tid_bytes[1..4]); // 24-bit TID

        for opt in &self.options {
            buf.extend_from_slice(&opt.code.to_be_bytes());
            buf.extend_from_slice(&(opt.data.len() as u16).to_be_bytes());
            buf.extend_from_slice(&opt.data);
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, Dhcpv6Error> {
        if data.len() < DHCPV6_HEADER_LEN {
            return Err(Dhcpv6Error::PacketTooShort(data.len()));
        }

        let msg_type = data[0];
        let transaction_id = u32::from_be_bytes([0, data[1], data[2], data[3]]);

        let mut options = Vec::new();
        let mut offset = 4;

        while offset + 4 <= data.len() {
            let code = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if offset + 4 + len > data.len() {
                return Err(Dhcpv6Error::InvalidLength);
            }

            let opt_data = data[offset + 4..offset + 4 + len].to_vec();
            options.push(Dhcpv6Option {
                code,
                data: opt_data,
            });
            offset += 4 + len;
        }

        Ok(Dhcpv6Message {
            msg_type,
            transaction_id,
            options,
        })
    }

    pub fn get_assigned_ipv6(&self) -> Option<Ipv6Address> {
        let ia_na = self.get_ia_na()?;
        ia_na.addresses.first().map(|a| a.address)
    }

    pub fn get_delegated_prefix(&self) -> Option<(Ipv6Address, u8)> {
        let ia_pd = self.get_ia_pd()?;
        ia_pd.prefixes.first().map(|p| (p.prefix, p.prefix_len))
    }

    pub fn get_ia_na(&self) -> Option<IaNaOption> {
        for opt in &self.options {
            if opt.code == DHCPV6_OPT_IA_NA && opt.data.len() >= 12 {
                let iaid = u32::from_be_bytes(opt.data[0..4].try_into().ok()?);
                let t1 = u32::from_be_bytes(opt.data[4..8].try_into().ok()?);
                let t2 = u32::from_be_bytes(opt.data[8..12].try_into().ok()?);
                let mut addresses = Vec::new();
                let mut sub_off = 12;
                while sub_off + 4 <= opt.data.len() {
                    let sub_code = u16::from_be_bytes([opt.data[sub_off], opt.data[sub_off + 1]]);
                    let sub_len =
                        u16::from_be_bytes([opt.data[sub_off + 2], opt.data[sub_off + 3]]) as usize;
                    if sub_off + 4 + sub_len > opt.data.len() {
                        break;
                    }
                    if sub_code == DHCPV6_OPT_IAADDR && sub_len >= 24 {
                        let mut addr_bytes = [0u8; 16];
                        addr_bytes.copy_from_slice(&opt.data[sub_off + 4..sub_off + 20]);
                        let pref = u32::from_be_bytes(
                            opt.data[sub_off + 20..sub_off + 24].try_into().ok()?,
                        );
                        let valid = u32::from_be_bytes(
                            opt.data[sub_off + 24..sub_off + 28].try_into().ok()?,
                        );
                        addresses.push(IaAddressOption {
                            address: Ipv6Address(addr_bytes),
                            preferred_lifetime: pref,
                            valid_lifetime: valid,
                        });
                    }
                    sub_off += 4 + sub_len;
                }
                return Some(IaNaOption {
                    iaid,
                    t1,
                    t2,
                    addresses,
                });
            }
        }
        None
    }

    pub fn get_ia_pd(&self) -> Option<IaPdOption> {
        for opt in &self.options {
            if opt.code == DHCPV6_OPT_IA_PD && opt.data.len() >= 12 {
                let iaid = u32::from_be_bytes(opt.data[0..4].try_into().ok()?);
                let t1 = u32::from_be_bytes(opt.data[4..8].try_into().ok()?);
                let t2 = u32::from_be_bytes(opt.data[8..12].try_into().ok()?);
                let mut prefixes = Vec::new();
                let mut sub_off = 12;
                while sub_off + 4 <= opt.data.len() {
                    let sub_code = u16::from_be_bytes([opt.data[sub_off], opt.data[sub_off + 1]]);
                    let sub_len =
                        u16::from_be_bytes([opt.data[sub_off + 2], opt.data[sub_off + 3]]) as usize;
                    if sub_off + 4 + sub_len > opt.data.len() {
                        break;
                    }
                    if sub_code == DHCPV6_OPT_IAPREFIX && sub_len >= 25 {
                        let pref =
                            u32::from_be_bytes(opt.data[sub_off + 4..sub_off + 8].try_into().ok()?);
                        let valid = u32::from_be_bytes(
                            opt.data[sub_off + 8..sub_off + 12].try_into().ok()?,
                        );
                        let prefix_len = opt.data[sub_off + 12];
                        let mut p_bytes = [0u8; 16];
                        p_bytes.copy_from_slice(&opt.data[sub_off + 13..sub_off + 29]);
                        prefixes.push(IaPrefixOption {
                            preferred_lifetime: pref,
                            valid_lifetime: valid,
                            prefix_len,
                            prefix: Ipv6Address(p_bytes),
                        });
                    }
                    sub_off += 4 + sub_len;
                }
                return Some(IaPdOption {
                    iaid,
                    t1,
                    t2,
                    prefixes,
                });
            }
        }
        None
    }

    pub fn get_dns_servers(&self) -> Vec<Ipv6Address> {
        let mut servers = Vec::new();
        for opt in &self.options {
            if opt.code == DHCPV6_OPT_DNS_SERVERS {
                let mut off = 0;
                while off + 16 <= opt.data.len() {
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&opt.data[off..off + 16]);
                    servers.push(Ipv6Address(addr));
                    off += 16;
                }
            }
        }
        servers
    }

    pub fn get_dnssl(&self) -> Vec<String> {
        let mut domains = Vec::new();
        for opt in &self.options {
            if opt.code == DHCPV6_OPT_DNSSL {
                let mut off = 0;
                while off < opt.data.len() {
                    let mut labels = Vec::new();
                    while off < opt.data.len() {
                        let len = opt.data[off] as usize;
                        if len == 0 {
                            off += 1;
                            break;
                        }
                        if len > 63 || off + 1 + len > opt.data.len() {
                            return domains;
                        }
                        let label =
                            String::from_utf8_lossy(&opt.data[off + 1..off + 1 + len]).to_string();
                        labels.push(label);
                        off += 1 + len;
                    }
                    if !labels.is_empty() {
                        domains.push(labels.join("."));
                    }
                }
            }
        }
        domains
    }

    pub fn has_rapid_commit(&self) -> bool {
        self.options
            .iter()
            .any(|o| o.code == DHCPV6_OPT_RAPID_COMMIT)
    }
}

/// DHCPv6 Server handling address allocation, prefix delegation, and rapid commit.
#[derive(Debug, Clone)]
pub struct Dhcpv6Server {
    pub server_duid: Vec<u8>,
    pub next_ip_suffix: u16,
    pub next_prefix_index: u16,
    pub dns_servers: Vec<Ipv6Address>,
    pub search_list: Vec<String>,
    pub prefix_pool_base: Ipv6Address,
    pub prefix_delegation_len: u8,
    pub active_leases: HashMap<Vec<u8>, Ipv6Address>,
    pub active_delegations: HashMap<Vec<u8>, (Ipv6Address, u8)>,
}

impl Default for Dhcpv6Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Dhcpv6Server {
    pub fn new() -> Self {
        Dhcpv6Server {
            server_duid: vec![
                0x00, 0x01, 0x00, 0x01, 0x2A, 0x55, 0x00, 0x50, 0x56, 0x00, 0x00, 0x01,
            ],
            next_ip_suffix: 100,
            next_prefix_index: 1,
            dns_servers: vec![Ipv6Address([
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x88, 0x88,
            ])],
            search_list: vec!["lab.example.com".to_string()],
            prefix_pool_base: Ipv6Address([
                0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]),
            prefix_delegation_len: 64,
            active_leases: HashMap::new(),
            active_delegations: HashMap::new(),
        }
    }

    /// Handles Solicit message (supports 2-message Rapid Commit and 4-message Advertise).
    pub fn handle_solicit(&mut self, msg: &Dhcpv6Message) -> Option<Dhcpv6Message> {
        let client_duid = msg
            .options
            .iter()
            .find(|o| o.code == DHCPV6_OPT_CLIENTID)?
            .data
            .clone();

        let assigned_ip = self.allocate_ip(&client_duid);
        let delegated_prefix = if msg.options.iter().any(|o| o.code == DHCPV6_OPT_IA_PD) {
            Some(self.allocate_prefix(&client_duid))
        } else {
            None
        };

        if msg.has_rapid_commit() {
            Some(Dhcpv6Message::build_reply(
                msg.transaction_id,
                &client_duid,
                &self.server_duid,
                Some(assigned_ip),
                delegated_prefix,
                &self.dns_servers,
                &self.search_list,
                true,
            ))
        } else {
            Some(Dhcpv6Message::build_advertise_full(
                msg.transaction_id,
                &client_duid,
                &self.server_duid,
                Some(assigned_ip),
                delegated_prefix,
                &self.dns_servers,
                &self.search_list,
            ))
        }
    }

    /// Handles Request message and emits Reply.
    pub fn handle_request(&mut self, msg: &Dhcpv6Message) -> Option<Dhcpv6Message> {
        let client_duid = msg
            .options
            .iter()
            .find(|o| o.code == DHCPV6_OPT_CLIENTID)?
            .data
            .clone();

        let assigned_ip = self.allocate_ip(&client_duid);
        let delegated_prefix = if msg.options.iter().any(|o| o.code == DHCPV6_OPT_IA_PD) {
            Some(self.allocate_prefix(&client_duid))
        } else {
            None
        };

        Some(Dhcpv6Message::build_reply(
            msg.transaction_id,
            &client_duid,
            &self.server_duid,
            Some(assigned_ip),
            delegated_prefix,
            &self.dns_servers,
            &self.search_list,
            false,
        ))
    }

    /// Handles Release message and releases bindings.
    pub fn handle_release(&mut self, msg: &Dhcpv6Message) -> Option<Dhcpv6Message> {
        let client_duid = msg
            .options
            .iter()
            .find(|o| o.code == DHCPV6_OPT_CLIENTID)?
            .data
            .clone();

        self.active_leases.remove(&client_duid);
        self.active_delegations.remove(&client_duid);

        let reply = Dhcpv6Message {
            msg_type: DHCPV6_MSG_REPLY,
            transaction_id: msg.transaction_id,
            options: vec![
                Dhcpv6Option {
                    code: DHCPV6_OPT_CLIENTID,
                    data: client_duid,
                },
                Dhcpv6Option {
                    code: DHCPV6_OPT_SERVERID,
                    data: self.server_duid.clone(),
                },
                Dhcpv6Option {
                    code: DHCPV6_OPT_STATUS_CODE,
                    data: vec![0x00, 0x00], // Success
                },
            ],
        };
        Some(reply)
    }

    fn allocate_ip(&mut self, client_duid: &[u8]) -> Ipv6Address {
        if let Some(existing) = self.active_leases.get(client_duid) {
            return *existing;
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes[0] = 0x20;
        ip_bytes[1] = 0x01;
        ip_bytes[2] = 0x0D;
        ip_bytes[3] = 0xB8;
        ip_bytes[14] = (self.next_ip_suffix >> 8) as u8;
        ip_bytes[15] = self.next_ip_suffix as u8;
        self.next_ip_suffix = self.next_ip_suffix.wrapping_add(1);
        let addr = Ipv6Address(ip_bytes);
        self.active_leases.insert(client_duid.to_vec(), addr);
        addr
    }

    fn allocate_prefix(&mut self, client_duid: &[u8]) -> (Ipv6Address, u8) {
        if let Some(existing) = self.active_delegations.get(client_duid) {
            return *existing;
        }
        let mut p_bytes = self.prefix_pool_base.0;
        p_bytes[6] = (self.next_prefix_index >> 8) as u8;
        p_bytes[7] = self.next_prefix_index as u8;
        self.next_prefix_index = self.next_prefix_index.wrapping_add(1);
        let prefix = (Ipv6Address(p_bytes), self.prefix_delegation_len);
        self.active_delegations.insert(client_duid.to_vec(), prefix);
        prefix
    }
}

/// Client Lifecycle State Machine for DHCPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dhcpv6ClientState {
    Init,
    Soliciting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
}

#[derive(Debug, Clone)]
pub struct Dhcpv6Client {
    pub state: Dhcpv6ClientState,
    pub client_duid: Duid,
    pub server_duid: Option<Vec<u8>>,
    pub transaction_id: u32,
    pub assigned_ip: Option<Ipv6Address>,
    pub delegated_prefix: Option<(Ipv6Address, u8)>,
    pub dns_servers: Vec<Ipv6Address>,
    pub search_list: Vec<String>,
    pub t1_ms: u64,
    pub t2_ms: u64,
    pub valid_until_ms: u64,
}

impl Dhcpv6Client {
    pub fn new(duid: Duid) -> Self {
        Dhcpv6Client {
            state: Dhcpv6ClientState::Init,
            client_duid: duid,
            server_duid: None,
            transaction_id: 1,
            assigned_ip: None,
            delegated_prefix: None,
            dns_servers: Vec::new(),
            search_list: Vec::new(),
            t1_ms: 0,
            t2_ms: 0,
            valid_until_ms: 0,
        }
    }

    /// Generates Solicit message to start address / prefix discovery.
    pub fn start_solicit(&mut self, rapid_commit: bool, request_pd: bool, _now_ms: u64) -> Vec<u8> {
        self.transaction_id = (self.transaction_id + 1) & 0x00FF_FFFF;
        self.state = Dhcpv6ClientState::Soliciting;
        let duid_bytes = self.client_duid.serialize();
        let solicit = Dhcpv6Message::build_solicit_full(
            self.transaction_id,
            &duid_bytes,
            rapid_commit,
            request_pd,
        );
        solicit.serialize()
    }

    /// Handles an Advertise message and returns a Request packet.
    pub fn handle_advertise(&mut self, data: &[u8], _now_ms: u64) -> Option<Vec<u8>> {
        let msg = Dhcpv6Message::parse(data).ok()?;
        if msg.msg_type != DHCPV6_MSG_ADVERTISE || msg.transaction_id != self.transaction_id {
            return None;
        }

        let s_duid = msg
            .options
            .iter()
            .find(|o| o.code == DHCPV6_OPT_SERVERID)?
            .data
            .clone();
        self.server_duid = Some(s_duid.clone());

        let ia_na = msg.get_ia_na();
        let ia_pd = msg.get_ia_pd();
        self.state = Dhcpv6ClientState::Requesting;

        let client_bytes = self.client_duid.serialize();
        let request = Dhcpv6Message::build_request(
            self.transaction_id,
            &client_bytes,
            &s_duid,
            ia_na.as_ref(),
            ia_pd.as_ref(),
        );
        Some(request.serialize())
    }

    /// Handles a Reply message and transitions to Bound.
    pub fn handle_reply(&mut self, data: &[u8], now_ms: u64) -> bool {
        let msg = match Dhcpv6Message::parse(data) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if msg.msg_type != DHCPV6_MSG_REPLY || msg.transaction_id != self.transaction_id {
            return false;
        }

        if let Some(s_duid) = msg.options.iter().find(|o| o.code == DHCPV6_OPT_SERVERID) {
            self.server_duid = Some(s_duid.data.clone());
        }

        if let Some(ip) = msg.get_assigned_ipv6() {
            self.assigned_ip = Some(ip);
        }
        if let Some(p) = msg.get_delegated_prefix() {
            self.delegated_prefix = Some(p);
        }
        self.dns_servers = msg.get_dns_servers();
        self.search_list = msg.get_dnssl();

        if let Some(na) = msg.get_ia_na() {
            self.t1_ms = now_ms.saturating_add((na.t1 as u64) * 1000);
            self.t2_ms = now_ms.saturating_add((na.t2 as u64) * 1000);
            if let Some(addr) = na.addresses.first() {
                self.valid_until_ms = now_ms.saturating_add((addr.valid_lifetime as u64) * 1000);
            }
        }

        self.state = Dhcpv6ClientState::Bound;
        true
    }

    /// Generates a Release message.
    pub fn create_release(&mut self) -> Option<Vec<u8>> {
        let s_duid = self.server_duid.as_ref()?;
        let ip = self.assigned_ip?;
        let ia_na = IaNaOption {
            iaid: 1,
            t1: 0,
            t2: 0,
            addresses: vec![IaAddressOption {
                address: ip,
                preferred_lifetime: 0,
                valid_lifetime: 0,
            }],
        };
        let client_bytes = self.client_duid.serialize();
        self.transaction_id = (self.transaction_id + 1) & 0x00FF_FFFF;
        let release = Dhcpv6Message::build_release(
            self.transaction_id,
            &client_bytes,
            s_duid,
            Some(&ia_na),
            None,
        );
        self.state = Dhcpv6ClientState::Init;
        self.assigned_ip = None;
        self.delegated_prefix = None;
        Some(release.serialize())
    }
}
