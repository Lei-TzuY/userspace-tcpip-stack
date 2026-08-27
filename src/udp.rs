//! Layer 4: User Datagram Protocol (UDP - RFC 768).
//!
//! Stateless, connectionless transport protocol with pseudo-header checksum.

use crate::checksum::{compute_ipv4_transport_checksum, verify_ipv4_transport_checksum};
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;
use std::fmt;

pub const UDP_HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpError {
    DatagramTooShort(usize),
    LengthTooShort { declared: usize },
    LengthMismatch { declared: usize, available: usize },
    InvalidChecksum { found: u16 },
}

impl fmt::Display for UdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpError::DatagramTooShort(len) => {
                write!(f, "UDP datagram too short ({} bytes, min 8)", len)
            }
            UdpError::LengthTooShort { declared } => {
                write!(
                    f,
                    "UDP declared length {} is smaller than the 8-byte header",
                    declared
                )
            }
            UdpError::LengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "UDP declared length {} exceeds data length {}",
                    declared, available
                )
            }
            UdpError::InvalidChecksum { found } => {
                write!(
                    f,
                    "UDP checksum mismatch with checksum field 0x{:04x}",
                    found
                )
            }
        }
    }
}

impl std::error::Error for UdpError {}

impl<'a> UdpDatagram<'a> {
    pub fn parse(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        data: &'a [u8],
        check_checksum: bool,
    ) -> Result<Self, UdpError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(UdpError::DatagramTooShort(data.len()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        if (length as usize) < UDP_HEADER_LEN {
            return Err(UdpError::LengthTooShort {
                declared: length as usize,
            });
        }

        if (length as usize) > data.len() {
            return Err(UdpError::LengthMismatch {
                declared: length as usize,
                available: data.len(),
            });
        }

        let segment = &data[0..length as usize];

        // If checksum is 0, checksum computation was omitted by sender (RFC 768)
        if check_checksum
            && checksum != 0
            && !verify_ipv4_transport_checksum(src_ip.0, dst_ip.0, 17, segment)
        {
            return Err(UdpError::InvalidChecksum { found: checksum });
        }

        let payload = &data[UDP_HEADER_LEN..length as usize];

        Ok(UdpDatagram {
            src_port,
            dst_port,
            length,
            checksum,
            payload,
        })
    }

    pub fn serialize(
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let length = (UDP_HEADER_LEN + payload.len()) as u16;
        let mut buf = Vec::with_capacity(length as usize);

        buf.extend_from_slice(&src_port.to_be_bytes());
        buf.extend_from_slice(&dst_port.to_be_bytes());
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(payload);

        let csum = compute_ipv4_transport_checksum(src_ip.0, dst_ip.0, 17, &buf);
        buf[6..8].copy_from_slice(&csum.to_be_bytes());

        buf
    }
}

/// UDP Socket Table to dispatch incoming datagrams to registered port listeners
pub type UdpHandler = Box<dyn Fn(Ipv4Address, u16, &[u8]) -> Option<Vec<u8>> + Send + Sync>;

#[derive(Default)]
pub struct UdpSocketTable {
    listeners: HashMap<u16, UdpHandler>,
}

impl UdpSocketTable {
    pub fn new() -> Self {
        UdpSocketTable {
            listeners: HashMap::new(),
        }
    }

    pub fn bind<F>(&mut self, port: u16, handler: F)
    where
        F: Fn(Ipv4Address, u16, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        self.listeners.insert(port, Box::new(handler));
    }

    pub fn unbind(&mut self, port: u16) {
        self.listeners.remove(&port);
    }

    pub fn dispatch(
        &self,
        src_ip: Ipv4Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(handler) = self.listeners.get(&dst_port) {
            handler(src_ip, src_port, payload)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_roundtrip() {
        let src_ip = Ipv4Address::new(10, 0, 0, 1);
        let dst_ip = Ipv4Address::new(10, 0, 0, 2);
        let payload = b"Echo request over UDP";

        let raw = UdpDatagram::serialize(src_ip, dst_ip, 12345, 53, payload);
        assert_eq!(raw.len(), 8 + payload.len());

        let dg = UdpDatagram::parse(src_ip, dst_ip, &raw, true).unwrap();
        assert_eq!(dg.src_port, 12345);
        assert_eq!(dg.dst_port, 53);
        assert_eq!(dg.payload, payload);
    }

    #[test]
    fn parse_rejects_declared_length_below_udp_header() {
        let src_ip = Ipv4Address::new(192, 0, 2, 1);
        let dst_ip = Ipv4Address::new(198, 51, 100, 1);

        for declared in [0u16, 7u16] {
            let mut raw = [0u8; UDP_HEADER_LEN];
            raw[4..6].copy_from_slice(&declared.to_be_bytes());

            assert_eq!(
                UdpDatagram::parse(src_ip, dst_ip, &raw, false),
                Err(UdpError::LengthTooShort {
                    declared: declared as usize,
                })
            );
        }
    }

    #[test]
    fn parse_accepts_header_only_udp_datagram() {
        let src_ip = Ipv4Address::new(192, 0, 2, 1);
        let dst_ip = Ipv4Address::new(198, 51, 100, 1);
        let mut raw = [0u8; UDP_HEADER_LEN];
        raw[0..2].copy_from_slice(&12345u16.to_be_bytes());
        raw[2..4].copy_from_slice(&53u16.to_be_bytes());
        raw[4..6].copy_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());

        let parsed = UdpDatagram::parse(src_ip, dst_ip, &raw, true).unwrap();
        assert_eq!(parsed.length, UDP_HEADER_LEN as u16);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_udp_socket_table() {
        let mut table = UdpSocketTable::new();
        table.bind(7, |_src_ip, _src_port, payload| {
            // Echo server
            Some(payload.to_vec())
        });

        let resp = table.dispatch(Ipv4Address::new(1, 2, 3, 4), 9999, 7, b"Ping");
        assert_eq!(resp, Some(b"Ping".to_vec()));

        let unbound = table.dispatch(Ipv4Address::new(1, 2, 3, 4), 9999, 80, b"Ping");
        assert_eq!(unbound, None);
    }
}
