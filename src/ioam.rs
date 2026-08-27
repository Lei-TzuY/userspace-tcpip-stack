//! In-situ Operations, Administration, and Maintenance (IOAM - RFC 9197 & RFC 9326).
//!
//! In-band Network Telemetry recording hop-by-hop latency, node ID, interfaces, and queue delay within packet headers.

use std::fmt;

pub const IOAM_TYPE_PREALLOC_TRACE: u8 = 0;
pub const IOAM_TYPE_INCREMENTAL_TRACE: u8 = 1;
pub const IOAM_TYPE_POT: u8 = 2;
pub const IOAM_TYPE_E2E: u8 = 3;

// IOAM-Trace-Type Bit-Mask Telemetry Selectors
pub const IOAM_TRACE_BIT_NODE_ID: u32 = 0x80000000;
pub const IOAM_TRACE_BIT_INGRESS_EGRESS: u32 = 0x40000000;
pub const IOAM_TRACE_BIT_TIMESTAMP_NS: u32 = 0x20000000;
pub const IOAM_TRACE_BIT_TRANSIT_DELAY: u32 = 0x10000000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoamTraceNode {
    pub node_id: u32,
    pub ingress_if: u16,
    pub egress_if: u16,
    pub timestamp_ns: u64,
    pub transit_delay_ns: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoamTraceHeader {
    pub namespace_id: u16,
    pub trace_type: u32,
    pub node_records: Vec<IoamTraceNode>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoamPacket {
    pub trace_header: IoamTraceHeader,
    pub inner_payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoamError {
    PacketTooShort(usize),
    InvalidLength,
}

impl fmt::Display for IoamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IoamError::PacketTooShort(l) => write!(f, "IOAM packet too short ({} bytes)", l),
            IoamError::InvalidLength => write!(f, "Invalid IOAM length"),
        }
    }
}

impl std::error::Error for IoamError {}

impl IoamTraceHeader {
    pub fn new(namespace_id: u16) -> Self {
        IoamTraceHeader {
            namespace_id,
            trace_type: IOAM_TRACE_BIT_NODE_ID
                | IOAM_TRACE_BIT_INGRESS_EGRESS
                | IOAM_TRACE_BIT_TIMESTAMP_NS
                | IOAM_TRACE_BIT_TRANSIT_DELAY,
            node_records: Vec::new(),
        }
    }

    pub fn add_hop(
        &mut self,
        node_id: u32,
        ingress_if: u16,
        egress_if: u16,
        timestamp_ns: u64,
        transit_delay_ns: u32,
    ) {
        self.node_records.push(IoamTraceNode {
            node_id,
            ingress_if,
            egress_if,
            timestamp_ns,
            transit_delay_ns,
        });
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.namespace_id.to_be_bytes());
        buf.push(self.node_records.len() as u8); // Node count
        buf.push(0); // Reserved

        buf.extend_from_slice(&self.trace_type.to_be_bytes());

        for node in &self.node_records {
            buf.extend_from_slice(&node.node_id.to_be_bytes());
            buf.extend_from_slice(&node.ingress_if.to_be_bytes());
            buf.extend_from_slice(&node.egress_if.to_be_bytes());
            buf.extend_from_slice(&node.timestamp_ns.to_be_bytes());
            buf.extend_from_slice(&node.transit_delay_ns.to_be_bytes());
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }

        let namespace_id = u16::from_be_bytes([data[0], data[1]]);
        let node_count = data[2] as usize;
        let trace_type = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let records_len = node_count.checked_mul(20)?;
        let header_len = 8usize.checked_add(records_len)?;
        if header_len > data.len() {
            return None;
        }

        let mut node_records = Vec::new();
        let mut offset = 8;

        for _ in 0..node_count {
            let node_id = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let ingress_if = u16::from_be_bytes([data[offset + 4], data[offset + 5]]);
            let egress_if = u16::from_be_bytes([data[offset + 6], data[offset + 7]]);
            let timestamp_ns = u64::from_be_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
                data[offset + 12],
                data[offset + 13],
                data[offset + 14],
                data[offset + 15],
            ]);
            let transit_delay_ns = u32::from_be_bytes([
                data[offset + 16],
                data[offset + 17],
                data[offset + 18],
                data[offset + 19],
            ]);

            node_records.push(IoamTraceNode {
                node_id,
                ingress_if,
                egress_if,
                timestamp_ns,
                transit_delay_ns,
            });
            offset += 20;
        }

        Some((
            IoamTraceHeader {
                namespace_id,
                trace_type,
                node_records,
            },
            offset,
        ))
    }
}

impl IoamPacket {
    pub fn new(namespace_id: u16, inner_payload: &[u8]) -> Self {
        IoamPacket {
            trace_header: IoamTraceHeader::new(namespace_id),
            inner_payload: inner_payload.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = self.trace_header.serialize();
        buf.extend_from_slice(&self.inner_payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, IoamError> {
        if data.len() < 8 {
            return Err(IoamError::PacketTooShort(data.len()));
        }

        if let Some((hdr, consumed)) = IoamTraceHeader::parse(data) {
            let inner_payload = data[consumed..].to_vec();
            Ok(IoamPacket {
                trace_header: hdr,
                inner_payload,
            })
        } else {
            Err(IoamError::InvalidLength)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ioam_hop_by_hop_telemetry_recording() {
        let mut ioam = IoamPacket::new(1, b"Application User Payload Data");

        // Spine-Leaf Network Hop 1 (Leaf Switch 1)
        ioam.trace_header.add_hop(101, 1, 2, 1700000000100000, 45);

        // Hop 2 (Spine Switch 1)
        ioam.trace_header.add_hop(201, 3, 4, 1700000000100050, 30);

        // Hop 3 (Leaf Switch 2)
        ioam.trace_header.add_hop(102, 2, 1, 1700000000100090, 50);

        let raw = ioam.serialize();
        assert!(raw.len() >= 68);

        let parsed = IoamPacket::parse(&raw).unwrap();
        assert_eq!(parsed.trace_header.namespace_id, 1);
        assert_eq!(parsed.trace_header.node_records.len(), 3);

        assert_eq!(parsed.trace_header.node_records[0].node_id, 101);
        assert_eq!(parsed.trace_header.node_records[0].transit_delay_ns, 45);

        assert_eq!(parsed.trace_header.node_records[1].node_id, 201);
        assert_eq!(parsed.trace_header.node_records[1].transit_delay_ns, 30);

        assert_eq!(parsed.trace_header.node_records[2].node_id, 102);
        assert_eq!(&parsed.inner_payload, b"Application User Payload Data");
    }
    #[test]
    fn test_ioam_rejects_missing_declared_node_record() {
        let raw = [0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0];
        assert_eq!(IoamPacket::parse(&raw), Err(IoamError::InvalidLength));
    }

    #[test]
    fn test_ioam_rejects_partial_declared_node_record() {
        let mut raw = vec![0x00, 0x01, 0x01, 0x00, 0, 0, 0, 0];
        raw.extend_from_slice(&[0u8; 19]);
        assert_eq!(IoamPacket::parse(&raw), Err(IoamError::InvalidLength));
    }
}
