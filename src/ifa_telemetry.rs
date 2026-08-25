//! In-Band Flow Analytics & Telemetry (IFA 2.0 / RFC 9197).
//!
//! Implements In-situ Flow Analytics (IFA 2.0) packet framing, hop-by-hop metadata insertion
//! (Node ID, Ingress/Egress Interface, Queue Depth, and Transit Latency), and egress flow
//! telemetry analytics extraction for real-time congestion and microburst detection.

/// IFA 2.0 Protocol Version.
pub const IFA_VERSION_2: u8 = 0x02;

/// Telemetry Request Bitflags in IFA Header.
pub const IFA_REQ_NODE_ID: u8 = 0x01;
pub const IFA_REQ_PORTS: u8 = 0x02;
pub const IFA_REQ_LATENCY: u8 = 0x04;
pub const IFA_REQ_QUEUE_DEPTH: u8 = 0x08;

/// IFA 2.0 Base Header (RFC 9197).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaHeader {
    pub version: u8,
    pub hop_limit: u8,
    pub current_hop_count: u8,
    pub request_vector: u8,
}

impl IfaHeader {
    pub fn new(hop_limit: u8, request_vector: u8) -> Self {
        IfaHeader {
            version: IFA_VERSION_2,
            hop_limit,
            current_hop_count: 0,
            request_vector,
        }
    }

    pub fn serialize(&self) -> [u8; 4] {
        [
            (self.version << 4) & 0xF0,
            self.hop_limit,
            self.current_hop_count,
            self.request_vector,
        ]
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let version = (data[0] >> 4) & 0x0F;
        if version != IFA_VERSION_2 {
            return None;
        }
        Some(IfaHeader {
            version,
            hop_limit: data[1],
            current_hop_count: data[2],
            request_vector: data[3],
        })
    }
}

/// Hop-by-Hop Telemetry Record inserted by transit routers (16 octets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaHopRecord {
    pub node_id: u32,
    pub ingress_port: u16,
    pub egress_port: u16,
    pub hop_latency_ns: u32,
    pub queue_depth_bytes: u32,
}

impl IfaHopRecord {
    pub fn new(
        node_id: u32,
        ingress_port: u16,
        egress_port: u16,
        hop_latency_ns: u32,
        queue_depth_bytes: u32,
    ) -> Self {
        IfaHopRecord {
            node_id,
            ingress_port,
            egress_port,
            hop_latency_ns,
            queue_depth_bytes,
        }
    }

    pub fn serialize(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.node_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.ingress_port.to_be_bytes());
        buf[6..8].copy_from_slice(&self.egress_port.to_be_bytes());
        buf[8..12].copy_from_slice(&self.hop_latency_ns.to_be_bytes());
        buf[12..16].copy_from_slice(&self.queue_depth_bytes.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let node_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let ingress_port = u16::from_be_bytes([data[4], data[5]]);
        let egress_port = u16::from_be_bytes([data[6], data[7]]);
        let hop_latency_ns = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let queue_depth_bytes = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        Some(IfaHopRecord {
            node_id,
            ingress_port,
            egress_port,
            hop_latency_ns,
            queue_depth_bytes,
        })
    }
}

/// IFA 2.0 In-Band Telemetry Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaPacket {
    pub header: IfaHeader,
    pub records: Vec<IfaHopRecord>,
    pub payload: Vec<u8>,
}

impl IfaPacket {
    pub fn new(header: IfaHeader, payload: Vec<u8>) -> Self {
        IfaPacket {
            header,
            records: Vec::new(),
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.records.len() * 16 + self.payload.len());
        buf.extend_from_slice(&self.header.serialize());
        for rec in &self.records {
            buf.extend_from_slice(&rec.serialize());
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let header = IfaHeader::parse(&data[0..4])?;
        let hop_count = header.current_hop_count as usize;
        let records_len = hop_count * 16;
        if data.len() < 4 + records_len {
            return None;
        }

        let mut records = Vec::with_capacity(hop_count);
        let mut offset = 4;
        for _ in 0..hop_count {
            let rec = IfaHopRecord::parse(&data[offset..offset + 16])?;
            records.push(rec);
            offset += 16;
        }

        let payload = data[offset..].to_vec();

        Some(IfaPacket {
            header,
            records,
            payload,
        })
    }
}

/// In-Band Flow Analytics (IFA 2.0) Processing Engine.
#[derive(Debug, Clone, Default)]
pub struct IfaTelemetryEngine {
    pub local_node_id: u32,
    pub probes_encapsulated: usize,
    pub hops_inserted: usize,
    pub packets_collected: usize,
}

impl IfaTelemetryEngine {
    pub fn new(local_node_id: u32) -> Self {
        IfaTelemetryEngine {
            local_node_id,
            probes_encapsulated: 0,
            hops_inserted: 0,
            packets_collected: 0,
        }
    }

    /// Ingress Encapsulation: Generates a new IFA packet with telemetry request vector.
    pub fn ingress_encapsulate(
        &mut self,
        payload: &[u8],
        hop_limit: u8,
        req_vector: u8,
    ) -> IfaPacket {
        self.probes_encapsulated += 1;
        let header = IfaHeader::new(hop_limit, req_vector);
        IfaPacket::new(header, payload.to_vec())
    }

    /// Transit Processing: Inserts this node's telemetry record if hop limit is not exceeded.
    pub fn transit_insert_hop(
        &mut self,
        pkt: &mut IfaPacket,
        ingress_port: u16,
        egress_port: u16,
        hop_latency_ns: u32,
        queue_depth_bytes: u32,
    ) -> bool {
        if pkt.header.current_hop_count >= pkt.header.hop_limit {
            return false;
        }

        let rec = IfaHopRecord::new(
            self.local_node_id,
            ingress_port,
            egress_port,
            hop_latency_ns,
            queue_depth_bytes,
        );
        pkt.records.push(rec);
        pkt.header.current_hop_count += 1;
        self.hops_inserted += 1;
        true
    }

    /// Egress Extraction: Collects telemetry records from an arriving IFA packet.
    pub fn egress_collect(&mut self, pkt: &IfaPacket) -> Vec<IfaHopRecord> {
        self.packets_collected += 1;
        pkt.records.clone()
    }
}
