//! Geneve Overlay In-Band Network Telemetry (INT) Option Header (RFC 8926 Section 4.4).
//!
//! Implements Geneve Variable-Length Option TLV carrying In-Band Network Telemetry (INT)
//! hop metadata (Option Class 0x0103, Type 0x01) including Switch ID, Ingress/Egress Ports,
//! Hop Latency in nanoseconds, and Queue Occupancy in bytes across overlay fabrics.

use crate::geneve::GeneveOption;

/// Geneve INT Option Class and Type.
pub const GENEVE_OPT_CLASS_INT_TELEMETRY: u16 = 0x0103;
pub const GENEVE_OPT_TYPE_INT_HOP_METADATA: u8 = 0x01;

/// Geneve INT Hop-by-Hop Telemetry Record (16 octets per hop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneveIntHop {
    pub switch_id: u32,
    pub ingress_port: u16,
    pub egress_port: u16,
    pub hop_latency_ns: u32,
    pub queue_occupancy_bytes: u32,
}

impl GeneveIntHop {
    pub fn new(switch_id: u32, in_port: u16, out_port: u16, latency_ns: u32, queue_bytes: u32) -> Self {
        GeneveIntHop {
            switch_id,
            ingress_port: in_port,
            egress_port: out_port,
            hop_latency_ns: latency_ns,
            queue_occupancy_bytes: queue_bytes,
        }
    }

    pub fn serialize(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.switch_id.to_be_bytes());
        buf[4..6].copy_from_slice(&self.ingress_port.to_be_bytes());
        buf[6..8].copy_from_slice(&self.egress_port.to_be_bytes());
        buf[8..12].copy_from_slice(&self.hop_latency_ns.to_be_bytes());
        buf[12..16].copy_from_slice(&self.queue_occupancy_bytes.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let switch_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let in_port = u16::from_be_bytes([data[4], data[5]]);
        let out_port = u16::from_be_bytes([data[6], data[7]]);
        let latency_ns = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let queue_bytes = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        Some(GeneveIntHop {
            switch_id,
            ingress_port: in_port,
            egress_port: out_port,
            hop_latency_ns: latency_ns,
            queue_occupancy_bytes: queue_bytes,
        })
    }
}

/// Geneve In-Band Telemetry Option Payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GeneveTelemetryOption {
    pub hops: Vec<GeneveIntHop>,
}

impl GeneveTelemetryOption {
    pub fn new() -> Self {
        GeneveTelemetryOption { hops: Vec::new() }
    }

    /// Converts this telemetry option into a standard GeneveOption TLV.
    pub fn to_geneve_option(&self) -> GeneveOption {
        let mut data = Vec::with_capacity(self.hops.len() * 16);
        for h in &self.hops {
            data.extend_from_slice(&h.serialize());
        }

        GeneveOption {
            class: GENEVE_OPT_CLASS_INT_TELEMETRY,
            opt_type: GENEVE_OPT_TYPE_INT_HOP_METADATA,
            critical: false,
            data,
        }
    }

    /// Parses a GeneveOption TLV into GeneveTelemetryOption.
    pub fn from_geneve_option(opt: &GeneveOption) -> Result<Self, String> {
        if opt.class != GENEVE_OPT_CLASS_INT_TELEMETRY || opt.opt_type != GENEVE_OPT_TYPE_INT_HOP_METADATA {
            return Err("Not a Geneve INT option".to_string());
        }

        let mut hops = Vec::new();
        let mut offset = 0;
        while offset + 16 <= opt.data.len() {
            if let Some(hop) = GeneveIntHop::parse(&opt.data[offset..offset + 16]) {
                hops.push(hop);
            }
            offset += 16;
        }

        Ok(GeneveTelemetryOption { hops })
    }
}

/// Geneve In-Band Network Telemetry Engine.
#[derive(Debug, Clone, Default)]
pub struct GeneveTelemetryEngine {
    pub local_switch_id: u32,
    pub hops_inserted_count: usize,
    pub packets_collected_count: usize,
}

impl GeneveTelemetryEngine {
    pub fn new(switch_id: u32) -> Self {
        GeneveTelemetryEngine {
            local_switch_id: switch_id,
            hops_inserted_count: 0,
            packets_collected_count: 0,
        }
    }

    /// Appends local switch telemetry metadata to a Geneve telemetry option.
    pub fn insert_hop(
        &mut self,
        opt: &mut GeneveTelemetryOption,
        in_port: u16,
        out_port: u16,
        latency_ns: u32,
        queue_bytes: u32,
    ) {
        self.hops_inserted_count += 1;
        let hop = GeneveIntHop::new(
            self.local_switch_id,
            in_port,
            out_port,
            latency_ns,
            queue_bytes,
        );
        opt.hops.push(hop);
    }

    /// Extracts and parses telemetry hops at overlay egress.
    pub fn collect_telemetry(&mut self, opt: &GeneveTelemetryOption) -> Vec<GeneveIntHop> {
        self.packets_collected_count += 1;
        opt.hops.clone()
    }
}
