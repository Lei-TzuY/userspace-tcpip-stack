//! NSH MD Type 2 Extended Context TLVs for SFC In-situ Telemetry, Congestion/ECN, and Subscriber Identity.
//!
//! Extends the NSH MD Type 2 variable-length TLV framework (RFC 8300 Section 3.5.2) with:
//! - **In-situ OAM / Path Telemetry TLV**: Per-hop latency, jitter, and loss counters for
//!   real-time SFC service path health monitoring (aligned with RFC 9197 IOAM).
//! - **Congestion/ECN Notification TLV**: Explicit Congestion Notification feedback from
//!   SFs propagated back along the SFC chain for congestion-aware scheduling.
//! - **Subscriber Identity TLV**: Per-flow subscriber context (IMSI/MSISDN) for
//!   deep packet inspection or policy-aware service functions.
//! - **SFC Telemetry Collector**: Aggregation engine that collects per-hop telemetry
//!   records from completed service chains and computes path-level statistics.

use crate::nsh_md2::{NSH_TLV_CLASS_IETF, NshContextTlv, NshMd2Packet};

/// Extended TLV Types (vendor-specific under IETF class for educational purposes).
pub const NSH_TLV_TYPE_IOAM_HOP_TELEMETRY: u8 = 0x10;
pub const NSH_TLV_TYPE_ECN_CONGESTION: u8 = 0x11;
pub const NSH_TLV_TYPE_SUBSCRIBER_ID: u8 = 0x12;

/// IOAM TLV Class (draft-ietf-ippm-ioam-data).
pub const NSH_TLV_CLASS_IOAM: u16 = 0x0104;

/// In-situ OAM Hop Telemetry Record (24 bytes, padded to 4-byte alignment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoamHopTelemetry {
    pub node_id: u32,
    pub ingress_if_id: u16,
    pub egress_if_id: u16,
    pub transit_delay_us: u32,
    pub queue_depth_bytes: u32,
    pub tx_packet_count: u32,
    pub rx_drop_count: u32,
}

impl IoamHopTelemetry {
    pub fn new(
        node_id: u32,
        ingress_if_id: u16,
        egress_if_id: u16,
        transit_delay_us: u32,
        queue_depth_bytes: u32,
    ) -> Self {
        IoamHopTelemetry {
            node_id,
            ingress_if_id,
            egress_if_id,
            transit_delay_us,
            queue_depth_bytes,
            tx_packet_count: 0,
            rx_drop_count: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        buf.extend_from_slice(&self.node_id.to_be_bytes());
        buf.extend_from_slice(&self.ingress_if_id.to_be_bytes());
        buf.extend_from_slice(&self.egress_if_id.to_be_bytes());
        buf.extend_from_slice(&self.transit_delay_us.to_be_bytes());
        buf.extend_from_slice(&self.queue_depth_bytes.to_be_bytes());
        buf.extend_from_slice(&self.tx_packet_count.to_be_bytes());
        buf.extend_from_slice(&self.rx_drop_count.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 24 {
            return None;
        }
        let node_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let ingress_if_id = u16::from_be_bytes([data[4], data[5]]);
        let egress_if_id = u16::from_be_bytes([data[6], data[7]]);
        let transit_delay_us = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let queue_depth_bytes = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let tx_packet_count = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let rx_drop_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

        Some(IoamHopTelemetry {
            node_id,
            ingress_if_id,
            egress_if_id,
            transit_delay_us,
            queue_depth_bytes,
            tx_packet_count,
            rx_drop_count,
        })
    }

    /// Constructs an NSH MD2 TLV carrying this IOAM hop telemetry.
    pub fn to_nsh_tlv(&self) -> NshContextTlv {
        NshContextTlv::new(
            NSH_TLV_CLASS_IOAM,
            NSH_TLV_TYPE_IOAM_HOP_TELEMETRY,
            false,
            self.serialize(),
        )
    }
}

/// ECN / Congestion Notification TLV (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcnCongestionTlv {
    /// SF node that detected congestion.
    pub reporting_node_id: u32,
    /// Congestion severity level (0 = none, 1 = mild, 2 = moderate, 3 = severe).
    pub congestion_level: u8,
    /// ECN codepoint feedback (0 = Not-ECT, 1 = ECT(1), 2 = ECT(0), 3 = CE).
    pub ecn_codepoint: u8,
    /// Queue utilization as percentage (0..100).
    pub queue_utilization_pct: u8,
    /// Reserved for future use.
    pub _reserved: u8,
}

impl EcnCongestionTlv {
    pub fn new(
        reporting_node_id: u32,
        congestion_level: u8,
        ecn_codepoint: u8,
        queue_util_pct: u8,
    ) -> Self {
        EcnCongestionTlv {
            reporting_node_id,
            congestion_level,
            ecn_codepoint,
            queue_utilization_pct: queue_util_pct,
            _reserved: 0,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8);
        buf.extend_from_slice(&self.reporting_node_id.to_be_bytes());
        buf.push(self.congestion_level);
        buf.push(self.ecn_codepoint);
        buf.push(self.queue_utilization_pct);
        buf.push(self._reserved);
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let reporting_node_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        Some(EcnCongestionTlv {
            reporting_node_id,
            congestion_level: data[4],
            ecn_codepoint: data[5],
            queue_utilization_pct: data[6],
            _reserved: data[7],
        })
    }

    pub fn to_nsh_tlv(&self) -> NshContextTlv {
        NshContextTlv::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_ECN_CONGESTION,
            true, // Critical: SFs must not ignore congestion signals
            self.serialize(),
        )
    }
}

/// Subscriber Identity TLV (variable length, up to 20 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriberIdType {
    Imsi = 0,
    Msisdn = 1,
    Nai = 2,
}

impl SubscriberIdType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => SubscriberIdType::Imsi,
            1 => SubscriberIdType::Msisdn,
            _ => SubscriberIdType::Nai,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriberIdTlv {
    pub id_type: SubscriberIdType,
    pub subscriber_id: String,
}

impl SubscriberIdTlv {
    pub fn new_imsi(imsi: &str) -> Self {
        SubscriberIdTlv {
            id_type: SubscriberIdType::Imsi,
            subscriber_id: imsi.to_string(),
        }
    }

    pub fn new_msisdn(msisdn: &str) -> Self {
        SubscriberIdTlv {
            id_type: SubscriberIdType::Msisdn,
            subscriber_id: msisdn.to_string(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.id_type.clone() as u8);
        let id_bytes = self.subscriber_id.as_bytes();
        buf.push(id_bytes.len() as u8);
        buf.extend_from_slice(id_bytes);
        // 4-byte alignment padding
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let id_type = SubscriberIdType::from_u8(data[0]);
        let id_len = data[1] as usize;
        if data.len() < 2 + id_len {
            return None;
        }
        let subscriber_id = String::from_utf8_lossy(&data[2..2 + id_len]).to_string();
        Some(SubscriberIdTlv {
            id_type,
            subscriber_id,
        })
    }

    pub fn to_nsh_tlv(&self) -> NshContextTlv {
        NshContextTlv::new(
            NSH_TLV_CLASS_IETF,
            NSH_TLV_TYPE_SUBSCRIBER_ID,
            false,
            self.serialize(),
        )
    }
}

// ---------------------------------------------------------------------------
// Transit Node Extended Telemetry Insertion
// ---------------------------------------------------------------------------

/// Extended transit node that inserts IOAM telemetry and ECN TLVs into NSH MD2 packets.
#[derive(Debug, Clone)]
pub struct NshMd2ExtendedTransitEngine {
    pub node_id: u32,
    pub hops_processed: usize,
    pub congestion_notifications_inserted: usize,
}

impl NshMd2ExtendedTransitEngine {
    pub fn new(node_id: u32) -> Self {
        NshMd2ExtendedTransitEngine {
            node_id,
            hops_processed: 0,
            congestion_notifications_inserted: 0,
        }
    }

    /// Inserts an IOAM hop telemetry TLV into the packet.
    pub fn insert_ioam_telemetry(
        &mut self,
        pkt: &mut NshMd2Packet,
        ingress_if: u16,
        egress_if: u16,
        transit_delay_us: u32,
        queue_depth_bytes: u32,
    ) {
        let hop = IoamHopTelemetry::new(
            self.node_id,
            ingress_if,
            egress_if,
            transit_delay_us,
            queue_depth_bytes,
        );
        pkt.header.tlvs.push(hop.to_nsh_tlv());
        self.hops_processed += 1;
    }

    /// Inserts an ECN congestion notification TLV if the queue utilization exceeds the threshold.
    pub fn insert_ecn_if_congested(
        &mut self,
        pkt: &mut NshMd2Packet,
        queue_util_pct: u8,
        threshold_pct: u8,
    ) -> bool {
        if queue_util_pct >= threshold_pct {
            let level = if queue_util_pct >= 95 {
                3 // severe
            } else if queue_util_pct >= 80 {
                2 // moderate
            } else {
                1 // mild
            };
            let ecn = EcnCongestionTlv::new(self.node_id, level, 3, queue_util_pct); // CE marking
            pkt.header.tlvs.push(ecn.to_nsh_tlv());
            self.congestion_notifications_inserted += 1;
            true
        } else {
            false
        }
    }

    /// Attaches subscriber identity metadata for DPI/policy-aware SFs.
    pub fn attach_subscriber_id(&self, pkt: &mut NshMd2Packet, subscriber: &SubscriberIdTlv) {
        pkt.header.tlvs.push(subscriber.to_nsh_tlv());
    }
}

// ---------------------------------------------------------------------------
// SFC Telemetry Collector
// ---------------------------------------------------------------------------

/// Statistics for a single service function chain path.
#[derive(Debug, Clone, Default)]
pub struct SfcPathStats {
    pub path_id: u32,
    pub total_flows_observed: usize,
    pub total_hop_records: usize,
    pub cumulative_delay_us: u64,
    pub max_single_hop_delay_us: u32,
    pub max_queue_depth_bytes: u32,
    pub congestion_events: usize,
}

/// Collects telemetry from completed SFC flows and computes aggregate statistics.
#[derive(Debug, Clone, Default)]
pub struct SfcTelemetryCollector {
    pub path_stats: std::collections::HashMap<u32, SfcPathStats>,
    pub total_flows_collected: usize,
}

impl SfcTelemetryCollector {
    pub fn new() -> Self {
        SfcTelemetryCollector {
            path_stats: std::collections::HashMap::new(),
            total_flows_collected: 0,
        }
    }

    /// Extracts IOAM telemetry and ECN signals from a completed NSH MD2 packet.
    pub fn collect_from_packet(&mut self, pkt: &NshMd2Packet) {
        let spi = pkt.header.service_path_id;
        let stats = self.path_stats.entry(spi).or_insert_with(|| SfcPathStats {
            path_id: spi,
            ..Default::default()
        });

        stats.total_flows_observed += 1;
        self.total_flows_collected += 1;

        for tlv in &pkt.header.tlvs {
            if tlv.class == NSH_TLV_CLASS_IOAM && tlv.tlv_type == NSH_TLV_TYPE_IOAM_HOP_TELEMETRY {
                if let Some(hop) = IoamHopTelemetry::parse(&tlv.data) {
                    stats.total_hop_records += 1;
                    stats.cumulative_delay_us += hop.transit_delay_us as u64;
                    if hop.transit_delay_us > stats.max_single_hop_delay_us {
                        stats.max_single_hop_delay_us = hop.transit_delay_us;
                    }
                    if hop.queue_depth_bytes > stats.max_queue_depth_bytes {
                        stats.max_queue_depth_bytes = hop.queue_depth_bytes;
                    }
                }
            }

            if tlv.class == NSH_TLV_CLASS_IETF && tlv.tlv_type == NSH_TLV_TYPE_ECN_CONGESTION {
                if EcnCongestionTlv::parse(&tlv.data).is_some() {
                    stats.congestion_events += 1;
                }
            }
        }
    }

    /// Returns the average per-hop delay across all observed flows for a service path.
    pub fn average_hop_delay_us(&self, spi: u32) -> Option<f64> {
        self.path_stats.get(&spi).and_then(|s| {
            if s.total_hop_records == 0 {
                None
            } else {
                Some(s.cumulative_delay_us as f64 / s.total_hop_records as f64)
            }
        })
    }
}
