//! 3GPP Release 18 / Release 19 Non-Terrestrial Networks (NTN) Discontinuous Coverage
//! & Delay-Tolerant Networking (DTN) Store-and-Forward Engine.
//!
//! Conforms to:
//! - 3GPP TR 38.882 Rel-18: Solutions for NR to support non-terrestrial networks (NTN) with discontinuous coverage.
//! - 3GPP TS 38.300 Rel-18 §16.14: NTN Support - Discontinuous Coverage & Store-and-Forward operation.
//! - 3GPP TS 23.501 Rel-18 §5.43: Store and Forward buffering for non-continuous satellite coverage.
//! - CCSDS 734.2-B-1 / RFC 9171: Bundle Protocol Version 7 (BPv7) architecture, EIDs, and Custody Transfer.
//!
//! Key Architecture:
//! 1. Satellite Contact Window & Orbit Visibility Engine:
//!    - Evaluates dynamic orbital contact periods [t_AOS, t_LOS] between ground terminals, satellites,
//!      and gateway earth stations.
//!    - Elevation-dependent data rate adaptation (10° mask angle up to 90° zenith) accounting for
//!      slant range path loss dynamics.
//! 2. Lightweight Bundle Protocol v7 (RFC 9171) Frame Codec:
//!    - Primary block: CRC-16, Bundle Processing Control Flags, Source/Destination EIDs, Creation
//!      Timestamp, and Lifetime (TTL).
//!    - Payload block: QoS Priority, sequence tracking, and binary payload.
//! 3. Priority Custody Storage & Multi-Queue Buffer:
//!    - Three traffic priority levels: Urgent/Emergency, Normal/Interactive, and Bulk/Background.
//!    - Automated TTL expiration, custody transfer acceptance/relinquishment, and proactive buffer
//!      eviction (Drop-Lowest-Priority-First).
//! 4. Contact Graph Scheduling & Burst Forwarding:
//!    - Automatically buffers traffic during satellite orbital dead zones (inter-pass duration 30-90 min).
//!    - Executes burst transmission upon Acquisition of Signal (AOS) with link budget gating.
//! 5. Discontinuous Coverage Telemetry & Link Analytics:
//!    - Contact window utilization efficiency, bundle delivery ratio (PDR), and storage dwell latency.
//!
//! Pure standard Rust with zero external dependencies.

use std::collections::{HashMap, VecDeque};
use std::fmt;

// ---------------------------------------------------------------------------
// Constants & CRC-16 CCITT
// ---------------------------------------------------------------------------

/// Standard minimum elevation mask angle for NTN satellite communications (degrees).
pub const DEFAULT_ELEVATION_MASK_DEG: f64 = 10.0;

/// Default maximum storage buffer capacity per satellite node (in bytes, 16 MB).
pub const DEFAULT_STORAGE_CAPACITY_BYTES: usize = 16 * 1024 * 1024;

/// Default maximum bundle count in storage.
pub const DEFAULT_MAX_BUNDLE_COUNT: usize = 2000;

/// Standard CRC-16 CCITT polynomial (0x1021, initial value 0xFFFF).
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// Computes CRC-16 CCITT checksum over a slice of bytes.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

/// Errors encountered in NTN DTN Store-and-Forward operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtnError {
    BufferFull {
        current_bytes: usize,
        capacity_bytes: usize,
    },
    BundleExpired {
        bundle_id: u64,
        age_ms: u64,
        ttl_ms: u64,
    },
    ContactWindowClosed {
        satellite_id: u32,
        current_time_ms: u64,
    },
    InvalidEid(String),
    SerializationError(String),
    DeserializationError(String),
    ChecksumMismatch {
        expected: u16,
        calculated: u16,
    },
    InvalidPriority(u8),
    NodeNotFound(u32),
}

impl fmt::Display for DtnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtnError::BufferFull {
                current_bytes,
                capacity_bytes,
            } => {
                write!(
                    f,
                    "DTN storage full: {} / {} bytes",
                    current_bytes, capacity_bytes
                )
            }
            DtnError::BundleExpired {
                bundle_id,
                age_ms,
                ttl_ms,
            } => {
                write!(
                    f,
                    "Bundle {} expired: age {} ms > TTL {} ms",
                    bundle_id, age_ms, ttl_ms
                )
            }
            DtnError::ContactWindowClosed {
                satellite_id,
                current_time_ms,
            } => {
                write!(
                    f,
                    "No active contact window for satellite {} at t={} ms",
                    satellite_id, current_time_ms
                )
            }
            DtnError::InvalidEid(msg) => write!(f, "Invalid Endpoint Identifier (EID): {}", msg),
            DtnError::SerializationError(msg) => write!(f, "DTN serialization error: {}", msg),
            DtnError::DeserializationError(msg) => write!(f, "DTN deserialization error: {}", msg),
            DtnError::ChecksumMismatch {
                expected,
                calculated,
            } => {
                write!(
                    f,
                    "CRC16 mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, calculated
                )
            }
            DtnError::InvalidPriority(p) => write!(f, "Invalid bundle priority level: {}", p),
            DtnError::NodeNotFound(id) => {
                write!(f, "Node {} not registered in contact topology", id)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bundle Protocol v7 (BPv7) Structures (RFC 9171)
// ---------------------------------------------------------------------------

/// Bundle Quality-of-Service (QoS) Priority Class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BundlePriority {
    /// Bulk background traffic (file transfers, firmware updates, non-urgent logs).
    Bulk = 0,
    /// Normal interactive user plane traffic (sensors, messaging, periodic reports).
    Normal = 1,
    /// Urgent emergency and safety signaling (disaster alerts, SOS, mission-critical control).
    Urgent = 2,
}

impl BundlePriority {
    pub fn from_u8(val: u8) -> Result<Self, DtnError> {
        match val {
            0 => Ok(BundlePriority::Bulk),
            1 => Ok(BundlePriority::Normal),
            2 => Ok(BundlePriority::Urgent),
            _ => Err(DtnError::InvalidPriority(val)),
        }
    }
}

/// Endpoint Identifier (EID) per RFC 9171 (e.g. `ipn:101.1` or `dtn:gateway/gw-1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EndpointId {
    pub scheme: String,
    pub ssp: String, // Scheme Specific Part
}

impl EndpointId {
    pub fn new(scheme: &str, ssp: &str) -> Self {
        Self {
            scheme: scheme.to_string(),
            ssp: ssp.to_string(),
        }
    }

    pub fn ipn(node_number: u32, service_number: u32) -> Self {
        Self {
            scheme: "ipn".to_string(),
            ssp: format!("{}.{}", node_number, service_number),
        }
    }

    pub fn dtn(uri_path: &str) -> Self {
        Self {
            scheme: "dtn".to_string(),
            ssp: uri_path.to_string(),
        }
    }

    pub fn to_uri(&self) -> String {
        format!("{}:{}", self.scheme, self.ssp)
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.scheme, self.ssp)
    }
}

/// Bundle Protocol Processing Control Flags (RFC 9171 §4.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BundleControlFlags {
    /// Bundle is a fragment.
    pub is_fragment: bool,
    /// Payload is administrative record (e.g. Custody Signal).
    pub is_admin_record: bool,
    /// Bundle must not be fragmented.
    pub do_not_fragment: bool,
    /// Custody transfer requested (sender retains copy until acknowledged).
    pub custody_requested: bool,
    /// Return receipt / status report requested upon delivery to destination.
    pub report_delivery: bool,
}

impl BundleControlFlags {
    pub fn to_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.is_fragment {
            bits |= 1 << 0;
        }
        if self.is_admin_record {
            bits |= 1 << 1;
        }
        if self.do_not_fragment {
            bits |= 1 << 2;
        }
        if self.custody_requested {
            bits |= 1 << 3;
        }
        if self.report_delivery {
            bits |= 1 << 4;
        }
        bits
    }

    pub fn from_bits(bits: u8) -> Self {
        Self {
            is_fragment: (bits & (1 << 0)) != 0,
            is_admin_record: (bits & (1 << 1)) != 0,
            do_not_fragment: (bits & (1 << 2)) != 0,
            custody_requested: (bits & (1 << 3)) != 0,
            report_delivery: (bits & (1 << 4)) != 0,
        }
    }
}

/// Bundle Protocol Version 7 Data Unit.
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    /// Unique bundle sequence identifier.
    pub bundle_id: u64,
    /// Source endpoint identifier.
    pub source_eid: EndpointId,
    /// Destination endpoint identifier.
    pub destination_eid: EndpointId,
    /// Report-to endpoint identifier for custody signals.
    pub report_to_eid: EndpointId,
    /// Bundle creation timestamp in milliseconds.
    pub creation_timestamp_ms: u64,
    /// Lifetime / Time-To-Live (TTL) in milliseconds.
    pub lifetime_ttl_ms: u64,
    /// Priority level for queuing and store-and-forward scheduling.
    pub priority: BundlePriority,
    /// Processing control flags.
    pub flags: BundleControlFlags,
    /// Payload byte content.
    pub payload: Vec<u8>,
    /// Whether custody has been accepted by a downstream custodian.
    pub custody_acknowledged: bool,
}

impl Bundle {
    pub fn new(
        bundle_id: u64,
        source_eid: EndpointId,
        destination_eid: EndpointId,
        creation_timestamp_ms: u64,
        lifetime_ttl_ms: u64,
        priority: BundlePriority,
        payload: Vec<u8>,
    ) -> Self {
        let report_to_eid = source_eid.clone();
        Self {
            bundle_id,
            source_eid,
            destination_eid,
            report_to_eid,
            creation_timestamp_ms,
            lifetime_ttl_ms,
            priority,
            flags: BundleControlFlags::default(),
            payload,
            custody_acknowledged: false,
        }
    }

    pub fn with_custody_transfer(mut self, enabled: bool) -> Self {
        self.flags.custody_requested = enabled;
        self
    }

    /// Size in bytes of this bundle including metadata and payload.
    pub fn wire_size_bytes(&self) -> usize {
        // Header overhead (~48 bytes) + Source/Dest EID strings + payload
        48 + self.source_eid.to_uri().len()
            + self.destination_eid.to_uri().len()
            + self.payload.len()
    }

    /// Checks whether the bundle has exceeded its lifetime relative to `current_time_ms`.
    pub fn is_expired(&self, current_time_ms: u64) -> bool {
        if current_time_ms < self.creation_timestamp_ms {
            false
        } else {
            (current_time_ms - self.creation_timestamp_ms) >= self.lifetime_ttl_ms
        }
    }

    /// Calculates remaining time-to-live in milliseconds.
    pub fn remaining_ttl_ms(&self, current_time_ms: u64) -> u64 {
        let age = current_time_ms.saturating_sub(self.creation_timestamp_ms);
        self.lifetime_ttl_ms.saturating_sub(age)
    }

    /// Encodes the bundle into a wire format binary frame with CRC-16 checksum.
    pub fn encode_wire(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic header: 0x33, 0x47 ("3G"), Version 7 (0x07)
        buf.push(0x33);
        buf.push(0x47);
        buf.push(0x07);

        // Bundle ID (8 bytes big-endian)
        buf.extend_from_slice(&self.bundle_id.to_be_bytes());

        // Creation timestamp (8 bytes) & Lifetime TTL (8 bytes)
        buf.extend_from_slice(&self.creation_timestamp_ms.to_be_bytes());
        buf.extend_from_slice(&self.lifetime_ttl_ms.to_be_bytes());

        // Priority & Flags (2 bytes)
        buf.push(self.priority as u8);
        buf.push(self.flags.to_bits());

        // Source EID string length & bytes
        let src_bytes = self.source_eid.to_uri().into_bytes();
        buf.extend_from_slice(&(src_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&src_bytes);

        // Destination EID string length & bytes
        let dst_bytes = self.destination_eid.to_uri().into_bytes();
        buf.extend_from_slice(&(dst_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&dst_bytes);

        // Payload length & content
        buf.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.payload);

        // Compute CRC-16 over entire buffer so far
        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());

        buf
    }

    /// Decodes a bundle from a binary wire frame, verifying CRC-16 integrity.
    pub fn decode_wire(data: &[u8]) -> Result<Self, DtnError> {
        if data.len() < 35 {
            return Err(DtnError::DeserializationError(
                "Data too short for DTN bundle header".into(),
            ));
        }

        // Verify CRC-16
        let payload_len = data.len() - 2;
        let expected_crc = u16::from_be_bytes([data[payload_len], data[payload_len + 1]]);
        let calculated_crc = compute_crc16(&data[..payload_len]);
        if expected_crc != calculated_crc {
            return Err(DtnError::ChecksumMismatch {
                expected: expected_crc,
                calculated: calculated_crc,
            });
        }

        // Check magic
        if data[0] != 0x33 || data[1] != 0x47 || data[2] != 0x07 {
            return Err(DtnError::DeserializationError(
                "Invalid BPv7 magic identifier".into(),
            ));
        }

        let mut offset = 3;
        let bundle_id = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let creation_timestamp_ms =
            u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let lifetime_ttl_ms = u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;

        let priority = BundlePriority::from_u8(data[offset])?;
        offset += 1;

        let flags = BundleControlFlags::from_bits(data[offset]);
        offset += 1;

        // Source EID
        let src_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let src_str = String::from_utf8(data[offset..offset + src_len].to_vec())
            .map_err(|e| DtnError::DeserializationError(format!("Invalid Source EID: {}", e)))?;
        offset += src_len;

        // Destination EID
        let dst_len = u16::from_be_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        offset += 2;
        let dst_str = String::from_utf8(data[offset..offset + dst_len].to_vec()).map_err(|e| {
            DtnError::DeserializationError(format!("Invalid Destination EID: {}", e))
        })?;
        offset += dst_len;

        // Payload
        let pld_len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let payload = data[offset..offset + pld_len].to_vec();

        let source_eid = parse_eid(&src_str)?;
        let destination_eid = parse_eid(&dst_str)?;
        let report_to_eid = source_eid.clone();

        Ok(Self {
            bundle_id,
            source_eid,
            destination_eid,
            report_to_eid,
            creation_timestamp_ms,
            lifetime_ttl_ms,
            priority,
            flags,
            payload,
            custody_acknowledged: false,
        })
    }
}

fn parse_eid(s: &str) -> Result<EndpointId, DtnError> {
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(DtnError::InvalidEid(format!(
            "Missing scheme colon in {}",
            s
        )));
    }
    Ok(EndpointId::new(parts[0], parts[1]))
}

// ---------------------------------------------------------------------------
// Satellite Contact Window & Orbital Pass Model
// ---------------------------------------------------------------------------

/// Dynamic orbital contact window between two DTN nodes (e.g. Satellite and Ground Station).
#[derive(Debug, Clone, PartialEq)]
pub struct ContactWindow {
    /// Contact Window Identifier.
    pub window_id: u32,
    /// Peer Node ID (Satellite or Earth Gateway ID).
    pub peer_node_id: u32,
    /// Acquisition of Signal (AOS) time in milliseconds.
    pub start_time_ms: u64,
    /// Loss of Signal (LOS) time in milliseconds.
    pub end_time_ms: u64,
    /// Maximum elevation angle achieved at culmination in degrees (e.g. 75.0°).
    pub max_elevation_deg: f64,
    /// Nominal transmission data rate in bits per second (bps).
    pub nominal_rate_bps: u64,
}

impl ContactWindow {
    pub fn new(
        window_id: u32,
        peer_node_id: u32,
        start_time_ms: u64,
        end_time_ms: u64,
        max_elevation_deg: f64,
        nominal_rate_bps: u64,
    ) -> Self {
        Self {
            window_id,
            peer_node_id,
            start_time_ms,
            end_time_ms,
            max_elevation_deg,
            nominal_rate_bps,
        }
    }

    /// Duration of the contact window in milliseconds.
    pub fn duration_ms(&self) -> u64 {
        self.end_time_ms.saturating_sub(self.start_time_ms)
    }

    /// Checks whether the contact window is active at `current_time_ms`.
    pub fn is_active(&self, current_time_ms: u64) -> bool {
        current_time_ms >= self.start_time_ms && current_time_ms < self.end_time_ms
    }

    /// Computes instantaneous data rate based on current elevation angle trajectory.
    ///
    /// The elevation follows an inverted parabolic approximation from AOS (10°) to max_elevation
    /// down to LOS (10°).
    pub fn instantaneous_rate_bps(&self, current_time_ms: u64) -> u64 {
        if !self.is_active(current_time_ms) {
            return 0;
        }
        let progress = (current_time_ms - self.start_time_ms) as f64 / self.duration_ms() as f64;
        // Peak at progress = 0.5
        let factor = 1.0 - 4.0 * (progress - 0.5) * (progress - 0.5);
        let elev = DEFAULT_ELEVATION_MASK_DEG
            + (self.max_elevation_deg - DEFAULT_ELEVATION_MASK_DEG) * factor.max(0.0);

        // Rate adaptation per elevation bands
        if elev >= 60.0 {
            self.nominal_rate_bps
        } else if elev >= 30.0 {
            (self.nominal_rate_bps as f64 * 0.70) as u64
        } else if elev >= DEFAULT_ELEVATION_MASK_DEG {
            (self.nominal_rate_bps as f64 * 0.35) as u64
        } else {
            0
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-Priority Store-and-Forward Buffer
// ---------------------------------------------------------------------------

/// Priority-based storage buffer enforcing capacity constraints, TTL expiry, and custody.
#[derive(Debug, Clone)]
pub struct DtnStorageBuffer {
    capacity_bytes: usize,
    max_bundle_count: usize,
    current_bytes: usize,
    urgent_queue: VecDeque<Bundle>,
    normal_queue: VecDeque<Bundle>,
    bulk_queue: VecDeque<Bundle>,
}

impl DtnStorageBuffer {
    pub fn new(capacity_bytes: usize, max_bundle_count: usize) -> Self {
        Self {
            capacity_bytes,
            max_bundle_count,
            current_bytes: 0,
            urgent_queue: VecDeque::new(),
            normal_queue: VecDeque::new(),
            bulk_queue: VecDeque::new(),
        }
    }

    /// Total number of stored bundles across all priority queues.
    pub fn total_bundle_count(&self) -> usize {
        self.urgent_queue.len() + self.normal_queue.len() + self.bulk_queue.len()
    }

    /// Total storage occupied in bytes.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Storage utilization percentage (0.0% to 100.0%).
    pub fn storage_utilization_pct(&self) -> f64 {
        if self.capacity_bytes == 0 {
            0.0
        } else {
            (self.current_bytes as f64 / self.capacity_bytes as f64) * 100.0
        }
    }

    /// Inserts a bundle into the appropriate priority queue, evicting low-priority traffic if full.
    pub fn store_bundle(&mut self, bundle: Bundle, current_time_ms: u64) -> Result<(), DtnError> {
        let size = bundle.wire_size_bytes();

        if bundle.is_expired(current_time_ms) {
            return Err(DtnError::BundleExpired {
                bundle_id: bundle.bundle_id,
                age_ms: current_time_ms.saturating_sub(bundle.creation_timestamp_ms),
                ttl_ms: bundle.lifetime_ttl_ms,
            });
        }

        // Evict expired bundles first across all queues
        self.purge_expired_bundles(current_time_ms);

        // If still over capacity, proactively evict lowest-priority bundles (Bulk first, then Normal)
        while (self.current_bytes + size > self.capacity_bytes
            || self.total_bundle_count() >= self.max_bundle_count)
            && !self.bulk_queue.is_empty()
        {
            if let Some(evicted) = self.bulk_queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(evicted.wire_size_bytes());
            }
        }

        while (self.current_bytes + size > self.capacity_bytes
            || self.total_bundle_count() >= self.max_bundle_count)
            && !self.normal_queue.is_empty()
            && bundle.priority == BundlePriority::Urgent
        {
            if let Some(evicted) = self.normal_queue.pop_front() {
                self.current_bytes = self.current_bytes.saturating_sub(evicted.wire_size_bytes());
            }
        }

        if self.current_bytes + size > self.capacity_bytes
            || self.total_bundle_count() >= self.max_bundle_count
        {
            return Err(DtnError::BufferFull {
                current_bytes: self.current_bytes,
                capacity_bytes: self.capacity_bytes,
            });
        }

        self.current_bytes += size;
        match bundle.priority {
            BundlePriority::Urgent => self.urgent_queue.push_back(bundle),
            BundlePriority::Normal => self.normal_queue.push_back(bundle),
            BundlePriority::Bulk => self.bulk_queue.push_back(bundle),
        }

        Ok(())
    }

    /// Purges all expired bundles across all queues, returning the count of purged bundles.
    pub fn purge_expired_bundles(&mut self, current_time_ms: u64) -> usize {
        let mut purged_count = 0;

        let mut purge_queue = |q: &mut VecDeque<Bundle>, current_bytes: &mut usize| {
            let mut retained = VecDeque::new();
            while let Some(b) = q.pop_front() {
                if b.is_expired(current_time_ms) {
                    *current_bytes = current_bytes.saturating_sub(b.wire_size_bytes());
                    purged_count += 1;
                } else {
                    retained.push_back(b);
                }
            }
            *q = retained;
        };

        purge_queue(&mut self.urgent_queue, &mut self.current_bytes);
        purge_queue(&mut self.normal_queue, &mut self.current_bytes);
        purge_queue(&mut self.bulk_queue, &mut self.current_bytes);

        purged_count
    }

    /// Pops the next highest-priority bundle ready for transmission.
    pub fn pop_next_bundle(&mut self) -> Option<Bundle> {
        if let Some(b) = self.urgent_queue.pop_front() {
            self.current_bytes = self.current_bytes.saturating_sub(b.wire_size_bytes());
            Some(b)
        } else if let Some(b) = self.normal_queue.pop_front() {
            self.current_bytes = self.current_bytes.saturating_sub(b.wire_size_bytes());
            Some(b)
        } else if let Some(b) = self.bulk_queue.pop_front() {
            self.current_bytes = self.current_bytes.saturating_sub(b.wire_size_bytes());
            Some(b)
        } else {
            None
        }
    }

    /// Peeks at the next highest-priority bundle without removing it.
    pub fn peek_next_bundle(&self) -> Option<&Bundle> {
        self.urgent_queue
            .front()
            .or_else(|| self.normal_queue.front())
            .or_else(|| self.bulk_queue.front())
    }
}

// ---------------------------------------------------------------------------
// Discontinuous NTN Engine Telemetry
// ---------------------------------------------------------------------------

/// Performance metrics and link analytics for discontinuous satellite DTN operation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NtnDtnTelemetry {
    pub total_bundles_ingested: u64,
    pub total_bundles_forwarded: u64,
    pub total_bundles_delivered: u64,
    pub total_bundles_expired: u64,
    pub total_bundles_dropped_overflow: u64,
    pub total_bytes_transmitted: u64,
    pub total_contact_duration_ms: u64,
    pub active_transmission_time_ms: u64,
    pub total_dwell_latency_ms: u64,
    pub max_dwell_latency_ms: u64,
}

impl NtnDtnTelemetry {
    /// Packet Delivery Ratio (PDR) in percentage.
    pub fn packet_delivery_ratio(&self) -> f64 {
        if self.total_bundles_ingested == 0 {
            0.0
        } else {
            (self.total_bundles_delivered as f64 / self.total_bundles_ingested as f64) * 100.0
        }
    }

    /// Contact Window Transmission Duty Cycle / Utilization Efficiency.
    pub fn contact_utilization_pct(&self) -> f64 {
        if self.total_contact_duration_ms == 0 {
            0.0
        } else {
            (self.active_transmission_time_ms as f64 / self.total_contact_duration_ms as f64)
                * 100.0
        }
    }

    /// Average storage dwell latency in milliseconds before bundle forwarding.
    pub fn average_dwell_latency_ms(&self) -> f64 {
        if self.total_bundles_forwarded == 0 {
            0.0
        } else {
            self.total_dwell_latency_ms as f64 / self.total_bundles_forwarded as f64
        }
    }
}

// ---------------------------------------------------------------------------
// NTN Store-and-Forward Engine
// ---------------------------------------------------------------------------

/// Central NTN Store-and-Forward Engine coordinating contact windows and bundle forwarding.
pub struct NtnDtnEngine {
    node_id: u32,
    local_eid: EndpointId,
    storage: DtnStorageBuffer,
    contact_schedule: HashMap<u32, Vec<ContactWindow>>,
    current_time_ms: u64,
    telemetry: NtnDtnTelemetry,
    next_bundle_id: u64,
}

impl NtnDtnEngine {
    /// Creates a new NTN DTN Engine for a specific satellite or ground station node.
    pub fn new(node_id: u32, local_eid: EndpointId) -> Self {
        Self {
            node_id,
            local_eid,
            storage: DtnStorageBuffer::new(
                DEFAULT_STORAGE_CAPACITY_BYTES,
                DEFAULT_MAX_BUNDLE_COUNT,
            ),
            contact_schedule: HashMap::new(),
            current_time_ms: 0,
            telemetry: NtnDtnTelemetry::default(),
            next_bundle_id: 1,
        }
    }

    pub fn with_storage_limits(mut self, capacity_bytes: usize, max_bundles: usize) -> Self {
        self.storage = DtnStorageBuffer::new(capacity_bytes, max_bundles);
        self
    }

    pub fn node_id(&self) -> u32 {
        self.node_id
    }

    pub fn local_eid(&self) -> &EndpointId {
        &self.local_eid
    }

    pub fn current_time_ms(&self) -> u64 {
        self.current_time_ms
    }

    pub fn telemetry(&self) -> &NtnDtnTelemetry {
        &self.telemetry
    }

    pub fn storage(&self) -> &DtnStorageBuffer {
        &self.storage
    }

    // -----------------------------------------------------------------------
    // Contact Schedule Management
    // -----------------------------------------------------------------------

    /// Registers a scheduled orbital contact window with a peer node.
    pub fn add_contact_window(&mut self, window: ContactWindow) {
        let peer = window.peer_node_id;
        self.telemetry.total_contact_duration_ms += window.duration_ms();
        self.contact_schedule.entry(peer).or_default().push(window);
    }

    /// Finds an active contact window with `peer_node_id` at current simulation time.
    pub fn get_active_contact_window(&self, peer_node_id: u32) -> Option<&ContactWindow> {
        if let Some(windows) = self.contact_schedule.get(&peer_node_id) {
            windows.iter().find(|w| w.is_active(self.current_time_ms))
        } else {
            None
        }
    }

    // -----------------------------------------------------------------------
    // Ingestion & Custody Storage
    // -----------------------------------------------------------------------

    /// Ingests a new locally-generated bundle into storage.
    pub fn create_and_store_bundle(
        &mut self,
        destination_eid: EndpointId,
        priority: BundlePriority,
        lifetime_ttl_ms: u64,
        payload: Vec<u8>,
    ) -> Result<u64, DtnError> {
        let id = self.next_bundle_id;
        self.next_bundle_id += 1;

        let bundle = Bundle::new(
            id,
            self.local_eid.clone(),
            destination_eid,
            self.current_time_ms,
            lifetime_ttl_ms,
            priority,
            payload,
        );

        self.telemetry.total_bundles_ingested += 1;
        self.storage.store_bundle(bundle, self.current_time_ms)?;
        Ok(id)
    }

    /// Receives a bundle from an ingress radio link and stores it.
    pub fn receive_bundle(&mut self, bundle: Bundle) -> Result<(), DtnError> {
        self.telemetry.total_bundles_ingested += 1;
        // Check if bundle is addressed directly to this node
        if bundle.destination_eid == self.local_eid {
            self.telemetry.total_bundles_delivered += 1;
            return Ok(());
        }

        self.storage.store_bundle(bundle, self.current_time_ms)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Contact Window Forwarding & Burst Transmission
    // -----------------------------------------------------------------------

    /// Attempts to forward stored bundles to `peer_node_id` over the active contact window.
    ///
    /// Transmits as many bundles as allowed by the instantaneous data rate and available duration.
    /// Returns the list of successfully transmitted bundles.
    pub fn transmit_burst(
        &mut self,
        peer_node_id: u32,
        duration_slice_ms: u64,
    ) -> Result<Vec<Bundle>, DtnError> {
        let rate_bps = {
            let win = self.get_active_contact_window(peer_node_id).ok_or(
                DtnError::ContactWindowClosed {
                    satellite_id: peer_node_id,
                    current_time_ms: self.current_time_ms,
                },
            )?;
            win.instantaneous_rate_bps(self.current_time_ms)
        };

        if rate_bps == 0 {
            return Ok(Vec::new());
        }

        // Available bytes budget for this duration slice
        let mut available_bytes =
            ((rate_bps as f64 * (duration_slice_ms as f64 / 1000.0)) / 8.0) as usize;
        let mut transmitted = Vec::new();

        while available_bytes > 0 {
            // Peek next bundle to see if it fits
            if let Some(next) = self.storage.peek_next_bundle() {
                let wire_len = next.wire_size_bytes();
                if wire_len <= available_bytes {
                    let mut b = self.storage.pop_next_bundle().unwrap();
                    available_bytes -= wire_len;
                    self.telemetry.total_bytes_transmitted += wire_len as u64;
                    self.telemetry.total_bundles_forwarded += 1;

                    let dwell = self.current_time_ms.saturating_sub(b.creation_timestamp_ms);
                    self.telemetry.total_dwell_latency_ms += dwell;
                    if dwell > self.telemetry.max_dwell_latency_ms {
                        self.telemetry.max_dwell_latency_ms = dwell;
                    }

                    b.custody_acknowledged = true;
                    transmitted.push(b);
                } else {
                    // Current bundle cannot fit in this time slice
                    break;
                }
            } else {
                // Buffer is empty
                break;
            }
        }

        if !transmitted.is_empty() {
            self.telemetry.active_transmission_time_ms += duration_slice_ms;
        }

        Ok(transmitted)
    }

    // -----------------------------------------------------------------------
    // Simulation Clock Advancement
    // -----------------------------------------------------------------------

    /// Advances simulation time by `delta_ms`, expiring bundles and tracking statistics.
    pub fn advance_time_ms(&mut self, delta_ms: u64) {
        self.current_time_ms += delta_ms;
        let expired = self.storage.purge_expired_bundles(self.current_time_ms);
        self.telemetry.total_bundles_expired += expired as u64;
    }
}
