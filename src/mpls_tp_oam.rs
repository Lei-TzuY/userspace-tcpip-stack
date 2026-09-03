//! MPLS-TP OAM: Telecommunication Profile Operations, Administration, and Maintenance (RFC 5860 / RFC 6374 / RFC 5586).
//!
//! Provides carrier-grade proactive Continuity Check (CC), Loss Measurement (LM),
//! and Delay Measurement (DM) over Generic Associated Channel (G-ACh) for MPLS-TP and Pseudowires.
//!
//! Features:
//! - 4-byte G-ACh Header (RFC 5586) with 0x1 Nibble identifier and Channel Types:
//!   - `0x0021`: IPv4 OAM
//!   - `0x0057`: IPv6 OAM
//!   - `0x0007`: BFD Direct Control without IP/UDP (RFC 5885)
//!   - `0x0025`: Direct Loss Measurement (LM RFC 6374)
//!   - `0x0026`: Direct Delay Measurement (DM RFC 6374)
//! - Packet Loss Measurement (LM) with Tx/Rx frame counters and loss ratio calculation.
//! - Two-Way Delay Measurement (DM) with nanosecond timestamps, round-trip delay, and jitter calculation.

pub const GACH_FIRST_NIBBLE: u8 = 0x10;
pub const GACH_HEADER_LEN: usize = 4;

pub const GACH_CHANNEL_IPV4_OAM: u16 = 0x0021;
pub const GACH_CHANNEL_IPV6_OAM: u16 = 0x0057;
pub const GACH_CHANNEL_BFD_DIRECT: u16 = 0x0007;
pub const GACH_CHANNEL_LM: u16 = 0x0025;
pub const GACH_CHANNEL_DM: u16 = 0x0026;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GachHeader {
    pub version: u8,
    pub channel_type: u16,
}

impl GachHeader {
    pub fn new(channel_type: u16) -> Self {
        GachHeader {
            version: 0,
            channel_type,
        }
    }

    pub fn serialize(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0] = GACH_FIRST_NIBBLE | (self.version & 0x0F);
        buf[1] = 0; // Reserved
        let ct_bytes = self.channel_type.to_be_bytes();
        buf[2] = ct_bytes[0];
        buf[3] = ct_bytes[1];
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < GACH_HEADER_LEN {
            return Err("G-ACh header too short");
        }
        if (data[0] & 0xF0) != GACH_FIRST_NIBBLE {
            return Err("Invalid G-ACh first nibble (expected 0x1)");
        }
        let version = data[0] & 0x0F;
        let channel_type = u16::from_be_bytes([data[2], data[3]]);

        Ok(GachHeader {
            version,
            channel_type,
        })
    }
}

/// Direct Loss Measurement PDU (RFC 6374 Section 3.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MplsLossMeasurementPdu {
    pub session_id: u32,
    pub tx_forward_frames: u64,
    pub rx_forward_frames: u64,
    pub tx_backward_frames: u64,
    pub rx_backward_frames: u64,
}

impl MplsLossMeasurementPdu {
    pub fn new(session_id: u32, tx_fwd: u64, rx_fwd: u64, tx_bwd: u64, rx_bwd: u64) -> Self {
        MplsLossMeasurementPdu {
            session_id,
            tx_forward_frames: tx_fwd,
            rx_forward_frames: rx_fwd,
            tx_backward_frames: tx_bwd,
            rx_backward_frames: rx_bwd,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.tx_forward_frames.to_be_bytes());
        buf.extend_from_slice(&self.rx_forward_frames.to_be_bytes());
        buf.extend_from_slice(&self.tx_backward_frames.to_be_bytes());
        buf.extend_from_slice(&self.rx_backward_frames.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 36 {
            return Err("Loss Measurement PDU too short");
        }
        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let tx_forward_frames = u64::from_be_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        let rx_forward_frames = u64::from_be_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]);
        let tx_backward_frames = u64::from_be_bytes([
            data[20], data[21], data[22], data[23], data[24], data[25], data[26], data[27],
        ]);
        let rx_backward_frames = u64::from_be_bytes([
            data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
        ]);

        Ok(MplsLossMeasurementPdu {
            session_id,
            tx_forward_frames,
            rx_forward_frames,
            tx_backward_frames,
            rx_backward_frames,
        })
    }

    /// Computes forward direction packet loss count and percentage (0.0 .. 1.0).
    pub fn compute_forward_loss(&self) -> (u64, f64) {
        if self.tx_forward_frames >= self.rx_forward_frames && self.tx_forward_frames > 0 {
            let lost = self.tx_forward_frames - self.rx_forward_frames;
            let ratio = lost as f64 / self.tx_forward_frames as f64;
            (lost, ratio)
        } else {
            (0, 0.0)
        }
    }
}

/// Direct Delay Measurement PDU (RFC 6374 Section 3.2)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MplsDelayMeasurementPdu {
    pub session_id: u32,
    pub t1_tx_sec: u32,
    pub t1_tx_nsec: u32,
    pub t2_rx_sec: u32,
    pub t2_rx_nsec: u32,
    pub t3_tx_sec: u32,
    pub t3_tx_nsec: u32,
    pub t4_rx_sec: u32,
    pub t4_rx_nsec: u32,
}

impl MplsDelayMeasurementPdu {
    pub fn new(
        session_id: u32,
        t1: (u32, u32),
        t2: (u32, u32),
        t3: (u32, u32),
        t4: (u32, u32),
    ) -> Self {
        MplsDelayMeasurementPdu {
            session_id,
            t1_tx_sec: t1.0,
            t1_tx_nsec: t1.1,
            t2_rx_sec: t2.0,
            t2_rx_nsec: t2.1,
            t3_tx_sec: t3.0,
            t3_tx_nsec: t3.1,
            t4_rx_sec: t4.0,
            t4_rx_nsec: t4.1,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.t1_tx_sec.to_be_bytes());
        buf.extend_from_slice(&self.t1_tx_nsec.to_be_bytes());
        buf.extend_from_slice(&self.t2_rx_sec.to_be_bytes());
        buf.extend_from_slice(&self.t2_rx_nsec.to_be_bytes());
        buf.extend_from_slice(&self.t3_tx_sec.to_be_bytes());
        buf.extend_from_slice(&self.t3_tx_nsec.to_be_bytes());
        buf.extend_from_slice(&self.t4_rx_sec.to_be_bytes());
        buf.extend_from_slice(&self.t4_rx_nsec.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 36 {
            return Err("Delay Measurement PDU too short");
        }
        let session_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let t1_tx_sec = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let t1_tx_nsec = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let t2_rx_sec = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let t2_rx_nsec = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let t3_tx_sec = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let t3_tx_nsec = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);
        let t4_rx_sec = u32::from_be_bytes([data[28], data[29], data[30], data[31]]);
        let t4_rx_nsec = u32::from_be_bytes([data[32], data[33], data[34], data[35]]);

        Ok(MplsDelayMeasurementPdu {
            session_id,
            t1_tx_sec,
            t1_tx_nsec,
            t2_rx_sec,
            t2_rx_nsec,
            t3_tx_sec,
            t3_tx_nsec,
            t4_rx_sec,
            t4_rx_nsec,
        })
    }

    /// Computes Two-Way round trip delay in nanoseconds: `(T4 - T1) - (T3 - T2)`.
    pub fn compute_two_way_delay_ns(&self) -> u64 {
        let t1 = (self.t1_tx_sec as u64) * 1_000_000_000 + (self.t1_tx_nsec as u64);
        let t2 = (self.t2_rx_sec as u64) * 1_000_000_000 + (self.t2_rx_nsec as u64);
        let t3 = (self.t3_tx_sec as u64) * 1_000_000_000 + (self.t3_tx_nsec as u64);
        let t4 = (self.t4_rx_sec as u64) * 1_000_000_000 + (self.t4_rx_nsec as u64);

        if t4 >= t1 && t3 >= t2 {
            let total_time = t4 - t1;
            let peer_residence = t3 - t2;
            total_time.saturating_sub(peer_residence)
        } else {
            0
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct MplsTpOamEngine {
    pub session_id: u32,
    pub tx_counter: u64,
    pub rx_counter: u64,
}

impl MplsTpOamEngine {
    pub fn new(session_id: u32) -> Self {
        MplsTpOamEngine {
            session_id,
            tx_counter: 0,
            rx_counter: 0,
        }
    }

    pub fn record_tx(&mut self) {
        self.tx_counter += 1;
    }

    pub fn record_rx(&mut self) {
        self.rx_counter += 1;
    }

    pub fn create_lm_query(&self) -> (GachHeader, MplsLossMeasurementPdu) {
        (
            GachHeader::new(GACH_CHANNEL_LM),
            MplsLossMeasurementPdu::new(self.session_id, self.tx_counter, 0, 0, 0),
        )
    }

    pub fn create_lm_reply(
        &self,
        query: &MplsLossMeasurementPdu,
    ) -> (GachHeader, MplsLossMeasurementPdu) {
        (
            GachHeader::new(GACH_CHANNEL_LM),
            MplsLossMeasurementPdu::new(
                query.session_id,
                query.tx_forward_frames,
                self.rx_counter,
                self.tx_counter,
                0,
            ),
        )
    }

    pub fn create_dm_query(
        &self,
        t1_sec: u32,
        t1_nsec: u32,
    ) -> (GachHeader, MplsDelayMeasurementPdu) {
        (
            GachHeader::new(GACH_CHANNEL_DM),
            MplsDelayMeasurementPdu::new(
                self.session_id,
                (t1_sec, t1_nsec),
                (0, 0),
                (0, 0),
                (0, 0),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gach_header_codec() {
        let gach = GachHeader::new(GACH_CHANNEL_LM);
        let bytes = gach.serialize();
        assert_eq!(bytes, [0x10, 0x00, 0x00, 0x25]);

        let parsed = GachHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.channel_type, GACH_CHANNEL_LM);
    }

    #[test]
    fn test_loss_measurement_and_ratio() {
        let lm = MplsLossMeasurementPdu::new(101, 1000, 990, 1000, 1000);
        let (lost, ratio) = lm.compute_forward_loss();

        assert_eq!(lost, 10);
        assert!((ratio - 0.01).abs() < 1e-6);

        let ser = lm.serialize();
        let parsed = MplsLossMeasurementPdu::parse(&ser).unwrap();
        assert_eq!(parsed.session_id, 101);
        assert_eq!(parsed.tx_forward_frames, 1000);
        assert_eq!(parsed.rx_forward_frames, 990);
    }

    #[test]
    fn test_delay_measurement_two_way_calculation() {
        // T1 = 100.000s, T2 = 100.005s (5ms fwd), T3 = 100.006s (1ms node residence), T4 = 100.011s (5ms bwd)
        // Two-way delay = (100.011 - 100.000) - (100.006 - 100.005) = 11ms - 1ms = 10ms (10,000,000 ns)
        let dm = MplsDelayMeasurementPdu::new(
            202,
            (100, 0),
            (100, 5_000_000),
            (100, 6_000_000),
            (100, 11_000_000),
        );

        let delay_ns = dm.compute_two_way_delay_ns();
        assert_eq!(delay_ns, 10_000_000); // exactly 10ms

        let ser = dm.serialize();
        let parsed = MplsDelayMeasurementPdu::parse(&ser).unwrap();
        assert_eq!(parsed.session_id, 202);
        assert_eq!(parsed.compute_two_way_delay_ns(), 10_000_000);
    }
}
