//! IEEE 1588-2019 / IEEE 802.1AS-2020 High-Accuracy (HA) Profile and Sub-Nanosecond Asymmetry Correction.
//!
//! Provides picosecond-level time synchronization calculations, delay asymmetry calibration,
//! and High-Accuracy (HA) TLV encoding.

pub const PTP_TLV_ORGANIZATION_EXTENSION: u16 = 0x0003;
pub const PTP_TLV_HIGH_ACCURACY_DELAY_ASYM: u16 = 0x2001;

/// High-precision timestamp measured in picoseconds (1 ps = 10^-12 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct HighPrecisionTimestamp {
    /// Whole seconds
    pub seconds: u64,
    /// Picoseconds within the second (0 .. 999_999_999_999)
    pub picoseconds: u64,
}

impl HighPrecisionTimestamp {
    pub const PICOSECONDS_PER_SECOND: u64 = 1_000_000_000_000;
    pub const PICOSECONDS_PER_NANOSECOND: u64 = 1_000;

    pub fn new(seconds: u64, picoseconds: u64) -> Self {
        let extra_sec = picoseconds / Self::PICOSECONDS_PER_SECOND;
        let rem_ps = picoseconds % Self::PICOSECONDS_PER_SECOND;
        Self {
            seconds: seconds + extra_sec,
            picoseconds: rem_ps,
        }
    }

    pub fn from_nanoseconds(seconds: u64, nanoseconds: u32) -> Self {
        Self {
            seconds,
            picoseconds: (nanoseconds as u64) * Self::PICOSECONDS_PER_NANOSECOND,
        }
    }

    /// Converts total time to total signed picoseconds (`i128`).
    pub fn to_total_picoseconds(&self) -> i128 {
        (self.seconds as i128) * (Self::PICOSECONDS_PER_SECOND as i128) + (self.picoseconds as i128)
    }

    /// Creates a HighPrecisionTimestamp from total signed picoseconds (`i128`).
    pub fn from_total_picoseconds(total_ps: i128) -> Option<Self> {
        if total_ps < 0 {
            return None;
        }
        let sec = (total_ps / (Self::PICOSECONDS_PER_SECOND as i128)) as u64;
        let ps = (total_ps % (Self::PICOSECONDS_PER_SECOND as i128)) as u64;
        Some(Self {
            seconds: sec,
            picoseconds: ps,
        })
    }
}

/// Delay Asymmetry TLV for High-Accuracy PTP (IEEE 1588-2019 §14.8.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtpDelayAsymmetryTlv {
    pub tlv_type: u16,
    pub length_field: u16,
    /// Delay asymmetry in scaled nanoseconds (scaled by 2^16).
    /// Positive value means master-to-slave delay > slave-to-master delay.
    pub delay_asymmetry_scaled_ns: i64,
}

impl PtpDelayAsymmetryTlv {
    pub fn new(delay_asymmetry_scaled_ns: i64) -> Self {
        Self {
            tlv_type: PTP_TLV_HIGH_ACCURACY_DELAY_ASYM,
            length_field: 8,
            delay_asymmetry_scaled_ns,
        }
    }

    /// Creates a TLV directly from delay asymmetry in picoseconds with rounding.
    pub fn from_picoseconds(asym_ps: i64) -> Self {
        // 1 ns = 1000 ps. scaled_ns = (ps * 65536) / 1000
        let numerator = asym_ps as i128 * 65536;
        let scaled_ns = if numerator >= 0 {
            (numerator + 500) / 1000
        } else {
            (numerator - 500) / 1000
        } as i64;
        Self::new(scaled_ns)
    }

    /// Converts the scaled nanoseconds to picoseconds with rounding.
    pub fn to_picoseconds(&self) -> i64 {
        let numerator = self.delay_asymmetry_scaled_ns as i128 * 1000;
        if numerator >= 0 {
            ((numerator + 32768) / 65536) as i64
        } else {
            ((numerator - 32768) / 65536) as i64
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.tlv_type.to_be_bytes());
        buf.extend_from_slice(&self.length_field.to_be_bytes());
        buf.extend_from_slice(&self.delay_asymmetry_scaled_ns.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 {
            return None;
        }
        let tlv_type = u16::from_be_bytes([buf[0], buf[1]]);
        let length_field = u16::from_be_bytes([buf[2], buf[3]]);
        if length_field < 8 || buf.len() < 4 + (length_field as usize) {
            return None;
        }
        let delay_asymmetry_scaled_ns = i64::from_be_bytes([
            buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
        ]);
        Some(Self {
            tlv_type,
            length_field,
            delay_asymmetry_scaled_ns,
        })
    }
}

/// Port-level physical calibration parameters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HighAccuracyPortCalibration {
    pub port_id: u16,
    /// Egress internal PHY/MAC latency in picoseconds
    pub tx_phy_latency_ps: i64,
    /// Ingress internal PHY/MAC latency in picoseconds
    pub rx_phy_latency_ps: i64,
    /// Calibrated constant fiber/wire asymmetry in picoseconds
    pub fiber_asymmetry_ps: i64,
    /// Is this port calibrated to sub-nanosecond accuracy
    pub is_calibrated: bool,
}

/// Result of high-accuracy sub-nanosecond clock synchronization calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighAccuracySyncResult {
    /// Calculated one-way mean propagation delay in picoseconds
    pub mean_path_delay_ps: i64,
    /// Calculated clock offset in picoseconds (positive means local clock is behind master)
    pub clock_offset_ps: i128,
    /// Total asymmetry correction applied in picoseconds
    pub total_asymmetry_correction_ps: i64,
}

/// High-Accuracy PTP Synchronization Engine (IEEE 1588-2019 / IEEE 802.1AS).
#[derive(Debug, Clone, Default)]
pub struct HighAccuracyPtpEngine {
    pub calibration: HighAccuracyPortCalibration,
}

impl HighAccuracyPtpEngine {
    pub fn new(calibration: HighAccuracyPortCalibration) -> Self {
        Self { calibration }
    }

    /// Computes high-precision path delay and clock offset given 4 four-timestamp measurements:
    /// - `t1`: Master TX timestamp (Sync)
    /// - `t2`: Slave RX timestamp (Sync)
    /// - `t3`: Slave TX timestamp (Delay_Req)
    /// - `t4`: Master RX timestamp (Delay_Req)
    /// - `correction_field_ps`: Transparent clock residence time & sub-ns corrections
    /// - `external_asymmetry_ps`: Additional asymmetry signaled via TLV or peer delay
    pub fn compute_offset_and_delay(
        &self,
        t1: HighPrecisionTimestamp,
        t2: HighPrecisionTimestamp,
        t3: HighPrecisionTimestamp,
        t4: HighPrecisionTimestamp,
        correction_field_ps: i64,
        external_asymmetry_ps: i64,
    ) -> HighAccuracySyncResult {
        // Physical port calibration adjustments:
        // t1_actual = t1 + tx_phy_latency (Master side, assumed 0 if not given)
        // t2_actual = t2 - rx_phy_latency (Slave side)
        // t3_actual = t3 + tx_phy_latency (Slave side)
        // t4_actual = t4 - rx_phy_latency (Master side, assumed 0 if not given)
        let t2_calibrated =
            t2.to_total_picoseconds() - (self.calibration.rx_phy_latency_ps as i128);
        let t3_calibrated =
            t3.to_total_picoseconds() + (self.calibration.tx_phy_latency_ps as i128);
        let t1_ps = t1.to_total_picoseconds();
        let t4_ps = t4.to_total_picoseconds();

        // Forward raw delay (Master -> Slave): t2 - t1
        let forward_raw = t2_calibrated - t1_ps;
        // Reverse raw delay (Slave -> Master): t4 - t3
        let reverse_raw = t4_ps - t3_calibrated;

        // Total asymmetry = calibrated fiber asymmetry + external TLV asymmetry
        let total_asym_ps = self.calibration.fiber_asymmetry_ps + external_asymmetry_ps;

        // Mean path delay D = [(t2 - t1) + (t4 - t3) - correctionField] / 2
        let raw_roundtrip = forward_raw + reverse_raw - (correction_field_ps as i128);
        let mean_path_delay_ps = (raw_roundtrip / 2) as i64;

        // One-way forward path delay adjusted for asymmetry:
        // D_ms = D + (total_asym / 2)
        // Clock Offset = (t2 - t1) - D_ms - correctionField = [(t2 - t1) - (t4 - t3) - total_asym] / 2
        let clock_offset_ps = (forward_raw - reverse_raw - (total_asym_ps as i128)) / 2;

        HighAccuracySyncResult {
            mean_path_delay_ps,
            clock_offset_ps,
            total_asymmetry_correction_ps: total_asym_ps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_precision_timestamp_picoseconds() {
        let ts = HighPrecisionTimestamp::new(10, 500_000_000_000);
        assert_eq!(ts.seconds, 10);
        assert_eq!(ts.picoseconds, 500_000_000_000);
        assert_eq!(ts.to_total_picoseconds(), 10_500_000_000_000);

        let from_ns = HighPrecisionTimestamp::from_nanoseconds(5, 250_000);
        assert_eq!(from_ns.picoseconds, 250_000_000);
    }

    #[test]
    fn test_delay_asymmetry_tlv_codec() {
        let tlv = PtpDelayAsymmetryTlv::from_picoseconds(12_500); // 12.5 ns asymmetry
        let bytes = tlv.serialize();
        assert_eq!(bytes.len(), 12);

        let parsed = PtpDelayAsymmetryTlv::parse(&bytes).unwrap();
        assert_eq!(parsed.to_picoseconds(), 12_500);
    }

    #[test]
    fn test_high_accuracy_ptp_engine_sub_nanosecond_sync() {
        let cal = HighAccuracyPortCalibration {
            port_id: 1,
            tx_phy_latency_ps: 2_500,  // 2.5 ns TX PHY latency
            rx_phy_latency_ps: 3_100,  // 3.1 ns RX PHY latency
            fiber_asymmetry_ps: 1_200, // 1.2 ns fiber asymmetry
            is_calibrated: true,
        };
        let engine = HighAccuracyPtpEngine::new(cal);

        // Master sends Sync at t1 = 100.000000000000 s
        let t1 = HighPrecisionTimestamp::new(100, 0);
        // Slave receives Sync at t2 = 100.000050000000 s (50 us later + 10 ns clock offset)
        let t2 = HighPrecisionTimestamp::new(100, 50_000_010_000);
        // Slave sends Delay_Req at t3 = 100.001000000000 s
        let t3 = HighPrecisionTimestamp::new(100, 1_000_000_000_000);
        // Master receives Delay_Req at t4 = 100.001049990000 s (50 us later - 10 ns clock offset)
        let t4 = HighPrecisionTimestamp::new(100, 1_050_000_000_000);

        let result = engine.compute_offset_and_delay(t1, t2, t3, t4, 0, 0);
        assert!(result.mean_path_delay_ps > 0);
        assert_eq!(result.total_asymmetry_correction_ps, 1_200);
    }
}
