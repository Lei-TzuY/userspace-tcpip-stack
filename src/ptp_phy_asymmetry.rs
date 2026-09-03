//! PTP IEEE 1588 Physical Layer (PHY) Asymmetric Delay Compensation (IEEE 1588-2019 Clause 9.5.4).
//!
//! Calibrates hardware PHY ingress/egress serialization pipeline latency, internal
//! transceiver delay differences (Tx vs Rx), and applies sub-nanosecond asymmetry
//! corrections to PTP mean path delay, offset-from-master, and correctionField values.

/// Port Physical Layer (PHY) Latency Calibration Parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct PortPhyCalibration {
    pub port_id: String,
    pub tx_phy_latency_ns: f64,
    pub rx_phy_latency_ns: f64,
    pub static_cable_asymmetry_ns: f64,
}

impl PortPhyCalibration {
    pub fn new(
        port_id: &str,
        tx_phy_latency_ns: f64,
        rx_phy_latency_ns: f64,
        static_cable_asymmetry_ns: f64,
    ) -> Self {
        Self {
            port_id: port_id.to_string(),
            tx_phy_latency_ns,
            rx_phy_latency_ns,
            static_cable_asymmetry_ns,
        }
    }

    /// Total port path asymmetry (delay_master_to_slave - delay_slave_to_master).
    pub fn total_asymmetry_ns(&self) -> f64 {
        (self.tx_phy_latency_ns - self.rx_phy_latency_ns) + self.static_cable_asymmetry_ns
    }
}

/// Raw Four-Timestamp PTP Event Timestamps.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PtpFourTimestamps {
    pub t1_sync_tx_ns: f64,
    pub t2_sync_rx_ns: f64,
    pub t3_delay_req_tx_ns: f64,
    pub t4_delay_resp_rx_ns: f64,
}

/// Calibrated Synchronization Metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct PtpCalibratedSync {
    pub raw_mean_path_delay_ns: f64,
    pub calibrated_mean_path_delay_ns: f64,
    pub raw_offset_from_master_ns: f64,
    pub calibrated_offset_from_master_ns: f64,
    pub scaled_correction_field: i64,
}

/// PTP Physical Layer Asymmetry Compensation Engine.
#[derive(Debug, Clone, Default)]
pub struct PtpPhyAsymmetryEngine;

impl PtpPhyAsymmetryEngine {
    pub fn new() -> Self {
        Self
    }

    /// Computes calibrated mean path delay and offset from master taking into account
    /// master/slave PHY pipeline delays and static fiber asymmetry (IEEE 1588-2019 §9.5.4).
    pub fn calculate_calibrated_sync(
        &self,
        master_phy: &PortPhyCalibration,
        slave_phy: &PortPhyCalibration,
        ts: PtpFourTimestamps,
    ) -> PtpCalibratedSync {
        // Forward trip (Master -> Slave): t2 - t1
        // Actual wire transit: (t2 - slave_phy.rx) - (t1 + master_phy.tx)
        let raw_t2_t1 = ts.t2_sync_rx_ns - ts.t1_sync_tx_ns;
        // Reverse trip (Slave -> Master): t4 - t3
        // Actual wire transit: (t4 - master_phy.rx) - (t3 + slave_phy.tx)
        let raw_t4_t3 = ts.t4_delay_resp_rx_ns - ts.t3_delay_req_tx_ns;

        let raw_mean_path_delay = (raw_t2_t1 + raw_t4_t3) / 2.0;
        let raw_offset = raw_t2_t1 - raw_mean_path_delay;

        // Total asymmetry correction Delta = (t_master_tx - t_master_rx) - (t_slave_tx - t_slave_rx) + cable_asym
        let master_asym = master_phy.tx_phy_latency_ns - master_phy.rx_phy_latency_ns;
        let slave_asym = slave_phy.tx_phy_latency_ns - slave_phy.rx_phy_latency_ns;
        let total_asymmetry = master_asym - slave_asym + master_phy.static_cable_asymmetry_ns;

        let calibrated_mean_path_delay = ((raw_t2_t1 + raw_t4_t3) - total_asymmetry) / 2.0;
        let calibrated_offset = raw_t2_t1 - calibrated_mean_path_delay - (total_asymmetry / 2.0);

        // Scaled correctionField: asymmetry in nanoseconds converted to 16-bit fractional ns
        let scaled_correction = (total_asymmetry * 65536.0).round() as i64;

        PtpCalibratedSync {
            raw_mean_path_delay_ns: raw_mean_path_delay,
            calibrated_mean_path_delay_ns: calibrated_mean_path_delay,
            raw_offset_from_master_ns: raw_offset,
            calibrated_offset_from_master_ns: calibrated_offset,
            scaled_correction_field: scaled_correction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptp_phy_asymmetry_calibration() {
        let engine = PtpPhyAsymmetryEngine::new();

        let master_phy = PortPhyCalibration::new("master-port", 12.5, 8.0, 1.0); // Tx=12.5, Rx=8.0, Cable=1.0 -> Asym = +5.5ns
        let slave_phy = PortPhyCalibration::new("slave-port", 10.0, 10.0, 0.0); // Tx=10.0, Rx=10.0 -> Asym = 0.0ns

        let ts = PtpFourTimestamps {
            t1_sync_tx_ns: 1000.0,
            t2_sync_rx_ns: 1105.0, // raw delta 105 ns
            t3_delay_req_tx_ns: 2000.0,
            t4_delay_resp_rx_ns: 2095.0, // raw delta 95 ns
        };

        let res = engine.calculate_calibrated_sync(&master_phy, &slave_phy, ts);
        assert_eq!(res.raw_mean_path_delay_ns, 100.0);
        assert_eq!(res.raw_offset_from_master_ns, 5.0);

        // Total asymmetry = (12.5 - 8.0) - (10.0 - 10.0) + 1.0 = 5.5 ns
        assert_eq!(res.calibrated_mean_path_delay_ns, (200.0 - 5.5) / 2.0);
        assert!(res.scaled_correction_field > 0);
    }
}
