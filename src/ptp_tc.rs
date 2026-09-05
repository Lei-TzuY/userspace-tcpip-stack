//! PTP Transparent Clock (IEEE 1588v2 & ITU-T G.8275.1 Residence Time Correction).
//!
//! Implements End-to-End (E2E) and Peer-to-Peer (P2P) Transparent Clocks (TC),
//! updating the 64-bit PTP Correction Field with switch residence time and link delays.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransparentClockMode {
    EndToEnd,   // E2E TC (Residence Time only)
    PeerToPeer, // P2P TC (Residence Time + Peer Link Delay)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpTcError {
    InvalidResidenceTimestamps,
    InvalidPeerDelayTimestamps,
    ArithmeticOverflow,
}

/// Hop Timestamping Measurement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopMeasurement {
    pub ingress_timestamp_ns: u64,
    pub egress_timestamp_ns: u64,
}

/// Transparent Clock Engine
#[derive(Debug, Clone)]
pub struct TransparentClockEngine {
    pub mode: TransparentClockMode,
    pub peer_delay_ns: u64,
    pub total_residence_time_ns: u64,
    pub corrected_packets_count: u64,
}

impl TransparentClockEngine {
    pub fn new(mode: TransparentClockMode) -> Self {
        TransparentClockEngine {
            mode,
            peer_delay_ns: 0,
            total_residence_time_ns: 0,
            corrected_packets_count: 0,
        }
    }

    /// Calculates node transit residence time: T_residence = T_egress - T_ingress
    pub fn calculate_residence_time(&self, hop: &HopMeasurement) -> Result<u64, PtpTcError> {
        hop.egress_timestamp_ns
            .checked_sub(hop.ingress_timestamp_ns)
            .ok_or(PtpTcError::InvalidResidenceTimestamps)
    }

    /// Calculates Peer Link Delay: PDelay = ((t4 - t1) - (t3 - t2)) / 2
    pub fn calculate_peer_delay(
        &mut self,
        t1_ns: u64,
        t2_ns: u64,
        t3_ns: u64,
        t4_ns: u64,
    ) -> Result<u64, PtpTcError> {
        let round_trip = t4_ns
            .checked_sub(t1_ns)
            .ok_or(PtpTcError::InvalidPeerDelayTimestamps)?;
        let peer_turnaround = t3_ns
            .checked_sub(t2_ns)
            .ok_or(PtpTcError::InvalidPeerDelayTimestamps)?;
        let link_delay = round_trip
            .checked_sub(peer_turnaround)
            .ok_or(PtpTcError::InvalidPeerDelayTimestamps)?
            / 2;
        self.peer_delay_ns = link_delay;
        Ok(link_delay)
    }

    /// Updates the incoming PTP frame Correction Field in nanoseconds.
    /// State is mutated only after all arithmetic is validated.
    pub fn update_correction_field(
        &mut self,
        initial_correction_ns: u64,
        hop: &HopMeasurement,
    ) -> Result<u64, PtpTcError> {
        let residence = self.calculate_residence_time(hop)?;
        let additional_delay = match self.mode {
            TransparentClockMode::EndToEnd => residence,
            TransparentClockMode::PeerToPeer => residence
                .checked_add(self.peer_delay_ns)
                .ok_or(PtpTcError::ArithmeticOverflow)?,
        };
        let new_correction = initial_correction_ns
            .checked_add(additional_delay)
            .ok_or(PtpTcError::ArithmeticOverflow)?;
        let new_total_residence = self
            .total_residence_time_ns
            .checked_add(residence)
            .ok_or(PtpTcError::ArithmeticOverflow)?;
        let new_count = self
            .corrected_packets_count
            .checked_add(1)
            .ok_or(PtpTcError::ArithmeticOverflow)?;

        self.total_residence_time_ns = new_total_residence;
        self.corrected_packets_count = new_count;
        Ok(new_correction)
    }

    /// Encodes nanoseconds to IEEE 1588v2 scaledNanoseconds (48-bit integer ns + 16-bit fractional ns)
    pub fn to_scaled_nanoseconds(ns: u64) -> Result<u64, PtpTcError> {
        ns.checked_mul(1u64 << 16)
            .ok_or(PtpTcError::ArithmeticOverflow)
    }

    /// Decodes IEEE 1588v2 scaledNanoseconds to integer nanoseconds
    pub fn from_scaled_nanoseconds(scaled: u64) -> u64 {
        scaled >> 16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2e_transparent_clock_residence_correction() {
        let mut tc = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
        let hop = HopMeasurement {
            ingress_timestamp_ns: 1_000_000_000,
            egress_timestamp_ns: 1_000_000_350,
        };

        assert_eq!(tc.calculate_residence_time(&hop), Ok(350));

        let new_corr = tc.update_correction_field(100, &hop).unwrap();
        assert_eq!(new_corr, 450);
        assert_eq!(tc.corrected_packets_count, 1);
    }

    #[test]
    fn test_p2p_transparent_clock_peer_delay_correction() {
        let mut tc = TransparentClockEngine::new(TransparentClockMode::PeerToPeer);
        let pdelay = tc.calculate_peer_delay(0, 100, 150, 250).unwrap();
        assert_eq!(pdelay, 100);

        let hop = HopMeasurement {
            ingress_timestamp_ns: 10_000,
            egress_timestamp_ns: 10_200,
        };

        let new_corr = tc.update_correction_field(50, &hop).unwrap();
        assert_eq!(new_corr, 350);
    }

    #[test]
    fn test_scaled_nanoseconds_conversions() {
        let ns = 12345;
        let scaled = TransparentClockEngine::to_scaled_nanoseconds(ns).unwrap();
        assert_eq!(scaled, 12345 << 16);
        assert_eq!(TransparentClockEngine::from_scaled_nanoseconds(scaled), ns);
    }

    #[test]
    fn test_invalid_residence_timestamps_fail_closed() {
        let mut tc = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
        let hop = HopMeasurement {
            ingress_timestamp_ns: 200,
            egress_timestamp_ns: 100,
        };

        assert_eq!(
            tc.update_correction_field(0, &hop),
            Err(PtpTcError::InvalidResidenceTimestamps)
        );
        assert_eq!(tc.total_residence_time_ns, 0);
        assert_eq!(tc.corrected_packets_count, 0);
    }

    #[test]
    fn test_invalid_peer_delay_timestamps_preserve_previous_delay() {
        let mut tc = TransparentClockEngine::new(TransparentClockMode::PeerToPeer);
        assert_eq!(tc.calculate_peer_delay(0, 100, 150, 250), Ok(100));

        assert_eq!(
            tc.calculate_peer_delay(300, 100, 150, 250),
            Err(PtpTcError::InvalidPeerDelayTimestamps)
        );
        assert_eq!(tc.peer_delay_ns, 100);
    }

    #[test]
    fn test_correction_overflow_does_not_mutate_state() {
        let mut tc = TransparentClockEngine::new(TransparentClockMode::EndToEnd);
        let hop = HopMeasurement {
            ingress_timestamp_ns: 0,
            egress_timestamp_ns: 1,
        };

        assert_eq!(
            tc.update_correction_field(u64::MAX, &hop),
            Err(PtpTcError::ArithmeticOverflow)
        );
        assert_eq!(tc.total_residence_time_ns, 0);
        assert_eq!(tc.corrected_packets_count, 0);
    }

    #[test]
    fn test_scaled_nanoseconds_overflow_fails_closed() {
        assert_eq!(
            TransparentClockEngine::to_scaled_nanoseconds(u64::MAX),
            Err(PtpTcError::ArithmeticOverflow)
        );
    }
}
