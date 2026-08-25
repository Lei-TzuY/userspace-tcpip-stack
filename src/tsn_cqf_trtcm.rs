//! IEEE 802.1Qch Cyclic Queuing & Forwarding (CQF) with trTCM Traffic Metering Integration.
//!
//! In mixed-criticality industrial TSN networks, cyclic queues must be protected
//! against rogue or bursty streams exceeding their contracted SLA bandwidth.
//!
//! This module integrates:
//! * Two-Rate Three-Color Marker (trTCM, RFC 2698) meter at CQF ingress:
//!   - PIR (Peak Information Rate) & PBS (Peak Burst Size)
//!   - CIR (Committed Information Rate) & CBS (Committed Burst Size)
//! * Color-aware admission:
//!   - **Green**: Committed deterministic traffic (admitted into regular CQF cyclic queue).
//!   - **Yellow**: Excess traffic (remarked / admitted with lower priority or subject to drop).
//!   - **Red**: Violating traffic (instantly dropped at CQF queue ingress).

/// trTCM Packet Color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrTcmColor {
    Green,
    Yellow,
    Red,
}

/// Token bucket state for trTCM meter.
#[derive(Debug, Clone)]
pub struct TrTcmMeter {
    pub cir_bps: u64,
    pub cbs_bytes: u64,
    pub pir_bps: u64,
    pub pbs_bytes: u64,
    pub current_c_tokens: f64,
    pub current_p_tokens: f64,
    pub last_update_ns: u64,
}

impl TrTcmMeter {
    pub fn new(cir_bps: u64, cbs_bytes: u64, pir_bps: u64, pbs_bytes: u64) -> Self {
        TrTcmMeter {
            cir_bps,
            cbs_bytes,
            pir_bps,
            pbs_bytes,
            current_c_tokens: cbs_bytes as f64,
            current_p_tokens: pbs_bytes as f64,
            last_update_ns: 0,
        }
    }

    /// Evaluates incoming packet color according to RFC 2698.
    pub fn meter_packet(&mut self, packet_bytes: usize, now_ns: u64) -> TrTcmColor {
        if self.last_update_ns > 0 && now_ns > self.last_update_ns {
            let elapsed_sec = (now_ns - self.last_update_ns) as f64 / 1_000_000_000.0;
            // Replenish C bucket (CIR)
            let c_inc = (self.cir_bps as f64 / 8.0) * elapsed_sec;
            self.current_c_tokens = (self.current_c_tokens + c_inc).min(self.cbs_bytes as f64);
            // Replenish P bucket (PIR)
            let p_inc = (self.pir_bps as f64 / 8.0) * elapsed_sec;
            self.current_p_tokens = (self.current_p_tokens + p_inc).min(self.pbs_bytes as f64);
        }
        self.last_update_ns = now_ns;

        let bytes = packet_bytes as f64;

        if self.current_p_tokens < bytes {
            TrTcmColor::Red
        } else if self.current_c_tokens < bytes {
            self.current_p_tokens -= bytes;
            TrTcmColor::Yellow
        } else {
            self.current_c_tokens -= bytes;
            self.current_p_tokens -= bytes;
            TrTcmColor::Green
        }
    }
}

/// A frame enqueued in the Color-Aware CQF Engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ColorAwareCqfFrame {
    pub stream_id: u32,
    pub bytes: usize,
    pub color: TrTcmColor,
}

/// IEEE 802.1Qch Multi-Class CQF with trTCM Traffic Metering Engine.
#[derive(Debug, Clone)]
pub struct TsnCqfTrTcmEngine {
    pub meter: TrTcmMeter,
    pub queue: Vec<ColorAwareCqfFrame>,
    pub drop_yellow_on_congestion: bool,
    pub total_green_admitted: u64,
    pub total_yellow_admitted: u64,
    pub total_red_dropped: u64,
}

impl TsnCqfTrTcmEngine {
    pub fn new(cir_bps: u64, cbs_bytes: u64, pir_bps: u64, pbs_bytes: u64) -> Self {
        TsnCqfTrTcmEngine {
            meter: TrTcmMeter::new(cir_bps, cbs_bytes, pir_bps, pbs_bytes),
            queue: Vec::new(),
            drop_yellow_on_congestion: false,
            total_green_admitted: 0,
            total_yellow_admitted: 0,
            total_red_dropped: 0,
        }
    }

    /// Ingests a frame into the CQF queue with trTCM color metering.
    pub fn ingest_frame(&mut self, stream_id: u32, bytes: usize, now_ns: u64) -> TrTcmColor {
        let color = self.meter.meter_packet(bytes, now_ns);

        match color {
            TrTcmColor::Green => {
                self.queue.push(ColorAwareCqfFrame { stream_id, bytes, color });
                self.total_green_admitted += 1;
            }
            TrTcmColor::Yellow => {
                if !self.drop_yellow_on_congestion {
                    self.queue.push(ColorAwareCqfFrame { stream_id, bytes, color });
                    self.total_yellow_admitted += 1;
                } else {
                    self.total_red_dropped += 1;
                }
            }
            TrTcmColor::Red => {
                self.total_red_dropped += 1;
            }
        }

        color
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tsn_cqf_trtcm_color_admission() {
        // CIR: 10 MB/s (80 Mbps), CBS: 2000 B, PIR: 20 MB/s (160 Mbps), PBS: 4000 B
        let mut engine = TsnCqfTrTcmEngine::new(80_000_000, 2000, 160_000_000, 4000);

        // 1. Packet of 1000B -> Green (fits in CBS & PBS)
        let c1 = engine.ingest_frame(1, 1000, 0);
        assert_eq!(c1, TrTcmColor::Green);

        // 2. Packet of 1500B -> Yellow (exceeds remaining CBS=1000B, fits in PBS=3000B)
        let c2 = engine.ingest_frame(1, 1500, 0);
        assert_eq!(c2, TrTcmColor::Yellow);

        // 3. Packet of 2000B -> Red (exceeds remaining PBS=1500B) -> Dropped!
        let c3 = engine.ingest_frame(1, 2000, 0);
        assert_eq!(c3, TrTcmColor::Red);

        assert_eq!(engine.total_green_admitted, 1);
        assert_eq!(engine.total_yellow_admitted, 1);
        assert_eq!(engine.total_red_dropped, 1);
        assert_eq!(engine.queue.len(), 2);
    }
}
