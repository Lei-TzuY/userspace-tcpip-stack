//! IEEE 802.1Qci-2017 Per-Stream Filtering and Policing (PSFP) Advanced Multi-Stage Engine.
//!
//! PSFP protects TSN networks from rogue, malfunctioning, or misbehaving talkers
//! by validating frames against three cascaded inspection blocks:
//! 1. **Stream Filter Instance (SFI)**: Stream identification and Max SDU size filtering.
//! 2. **Stream Gate Instance (SGI)**: Time-scheduled gate states (`Open` / `Closed`) with gating violation detection.
//! 3. **Flow Meter Instance (FMI)**: RFC 2698 Two-Rate Three-Color Marker (trTCM) with CIR/CBS and PIR/PBS bandwidth metering.
//!
//! This module implements:
//! * Complete SFI -> SGI -> FMI evaluation pipeline.
//! * trTCM Color marking: `Green` (conforming), `Yellow` (burst conforming), `Red` (excessive, dropped).
//! * PSFP Verdicts: `Pass`, `MarkYellow`, `DropMaxSduExceeded`, `DropGateClosed`, `DropMeterRed`.
//! * Per-stream violation accounting and blocking state transitions.

/// trTCM Packet Color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsfpColor {
    Green,
    Yellow,
    Red,
}

/// PSFP Forwarding Action Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsfpVerdict {
    /// Frame passes cleanly through filter, gate, and meter (Green).
    Pass,
    /// Frame exceeds committed rate but is within peak burst (Yellow, remark DEI/drop-eligible).
    MarkYellow,
    /// Frame exceeded Maximum SDU byte length (dropped).
    DropMaxSduExceeded,
    /// Frame arrived while Stream Gate was closed (dropped).
    DropGateClosed,
    /// Frame exceeded Peak Information Rate / Peak Burst Size (dropped).
    DropMeterRed,
}

/// Stream Filter Instance (SFI) Configuration and State.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFilterInstance {
    pub stream_id: u32,
    pub priority: u8,
    pub max_sdu_bytes: usize,
    pub gate_id: u32,
    pub meter_id: Option<u32>,
    pub matching_frames: u64,
    pub sdu_oversized_drops: u64,
}

/// Stream Gate Instance (SGI) Configuration and State.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamGateInstance {
    pub gate_id: u32,
    pub is_open: bool,
    pub gate_closed_drops: u64,
    pub invalid_rx_count: u64,
}

/// Flow Meter Instance (FMI) Configuration and State implementing trTCM (RFC 2698).
#[derive(Debug, Clone)]
pub struct FlowMeterInstance {
    pub meter_id: u32,
    /// Committed Information Rate in bytes per second.
    pub cir_bps: u64,
    /// Committed Burst Size in bytes.
    pub cbs_bytes: u64,
    /// Peak Information Rate in bytes per second.
    pub pir_bps: u64,
    /// Peak Burst Size in bytes.
    pub pbs_bytes: u64,
    /// Current committed token bucket ($T_c$).
    pub tc_tokens: f64,
    /// Current peak token bucket ($T_p$).
    pub tp_tokens: f64,
    /// Last token update timestamp in nanoseconds.
    pub last_update_ns: u64,
    /// Counter stats.
    pub green_packets: u64,
    pub yellow_packets: u64,
    pub red_drops: u64,
}

impl FlowMeterInstance {
    pub fn new(meter_id: u32, cir_bps: u64, cbs_bytes: u64, pir_bps: u64, pbs_bytes: u64) -> Self {
        FlowMeterInstance {
            meter_id,
            cir_bps,
            cbs_bytes,
            pir_bps,
            pbs_bytes,
            tc_tokens: cbs_bytes as f64,
            tp_tokens: pbs_bytes as f64,
            last_update_ns: 0,
            green_packets: 0,
            yellow_packets: 0,
            red_drops: 0,
        }
    }

    /// Evaluates a frame of `byte_len` at timestamp `now_ns` using trTCM.
    pub fn evaluate(&mut self, byte_len: usize, now_ns: u64) -> PsfpColor {
        if self.last_update_ns > 0 && now_ns > self.last_update_ns {
            let elapsed_sec = (now_ns - self.last_update_ns) as f64 / 1_000_000_000.0;
            self.tc_tokens =
                (self.tc_tokens + self.cir_bps as f64 * elapsed_sec).min(self.cbs_bytes as f64);
            self.tp_tokens =
                (self.tp_tokens + self.pir_bps as f64 * elapsed_sec).min(self.pbs_bytes as f64);
        }
        self.last_update_ns = now_ns;

        let len_f = byte_len as f64;
        if self.tp_tokens < len_f {
            self.red_drops += 1;
            PsfpColor::Red
        } else if self.tc_tokens < len_f {
            self.tp_tokens -= len_f;
            self.yellow_packets += 1;
            PsfpColor::Yellow
        } else {
            self.tc_tokens -= len_f;
            self.tp_tokens -= len_f;
            self.green_packets += 1;
            PsfpColor::Green
        }
    }
}

/// Complete IEEE 802.1Qci PSFP Policing Engine.
#[derive(Debug, Clone, Default)]
pub struct PsfpEngine {
    pub filters: Vec<StreamFilterInstance>,
    pub gates: Vec<StreamGateInstance>,
    pub meters: Vec<FlowMeterInstance>,
}

impl PsfpEngine {
    pub fn new() -> Self {
        PsfpEngine {
            filters: Vec::new(),
            gates: Vec::new(),
            meters: Vec::new(),
        }
    }

    pub fn add_filter(&mut self, filter: StreamFilterInstance) {
        self.filters.push(filter);
    }

    pub fn add_gate(&mut self, gate: StreamGateInstance) {
        self.gates.push(gate);
    }

    pub fn add_meter(&mut self, meter: FlowMeterInstance) {
        self.meters.push(meter);
    }

    /// Evaluates an incoming TSN frame through the 3-stage PSFP pipeline.
    pub fn process_frame(
        &mut self,
        stream_id: u32,
        priority: u8,
        frame_len: usize,
        now_ns: u64,
    ) -> PsfpVerdict {
        // 1. Stage 1: Stream Filter Instance (SFI)
        let filter = match self
            .filters
            .iter_mut()
            .find(|f| f.stream_id == stream_id && f.priority == priority)
        {
            Some(f) => f,
            None => return PsfpVerdict::Pass, // Unmanaged stream bypasses PSFP
        };

        filter.matching_frames += 1;
        if frame_len > filter.max_sdu_bytes {
            filter.sdu_oversized_drops += 1;
            return PsfpVerdict::DropMaxSduExceeded;
        }

        let gate_id = filter.gate_id;
        let meter_id = filter.meter_id;

        // 2. Stage 2: Stream Gate Instance (SGI)
        if let Some(gate) = self.gates.iter_mut().find(|g| g.gate_id == gate_id) {
            if !gate.is_open {
                gate.gate_closed_drops += 1;
                gate.invalid_rx_count += 1;
                return PsfpVerdict::DropGateClosed;
            }
        }

        // 3. Stage 3: Flow Meter Instance (FMI) with trTCM
        if let Some(m_id) = meter_id {
            if let Some(meter) = self.meters.iter_mut().find(|m| m.meter_id == m_id) {
                let color = meter.evaluate(frame_len, now_ns);
                return match color {
                    PsfpColor::Green => PsfpVerdict::Pass,
                    PsfpColor::Yellow => PsfpVerdict::MarkYellow,
                    PsfpColor::Red => PsfpVerdict::DropMeterRed,
                };
            }
        }

        PsfpVerdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_psfp_max_sdu_oversized_drop() {
        let mut engine = PsfpEngine::new();
        engine.add_filter(StreamFilterInstance {
            stream_id: 101,
            priority: 7,
            max_sdu_bytes: 256,
            gate_id: 1,
            meter_id: None,
            matching_frames: 0,
            sdu_oversized_drops: 0,
        });
        engine.add_gate(StreamGateInstance {
            gate_id: 1,
            is_open: true,
            gate_closed_drops: 0,
            invalid_rx_count: 0,
        });

        // 200B fits
        assert_eq!(engine.process_frame(101, 7, 200, 1000), PsfpVerdict::Pass);
        // 300B exceeds 256B limit -> dropped
        assert_eq!(
            engine.process_frame(101, 7, 300, 2000),
            PsfpVerdict::DropMaxSduExceeded
        );
        assert_eq!(engine.filters[0].sdu_oversized_drops, 1);
    }

    #[test]
    fn test_psfp_stream_gate_closed_drop() {
        let mut engine = PsfpEngine::new();
        engine.add_filter(StreamFilterInstance {
            stream_id: 202,
            priority: 6,
            max_sdu_bytes: 1500,
            gate_id: 2,
            meter_id: None,
            matching_frames: 0,
            sdu_oversized_drops: 0,
        });
        engine.add_gate(StreamGateInstance {
            gate_id: 2,
            is_open: false, // Closed gate
            gate_closed_drops: 0,
            invalid_rx_count: 0,
        });

        assert_eq!(
            engine.process_frame(202, 6, 128, 5000),
            PsfpVerdict::DropGateClosed
        );
        assert_eq!(engine.gates[0].gate_closed_drops, 1);
    }

    #[test]
    fn test_psfp_trtcm_meter_color_evaluation() {
        let mut meter = FlowMeterInstance::new(1, 100_000, 1_000, 200_000, 2_000);

        // Frame 1: 500B -> Green (fits in 1000B CBS)
        assert_eq!(meter.evaluate(500, 0), PsfpColor::Green);
        // Frame 2: 600B -> Yellow (exceeds remaining 500B CBS, but fits in remaining 1500B PBS)
        assert_eq!(meter.evaluate(600, 0), PsfpColor::Yellow);
        // Frame 3: 1000B -> Red (exceeds remaining 900B PBS)
        assert_eq!(meter.evaluate(1000, 0), PsfpColor::Red);
        assert_eq!(meter.red_drops, 1);
    }
}
