//! Deterministic IP DetNet Bounded Jitter & End-to-End Latency Budget Calculator (RFC 8939 / RFC 9024).
//!
//! Evaluates bounded mathematical latency limits (D_min, D_max), worst-case end-to-end
//! jitter (J_e2e), PREOF differential path skew, and required PEF de-jitter elimination
//! buffer capacity across multi-path DetNet topologies.

/// Queuing and traffic shaping model employed at a DetNet transit node.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetNetQueuingModel {
    /// Cyclic Queuing and Forwarding (IEEE 802.1Qch CQF): bounded to 1..2 cycle times
    Cqf { cycle_time_us: f64 },
    /// Asynchronous Traffic Shaping (IEEE 802.1Qcr ATS): bounded delay based on burst size & rate
    Ats {
        max_burst_bytes: u32,
        committed_rate_mbps: f64,
    },
    /// Time-Aware Shaper (IEEE 802.1Qbv TAS): gate-aligned slot delay
    Tas { slot_duration_us: f64 },
    /// Credit-Based Shaper (IEEE 802.1Qav CBS): bounded interference delay
    Cbs { max_interference_us: f64 },
    /// Standard strict priority / FIFO
    StrictPriority {
        max_queue_depth_bytes: u32,
        line_rate_mbps: f64,
    },
}

impl DetNetQueuingModel {
    /// Computes minimum and maximum queuing delay in microseconds (us).
    pub fn delay_bounds_us(&self) -> (f64, f64) {
        match self {
            DetNetQueuingModel::Cqf { cycle_time_us } => (*cycle_time_us, 2.0 * cycle_time_us),
            DetNetQueuingModel::Ats {
                max_burst_bytes,
                committed_rate_mbps,
            } => {
                let burst_delay_us = (*max_burst_bytes as f64 * 8.0) / *committed_rate_mbps;
                (0.5, burst_delay_us + 1.0)
            }
            DetNetQueuingModel::Tas { slot_duration_us } => (0.2, *slot_duration_us),
            DetNetQueuingModel::Cbs {
                max_interference_us,
            } => (0.5, *max_interference_us),
            DetNetQueuingModel::StrictPriority {
                max_queue_depth_bytes,
                line_rate_mbps,
            } => {
                let queue_delay_us = (*max_queue_depth_bytes as f64 * 8.0) / *line_rate_mbps;
                (0.1, queue_delay_us)
            }
        }
    }
}

/// A single hop / link in a DetNet network path.
#[derive(Debug, Clone, PartialEq)]
pub struct DetNetHop {
    pub node_id: String,
    pub link_length_km: f64,
    pub proc_delay_min_us: f64,
    pub proc_delay_max_us: f64,
    pub queuing: DetNetQueuingModel,
}

impl DetNetHop {
    pub fn new(
        node_id: &str,
        link_length_km: f64,
        proc_delay_min_us: f64,
        proc_delay_max_us: f64,
        queuing: DetNetQueuingModel,
    ) -> Self {
        Self {
            node_id: node_id.to_string(),
            link_length_km,
            proc_delay_min_us,
            proc_delay_max_us,
            queuing,
        }
    }

    /// Propagation delay in optical fiber (~5 us per km, c/n = 200,000 km/s).
    pub fn propagation_delay_us(&self) -> f64 {
        self.link_length_km * 5.0
    }
}

/// Calculated Latency & Jitter Budget for a single DetNet Path.
#[derive(Debug, Clone, PartialEq)]
pub struct PathDelayBudget {
    pub min_delay_us: f64,
    pub max_delay_us: f64,
    pub e2e_jitter_us: f64,
    pub total_prop_delay_us: f64,
    pub total_proc_delay_max_us: f64,
    pub total_queue_delay_max_us: f64,
}

/// PREOF Multi-Path Replication & Elimination Analysis Result.
#[derive(Debug, Clone, PartialEq)]
pub struct PreofMultiPathBudget {
    pub path_budgets: Vec<PathDelayBudget>,
    pub overall_min_delay_us: f64,
    pub overall_max_delay_us: f64,
    pub differential_path_skew_us: f64,
    pub recommended_pef_buffer_bytes: usize,
}

/// DetNet Latency Budget Engine.
#[derive(Debug, Clone, Default)]
pub struct DetNetLatencyBudgetEngine;

impl DetNetLatencyBudgetEngine {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates deterministic latency and jitter bounds along a sequential DetNet path.
    pub fn evaluate_path(&self, hops: &[DetNetHop]) -> PathDelayBudget {
        let mut min_delay = 0.0;
        let mut max_delay = 0.0;
        let mut total_prop = 0.0;
        let mut total_proc_max = 0.0;
        let mut total_queue_max = 0.0;

        for hop in hops {
            let prop = hop.propagation_delay_us();
            let (q_min, q_max) = hop.queuing.delay_bounds_us();

            total_prop += prop;
            total_proc_max += hop.proc_delay_max_us;
            total_queue_max += q_max;

            min_delay += prop + hop.proc_delay_min_us + q_min;
            max_delay += prop + hop.proc_delay_max_us + q_max;
        }

        let jitter = (max_delay - min_delay).max(0.0);

        PathDelayBudget {
            min_delay_us: min_delay,
            max_delay_us: max_delay,
            e2e_jitter_us: jitter,
            total_prop_delay_us: total_prop,
            total_proc_delay_max_us: total_proc_max,
            total_queue_delay_max_us: total_queue_max,
        }
    }

    /// Evaluates multi-path PREOF replication and computes differential skew and PEF buffer size.
    pub fn evaluate_preof_paths(
        &self,
        paths: &[Vec<DetNetHop>],
        flow_peak_rate_mbps: f64,
    ) -> Result<PreofMultiPathBudget, String> {
        if paths.is_empty() {
            return Err("At least one DetNet path required".to_string());
        }

        let mut budgets = Vec::new();
        let mut overall_min = f64::INFINITY;
        let mut overall_max = 0.0;

        for path in paths {
            let budget = self.evaluate_path(path);
            if budget.min_delay_us < overall_min {
                overall_min = budget.min_delay_us;
            }
            if budget.max_delay_us > overall_max {
                overall_max = budget.max_delay_us;
            }
            budgets.push(budget);
        }

        let differential_skew = (overall_max - overall_min).max(0.0);

        // Required PEF buffer in bytes: skew_seconds * (peak_rate_bps / 8)
        let skew_seconds = differential_skew / 1_000_000.0;
        let bytes_per_sec = (flow_peak_rate_mbps * 1_000_000.0) / 8.0;
        let buffer_bytes = (skew_seconds * bytes_per_sec).ceil() as usize;

        Ok(PreofMultiPathBudget {
            path_budgets: budgets,
            overall_min_delay_us: overall_min,
            overall_max_delay_us: overall_max,
            differential_path_skew_us: differential_skew,
            recommended_pef_buffer_bytes: buffer_bytes.max(1500),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_latency_budget_single_path() {
        let engine = DetNetLatencyBudgetEngine::new();

        let path = vec![
            DetNetHop::new(
                "node-1",
                10.0,
                1.0,
                2.0,
                DetNetQueuingModel::Cqf {
                    cycle_time_us: 100.0,
                },
            ), // prop 50us, q 100..200us
            DetNetHop::new(
                "node-2",
                20.0,
                1.5,
                3.0,
                DetNetQueuingModel::Tas {
                    slot_duration_us: 50.0,
                },
            ), // prop 100us, q 0.2..50us
        ];

        let budget = engine.evaluate_path(&path);
        // Prop = 50 + 100 = 150us
        assert_eq!(budget.total_prop_delay_us, 150.0);
        // Min = 50 + 1.0 + 100 + 100 + 1.5 + 0.2 = 252.7 us
        assert!((budget.min_delay_us - 252.7).abs() < 1e-3);
        // Max = 50 + 2.0 + 200 + 100 + 3.0 + 50 = 405.0 us
        assert!((budget.max_delay_us - 405.0).abs() < 1e-3);
        assert!((budget.e2e_jitter_us - 152.3).abs() < 1e-3);
    }
}
