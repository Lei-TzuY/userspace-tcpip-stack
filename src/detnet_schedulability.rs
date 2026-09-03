//! Deterministic IP DetNet Schedulability & Over-Provisioning Analysis Engine (RFC 9024 §4 / IEEE 802.1Qbv)
//!
//! Provides multi-hop schedulability verification, worst-case queue backlog bounds,
//! over-provisioning factor ($\alpha_{\text{over}}$) estimation, and deterministic SLA admission control
//! for zero packet loss ($P_{\text{loss}} = 0$) time-critical streams.
//!
//! # Standard References
//! - RFC 9024: Deterministic Networking (DetNet) Data Plane: IEEE 802.1 Time-Sensitive Networking
//! - RFC 8938: Deterministic Networking (DetNet) Data Plane Framework
//! - IEEE Std 802.1Qbv: Enhancements for Scheduled Traffic

use std::collections::HashMap;

/// DetNet Flow Traffic Specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetNetFlowSpec {
    pub flow_id: u32,
    pub traffic_class: u8,
    pub peak_data_rate_bps: u64,
    pub max_payload_bytes: u32,
    pub max_burst_bytes: u32,
    pub max_tolerable_latency_ns: u64,
    pub max_tolerable_jitter_ns: u64,
}

/// DetNet Hop / Node Capacity & Shaper Specification
#[derive(Debug, Clone, PartialEq)]
pub struct DetNetNodeCapacity {
    pub node_id: u32,
    pub link_speed_bps: u64,
    pub cycle_time_ns: u64,
    pub max_reservable_utilization: f64,
    pub propagation_delay_ns: u64,
    pub processing_delay_ns: u64,
}

/// Schedulability Evaluation Result for a Hop or Path
#[derive(Debug, Clone, PartialEq)]
pub struct SchedulabilityReport {
    pub schedulable: bool,
    pub total_reserved_rate_bps: u64,
    pub bandwidth_utilization: f64,
    pub over_provisioning_factor: f64,
    pub max_queue_backlog_bytes: u64,
    pub worst_case_latency_ns: u64,
    pub worst_case_jitter_ns: u64,
    pub bottleneck_node: Option<u32>,
    pub reason: String,
}

/// DetNet Admission Control Decision
#[derive(Debug, Clone, PartialEq)]
pub enum DetNetAdmissionDecision {
    Admitted {
        flow_id: u32,
        assigned_bandwidth_bps: u64,
        guaranteed_latency_ns: u64,
        guaranteed_jitter_ns: u64,
        over_provisioning_factor: f64,
    },
    Rejected {
        flow_id: u32,
        bottleneck_node_id: u32,
        cause: String,
    },
}

/// DetNet Schedulability and Admission Control Engine
#[derive(Debug)]
pub struct DetNetSchedulabilityEngine {
    pub nodes: HashMap<u32, DetNetNodeCapacity>,
    pub active_reservations: HashMap<u32, (DetNetFlowSpec, Vec<u32>)>, // flow_id -> (spec, path_node_ids)
    pub node_reserved_bandwidth: HashMap<u32, u64>,                    // node_id -> sum(bps)
    pub node_burst_backlog: HashMap<u32, u64>, // node_id -> sum(burst_bytes)
}

impl DetNetSchedulabilityEngine {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            active_reservations: HashMap::new(),
            node_reserved_bandwidth: HashMap::new(),
            node_burst_backlog: HashMap::new(),
        }
    }

    /// Add a deterministic hop / switch node to the topology
    pub fn add_node(&mut self, node: DetNetNodeCapacity) {
        let node_id = node.node_id;
        self.nodes.insert(node_id, node);
        self.node_reserved_bandwidth.entry(node_id).or_insert(0);
        self.node_burst_backlog.entry(node_id).or_insert(0);
    }

    /// Analyze end-to-end path schedulability for a prospective or existing flow
    pub fn evaluate_path(&self, flow: &DetNetFlowSpec, path: &[u32]) -> SchedulabilityReport {
        if path.is_empty() {
            return SchedulabilityReport {
                schedulable: false,
                total_reserved_rate_bps: 0,
                bandwidth_utilization: 0.0,
                over_provisioning_factor: 1.0,
                max_queue_backlog_bytes: 0,
                worst_case_latency_ns: 0,
                worst_case_jitter_ns: 0,
                bottleneck_node: None,
                reason: "Empty path".to_string(),
            };
        }

        let mut total_latency_ns = 0u64;
        let mut total_jitter_ns = 0u64;
        let mut max_utilization = 0.0f64;
        let mut max_over_provisioning = 1.0f64;
        let mut max_queue_backlog_bytes = 0u64;
        let mut bottleneck_node = None;

        for &node_id in path {
            let node = match self.nodes.get(&node_id) {
                Some(n) => n,
                None => {
                    return SchedulabilityReport {
                        schedulable: false,
                        total_reserved_rate_bps: 0,
                        bandwidth_utilization: 0.0,
                        over_provisioning_factor: 1.0,
                        max_queue_backlog_bytes: 0,
                        worst_case_latency_ns: 0,
                        worst_case_jitter_ns: 0,
                        bottleneck_node: Some(node_id),
                        reason: format!("Node {} not found in topology", node_id),
                    };
                }
            };

            let current_res = *self.node_reserved_bandwidth.get(&node_id).unwrap_or(&0);
            let current_burst = *self.node_burst_backlog.get(&node_id).unwrap_or(&0);

            let prospective_rate = current_res + flow.peak_data_rate_bps;
            let prospective_burst = current_burst + flow.max_burst_bytes as u64;

            let util = prospective_rate as f64 / node.link_speed_bps as f64;
            if util > max_utilization {
                max_utilization = util;
                bottleneck_node = Some(node_id);
            }

            // Check bandwidth capacity constraint (RFC 9024 §4.1)
            if util > node.max_reservable_utilization {
                return SchedulabilityReport {
                    schedulable: false,
                    total_reserved_rate_bps: prospective_rate,
                    bandwidth_utilization: util,
                    over_provisioning_factor: 1.0,
                    max_queue_backlog_bytes: prospective_burst,
                    worst_case_latency_ns: 0,
                    worst_case_jitter_ns: 0,
                    bottleneck_node: Some(node_id),
                    reason: format!(
                        "Node {} utilization {:.2}% exceeds max limit {:.2}%",
                        node_id,
                        util * 100.0,
                        node.max_reservable_utilization * 100.0
                    ),
                };
            }

            // Over-provisioning factor calculation (RFC 9024 §4.2):
            // Alpha = 1.0 + (Burst_cumulative + Max_SDU) / (C * T_cycle)
            let cycle_bits = (node.link_speed_bps as f64
                * (node.cycle_time_ns as f64 / 1_000_000_000.0))
                .max(1.0);
            let burst_bits = (prospective_burst + flow.max_payload_bytes as u64) as f64 * 8.0;
            let alpha = 1.0 + (burst_bits / cycle_bits);
            if alpha > max_over_provisioning {
                max_over_provisioning = alpha;
            }

            if prospective_burst > max_queue_backlog_bytes {
                max_queue_backlog_bytes = prospective_burst;
            }

            // Per-hop deterministic latency components:
            // 1. Serialization delay for max packet = (L_max * 8 * 1e9) / C
            let serialization_ns =
                (flow.max_payload_bytes as u64 * 8 * 1_000_000_000) / node.link_speed_bps;
            // 2. Queuing delay bound = 2 * cycle_time (for CQF) + burst drain time
            let queuing_ns = (2 * node.cycle_time_ns)
                + ((prospective_burst * 8 * 1_000_000_000) / node.link_speed_bps);
            // 3. Propagation and processing delay
            let hop_delay = serialization_ns
                + queuing_ns
                + node.propagation_delay_ns
                + node.processing_delay_ns;

            total_latency_ns += hop_delay;
            // Jitter bounded by queuing variation within cycle
            total_jitter_ns += node.cycle_time_ns;
        }

        // Check if latency budget is within flow's tolerable bound
        if total_latency_ns > flow.max_tolerable_latency_ns {
            return SchedulabilityReport {
                schedulable: false,
                total_reserved_rate_bps: flow.peak_data_rate_bps,
                bandwidth_utilization: max_utilization,
                over_provisioning_factor: max_over_provisioning,
                max_queue_backlog_bytes,
                worst_case_latency_ns: total_latency_ns,
                worst_case_jitter_ns: total_jitter_ns,
                bottleneck_node,
                reason: format!(
                    "End-to-end latency {} ns exceeds flow tolerance {} ns",
                    total_latency_ns, flow.max_tolerable_latency_ns
                ),
            };
        }

        // Check jitter budget
        if total_jitter_ns > flow.max_tolerable_jitter_ns {
            return SchedulabilityReport {
                schedulable: false,
                total_reserved_rate_bps: flow.peak_data_rate_bps,
                bandwidth_utilization: max_utilization,
                over_provisioning_factor: max_over_provisioning,
                max_queue_backlog_bytes,
                worst_case_latency_ns: total_latency_ns,
                worst_case_jitter_ns: total_jitter_ns,
                bottleneck_node,
                reason: format!(
                    "End-to-end jitter {} ns exceeds flow tolerance {} ns",
                    total_jitter_ns, flow.max_tolerable_jitter_ns
                ),
            };
        }

        SchedulabilityReport {
            schedulable: true,
            total_reserved_rate_bps: flow.peak_data_rate_bps,
            bandwidth_utilization: max_utilization,
            over_provisioning_factor: max_over_provisioning,
            max_queue_backlog_bytes,
            worst_case_latency_ns: total_latency_ns,
            worst_case_jitter_ns: total_jitter_ns,
            bottleneck_node,
            reason: "Path verified schedulable with zero packet loss guarantees".to_string(),
        }
    }

    /// Perform admission control for a new DetNet flow reservation
    pub fn request_admission(
        &mut self,
        flow: DetNetFlowSpec,
        path: Vec<u32>,
    ) -> DetNetAdmissionDecision {
        let report = self.evaluate_path(&flow, &path);

        if report.schedulable {
            // Commit reservation state across all path nodes
            for &node_id in &path {
                let res = self.node_reserved_bandwidth.entry(node_id).or_insert(0);
                *res += flow.peak_data_rate_bps;

                let burst = self.node_burst_backlog.entry(node_id).or_insert(0);
                *burst += flow.max_burst_bytes as u64;
            }

            let flow_id = flow.flow_id;
            let assigned_bps = flow.peak_data_rate_bps;
            self.active_reservations.insert(flow_id, (flow, path));

            DetNetAdmissionDecision::Admitted {
                flow_id,
                assigned_bandwidth_bps: assigned_bps,
                guaranteed_latency_ns: report.worst_case_latency_ns,
                guaranteed_jitter_ns: report.worst_case_jitter_ns,
                over_provisioning_factor: report.over_provisioning_factor,
            }
        } else {
            DetNetAdmissionDecision::Rejected {
                flow_id: flow.flow_id,
                bottleneck_node_id: report.bottleneck_node.unwrap_or(0),
                cause: report.reason,
            }
        }
    }

    /// Release an existing DetNet flow reservation
    pub fn release_reservation(&mut self, flow_id: u32) -> bool {
        if let Some((flow, path)) = self.active_reservations.remove(&flow_id) {
            for node_id in path {
                if let Some(res) = self.node_reserved_bandwidth.get_mut(&node_id) {
                    *res = res.saturating_sub(flow.peak_data_rate_bps);
                }
                if let Some(burst) = self.node_burst_backlog.get_mut(&node_id) {
                    *burst = burst.saturating_sub(flow.max_burst_bytes as u64);
                }
            }
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detnet_admission_and_over_provisioning() {
        let mut engine = DetNetSchedulabilityEngine::new();

        // 3-hop 10 Gbps deterministic path with 125 us cycles
        for id in 1..=3 {
            engine.add_node(DetNetNodeCapacity {
                node_id: id,
                link_speed_bps: 10_000_000_000,   // 10 Gbps
                cycle_time_ns: 125_000,           // 125 µs
                max_reservable_utilization: 0.80, // 80%
                propagation_delay_ns: 5_000,      // 5 µs
                processing_delay_ns: 2_000,       // 2 µs
            });
        }

        let flow1 = DetNetFlowSpec {
            flow_id: 101,
            traffic_class: 7,
            peak_data_rate_bps: 1_000_000_000, // 1 Gbps
            max_payload_bytes: 1500,
            max_burst_bytes: 3000,
            max_tolerable_latency_ns: 2_000_000, // 2 ms
            max_tolerable_jitter_ns: 500_000,    // 500 µs
        };

        let decision = engine.request_admission(flow1, vec![1, 2, 3]);
        match decision {
            DetNetAdmissionDecision::Admitted {
                flow_id,
                assigned_bandwidth_bps,
                guaranteed_latency_ns,
                guaranteed_jitter_ns,
                over_provisioning_factor,
            } => {
                assert_eq!(flow_id, 101);
                assert_eq!(assigned_bandwidth_bps, 1_000_000_000);
                assert!(guaranteed_latency_ns < 2_000_000);
                assert!(guaranteed_jitter_ns <= 375_000); // 3 hops * 125 µs
                assert!(over_provisioning_factor >= 1.0);
            }
            DetNetAdmissionDecision::Rejected { .. } => panic!("Flow 1 should be admitted"),
        }

        // Try an excessive flow that exceeds bandwidth limit (e.g. 9 Gbps on 10 Gbps link where max is 80% = 8 Gbps)
        let flow_huge = DetNetFlowSpec {
            flow_id: 102,
            traffic_class: 7,
            peak_data_rate_bps: 9_000_000_000, // 9 Gbps
            max_payload_bytes: 1500,
            max_burst_bytes: 3000,
            max_tolerable_latency_ns: 2_000_000,
            max_tolerable_jitter_ns: 500_000,
        };

        let decision2 = engine.request_admission(flow_huge, vec![1, 2, 3]);
        match decision2 {
            DetNetAdmissionDecision::Rejected {
                flow_id,
                bottleneck_node_id,
                cause,
            } => {
                assert_eq!(flow_id, 102);
                assert_eq!(bottleneck_node_id, 1);
                assert!(cause.contains("exceeds max limit"));
            }
            DetNetAdmissionDecision::Admitted { .. } => panic!("Huge flow must be rejected"),
        }

        // Release flow1
        assert!(engine.release_reservation(101));
        assert_eq!(*engine.node_reserved_bandwidth.get(&1).unwrap(), 0);
    }
}
