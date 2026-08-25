//! EVPN Layer 2 Port Flap Damping & Route Dampening Engine (RFC 7432 Section 16).
//!
//! Rapidly flapping physical Attachment Circuits (AC) or malfunctioning Virtual Machines
//! generating unstable MAC churn can overwhelm the BGP control plane with endless Type 2 / Type 1
//! advertisements and withdrawals.
//!
//! Route Dampening applies an exponential decay penalty algorithm:
//! 1. Each flap event adds a penalty (e.g. 1000 points).
//! 2. Penalty decays over time with a half-life $T_{half}$ (e.g. 15 seconds):
//!    $$\text{Penalty}(t) = \text{Penalty}(t_0) \times 2^{-(t - t_0) / T_{half}}$$
//! 3. When $\text{Penalty} \ge \text{SuppressThreshold}$ (e.g. 2000 points), the port/route is **Suppressed**.
//! 4. When the penalty decays below $\text{ReuseThreshold}$ (e.g. 750 points), the port/route is **Reused / Restored**.
//!
//! This module implements:
//! * Exponential decay penalty accumulator with nanosecond timestamp precision.
//! * Attachment circuit and MAC route damping state machine.
//! * Automated suppress and reuse actions.

use std::collections::HashMap;

/// Damping State of an interface or route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DampState {
    Unsuppressed,
    Suppressed,
}

/// Damping Record for an individual entity.
#[derive(Debug, Clone)]
pub struct DampEntry {
    pub name: String,
    pub penalty: f64,
    pub last_flap_timestamp_ns: Option<u64>,
    pub state: DampState,
    pub total_flaps: u64,
    pub total_suppressions: u64,
}

impl DampEntry {
    pub fn new(name: &str) -> Self {
        DampEntry {
            name: name.to_string(),
            penalty: 0.0,
            last_flap_timestamp_ns: None,
            state: DampState::Unsuppressed,
            total_flaps: 0,
            total_suppressions: 0,
        }
    }

    /// Evaluates current decayed penalty.
    pub fn current_penalty(&self, now_ns: u64, half_life_ns: u64) -> f64 {
        match self.last_flap_timestamp_ns {
            None => self.penalty,
            Some(last_ns) => {
                if now_ns <= last_ns {
                    self.penalty
                } else {
                    let elapsed_ns = now_ns - last_ns;
                    let half_lives = (elapsed_ns as f64) / (half_life_ns as f64);
                    self.penalty * (0.5f64).powf(half_lives)
                }
            }
        }
    }
}

/// EVPN Route & Port Flap Damping Engine.
#[derive(Debug, Clone)]
pub struct EvpnFlapDampingEngine {
    pub flap_penalty: f64,
    pub suppress_threshold: f64,
    pub reuse_threshold: f64,
    pub half_life_ns: u64,
    pub entries: HashMap<String, DampEntry>,
}

impl EvpnFlapDampingEngine {
    pub fn new(
        flap_penalty: f64,
        suppress_threshold: f64,
        reuse_threshold: f64,
        half_life_seconds: u64,
    ) -> Self {
        EvpnFlapDampingEngine {
            flap_penalty,
            suppress_threshold,
            reuse_threshold,
            half_life_ns: half_life_seconds * 1_000_000_000,
            entries: HashMap::new(),
        }
    }

    /// Records a flap event and evaluates if the entity should be suppressed.
    pub fn record_flap(&mut self, name: &str, now_ns: u64) -> DampState {
        let half_life_ns = self.half_life_ns;
        let flap_penalty = self.flap_penalty;
        let suppress_threshold = self.suppress_threshold;

        let entry = self
            .entries
            .entry(name.to_string())
            .or_insert_with(|| DampEntry::new(name));

        // 1. Decay previous penalty
        let decayed = entry.current_penalty(now_ns, half_life_ns);
        entry.penalty = decayed + flap_penalty;
        entry.last_flap_timestamp_ns = Some(now_ns);
        entry.total_flaps += 1;

        // 2. Check if suppress threshold exceeded
        if entry.penalty >= suppress_threshold && entry.state == DampState::Unsuppressed {
            entry.state = DampState::Suppressed;
            entry.total_suppressions += 1;
        }

        entry.state
    }

    /// Evaluates if an entity has decayed below the reuse threshold and can be unsuppressed.
    pub fn evaluate_state(&mut self, name: &str, now_ns: u64) -> DampState {
        let half_life_ns = self.half_life_ns;
        let reuse_threshold = self.reuse_threshold;

        if let Some(entry) = self.entries.get_mut(name) {
            let decayed = entry.current_penalty(now_ns, half_life_ns);
            entry.penalty = decayed;
            entry.last_flap_timestamp_ns = Some(now_ns);

            if entry.state == DampState::Suppressed && entry.penalty <= reuse_threshold {
                entry.state = DampState::Unsuppressed;
            }
            entry.state
        } else {
            DampState::Unsuppressed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evpn_flap_damping_suppress_and_reuse() {
        // Flap penalty: 1000, Suppress: 2000, Reuse: 750, Half-life: 10s
        let mut engine = EvpnFlapDampingEngine::new(1000.0, 2000.0, 750.0, 10);

        // Flap 1 at t=0s -> penalty = 1000 (Unsuppressed)
        assert_eq!(engine.record_flap("eth1", 0), DampState::Unsuppressed);

        // Flap 2 at t=1s -> penalty ≈ 1000 * 0.93 + 1000 = 1930 (Unsuppressed)
        assert_eq!(
            engine.record_flap("eth1", 1_000_000_000),
            DampState::Unsuppressed
        );

        // Flap 3 at t=2s -> penalty > 2000 -> Suppressed!
        assert_eq!(
            engine.record_flap("eth1", 2_000_000_000),
            DampState::Suppressed
        );

        // Advance time to t=25s (23 seconds since flap 3):
        // 23s is > 2 half-lives (20s). Penalty decays from ~2800 to < 700 (< 750 ReuseThreshold) -> Unsuppressed!
        assert_eq!(
            engine.evaluate_state("eth1", 25_000_000_000),
            DampState::Unsuppressed
        );
    }
}
