//! PTP Packet Delay Variation (PDV) Floor Filter & Min-Delay Estimator (ITU-T G.8275.2 / IEEE 1588 Annex C)
//!
//! Provides sliding-window min-delay floor selection, queuing jitter rejection,
//! outlier filtering, and stable phase offset estimation across packet-switched networks
//! lacking full on-path timing support.
//!
//! # Standard References
//! - ITU-T Recommendation G.8275.2: Precision time protocol telecom profile for phase/time synchronization with partial timing support
//! - IEEE Std 1588-2019: Standard for a Precision Clock Synchronization Protocol (Annex C: Network Impairments)

use std::collections::VecDeque;

/// A PTP Four-Timestamp Measurement Sample (t1, t2, t3, t4 in nanoseconds)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpTimestampSample {
    pub seq_id: u16,
    pub t1_master_tx: i64,
    pub t2_slave_rx: i64,
    pub t3_slave_tx: i64,
    pub t4_master_rx: i64,
}

impl PtpTimestampSample {
    pub fn new(seq_id: u16, t1: i64, t2: i64, t3: i64, t4: i64) -> Self {
        Self {
            seq_id,
            t1_master_tx: t1,
            t2_slave_rx: t2,
            t3_slave_tx: t3,
            t4_master_rx: t4,
        }
    }

    /// Raw forward delay: (t2 - t1)
    pub fn forward_delay(&self) -> i64 {
        self.t2_slave_rx - self.t1_master_tx
    }

    /// Raw reverse delay: (t4 - t3)
    pub fn reverse_delay(&self) -> i64 {
        self.t4_master_rx - self.t3_slave_tx
    }
}

/// Filtered PTP Synchronization Estimate
#[derive(Debug, Clone, PartialEq)]
pub struct PtpFilteredEstimate {
    pub forward_delay_floor_ns: i64,
    pub reverse_delay_floor_ns: i64,
    pub mean_path_delay_ns: i64,
    pub estimated_offset_ns: i64,
    pub forward_pdv_spread_ns: i64,
    pub reverse_pdv_spread_ns: i64,
    pub floor_population_ratio: f64,
    pub valid_samples_in_window: usize,
}

/// PTP PDV Floor Filter & Min-Delay Estimator
#[derive(Debug, Clone)]
pub struct PtpPdvFloorFilter {
    pub window_size: usize,
    pub floor_threshold_percent: f64, // e.g. 5.0% lowest delay
    pub max_cluster_spread_ns: i64,   // Max allowable spread within floor cluster
    pub samples: VecDeque<PtpTimestampSample>,
    pub asymmetry_compensation_ns: i64,
    pub delay_asymmetry_ratio: Option<f64>,
    pub smoothed_offset_ns: Option<f64>,
}

/// PTP Time Error Conformance Metrics (ITU-T G.8271 / G.8275.1 / G.8275.2)
#[derive(Debug, Clone, PartialEq)]
pub struct PtpTimeErrorMetrics {
    /// Constant Time Error (cTE): Average phase offset across the measurement window (ns)
    pub cte_ns: f64,
    /// Dynamic Time Error (dTE): Peak-to-peak phase fluctuation around the mean (ns)
    pub dte_peak_to_peak_ns: i64,
    /// Maximum Absolute Time Error: max(|TE(t)|) across the observation interval (ns)
    pub max_abs_te_ns: i64,
    /// Sample count evaluated
    pub sample_count: usize,
}

impl PtpPdvFloorFilter {
    pub fn new(
        window_size: usize,
        floor_threshold_percent: f64,
        max_cluster_spread_ns: i64,
    ) -> Self {
        Self {
            window_size: window_size.max(4),
            floor_threshold_percent: floor_threshold_percent.clamp(0.01, 50.0),
            max_cluster_spread_ns: max_cluster_spread_ns.max(10),
            samples: VecDeque::with_capacity(window_size),
            asymmetry_compensation_ns: 0,
            delay_asymmetry_ratio: None,
            smoothed_offset_ns: None,
        }
    }

    pub fn with_asymmetry_compensation(mut self, asym_ns: i64) -> Self {
        self.asymmetry_compensation_ns = asym_ns;
        self
    }

    /// Sets the dynamic delay asymmetry ratio alpha = T_fwd / T_rev (IEEE 1588-2019 Clause 9.5.5 / ITU-T G.8271).
    ///
    /// In Single-Fiber Bidirectional (BiDi) WDM optical networks, different wavelengths (e.g. 1310/1550nm)
    /// exhibit chromatic velocity differences resulting in asymmetry proportional to the total fiber delay:
    /// Asymmetry_dynamic = ((1 - alpha) / (1 + alpha)) * RoundTripDelay
    pub fn with_delay_asymmetry_ratio(mut self, alpha: f64) -> Self {
        self.delay_asymmetry_ratio = Some(alpha);
        self
    }

    /// Ingest a new PTP timestamp measurement sample into the sliding window
    pub fn push_sample(&mut self, sample: PtpTimestampSample) {
        if self.samples.len() >= self.window_size {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);
    }

    /// Reset filter history
    pub fn clear(&mut self) {
        self.samples.clear();
    }

    /// Computes Constant Time Error (cTE) and Dynamic Time Error (dTE) metrics
    /// across the current sample window.
    pub fn compute_time_error_metrics(&self) -> Option<PtpTimeErrorMetrics> {
        let n = self.samples.len();
        if n < 4 {
            return None;
        }

        let offsets: Vec<i64> = self
            .samples
            .iter()
            .map(|s| (s.forward_delay() - s.reverse_delay()) / 2)
            .collect();

        let sum: i64 = offsets.iter().sum();
        let cte = sum as f64 / n as f64;

        let min_offset = *offsets.iter().min().unwrap();
        let max_offset = *offsets.iter().max().unwrap();
        let dte_peak_to_peak = max_offset - min_offset;

        let max_abs = offsets.iter().map(|&o| o.abs()).max().unwrap();

        Some(PtpTimeErrorMetrics {
            cte_ns: cte,
            dte_peak_to_peak_ns: dte_peak_to_peak,
            max_abs_te_ns: max_abs,
            sample_count: n,
        })
    }

    /// Filters extreme delay spikes using Interquartile Range (IQR) outlier detection.
    pub fn filter_iqr_outliers(delays: &[i64]) -> Vec<i64> {
        if delays.len() < 4 {
            return delays.to_vec();
        }
        let mut sorted = delays.to_vec();
        sorted.sort();

        let n = sorted.len();
        let q1 = sorted[n / 4];
        let q3 = sorted[(3 * n) / 4];
        let iqr = q3 - q1;
        let upper_cutoff = q3.saturating_add(iqr.saturating_mul(3));

        sorted.into_iter().filter(|&d| d <= upper_cutoff).collect()
    }

    /// Partitions sliding window into subwindows, selects the minimum-delay "lucky packet"
    /// per subwindow, and aggregates to prevent sample bunching under bursty queuing.
    pub fn compute_subwindow_lucky_estimate(
        &self,
        subwindow_count: usize,
    ) -> Option<PtpFilteredEstimate> {
        let n = self.samples.len();
        let k = subwindow_count.max(2);
        if n < k * 2 {
            return self.compute_estimate();
        }

        let chunk_size = n / k;
        let sample_vec: Vec<&PtpTimestampSample> = self.samples.iter().collect();
        let mut fwd_floors = Vec::with_capacity(k);
        let mut rev_floors = Vec::with_capacity(k);

        for chunk in sample_vec.chunks(chunk_size) {
            if chunk.is_empty() {
                continue;
            }
            let min_fwd = chunk.iter().map(|s| s.forward_delay()).min().unwrap();
            let min_rev = chunk.iter().map(|s| s.reverse_delay()).min().unwrap();
            fwd_floors.push(min_fwd);
            rev_floors.push(min_rev);
        }

        if fwd_floors.is_empty() {
            return None;
        }

        let fwd_avg = fwd_floors.iter().sum::<i64>() / fwd_floors.len() as i64;
        let rev_avg = rev_floors.iter().sum::<i64>() / rev_floors.len() as i64;

        let estimated_offset = (fwd_avg - rev_avg) / 2;
        let mean_path_delay = (fwd_avg + rev_avg) / 2;

        let fwd_spread = fwd_floors.iter().max().unwrap() - fwd_floors.iter().min().unwrap();
        let rev_spread = rev_floors.iter().max().unwrap() - rev_floors.iter().min().unwrap();

        Some(PtpFilteredEstimate {
            forward_delay_floor_ns: fwd_avg,
            reverse_delay_floor_ns: rev_avg,
            mean_path_delay_ns: mean_path_delay,
            estimated_offset_ns: estimated_offset,
            forward_pdv_spread_ns: fwd_spread,
            reverse_pdv_spread_ns: rev_spread,
            floor_population_ratio: fwd_floors.len() as f64 / n as f64,
            valid_samples_in_window: n,
        })
    }

    /// Compute filtered phase offset and mean path delay using the window floor estimator
    pub fn compute_estimate(&self) -> Option<PtpFilteredEstimate> {
        let n = self.samples.len();
        if n < 4 {
            return None;
        }

        let mut fwd_delays: Vec<i64> = self.samples.iter().map(|s| s.forward_delay()).collect();
        let mut rev_delays: Vec<i64> = self.samples.iter().map(|s| s.reverse_delay()).collect();

        fwd_delays.sort();
        rev_delays.sort();

        let floor_count =
            ((n as f64 * (self.floor_threshold_percent / 100.0)).ceil() as usize).max(1);

        // Compute average of the lowest `floor_count` delays to reduce discretization noise
        let fwd_floor_slice = &fwd_delays[0..floor_count];
        let rev_floor_slice = &rev_delays[0..floor_count];

        let fwd_floor_avg = fwd_floor_slice.iter().sum::<i64>() / floor_count as i64;
        let rev_floor_avg = rev_floor_slice.iter().sum::<i64>() / floor_count as i64;

        let fwd_spread = fwd_delays[n - 1] - fwd_delays[0];
        let rev_spread = rev_delays[n - 1] - rev_delays[0];

        // Standard two-way offset calculation on filtered delay floors with static + dynamic WDM asymmetry compensation:
        let dynamic_asym = if let Some(alpha) = self.delay_asymmetry_ratio {
            if alpha > 0.0 {
                let round_trip = (fwd_floor_avg + rev_floor_avg) as f64;
                ((1.0 - alpha) / (1.0 + alpha)) * round_trip
            } else {
                0.0
            }
        } else {
            0.0
        };
        let total_asymmetry = self.asymmetry_compensation_ns + dynamic_asym.round() as i64;

        // offset = ((d_fwd - d_rev) - total_asymmetry) / 2
        let estimated_offset = ((fwd_floor_avg - rev_floor_avg) - total_asymmetry) / 2;
        // meanPathDelay = (d_fwd + d_rev) / 2
        let mean_path_delay = (fwd_floor_avg + rev_floor_avg) / 2;

        // Ratio of samples within cluster spread of the floor
        let fwd_cluster_count = fwd_delays
            .iter()
            .filter(|&&d| (d - fwd_delays[0]) <= self.max_cluster_spread_ns)
            .count();
        let floor_population_ratio = fwd_cluster_count as f64 / n as f64;

        Some(PtpFilteredEstimate {
            forward_delay_floor_ns: fwd_floor_avg,
            reverse_delay_floor_ns: rev_floor_avg,
            mean_path_delay_ns: mean_path_delay,
            estimated_offset_ns: estimated_offset,
            forward_pdv_spread_ns: fwd_spread,
            reverse_pdv_spread_ns: rev_spread,
            floor_population_ratio,
            valid_samples_in_window: n,
        })
    }

    /// Estimates delay floors by building a delay histogram and locating the primary floor cluster bin,
    /// providing robust noise immunity against multi-modal queuing delay distributions (ITU-T G.8275.2 Annex D).
    pub fn compute_histogram_floor_estimate(
        &self,
        bin_width_ns: i64,
    ) -> Option<PtpFilteredEstimate> {
        let n = self.samples.len();
        if n < 4 {
            return None;
        }
        let bw = bin_width_ns.max(10);

        let fwd_delays: Vec<i64> = self.samples.iter().map(|s| s.forward_delay()).collect();
        let rev_delays: Vec<i64> = self.samples.iter().map(|s| s.reverse_delay()).collect();

        let min_fwd = *fwd_delays.iter().min().unwrap();
        let min_rev = *rev_delays.iter().min().unwrap();

        // Bin forward delays
        let mut fwd_bins: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::new();
        for &d in &fwd_delays {
            let bin_idx = (d - min_fwd) / bw;
            fwd_bins.entry(bin_idx).or_default().push(d);
        }

        // Bin reverse delays
        let mut rev_bins: std::collections::HashMap<i64, Vec<i64>> =
            std::collections::HashMap::new();
        for &d in &rev_delays {
            let bin_idx = (d - min_rev) / bw;
            rev_bins.entry(bin_idx).or_default().push(d);
        }

        // Locate dominant floor cluster within the lowest bins
        let fwd_floor_bin = (0..=2)
            .filter_map(|idx| fwd_bins.get(&idx).map(|v| (idx, v)))
            .max_by_key(|(_, v)| v.len())
            .map(|(_, v)| v)
            .or_else(|| fwd_bins.get(&0))?;

        let rev_floor_bin = (0..=2)
            .filter_map(|idx| rev_bins.get(&idx).map(|v| (idx, v)))
            .max_by_key(|(_, v)| v.len())
            .map(|(_, v)| v)
            .or_else(|| rev_bins.get(&0))?;

        let fwd_floor_avg = fwd_floor_bin.iter().sum::<i64>() / fwd_floor_bin.len() as i64;
        let rev_floor_avg = rev_floor_bin.iter().sum::<i64>() / rev_floor_bin.len() as i64;

        let dynamic_asym = if let Some(alpha) = self.delay_asymmetry_ratio {
            if alpha > 0.0 {
                let round_trip = (fwd_floor_avg + rev_floor_avg) as f64;
                ((1.0 - alpha) / (1.0 + alpha)) * round_trip
            } else {
                0.0
            }
        } else {
            0.0
        };

        let total_asym = self.asymmetry_compensation_ns + dynamic_asym.round() as i64;
        let estimated_offset = ((fwd_floor_avg - rev_floor_avg) - total_asym) / 2;
        let mean_path_delay = (fwd_floor_avg + rev_floor_avg) / 2;

        let max_fwd = *fwd_delays.iter().max().unwrap();
        let max_rev = *rev_delays.iter().max().unwrap();

        Some(PtpFilteredEstimate {
            forward_delay_floor_ns: fwd_floor_avg,
            reverse_delay_floor_ns: rev_floor_avg,
            mean_path_delay_ns: mean_path_delay,
            estimated_offset_ns: estimated_offset,
            forward_pdv_spread_ns: max_fwd - min_fwd,
            reverse_pdv_spread_ns: max_rev - min_rev,
            floor_population_ratio: fwd_floor_bin.len() as f64 / n as f64,
            valid_samples_in_window: n,
        })
    }

    /// Evaluates forward vs reverse Packet Delay Variation (PDV) correlation and computes
    /// an overall composite Path Stability Score (0.0 to 100.0).
    pub fn compute_pdv_correlation_and_stability(
        &self,
        floor_width_ns: i64,
    ) -> Option<PdvPathStabilityReport> {
        let n = self.samples.len();
        if n < 4 {
            return None;
        }

        let fwd: Vec<f64> = self
            .samples
            .iter()
            .map(|s| s.forward_delay() as f64)
            .collect();
        let rev: Vec<f64> = self
            .samples
            .iter()
            .map(|s| s.reverse_delay() as f64)
            .collect();

        let mean_fwd = fwd.iter().sum::<f64>() / n as f64;
        let mean_rev = rev.iter().sum::<f64>() / n as f64;

        let mut var_fwd = 0.0;
        let mut var_rev = 0.0;
        let mut cov = 0.0;

        for i in 0..n {
            let df = fwd[i] - mean_fwd;
            let dr = rev[i] - mean_rev;
            var_fwd += df * df;
            var_rev += dr * dr;
            cov += df * dr;
        }

        var_fwd /= n as f64;
        var_rev /= n as f64;
        cov /= n as f64;

        let std_fwd = var_fwd.sqrt();
        let std_rev = var_rev.sqrt();

        let pearson = if std_fwd > 1e-9 && std_rev > 1e-9 {
            (cov / (std_fwd * std_rev)).clamp(-1.0, 1.0)
        } else {
            0.0
        };

        let (fwd_floor_pct, rev_floor_pct) = self.floor_packet_percentage(floor_width_ns);
        let min_floor_pct = fwd_floor_pct.min(rev_floor_pct);

        // Path Stability Score (0.0 to 100.0):
        // 1. Floor density component (up to 70 points)
        let density_score = (min_floor_pct / 100.0) * 70.0;

        // 2. Jitter penalty: standard deviation in microseconds
        let avg_jitter_us = ((std_fwd + std_rev) / 2.0) / 1_000.0;
        let jitter_score = (30.0 - avg_jitter_us.min(30.0)).max(0.0);

        let raw_score = density_score + jitter_score;
        let final_score = raw_score.clamp(0.0, 100.0);

        Some(PdvPathStabilityReport {
            pearson_correlation: pearson,
            path_stability_score: final_score,
            forward_floor_density_percent: fwd_floor_pct,
            reverse_floor_density_percent: rev_floor_pct,
            forward_pdv_variance_ns2: var_fwd,
            reverse_pdv_variance_ns2: var_rev,
        })
    }

    /// Computes percentage of samples in the window within `floor_width_ns` of the minimum delay
    /// for forward and reverse directions: `(fwd_percent, rev_percent)` (ITU-T G.8275.2 Section 6.2).
    pub fn floor_packet_percentage(&self, floor_width_ns: i64) -> (f64, f64) {
        let n = self.samples.len();
        if n == 0 {
            return (0.0, 0.0);
        }

        let min_fwd = self
            .samples
            .iter()
            .map(|s| s.forward_delay())
            .min()
            .unwrap();
        let min_rev = self
            .samples
            .iter()
            .map(|s| s.reverse_delay())
            .min()
            .unwrap();

        let fwd_floor_count = self
            .samples
            .iter()
            .filter(|s| s.forward_delay() <= min_fwd + floor_width_ns)
            .count();
        let rev_floor_count = self
            .samples
            .iter()
            .filter(|s| s.reverse_delay() <= min_rev + floor_width_ns)
            .count();

        (
            (fwd_floor_count as f64 / n as f64) * 100.0,
            (rev_floor_count as f64 / n as f64) * 100.0,
        )
    }

    /// Evaluates whether the floor packet rate in both forward and reverse paths meets the minimum
    /// operational threshold required to maintain phase synchronization lock (ITU-T G.8275.2).
    pub fn is_floor_rate_adequate(&self, min_rate_percent: f64, floor_width_ns: i64) -> bool {
        let (fwd_rate, rev_rate) = self.floor_packet_percentage(floor_width_ns);
        fwd_rate >= min_rate_percent && rev_rate >= min_rate_percent
    }

    /// Updates and returns the exponential moving average (EMA) of the estimated phase offset
    /// with smoothing factor `alpha` in range (0.0, 1.0].
    pub fn update_smoothed_offset(&mut self, alpha: f64) -> Option<f64> {
        let current_estimate = self.compute_estimate()?;
        let raw_offset = current_estimate.estimated_offset_ns as f64;
        let clamped_alpha = alpha.clamp(0.001, 1.0);

        let new_smoothed = match self.smoothed_offset_ns {
            Some(prev) => prev * (1.0 - clamped_alpha) + raw_offset * clamped_alpha,
            None => raw_offset,
        };
        self.smoothed_offset_ns = Some(new_smoothed);
        Some(new_smoothed)
    }

    /// Detects whether an abrupt forward or reverse delay step occurred in the sliding window,
    /// indicating an underlying network path reroute (e.g. MPLS/SR reroute, ECMP switch).
    pub fn detect_delay_step(&self, step_threshold_ns: i64) -> Option<DelayStepEvent> {
        let n = self.samples.len();
        if n < 8 {
            return None;
        }

        let k = (n / 4).clamp(2, 10);
        let older_count = n - k;

        let older_min_fwd = self
            .samples
            .iter()
            .take(older_count)
            .map(|s| s.forward_delay())
            .min()?;
        let older_min_rev = self
            .samples
            .iter()
            .take(older_count)
            .map(|s| s.reverse_delay())
            .min()?;

        let recent_min_fwd = self
            .samples
            .iter()
            .skip(older_count)
            .map(|s| s.forward_delay())
            .min()?;
        let recent_min_rev = self
            .samples
            .iter()
            .skip(older_count)
            .map(|s| s.reverse_delay())
            .min()?;

        let fwd_step = recent_min_fwd - older_min_fwd;
        let rev_step = recent_min_rev - older_min_rev;

        if fwd_step.abs() >= step_threshold_ns || rev_step.abs() >= step_threshold_ns {
            let last_seq = self.samples.back().map(|s| s.seq_id).unwrap_or(0);
            Some(DelayStepEvent {
                forward_step_ns: fwd_step,
                reverse_step_ns: rev_step,
                detected_at_seq: last_seq,
            })
        } else {
            None
        }
    }

    /// Detects route delay steps, and if found, purges stale pre-reroute samples from the window
    /// to immediately realign the floor estimator to the new network path.
    pub fn flush_on_route_step(&mut self, step_threshold_ns: i64) -> Option<DelayStepEvent> {
        let event = self.detect_delay_step(step_threshold_ns)?;
        let n = self.samples.len();
        let k = (n / 4).clamp(2, 10);

        // Retain only the post-step recent k samples
        let recent: Vec<PtpTimestampSample> = self.samples.iter().skip(n - k).cloned().collect();
        self.samples.clear();
        for s in recent {
            self.samples.push_back(s);
        }
        self.smoothed_offset_ns = None;
        Some(event)
    }
}

/// Network Route Change / Delay Step Event in Packet Switched Network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayStepEvent {
    pub forward_step_ns: i64,
    pub reverse_step_ns: i64,
    pub detected_at_seq: u16,
}

/// Directional Packet Delay Variation (PDV) Correlation and Path Stability Report.
#[derive(Debug, Clone, PartialEq)]
pub struct PdvPathStabilityReport {
    /// Pearson correlation coefficient between forward and reverse queuing jitter (-1.0 to 1.0)
    pub pearson_correlation: f64,
    /// Composite timing path stability rating (0.0 to 100.0)
    pub path_stability_score: f64,
    /// Percentage of packets meeting forward delay floor threshold (%)
    pub forward_floor_density_percent: f64,
    /// Percentage of packets meeting reverse delay floor threshold (%)
    pub reverse_floor_density_percent: f64,
    /// Forward delay variance in ns^2
    pub forward_pdv_variance_ns2: f64,
    /// Reverse delay variance in ns^2
    pub reverse_pdv_variance_ns2: f64,
}

/// PTP Clock Servo Phase-Lock State (IEEE 1588-2019 / ITU-T G.8275.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpClockServoState {
    /// Uninitialized or awaiting initial sample
    Unset,
    /// Stepping clock counter directly to align epoch
    Stepping,
    /// Phase slewing towards target
    Aligning,
    /// Phase offset and frequency disciplined within telecom lock threshold
    Locked,
    /// Packet updates stopped; maintaining frequency offset in holdover
    Holdover,
}

/// Action output produced by the PTP Clock Servo for local clock discipline.
#[derive(Debug, Clone, PartialEq)]
pub enum PtpServoAction {
    /// Immediate phase step requested for large time error
    Step { step_ns: i64 },
    /// Frequency discipline (ppb) and phase slewing adjustment
    AdjustFreq { freq_ppb: f64, phase_adjust_ns: i64 },
    /// Holdover state: maintain frozen frequency offset
    Holdover { drift_ppb: f64 },
}

/// Configuration parameters for the PTP PI Clock Servo.
#[derive(Debug, Clone, PartialEq)]
pub struct PtpClockServoConfig {
    /// Proportional gain coefficient
    pub kp: f64,
    /// Integral gain coefficient
    pub ki: f64,
    /// Phase error threshold (ns) exceeding which an immediate step is performed
    pub step_threshold_ns: i64,
    /// Target phase error bound (ns) to consider the clock locked (e.g. 50ns)
    pub lock_threshold_ns: i64,
    /// Number of consecutive locked samples required before declaring Locked state
    pub lock_consecutive_count: usize,
    /// Maximum allowed frequency offset in parts-per-billion (e.g. 100,000 ppb = 100 ppm)
    pub max_frequency_offset_ppb: f64,
    /// Anti-windup limit for integrated phase error (ns)
    pub max_integral_windup_ns: f64,
}

impl Default for PtpClockServoConfig {
    fn default() -> Self {
        Self {
            kp: 0.7,
            ki: 0.3,
            step_threshold_ns: 100_000, // 100 µs
            lock_threshold_ns: 50,      // 50 ns (Class C / D requirement)
            lock_consecutive_count: 4,
            max_frequency_offset_ppb: 100_000.0, // ±100 ppm
            max_integral_windup_ns: 1_000_000.0,
        }
    }
}

/// PTP Proportional-Integral (PI) Clock Servo with Anti-Windup (IEEE 1588-2019 / ITU-T G.8275.2).
#[derive(Debug, Clone)]
pub struct PtpClockServo {
    pub config: PtpClockServoConfig,
    pub state: PtpClockServoState,
    pub integrated_error_ns: f64,
    pub current_freq_ppb: f64,
    pub consecutive_locked: usize,
    pub total_step_ns: i64,
    pub samples_processed: usize,
}

impl Default for PtpClockServo {
    fn default() -> Self {
        Self::new(PtpClockServoConfig::default())
    }
}

impl PtpClockServo {
    pub fn new(config: PtpClockServoConfig) -> Self {
        Self {
            config,
            state: PtpClockServoState::Unset,
            integrated_error_ns: 0.0,
            current_freq_ppb: 0.0,
            consecutive_locked: 0,
            total_step_ns: 0,
            samples_processed: 0,
        }
    }

    /// Returns current servo operating state.
    pub fn state(&self) -> PtpClockServoState {
        self.state
    }

    /// Returns whether the servo is currently in Locked state.
    pub fn is_locked(&self) -> bool {
        self.state == PtpClockServoState::Locked
    }

    /// Returns the current disciplined frequency offset in ppb.
    pub fn current_freq_ppb(&self) -> f64 {
        self.current_freq_ppb
    }

    /// Returns total cumulative phase stepped by the servo.
    pub fn total_step_ns(&self) -> i64 {
        self.total_step_ns
    }

    /// Resets the servo state machine and clears integral history.
    pub fn reset(&mut self) {
        self.state = PtpClockServoState::Unset;
        self.integrated_error_ns = 0.0;
        self.current_freq_ppb = 0.0;
        self.consecutive_locked = 0;
    }

    /// Transitions the clock into Holdover, freezing the current frequency discipline.
    pub fn enter_holdover(&mut self) -> PtpServoAction {
        self.state = PtpClockServoState::Holdover;
        self.consecutive_locked = 0;
        PtpServoAction::Holdover {
            drift_ppb: self.current_freq_ppb,
        }
    }

    /// Samples a new estimated phase offset and calculates local clock discipline action.
    ///
    /// # Arguments
    /// - `offset_ns`: Filtered phase error in nanoseconds (t_master - t_slave)
    /// - `interval_sec`: Sample interval in seconds (e.g. 0.0625s for 16 pkts/s)
    pub fn sample(&mut self, offset_ns: i64, interval_sec: f64) -> PtpServoAction {
        self.samples_processed += 1;
        let dt = interval_sec.max(0.001);

        // If in Unset state or phase offset exceeds step threshold, command a phase step
        if self.state == PtpClockServoState::Unset
            || self.state == PtpClockServoState::Stepping
            || offset_ns.abs() >= self.config.step_threshold_ns
        {
            self.state = PtpClockServoState::Aligning;
            self.consecutive_locked = 0;
            self.total_step_ns += offset_ns;
            self.integrated_error_ns = 0.0;
            return PtpServoAction::Step { step_ns: offset_ns };
        }

        // Proportional term
        let p_term = self.config.kp * (offset_ns as f64);

        // Integral term with Anti-Windup Clamping
        self.integrated_error_ns += (offset_ns as f64) * dt;
        let max_w = self.config.max_integral_windup_ns;
        self.integrated_error_ns = self.integrated_error_ns.clamp(-max_w, max_w);
        let i_term = self.config.ki * self.integrated_error_ns;

        // Target frequency adjustment in ppb (negative feedback)
        let raw_freq = -(p_term + i_term);
        let max_f = self.config.max_frequency_offset_ppb;
        self.current_freq_ppb = raw_freq.clamp(-max_f, max_f);

        // Update phase lock state machine
        if offset_ns.abs() <= self.config.lock_threshold_ns {
            self.consecutive_locked += 1;
            if self.consecutive_locked >= self.config.lock_consecutive_count {
                self.state = PtpClockServoState::Locked;
            }
        } else if offset_ns.abs() > self.config.lock_threshold_ns * 3 {
            self.consecutive_locked = 0;
            if self.state == PtpClockServoState::Locked {
                self.state = PtpClockServoState::Aligning;
            }
        }

        PtpServoAction::AdjustFreq {
            freq_ppb: self.current_freq_ppb,
            phase_adjust_ns: offset_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptp_pdv_floor_filter_rejection_and_convergence() {
        let mut filter = PtpPdvFloorFilter::new(20, 10.0, 100);

        // True one-way delay = 10,000 ns (10 µs)
        // True clock offset = +500 ns
        // So base t2 - t1 = 10,000 + 500 = 10,500 ns
        // base t4 - t3 = 10,000 - 500 = 9,500 ns

        // Inject 20 samples with occasional queuing spikes (+50,000 ns PDV jitter)
        for i in 0..20 {
            let jitter_fwd = if i % 4 == 0 { 0 } else { i as i64 * 3_000 }; // Spikes up to +57 µs
            let jitter_rev = if i % 4 == 0 { 0 } else { i as i64 * 4_000 };

            let t1 = (i as i64) * 1_000_000;
            let t2 = t1 + 10_500 + jitter_fwd;
            let t3 = t2 + 100_000;
            let t4 = t3 + 9_500 + jitter_rev;

            filter.push_sample(PtpTimestampSample::new(i as u16, t1, t2, t3, t4));
        }

        let estimate = filter.compute_estimate().expect("Expected valid estimate");

        // Delay floors should lock onto the true minimum delay of 10,500 ns and 9,500 ns
        assert_eq!(estimate.forward_delay_floor_ns, 10_500);
        assert_eq!(estimate.reverse_delay_floor_ns, 9_500);
        assert_eq!(estimate.mean_path_delay_ns, 10_000);
        assert_eq!(estimate.estimated_offset_ns, 500);
        assert!(estimate.forward_pdv_spread_ns > 0);
    }
}
