//! 3GPP TS 38.104 5G NR TDD & Time Alignment Error (TAE) Synchronization Conformance Engine.
//!
//! Evaluates end-to-end 5G TDD cell phase synchronization, Time Alignment Error (TAE) across
//! MIMO antenna branches, intra/inter-band Carrier Aggregation (CA), Coordinated Multipoint (CoMP),
//! and decomposes O-RAN / ITU-T G.8271.1 fronthaul synchronization time error budgets.

/// 3GPP TS 38.104 Section 6.5.3 Synchronization & Time Alignment Categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NrTddSyncCategory {
    /// Basic 5G TDD Cell Phase Synchronization (|TE| <= 1500 ns, Relative <= 3000 ns)
    BasicTddCellSync,
    /// MIMO or TX Diversity Transmission across antenna ports (TAE <= 65 ns)
    MimoTransmission,
    /// Intra-Band Contiguous Carrier Aggregation (TAE <= 260 ns)
    IntraBandContiguousCa,
    /// Intra-Band Non-Contiguous Carrier Aggregation (TAE <= 3000 ns)
    IntraBandNonContiguousCa,
    /// Inter-Band Carrier Aggregation (TAE <= 3000 ns)
    InterBandCa,
    /// Coordinated Multi-Point (CoMP) / Distributed MIMO across sites (Relative <= 260 ns)
    CoordinatedMultipoint,
}

impl NrTddSyncCategory {
    /// Allowable Time Alignment Error (TAE) or relative error limit in nanoseconds.
    pub fn limit_ns(&self) -> i64 {
        match self {
            NrTddSyncCategory::BasicTddCellSync => 1500,
            NrTddSyncCategory::MimoTransmission => 65,
            NrTddSyncCategory::IntraBandContiguousCa => 260,
            NrTddSyncCategory::IntraBandNonContiguousCa => 3000,
            NrTddSyncCategory::InterBandCa => 3000,
            NrTddSyncCategory::CoordinatedMultipoint => 260,
        }
    }

    /// Descriptive name of the 3GPP 38.104 requirement.
    pub fn description(&self) -> &'static str {
        match self {
            NrTddSyncCategory::BasicTddCellSync => "3GPP Basic TDD Cell Phase Synchronization",
            NrTddSyncCategory::MimoTransmission => "3GPP MIMO Transmission (TAE <= 65ns)",
            NrTddSyncCategory::IntraBandContiguousCa => {
                "3GPP Intra-Band Contiguous CA (TAE <= 260ns)"
            }
            NrTddSyncCategory::IntraBandNonContiguousCa => {
                "3GPP Intra-Band Non-Contiguous CA (TAE <= 3000ns)"
            }
            NrTddSyncCategory::InterBandCa => "3GPP Inter-Band CA (TAE <= 3000ns)",
            NrTddSyncCategory::CoordinatedMultipoint => {
                "3GPP CoMP / Distributed MIMO (Relative <= 260ns)"
            }
        }
    }
}

/// Antenna Port Time Error (TE) Measurement Sample.
#[derive(Debug, Clone, PartialEq)]
pub struct AntennaPortMeasurement {
    pub port_id: u32,
    pub antenna_group: u8,
    pub carrier_freq_mhz: f64,
    pub measured_te_ns: i64, // Time Error TE(t) at antenna connector in nanoseconds
}

impl AntennaPortMeasurement {
    pub fn new(
        port_id: u32,
        antenna_group: u8,
        carrier_freq_mhz: f64,
        measured_te_ns: i64,
    ) -> Self {
        Self {
            port_id,
            antenna_group,
            carrier_freq_mhz,
            measured_te_ns,
        }
    }
}

/// Fronthaul Synchronization Time Error Budget Partitioning (ITU-T G.8271.1 / O-RAN WG4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FronthaulBudgetPartition {
    /// PRTC / Grandmaster Time Error budget (typically <= 100 ns)
    pub prtc_budget_ns: i64,
    /// Transport Network Time Error budget (T-BC / T-TC network, typically <= 800 ns or 1100 ns)
    pub transport_network_budget_ns: i64,
    /// O-RU internal hardware & transceiver processing budget (typically <= 150 ns)
    pub ru_internal_budget_ns: i64,
    /// Remaining air interface and antenna cable margin
    pub radio_margin_ns: i64,
}

impl Default for FronthaulBudgetPartition {
    fn default() -> Self {
        // Standard O-RAN Fronthaul Category B: 100ns (PRTC) + 800ns (Transport) + 150ns (RU) + 450ns (Margin) = 1500ns
        Self {
            prtc_budget_ns: 100,
            transport_network_budget_ns: 800,
            ru_internal_budget_ns: 150,
            radio_margin_ns: 450,
        }
    }
}

impl FronthaulBudgetPartition {
    pub fn total_budget_ns(&self) -> i64 {
        self.prtc_budget_ns
            + self.transport_network_budget_ns
            + self.ru_internal_budget_ns
            + self.radio_margin_ns
    }
}

/// Fronthaul Budget Diagnostics Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetDiagnosticReport {
    pub total_measured_te_ns: i64,
    pub allowed_total_budget_ns: i64,
    pub is_total_compliant: bool,
    pub prtc_exceeded: bool,
    pub transport_exceeded: bool,
    pub ru_exceeded: bool,
    pub bottleneck_segment: Option<&'static str>,
}

/// Time Alignment Error (TAE) Evaluation Report for an Antenna Group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaeEvaluationReport {
    pub category: NrTddSyncCategory,
    pub antenna_group: u8,
    pub max_measured_tae_ns: i64,
    pub allowed_limit_ns: i64,
    pub worst_pair: (u32, u32),
    pub port_count: usize,
    pub is_compliant: bool,
}

/// Absolute Cell Phase Synchronization Compliance Report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsoluteCellSyncReport {
    pub max_abs_te_ns: i64,
    pub allowed_limit_ns: i64,
    pub violating_ports: Vec<(u32, i64)>,
    pub total_ports_evaluated: usize,
    pub is_compliant: bool,
}

/// 3GPP TS 38.104 5G NR TDD & Time Alignment Error Conformance Engine.
#[derive(Debug, Clone)]
pub struct NrTddSyncEngine {
    pub budget: FronthaulBudgetPartition,
    pub measurements: Vec<AntennaPortMeasurement>,
}

impl Default for NrTddSyncEngine {
    fn default() -> Self {
        Self::new(FronthaulBudgetPartition::default())
    }
}

impl NrTddSyncEngine {
    pub fn new(budget: FronthaulBudgetPartition) -> Self {
        Self {
            budget,
            measurements: Vec::new(),
        }
    }

    /// Ingests an antenna port measurement sample into the engine.
    pub fn add_measurement(&mut self, m: AntennaPortMeasurement) {
        if let Some(pos) = self
            .measurements
            .iter()
            .position(|p| p.port_id == m.port_id)
        {
            self.measurements[pos] = m;
        } else {
            self.measurements.push(m);
        }
    }

    /// Clears all stored antenna port measurements.
    pub fn clear(&mut self) {
        self.measurements.clear();
    }

    /// Evaluates Absolute Cell Phase Synchronization (|TE| <= 1500 ns per 3GPP 38.104).
    pub fn evaluate_absolute_cell_sync(&self) -> AbsoluteCellSyncReport {
        let limit = NrTddSyncCategory::BasicTddCellSync.limit_ns();
        let mut max_abs_te: i64 = 0;
        let mut violating_ports = Vec::new();

        for m in &self.measurements {
            let abs_te = m.measured_te_ns.abs();
            if abs_te > max_abs_te {
                max_abs_te = abs_te;
            }
            if abs_te > limit {
                violating_ports.push((m.port_id, m.measured_te_ns));
            }
        }

        let is_compliant = violating_ports.is_empty();

        AbsoluteCellSyncReport {
            max_abs_te_ns: max_abs_te,
            allowed_limit_ns: limit,
            violating_ports,
            total_ports_evaluated: self.measurements.len(),
            is_compliant,
        }
    }

    /// Evaluates Time Alignment Error (TAE) across antenna ports within a specific group.
    ///
    /// TAE is defined as the largest timing difference between any two antenna ports:
    /// TAE = max_{i, j} |TE_i - TE_j|
    pub fn evaluate_group_tae(
        &self,
        group: u8,
        category: NrTddSyncCategory,
    ) -> Option<TaeEvaluationReport> {
        let group_ports: Vec<&AntennaPortMeasurement> = self
            .measurements
            .iter()
            .filter(|m| m.antenna_group == group)
            .collect();

        if group_ports.len() < 2 {
            return None;
        }

        let mut max_tae: i64 = 0;
        let mut worst_pair = (group_ports[0].port_id, group_ports[1].port_id);

        for i in 0..group_ports.len() {
            for j in (i + 1)..group_ports.len() {
                let diff = (group_ports[i].measured_te_ns - group_ports[j].measured_te_ns).abs();
                if diff > max_tae {
                    max_tae = diff;
                    worst_pair = (group_ports[i].port_id, group_ports[j].port_id);
                }
            }
        }

        let limit = category.limit_ns();
        let is_compliant = max_tae <= limit;

        Some(TaeEvaluationReport {
            category,
            antenna_group: group,
            max_measured_tae_ns: max_tae,
            allowed_limit_ns: limit,
            worst_pair,
            port_count: group_ports.len(),
            is_compliant,
        })
    }

    /// Evaluates TAE across all distinct antenna groups configured in the engine.
    pub fn evaluate_all_groups(&self, category: NrTddSyncCategory) -> Vec<TaeEvaluationReport> {
        let mut groups: Vec<u8> = self.measurements.iter().map(|m| m.antenna_group).collect();
        groups.sort_unstable();
        groups.dedup();

        groups
            .into_iter()
            .filter_map(|g| self.evaluate_group_tae(g, category))
            .collect()
    }

    /// Evaluates Relative Cell Phase Synchronization between any two antenna ports in the network
    /// (e.g. adjacent cells in basic TDD <= 3000 ns, or CoMP <= 260 ns).
    pub fn evaluate_inter_cell_phase_sync(
        &self,
        max_relative_limit_ns: i64,
    ) -> Result<(), (u32, u32, i64)> {
        let n = self.measurements.len();
        for i in 0..n {
            for j in (i + 1)..n {
                let diff = (self.measurements[i].measured_te_ns
                    - self.measurements[j].measured_te_ns)
                    .abs();
                if diff > max_relative_limit_ns {
                    return Err((
                        self.measurements[i].port_id,
                        self.measurements[j].port_id,
                        diff,
                    ));
                }
            }
        }
        Ok(())
    }

    /// Decomposes and pinpoints fronthaul synchronization budget violations across segments.
    pub fn diagnose_fronthaul_budget(
        &self,
        measured_prtc_ns: i64,
        measured_transport_ns: i64,
        measured_ru_ns: i64,
    ) -> BudgetDiagnosticReport {
        let prtc_abs = measured_prtc_ns.abs();
        let transport_abs = measured_transport_ns.abs();
        let ru_abs = measured_ru_ns.abs();

        let total_measured = prtc_abs + transport_abs + ru_abs;
        let allowed_total = self.budget.total_budget_ns();

        let prtc_exceeded = prtc_abs > self.budget.prtc_budget_ns;
        let transport_exceeded = transport_abs > self.budget.transport_network_budget_ns;
        let ru_exceeded = ru_abs > self.budget.ru_internal_budget_ns;

        let bottleneck = if transport_exceeded {
            Some("Fronthaul Transport Network (T-BC / Packet Jitter)")
        } else if prtc_exceeded {
            Some("PRTC / Primary Reference Grandmaster Clock")
        } else if ru_exceeded {
            Some("O-RU Internal Timestamping / Baseband PLL")
        } else if total_measured > allowed_total {
            Some("Cumulative Margin Exhaustion across Segments")
        } else {
            None
        };

        BudgetDiagnosticReport {
            total_measured_te_ns: total_measured,
            allowed_total_budget_ns: allowed_total,
            is_total_compliant: total_measured <= allowed_total,
            prtc_exceeded,
            transport_exceeded,
            ru_exceeded,
            bottleneck_segment: bottleneck,
        }
    }
}
