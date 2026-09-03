//! IEEE 802.1CM / eCPRI Time-Sensitive Networking (TSN) for Fronthaul Profile Engine.
//!
//! Standardizes bridged Ethernet fronthaul transport network profiles (Profile A and Profile B)
//! connecting 5G O-DU (Distributed Unit) and O-RU (Radio Unit), evaluates end-to-end One-Way
//! Transfer Delay (OWTD), Packet Delay Variation (PDV) jitter bounds, IEEE 802.1Qbu frame
//! preemption effects, and validates eCPRI traffic class priority mappings.

/// IEEE 802.1CM Fronthaul Profiles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ieee8021CmProfile {
    /// Profile A: Strict latency and jitter for high-performance fronthaul with Full Timing Support (FTS).
    /// - Max OWTD <= 100 µs (100,000 ns)
    /// - Max PDV <= 10 µs (10,000 ns)
    /// - Target Frame Loss Ratio (FLR) <= 10^-7
    /// - Requires ITU-T G.8275.1 + SyncE G.8262
    ProfileA,

    /// Profile B: Relaxed latency for normal-performance fronthaul with Partial Timing Support (PTS).
    /// - Max OWTD <= 1000 µs (1,000,000 ns = 1 ms)
    /// - Max PDV <= 200 µs (200,000 ns)
    /// - Target Frame Loss Ratio (FLR) <= 10^-7
    /// - Requires ITU-T G.8275.2 (APTS / PTS)
    ProfileB,
}

impl Ieee8021CmProfile {
    /// Maximum allowable One-Way Transfer Delay (OWTD) in nanoseconds.
    pub fn max_owtd_ns(&self) -> u64 {
        match self {
            Ieee8021CmProfile::ProfileA => 100_000,
            Ieee8021CmProfile::ProfileB => 1_000_000,
        }
    }

    /// Maximum allowable Packet Delay Variation (PDV) jitter in nanoseconds.
    pub fn max_pdv_ns(&self) -> u64 {
        match self {
            Ieee8021CmProfile::ProfileA => 10_000,
            Ieee8021CmProfile::ProfileB => 200_000,
        }
    }

    /// Frame Loss Ratio (FLR) bound.
    pub fn target_flr(&self) -> f64 {
        1e-7
    }

    /// Primary synchronization architecture required by this profile.
    pub fn required_sync_architecture(&self) -> &'static str {
        match self {
            Ieee8021CmProfile::ProfileA => "Full Timing Support (ITU-T G.8275.1 + SyncE G.8262)",
            Ieee8021CmProfile::ProfileB => "Partial Timing Support (ITU-T G.8275.2 APTS / PTS)",
        }
    }
}

/// eCPRI Fronthaul Traffic Classes (eCPRI Specification V2.0 / IEEE 802.1CM Clause 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcpriTrafficClass {
    /// High-Priority User Plane (eCPRI Message Type 0: In-phase & Quadrature IQ data)
    UserPlaneHigh,
    /// Normal-Priority User Plane (eCPRI Message Type 0: Delay-tolerant IQ streams)
    UserPlaneLow,
    /// Real-Time Control Plane (eCPRI Message Type 2: Beamforming & Scheduling commands)
    RealTimeControl,
    /// Time Synchronization (eCPRI Message Type 5 / IEEE 1588 PTP Event)
    Synchronization,
    /// Operations, Administration, and Maintenance (eCPRI Message Type 1: Bit sequence / OAM)
    OamManagement,
}

impl EcpriTrafficClass {
    /// Recommended IEEE 802.1Q Priority Code Point (PCP) for VLAN tagging (0 to 7).
    pub fn recommended_pcp(&self) -> u8 {
        match self {
            EcpriTrafficClass::Synchronization => 7,
            EcpriTrafficClass::UserPlaneHigh => 7,
            EcpriTrafficClass::UserPlaneLow => 6,
            EcpriTrafficClass::RealTimeControl => 5,
            EcpriTrafficClass::OamManagement => 1,
        }
    }

    /// Whether this traffic class maps to an IEEE 802.1Qbu Express Queue (non-preemptible).
    pub fn is_express_traffic(&self) -> bool {
        match self {
            EcpriTrafficClass::Synchronization | EcpriTrafficClass::UserPlaneHigh => true,
            _ => false,
        }
    }
}

/// Single TSN Bridge / Fiber Hop in the Fronthaul Network Path.
#[derive(Debug, Clone, PartialEq)]
pub struct FronthaulBridgeHop {
    pub bridge_id: String,
    /// Internal bridge forwarding & pipeline latency in nanoseconds (e.g. 1500 ns)
    pub processing_delay_ns: u64,
    /// Worst-case queuing jitter in bridge buffer without preemption in nanoseconds
    pub queuing_jitter_ns: u64,
    /// Physical optical fiber cable length in meters
    pub cable_length_meters: f64,
    /// Whether IEEE 802.1Qbu Frame Preemption is active on this egress port
    pub preemption_active: bool,
}

impl FronthaulBridgeHop {
    pub fn new(
        bridge_id: &str,
        processing_delay_ns: u64,
        queuing_jitter_ns: u64,
        cable_length_meters: f64,
        preemption_active: bool,
    ) -> Self {
        Self {
            bridge_id: bridge_id.to_string(),
            processing_delay_ns,
            queuing_jitter_ns,
            cable_length_meters,
            preemption_active,
        }
    }

    /// Optical propagation delay in silica fiber (~5.0 ns per meter / ~200,000 km/s).
    pub fn cable_delay_ns(&self) -> u64 {
        (self.cable_length_meters * 5.0).round() as u64
    }

    /// Effective queuing jitter after applying IEEE 802.1Qbu frame preemption.
    ///
    /// For Express traffic on a preemption-enabled link, interfering jumbo/MTU frames
    /// are preempted into fragments (minimum non-final fragment size ~64-124 bytes),
    /// drastically limiting maximum express queue blocking delay to <= 100 ns.
    pub fn effective_queuing_jitter_ns(&self, is_express: bool) -> u64 {
        if is_express && self.preemption_active {
            // 802.1Qbu preemption limits express queue blocking delay to fragment transmission time (~100 ns on 10G/25G)
            self.queuing_jitter_ns.min(100)
        } else {
            self.queuing_jitter_ns
        }
    }

    /// Total latency contribution of this single hop for a given traffic class.
    pub fn hop_total_delay_ns(&self, is_express: bool) -> u64 {
        self.processing_delay_ns
            + self.cable_delay_ns()
            + self.effective_queuing_jitter_ns(is_express)
    }
}

/// End-to-End Fronthaul Path Evaluation Report.
#[derive(Debug, Clone, PartialEq)]
pub struct FronthaulPathEvaluation {
    pub profile: Ieee8021CmProfile,
    pub traffic_class: EcpriTrafficClass,
    pub total_owtd_ns: u64,
    pub total_pdv_ns: u64,
    pub total_fiber_length_meters: f64,
    pub hop_count: usize,
    pub owtd_compliant: bool,
    pub pdv_compliant: bool,
    pub is_fully_compliant: bool,
}

/// IEEE 802.1CM TSN for Fronthaul Profile Engine.
#[derive(Debug, Clone)]
pub struct Ieee8021CmEngine {
    pub profile: Ieee8021CmProfile,
    pub hops: Vec<FronthaulBridgeHop>,
}

impl Ieee8021CmEngine {
    pub fn new(profile: Ieee8021CmProfile) -> Self {
        Self {
            profile,
            hops: Vec::new(),
        }
    }

    /// Appends a TSN bridge / fiber hop to the end-to-end path.
    pub fn add_bridge_hop(&mut self, hop: FronthaulBridgeHop) {
        self.hops.push(hop);
    }

    /// Clears all hops in the current path.
    pub fn clear_hops(&mut self) {
        self.hops.clear();
    }

    /// Evaluates the end-to-end path against IEEE 802.1CM profile bounds for a traffic class.
    pub fn evaluate_fronthaul_path(
        &self,
        traffic_class: EcpriTrafficClass,
    ) -> FronthaulPathEvaluation {
        let is_express = traffic_class.is_express_traffic();

        let mut total_owtd: u64 = 0;
        let mut total_pdv: u64 = 0;
        let mut total_fiber: f64 = 0.0;

        for hop in &self.hops {
            let hop_proc = hop.processing_delay_ns;
            let hop_cable = hop.cable_delay_ns();
            let hop_jitter = hop.effective_queuing_jitter_ns(is_express);

            total_owtd += hop_proc + hop_cable + hop_jitter;
            total_pdv += hop_jitter;
            total_fiber += hop.cable_length_meters;
        }

        let max_owtd = self.profile.max_owtd_ns();
        let max_pdv = self.profile.max_pdv_ns();

        let owtd_compliant = total_owtd <= max_owtd;
        let pdv_compliant = total_pdv <= max_pdv;
        let is_fully_compliant = owtd_compliant && pdv_compliant;

        FronthaulPathEvaluation {
            profile: self.profile,
            traffic_class,
            total_owtd_ns: total_owtd,
            total_pdv_ns: total_pdv,
            total_fiber_length_meters: total_fiber,
            hop_count: self.hops.len(),
            owtd_compliant,
            pdv_compliant,
            is_fully_compliant,
        }
    }

    /// Validates whether an incoming eCPRI message type and VLAN PCP priority match IEEE 802.1CM requirements.
    pub fn validate_ecpri_mapping(
        &self,
        msg_type: u8,
        pcp: u8,
    ) -> Result<EcpriTrafficClass, &'static str> {
        let class = match msg_type {
            0 => {
                if pcp >= 7 {
                    EcpriTrafficClass::UserPlaneHigh
                } else if pcp == 6 {
                    EcpriTrafficClass::UserPlaneLow
                } else {
                    return Err("eCPRI User Plane IQ data must be mapped to PCP 7 or 6");
                }
            }
            2 => {
                if pcp >= 5 {
                    EcpriTrafficClass::RealTimeControl
                } else {
                    return Err("eCPRI Real-Time Control must be mapped to PCP >= 5");
                }
            }
            5 => {
                if pcp == 7 {
                    EcpriTrafficClass::Synchronization
                } else {
                    return Err("eCPRI Synchronization must be mapped to highest priority PCP 7");
                }
            }
            1 => EcpriTrafficClass::OamManagement,
            _ => return Err("Unsupported eCPRI message type"),
        };

        Ok(class)
    }
}
