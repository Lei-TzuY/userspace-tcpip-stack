//! O-RAN Alliance WG3 E2 Service Model (E2SM) Engine.
//!
//! Implements O-RAN WG3 standard service models connecting the Near-Real-Time
//! RAN Intelligent Controller (Near-RT RIC) xApps with E2 Nodes (gNB-O-DU, gNB-O-CU):
//! - E2SM-KPM (Key Performance Measurement - O-RAN.WG3.E2SM-KPM):
//!   - Real-time cell-level, slice-level, and UE-level telemetry reporting
//!   - PRB utilization, user throughput, packet delay, and loss rate metrics
//!   - Event trigger definitions and indication message framing
//! - E2SM-RC (RAN Control - O-RAN.WG3.E2SM-RC):
//!   - Closed-loop intelligent control actions (Radio Resource Allocation,
//!     Connected-mode Mobility, Traffic Steering, Slice SLA enforcement)
//!   - Control header, control message, and control outcome structures
//! - Near-RT RIC xApp Closed-Loop Intelligence Framework:
//!   - Policy-driven telemetry evaluation and automated control remediation
//!   - Direct translation of A1 policies into E2SM-RC control actions

use std::collections::HashMap;

use crate::ngap_5g::Snssai;
use crate::oran_a1_interface::SliceSlaPolicyPayload;

// ---------------------------------------------------------------------------
// Constants & Well-Known Parameter IDs (O-RAN.WG3.E2SM-KPM / E2SM-RC)
// ---------------------------------------------------------------------------

/// E2SM-KPM Service Model OID / Function ID.
pub const E2SM_KPM_RAN_FUNCTION_ID: u16 = 1;

/// E2SM-RC Service Model OID / Function ID.
pub const E2SM_RC_RAN_FUNCTION_ID: u16 = 2;

/// Well-known E2SM-RC Control Style Types.
pub const RC_STYLE_RADIO_RESOURCE_ALLOCATION: u8 = 1;
pub const RC_STYLE_CONNECTED_MODE_MOBILITY: u8 = 2;
pub const RC_STYLE_TRAFFIC_STEERING: u8 = 3;
pub const RC_STYLE_SLICE_SLA_ENFORCEMENT: u8 = 4;

/// Well-known E2SM-RC Control Action IDs.
pub const RC_ACTION_SET_PRB_QUOTA: u8 = 1;
pub const RC_ACTION_ADJUST_A3_OFFSET: u8 = 2;
pub const RC_ACTION_STEER_TRAFFIC: u8 = 3;
pub const RC_ACTION_THROTTLE_BEARER: u8 = 4;

/// Standard E2SM-RC Parameter IDs.
pub const RC_PARAM_ID_GUARANTEED_PRB_PPM: u32 = 1001;
pub const RC_PARAM_ID_MAX_PRB_PPM: u32 = 1002;
pub const RC_PARAM_ID_A3_OFFSET_DB: u32 = 2001;
pub const RC_PARAM_ID_TIME_TO_TRIGGER_MS: u32 = 2002;
pub const RC_PARAM_ID_TRAFFIC_OFFLOAD_RATIO_PPM: u32 = 3001;
pub const RC_PARAM_ID_MAX_BITRATE_KBPS: u32 = 4001;

// ---------------------------------------------------------------------------
// E2SM-KPM: Measurement Types & Metrics (O-RAN.WG3.E2SM-KPM Section 7)
// ---------------------------------------------------------------------------

/// Standard 3GPP / O-RAN KPM Measurement Types (TS 28.552 / O-RAN.WG3.E2SM-KPM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KpmMeasType {
    /// Total available DL PRBs.
    RruPrbTotDl,
    /// Total available UL PRBs.
    RruPrbTotUl,
    /// Used DL PRBs in PPM (parts-per-million, 0..1,000,000).
    RruPrbUsedDlPpm,
    /// Used UL PRBs in PPM.
    RruPrbUsedUlPpm,
    /// DL PDCP user data throughput in Mbps.
    PdcpThroughputDlMbps,
    /// UL PDCP user data throughput in Mbps.
    PdcpThroughputUlMbps,
    /// Average DL packet delay in microseconds.
    PdcpPduDelayDlUs,
    /// DL PDCP packet loss rate in PPM.
    PdcpPduLossRateDlPpm,
    /// Number of UEs in RRC_CONNECTED state.
    RrcConnActiveUeCount,
}

impl KpmMeasType {
    pub fn as_str(&self) -> &'static str {
        match self {
            KpmMeasType::RruPrbTotDl => "RRU.PrbTotDl",
            KpmMeasType::RruPrbTotUl => "RRU.PrbTotUl",
            KpmMeasType::RruPrbUsedDlPpm => "RRU.PrbUsedDl.Ppm",
            KpmMeasType::RruPrbUsedUlPpm => "RRU.PrbUsedUl.Ppm",
            KpmMeasType::PdcpThroughputDlMbps => "DRB.PdcpThroughputDl.Mbps",
            KpmMeasType::PdcpThroughputUlMbps => "DRB.PdcpThroughputUl.Mbps",
            KpmMeasType::PdcpPduDelayDlUs => "DRB.PdcpPduDelayDl.Us",
            KpmMeasType::PdcpPduLossRateDlPpm => "DRB.PdcpPduLossRateDl.Ppm",
            KpmMeasType::RrcConnActiveUeCount => "RRC.ConnActiveUeCount",
        }
    }
}

/// Generic record value for telemetry metrics.
#[derive(Debug, Clone, PartialEq)]
pub enum KpmRecordValue {
    Integer(i64),
    Real(f64),
}

/// A single measurement record in an E2SM-KPM Indication Message.
#[derive(Debug, Clone, PartialEq)]
pub struct KpmMeasurementRecord {
    pub meas_type: KpmMeasType,
    pub value: KpmRecordValue,
}

/// Slice-specific telemetry metrics (O-RAN.WG3.E2SM-KPM Section 7.4).
#[derive(Debug, Clone, PartialEq)]
pub struct KpmSliceMeasurement {
    pub s_nssai: Snssai,
    pub qfi: Option<u8>,
    pub dl_prb_usage_ppm: u32,
    pub ul_prb_usage_ppm: u32,
    pub throughput_dl_mbps: f64,
}

/// Per-UE telemetry metrics.
#[derive(Debug, Clone, PartialEq)]
pub struct KpmUeMeasurement {
    pub crnti: u16,
    pub ue_identity_5g_s_tmsi: Option<u64>,
    pub dl_throughput_mbps: f64,
    pub ul_throughput_mbps: f64,
    pub dl_packet_delay_us: u32,
    pub dl_packet_loss_ppm: u32,
}

/// E2SM-KPM Event Trigger Definition (Format 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpmEventTriggerDefinition {
    pub reporting_period_ms: u32,
}

/// E2SM-KPM Action Definition (Format 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpmActionDefinition {
    pub meas_types: Vec<KpmMeasType>,
    pub granularity_period_ms: u32,
    pub cell_global_id: Option<u64>,
}

/// E2SM-KPM Indication Header (Format 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KpmIndicationHeader {
    pub collect_start_time_epoch_ms: u64,
    pub sender_name: String,
}

/// E2SM-KPM Indication Message (Format 1 & Format 2).
#[derive(Debug, Clone, PartialEq)]
pub struct KpmIndicationMessage {
    pub cell_id: u64,
    pub cell_records: Vec<KpmMeasurementRecord>,
    pub slice_measurements: Vec<KpmSliceMeasurement>,
    pub ue_measurements: Vec<KpmUeMeasurement>,
}

// ---------------------------------------------------------------------------
// E2SM-RC: RAN Control Service Model (O-RAN.WG3.E2SM-RC Section 7)
// ---------------------------------------------------------------------------

/// Dynamic parameter value types in E2SM-RC.
#[derive(Debug, Clone, PartialEq)]
pub enum RcParameterValue {
    Integer(i64),
    Real(f64),
    Boolean(bool),
    OctetString(Vec<u8>),
}

/// Single control parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct RcControlParameter {
    pub param_id: u32,
    pub param_name: &'static str,
    pub param_value: RcParameterValue,
}

/// E2SM-RC Control Header (Format 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcControlHeader {
    pub ue_id: Option<u64>,
    pub ric_control_style_type: u8,
    pub ric_control_action_id: u8,
}

/// E2SM-RC Control Message (Format 1).
#[derive(Debug, Clone, PartialEq)]
pub struct RcControlMessage {
    pub parameters: Vec<RcControlParameter>,
}

/// E2SM-RC Control Outcome (Format 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcControlOutcome {
    pub success: bool,
    pub executed_parameter_ids: Vec<u32>,
    pub error_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Serialization / Deserialization helpers for E2AP transparent containers
// ---------------------------------------------------------------------------

impl KpmIndicationMessage {
    /// Encode to wire container bytes for embedding into E2AP `ric_indication_message`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.cell_id.to_be_bytes());

        // Cell records count
        buf.push(self.cell_records.len() as u8);
        for rec in &self.cell_records {
            let meas_code = match rec.meas_type {
                KpmMeasType::RruPrbTotDl => 1,
                KpmMeasType::RruPrbTotUl => 2,
                KpmMeasType::RruPrbUsedDlPpm => 3,
                KpmMeasType::RruPrbUsedUlPpm => 4,
                KpmMeasType::PdcpThroughputDlMbps => 5,
                KpmMeasType::PdcpThroughputUlMbps => 6,
                KpmMeasType::PdcpPduDelayDlUs => 7,
                KpmMeasType::PdcpPduLossRateDlPpm => 8,
                KpmMeasType::RrcConnActiveUeCount => 9,
            };
            buf.push(meas_code);
            match rec.value {
                KpmRecordValue::Integer(v) => {
                    buf.push(1); // 1 = Integer
                    buf.extend_from_slice(&v.to_be_bytes());
                }
                KpmRecordValue::Real(v) => {
                    buf.push(2); // 2 = Real
                    buf.extend_from_slice(&v.to_be_bytes());
                }
            }
        }

        // Slice measurements count
        buf.push(self.slice_measurements.len() as u8);
        for s in &self.slice_measurements {
            buf.push(s.s_nssai.sst);
            buf.extend_from_slice(&s.dl_prb_usage_ppm.to_be_bytes());
            buf.extend_from_slice(&s.ul_prb_usage_ppm.to_be_bytes());
            buf.extend_from_slice(&s.throughput_dl_mbps.to_be_bytes());
        }

        // UE measurements count
        buf.push(self.ue_measurements.len() as u8);
        for u in &self.ue_measurements {
            buf.extend_from_slice(&u.crnti.to_be_bytes());
            buf.extend_from_slice(&u.dl_throughput_mbps.to_be_bytes());
            buf.extend_from_slice(&u.dl_packet_delay_us.to_be_bytes());
            buf.extend_from_slice(&u.dl_packet_loss_ppm.to_be_bytes());
        }

        buf
    }

    /// Decode from wire container bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 9 {
            return None;
        }
        let mut cell_b = [0u8; 8];
        cell_b.copy_from_slice(&data[0..8]);
        let cell_id = u64::from_be_bytes(cell_b);

        let num_recs = data[8] as usize;
        let mut offset = 9;
        let mut cell_records = Vec::new();

        for _ in 0..num_recs {
            if offset + 10 > data.len() {
                return None;
            }
            let meas_type = match data[offset] {
                1 => KpmMeasType::RruPrbTotDl,
                2 => KpmMeasType::RruPrbTotUl,
                3 => KpmMeasType::RruPrbUsedDlPpm,
                4 => KpmMeasType::RruPrbUsedUlPpm,
                5 => KpmMeasType::PdcpThroughputDlMbps,
                6 => KpmMeasType::PdcpThroughputUlMbps,
                7 => KpmMeasType::PdcpPduDelayDlUs,
                8 => KpmMeasType::PdcpPduLossRateDlPpm,
                9 => KpmMeasType::RrcConnActiveUeCount,
                _ => return None,
            };
            let val_type = data[offset + 1];
            let mut val_b = [0u8; 8];
            val_b.copy_from_slice(&data[offset + 2..offset + 10]);
            offset += 10;

            let value = if val_type == 1 {
                KpmRecordValue::Integer(i64::from_be_bytes(val_b))
            } else {
                KpmRecordValue::Real(f64::from_be_bytes(val_b))
            };
            cell_records.push(KpmMeasurementRecord { meas_type, value });
        }

        if offset >= data.len() {
            return None;
        }
        let num_slices = data[offset] as usize;
        offset += 1;
        let mut slice_measurements = Vec::new();

        for _ in 0..num_slices {
            if offset + 17 > data.len() {
                return None;
            }
            let sst = data[offset];
            let mut dl_prb_b = [0u8; 4];
            dl_prb_b.copy_from_slice(&data[offset + 1..offset + 5]);
            let dl_prb_ppm = u32::from_be_bytes(dl_prb_b);

            let mut ul_prb_b = [0u8; 4];
            ul_prb_b.copy_from_slice(&data[offset + 5..offset + 9]);
            let ul_prb_ppm = u32::from_be_bytes(ul_prb_b);

            let mut tp_b = [0u8; 8];
            tp_b.copy_from_slice(&data[offset + 9..offset + 17]);
            let tp = f64::from_be_bytes(tp_b);
            offset += 17;

            slice_measurements.push(KpmSliceMeasurement {
                s_nssai: Snssai { sst, sd: None },
                qfi: None,
                dl_prb_usage_ppm: dl_prb_ppm,
                ul_prb_usage_ppm: ul_prb_ppm,
                throughput_dl_mbps: tp,
            });
        }

        if offset >= data.len() {
            return None;
        }
        let num_ues = data[offset] as usize;
        offset += 1;
        let mut ue_measurements = Vec::new();

        for _ in 0..num_ues {
            if offset + 18 > data.len() {
                return None;
            }
            let mut crnti_b = [0u8; 2];
            crnti_b.copy_from_slice(&data[offset..offset + 2]);
            let crnti = u16::from_be_bytes(crnti_b);

            let mut tp_b = [0u8; 8];
            tp_b.copy_from_slice(&data[offset + 2..offset + 10]);
            let tp = f64::from_be_bytes(tp_b);

            let mut del_b = [0u8; 4];
            del_b.copy_from_slice(&data[offset + 10..offset + 14]);
            let delay = u32::from_be_bytes(del_b);

            let mut loss_b = [0u8; 4];
            loss_b.copy_from_slice(&data[offset + 14..offset + 18]);
            let loss = u32::from_be_bytes(loss_b);
            offset += 18;

            ue_measurements.push(KpmUeMeasurement {
                crnti,
                ue_identity_5g_s_tmsi: None,
                dl_throughput_mbps: tp,
                ul_throughput_mbps: 0.0,
                dl_packet_delay_us: delay,
                dl_packet_loss_ppm: loss,
            });
        }

        Some(KpmIndicationMessage {
            cell_id,
            cell_records,
            slice_measurements,
            ue_measurements,
        })
    }
}

// ---------------------------------------------------------------------------
// Near-RT RIC xApp Closed-Loop Intelligence Framework
// ---------------------------------------------------------------------------

/// Policy rule for closed-loop xApp automation.
#[derive(Debug, Clone, PartialEq)]
pub struct SlaPolicyRule {
    pub max_prb_threshold_ppm: u32,
    pub max_packet_loss_ppm: u32,
    pub max_packet_delay_us: u32,
    pub target_prb_adjustment_ppm: u32,
}

impl Default for SlaPolicyRule {
    fn default() -> Self {
        SlaPolicyRule {
            max_prb_threshold_ppm: 850_000,     // 85%
            max_packet_loss_ppm: 1_000,         // 0.1%
            max_packet_delay_us: 5_000,         // 5 ms
            target_prb_adjustment_ppm: 100_000, // +10%
        }
    }
}

/// Near-RT RIC xApp instance executing intelligent closed-loop control.
pub struct SliceSlaAssuranceXApp {
    pub xapp_id: String,
    pub sla_rule: SlaPolicyRule,
    pub managed_cells: Vec<u64>,
    pub generated_control_actions: Vec<(RcControlHeader, RcControlMessage)>,
}

impl SliceSlaAssuranceXApp {
    /// Create a new SLA Assurance xApp.
    pub fn new(xapp_id: &str, managed_cells: Vec<u64>) -> Self {
        SliceSlaAssuranceXApp {
            xapp_id: xapp_id.to_string(),
            sla_rule: SlaPolicyRule::default(),
            managed_cells,
            generated_control_actions: Vec::new(),
        }
    }

    /// Ingest an incoming E2SM-KPM telemetry report from an E2 Node,
    /// evaluate SLA violations, and trigger closed-loop E2SM-RC control actions.
    pub fn process_kpm_indication(
        &mut self,
        kpm: &KpmIndicationMessage,
    ) -> Option<(RcControlHeader, RcControlMessage)> {
        if !self.managed_cells.contains(&kpm.cell_id) {
            return None;
        }

        // 1. Check for cell-level PRB congestion
        for rec in &kpm.cell_records {
            if rec.meas_type == KpmMeasType::RruPrbUsedDlPpm {
                if let KpmRecordValue::Integer(prb_ppm) = rec.value {
                    if prb_ppm as u32 > self.sla_rule.max_prb_threshold_ppm {
                        // Trigger E2SM-RC Control: Adjust A3 offset to shed traffic to neighbor
                        let header = RcControlHeader {
                            ue_id: None,
                            ric_control_style_type: RC_STYLE_CONNECTED_MODE_MOBILITY,
                            ric_control_action_id: RC_ACTION_ADJUST_A3_OFFSET,
                        };
                        let message = RcControlMessage {
                            parameters: vec![
                                RcControlParameter {
                                    param_id: RC_PARAM_ID_A3_OFFSET_DB,
                                    param_name: "A3-Offset-dB",
                                    param_value: RcParameterValue::Integer(-3), // Shed traffic early
                                },
                                RcControlParameter {
                                    param_id: RC_PARAM_ID_TIME_TO_TRIGGER_MS,
                                    param_name: "TimeToTrigger-ms",
                                    param_value: RcParameterValue::Integer(40),
                                },
                            ],
                        };
                        self.generated_control_actions
                            .push((header.clone(), message.clone()));
                        return Some((header, message));
                    }
                }
            }
        }

        // 2. Check for slice SLA violations (excessive delay or packet loss)
        for u in &kpm.ue_measurements {
            if u.dl_packet_delay_us > self.sla_rule.max_packet_delay_us
                || u.dl_packet_loss_ppm > self.sla_rule.max_packet_loss_ppm
            {
                // Trigger E2SM-RC Control: Allocate dedicated PRB quota for this slice / UE
                let header = RcControlHeader {
                    ue_id: Some(u.crnti as u64),
                    ric_control_style_type: RC_STYLE_SLICE_SLA_ENFORCEMENT,
                    ric_control_action_id: RC_ACTION_SET_PRB_QUOTA,
                };
                let message = RcControlMessage {
                    parameters: vec![
                        RcControlParameter {
                            param_id: RC_PARAM_ID_GUARANTEED_PRB_PPM,
                            param_name: "GuaranteedPRB-Ppm",
                            param_value: RcParameterValue::Integer(
                                self.sla_rule.target_prb_adjustment_ppm as i64,
                            ),
                        },
                        RcControlParameter {
                            param_id: RC_PARAM_ID_MAX_BITRATE_KBPS,
                            param_name: "MaxBitrate-Kbps",
                            param_value: RcParameterValue::Integer(100_000),
                        },
                    ],
                };
                self.generated_control_actions
                    .push((header.clone(), message.clone()));
                return Some((header, message));
            }
        }

        None
    }

    /// Translate an A1 Policy from Non-RT RIC into an imperative E2SM-RC Control Message.
    pub fn translate_a1_policy_to_rc_control(
        &mut self,
        policy: &SliceSlaPolicyPayload,
    ) -> (RcControlHeader, RcControlMessage) {
        let header = RcControlHeader {
            ue_id: None,
            ric_control_style_type: RC_STYLE_SLICE_SLA_ENFORCEMENT,
            ric_control_action_id: RC_ACTION_SET_PRB_QUOTA,
        };

        let message = RcControlMessage {
            parameters: vec![
                RcControlParameter {
                    param_id: RC_PARAM_ID_GUARANTEED_PRB_PPM,
                    param_name: "GuaranteedPRB-Ppm",
                    param_value: RcParameterValue::Integer(policy.guaranteed_prb_quota_ppm as i64),
                },
                RcControlParameter {
                    param_id: RC_PARAM_ID_MAX_BITRATE_KBPS,
                    param_name: "LatencyBudget-Ms",
                    param_value: RcParameterValue::Integer(policy.max_latency_ms as i64),
                },
            ],
        };

        self.generated_control_actions
            .push((header.clone(), message.clone()));
        (header, message)
    }
}

// ---------------------------------------------------------------------------
// E2SM Service Model Engine for E2 Node
// ---------------------------------------------------------------------------

/// E2 Node Service Model Engine (collects KPM telemetry and executes RC controls).
pub struct E2NodeSmEngine {
    pub cell_id: u64,
    pub current_prb_quota_ppm: u32,
    pub current_a3_offset_db: i32,
    pub executed_controls: Vec<RcControlHeader>,
}

impl E2NodeSmEngine {
    /// Create an E2 Node SM engine.
    pub fn new(cell_id: u64) -> Self {
        E2NodeSmEngine {
            cell_id,
            current_prb_quota_ppm: 0,
            current_a3_offset_db: 0,
            executed_controls: Vec::new(),
        }
    }

    /// Generate an E2SM-KPM Indication Message with real telemetry.
    pub fn collect_kpm_telemetry(
        &self,
        dl_prb_used_ppm: u32,
        dl_throughput_mbps: f64,
        active_ue_count: u32,
        slice_stats: Vec<KpmSliceMeasurement>,
        ue_stats: Vec<KpmUeMeasurement>,
    ) -> KpmIndicationMessage {
        let cell_records = vec![
            KpmMeasurementRecord {
                meas_type: KpmMeasType::RruPrbTotDl,
                value: KpmRecordValue::Integer(273), // 100MHz @ 30kHz SCS = 273 PRBs
            },
            KpmMeasurementRecord {
                meas_type: KpmMeasType::RruPrbUsedDlPpm,
                value: KpmRecordValue::Integer(dl_prb_used_ppm as i64),
            },
            KpmMeasurementRecord {
                meas_type: KpmMeasType::PdcpThroughputDlMbps,
                value: KpmRecordValue::Real(dl_throughput_mbps),
            },
            KpmMeasurementRecord {
                meas_type: KpmMeasType::RrcConnActiveUeCount,
                value: KpmRecordValue::Integer(active_ue_count as i64),
            },
        ];

        KpmIndicationMessage {
            cell_id: self.cell_id,
            cell_records,
            slice_measurements: slice_stats,
            ue_measurements: ue_stats,
        }
    }

    /// Execute an incoming E2SM-RC Control Message on the E2 Node.
    pub fn execute_rc_control(
        &mut self,
        header: &RcControlHeader,
        message: &RcControlMessage,
    ) -> RcControlOutcome {
        let mut executed = Vec::new();

        for param in &message.parameters {
            match param.param_id {
                RC_PARAM_ID_GUARANTEED_PRB_PPM => {
                    if let RcParameterValue::Integer(val) = param.param_value {
                        self.current_prb_quota_ppm = val as u32;
                        executed.push(param.param_id);
                    }
                }
                RC_PARAM_ID_A3_OFFSET_DB => {
                    if let RcParameterValue::Integer(val) = param.param_value {
                        self.current_a3_offset_db = val as i32;
                        executed.push(param.param_id);
                    }
                }
                _ => {
                    executed.push(param.param_id);
                }
            }
        }

        self.executed_controls.push(header.clone());

        RcControlOutcome {
            success: true,
            executed_parameter_ids: executed,
            error_message: None,
        }
    }
}

/// Top-level O-RAN E2SM Coordinator for Near-RT RIC.
pub struct E2smEngine {
    pub registered_nodes: HashMap<u64, E2NodeSmEngine>,
    pub xapps: Vec<SliceSlaAssuranceXApp>,
}

impl E2smEngine {
    pub fn new() -> Self {
        E2smEngine {
            registered_nodes: HashMap::new(),
            xapps: Vec::new(),
        }
    }

    pub fn register_node(&mut self, node: E2NodeSmEngine) {
        self.registered_nodes.insert(node.cell_id, node);
    }

    pub fn add_xapp(&mut self, xapp: SliceSlaAssuranceXApp) {
        self.xapps.push(xapp);
    }

    /// Ingest a KPM indication and dispatch to subscribed xApps, executing any resulting controls.
    pub fn ingest_and_remediate(&mut self, kpm: &KpmIndicationMessage) -> Vec<RcControlOutcome> {
        let mut outcomes = Vec::new();
        for xapp in &mut self.xapps {
            if let Some((header, msg)) = xapp.process_kpm_indication(kpm) {
                if let Some(node) = self.registered_nodes.get_mut(&kpm.cell_id) {
                    let outcome = node.execute_rc_control(&header, &msg);
                    outcomes.push(outcome);
                }
            }
        }
        outcomes
    }
}

impl Default for E2smEngine {
    fn default() -> Self {
        Self::new()
    }
}
