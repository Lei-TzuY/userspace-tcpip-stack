//! 3GPP TS 38.331 5G NR Radio Resource Control (RRC) Protocol Engine.
//!
//! Implements 5G NR Layer 3 Control Plane signaling between UE and gNB (gNB-CU-CP):
//! - RRC State Machine (`RRC_IDLE`, `RRC_INACTIVE`, `RRC_CONNECTED`)
//! - Broadcast System Information: MIB (MasterInformationBlock) & SIB1
//! - Signaling Radio Bearers (SRB0, SRB1, SRB2, SRB3) and DRB configuration
//! - Procedures:
//!   - Connection Establishment (`RrcSetupRequest`, `RrcSetup`, `RrcSetupComplete` with NAS)
//!   - Reconfiguration (`RrcReconfiguration`, `RrcReconfigurationComplete`)
//!   - Release with Suspend (`RrcRelease` with `SuspendConfig` into `RRC_INACTIVE`)
//!   - Connection Resume (`RrcResumeRequest`, `RrcResume`, `RrcResumeComplete`)
//!   - Re-establishment (`RrcReestablishmentRequest`, `RrcReestablishment`, `RrcReestablishmentComplete`)
//!   - Paging & Measurement Reporting
//! - RRC container binary serialization/deserialization for F1AP/PDCP transport

use std::collections::HashMap;

use crate::ngap_5g::PlmnId;

// ---------------------------------------------------------------------------
// Constants & Identifiers (TS 38.331 Section 6)
// ---------------------------------------------------------------------------

/// Maximum number of DRBs per UE (TS 38.331 Section 6.3.2).
pub const RRC_MAX_DRBS: usize = 32;

/// Signaling Radio Bearer (SRB) Identifiers.
pub const SRB0_ID: u8 = 0; // CCCH, transparent RLC TM
pub const SRB1_ID: u8 = 1; // DCCH, AM RLC, carries RRC & initial NAS
pub const SRB2_ID: u8 = 2; // DCCH, AM RLC, carries NAS after security activation
pub const SRB3_ID: u8 = 3; // DCCH, AM RLC, used in MR-DC / EN-DC

// ---------------------------------------------------------------------------
// RRC State Machine (TS 38.331 Section 4.2.1)
// ---------------------------------------------------------------------------

/// Operating state of a 5G NR UE's RRC entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcState {
    /// RRC_IDLE: No RRC connection established; UE monitors paging and SIBs.
    RrcIdle,
    /// RRC_INACTIVE: Connection suspended; AS context stored; fast resume via I-RNTI.
    RrcInactive,
    /// RRC_CONNECTED: Active RRC connection; SRBs and optional DRBs configured.
    RrcConnected,
}

// ---------------------------------------------------------------------------
// Establishment & Resume Causes (TS 38.331 Section 6.2.2)
// ---------------------------------------------------------------------------

/// Establishment causes in RrcSetupRequest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcEstablishmentCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    MoVideoCall = 6,
    MoSms = 7,
    MpsPriorityAccess = 8,
    McsPriorityAccess = 9,
}

impl RrcEstablishmentCause {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(RrcEstablishmentCause::Emergency),
            1 => Some(RrcEstablishmentCause::HighPriorityAccess),
            2 => Some(RrcEstablishmentCause::MtAccess),
            3 => Some(RrcEstablishmentCause::MoSignalling),
            4 => Some(RrcEstablishmentCause::MoData),
            5 => Some(RrcEstablishmentCause::MoVoiceCall),
            6 => Some(RrcEstablishmentCause::MoVideoCall),
            7 => Some(RrcEstablishmentCause::MoSms),
            8 => Some(RrcEstablishmentCause::MpsPriorityAccess),
            9 => Some(RrcEstablishmentCause::McsPriorityAccess),
            _ => None,
        }
    }
}

/// Resume causes in RrcResumeRequest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcResumeCause {
    Emergency = 0,
    HighPriorityAccess = 1,
    MtAccess = 2,
    MoSignalling = 3,
    MoData = 4,
    MoVoiceCall = 5,
    RnaUpdate = 6,
}

impl RrcResumeCause {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(RrcResumeCause::Emergency),
            1 => Some(RrcResumeCause::HighPriorityAccess),
            2 => Some(RrcResumeCause::MtAccess),
            3 => Some(RrcResumeCause::MoSignalling),
            4 => Some(RrcResumeCause::MoData),
            5 => Some(RrcResumeCause::MoVoiceCall),
            6 => Some(RrcResumeCause::RnaUpdate),
            _ => None,
        }
    }
}

/// Causes for RRC Re-establishment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcReestablishmentCause {
    ReconfigurationFailure = 0,
    HandoverFailure = 1,
    OtherFailure = 2,
}

impl RrcReestablishmentCause {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(RrcReestablishmentCause::ReconfigurationFailure),
            1 => Some(RrcReestablishmentCause::HandoverFailure),
            2 => Some(RrcReestablishmentCause::OtherFailure),
            _ => None,
        }
    }
}

/// Causes for RRC Release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcReleaseCause {
    Other = 0,
    RrcSuspend = 1,
    LoadBalancingTauRequired = 2,
}

impl RrcReleaseCause {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(RrcReleaseCause::Other),
            1 => Some(RrcReleaseCause::RrcSuspend),
            2 => Some(RrcReleaseCause::LoadBalancingTauRequired),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Radio Bearer & Security Configuration (TS 38.331 Section 6.3.2)
// ---------------------------------------------------------------------------

/// RLC operating mode configured by RRC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcRlcMode {
    Transparent,
    Unacknowledged,
    Acknowledged,
}

/// Configuration for an SRB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcSrbConfig {
    pub srb_id: u8,
    pub rlc_mode: RrcRlcMode,
}

/// Configuration for a Data Radio Bearer (DRB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcDrbConfig {
    pub drb_id: u8,
    pub qfi_list: Vec<u8>,
    pub pdcp_sn_size_bits: u8, // 12 or 18
    pub rlc_mode: RrcRlcMode,
}

/// Ciphering & Integrity algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipheringAlgorithm {
    Nea0 = 0, // Null
    Nea1 = 1, // SNOW 3G
    Nea2 = 2, // 128-AES
    Nea3 = 3, // 128-ZUC
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityAlgorithm {
    Nia0 = 0, // Null
    Nia1 = 1, // SNOW 3G
    Nia2 = 2, // 128-AES
    Nia3 = 3, // 128-ZUC
}

/// Security configuration for AS security.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityConfig {
    pub ciphering: CipheringAlgorithm,
    pub integrity: IntegrityAlgorithm,
    pub security_activated: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        SecurityConfig {
            ciphering: CipheringAlgorithm::Nea2,
            integrity: IntegrityAlgorithm::Nia2,
            security_activated: false,
        }
    }
}

/// Radio Bearer Configuration container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioBearerConfig {
    pub srb_to_add_mod_list: Vec<RrcSrbConfig>,
    pub drb_to_add_mod_list: Vec<RrcDrbConfig>,
    pub drb_to_release_list: Vec<u8>,
    pub security_config: Option<SecurityConfig>,
}

impl RadioBearerConfig {
    pub fn new() -> Self {
        RadioBearerConfig {
            srb_to_add_mod_list: Vec::new(),
            drb_to_add_mod_list: Vec::new(),
            drb_to_release_list: Vec::new(),
            security_config: None,
        }
    }
}

impl Default for RadioBearerConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// System Information: MIB & SIB1 (TS 38.331 Section 5.2)
// ---------------------------------------------------------------------------

/// MasterInformationBlock (MIB) broadcast over BCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterInformationBlock {
    pub system_frame_number: u16,   // 0..1023
    pub subcarrier_spacing_khz: u8, // 15 or 30 (FR1), 60 or 120 (FR2)
    pub ssb_subcarrier_offset: u8,  // 0..15 (k_SSB)
    pub dmrs_type_a_position: u8,   // 2 or 3
    pub pdcch_config_sib1: u8,
    pub cell_barred: bool,
    pub intra_freq_reselection: bool,
}

/// SystemInformationBlockType1 (SIB1) broadcast over DL-SCH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInformationBlockType1 {
    pub plmn: PlmnId,
    pub tac: u32,
    pub cell_identity: u64,   // 36-bit NR Cell Identity
    pub q_rx_lev_min_dbm: i8, // e.g. -70
    pub ranac: Option<u16>,   // RAN Area Code for RRC_INACTIVE
    pub si_window_length_slots: u8,
}

// ---------------------------------------------------------------------------
// Inactive / Suspend Configuration (TS 38.331 Section 6.3.2)
// ---------------------------------------------------------------------------

/// Configuration for UE transitioning to RRC_INACTIVE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuspendConfig {
    pub full_i_rnti: u64,
    pub short_i_rnti: u32,
    pub ran_paging_cycle_rf: u16,
    pub t380_periodic_ran_update_mins: u16,
}

// ---------------------------------------------------------------------------
// Measurement Reporting & Paging (TS 38.331 Section 5.5, 5.3.2)
// ---------------------------------------------------------------------------

/// Serving cell measurement results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasResultServingCell {
    pub rsrp_dbm: i16,
    pub rsrq_db: i16,
    pub sinr_db: i16,
}

/// Measurement Report message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeasurementReport {
    pub meas_id: u8,
    pub serving_cell_results: MeasResultServingCell,
}

/// Paging record for UE notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingRecord {
    pub ue_identity_5g_s_tmsi: u64,
    pub access_type_non_3gpp: bool,
}

/// Paging message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagingMessage {
    pub paging_records: Vec<PagingRecord>,
}

// ---------------------------------------------------------------------------
// RRC Procedures & Messages (TS 38.331 Section 6.2.2)
// ---------------------------------------------------------------------------

/// RrcSetupRequest (UL, SRB0 / CCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcSetupRequest {
    pub ue_identity: u64, // 5G-S-TMSI or 39-bit random value
    pub establishment_cause: RrcEstablishmentCause,
}

/// RrcSetup (DL, SRB0 / CCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcSetup {
    pub rrc_transaction_identifier: u8,
    pub radio_bearer_config: RadioBearerConfig,
    pub master_cell_group_allocated_crnti: u16,
}

/// RrcSetupComplete (UL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcSetupComplete {
    pub rrc_transaction_identifier: u8,
    pub selected_plmn_id: PlmnId,
    pub dedicated_nas_message: Vec<u8>,
}

/// RrcReconfiguration (DL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcReconfiguration {
    pub rrc_transaction_identifier: u8,
    pub radio_bearer_config: Option<RadioBearerConfig>,
}

/// RrcReconfigurationComplete (UL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcReconfigurationComplete {
    pub rrc_transaction_identifier: u8,
}

/// RrcRelease (DL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcRelease {
    pub rrc_transaction_identifier: u8,
    pub release_cause: RrcReleaseCause,
    pub suspend_config: Option<SuspendConfig>,
}

/// RrcResumeRequest (UL, SRB0 / CCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcResumeRequest {
    pub resume_identity_short_i_rnti: u32,
    pub resume_cause: RrcResumeCause,
    pub short_mac_i: u16,
}

/// RrcResume (DL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcResume {
    pub rrc_transaction_identifier: u8,
    pub radio_bearer_config: Option<RadioBearerConfig>,
}

/// RrcResumeComplete (UL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcResumeComplete {
    pub rrc_transaction_identifier: u8,
    pub dedicated_nas_message: Option<Vec<u8>>,
}

/// RrcReestablishmentRequest (UL, SRB0 / CCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcReestablishmentRequest {
    pub crnti: u16,
    pub phys_cell_id: u16,
    pub short_mac_i: u16,
    pub reestablishment_cause: RrcReestablishmentCause,
}

/// RrcReestablishment (DL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcReestablishment {
    pub rrc_transaction_identifier: u8,
    pub next_hop_chaining_count: u8,
}

/// RrcReestablishmentComplete (UL, SRB1 / DCCH).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcReestablishmentComplete {
    pub rrc_transaction_identifier: u8,
}

// ---------------------------------------------------------------------------
// RRC Top-Level Message Enum & Binary Serialization
// ---------------------------------------------------------------------------

/// Message type discriminator for wire containers.
pub const RRC_MSG_TYPE_SETUP_REQUEST: u8 = 1;
pub const RRC_MSG_TYPE_SETUP: u8 = 2;
pub const RRC_MSG_TYPE_SETUP_COMPLETE: u8 = 3;
pub const RRC_MSG_TYPE_RECONFIG: u8 = 4;
pub const RRC_MSG_TYPE_RECONFIG_COMPLETE: u8 = 5;
pub const RRC_MSG_TYPE_RELEASE: u8 = 6;
pub const RRC_MSG_TYPE_RESUME_REQUEST: u8 = 7;
pub const RRC_MSG_TYPE_RESUME: u8 = 8;
pub const RRC_MSG_TYPE_RESUME_COMPLETE: u8 = 9;
pub const RRC_MSG_TYPE_REESTABLISH_REQUEST: u8 = 10;
pub const RRC_MSG_TYPE_REESTABLISH: u8 = 11;
pub const RRC_MSG_TYPE_REESTABLISH_COMPLETE: u8 = 12;
pub const RRC_MSG_TYPE_PAGING: u8 = 13;
pub const RRC_MSG_TYPE_MEAS_REPORT: u8 = 14;

/// Unified RRC message enum representing any PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RrcMessage {
    SetupRequest(RrcSetupRequest),
    Setup(RrcSetup),
    SetupComplete(RrcSetupComplete),
    Reconfiguration(RrcReconfiguration),
    ReconfigurationComplete(RrcReconfigurationComplete),
    Release(RrcRelease),
    ResumeRequest(RrcResumeRequest),
    Resume(RrcResume),
    ResumeComplete(RrcResumeComplete),
    ReestablishmentRequest(RrcReestablishmentRequest),
    Reestablishment(RrcReestablishment),
    ReestablishmentComplete(RrcReestablishmentComplete),
    Paging(PagingMessage),
    MeasurementReport(MeasurementReport),
}

impl RrcMessage {
    /// Serialize this RRC message into a wire container byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            RrcMessage::SetupRequest(req) => {
                buf.push(RRC_MSG_TYPE_SETUP_REQUEST);
                buf.extend_from_slice(&req.ue_identity.to_be_bytes());
                buf.push(req.establishment_cause as u8);
            }
            RrcMessage::Setup(setup) => {
                buf.push(RRC_MSG_TYPE_SETUP);
                buf.push(setup.rrc_transaction_identifier);
                buf.extend_from_slice(&setup.master_cell_group_allocated_crnti.to_be_bytes());
                // Number of SRBs
                buf.push(setup.radio_bearer_config.srb_to_add_mod_list.len() as u8);
                for srb in &setup.radio_bearer_config.srb_to_add_mod_list {
                    buf.push(srb.srb_id);
                    buf.push(srb.rlc_mode as u8);
                }
                // Number of DRBs
                buf.push(setup.radio_bearer_config.drb_to_add_mod_list.len() as u8);
                for drb in &setup.radio_bearer_config.drb_to_add_mod_list {
                    buf.push(drb.drb_id);
                    buf.push(drb.pdcp_sn_size_bits);
                    buf.push(drb.rlc_mode as u8);
                    buf.push(drb.qfi_list.len() as u8);
                    buf.extend_from_slice(&drb.qfi_list);
                }
            }
            RrcMessage::SetupComplete(comp) => {
                buf.push(RRC_MSG_TYPE_SETUP_COMPLETE);
                buf.push(comp.rrc_transaction_identifier);
                buf.extend_from_slice(&comp.selected_plmn_id.mcc);
                buf.extend_from_slice(&comp.selected_plmn_id.mnc);
                buf.extend_from_slice(&(comp.dedicated_nas_message.len() as u16).to_be_bytes());
                buf.extend_from_slice(&comp.dedicated_nas_message);
            }
            RrcMessage::Reconfiguration(reconfig) => {
                buf.push(RRC_MSG_TYPE_RECONFIG);
                buf.push(reconfig.rrc_transaction_identifier);
                if let Some(ref rbc) = reconfig.radio_bearer_config {
                    buf.push(1); // has RBC
                    buf.push(rbc.drb_to_add_mod_list.len() as u8);
                    for drb in &rbc.drb_to_add_mod_list {
                        buf.push(drb.drb_id);
                        buf.push(drb.pdcp_sn_size_bits);
                        buf.push(drb.rlc_mode as u8);
                        buf.push(drb.qfi_list.len() as u8);
                        buf.extend_from_slice(&drb.qfi_list);
                    }
                } else {
                    buf.push(0);
                }
            }
            RrcMessage::ReconfigurationComplete(comp) => {
                buf.push(RRC_MSG_TYPE_RECONFIG_COMPLETE);
                buf.push(comp.rrc_transaction_identifier);
            }
            RrcMessage::Release(rel) => {
                buf.push(RRC_MSG_TYPE_RELEASE);
                buf.push(rel.rrc_transaction_identifier);
                buf.push(rel.release_cause as u8);
                if let Some(ref sc) = rel.suspend_config {
                    buf.push(1); // has suspend config
                    buf.extend_from_slice(&sc.full_i_rnti.to_be_bytes());
                    buf.extend_from_slice(&sc.short_i_rnti.to_be_bytes());
                    buf.extend_from_slice(&sc.ran_paging_cycle_rf.to_be_bytes());
                    buf.extend_from_slice(&sc.t380_periodic_ran_update_mins.to_be_bytes());
                } else {
                    buf.push(0);
                }
            }
            RrcMessage::ResumeRequest(req) => {
                buf.push(RRC_MSG_TYPE_RESUME_REQUEST);
                buf.extend_from_slice(&req.resume_identity_short_i_rnti.to_be_bytes());
                buf.push(req.resume_cause as u8);
                buf.extend_from_slice(&req.short_mac_i.to_be_bytes());
            }
            RrcMessage::Resume(res) => {
                buf.push(RRC_MSG_TYPE_RESUME);
                buf.push(res.rrc_transaction_identifier);
            }
            RrcMessage::ResumeComplete(comp) => {
                buf.push(RRC_MSG_TYPE_RESUME_COMPLETE);
                buf.push(comp.rrc_transaction_identifier);
            }
            RrcMessage::ReestablishmentRequest(req) => {
                buf.push(RRC_MSG_TYPE_REESTABLISH_REQUEST);
                buf.extend_from_slice(&req.crnti.to_be_bytes());
                buf.extend_from_slice(&req.phys_cell_id.to_be_bytes());
                buf.extend_from_slice(&req.short_mac_i.to_be_bytes());
                buf.push(req.reestablishment_cause as u8);
            }
            RrcMessage::Reestablishment(res) => {
                buf.push(RRC_MSG_TYPE_REESTABLISH);
                buf.push(res.rrc_transaction_identifier);
                buf.push(res.next_hop_chaining_count);
            }
            RrcMessage::ReestablishmentComplete(comp) => {
                buf.push(RRC_MSG_TYPE_REESTABLISH_COMPLETE);
                buf.push(comp.rrc_transaction_identifier);
            }
            RrcMessage::Paging(paging) => {
                buf.push(RRC_MSG_TYPE_PAGING);
                buf.push(paging.paging_records.len() as u8);
                for rec in &paging.paging_records {
                    buf.extend_from_slice(&rec.ue_identity_5g_s_tmsi.to_be_bytes());
                    buf.push(if rec.access_type_non_3gpp { 1 } else { 0 });
                }
            }
            RrcMessage::MeasurementReport(rep) => {
                buf.push(RRC_MSG_TYPE_MEAS_REPORT);
                buf.push(rep.meas_id);
                buf.extend_from_slice(&rep.serving_cell_results.rsrp_dbm.to_be_bytes());
                buf.extend_from_slice(&rep.serving_cell_results.rsrq_db.to_be_bytes());
                buf.extend_from_slice(&rep.serving_cell_results.sinr_db.to_be_bytes());
            }
        }
        buf
    }

    /// Parse an RRC message from wire container bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let msg_type = data[0];
        match msg_type {
            RRC_MSG_TYPE_SETUP_REQUEST => {
                if data.len() < 10 {
                    return None;
                }
                let mut ue_id_bytes = [0u8; 8];
                ue_id_bytes.copy_from_slice(&data[1..9]);
                let ue_identity = u64::from_be_bytes(ue_id_bytes);
                let establishment_cause = RrcEstablishmentCause::from_u8(data[9])?;
                Some(RrcMessage::SetupRequest(RrcSetupRequest {
                    ue_identity,
                    establishment_cause,
                }))
            }
            RRC_MSG_TYPE_SETUP => {
                if data.len() < 5 {
                    return None;
                }
                let tid = data[1];
                let mut crnti_bytes = [0u8; 2];
                crnti_bytes.copy_from_slice(&data[2..4]);
                let crnti = u16::from_be_bytes(crnti_bytes);

                let mut offset = 4;
                let num_srbs = data[offset] as usize;
                offset += 1;
                let mut srb_list = Vec::new();
                for _ in 0..num_srbs {
                    if offset + 2 > data.len() {
                        return None;
                    }
                    let srb_id = data[offset];
                    let rlc_mode = match data[offset + 1] {
                        0 => RrcRlcMode::Transparent,
                        1 => RrcRlcMode::Unacknowledged,
                        _ => RrcRlcMode::Acknowledged,
                    };
                    srb_list.push(RrcSrbConfig { srb_id, rlc_mode });
                    offset += 2;
                }

                if offset >= data.len() {
                    return None;
                }
                let num_drbs = data[offset] as usize;
                offset += 1;
                let mut drb_list = Vec::new();
                for _ in 0..num_drbs {
                    if offset + 4 > data.len() {
                        return None;
                    }
                    let drb_id = data[offset];
                    let pdcp_sn = data[offset + 1];
                    let rlc_mode = match data[offset + 2] {
                        0 => RrcRlcMode::Transparent,
                        1 => RrcRlcMode::Unacknowledged,
                        _ => RrcRlcMode::Acknowledged,
                    };
                    let qfi_len = data[offset + 3] as usize;
                    offset += 4;
                    if offset + qfi_len > data.len() {
                        return None;
                    }
                    let qfi_list = data[offset..offset + qfi_len].to_vec();
                    offset += qfi_len;
                    drb_list.push(RrcDrbConfig {
                        drb_id,
                        qfi_list,
                        pdcp_sn_size_bits: pdcp_sn,
                        rlc_mode,
                    });
                }

                Some(RrcMessage::Setup(RrcSetup {
                    rrc_transaction_identifier: tid,
                    radio_bearer_config: RadioBearerConfig {
                        srb_to_add_mod_list: srb_list,
                        drb_to_add_mod_list: drb_list,
                        drb_to_release_list: Vec::new(),
                        security_config: None,
                    },
                    master_cell_group_allocated_crnti: crnti,
                }))
            }
            RRC_MSG_TYPE_SETUP_COMPLETE => {
                if data.len() < 10 {
                    return None;
                }
                let tid = data[1];
                let mut mcc = [0u8; 3];
                mcc.copy_from_slice(&data[2..5]);
                let mut mnc = [0u8; 3];
                mnc.copy_from_slice(&data[5..8]);
                let mut len_bytes = [0u8; 2];
                len_bytes.copy_from_slice(&data[8..10]);
                let nas_len = u16::from_be_bytes(len_bytes) as usize;
                if data.len() < 10 + nas_len {
                    return None;
                }
                let nas_pdu = data[10..10 + nas_len].to_vec();
                Some(RrcMessage::SetupComplete(RrcSetupComplete {
                    rrc_transaction_identifier: tid,
                    selected_plmn_id: PlmnId { mcc, mnc },
                    dedicated_nas_message: nas_pdu,
                }))
            }
            RRC_MSG_TYPE_RECONFIG => {
                if data.len() < 3 {
                    return None;
                }
                let tid = data[1];
                let has_rbc = data[2] != 0;
                let radio_bearer_config = if has_rbc {
                    let mut offset = 3;
                    if offset >= data.len() {
                        return None;
                    }
                    let num_drbs = data[offset] as usize;
                    offset += 1;
                    let mut drb_list = Vec::new();
                    for _ in 0..num_drbs {
                        if offset + 4 > data.len() {
                            return None;
                        }
                        let drb_id = data[offset];
                        let pdcp_sn = data[offset + 1];
                        let rlc_mode = match data[offset + 2] {
                            0 => RrcRlcMode::Transparent,
                            1 => RrcRlcMode::Unacknowledged,
                            _ => RrcRlcMode::Acknowledged,
                        };
                        let qfi_len = data[offset + 3] as usize;
                        offset += 4;
                        if offset + qfi_len > data.len() {
                            return None;
                        }
                        let qfi_list = data[offset..offset + qfi_len].to_vec();
                        offset += qfi_len;
                        drb_list.push(RrcDrbConfig {
                            drb_id,
                            qfi_list,
                            pdcp_sn_size_bits: pdcp_sn,
                            rlc_mode,
                        });
                    }
                    Some(RadioBearerConfig {
                        srb_to_add_mod_list: Vec::new(),
                        drb_to_add_mod_list: drb_list,
                        drb_to_release_list: Vec::new(),
                        security_config: None,
                    })
                } else {
                    None
                };
                Some(RrcMessage::Reconfiguration(RrcReconfiguration {
                    rrc_transaction_identifier: tid,
                    radio_bearer_config,
                }))
            }
            RRC_MSG_TYPE_RECONFIG_COMPLETE => {
                if data.len() < 2 {
                    return None;
                }
                Some(RrcMessage::ReconfigurationComplete(
                    RrcReconfigurationComplete {
                        rrc_transaction_identifier: data[1],
                    },
                ))
            }
            RRC_MSG_TYPE_RELEASE => {
                if data.len() < 4 {
                    return None;
                }
                let tid = data[1];
                let release_cause = RrcReleaseCause::from_u8(data[2])?;
                let has_suspend = data[3] != 0;
                let suspend_config = if has_suspend {
                    if data.len() < 20 {
                        return None;
                    }
                    let mut full_i_bytes = [0u8; 8];
                    full_i_bytes.copy_from_slice(&data[4..12]);
                    let full_i_rnti = u64::from_be_bytes(full_i_bytes);

                    let mut short_i_bytes = [0u8; 4];
                    short_i_bytes.copy_from_slice(&data[12..16]);
                    let short_i_rnti = u32::from_be_bytes(short_i_bytes);

                    let mut paging_bytes = [0u8; 2];
                    paging_bytes.copy_from_slice(&data[16..18]);
                    let ran_paging_cycle_rf = u16::from_be_bytes(paging_bytes);

                    let mut t380_bytes = [0u8; 2];
                    t380_bytes.copy_from_slice(&data[18..20]);
                    let t380_periodic_ran_update_mins = u16::from_be_bytes(t380_bytes);

                    Some(SuspendConfig {
                        full_i_rnti,
                        short_i_rnti,
                        ran_paging_cycle_rf,
                        t380_periodic_ran_update_mins,
                    })
                } else {
                    None
                };
                Some(RrcMessage::Release(RrcRelease {
                    rrc_transaction_identifier: tid,
                    release_cause,
                    suspend_config,
                }))
            }
            RRC_MSG_TYPE_RESUME_REQUEST => {
                if data.len() < 8 {
                    return None;
                }
                let mut short_i_bytes = [0u8; 4];
                short_i_bytes.copy_from_slice(&data[1..5]);
                let resume_identity_short_i_rnti = u32::from_be_bytes(short_i_bytes);
                let resume_cause = RrcResumeCause::from_u8(data[5])?;
                let mut mac_bytes = [0u8; 2];
                mac_bytes.copy_from_slice(&data[6..8]);
                let short_mac_i = u16::from_be_bytes(mac_bytes);
                Some(RrcMessage::ResumeRequest(RrcResumeRequest {
                    resume_identity_short_i_rnti,
                    resume_cause,
                    short_mac_i,
                }))
            }
            RRC_MSG_TYPE_RESUME => {
                if data.len() < 2 {
                    return None;
                }
                Some(RrcMessage::Resume(RrcResume {
                    rrc_transaction_identifier: data[1],
                    radio_bearer_config: None,
                }))
            }
            RRC_MSG_TYPE_RESUME_COMPLETE => {
                if data.len() < 2 {
                    return None;
                }
                Some(RrcMessage::ResumeComplete(RrcResumeComplete {
                    rrc_transaction_identifier: data[1],
                    dedicated_nas_message: None,
                }))
            }
            RRC_MSG_TYPE_REESTABLISH_REQUEST => {
                if data.len() < 8 {
                    return None;
                }
                let mut crnti_bytes = [0u8; 2];
                crnti_bytes.copy_from_slice(&data[1..3]);
                let crnti = u16::from_be_bytes(crnti_bytes);

                let mut pci_bytes = [0u8; 2];
                pci_bytes.copy_from_slice(&data[3..5]);
                let phys_cell_id = u16::from_be_bytes(pci_bytes);

                let mut mac_bytes = [0u8; 2];
                mac_bytes.copy_from_slice(&data[5..7]);
                let short_mac_i = u16::from_be_bytes(mac_bytes);

                let reestablishment_cause = RrcReestablishmentCause::from_u8(data[7])?;
                Some(RrcMessage::ReestablishmentRequest(
                    RrcReestablishmentRequest {
                        crnti,
                        phys_cell_id,
                        short_mac_i,
                        reestablishment_cause,
                    },
                ))
            }
            RRC_MSG_TYPE_REESTABLISH => {
                if data.len() < 3 {
                    return None;
                }
                Some(RrcMessage::Reestablishment(RrcReestablishment {
                    rrc_transaction_identifier: data[1],
                    next_hop_chaining_count: data[2],
                }))
            }
            RRC_MSG_TYPE_REESTABLISH_COMPLETE => {
                if data.len() < 2 {
                    return None;
                }
                Some(RrcMessage::ReestablishmentComplete(
                    RrcReestablishmentComplete {
                        rrc_transaction_identifier: data[1],
                    },
                ))
            }
            RRC_MSG_TYPE_PAGING => {
                if data.len() < 2 {
                    return None;
                }
                let num_records = data[1] as usize;
                let mut offset = 2;
                let mut records = Vec::new();
                for _ in 0..num_records {
                    if offset + 9 > data.len() {
                        return None;
                    }
                    let mut ue_bytes = [0u8; 8];
                    ue_bytes.copy_from_slice(&data[offset..offset + 8]);
                    let ue_identity_5g_s_tmsi = u64::from_be_bytes(ue_bytes);
                    let access_type_non_3gpp = data[offset + 8] != 0;
                    offset += 9;
                    records.push(PagingRecord {
                        ue_identity_5g_s_tmsi,
                        access_type_non_3gpp,
                    });
                }
                Some(RrcMessage::Paging(PagingMessage {
                    paging_records: records,
                }))
            }
            RRC_MSG_TYPE_MEAS_REPORT => {
                if data.len() < 8 {
                    return None;
                }
                let meas_id = data[1];
                let mut rsrp_b = [0u8; 2];
                rsrp_b.copy_from_slice(&data[2..4]);
                let mut rsrq_b = [0u8; 2];
                rsrq_b.copy_from_slice(&data[4..6]);
                let mut sinr_b = [0u8; 2];
                sinr_b.copy_from_slice(&data[6..8]);
                Some(RrcMessage::MeasurementReport(MeasurementReport {
                    meas_id,
                    serving_cell_results: MeasResultServingCell {
                        rsrp_dbm: i16::from_be_bytes(rsrp_b),
                        rsrq_db: i16::from_be_bytes(rsrq_b),
                        sinr_db: i16::from_be_bytes(sinr_b),
                    },
                }))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// RRC UE Context & Entity (TS 38.331 Section 5)
// ---------------------------------------------------------------------------

/// Role of the RRC entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RrcRole {
    Ue,
    Gnb,
}

/// UE Context maintained on gNB or UE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrcUeContext {
    pub crnti: u16,
    pub ue_identity: u64, // 5G-S-TMSI or random identity
    pub state: RrcState,
    pub srbs: HashMap<u8, RrcSrbConfig>,
    pub drbs: HashMap<u8, RrcDrbConfig>,
    pub security: SecurityConfig,
    pub suspend_config: Option<SuspendConfig>,
    pub selected_plmn: Option<PlmnId>,
    pub last_nas_pdu: Option<Vec<u8>>,
}

impl RrcUeContext {
    pub fn new(crnti: u16, ue_identity: u64) -> Self {
        let mut srbs = HashMap::new();
        // SRB0 is always available
        srbs.insert(
            SRB0_ID,
            RrcSrbConfig {
                srb_id: SRB0_ID,
                rlc_mode: RrcRlcMode::Transparent,
            },
        );
        RrcUeContext {
            crnti,
            ue_identity,
            state: RrcState::RrcIdle,
            srbs,
            drbs: HashMap::new(),
            security: SecurityConfig::default(),
            suspend_config: None,
            selected_plmn: None,
            last_nas_pdu: None,
        }
    }
}

/// Top-level RRC protocol engine.
pub struct RrcEngine {
    pub role: RrcRole,
    /// UE Contexts indexed by C-RNTI (for gNB) or single context (for UE).
    pub contexts: HashMap<u16, RrcUeContext>,
    /// Suspended contexts indexed by short_i_rnti for fast resume (gNB side).
    pub suspended_contexts: HashMap<u32, u16>, // short_i_rnti -> crnti
    /// Broadcast MIB configuration.
    pub mib: Option<MasterInformationBlock>,
    /// Broadcast SIB1 configuration.
    pub sib1: Option<SystemInformationBlockType1>,
    /// Next allocated C-RNTI for gNB role.
    pub next_crnti: u16,
    /// Transaction ID counter.
    pub next_tid: u8,
}

impl RrcEngine {
    /// Create a new RRC engine.
    pub fn new(role: RrcRole) -> Self {
        RrcEngine {
            role,
            contexts: HashMap::new(),
            suspended_contexts: HashMap::new(),
            mib: None,
            sib1: None,
            next_crnti: 0x4001,
            next_tid: 1,
        }
    }

    /// Set broadcast MIB information.
    pub fn set_mib(&mut self, mib: MasterInformationBlock) {
        self.mib = Some(mib);
    }

    /// Set broadcast SIB1 information.
    pub fn set_sib1(&mut self, sib1: SystemInformationBlockType1) {
        self.sib1 = Some(sib1);
    }

    // -----------------------------------------------------------------------
    // UE Side Procedures
    // -----------------------------------------------------------------------

    /// (UE) Initiate RRC connection establishment: creates local context and builds RrcSetupRequest.
    pub fn ue_initiate_setup_request(
        &mut self,
        ue_identity: u64,
        cause: RrcEstablishmentCause,
    ) -> RrcSetupRequest {
        let crnti = 0x0000; // Temporary before allocation
        let mut ctx = RrcUeContext::new(crnti, ue_identity);
        ctx.state = RrcState::RrcIdle;
        self.contexts.insert(crnti, ctx);

        RrcSetupRequest {
            ue_identity,
            establishment_cause: cause,
        }
    }

    /// (UE) Handle RrcSetup from gNB: configures SRB1, allocates C-RNTI, transitions to RRC_CONNECTED,
    /// and generates RrcSetupComplete carrying the initial NAS Registration Request.
    pub fn ue_handle_setup(
        &mut self,
        setup: &RrcSetup,
        selected_plmn: PlmnId,
        nas_pdu: Vec<u8>,
    ) -> Option<RrcSetupComplete> {
        let old_crnti = 0x0000;
        let mut ctx = self.contexts.remove(&old_crnti)?;

        // Apply allocated C-RNTI
        ctx.crnti = setup.master_cell_group_allocated_crnti;
        // Apply SRB configs (e.g. SRB1)
        for srb in &setup.radio_bearer_config.srb_to_add_mod_list {
            ctx.srbs.insert(srb.srb_id, srb.clone());
        }
        // Transition to RRC_CONNECTED
        ctx.state = RrcState::RrcConnected;
        ctx.selected_plmn = Some(selected_plmn.clone());
        ctx.last_nas_pdu = Some(nas_pdu.clone());

        let new_crnti = ctx.crnti;
        self.contexts.insert(new_crnti, ctx);

        Some(RrcSetupComplete {
            rrc_transaction_identifier: setup.rrc_transaction_identifier,
            selected_plmn_id: selected_plmn,
            dedicated_nas_message: nas_pdu,
        })
    }

    /// (UE) Handle RrcReconfiguration: applies DRB configurations and responds with complete.
    pub fn ue_handle_reconfiguration(
        &mut self,
        crnti: u16,
        reconfig: &RrcReconfiguration,
    ) -> Option<RrcReconfigurationComplete> {
        let ctx = self.contexts.get_mut(&crnti)?;
        if ctx.state != RrcState::RrcConnected {
            return None;
        }

        if let Some(ref rbc) = reconfig.radio_bearer_config {
            for drb in &rbc.drb_to_add_mod_list {
                ctx.drbs.insert(drb.drb_id, drb.clone());
            }
            for drb_id in &rbc.drb_to_release_list {
                ctx.drbs.remove(drb_id);
            }
        }

        Some(RrcReconfigurationComplete {
            rrc_transaction_identifier: reconfig.rrc_transaction_identifier,
        })
    }

    /// (UE) Handle RrcRelease: transitions to RRC_INACTIVE if SuspendConfig is present,
    /// or RRC_IDLE if released normally.
    pub fn ue_handle_release(&mut self, crnti: u16, release: &RrcRelease) -> bool {
        let ctx = match self.contexts.get_mut(&crnti) {
            Some(c) => c,
            None => return false,
        };

        if let Some(ref sc) = release.suspend_config {
            // Transition to RRC_INACTIVE
            ctx.state = RrcState::RrcInactive;
            ctx.suspend_config = Some(sc.clone());
        } else {
            // Transition to RRC_IDLE
            ctx.state = RrcState::RrcIdle;
            ctx.drbs.clear();
            ctx.suspend_config = None;
        }
        true
    }

    /// (UE) Initiate RrcResumeRequest from RRC_INACTIVE.
    pub fn ue_initiate_resume_request(
        &mut self,
        crnti: u16,
        cause: RrcResumeCause,
    ) -> Option<RrcResumeRequest> {
        let ctx = self.contexts.get(&crnti)?;
        if ctx.state != RrcState::RrcInactive {
            return None;
        }
        let suspend_cfg = ctx.suspend_config.as_ref()?;
        Some(RrcResumeRequest {
            resume_identity_short_i_rnti: suspend_cfg.short_i_rnti,
            resume_cause: cause,
            short_mac_i: 0x5A5A,
        })
    }

    /// (UE) Handle RrcResume: restores active state and generates RrcResumeComplete.
    pub fn ue_handle_resume(
        &mut self,
        crnti: u16,
        resume: &RrcResume,
    ) -> Option<RrcResumeComplete> {
        let ctx = self.contexts.get_mut(&crnti)?;
        if ctx.state != RrcState::RrcInactive {
            return None;
        }
        ctx.state = RrcState::RrcConnected;
        ctx.suspend_config = None;

        Some(RrcResumeComplete {
            rrc_transaction_identifier: resume.rrc_transaction_identifier,
            dedicated_nas_message: None,
        })
    }

    // -----------------------------------------------------------------------
    // gNB Side Procedures
    // -----------------------------------------------------------------------

    /// (gNB) Handle RrcSetupRequest from UE: creates UE context, allocates C-RNTI,
    /// configures SRB1, and returns RrcSetup.
    pub fn gnb_handle_setup_request(&mut self, req: &RrcSetupRequest) -> (u16, RrcSetup) {
        let crnti = self.next_crnti;
        self.next_crnti += 1;

        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        let mut ctx = RrcUeContext::new(crnti, req.ue_identity);
        // Configure SRB1 (AM mode)
        ctx.srbs.insert(
            SRB1_ID,
            RrcSrbConfig {
                srb_id: SRB1_ID,
                rlc_mode: RrcRlcMode::Acknowledged,
            },
        );

        let rbc = RadioBearerConfig {
            srb_to_add_mod_list: vec![RrcSrbConfig {
                srb_id: SRB1_ID,
                rlc_mode: RrcRlcMode::Acknowledged,
            }],
            drb_to_add_mod_list: Vec::new(),
            drb_to_release_list: Vec::new(),
            security_config: None,
        };

        let setup = RrcSetup {
            rrc_transaction_identifier: tid,
            radio_bearer_config: rbc,
            master_cell_group_allocated_crnti: crnti,
        };

        self.contexts.insert(crnti, ctx);
        (crnti, setup)
    }

    /// (gNB) Handle RrcSetupComplete from UE: marks UE as RRC_CONNECTED and extracts NAS PDU.
    pub fn gnb_handle_setup_complete(&mut self, crnti: u16, comp: &RrcSetupComplete) -> bool {
        let ctx = match self.contexts.get_mut(&crnti) {
            Some(c) => c,
            None => return false,
        };

        ctx.state = RrcState::RrcConnected;
        ctx.selected_plmn = Some(comp.selected_plmn_id.clone());
        ctx.last_nas_pdu = Some(comp.dedicated_nas_message.clone());
        true
    }

    /// (gNB) Build RrcReconfiguration message to setup DRBs.
    pub fn gnb_build_reconfiguration(
        &mut self,
        crnti: u16,
        drb_list: Vec<RrcDrbConfig>,
    ) -> Option<RrcReconfiguration> {
        let ctx = self.contexts.get_mut(&crnti)?;
        if ctx.state != RrcState::RrcConnected {
            return None;
        }

        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        for drb in &drb_list {
            ctx.drbs.insert(drb.drb_id, drb.clone());
        }

        Some(RrcReconfiguration {
            rrc_transaction_identifier: tid,
            radio_bearer_config: Some(RadioBearerConfig {
                srb_to_add_mod_list: Vec::new(),
                drb_to_add_mod_list: drb_list,
                drb_to_release_list: Vec::new(),
                security_config: None,
            }),
        })
    }

    /// (gNB) Handle RrcReconfigurationComplete from UE.
    pub fn gnb_handle_reconfiguration_complete(
        &mut self,
        crnti: u16,
        _comp: &RrcReconfigurationComplete,
    ) -> bool {
        self.contexts.contains_key(&crnti)
    }

    /// (gNB) Build RrcRelease message, optionally with SuspendConfig to transition to RRC_INACTIVE.
    pub fn gnb_build_release(&mut self, crnti: u16, suspend: bool) -> Option<RrcRelease> {
        let ctx = self.contexts.get_mut(&crnti)?;
        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        if suspend {
            let short_i_rnti = (crnti as u32) | 0x00A0_0000;
            let full_i_rnti = (short_i_rnti as u64) | 0x0000_0001_0000_0000;
            let suspend_cfg = SuspendConfig {
                full_i_rnti,
                short_i_rnti,
                ran_paging_cycle_rf: 64,
                t380_periodic_ran_update_mins: 60,
            };
            ctx.state = RrcState::RrcInactive;
            ctx.suspend_config = Some(suspend_cfg.clone());
            self.suspended_contexts.insert(short_i_rnti, crnti);

            Some(RrcRelease {
                rrc_transaction_identifier: tid,
                release_cause: RrcReleaseCause::RrcSuspend,
                suspend_config: Some(suspend_cfg),
            })
        } else {
            ctx.state = RrcState::RrcIdle;
            ctx.drbs.clear();
            ctx.suspend_config = None;

            Some(RrcRelease {
                rrc_transaction_identifier: tid,
                release_cause: RrcReleaseCause::Other,
                suspend_config: None,
            })
        }
    }

    /// (gNB) Handle RrcResumeRequest: restores suspended UE context and returns RrcResume.
    pub fn gnb_handle_resume_request(
        &mut self,
        req: &RrcResumeRequest,
    ) -> Option<(u16, RrcResume)> {
        let crnti = *self
            .suspended_contexts
            .get(&req.resume_identity_short_i_rnti)?;
        let ctx = self.contexts.get_mut(&crnti)?;

        ctx.state = RrcState::RrcConnected;
        ctx.suspend_config = None;
        self.suspended_contexts
            .remove(&req.resume_identity_short_i_rnti);

        let tid = self.next_tid;
        self.next_tid = self.next_tid.wrapping_add(1);

        Some((
            crnti,
            RrcResume {
                rrc_transaction_identifier: tid,
                radio_bearer_config: None,
            },
        ))
    }

    /// (gNB) Handle RrcResumeComplete.
    pub fn gnb_handle_resume_complete(&mut self, crnti: u16, _comp: &RrcResumeComplete) -> bool {
        self.contexts.contains_key(&crnti)
    }

    /// (gNB) Build Paging message for a list of UE 5G-S-TMSIs.
    pub fn gnb_build_paging(&self, ue_identities: &[u64]) -> PagingMessage {
        let records = ue_identities
            .iter()
            .map(|&ue_id| PagingRecord {
                ue_identity_5g_s_tmsi: ue_id,
                access_type_non_3gpp: false,
            })
            .collect();
        PagingMessage {
            paging_records: records,
        }
    }
}
