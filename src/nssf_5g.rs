//! 3GPP TS 29.531 / TS 23.501 5G Network Slice Selection Function (NSSF) Engine.
//!
//! Implements 5G Core Network Slicing control plane operations:
//! - Nnssf_NSSelection Service (TS 29.531 Section 5.2):
//!   - Slice validation against Subscribed S-NSSAIs from UDM
//!   - Mapping Requested NSSAI to Allowed, Configured, and Rejected NSSAIs per (PLMN, TAC)
//!   - Network Slice Instance (NSI) selection and Candidate AMF / AMF Set resolution
//! - Nnssf_NSSAIAvailability Service (TS 29.531 Section 5.3):
//!   - AMF registration of supported S-NSSAIs per Tracking Area (TA)
//!   - Real-time slice availability updates and event notifications

use std::collections::HashMap;

use crate::ngap_5g::{PlmnId, Snssai};
use crate::sba_5g::NfType;

// ---------------------------------------------------------------------------
// 5G Network Slicing Enums & Data Structures (TS 29.531 Section 6)
// ---------------------------------------------------------------------------

/// Cause for rejecting an S-NSSAI (TS 29.531 Section 6.1.6.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnssaiRejectionCause {
    /// S-NSSAI not supported in the serving PLMN.
    NotAvailableInPlmn,
    /// S-NSSAI not supported in the current Tracking Area (TAC).
    NotAvailableInCurrentTa,
    /// S-NSSAI not authorized in subscription data.
    NotSubscribed,
}

/// Context of slice selection inquiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SliceInfoType {
    /// Initial or periodic UE Registration.
    Registration,
    /// Establishing a specific PDU Session.
    PduSessionEstablishment,
}

/// Allowed S-NSSAI returned to the UE and AMF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowedSnssai {
    pub snssai: Snssai,
    pub mapped_home_snssai: Option<Snssai>,
    pub nsi_id: Option<String>,
}

/// Candidate AMF information capable of serving the selected network slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateAmf {
    pub amf_instance_id: String,
    pub amf_set_id: String,
    pub supported_snssais: Vec<Snssai>,
    pub capacity: u16,
}

/// Authorized Network Slice Information (TS 29.531 Section 6.1.6.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedNetworkSliceInfo {
    pub allowed_nssai_list: Vec<AllowedSnssai>,
    pub configured_nssai: Vec<Snssai>,
    pub rejected_nssai_list: Vec<(Snssai, SnssaiRejectionCause)>,
    pub target_amf_set_id: Option<String>,
    pub candidate_amf_list: Vec<CandidateAmf>,
}

// ---------------------------------------------------------------------------
// Nnssf_NSSelection Service Operations (TS 29.531 Section 5.2)
// ---------------------------------------------------------------------------

/// Request for Nnssf_NSSelection_Get (AMF -> NSSF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsSelectionRequest {
    pub nf_type: NfType,
    pub nf_id: String,
    pub slice_info_type: SliceInfoType,
    pub requested_nssai: Vec<Snssai>,
    pub subscribed_snssais: Vec<Snssai>,
    pub plmn_id: PlmnId,
    pub tai: u32, // Tracking Area Code (TAC)
}

/// Response for Nnssf_NSSelection_Get (NSSF -> AMF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsSelectionResponse {
    pub authorized_network_slice_info: AuthorizedNetworkSliceInfo,
}

// ---------------------------------------------------------------------------
// Nnssf_NSSAIAvailability Service Operations (TS 29.531 Section 5.3)
// ---------------------------------------------------------------------------

/// Update message from AMF registering supported slices per TA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NssaiAvailabilityUpdate {
    pub amf_instance_id: String,
    pub amf_set_id: String,
    pub plmn_id: PlmnId,
    pub tai: u32,
    pub supported_snssais: Vec<Snssai>,
    pub capacity: u16,
}

// ---------------------------------------------------------------------------
// NSSF Protocol Engine
// ---------------------------------------------------------------------------

/// 5G Network Slice Selection Function (NSSF) Engine.
pub struct NssfEngine {
    pub nssf_instance_id: String,
    /// Configured S-NSSAIs per PLMN: PlmnId -> Vec<Snssai>
    pub plmn_configured_slices: HashMap<PlmnId, Vec<Snssai>>,
    /// S-NSSAI to NSI-ID mappings: (PlmnId, Snssai) -> nsi_id
    pub slice_nsi_map: HashMap<(PlmnId, Snssai), String>,
    /// Registered AMF capabilities: amf_instance_id -> NssaiAvailabilityUpdate
    pub amf_registry: HashMap<String, NssaiAvailabilityUpdate>,
}

impl NssfEngine {
    /// Create a new NSSF engine instance.
    pub fn new(nssf_instance_id: &str) -> Self {
        NssfEngine {
            nssf_instance_id: nssf_instance_id.to_string(),
            plmn_configured_slices: HashMap::new(),
            slice_nsi_map: HashMap::new(),
            amf_registry: HashMap::new(),
        }
    }

    /// Provision configured slices for a given PLMN.
    pub fn configure_plmn_slices(&mut self, plmn: PlmnId, slices: Vec<Snssai>) {
        self.plmn_configured_slices.insert(plmn, slices);
    }

    /// Provision Network Slice Instance (NSI) identifier for an S-NSSAI.
    pub fn set_slice_nsi(&mut self, plmn: PlmnId, snssai: Snssai, nsi_id: &str) {
        self.slice_nsi_map
            .insert((plmn, snssai), nsi_id.to_string());
    }

    /// Nnssf_NSSAIAvailability_Update: AMF registers supported slices in a Tracking Area.
    pub fn handle_availability_update(&mut self, update: NssaiAvailabilityUpdate) {
        self.amf_registry
            .insert(update.amf_instance_id.clone(), update);
    }

    /// Nnssf_NSSelection_Get: Evaluate requested slices against subscriptions and availability.
    pub fn handle_ns_selection(
        &self,
        req: &NsSelectionRequest,
    ) -> Result<NsSelectionResponse, &'static str> {
        let configured = self
            .plmn_configured_slices
            .get(&req.plmn_id)
            .cloned()
            .unwrap_or_default();

        let mut allowed = Vec::new();
        let mut rejected = Vec::new();

        // If UE provided no requested S-NSSAIs, default to subscribed S-NSSAIs
        let candidates = if req.requested_nssai.is_empty() {
            &req.subscribed_snssais
        } else {
            &req.requested_nssai
        };

        // Determine slice availability in current TAC across registered AMFs
        let ta_supported: Vec<Snssai> = self
            .amf_registry
            .values()
            .filter(|a| a.plmn_id == req.plmn_id && a.tai == req.tai)
            .flat_map(|a| a.supported_snssais.iter().cloned())
            .collect();

        for snssai in candidates {
            // 1. Check if subscribed
            if !req.subscribed_snssais.contains(snssai) {
                rejected.push((snssai.clone(), SnssaiRejectionCause::NotSubscribed));
                continue;
            }

            // 2. Check if configured in serving PLMN
            if !configured.is_empty() && !configured.contains(snssai) {
                rejected.push((snssai.clone(), SnssaiRejectionCause::NotAvailableInPlmn));
                continue;
            }

            // 3. Check if available in current Tracking Area
            if !ta_supported.is_empty() && !ta_supported.contains(snssai) {
                rejected.push((
                    snssai.clone(),
                    SnssaiRejectionCause::NotAvailableInCurrentTa,
                ));
                continue;
            }

            // Slice admitted
            let nsi_id = self
                .slice_nsi_map
                .get(&(req.plmn_id, snssai.clone()))
                .cloned();
            allowed.push(AllowedSnssai {
                snssai: snssai.clone(),
                mapped_home_snssai: None,
                nsi_id,
            });
        }

        // 4. Resolve candidate AMFs capable of serving the allowed slices
        let mut candidate_amfs = Vec::new();
        let mut target_amf_set_id = None;

        for amf in self.amf_registry.values() {
            if amf.plmn_id == req.plmn_id && amf.tai == req.tai {
                // Check if this AMF supports at least one allowed slice
                let supports_allowed = allowed
                    .iter()
                    .any(|a| amf.supported_snssais.contains(&a.snssai));
                if supports_allowed {
                    candidate_amfs.push(CandidateAmf {
                        amf_instance_id: amf.amf_instance_id.clone(),
                        amf_set_id: amf.amf_set_id.clone(),
                        supported_snssais: amf.supported_snssais.clone(),
                        capacity: amf.capacity,
                    });
                    if target_amf_set_id.is_none() {
                        target_amf_set_id = Some(amf.amf_set_id.clone());
                    }
                }
            }
        }

        Ok(NsSelectionResponse {
            authorized_network_slice_info: AuthorizedNetworkSliceInfo {
                allowed_nssai_list: allowed,
                configured_nssai: configured,
                rejected_nssai_list: rejected,
                target_amf_set_id,
                candidate_amf_list: candidate_amfs,
            },
        })
    }
}
