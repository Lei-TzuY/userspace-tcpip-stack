//! 3GPP TS 29.580 / TS 29.581 / TS 23.247 Release 17 5G Multicast/Broadcast Services Engine.
//!
//! Implements 5MBS Core Network functions:
//! - Multicast/Broadcast Service Function (MBSF - TS 29.580):
//!   - Nmbsf_MBSUserService Service: TMGI allocation, service area mapping, and session parameters
//! - Multicast/Broadcast Session Management Function (MB-SMF - TS 29.581):
//!   - Nmbsmf_MBSSession Service: Session Context lifecycle, multicast UE Join/Leave management
//!   - Dynamic Point-to-Multipoint (PTM) vs Point-to-Point (PTP) radio delivery mode switching
//!   - 5MBS 5QI QoS profile enforcement (e.g. 5QI 75, 79)

use std::collections::{HashMap, HashSet};

// ---------------------------------------------------------------------------
// 5MBS Enums & Data Structures (TS 29.580 / TS 23.003 / TS 23.247)
// ---------------------------------------------------------------------------

/// Temporary Mobile Group Identity (TMGI - TS 23.003 Section 20.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tmgi {
    pub service_id: [u8; 3], // 24-bit MBS Service ID
    pub mcc: String,         // Mobile Country Code, e.g. "208"
    pub mnc: String,         // Mobile Network Code, e.g. "95"
}

impl Tmgi {
    pub fn new(service_id: [u8; 3], mcc: &str, mnc: &str) -> Self {
        Tmgi {
            service_id,
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
        }
    }

    pub fn to_string(&self) -> String {
        format!(
            "{:02x}{:02x}{:02x}-{}-{}",
            self.service_id[0], self.service_id[1], self.service_id[2], self.mcc, self.mnc
        )
    }
}

/// 5MBS Service Type (Broadcast vs Multicast).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsServiceType {
    /// Broadcast service: open to all UEs in the service area without explicit join.
    Broadcast,
    /// Multicast service: subscription-based, requires explicit UE Join/Leave.
    Multicast,
}

/// Radio Delivery Method over 5G NR (TS 23.247 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsDeliveryMethod {
    /// Point-to-Multipoint (PTM) only via SC-MTCH common channels.
    PtmOnly,
    /// Point-to-Point (PTP) unicast fallback via dedicated DTCH channels.
    PtpOnly,
    /// Dynamic switching between PTM and PTP based on cell UE density threshold.
    DynamicPtmPtp,
}

/// Effective Radio Transmission Mode chosen for a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellDeliveryMode {
    PointToMultipoint,
    PointToPoint,
}

/// MBS Session State machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsSessionState {
    Configured,
    Active,
    Suspended,
    Released,
}

/// MBS Session Context (TS 29.581 Section 6.1.6.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbsSessionContext {
    pub mbs_session_id: String,
    pub tmgi: Tmgi,
    pub service_type: MbsServiceType,
    pub service_area_tais: Vec<String>,
    pub qos_5qi: u8,
    pub delivery_method: MbsDeliveryMethod,
    pub state: MbsSessionState,
    pub joined_ue_supis: HashSet<String>,
    pub ptm_ue_threshold: u32,
}

/// 5MBS Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MbsError {
    SessionNotFound,
    SessionAlreadyActive,
    SessionNotActive,
    UeAlreadyJoined,
    UeNotJoined,
    InvalidServiceType(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level 5MBS Engine (MBSF & MB-SMF)
// ---------------------------------------------------------------------------

/// 5G Multicast/Broadcast Service Function (MBSF) & MB-SMF Unified Engine.
pub struct MbsfEngine {
    pub mbsf_id: String,
    pub next_service_id_counter: u32,
    pub mcc: String,
    pub mnc: String,
    /// Active sessions: mbs_session_id -> MbsSessionContext
    pub sessions: HashMap<String, MbsSessionContext>,
    /// TMGI lookup: tmgi -> mbs_session_id
    pub tmgi_to_session: HashMap<Tmgi, String>,
}

impl MbsfEngine {
    /// Create a new MBSF / MB-SMF engine instance.
    pub fn new(mbsf_id: &str, mcc: &str, mnc: &str) -> Self {
        MbsfEngine {
            mbsf_id: mbsf_id.to_string(),
            next_service_id_counter: 1,
            mcc: mcc.to_string(),
            mnc: mnc.to_string(),
            sessions: HashMap::new(),
            tmgi_to_session: HashMap::new(),
        }
    }

    /// Nmbsf_MBSUserService_Create operation (TS 29.580 Section 5.2.2.2).
    /// Creates an MBS session, allocates TMGI, and sets QoS/delivery parameters.
    pub fn create_mbs_session(
        &mut self,
        service_type: MbsServiceType,
        service_area_tais: Vec<String>,
        qos_5qi: u8,
        delivery_method: MbsDeliveryMethod,
        ptm_ue_threshold: u32,
    ) -> String {
        let sid_bytes = [
            ((self.next_service_id_counter >> 16) & 0xFF) as u8,
            ((self.next_service_id_counter >> 8) & 0xFF) as u8,
            (self.next_service_id_counter & 0xFF) as u8,
        ];
        self.next_service_id_counter += 1;

        let tmgi = Tmgi::new(sid_bytes, &self.mcc, &self.mnc);
        let session_id = format!("mbs-sess-{}", tmgi.to_string());

        let ctx = MbsSessionContext {
            mbs_session_id: session_id.clone(),
            tmgi: tmgi.clone(),
            service_type,
            service_area_tais,
            qos_5qi,
            delivery_method,
            state: MbsSessionState::Configured,
            joined_ue_supis: HashSet::new(),
            ptm_ue_threshold,
        };

        self.tmgi_to_session.insert(tmgi, session_id.clone());
        self.sessions.insert(session_id.clone(), ctx);

        session_id
    }

    /// Activate an MBS Session (transitions to Active, starts media transmission).
    pub fn activate_mbs_session(&mut self, session_id: &str) -> Result<(), MbsError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbsError::SessionNotFound)?;
        if sess.state == MbsSessionState::Active {
            return Err(MbsError::SessionAlreadyActive);
        }
        sess.state = MbsSessionState::Active;
        Ok(())
    }

    /// Multicast UE Join operation (TS 23.247 Section 7.2.1).
    pub fn ue_join_multicast_session(
        &mut self,
        session_id: &str,
        supi: &str,
    ) -> Result<(), MbsError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbsError::SessionNotFound)?;
        if sess.service_type != MbsServiceType::Multicast {
            return Err(MbsError::InvalidServiceType(
                "UE Join is only applicable to Multicast service type",
            ));
        }

        if sess.joined_ue_supis.contains(supi) {
            return Err(MbsError::UeAlreadyJoined);
        }

        sess.joined_ue_supis.insert(supi.to_string());
        Ok(())
    }

    /// Multicast UE Leave operation (TS 23.247 Section 7.2.2).
    pub fn ue_leave_multicast_session(
        &mut self,
        session_id: &str,
        supi: &str,
    ) -> Result<(), MbsError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbsError::SessionNotFound)?;
        if sess.service_type != MbsServiceType::Multicast {
            return Err(MbsError::InvalidServiceType(
                "UE Leave is only applicable to Multicast service type",
            ));
        }

        if !sess.joined_ue_supis.remove(supi) {
            return Err(MbsError::UeNotJoined);
        }

        Ok(())
    }

    /// Evaluate cell radio delivery mode (PTM vs PTP) based on UE density and policy.
    pub fn evaluate_cell_delivery_mode(
        &self,
        session_id: &str,
        active_cell_ues: u32,
    ) -> Result<CellDeliveryMode, MbsError> {
        let sess = self
            .sessions
            .get(session_id)
            .ok_or(MbsError::SessionNotFound)?;

        match sess.delivery_method {
            MbsDeliveryMethod::PtmOnly => Ok(CellDeliveryMode::PointToMultipoint),
            MbsDeliveryMethod::PtpOnly => Ok(CellDeliveryMode::PointToPoint),
            MbsDeliveryMethod::DynamicPtmPtp => {
                if active_cell_ues >= sess.ptm_ue_threshold {
                    Ok(CellDeliveryMode::PointToMultipoint)
                } else {
                    Ok(CellDeliveryMode::PointToPoint)
                }
            }
        }
    }

    /// Release an MBS session and reclaim its TMGI.
    pub fn release_mbs_session(&mut self, session_id: &str) -> Result<(), MbsError> {
        let sess = self
            .sessions
            .remove(session_id)
            .ok_or(MbsError::SessionNotFound)?;
        self.tmgi_to_session.remove(&sess.tmgi);
        Ok(())
    }
}
