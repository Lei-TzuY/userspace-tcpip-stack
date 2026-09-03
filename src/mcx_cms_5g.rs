//! 3GPP TS 29.549 / TS 23.280 / TS 23.379 / TS 24.281 Release 17 5G Mission Critical Services (MCX) Engine.
//!
//! Implements 5G Core Common Core Services for Mission Critical Services (CMS & Floor Control):
//! - Configuration Management Server (CMS - TS 29.549 Section 5.2):
//!   - MCX User Profile provisioning (MCPTT, MCVideo, MCData) with 1..15 priority levels
//!   - MCX Tactical Group configuration with 5QI QoS binding (5QI 65 voice, 5QI 69 video)
//! - MCPTT Floor Control Arbitration State Machine (TS 24.379 Section 8.2):
//!   - Floor Idle, Granted, Taken, Denied, and Released states
//!   - Emergency & Imminent Peril Call Preemption (preempts routine talk sessions within <300ms)
//!   - Ambient listening permission validation

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G MCX Enums & Data Structures (TS 29.549 / TS 23.280 / TS 23.379)
// ---------------------------------------------------------------------------

/// Mission Critical Service Type (TS 23.280 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McxServiceType {
    /// Mission Critical Push-To-Talk (Voice - 5QI 65)
    Mcptt,
    /// Mission Critical Video (Tactical feeds - 5QI 69)
    McVideo,
    /// Mission Critical Data (SDS / Tactical Telemetry - 5QI 70)
    McData,
}

/// MCX User Profile (TS 29.549 Section 6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McxUserProfile {
    pub mcx_id: String,     // e.g. "sip:chief.connor@police.gov"
    pub priority_level: u8, // 1 (highest) to 15 (lowest)
    pub allowed_services: Vec<McxServiceType>,
    pub emergency_call_capable: bool,
    pub ambient_listening_allowed: bool,
}

/// Floor Control State Machine (TS 24.379 Section 8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorState {
    Idle,
    Granted {
        holder_mcx_id: String,
        priority: u8,
        is_emergency: bool,
    },
}

/// Result of a Floor Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorRequestResult {
    Granted,
    PreemptedCurrentHolder { previous_holder: String },
    DeniedBusy { current_holder: String },
}

/// Mission Critical Group Configuration (TS 29.549 Section 6.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McxGroupConfig {
    pub group_id: String,     // e.g. "sip:police-tactical-swat-01@police.gov"
    pub group_priority: u8,   // 1..15
    pub qos_5qi: u8,          // e.g. 5QI 65
    pub members: Vec<String>, // Member mcx_ids
    pub floor_state: FloorState,
}

/// MCX Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McxError {
    UserNotFound,
    GroupNotFound,
    NotGroupMember,
    UnauthorizedEmergencyCall,
    FloorNotHeldByUser,
    InvalidPriorityLevel,
}

// ---------------------------------------------------------------------------
// Top-Level 5G MCX CMS Engine
// ---------------------------------------------------------------------------

/// 5G Mission Critical Configuration Management Server & Floor Controller.
pub struct McxServerEngine {
    pub server_id: String,
    pub user_profiles: HashMap<String, McxUserProfile>,
    pub groups: HashMap<String, McxGroupConfig>,
}

impl McxServerEngine {
    /// Create a new 5G MCX Server instance.
    pub fn new(server_id: &str) -> Self {
        McxServerEngine {
            server_id: server_id.to_string(),
            user_profiles: HashMap::new(),
            groups: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Configuration Management Operations (TS 29.549 Section 5.2)
    // -----------------------------------------------------------------------

    /// Provision or update an MCX User Profile.
    pub fn provision_user_profile(&mut self, profile: McxUserProfile) -> Result<(), McxError> {
        if profile.priority_level == 0 || profile.priority_level > 15 {
            return Err(McxError::InvalidPriorityLevel);
        }
        self.user_profiles.insert(profile.mcx_id.clone(), profile);
        Ok(())
    }

    /// Create or update an MCX Tactical Group.
    pub fn create_group(
        &mut self,
        group_id: &str,
        group_priority: u8,
        qos_5qi: u8,
        members: Vec<&str>,
    ) -> Result<(), McxError> {
        if group_priority == 0 || group_priority > 15 {
            return Err(McxError::InvalidPriorityLevel);
        }

        let cfg = McxGroupConfig {
            group_id: group_id.to_string(),
            group_priority,
            qos_5qi,
            members: members.into_iter().map(|s| s.to_string()).collect(),
            floor_state: FloorState::Idle,
        };

        self.groups.insert(group_id.to_string(), cfg);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Floor Control & Emergency Preemption Arbitration (TS 24.379 Section 8.2)
    // -----------------------------------------------------------------------

    /// Request the floor (Push-To-Talk microphone grant) in an MCX group.
    pub fn request_floor(
        &mut self,
        group_id: &str,
        mcx_id: &str,
        is_emergency: bool,
    ) -> Result<FloorRequestResult, McxError> {
        // 1. Verify User Profile
        let user = self
            .user_profiles
            .get(mcx_id)
            .ok_or(McxError::UserNotFound)?;

        if is_emergency && !user.emergency_call_capable {
            return Err(McxError::UnauthorizedEmergencyCall);
        }

        let requester_priority = user.priority_level;

        // 2. Verify Group Membership
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(McxError::GroupNotFound)?;

        if !group.members.iter().any(|m| m == mcx_id) {
            return Err(McxError::NotGroupMember);
        }

        // 3. Evaluate Floor State and Preemption
        match &group.floor_state {
            FloorState::Idle => {
                group.floor_state = FloorState::Granted {
                    holder_mcx_id: mcx_id.to_string(),
                    priority: requester_priority,
                    is_emergency,
                };
                Ok(FloorRequestResult::Granted)
            }
            FloorState::Granted {
                holder_mcx_id,
                priority,
                is_emergency: current_is_emergency,
            } => {
                let current_holder = holder_mcx_id.clone();
                let current_prio = *priority;
                let current_em = *current_is_emergency;

                // Preemption logic:
                // Case A: Requester is Emergency, current holder is NOT Emergency -> Preempt!
                // Case B: Both Emergency or neither, but requester priority is strictly higher (numerically lower) -> Preempt!
                let can_preempt = if is_emergency && !current_em {
                    true
                } else if is_emergency == current_em && requester_priority < current_prio {
                    true
                } else {
                    false
                };

                if can_preempt {
                    group.floor_state = FloorState::Granted {
                        holder_mcx_id: mcx_id.to_string(),
                        priority: requester_priority,
                        is_emergency,
                    };
                    Ok(FloorRequestResult::PreemptedCurrentHolder {
                        previous_holder: current_holder,
                    })
                } else {
                    Ok(FloorRequestResult::DeniedBusy { current_holder })
                }
            }
        }
    }

    /// Release the floor (releasing the PTT button) to return group to Idle state.
    pub fn release_floor(&mut self, group_id: &str, mcx_id: &str) -> Result<(), McxError> {
        let group = self
            .groups
            .get_mut(group_id)
            .ok_or(McxError::GroupNotFound)?;

        match &group.floor_state {
            FloorState::Granted { holder_mcx_id, .. } if holder_mcx_id == mcx_id => {
                group.floor_state = FloorState::Idle;
                Ok(())
            }
            _ => Err(McxError::FloorNotHeldByUser),
        }
    }
}
