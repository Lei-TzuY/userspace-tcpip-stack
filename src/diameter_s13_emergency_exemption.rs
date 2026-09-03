// =============================================================================
// 3GPP TS 29.272 Diameter S13 Emergency Call / eCall IMEI Exemption Engine
// =============================================================================
//
// In 3GPP LTE/5G networks (3GPP TS 22.101, TS 23.401, TS 29.272), telecommunication
// regulations mandate that emergency calls (e.g., 911, 112, and automated eCall crash
// alerts) MUST be allowed even if the user equipment (UE) IMEI is blacklisted (stolen),
// graylisted, unauthenticated, or has no valid subscription.
//
// The Diameter S13/S13' EIR interface must grant a temporary emergency exemption
// token, restrict data connectivity strictly to dedicated emergency APNs (e.g., "sos"),
// maintain strict audit logs, and auto-expire emergency sessions.
//
// Pure safe Rust, zero external dependencies.

use crate::diameter_s13_escn::S13EquipmentStatus;

/// Type of emergency call service (3GPP TS 22.101 / eCall).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyCallType {
    Voice112_911,
    ECallManual,
    ECallAutomaticCrash,
    TestEmergency,
}

/// Active emergency exemption session record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmergencySessionRecord {
    pub session_id: u32,
    pub imei: String,
    pub call_type: EmergencyCallType,
    pub apn: String,
    pub granted_at_secs: u64,
    pub max_duration_secs: u64,
    pub is_active: bool,
}

/// Decision verdict for Diameter S13 check with emergency evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmergencyExemptionVerdict {
    /// Normal authorized device allowed standard access.
    StandardAccessAllowed {
        imei: String,
        status: S13EquipmentStatus,
    },
    /// Blacklisted / graylisted device granted temporary emergency exemption.
    EmergencyExemptionGranted {
        imei: String,
        original_status: S13EquipmentStatus,
        call_type: EmergencyCallType,
        session_id: u32,
        permitted_apn: String,
    },
    /// Non-emergency call rejected due to blacklisted equipment.
    NonEmergencyBlocked {
        imei: String,
        status: S13EquipmentStatus,
        reason: &'static str,
    },
    /// Input IMEI string is invalid (must be 14-16 numeric digits).
    MalformedImeiRejected { input: String },
}

/// Engine managing Diameter S13 Emergency Call Exemption and Regulatory Audit.
pub struct DiameterS13EmergencyExemptionEngine {
    pub default_emergency_duration_secs: u64,
    pub equipment_db: Vec<(String, S13EquipmentStatus)>,
    pub sessions: Vec<EmergencySessionRecord>,
    pub next_session_id: u32,
    pub total_exemptions_granted: u64,
    pub total_blocked_calls: u64,
    pub total_standard_calls: u64,
}

impl DiameterS13EmergencyExemptionEngine {
    pub fn new(default_emergency_duration_secs: u64) -> Self {
        Self {
            default_emergency_duration_secs,
            equipment_db: Vec::new(),
            sessions: Vec::new(),
            next_session_id: 1,
            total_exemptions_granted: 0,
            total_blocked_calls: 0,
            total_standard_calls: 0,
        }
    }

    /// Registers or updates an equipment status in the EIR database.
    pub fn set_equipment_status(&mut self, imei: &str, status: S13EquipmentStatus) {
        if let Some(entry) = self.equipment_db.iter_mut().find(|(k, _)| k == imei) {
            entry.1 = status;
        } else {
            self.equipment_db.push((imei.to_string(), status));
        }
    }

    /// Evaluates terminal authorization with 3GPP Emergency Exemption rules.
    pub fn evaluate_access(
        &mut self,
        imei: &str,
        is_emergency_request: bool,
        call_type: Option<EmergencyCallType>,
        requested_apn: &str,
        current_time_secs: u64,
    ) -> EmergencyExemptionVerdict {
        if imei.len() < 14 || imei.len() > 16 || !imei.chars().all(|c| c.is_ascii_digit()) {
            return EmergencyExemptionVerdict::MalformedImeiRejected {
                input: imei.to_string(),
            };
        }

        let status = self
            .equipment_db
            .iter()
            .find(|(k, _)| k == imei)
            .map(|(_, v)| *v)
            .unwrap_or(S13EquipmentStatus::WhiteListed);

        if is_emergency_request {
            let emergency_type = call_type.unwrap_or(EmergencyCallType::Voice112_911);
            let session_id = self.next_session_id;
            self.next_session_id += 1;

            let apn = if requested_apn.is_empty() || requested_apn == "internet" {
                "sos".to_string()
            } else {
                requested_apn.to_string()
            };

            self.sessions.push(EmergencySessionRecord {
                session_id,
                imei: imei.to_string(),
                call_type: emergency_type,
                apn: apn.clone(),
                granted_at_secs: current_time_secs,
                max_duration_secs: self.default_emergency_duration_secs,
                is_active: true,
            });

            self.total_exemptions_granted += 1;

            EmergencyExemptionVerdict::EmergencyExemptionGranted {
                imei: imei.to_string(),
                original_status: status,
                call_type: emergency_type,
                session_id,
                permitted_apn: apn,
            }
        } else {
            match status {
                S13EquipmentStatus::WhiteListed => {
                    self.total_standard_calls += 1;
                    EmergencyExemptionVerdict::StandardAccessAllowed {
                        imei: imei.to_string(),
                        status,
                    }
                }
                S13EquipmentStatus::BlackListed => {
                    self.total_blocked_calls += 1;
                    EmergencyExemptionVerdict::NonEmergencyBlocked {
                        imei: imei.to_string(),
                        status,
                        reason: "Equipment is blacklisted (stolen/fraudulent) and request is non-emergency.",
                    }
                }
                S13EquipmentStatus::GrayListed => {
                    self.total_standard_calls += 1;
                    EmergencyExemptionVerdict::StandardAccessAllowed {
                        imei: imei.to_string(),
                        status,
                    }
                }
                S13EquipmentStatus::Unknown => {
                    self.total_blocked_calls += 1;
                    EmergencyExemptionVerdict::NonEmergencyBlocked {
                        imei: imei.to_string(),
                        status,
                        reason: "Equipment status is unknown or unverified.",
                    }
                }
            }
        }
    }

    /// Terminates an active emergency exemption session.
    pub fn terminate_session(&mut self, session_id: u32) -> bool {
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session_id)
        {
            session.is_active = false;
            true
        } else {
            false
        }
    }

    /// Sweeps and deactivates expired emergency exemption sessions.
    pub fn sweep_expired(&mut self, current_time_secs: u64) -> usize {
        let mut expired_count = 0;
        for s in &mut self.sessions {
            if s.is_active && current_time_secs >= s.granted_at_secs + s.max_duration_secs {
                s.is_active = false;
                expired_count += 1;
            }
        }
        expired_count
    }

    /// Resets all equipment records and active sessions.
    pub fn reset(&mut self) {
        self.equipment_db.clear();
        self.sessions.clear();
        self.next_session_id = 1;
        self.total_exemptions_granted = 0;
        self.total_blocked_calls = 0;
        self.total_standard_calls = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emergency_exemption_lifecycle() {
        let mut engine = DiameterS13EmergencyExemptionEngine::new(3600);
        let stolen_imei = "867530901234567";
        engine.set_equipment_status(stolen_imei, S13EquipmentStatus::BlackListed);

        // Non-emergency access is blocked
        let v_block = engine.evaluate_access(stolen_imei, false, None, "internet", 1000);
        assert_eq!(
            v_block,
            EmergencyExemptionVerdict::NonEmergencyBlocked {
                imei: stolen_imei.to_string(),
                status: S13EquipmentStatus::BlackListed,
                reason: "Equipment is blacklisted (stolen/fraudulent) and request is non-emergency.",
            }
        );

        // Emergency access (112 / 911) is exempt and permitted
        let v_exempt = engine.evaluate_access(
            stolen_imei,
            true,
            Some(EmergencyCallType::Voice112_911),
            "internet",
            1000,
        );
        assert_eq!(
            v_exempt,
            EmergencyExemptionVerdict::EmergencyExemptionGranted {
                imei: stolen_imei.to_string(),
                original_status: S13EquipmentStatus::BlackListed,
                call_type: EmergencyCallType::Voice112_911,
                session_id: 1,
                permitted_apn: "sos".to_string(),
            }
        );
        assert_eq!(engine.sessions.len(), 1);
        assert!(engine.sessions[0].is_active);

        // Sweep before expiry -> 0 expired
        assert_eq!(engine.sweep_expired(2000), 0);

        // Sweep after expiry (1000 + 3600 = 4600)
        assert_eq!(engine.sweep_expired(5000), 1);
        assert!(!engine.sessions[0].is_active);
    }
}
