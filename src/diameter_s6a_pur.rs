// =============================================================================
// 3GPP TS 29.272 Diameter S6a / S6d Purge-UE-Request / Answer (PUR / PUA)
// Command Code 321
// =============================================================================
//
// When a UE has been detached for an extended period and the MME/SGSN wishes
// to reclaim local subscriber context, it sends a Purge-UE-Request (PUR) to
// the HSS.  The HSS marks the subscriber as "not attached" and responds with
// a Purge-UE-Answer (PUA) indicating success or failure.
//
// Key AVPs (Attribute-Value Pairs):
//   - Session-Id, Origin-Host, Origin-Realm
//   - User-Name (IMSI)
//   - PUA-Flags: bit 0 = Freeze-M-TMSI, bit 1 = Freeze-P-TMSI
//   - Result-Code / Experimental-Result-Code
//
// This module implements:
//   1. PUR message construction with IMSI and purge flags.
//   2. HSS-side engine that processes PUR, marks subscriber as purged, and
//      generates PUA with appropriate Result-Code.
//   3. Purge state tracking per subscriber (IMSI) with timestamps.
//
// Pure safe Rust, zero external crates.

/// Diameter Application ID for S6a/S6d (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S6A: u32 = 16_777_251;

/// Command Code for Purge-UE-Request / Answer.
pub const DIAMETER_CMD_PURGE_UE: u32 = 321;

/// Diameter Result-Code: success.
pub const RESULT_CODE_SUCCESS: u32 = 2001;

/// Diameter Result-Code: user unknown.
pub const RESULT_CODE_USER_UNKNOWN: u32 = 5001;

/// PUA Flags bitmask constants.
pub const PUA_FLAG_FREEZE_M_TMSI: u32 = 0x0000_0001;
pub const PUA_FLAG_FREEZE_P_TMSI: u32 = 0x0000_0002;

/// AVP types relevant to PUR/PUA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aPurAvp {
    SessionId(String),
    OriginHost(String),
    OriginRealm(String),
    UserName(String), // IMSI
    PuaFlags(u32),
    ResultCode(u32),
}

/// PUR or PUA message.
#[derive(Debug, Clone)]
pub struct S6aPurMessage {
    pub command_code: u32,
    pub application_id: u32,
    pub is_request: bool,
    pub avps: Vec<S6aPurAvp>,
}

impl S6aPurMessage {
    /// Build a Purge-UE-Request.
    pub fn new_pur(session_id: &str, imsi: &str, flags: u32) -> Self {
        Self {
            command_code: DIAMETER_CMD_PURGE_UE,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: true,
            avps: vec![
                S6aPurAvp::SessionId(session_id.to_string()),
                S6aPurAvp::UserName(imsi.to_string()),
                S6aPurAvp::PuaFlags(flags),
            ],
        }
    }

    /// Build a Purge-UE-Answer.
    pub fn new_pua(session_id: &str, result_code: u32, flags: u32) -> Self {
        Self {
            command_code: DIAMETER_CMD_PURGE_UE,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: false,
            avps: vec![
                S6aPurAvp::SessionId(session_id.to_string()),
                S6aPurAvp::ResultCode(result_code),
                S6aPurAvp::PuaFlags(flags),
            ],
        }
    }

    /// Extract the IMSI (User-Name) from the message AVPs.
    pub fn imsi(&self) -> Option<&str> {
        for avp in &self.avps {
            if let S6aPurAvp::UserName(v) = avp {
                return Some(v.as_str());
            }
        }
        None
    }

    /// Extract the PUA Flags from the message AVPs.
    pub fn pua_flags(&self) -> u32 {
        for avp in &self.avps {
            if let S6aPurAvp::PuaFlags(f) = avp {
                return *f;
            }
        }
        0
    }

    /// Extract the Result-Code from the message AVPs.
    pub fn result_code(&self) -> Option<u32> {
        for avp in &self.avps {
            if let S6aPurAvp::ResultCode(rc) = avp {
                return Some(*rc);
            }
        }
        None
    }

    /// Extract the Session-Id from the message AVPs.
    pub fn session_id(&self) -> Option<&str> {
        for avp in &self.avps {
            if let S6aPurAvp::SessionId(s) = avp {
                return Some(s.as_str());
            }
        }
        None
    }
}

/// Per-subscriber purge state held by the HSS.
#[derive(Debug, Clone)]
pub struct PurgeRecord {
    /// IMSI of the purged subscriber.
    pub imsi: String,
    /// Timestamp (arbitrary monotonic nanoseconds) when the purge was recorded.
    pub purged_at_ns: u64,
    /// PUA flags echoed back during the purge.
    pub flags: u32,
    /// Whether the subscriber context has been fully reclaimed.
    pub context_released: bool,
}

/// HSS-side Purge-UE processing engine.
pub struct S6aPurEngine {
    /// Known subscribers (by IMSI) and whether they are currently attached.
    subscribers: Vec<(String, bool)>, // (imsi, is_attached)
    /// Records of completed purge operations.
    purge_log: Vec<PurgeRecord>,
    /// Monotonic clock for timestamping.
    clock_ns: u64,
}

impl S6aPurEngine {
    pub fn new() -> Self {
        Self {
            subscribers: Vec::new(),
            purge_log: Vec::new(),
            clock_ns: 0,
        }
    }

    /// Provision a subscriber in the HSS database.
    pub fn add_subscriber(&mut self, imsi: &str) {
        // Default to attached.
        if !self.subscribers.iter().any(|(i, _)| i == imsi) {
            self.subscribers.push((imsi.to_string(), true));
        }
    }

    /// Detach a subscriber (simulate the UE going offline).
    pub fn detach_subscriber(&mut self, imsi: &str) {
        for entry in &mut self.subscribers {
            if entry.0 == imsi {
                entry.1 = false;
            }
        }
    }

    /// Check if a subscriber is known.
    pub fn is_known(&self, imsi: &str) -> bool {
        self.subscribers.iter().any(|(i, _)| i == imsi)
    }

    /// Check if a subscriber is currently attached.
    pub fn is_attached(&self, imsi: &str) -> bool {
        self.subscribers.iter().any(|(i, a)| i == imsi && *a)
    }

    /// Advance the internal clock.
    pub fn advance_clock(&mut self, delta_ns: u64) {
        self.clock_ns = self.clock_ns.saturating_add(delta_ns);
    }

    /// Return the purge log.
    pub fn purge_log(&self) -> &[PurgeRecord] {
        &self.purge_log
    }

    /// Process an incoming Purge-UE-Request and return a Purge-UE-Answer.
    pub fn process_pur(&mut self, pur: &S6aPurMessage) -> S6aPurMessage {
        let session_id = pur.session_id().unwrap_or("unknown");
        let imsi = match pur.imsi() {
            Some(i) => i.to_string(),
            None => {
                return S6aPurMessage::new_pua(session_id, RESULT_CODE_USER_UNKNOWN, 0);
            }
        };
        let flags = pur.pua_flags();

        if !self.is_known(&imsi) {
            return S6aPurMessage::new_pua(session_id, RESULT_CODE_USER_UNKNOWN, flags);
        }

        // Mark subscriber as detached (purged).
        for entry in &mut self.subscribers {
            if entry.0 == imsi {
                entry.1 = false;
            }
        }

        // Record the purge event.
        self.purge_log.push(PurgeRecord {
            imsi,
            purged_at_ns: self.clock_ns,
            flags,
            context_released: true,
        });

        S6aPurMessage::new_pua(session_id, RESULT_CODE_SUCCESS, flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_purge_known_subscriber() {
        let mut engine = S6aPurEngine::new();
        engine.add_subscriber("262011234567890");
        engine.advance_clock(1_000_000);

        let pur =
            S6aPurMessage::new_pur("session-pur-001", "262011234567890", PUA_FLAG_FREEZE_M_TMSI);
        let pua = engine.process_pur(&pur);
        assert!(!pua.is_request);
        assert_eq!(pua.result_code(), Some(RESULT_CODE_SUCCESS));
        assert!(!engine.is_attached("262011234567890"));
        assert_eq!(engine.purge_log().len(), 1);
        assert_eq!(engine.purge_log()[0].flags, PUA_FLAG_FREEZE_M_TMSI);
    }

    #[test]
    fn test_purge_unknown_subscriber() {
        let mut engine = S6aPurEngine::new();
        let pur = S6aPurMessage::new_pur("session-pur-002", "999990000000001", 0);
        let pua = engine.process_pur(&pur);
        assert_eq!(pua.result_code(), Some(RESULT_CODE_USER_UNKNOWN));
        assert_eq!(engine.purge_log().len(), 0);
    }
}
