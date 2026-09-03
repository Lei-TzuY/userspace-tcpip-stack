// =============================================================================
// 3GPP TS 29.272 Diameter S6a / S6d Reset-Request / Answer (RSR / RSA)
// Command Code 322
// =============================================================================
//
// Following an HSS restart, database failover, or loss of state synchronization,
// the HSS sends a Reset-Request (RSR) to serving MMEs and SGSNs. This instructs
// serving nodes to request subscriber authentication data and location updates
// on the next signaling transaction with the UE.
//
// Key AVPs:
//   - Session-Id, Origin-Host, Origin-Realm, Destination-Host, Destination-Realm
//   - User-Id (IMSI list of affected subscribers, or empty for all subscribers)
//   - Reset-Predicate / Supported-Features
//   - Result-Code (2001 DIAMETER_SUCCESS)
//
// Pure safe Rust, zero external crates.

/// Diameter Application ID for S6a/S6d (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S6A: u32 = 16_777_251;

/// Command Code for Reset-Request / Answer.
pub const DIAMETER_CMD_RESET: u32 = 322;

/// Diameter Result-Code: success.
pub const RESULT_CODE_SUCCESS: u32 = 2001;

/// Diameter Result-Code: unable to deliver.
pub const RESULT_CODE_UNABLE_TO_DELIVER: u32 = 3002;

/// AVP representation for S6a RSR/RSA messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aRsrAvp {
    SessionId(String),
    OriginHost(String),
    OriginRealm(String),
    DestinationHost(String),
    DestinationRealm(String),
    UserId(String), // IMSI
    ResultCode(u32),
}

/// Reset-Request or Reset-Answer message.
#[derive(Debug, Clone)]
pub struct S6aRsrMessage {
    pub command_code: u32,
    pub application_id: u32,
    pub is_request: bool,
    pub session_id: String,
    pub avps: Vec<S6aRsrAvp>,
}

impl S6aRsrMessage {
    /// Create a new Reset-Request (HSS -> MME/SGSN).
    pub fn new_rsr(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        dest_host: &str,
        dest_realm: &str,
        affected_imsis: &[&str],
    ) -> Self {
        let mut avps = vec![
            S6aRsrAvp::SessionId(session_id.to_string()),
            S6aRsrAvp::OriginHost(origin_host.to_string()),
            S6aRsrAvp::OriginRealm(origin_realm.to_string()),
            S6aRsrAvp::DestinationHost(dest_host.to_string()),
            S6aRsrAvp::DestinationRealm(dest_realm.to_string()),
        ];
        for imsi in affected_imsis {
            avps.push(S6aRsrAvp::UserId(imsi.to_string()));
        }

        Self {
            command_code: DIAMETER_CMD_RESET,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: true,
            session_id: session_id.to_string(),
            avps,
        }
    }

    /// Create a new Reset-Answer (MME/SGSN -> HSS).
    pub fn new_rsa(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_RESET,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: false,
            session_id: session_id.to_string(),
            avps: vec![
                S6aRsrAvp::SessionId(session_id.to_string()),
                S6aRsrAvp::OriginHost(origin_host.to_string()),
                S6aRsrAvp::OriginRealm(origin_realm.to_string()),
                S6aRsrAvp::ResultCode(result_code),
            ],
        }
    }

    /// Extract all User-Id (IMSI) values from AVPs.
    pub fn user_ids(&self) -> Vec<&str> {
        self.avps
            .iter()
            .filter_map(|avp| match avp {
                S6aRsrAvp::UserId(s) => Some(s.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Extract Result-Code if present.
    pub fn result_code(&self) -> Option<u32> {
        self.avps.iter().find_map(|avp| match avp {
            S6aRsrAvp::ResultCode(rc) => Some(*rc),
            _ => None,
        })
    }
}

/// Serving node (MME/SGSN) subscriber record.
#[derive(Debug, Clone)]
pub struct ServingSubscriberState {
    pub imsi: String,
    /// Whether this subscriber requires re-synchronization with HSS.
    pub needs_resync: bool,
    /// Timestamp (ns) when marked for resync.
    pub marked_at_ns: u64,
}

/// MME/SGSN Reset Receiver and State Synchronization Engine.
pub struct S6aRsrEngine {
    pub node_id: String,
    pub realm: String,
    /// Serving node subscriber database.
    pub subscribers: Vec<ServingSubscriberState>,
    /// Total RSR requests processed.
    pub total_rsr_received: u64,
    /// Total subscribers marked for resynchronization.
    pub total_subscribers_reset: u64,
    /// Current wall-clock time in nanoseconds.
    pub clock_ns: u64,
}

impl S6aRsrEngine {
    pub fn new(node_id: &str, realm: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            realm: realm.to_string(),
            subscribers: Vec::new(),
            total_rsr_received: 0,
            total_subscribers_reset: 0,
            clock_ns: 0,
        }
    }

    /// Provision a subscriber in the serving node cache.
    pub fn provision_subscriber(&mut self, imsi: &str) {
        if !self.subscribers.iter().any(|s| s.imsi == imsi) {
            self.subscribers.push(ServingSubscriberState {
                imsi: imsi.to_string(),
                needs_resync: false,
                marked_at_ns: 0,
            });
        }
    }

    /// Advance the internal clock by `delta_ns`.
    pub fn advance_clock(&mut self, delta_ns: u64) {
        self.clock_ns = self.clock_ns.saturating_add(delta_ns);
    }

    /// Process an incoming Reset-Request from the HSS.
    /// If User-Ids are provided, mark only those subscribers; otherwise mark all.
    /// Returns a Reset-Answer.
    pub fn process_rsr(&mut self, rsr: &S6aRsrMessage) -> S6aRsrMessage {
        self.total_rsr_received += 1;
        let targeted_imsis = rsr.user_ids();

        let now = self.clock_ns;
        let mut reset_count = 0;

        if targeted_imsis.is_empty() {
            // Reset all subscribers
            for sub in &mut self.subscribers {
                sub.needs_resync = true;
                sub.marked_at_ns = now;
                reset_count += 1;
            }
        } else {
            // Reset only matching subscribers
            for sub in &mut self.subscribers {
                if targeted_imsis.contains(&sub.imsi.as_str()) {
                    sub.needs_resync = true;
                    sub.marked_at_ns = now;
                    reset_count += 1;
                }
            }
        }

        self.total_subscribers_reset += reset_count;

        S6aRsrMessage::new_rsa(
            &rsr.session_id,
            &self.node_id,
            &self.realm,
            RESULT_CODE_SUCCESS,
        )
    }

    /// Check if a subscriber needs re-synchronization.
    pub fn needs_resync(&self, imsi: &str) -> bool {
        self.subscribers
            .iter()
            .find(|s| s.imsi == imsi)
            .map(|s| s.needs_resync)
            .unwrap_or(false)
    }

    /// Clear the resync flag once the subscriber has updated location with the HSS.
    pub fn clear_resync(&mut self, imsi: &str) -> bool {
        if let Some(sub) = self.subscribers.iter_mut().find(|s| s.imsi == imsi) {
            sub.needs_resync = false;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_targeted_reset() {
        let mut engine = S6aRsrEngine::new(
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
        );
        engine.provision_subscriber("460011111111111");
        engine.provision_subscriber("460022222222222");

        let rsr = S6aRsrMessage::new_rsr(
            "sess-rsr-001",
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            &["460011111111111"],
        );

        let rsa = engine.process_rsr(&rsr);
        assert_eq!(rsa.result_code(), Some(RESULT_CODE_SUCCESS));
        assert!(engine.needs_resync("460011111111111"));
        assert!(!engine.needs_resync("460022222222222"));
    }

    #[test]
    fn test_global_reset() {
        let mut engine = S6aRsrEngine::new("mme01", "realm");
        engine.provision_subscriber("46001");
        engine.provision_subscriber("46002");

        let rsr = S6aRsrMessage::new_rsr("sess-rsr-002", "hss01", "realm", "mme01", "realm", &[]);
        let rsa = engine.process_rsr(&rsr);
        assert_eq!(rsa.result_code(), Some(RESULT_CODE_SUCCESS));
        assert!(engine.needs_resync("46001"));
        assert!(engine.needs_resync("46002"));
    }
}
