// =============================================================================
// 3GPP TS 29.272 Diameter S6a / S6d User-Authorization-Request / Answer (UAR / UAA)
// Command Code 316
// =============================================================================
//
// The User-Authorization procedure is invoked by an MME/SGSN or Diameter Edge
// Agent (DEA) prior to full authentication/location update to verify whether
// a subscriber (IMSI) is authorized to attach in a specific Visited PLMN (VPLMN)
// and to query roaming restrictions or HSS identity.
//
// Key AVPs:
//   - Session-Id, Origin-Host, Origin-Realm, Destination-Host, Destination-Realm
//   - User-Name (IMSI)
//   - Visited-PLMN-Id (MCC + MNC 3-octet encoded format)
//   - UAR-Flags (bitmask: e.g. Emergency Attach, CSFB support)
//   - Result-Code (2001 SUCCESS, 5004 USER_UNKNOWN, 5005 ROAMING_NOT_ALLOWED)
//
// Pure safe Rust, zero external crates.

/// Diameter Application ID for S6a/S6d (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S6A: u32 = 16_777_251;

/// Command Code for User-Authorization-Request / Answer.
pub const DIAMETER_CMD_USER_AUTHORIZATION: u32 = 316;

/// Diameter Result-Code: DIAMETER_SUCCESS (2001).
pub const RESULT_CODE_SUCCESS: u32 = 2001;

/// Diameter Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001).
pub const RESULT_CODE_USER_UNKNOWN: u32 = 5001;

/// Diameter Result-Code: DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004).
pub const RESULT_CODE_ROAMING_NOT_ALLOWED: u32 = 5004;

/// UAR-Flags: Emergency registration indicator.
pub const UAR_FLAG_EMERGENCY_ATTACH: u32 = 0x0000_0001;

/// UAR-Flags: SMS in MME indicator.
pub const UAR_FLAG_SMS_IN_MME: u32 = 0x0000_0002;

/// AVP representation for S6a UAR/UAA messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aUarAvp {
    SessionId(String),
    OriginHost(String),
    OriginRealm(String),
    DestinationHost(String),
    DestinationRealm(String),
    UserName(String),       // IMSI
    VisitedPlmnId([u8; 3]), // 3-octet encoded MCC/MNC
    UarFlags(u32),
    ResultCode(u32),
}

/// User-Authorization-Request or Answer message.
#[derive(Debug, Clone)]
pub struct S6aUarMessage {
    pub command_code: u32,
    pub application_id: u32,
    pub is_request: bool,
    pub session_id: String,
    pub avps: Vec<S6aUarAvp>,
}

impl S6aUarMessage {
    /// Construct a new User-Authorization-Request (MME -> HSS).
    pub fn new_uar(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        dest_realm: &str,
        imsi: &str,
        visited_plmn: [u8; 3],
        flags: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_USER_AUTHORIZATION,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: true,
            session_id: session_id.to_string(),
            avps: vec![
                S6aUarAvp::SessionId(session_id.to_string()),
                S6aUarAvp::OriginHost(origin_host.to_string()),
                S6aUarAvp::OriginRealm(origin_realm.to_string()),
                S6aUarAvp::DestinationRealm(dest_realm.to_string()),
                S6aUarAvp::UserName(imsi.to_string()),
                S6aUarAvp::VisitedPlmnId(visited_plmn),
                S6aUarAvp::UarFlags(flags),
            ],
        }
    }

    /// Construct a new User-Authorization-Answer (HSS -> MME).
    pub fn new_uaa(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_USER_AUTHORIZATION,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: false,
            session_id: session_id.to_string(),
            avps: vec![
                S6aUarAvp::SessionId(session_id.to_string()),
                S6aUarAvp::OriginHost(origin_host.to_string()),
                S6aUarAvp::OriginRealm(origin_realm.to_string()),
                S6aUarAvp::ResultCode(result_code),
            ],
        }
    }

    /// Extract IMSI from message.
    pub fn imsi(&self) -> Option<&str> {
        self.avps.iter().find_map(|avp| match avp {
            S6aUarAvp::UserName(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Extract Visited-PLMN-Id.
    pub fn visited_plmn(&self) -> Option<[u8; 3]> {
        self.avps.iter().find_map(|avp| match avp {
            S6aUarAvp::VisitedPlmnId(p) => Some(*p),
            _ => None,
        })
    }

    /// Extract UAR Flags.
    pub fn uar_flags(&self) -> u32 {
        self.avps
            .iter()
            .find_map(|avp| match avp {
                S6aUarAvp::UarFlags(f) => Some(*f),
                _ => None,
            })
            .unwrap_or(0)
    }

    /// Extract Result-Code.
    pub fn result_code(&self) -> Option<u32> {
        self.avps.iter().find_map(|avp| match avp {
            S6aUarAvp::ResultCode(rc) => Some(*rc),
            _ => None,
        })
    }
}

/// Roaming policy rule for a subscriber.
#[derive(Debug, Clone)]
pub struct SubscriberAuthRule {
    pub imsi: String,
    pub is_roaming_allowed: bool,
    /// Explicit allowed PLMNs (empty = all allowed if is_roaming_allowed == true).
    pub allowed_plmns: Vec<[u8; 3]>,
}

/// HSS User-Authorization (UAR/UAA) Server Engine.
pub struct S6aUarEngine {
    pub hss_id: String,
    pub realm: String,
    pub subscriber_rules: Vec<SubscriberAuthRule>,
    pub total_uar_processed: u64,
    pub total_authorized: u64,
    pub total_rejected: u64,
}

impl S6aUarEngine {
    pub fn new(hss_id: &str, realm: &str) -> Self {
        Self {
            hss_id: hss_id.to_string(),
            realm: realm.to_string(),
            subscriber_rules: Vec::new(),
            total_uar_processed: 0,
            total_authorized: 0,
            total_rejected: 0,
        }
    }

    /// Add a subscriber authorization entry to the HSS database.
    pub fn add_subscriber_rule(&mut self, rule: SubscriberAuthRule) {
        if let Some(pos) = self
            .subscriber_rules
            .iter()
            .position(|r| r.imsi == rule.imsi)
        {
            self.subscriber_rules[pos] = rule;
        } else {
            self.subscriber_rules.push(rule);
        }
    }

    /// Process incoming User-Authorization-Request (UAR).
    pub fn process_uar(&mut self, uar: &S6aUarMessage) -> S6aUarMessage {
        self.total_uar_processed += 1;

        let imsi = match uar.imsi() {
            Some(i) => i,
            None => {
                self.total_rejected += 1;
                return S6aUarMessage::new_uaa(
                    &uar.session_id,
                    &self.hss_id,
                    &self.realm,
                    RESULT_CODE_USER_UNKNOWN,
                );
            }
        };

        let vplmn = uar.visited_plmn().unwrap_or([0, 0, 0]);
        let flags = uar.uar_flags();

        // Emergency attach is always authorized by 3GPP spec regardless of subscription
        if (flags & UAR_FLAG_EMERGENCY_ATTACH) != 0 {
            self.total_authorized += 1;
            return S6aUarMessage::new_uaa(
                &uar.session_id,
                &self.hss_id,
                &self.realm,
                RESULT_CODE_SUCCESS,
            );
        }

        let rule = self.subscriber_rules.iter().find(|r| r.imsi == imsi);
        match rule {
            None => {
                self.total_rejected += 1;
                S6aUarMessage::new_uaa(
                    &uar.session_id,
                    &self.hss_id,
                    &self.realm,
                    RESULT_CODE_USER_UNKNOWN,
                )
            }
            Some(r) => {
                if !r.is_roaming_allowed {
                    self.total_rejected += 1;
                    S6aUarMessage::new_uaa(
                        &uar.session_id,
                        &self.hss_id,
                        &self.realm,
                        RESULT_CODE_ROAMING_NOT_ALLOWED,
                    )
                } else if !r.allowed_plmns.is_empty() && !r.allowed_plmns.contains(&vplmn) {
                    self.total_rejected += 1;
                    S6aUarMessage::new_uaa(
                        &uar.session_id,
                        &self.hss_id,
                        &self.realm,
                        RESULT_CODE_ROAMING_NOT_ALLOWED,
                    )
                } else {
                    self.total_authorized += 1;
                    S6aUarMessage::new_uaa(
                        &uar.session_id,
                        &self.hss_id,
                        &self.realm,
                        RESULT_CODE_SUCCESS,
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uar_authorization_lifecycle() {
        let mut engine = S6aUarEngine::new("hss01", "epc.mnc001.mcc208.3gppnetwork.org");

        let home_plmn = [0x02, 0xF8, 0x59]; // MCC 208 MNC 95
        let foreign_plmn = [0x02, 0xF8, 0x10]; // MCC 208 MNC 01

        engine.add_subscriber_rule(SubscriberAuthRule {
            imsi: "208950000000001".to_string(),
            is_roaming_allowed: true,
            allowed_plmns: vec![home_plmn],
        });

        // 1. Authorized PLMN
        let uar_ok = S6aUarMessage::new_uar(
            "sess-1",
            "mme01",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "208950000000001",
            home_plmn,
            0,
        );
        let uaa_ok = engine.process_uar(&uar_ok);
        assert_eq!(uaa_ok.result_code(), Some(RESULT_CODE_SUCCESS));

        // 2. Barred Roaming PLMN
        let uar_roam = S6aUarMessage::new_uar(
            "sess-2",
            "mme01",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "208950000000001",
            foreign_plmn,
            0,
        );
        let uaa_roam = engine.process_uar(&uar_roam);
        assert_eq!(
            uaa_roam.result_code(),
            Some(RESULT_CODE_ROAMING_NOT_ALLOWED)
        );

        // 3. Emergency Attach on barred PLMN -> Overrides to Success
        let uar_emg = S6aUarMessage::new_uar(
            "sess-3",
            "mme01",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "208950000000001",
            foreign_plmn,
            UAR_FLAG_EMERGENCY_ATTACH,
        );
        let uaa_emg = engine.process_uar(&uar_emg);
        assert_eq!(uaa_emg.result_code(), Some(RESULT_CODE_SUCCESS));
    }
}
