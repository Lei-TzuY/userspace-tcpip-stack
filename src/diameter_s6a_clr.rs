// =============================================================================
// 3GPP TS 29.272 Diameter S6a / S6d Cancel-Location-Request / Answer (CLR / CLA)
// Command Code 317
// =============================================================================
//
// When a subscriber moves to a new MME/SGSN or the subscription is revoked, the
// HSS issues a Cancel-Location-Request (CLR) to the previous serving node to
// trigger context tear-down and bearer release.
//
// Key AVPs:
//   - Session-Id, Origin-Host, Origin-Realm, Destination-Host, Destination-Realm
//   - User-Name (IMSI)
//   - Cancellation-Type (3GPP TS 29.272 Section 7.3.24):
//       0: MME_UPDATE_PROCEDURE
//       1: SGSN_UPDATE_PROCEDURE
//       2: SUBSCRIPTION_WITHDRAWAL
//       3: UPDATE_PROCEDURE_IWF
//       4: INITIAL_ATTACH_PROCEDURE
//   - CLR-Flags (Bit 0: S6a/S6d-Indicator)
//   - Result-Code (2001 SUCCESS, 5001 USER_UNKNOWN)
//
// Pure safe Rust, zero external crates.

/// Diameter Application ID for S6a/S6d (3GPP TS 29.272).
pub const DIAMETER_APPLICATION_S6A: u32 = 16_777_251;

/// Command Code for Cancel-Location-Request / Answer.
pub const DIAMETER_CMD_CANCEL_LOCATION: u32 = 317;

/// Diameter Result-Code: DIAMETER_SUCCESS (2001).
pub const RESULT_CODE_SUCCESS: u32 = 2001;

/// Diameter Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001).
pub const RESULT_CODE_USER_UNKNOWN: u32 = 5001;

/// 3GPP Cancellation-Type (TS 29.272 AVP 1420).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationType {
    MmeUpdateProcedure = 0,
    SgsnUpdateProcedure = 1,
    SubscriptionWithdrawal = 2,
    UpdateProcedureIwf = 3,
    InitialAttachProcedure = 4,
}

impl CancellationType {
    pub fn from_u32(val: u32) -> Option<Self> {
        match val {
            0 => Some(Self::MmeUpdateProcedure),
            1 => Some(Self::SgsnUpdateProcedure),
            2 => Some(Self::SubscriptionWithdrawal),
            3 => Some(Self::UpdateProcedureIwf),
            4 => Some(Self::InitialAttachProcedure),
            _ => None,
        }
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

/// AVP representation for S6a CLR/CLA messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aClrAvp {
    SessionId(String),
    OriginHost(String),
    OriginRealm(String),
    DestinationHost(String),
    DestinationRealm(String),
    UserName(String), // IMSI
    CancellationType(u32),
    ClrFlags(u32),
    ResultCode(u32),
}

/// Cancel-Location-Request or Answer message.
#[derive(Debug, Clone)]
pub struct S6aClrMessage {
    pub command_code: u32,
    pub application_id: u32,
    pub is_request: bool,
    pub session_id: String,
    pub avps: Vec<S6aClrAvp>,
}

impl S6aClrMessage {
    /// Construct a new Cancel-Location-Request (HSS -> MME).
    pub fn new_clr(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        dest_host: &str,
        dest_realm: &str,
        imsi: &str,
        cancel_type: CancellationType,
        clr_flags: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_CANCEL_LOCATION,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: true,
            session_id: session_id.to_string(),
            avps: vec![
                S6aClrAvp::SessionId(session_id.to_string()),
                S6aClrAvp::OriginHost(origin_host.to_string()),
                S6aClrAvp::OriginRealm(origin_realm.to_string()),
                S6aClrAvp::DestinationHost(dest_host.to_string()),
                S6aClrAvp::DestinationRealm(dest_realm.to_string()),
                S6aClrAvp::UserName(imsi.to_string()),
                S6aClrAvp::CancellationType(cancel_type.to_u32()),
                S6aClrAvp::ClrFlags(clr_flags),
            ],
        }
    }

    /// Construct a new Cancel-Location-Answer (MME -> HSS).
    pub fn new_cla(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_CANCEL_LOCATION,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: false,
            session_id: session_id.to_string(),
            avps: vec![
                S6aClrAvp::SessionId(session_id.to_string()),
                S6aClrAvp::OriginHost(origin_host.to_string()),
                S6aClrAvp::OriginRealm(origin_realm.to_string()),
                S6aClrAvp::ResultCode(result_code),
            ],
        }
    }

    /// Extract IMSI from message.
    pub fn imsi(&self) -> Option<&str> {
        self.avps.iter().find_map(|avp| match avp {
            S6aClrAvp::UserName(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Extract CancellationType.
    pub fn cancellation_type(&self) -> Option<CancellationType> {
        self.avps.iter().find_map(|avp| match avp {
            S6aClrAvp::CancellationType(t) => CancellationType::from_u32(*t),
            _ => None,
        })
    }

    /// Extract Result-Code.
    pub fn result_code(&self) -> Option<u32> {
        self.avps.iter().find_map(|avp| match avp {
            S6aClrAvp::ResultCode(rc) => Some(*rc),
            _ => None,
        })
    }
}

/// MME Serving Subscriber Record.
#[derive(Debug, Clone)]
pub struct MmeSubscriberSession {
    pub imsi: String,
    pub is_active: bool,
    pub cancellation_reason: Option<CancellationType>,
}

/// MME/SGSN Cancel-Location (CLR/CLA) Handler Engine.
pub struct S6aClrEngine {
    pub mme_id: String,
    pub realm: String,
    pub active_subscribers: Vec<MmeSubscriberSession>,
    pub total_clr_received: u64,
    pub total_cancelled_success: u64,
    pub total_rejected: u64,
}

impl S6aClrEngine {
    pub fn new(mme_id: &str, realm: &str) -> Self {
        Self {
            mme_id: mme_id.to_string(),
            realm: realm.to_string(),
            active_subscribers: Vec::new(),
            total_clr_received: 0,
            total_cancelled_success: 0,
            total_rejected: 0,
        }
    }

    /// Attach a subscriber to this MME.
    pub fn attach_subscriber(&mut self, imsi: &str) {
        if let Some(pos) = self.active_subscribers.iter().position(|s| s.imsi == imsi) {
            self.active_subscribers[pos].is_active = true;
            self.active_subscribers[pos].cancellation_reason = None;
        } else {
            self.active_subscribers.push(MmeSubscriberSession {
                imsi: imsi.to_string(),
                is_active: true,
                cancellation_reason: None,
            });
        }
    }

    /// Process incoming Cancel-Location-Request (CLR) from HSS.
    pub fn process_clr(&mut self, clr: &S6aClrMessage) -> S6aClrMessage {
        self.total_clr_received += 1;

        let imsi = match clr.imsi() {
            Some(i) => i,
            None => {
                self.total_rejected += 1;
                return S6aClrMessage::new_cla(
                    &clr.session_id,
                    &self.mme_id,
                    &self.realm,
                    RESULT_CODE_USER_UNKNOWN,
                );
            }
        };

        let cancel_type = clr
            .cancellation_type()
            .unwrap_or(CancellationType::MmeUpdateProcedure);

        if let Some(sub) = self.active_subscribers.iter_mut().find(|s| s.imsi == imsi) {
            sub.is_active = false;
            sub.cancellation_reason = Some(cancel_type);
            self.total_cancelled_success += 1;
            S6aClrMessage::new_cla(
                &clr.session_id,
                &self.mme_id,
                &self.realm,
                RESULT_CODE_SUCCESS,
            )
        } else {
            self.total_rejected += 1;
            S6aClrMessage::new_cla(
                &clr.session_id,
                &self.mme_id,
                &self.realm,
                RESULT_CODE_USER_UNKNOWN,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cancel_location_lifecycle() {
        let mut mme_engine = S6aClrEngine::new(
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
        );

        let imsi = "208950000000001";
        mme_engine.attach_subscriber(imsi);

        assert!(mme_engine.active_subscribers[0].is_active);

        // HSS sends CLR due to UE moving to another MME (MmeUpdateProcedure)
        let clr = S6aClrMessage::new_clr(
            "sess-clr-01",
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            imsi,
            CancellationType::MmeUpdateProcedure,
            0,
        );

        let cla = mme_engine.process_clr(&clr);
        assert_eq!(cla.result_code(), Some(RESULT_CODE_SUCCESS));
        assert!(!mme_engine.active_subscribers[0].is_active);
        assert_eq!(
            mme_engine.active_subscribers[0].cancellation_reason,
            Some(CancellationType::MmeUpdateProcedure)
        );

        // Second CLR for unknown IMSI -> USER_UNKNOWN
        let clr_unknown = S6aClrMessage::new_clr(
            "sess-clr-02",
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "999999999999999",
            CancellationType::SubscriptionWithdrawal,
            0,
        );
        let cla_unknown = mme_engine.process_clr(&clr_unknown);
        assert_eq!(cla_unknown.result_code(), Some(RESULT_CODE_USER_UNKNOWN));
    }
}
