// =============================================================================
// 3GPP TS 29.272 Diameter S6a / S6d Notify-Request / Answer (NOR / NOA)
// Command Code 323
// =============================================================================
//
// The MME/SGSN sends a Notify-Request (NOR) to the HSS to update subscriber state
// changes such as:
//   - SRVCC (Single Radio Voice Call Continuity) support capability
//   - IMEI / Terminal equipment change
//   - Short Message memory availability ("Ready for SM")
//   - Single registration indication
//
// Key AVPs:
//   - Session-Id, Origin-Host, Origin-Realm, Destination-Host, Destination-Realm
//   - User-Name (IMSI)
//   - NOR-Flags (Bitmask):
//       Bit 0: Single-Registration-Indication (1)
//       Bit 1: SRVCC-Support-Indication (2)
//       Bit 2: Initial-Attach-Indication (4)
//       Bit 3: Ready-for-SM (8)
//   - Terminal-Information (IMEI / Software-Version)
//   - Result-Code (2001 SUCCESS, 5001 USER_UNKNOWN)
//
// Pure safe Rust, zero external crates.

/// Diameter Application ID for S6a/S6d.
pub const DIAMETER_APPLICATION_S6A: u32 = 16_777_251;

/// Command Code for Notify-Request / Answer.
pub const DIAMETER_CMD_NOTIFY: u32 = 323;

/// NOR-Flags constants (3GPP TS 29.272 Section 7.3.110).
pub const NOR_FLAG_SINGLE_REGISTRATION: u32 = 1 << 0;
pub const NOR_FLAG_SRVCC_SUPPORT: u32 = 1 << 1;
pub const NOR_FLAG_INITIAL_ATTACH: u32 = 1 << 2;
pub const NOR_FLAG_READY_FOR_SM: u32 = 1 << 3;

/// Diameter Result-Code: DIAMETER_SUCCESS (2001).
pub const RESULT_CODE_SUCCESS: u32 = 2001;

/// Diameter Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001).
pub const RESULT_CODE_USER_UNKNOWN: u32 = 5001;

/// AVP representation for S6a NOR/NOA messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S6aNorAvp {
    SessionId(String),
    OriginHost(String),
    OriginRealm(String),
    DestinationHost(String),
    DestinationRealm(String),
    UserName(String), // IMSI
    NorFlags(u32),
    TerminalImei(String),
    ResultCode(u32),
}

/// Notify-Request or Answer message.
#[derive(Debug, Clone)]
pub struct S6aNorMessage {
    pub command_code: u32,
    pub application_id: u32,
    pub is_request: bool,
    pub session_id: String,
    pub avps: Vec<S6aNorAvp>,
}

impl S6aNorMessage {
    /// Create a new Notify-Request (MME -> HSS).
    pub fn new_nor(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        dest_host: &str,
        dest_realm: &str,
        imsi: &str,
        nor_flags: u32,
        terminal_imei: Option<&str>,
    ) -> Self {
        let mut avps = vec![
            S6aNorAvp::SessionId(session_id.to_string()),
            S6aNorAvp::OriginHost(origin_host.to_string()),
            S6aNorAvp::OriginRealm(origin_realm.to_string()),
            S6aNorAvp::DestinationHost(dest_host.to_string()),
            S6aNorAvp::DestinationRealm(dest_realm.to_string()),
            S6aNorAvp::UserName(imsi.to_string()),
            S6aNorAvp::NorFlags(nor_flags),
        ];
        if let Some(imei) = terminal_imei {
            avps.push(S6aNorAvp::TerminalImei(imei.to_string()));
        }

        Self {
            command_code: DIAMETER_CMD_NOTIFY,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: true,
            session_id: session_id.to_string(),
            avps,
        }
    }

    /// Create a new Notify-Answer (HSS -> MME).
    pub fn new_noa(
        session_id: &str,
        origin_host: &str,
        origin_realm: &str,
        result_code: u32,
    ) -> Self {
        Self {
            command_code: DIAMETER_CMD_NOTIFY,
            application_id: DIAMETER_APPLICATION_S6A,
            is_request: false,
            session_id: session_id.to_string(),
            avps: vec![
                S6aNorAvp::SessionId(session_id.to_string()),
                S6aNorAvp::OriginHost(origin_host.to_string()),
                S6aNorAvp::OriginRealm(origin_realm.to_string()),
                S6aNorAvp::ResultCode(result_code),
            ],
        }
    }

    /// Extract IMSI.
    pub fn imsi(&self) -> Option<&str> {
        self.avps.iter().find_map(|avp| match avp {
            S6aNorAvp::UserName(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Extract NOR-Flags.
    pub fn nor_flags(&self) -> Option<u32> {
        self.avps.iter().find_map(|avp| match avp {
            S6aNorAvp::NorFlags(f) => Some(*f),
            _ => None,
        })
    }

    /// Extract Terminal IMEI.
    pub fn imei(&self) -> Option<&str> {
        self.avps.iter().find_map(|avp| match avp {
            S6aNorAvp::TerminalImei(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Extract Result-Code.
    pub fn result_code(&self) -> Option<u32> {
        self.avps.iter().find_map(|avp| match avp {
            S6aNorAvp::ResultCode(rc) => Some(*rc),
            _ => None,
        })
    }
}

/// HSS Subscriber State Record for Notifications.
#[derive(Debug, Clone)]
pub struct HssNotifiedState {
    pub imsi: String,
    pub srvcc_supported: bool,
    pub ready_for_sm: bool,
    pub current_imei: Option<String>,
}

/// HSS Notify (NOR/NOA) Handler Engine.
pub struct S6aNorEngine {
    pub hss_id: String,
    pub realm: String,
    pub subscribers: Vec<HssNotifiedState>,
    pub total_nor_received: u64,
    pub total_nor_accepted: u64,
    pub total_nor_rejected: u64,
}

impl S6aNorEngine {
    pub fn new(hss_id: &str, realm: &str) -> Self {
        Self {
            hss_id: hss_id.to_string(),
            realm: realm.to_string(),
            subscribers: Vec::new(),
            total_nor_received: 0,
            total_nor_accepted: 0,
            total_nor_rejected: 0,
        }
    }

    /// Register a provisioned subscriber.
    pub fn register_subscriber(&mut self, imsi: &str) {
        if !self.subscribers.iter().any(|s| s.imsi == imsi) {
            self.subscribers.push(HssNotifiedState {
                imsi: imsi.to_string(),
                srvcc_supported: false,
                ready_for_sm: false,
                current_imei: None,
            });
        }
    }

    /// Process incoming Notify-Request (NOR).
    pub fn process_nor(&mut self, nor: &S6aNorMessage) -> S6aNorMessage {
        self.total_nor_received += 1;

        let imsi = match nor.imsi() {
            Some(i) => i,
            None => {
                self.total_nor_rejected += 1;
                return S6aNorMessage::new_noa(
                    &nor.session_id,
                    &self.hss_id,
                    &self.realm,
                    RESULT_CODE_USER_UNKNOWN,
                );
            }
        };

        let flags = nor.nor_flags().unwrap_or(0);
        let imei = nor.imei();

        if let Some(sub) = self.subscribers.iter_mut().find(|s| s.imsi == imsi) {
            sub.srvcc_supported = (flags & NOR_FLAG_SRVCC_SUPPORT) != 0;
            sub.ready_for_sm = (flags & NOR_FLAG_READY_FOR_SM) != 0;
            if let Some(im) = imei {
                sub.current_imei = Some(im.to_string());
            }
            self.total_nor_accepted += 1;
            S6aNorMessage::new_noa(
                &nor.session_id,
                &self.hss_id,
                &self.realm,
                RESULT_CODE_SUCCESS,
            )
        } else {
            self.total_nor_rejected += 1;
            S6aNorMessage::new_noa(
                &nor.session_id,
                &self.hss_id,
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
    fn test_notify_nor_noa_lifecycle() {
        let mut hss = S6aNorEngine::new(
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
        );
        let imsi = "208950123456789";
        hss.register_subscriber(imsi);

        // 1. MME reports SRVCC support and IMEI update
        let nor = S6aNorMessage::new_nor(
            "sess-nor-01",
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            imsi,
            NOR_FLAG_SRVCC_SUPPORT | NOR_FLAG_READY_FOR_SM,
            Some("860123456789012"),
        );

        let noa = hss.process_nor(&nor);
        assert_eq!(noa.result_code(), Some(RESULT_CODE_SUCCESS));

        let sub = hss.subscribers.iter().find(|s| s.imsi == imsi).unwrap();
        assert!(sub.srvcc_supported);
        assert!(sub.ready_for_sm);
        assert_eq!(sub.current_imei.as_deref(), Some("860123456789012"));

        // 2. NOR for unknown IMSI -> USER_UNKNOWN
        let nor_unk = S6aNorMessage::new_nor(
            "sess-nor-02",
            "mme01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "hss01.epc.mnc001.mcc208.3gppnetwork.org",
            "epc.mnc001.mcc208.3gppnetwork.org",
            "999999999999999",
            0,
            None,
        );
        let noa_unk = hss.process_nor(&nor_unk);
        assert_eq!(noa_unk.result_code(), Some(RESULT_CODE_USER_UNKNOWN));
    }
}
