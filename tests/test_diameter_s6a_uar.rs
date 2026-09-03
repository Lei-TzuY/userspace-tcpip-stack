use toy_tcpip::diameter_s6a_uar::{
    DIAMETER_CMD_USER_AUTHORIZATION, RESULT_CODE_ROAMING_NOT_ALLOWED, RESULT_CODE_SUCCESS,
    RESULT_CODE_USER_UNKNOWN, S6aUarEngine, S6aUarMessage, SubscriberAuthRule,
    UAR_FLAG_EMERGENCY_ATTACH,
};

#[test]
fn test_diameter_s6a_uar_lifecycle() {
    let mut hss_engine = S6aUarEngine::new(
        "hss01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
    );

    let home_plmn = [0x02, 0xF8, 0x59]; // MCC 208 MNC 95
    let roaming_partner_plmn = [0x02, 0xF8, 0x10]; // MCC 208 MNC 01
    let non_partner_plmn = [0x03, 0xF1, 0x20]; // MCC 310 MNC 20

    let imsi = "208950123456789";

    hss_engine.add_subscriber_rule(SubscriberAuthRule {
        imsi: imsi.to_string(),
        is_roaming_allowed: true,
        allowed_plmns: vec![home_plmn, roaming_partner_plmn],
    });

    // 1. Attach in home PLMN -> Allowed
    let uar_home = S6aUarMessage::new_uar(
        "sess-uar-01",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        home_plmn,
        0,
    );
    assert_eq!(uar_home.command_code, DIAMETER_CMD_USER_AUTHORIZATION);
    assert!(uar_home.is_request);
    let uaa_home = hss_engine.process_uar(&uar_home);
    assert_eq!(uaa_home.result_code(), Some(RESULT_CODE_SUCCESS));

    // 2. Attach in roaming partner PLMN -> Allowed
    let uar_partner = S6aUarMessage::new_uar(
        "sess-uar-02",
        "mme02.partner.org",
        "partner.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        roaming_partner_plmn,
        0,
    );
    let uaa_partner = hss_engine.process_uar(&uar_partner);
    assert_eq!(uaa_partner.result_code(), Some(RESULT_CODE_SUCCESS));

    // 3. Attach in unauthorized foreign PLMN -> Roaming Not Allowed
    let uar_unauth = S6aUarMessage::new_uar(
        "sess-uar-03",
        "mme03.foreign.org",
        "foreign.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        non_partner_plmn,
        0,
    );
    let uaa_unauth = hss_engine.process_uar(&uar_unauth);
    assert_eq!(
        uaa_unauth.result_code(),
        Some(RESULT_CODE_ROAMING_NOT_ALLOWED)
    );

    // 4. Emergency Attach in unauthorized foreign PLMN -> Allowed
    let uar_emg = S6aUarMessage::new_uar(
        "sess-uar-04",
        "mme03.foreign.org",
        "foreign.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        imsi,
        non_partner_plmn,
        UAR_FLAG_EMERGENCY_ATTACH,
    );
    let uaa_emg = hss_engine.process_uar(&uar_emg);
    assert_eq!(uaa_emg.result_code(), Some(RESULT_CODE_SUCCESS));

    // 5. Unknown subscriber -> User Unknown
    let uar_unknown = S6aUarMessage::new_uar(
        "sess-uar-05",
        "mme01",
        "realm",
        "realm",
        "999999999999999",
        home_plmn,
        0,
    );
    let uaa_unknown = hss_engine.process_uar(&uar_unknown);
    assert_eq!(uaa_unknown.result_code(), Some(RESULT_CODE_USER_UNKNOWN));
}
