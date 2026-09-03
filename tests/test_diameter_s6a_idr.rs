use toy_tcpip::diameter_s6a_idr::{
    DIAMETER_APPLICATION_S6A, DIAMETER_CMD_INSERT_SUBSCRIBER_DATA, DynamicSubscriberProfile,
    S6aIdrEngine, S6aIdrMessage,
};

#[test]
fn test_diameter_s6a_idr_hss_initiated_update() {
    let mut engine = S6aIdrEngine::new("hss.epc.mnc001.mcc460.3gppnetwork.org");

    let prof = DynamicSubscriberProfile {
        imsi: "460019988776655".into(),
        max_bandwidth_ul_kbps: 20_000,
        max_bandwidth_dl_kbps: 80_000,
        default_apn: "internet".into(),
        roaming_allowed: false,
    };

    let idr = engine.update_profile(prof);
    assert_eq!(idr.application_id, DIAMETER_APPLICATION_S6A);
    assert_eq!(idr.command_code, DIAMETER_CMD_INSERT_SUBSCRIBER_DATA);

    let ida = S6aIdrMessage::new_ida(&idr, 2001);
    assert!(engine.handle_ida(&ida));
}
