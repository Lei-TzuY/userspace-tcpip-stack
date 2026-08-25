use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_charging::CcRequestType;
use toy_tcpip::diameter_gx::{
    GxCreditControlRequest, IpCanType, PccRule, PcefGxEngine, DIAMETER_APPLICATION_GX,
    DIAMETER_CMD_CC,
};

#[test]
fn test_diameter_gx_ccr_message_formatting() {
    let ccr = GxCreditControlRequest::new(
        "gx-session-12345",
        CcRequestType::InitialRequest,
        1,
        "imsi-208950000000001",
        IpCanType::ThreeGpp5Gs,
    );
    let msg = ccr.to_diameter_message(101, 202);
    assert_eq!(msg.header.command_code, DIAMETER_CMD_CC);
    assert_eq!(msg.header.application_id, DIAMETER_APPLICATION_GX);
    assert_eq!(msg.get_avp(263).unwrap().as_string().unwrap(), "gx-session-12345");
}

#[test]
fn test_diameter_gx_pcc_rule_grouped_avp_codec() {
    let mut rule = PccRule::new("rule-video-streaming", 2, 2_000_000, 10_000_000);
    rule.flow_descriptions.push("permit out ip from any to 10.200.0.1".to_string());

    let avp = rule.to_grouped_avp();
    let parsed = PccRule::from_grouped_avp(&avp).expect("parse PCC rule");

    assert_eq!(parsed.rule_name, "rule-video-streaming");
    assert_eq!(parsed.qci, 2);
    assert_eq!(parsed.max_bandwidth_ul_bps, 2_000_000);
    assert_eq!(parsed.max_bandwidth_dl_bps, 10_000_000);
    assert_eq!(parsed.flow_descriptions.len(), 1);
}

#[test]
fn test_pcef_gx_session_lifecycle_and_rule_installation() {
    let mut pcef = PcefGxEngine::new("pcrf.example.com");
    let sess_id = "gx-sess-ue-9988";
    let imsi = "imsi-208950000000002";

    // 1. Initial Session Establishment (CCR-I)
    let cca = pcef.handle_session_establishment(sess_id, imsi, IpCanType::ThreeGpp5Gs);
    assert_eq!(cca.header.command_code, DIAMETER_CMD_CC);
    assert_eq!(cca.header.application_id, DIAMETER_APPLICATION_GX);
    assert_eq!(cca.get_avp(268).unwrap().as_u32().unwrap(), DIAMETER_SUCCESS);

    let installed = pcef.installed_rules.get(sess_id).unwrap();
    assert_eq!(installed.len(), 2); // Default Internet (QCI 9) + IMS (QCI 5)

    // 2. Install dynamic VoLTE Voice rule (QCI 1)
    let volte = PccRule::new("rule-volte", 1, 64_000, 64_000);
    assert!(pcef.install_rule(sess_id, volte));
    assert_eq!(pcef.installed_rules.get(sess_id).unwrap().len(), 3);

    // 3. Remove rule
    assert!(pcef.remove_rule(sess_id, "rule-volte"));
    assert_eq!(pcef.installed_rules.get(sess_id).unwrap().len(), 2);

    // 4. Terminate session
    assert!(pcef.handle_session_termination(sess_id));
    assert!(!pcef.active_sessions.contains_key(sess_id));
    assert!(!pcef.installed_rules.contains_key(sess_id));
}
