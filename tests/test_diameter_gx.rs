use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_charging::CcRequestType;
use toy_tcpip::diameter_gx::{
    DIAMETER_APPLICATION_GX, DIAMETER_CMD_CC, GxCreditControlRequest, IpCanType, PccRule,
    PcefGxEngine,
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
    assert_eq!(
        msg.get_avp(263).unwrap().as_string().unwrap(),
        "gx-session-12345"
    );
}

#[test]
fn test_diameter_gx_pcc_rule_grouped_avp_codec() {
    let mut rule = PccRule::new("rule-video-streaming", 2, 2_000_000, 10_000_000);
    rule.flow_descriptions
        .push("permit out ip from any to 10.200.0.1".to_string());

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
    assert_eq!(
        cca.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );

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

#[test]
fn test_diameter_gx_rar_raa_wire_codec() {
    use toy_tcpip::diameter_gx::{
        DIAMETER_APPLICATION_GX, DIAMETER_CMD_RE_AUTH, GxReAuthAnswer, GxReAuthRequest,
    };

    let mut volte_rule = PccRule::new("rule-volte-qci1", 1, 64_000, 64_000);
    volte_rule
        .flow_descriptions
        .push("permit out udp from any to 10.0.0.1 4000-4020".to_string());

    let rar = GxReAuthRequest {
        session_id: "gx-rar-session-555".to_string(),
        origin_host: "pcrf01.carrier.net".to_string(),
        origin_realm: "carrier.net".to_string(),
        destination_host: "smf01.carrier.net".to_string(),
        destination_realm: "carrier.net".to_string(),
        rules_to_install: vec![volte_rule.clone()],
        rules_to_remove: vec!["rule-temp-boost".to_string()],
        event_triggers: vec![101],
    };

    let msg = rar.to_diameter_message(301, 302);
    assert_eq!(msg.header.command_code, DIAMETER_CMD_RE_AUTH);
    assert_eq!(msg.header.application_id, DIAMETER_APPLICATION_GX);
    assert!(msg.header.is_request());

    let parsed_rar = GxReAuthRequest::from_diameter_message(&msg).expect("parse Gx RAR");
    assert_eq!(parsed_rar.session_id, "gx-rar-session-555");
    assert_eq!(parsed_rar.rules_to_install.len(), 1);
    assert_eq!(parsed_rar.rules_to_install[0].rule_name, "rule-volte-qci1");
    assert_eq!(parsed_rar.rules_to_install[0].qci, 1);
    assert_eq!(parsed_rar.rules_to_remove, vec!["rule-temp-boost"]);
    assert_eq!(parsed_rar.event_triggers, vec![101]);

    // Test Gx RAA Answer
    let raa = GxReAuthAnswer {
        session_id: "gx-rar-session-555".to_string(),
        result_code: DIAMETER_SUCCESS,
        origin_host: "smf01.carrier.net".to_string(),
        origin_realm: "carrier.net".to_string(),
    };
    let ans_msg = raa.to_diameter_message(301, 302);
    assert_eq!(ans_msg.header.command_code, DIAMETER_CMD_RE_AUTH);
    assert!(!ans_msg.header.is_request());

    let parsed_raa = GxReAuthAnswer::from_diameter_message(&ans_msg).expect("parse Gx RAA");
    assert_eq!(parsed_raa, raa);
}

#[test]
fn test_diameter_gx_pcrf_pcef_push_rule_and_traffic_enforcement() {
    use toy_tcpip::diameter_gx::{PccRule, PcrfGxEngine};

    let mut pcrf = PcrfGxEngine::new("pcrf.carrier.com", "carrier.com");
    let mut pcef = PcefGxEngine::new("carrier.com");

    let sess_id = "gx-sess-ue-1001";
    let imsi = "imsi-460011223344556";

    // 1. Initial attach (CCR-I) creates session on PCRF and provisions defaults on PCEF
    let ccr = GxCreditControlRequest::new(
        sess_id,
        CcRequestType::InitialRequest,
        1,
        imsi,
        IpCanType::ThreeGppEps,
    );
    let (cca, _rules) = pcrf.handle_ccr_initial(&ccr);
    assert_eq!(
        cca.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(pcrf.active_session_count(), 1);

    pcef.handle_session_establishment(sess_id, imsi, IpCanType::ThreeGppEps);
    assert_eq!(pcef.installed_rules.get(sess_id).unwrap().len(), 2); // Internet + IMS

    // 2. PCRF proactively pushes VoLTE Dedicated Bearer (QCI 1) via RAR
    let mut volte_voice = PccRule::new("rule-volte-voice", 1, 32_000, 32_000);
    volte_voice
        .flow_descriptions
        .push("permit out udp from 10.10.1.5 to 10.20.1.5 5004".to_string());

    let rar = pcrf
        .push_rar(
            sess_id,
            "pgw01.carrier.com",
            "carrier.com",
            vec![volte_voice],
            vec!["rule-default-internet".to_string()], // Deprioritize / remove default internet during dedicated call
        )
        .expect("generate RAR");

    let raa = pcef.handle_rar(&rar, "pgw01.carrier.com", "carrier.com");
    assert_eq!(raa.result_code, DIAMETER_SUCCESS);

    let installed_pcef = pcef.installed_rules.get(sess_id).unwrap();
    assert_eq!(installed_pcef.len(), 2); // IMS signalling + VoLTE voice (Internet was removed)
    assert!(
        installed_pcef
            .iter()
            .any(|r| r.rule_name == "rule-volte-voice")
    );
    assert!(
        !installed_pcef
            .iter()
            .any(|r| r.rule_name == "rule-default-internet")
    );

    // 3. Evaluate packet enforcement
    // Matches VoLTE Voice filter -> Allowed and counted
    let matched_voice = pcef.enforce_traffic(sess_id, "10.10.1.5 to 10.20.1.5 5004", 160);
    assert!(matched_voice.is_some());
    assert_eq!(matched_voice.unwrap().qci, 1);
    assert_eq!(pcef.total_enforced_bytes, 160);

    // Unmatched arbitrary packet (Internet rule was removed) -> Denied / None
    let unmatched = pcef.enforce_traffic(sess_id, "192.168.100.1 to 8.8.8.8 443", 500);
    assert!(unmatched.is_none());
    assert_eq!(pcef.total_enforced_bytes, 160); // Byte count remains unchanged

    // 4. Teardown
    assert!(pcrf.terminate_session(sess_id));
    assert!(pcef.handle_session_termination(sess_id));
    assert_eq!(pcrf.active_session_count(), 0);
}
