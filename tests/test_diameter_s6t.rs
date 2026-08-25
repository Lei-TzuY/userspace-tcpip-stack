use toy_tcpip::diameter_s6t::{
    MonitoringEventConfig, MonitoringEventType, S6tAvp, S6tMessage, ScefS6tHssEngine,
    DIAMETER_APPLICATION_S6T, DIAMETER_CMD_CONFIGURATION_INFORMATION,
};

#[test]
fn test_diameter_s6t_ciot_monitoring_event() {
    let mut hss = ScefS6tHssEngine::new("hss01.ciot.telco");
    let cfg = MonitoringEventConfig {
        scef_id: "scef.node.net".into(),
        scef_ref_id: 101,
        event_type: MonitoringEventType::LossOfConnectivity,
    };
    let cir = S6tMessage::new_cir("s6t-test-session", "460011112222333", cfg);
    assert_eq!(cir.application_id, DIAMETER_APPLICATION_S6T);
    assert_eq!(cir.command_code, DIAMETER_CMD_CONFIGURATION_INFORMATION);

    let cia = hss.handle_cir(&cir);
    let rc = cia.avps.iter().find_map(|a| if let S6tAvp::ResultCode(c) = a { Some(*c) } else { None });
    assert_eq!(rc, Some(2001));
    assert_eq!(hss.total_cir_requests, 1);
}
