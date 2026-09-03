use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_sy::{
    DIAMETER_APPLICATION_SY, DIAMETER_CMD_SPENDING_LIMIT,
    DIAMETER_CMD_SPENDING_STATUS_NOTIFICATION, OcsSyEngine, PcrfSyClient,
    PolicyCounterStatusReport, SlRequestType, SpendingLimitAnswer, SpendingLimitRequest,
    SpendingStatusNotificationRequest,
};

#[test]
fn test_diameter_sy_slr_sla_codec() {
    let slr = SpendingLimitRequest::new(
        "sy-sess-001",
        SlRequestType::InitialRequest,
        "imsi-460012345678901",
    )
    .with_counter("data-highspeed-50gb")
    .with_counter("voice-roaming-300m");

    let msg = slr.to_diameter_message(1001, 2002);
    assert_eq!(msg.header.application_id, DIAMETER_APPLICATION_SY);
    assert_eq!(msg.header.command_code, DIAMETER_CMD_SPENDING_LIMIT);
    assert!(msg.header.is_request());

    let parsed_slr = SpendingLimitRequest::from_diameter_message(&msg).expect("parse SLR");
    assert_eq!(parsed_slr.session_id, "sy-sess-001");
    assert_eq!(parsed_slr.request_type, SlRequestType::InitialRequest);
    assert_eq!(parsed_slr.subscription_id, "imsi-460012345678901");
    assert_eq!(parsed_slr.subscribed_counters.len(), 2);
    assert_eq!(parsed_slr.subscribed_counters[0], "data-highspeed-50gb");
    assert_eq!(parsed_slr.subscribed_counters[1], "voice-roaming-300m");

    // Test SLA with Grouped Status Reports
    let r1 = PolicyCounterStatusReport::new("data-highspeed-50gb", "BELOW_THRESHOLD");
    let r2 = PolicyCounterStatusReport::new("voice-roaming-300m", "AVAILABLE");
    let sla = SpendingLimitAnswer::new("sy-sess-001", DIAMETER_SUCCESS)
        .with_report(r1)
        .with_report(r2);

    let sla_msg = sla.to_diameter_message(1001, 2002);
    assert!(!sla_msg.header.is_request());
    let parsed_sla = SpendingLimitAnswer::from_diameter_message(&sla_msg).expect("parse SLA");
    assert_eq!(parsed_sla.session_id, "sy-sess-001");
    assert_eq!(parsed_sla.result_code, DIAMETER_SUCCESS);
    assert_eq!(parsed_sla.reports.len(), 2);
    assert_eq!(parsed_sla.reports[0].counter_id, "data-highspeed-50gb");
    assert_eq!(parsed_sla.reports[0].current_status, "BELOW_THRESHOLD");
    assert_eq!(parsed_sla.reports[1].counter_id, "voice-roaming-300m");
    assert_eq!(parsed_sla.reports[1].current_status, "AVAILABLE");
}

#[test]
fn test_diameter_sy_snr_sna_codec() {
    let report = PolicyCounterStatusReport::new("data-highspeed-50gb", "EXCEEDED_THRESHOLD");
    let snr = SpendingStatusNotificationRequest::new("sy-sess-002").with_report(report);

    let msg = snr.to_diameter_message(3001, 4002);
    assert_eq!(msg.header.application_id, DIAMETER_APPLICATION_SY);
    assert_eq!(
        msg.header.command_code,
        DIAMETER_CMD_SPENDING_STATUS_NOTIFICATION
    );
    assert!(msg.header.is_request());

    let parsed_snr =
        SpendingStatusNotificationRequest::from_diameter_message(&msg).expect("parse SNR");
    assert_eq!(parsed_snr.session_id, "sy-sess-002");
    assert_eq!(parsed_snr.reports.len(), 1);
    assert_eq!(parsed_snr.reports[0].counter_id, "data-highspeed-50gb");
    assert_eq!(parsed_snr.reports[0].current_status, "EXCEEDED_THRESHOLD");
}

#[test]
fn test_diameter_sy_ocs_pcrf_spending_limit_lifecycle() {
    let mut ocs = OcsSyEngine::new();
    let mut pcrf = PcrfSyClient::new();

    let imsi = "imsi-460019998887776";
    let sess_id = "sy-pcrf-ue-session-42";

    // 1. OCS holds current balances/counters for the subscriber
    ocs.set_counter_status(imsi, "tier1-data", "BELOW_THRESHOLD");
    ocs.set_counter_status(imsi, "tier2-video", "NORMAL");

    // 2. PCRF subscribes to spending limit reports via SLR
    let slr = pcrf.create_initial_slr(sess_id, imsi, &["tier1-data", "tier2-video"]);
    let sla = ocs.handle_slr(&slr);
    assert_eq!(sla.result_code, DIAMETER_SUCCESS);
    assert_eq!(sla.reports.len(), 2);

    // PCRF processes SLA and populates local counter cache
    pcrf.process_sla(&sla);
    assert_eq!(
        pcrf.get_counter_status(sess_id, "tier1-data"),
        Some("BELOW_THRESHOLD")
    );
    assert_eq!(
        pcrf.get_counter_status(sess_id, "tier2-video"),
        Some("NORMAL")
    );

    // 3. Subscriber crosses threshold in OCS -> OCS proactively generates SNR
    let snr_list = ocs.update_counter_and_notify(imsi, "tier1-data", "EXCEEDED_QUOTA");
    assert_eq!(snr_list.len(), 1);
    assert_eq!(snr_list[0].session_id, sess_id);
    assert_eq!(snr_list[0].reports[0].counter_id, "tier1-data");
    assert_eq!(snr_list[0].reports[0].current_status, "EXCEEDED_QUOTA");

    // 4. PCRF handles SNR, updates its internal cache, and produces SNA
    let sna = pcrf.process_snr(&snr_list[0]);
    assert_eq!(sna.session_id, sess_id);
    assert_eq!(sna.result_code, DIAMETER_SUCCESS);
    assert_eq!(
        pcrf.get_counter_status(sess_id, "tier1-data"),
        Some("EXCEEDED_QUOTA")
    );

    // 5. Session termination via StopRequest
    let stop_slr = SpendingLimitRequest::new(sess_id, SlRequestType::StopRequest, imsi);
    let stop_sla = ocs.handle_slr(&stop_slr);
    assert_eq!(stop_sla.result_code, DIAMETER_SUCCESS);
    assert!(!ocs.active_sessions.contains_key(sess_id));
}

#[test]
fn test_diameter_sy_intermediate_request_counter_modification() {
    let mut ocs = OcsSyEngine::new();
    let mut pcrf = PcrfSyClient::new();

    let imsi = "imsi-460011122334455";
    let sess_id = "sy-sess-mod-99";

    ocs.set_counter_status(imsi, "initial-tier", "ACTIVE");
    ocs.set_counter_status(imsi, "addon-boost", "AVAILABLE");

    // 1. Initial SLR subscribes only to initial-tier
    let slr_init = pcrf.create_initial_slr(sess_id, imsi, &["initial-tier"]);
    let sla_init = ocs.handle_slr(&slr_init);
    pcrf.process_sla(&sla_init);
    assert_eq!(
        pcrf.get_counter_status(sess_id, "initial-tier"),
        Some("ACTIVE")
    );
    assert_eq!(pcrf.get_counter_status(sess_id, "addon-boost"), None);

    // 2. Intermediate SLR dynamically subscribes to addon-boost as well
    let slr_inter = pcrf.create_intermediate_slr(sess_id, imsi, &["initial-tier", "addon-boost"]);
    let sla_inter = ocs.handle_slr(&slr_inter);
    assert_eq!(sla_inter.reports.len(), 2);
    pcrf.process_sla(&sla_inter);
    assert_eq!(
        pcrf.get_counter_status(sess_id, "addon-boost"),
        Some("AVAILABLE")
    );

    // 3. Unsubscribe from initial-tier
    assert!(ocs.unsubscribe_counter(sess_id, "initial-tier"));
    // OCS status update for initial-tier will no longer notify this session
    let empty_notifications = ocs.update_counter_and_notify(imsi, "initial-tier", "EXPIRED");
    assert!(empty_notifications.is_empty());

    // But addon-boost is still subscribed
    let boost_notifications = ocs.update_counter_and_notify(imsi, "addon-boost", "EXHAUSTED");
    assert_eq!(boost_notifications.len(), 1);

    // 4. Terminate sessions on both sides
    assert!(pcrf.terminate_session(sess_id));
    assert!(ocs.terminate_session(sess_id));
    assert_eq!(pcrf.active_session_count(), 0);
    assert_eq!(ocs.active_session_count(), 0);
}
