//! Integration tests for 3GPP TS 29.512 / TS 29.514 5G Policy Control Function (PCF) Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::Snssai;
use toy_tcpip::pcf_5g::*;

// ---------------------------------------------------------------------------
// 1. Npcf_SMPolicyControl_Create Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_create_sm_policy_happy_path() {
    let mut pcf = PcfEngine::new("pcf-core-001");
    let ue_ip = Ipv4Address::new(10, 45, 0, 2);

    let req = CreateSmPolicyRequest {
        supi: "imsi-208950000000001".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        ue_ipv4: ue_ip,
    };

    let resp = pcf
        .handle_create_sm_policy(&req)
        .expect("Failed to create SM Policy");

    assert!(!resp.policy_ref.is_empty());
    assert_eq!(resp.session_ambr_dl_kbps, 200_000);
    assert_eq!(resp.session_ambr_ul_kbps, 100_000);
    assert_eq!(resp.initial_pcc_rules.len(), 1);

    let default_rule = &resp.initial_pcc_rules[0];
    assert_eq!(default_rule.five_qi, 9);
    assert_eq!(default_rule.qfi, 9);
    assert_eq!(default_rule.precedence, 1000);
    assert!(default_rule.gate_status_open);
}

// ---------------------------------------------------------------------------
// 2. Multi-flow Packet Classification to Default Best-Effort Rule
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_packet_classification_default_rule() {
    let mut pcf = PcfEngine::new("pcf-core-002");
    let ue_ip = Ipv4Address::new(10, 45, 0, 3);
    let server_ip = Ipv4Address::new(93, 184, 216, 34);

    let req = CreateSmPolicyRequest {
        supi: "imsi-208950000000002".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        ue_ipv4: ue_ip,
    };
    let resp = pcf.handle_create_sm_policy(&req).unwrap();

    // DL packet: server -> UE
    let matched = pcf
        .classify_packet(
            &resp.policy_ref,
            true,
            &server_ip,
            &ue_ip,
            6, // TCP
            443,
            50000,
        )
        .expect("Should match default PCC rule");

    assert_eq!(matched.five_qi, 9);
    assert_eq!(matched.qfi, 9);
    assert_eq!(matched.precedence, 1000);
}

// ---------------------------------------------------------------------------
// 3. AF Dynamic QoS Reservation (Npcf_PolicyAuthorization)
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_af_dynamic_qos_reservation() {
    let mut pcf = PcfEngine::new("pcf-core-003");
    let ue_ip = Ipv4Address::new(10, 45, 0, 4);
    let edge_game_server = Ipv4Address::new(198, 51, 100, 10);

    // 1. Initial PDU Session policy establishment
    let create_req = CreateSmPolicyRequest {
        supi: "imsi-208950000000003".to_string(),
        pdu_session_id: 1,
        dnn: "gaming".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        ue_ipv4: ue_ip,
    };
    let policy_resp = pcf.handle_create_sm_policy(&create_req).unwrap();

    // 2. Edge Gaming Application Function requests dedicated GBR bearer for UDP port 27015
    let game_filter = PacketFilter {
        filter_id: "game-flow-01".to_string(),
        direction: FlowDirection::Bidirectional,
        protocol: Some(17), // UDP
        source_ip: Some(edge_game_server),
        source_port: Some(27015),
        dest_ip: Some(ue_ip),
        dest_port: None,
    };

    let af_req = AppSessionContextRequest {
        app_session_id: "af-session-99".to_string(),
        supi: "imsi-208950000000003".to_string(),
        af_id: "edge-cloud-gaming-af".to_string(),
        media_type: AfMediaType::Gaming,
        requested_bandwidth_kbps: 50_000, // 50 Mbps
        flow_descriptions: vec![game_filter],
    };

    let af_resp = pcf
        .handle_af_session_authorization(&af_req)
        .expect("AF session authorization failed");

    assert!(af_resp.authorized);
    assert_eq!(af_resp.assigned_5qi, 3); // 5QI=3 (Real Time Gaming)
    let dyn_rule = af_resp.generated_pcc_rule.unwrap();
    assert_eq!(dyn_rule.five_qi, 3);
    assert_eq!(dyn_rule.qfi, 3);
    assert_eq!(dyn_rule.precedence, 30); // Higher priority than default 1000
    assert_eq!(dyn_rule.gbr_dl_kbps, Some(50_000));

    // 3. Test packet classification: Gaming packet MUST hit dedicated 5QI=3 rule!
    let game_hit = pcf
        .classify_packet(
            &policy_resp.policy_ref,
            true,
            &edge_game_server,
            &ue_ip,
            17, // UDP
            27015,
            49152,
        )
        .expect("Gaming packet should match");
    assert_eq!(game_hit.five_qi, 3);
    assert_eq!(game_hit.qfi, 3);

    // 4. Other traffic on same session hits default 5QI=9 rule
    let web_hit = pcf
        .classify_packet(
            &policy_resp.policy_ref,
            true,
            &Ipv4Address::new(1, 1, 1, 1),
            &ue_ip,
            6, // TCP
            80,
            49153,
        )
        .expect("Web packet should match default");
    assert_eq!(web_hit.five_qi, 9);
}

// ---------------------------------------------------------------------------
// 4. Policy Update & Usage-Based Throttling
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_update_sm_policy_usage_threshold_throttling() {
    let mut pcf = PcfEngine::new("pcf-core-004");
    let ue_ip = Ipv4Address::new(10, 45, 0, 5);

    let create_req = CreateSmPolicyRequest {
        supi: "imsi-208950000000004".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        ue_ipv4: ue_ip,
    };
    let create_resp = pcf.handle_create_sm_policy(&create_req).unwrap();

    // Trigger: Quota exceeded
    let update_req = UpdateSmPolicyRequest {
        policy_ref: create_resp.policy_ref.clone(),
        triggers: vec![PolicyEventTrigger::UsageReportThresholdReached],
        consumed_dl_bytes: Some(100_000_000),
    };

    let update_resp = pcf
        .handle_update_sm_policy(&update_req)
        .expect("Policy update failed");

    assert_eq!(update_resp.modified_pcc_rules.len(), 1);
    let throttled = &update_resp.modified_pcc_rules[0];
    assert_eq!(throttled.five_qi, 9);
    assert_eq!(throttled.mbr_dl_kbps, Some(1_000)); // Throttled to 1 Mbps
    assert_eq!(throttled.mbr_ul_kbps, Some(500));
}

// ---------------------------------------------------------------------------
// 5. Policy Association Deletion Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_delete_sm_policy_lifecycle() {
    let mut pcf = PcfEngine::new("pcf-core-005");
    let create_req = CreateSmPolicyRequest {
        supi: "imsi-208950000000005".to_string(),
        pdu_session_id: 1,
        dnn: "internet".to_string(),
        s_nssai: Snssai { sst: 1, sd: None },
        ue_ipv4: Ipv4Address::new(10, 45, 0, 6),
    };
    let create_resp = pcf.handle_create_sm_policy(&create_req).unwrap();
    assert_eq!(pcf.policy_associations.len(), 1);

    // Delete policy association
    assert!(pcf.handle_delete_sm_policy(&create_resp.policy_ref));
    assert!(pcf.policy_associations.is_empty());
    assert!(!pcf.handle_delete_sm_policy(&create_resp.policy_ref));
}

// ---------------------------------------------------------------------------
// 6. Detailed Packet Filter Direction & Protocol Matching
// ---------------------------------------------------------------------------

#[test]
fn test_pcf_multi_flow_filter_matching() {
    let filter = PacketFilter {
        filter_id: "pf-test-01".to_string(),
        direction: FlowDirection::Uplink,
        protocol: Some(6), // TCP only
        source_ip: Some(Ipv4Address::new(10, 45, 0, 10)),
        source_port: None,
        dest_ip: Some(Ipv4Address::new(8, 8, 8, 8)),
        dest_port: Some(53),
    };

    let ue_ip = Ipv4Address::new(10, 45, 0, 10);
    let dns_ip = Ipv4Address::new(8, 8, 8, 8);

    // 1. Correct Uplink TCP packet -> Match!
    assert!(filter.matches(false, &ue_ip, &dns_ip, 6, 12345, 53));

    // 2. Downlink packet (is_downlink = true) -> Reject (Uplink only)
    assert!(!filter.matches(true, &dns_ip, &ue_ip, 6, 53, 12345));

    // 3. UDP packet (proto = 17) -> Reject (TCP only)
    assert!(!filter.matches(false, &ue_ip, &dns_ip, 17, 12345, 53));

    // 4. Wrong destination IP -> Reject
    assert!(!filter.matches(false, &ue_ip, &Ipv4Address::new(1, 1, 1, 1), 6, 12345, 53));
}
