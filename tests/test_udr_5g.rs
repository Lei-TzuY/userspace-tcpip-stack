//! Integration tests for 3GPP TS 29.504 / TS 29.505 5G Unified Data Repository (UDR) Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::Snssai;
use toy_tcpip::udr_5g::*;

// ---------------------------------------------------------------------------
// 1. Subscription Auth & Access/Mobility Data CRUD
// ---------------------------------------------------------------------------

#[test]
fn test_udr_subscription_auth_and_am_crud() {
    let mut udr = UdrEngine::new("udr-core-001");
    let supi = "imsi-208950000000001";

    let auth = AuthenticationData {
        supi: supi.to_string(),
        auth_method: AuthMethod::FiveGAka,
        k: [
            0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38,
            0xa6, 0xbc,
        ],
        opc: [
            0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c,
            0xb3, 0x18,
        ],
        sqn: 0x000000000021,
    };
    udr.set_auth_data(auth.clone(), 1700000000);

    let retrieved_auth = udr.get_auth_data(supi).expect("Auth data not found");
    assert_eq!(retrieved_auth, &auth);

    let embb = Snssai { sst: 1, sd: None };
    let am = AccessAndMobilityData {
        supi: supi.to_string(),
        subscribed_snssais: vec![embb.clone()],
        ue_ambr_dl_kbps: 1_000_000,
        ue_ambr_ul_kbps: 500_000,
    };
    udr.set_am_data(am.clone(), 1700000000);

    let retrieved_am = udr.get_am_data(supi).expect("AM data not found");
    assert_eq!(retrieved_am, &am);
}

// ---------------------------------------------------------------------------
// 2. Session Management & Policy Data Management
// ---------------------------------------------------------------------------

#[test]
fn test_udr_session_management_and_policy_data() {
    let mut udr = UdrEngine::new("udr-core-002");
    let supi = "imsi-208950000000002";
    let embb = Snssai { sst: 1, sd: None };

    // Set SM Data
    let sm = SessionManagementData {
        supi: supi.to_string(),
        dnn: "internet".to_string(),
        s_nssai: embb.clone(),
        default_5qi: 9,
        session_ambr_dl_kbps: 200_000,
        session_ambr_ul_kbps: 100_000,
        arp_priority_level: 8,
    };
    udr.set_sm_data(sm.clone(), 1700000000);

    let retrieved_sm = udr
        .get_sm_data(supi, "internet", &embb)
        .expect("SM data not found");
    assert_eq!(retrieved_sm, &sm);

    // Set PCF Policy Data
    let policy = SmPolicyData {
        supi: supi.to_string(),
        dnn: "internet".to_string(),
        s_nssai: embb.clone(),
        authorized_pcc_rules: vec!["pcc-rule-default-01".to_string()],
        max_bandwidth_dl_kbps: Some(200_000),
        max_bandwidth_ul_kbps: Some(100_000),
    };
    udr.set_policy_data(policy.clone(), 1700000000);

    let retrieved_policy = udr
        .get_policy_data(supi, "internet", &embb)
        .expect("Policy data not found");
    assert_eq!(retrieved_policy, &policy);
}

// ---------------------------------------------------------------------------
// 3. Exposure Data (Traffic Influence & Edge Breakout)
// ---------------------------------------------------------------------------

#[test]
fn test_udr_exposure_traffic_influence() {
    let mut udr = UdrEngine::new("udr-core-003");
    let urllc = Snssai {
        sst: 2,
        sd: Some([1, 2, 3]),
    };
    let edge_ip = Ipv4Address::new(192, 168, 100, 1);

    let inf = TrafficInfluenceData {
        af_trans_id: "af-trans-gaming-001".to_string(),
        dnn: "edge-gaming".to_string(),
        s_nssai: urllc.clone(),
        target_dnai: "DNAI-Edge-Tokyo".to_string(),
        edge_breakout_ip: edge_ip,
    };
    udr.set_exposure_data(inf.clone(), 1700000000);

    assert_eq!(udr.get_exposure_data("af-trans-gaming-001"), Some(&inf));

    let matched = udr.find_traffic_influence("edge-gaming", &urllc);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].target_dnai, "DNAI-Edge-Tokyo");
    assert_eq!(matched[0].edge_breakout_ip, edge_ip);
}

// ---------------------------------------------------------------------------
// 4. Application Data PFD & Layer-7 DPI Domain Matching
// ---------------------------------------------------------------------------

#[test]
fn test_udr_pfd_layer7_domain_matching() {
    let mut udr = UdrEngine::new("udr-core-004");

    let pfd_video = PacketFlowDescription {
        app_id: "video-streaming".to_string(),
        flow_descriptions: vec!["ip:any:tcp:443".to_string()],
        domain_names: vec!["*.youtube.com".to_string(), "*.googlevideo.com".to_string()],
    };
    let pfd_game = PacketFlowDescription {
        app_id: "cloud-gaming".to_string(),
        flow_descriptions: vec!["ip:any:udp:27015".to_string()],
        domain_names: vec![
            "*.geforcenow.com".to_string(),
            "cloudgame.carrier.net".to_string(),
        ],
    };

    udr.set_pfd(pfd_video, 1700000000);
    udr.set_pfd(pfd_game, 1700000000);

    // DPI domain matches
    assert_eq!(
        udr.match_app_by_domain("m.youtube.com").as_deref(),
        Some("video-streaming")
    );
    assert_eq!(
        udr.match_app_by_domain("rr1---sn-4g5edn7s.googlevideo.com")
            .as_deref(),
        Some("video-streaming")
    );
    assert_eq!(
        udr.match_app_by_domain("play.geforcenow.com").as_deref(),
        Some("cloud-gaming")
    );
    assert_eq!(
        udr.match_app_by_domain("cloudgame.carrier.net").as_deref(),
        Some("cloud-gaming")
    );
    assert_eq!(udr.match_app_by_domain("unknown-site.org"), None);
}

// ---------------------------------------------------------------------------
// 5. Data Change Subscriptions & Event Notifications
// ---------------------------------------------------------------------------

#[test]
fn test_udr_data_change_subscription_and_notification() {
    let mut udr = UdrEngine::new("udr-core-005");
    let supi = "imsi-208950000000005";
    let embb = Snssai { sst: 1, sd: None };

    // UDM subscribes to SM data changes for this subscriber
    udr.subscribe(UdrDataChangeSubscription {
        subscription_id: "sub-udm-sm-change-01".to_string(),
        supi: Some(supi.to_string()),
        data_type: UdrDataType::SubscriptionSm,
        callback_uri: "https://udm.5gc.local/v1/notifications".to_string(),
    });

    // Initial SM data update -> Dispatches notification
    let sm = SessionManagementData {
        supi: supi.to_string(),
        dnn: "internet".to_string(),
        s_nssai: embb.clone(),
        default_5qi: 9,
        session_ambr_dl_kbps: 100_000,
        session_ambr_ul_kbps: 50_000,
        arp_priority_level: 8,
    };
    udr.set_sm_data(sm, 1700000000);

    assert_eq!(udr.notification_history.len(), 1);
    let notif = &udr.notification_history[0];
    assert_eq!(notif.subscription_id, "sub-udm-sm-change-01");
    assert_eq!(notif.data_type, UdrDataType::SubscriptionSm);
    assert_eq!(notif.supi.as_deref(), Some(supi));
}
