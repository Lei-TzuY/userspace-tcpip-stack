//! Integration tests for 3GPP TS 29.510 5G Network Repository Function (NRF) Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::{PlmnId, Snssai};
use toy_tcpip::nrf_5g::*;
use toy_tcpip::sba_5g::NfType;

// Helper to create a basic profile
fn make_profile(
    id: &str,
    nf_type: NfType,
    snssais: Vec<Snssai>,
    dnns: Vec<&str>,
    priority: u16,
    load: u8,
    locality: Option<&str>,
) -> NfProfileRecord {
    NfProfileRecord {
        nf_instance_id: id.to_string(),
        nf_type,
        nf_status: NfStatus::Registered,
        heartbeat_timer_s: 30,
        fqdn: format!("{}.5gc.mnc095.mcc208.3gppnetwork.org", id),
        ipv4_addresses: vec![Ipv4Address::new(10, 45, 0, 10)],
        plmn_list: vec![PlmnId {
            mcc: [2, 0, 8],
            mnc: [9, 5, 0],
        }],
        s_nssais: snssais,
        dnns: dnns.into_iter().map(|s| s.to_string()).collect(),
        tai_list: vec![100],
        priority,
        capacity: 100,
        load: Some(load),
        locality: locality.map(|s| s.to_string()),
        services: vec![NfServiceRecord {
            service_instance_id: format!("{}-svc-01", id),
            service_name: format!("n{}-test", nf_type.as_str().to_lowercase()),
            version: "v1".to_string(),
            endpoint_uri: format!("http://{}.local/v1", id),
        }],
        lease_expires_at_s: 0,
    }
}

// ---------------------------------------------------------------------------
// 1. Basic Registration & Discovery by NF Type
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_register_and_discover_by_nf_type() {
    let mut nrf = NrfEngine::new("nrf-core-001");
    let smf = make_profile(
        "smf-01",
        NfType::Smf,
        vec![],
        vec!["internet"],
        10,
        20,
        None,
    );
    let amf = make_profile("amf-01", NfType::Amf, vec![], vec![], 10, 30, None);

    nrf.register_nf(smf, 1700000000)
        .expect("SMF register failed");
    nrf.register_nf(amf, 1700000000)
        .expect("AMF register failed");

    let query = DiscoveryQuery {
        target_nf_type: NfType::Smf,
        requester_nf_type: NfType::Amf,
        target_snssai: None,
        target_dnn: None,
        target_tai: None,
        preferred_locality: None,
    };

    let res = nrf.discover_nf(&query);
    assert_eq!(res.candidate_profiles.len(), 1);
    assert_eq!(res.candidate_profiles[0].nf_instance_id, "smf-01");
}

// ---------------------------------------------------------------------------
// 2. Discovery by S-NSSAI and DNN
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_discover_by_snssai_and_dnn() {
    let mut nrf = NrfEngine::new("nrf-core-002");
    let embb = Snssai { sst: 1, sd: None };
    let urllc = Snssai {
        sst: 2,
        sd: Some([1, 2, 3]),
    };

    let smf_embb = make_profile(
        "smf-embb",
        NfType::Smf,
        vec![embb.clone()],
        vec!["internet"],
        10,
        20,
        None,
    );
    let smf_urllc = make_profile(
        "smf-urllc",
        NfType::Smf,
        vec![urllc.clone()],
        vec!["factory-iot"],
        10,
        20,
        None,
    );

    nrf.register_nf(smf_embb, 1700000000).unwrap();
    nrf.register_nf(smf_urllc, 1700000000).unwrap();

    // Query for URLLC slice & factory-iot DNN
    let query = DiscoveryQuery {
        target_nf_type: NfType::Smf,
        requester_nf_type: NfType::Amf,
        target_snssai: Some(urllc.clone()),
        target_dnn: Some("factory-iot".to_string()),
        target_tai: None,
        preferred_locality: None,
    };

    let res = nrf.discover_nf(&query);
    assert_eq!(res.candidate_profiles.len(), 1);
    assert_eq!(res.candidate_profiles[0].nf_instance_id, "smf-urllc");
}

// ---------------------------------------------------------------------------
// 3. Candidate Ranking: Priority & Dynamic Load
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_load_balancing_and_priority_ranking() {
    let mut nrf = NrfEngine::new("nrf-core-003");

    // PCF-1: Priority 20 (worse), Load 80%
    let pcf1 = make_profile("pcf-backup", NfType::Pcf, vec![], vec![], 20, 80, None);
    // PCF-2: Priority 10 (better), Load 15%
    let pcf2 = make_profile("pcf-primary", NfType::Pcf, vec![], vec![], 10, 15, None);

    nrf.register_nf(pcf1, 1700000000).unwrap();
    nrf.register_nf(pcf2, 1700000000).unwrap();

    let query = DiscoveryQuery {
        target_nf_type: NfType::Pcf,
        requester_nf_type: NfType::Smf,
        target_snssai: None,
        target_dnn: None,
        target_tai: None,
        preferred_locality: None,
    };

    let res = nrf.discover_nf(&query);
    assert_eq!(res.candidate_profiles.len(), 2);
    // PCF-2 must be ranked first due to lower priority number
    assert_eq!(res.candidate_profiles[0].nf_instance_id, "pcf-primary");
    assert_eq!(res.candidate_profiles[1].nf_instance_id, "pcf-backup");
}

// ---------------------------------------------------------------------------
// 4. Locality Proximity Preference
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_locality_proximity_preference() {
    let mut nrf = NrfEngine::new("nrf-core-004");

    let smf_central = make_profile(
        "smf-central",
        NfType::Smf,
        vec![],
        vec![],
        10,
        10,
        Some("central-dc"),
    );
    let smf_edge = make_profile(
        "smf-edge",
        NfType::Smf,
        vec![],
        vec![],
        10,
        10,
        Some("edge-zone-east"),
    );

    nrf.register_nf(smf_central, 1700000000).unwrap();
    nrf.register_nf(smf_edge, 1700000000).unwrap();

    // Query preferring edge-zone-east
    let query = DiscoveryQuery {
        target_nf_type: NfType::Smf,
        requester_nf_type: NfType::Amf,
        target_snssai: None,
        target_dnn: None,
        target_tai: None,
        preferred_locality: Some("edge-zone-east".to_string()),
    };

    let res = nrf.discover_nf(&query);
    assert_eq!(res.candidate_profiles.len(), 2);
    assert_eq!(res.candidate_profiles[0].nf_instance_id, "smf-edge");
}

// ---------------------------------------------------------------------------
// 5. Heartbeat Expiration, Suspension & Recovery
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_heartbeat_lease_expiration_and_recovery() {
    let mut nrf = NrfEngine::new("nrf-core-005");
    let upf = make_profile("upf-01", NfType::Upf, vec![], vec![], 10, 20, None);

    // Registered at t = 1000s, heartbeat_timer = 30s -> lease expires at t = 1060s
    nrf.register_nf(upf, 1000).unwrap();

    // 1. Check discovery at t = 1010s -> UPF is discoverable
    let query = DiscoveryQuery {
        target_nf_type: NfType::Upf,
        requester_nf_type: NfType::Smf,
        target_snssai: None,
        target_dnn: None,
        target_tai: None,
        preferred_locality: None,
    };
    assert_eq!(nrf.discover_nf(&query).candidate_profiles.len(), 1);

    // 2. Advance time to t = 1070s without heartbeat -> Expire!
    let expired = nrf.check_and_expire_heartbeats(1070);
    assert_eq!(expired, vec!["upf-01"]);

    // UPF status transitioned to Suspended -> Not discoverable!
    assert_eq!(nrf.discover_nf(&query).candidate_profiles.len(), 0);

    // 3. UPF sends heartbeat keepalive at t = 1075s -> Recovers to Registered!
    nrf.update_heartbeat("upf-01", Some(25), 1075)
        .expect("Heartbeat update failed");
    assert_eq!(nrf.discover_nf(&query).candidate_profiles.len(), 1);
}

// ---------------------------------------------------------------------------
// 6. Graceful Deregistration
// ---------------------------------------------------------------------------

#[test]
fn test_nrf_deregister_graceful() {
    let mut nrf = NrfEngine::new("nrf-core-006");
    let ausf = make_profile("ausf-01", NfType::Ausf, vec![], vec![], 10, 10, None);

    nrf.register_nf(ausf, 1000).unwrap();
    assert_eq!(nrf.profiles.len(), 1);

    // Graceful deregister
    assert!(nrf.deregister_nf("ausf-01").is_ok());
    assert_eq!(nrf.profiles.len(), 0);

    let query = DiscoveryQuery {
        target_nf_type: NfType::Ausf,
        requester_nf_type: NfType::Amf,
        target_snssai: None,
        target_dnn: None,
        target_tai: None,
        preferred_locality: None,
    };
    assert_eq!(nrf.discover_nf(&query).candidate_profiles.len(), 0);
}
