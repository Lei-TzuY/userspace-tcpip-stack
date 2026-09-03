//! Integration tests for 3GPP TS 29.521 5G Binding Support Function (BSF) Engine.

use toy_tcpip::bsf_5g::*;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// 1. Register & Discover by UE IPv4 Address Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_bsf_register_and_discover_by_ue_ipv4() {
    let mut bsf = BsfEngine::new("bsf-core-001");
    let ue_ip = Ipv4Address::new(10, 45, 0, 100);
    let embb = Snssai { sst: 1, sd: None };

    let req = CreateBindingRequest {
        supi: "imsi-208950000000001".to_string(),
        gpsi: Some("msisdn-33600000001".to_string()),
        ue_ipv4_address: Some(ue_ip),
        dnn: "internet".to_string(),
        snssai: embb.clone(),
        pdu_session_id: Some(1),
        pcf_instance_id: "pcf-cluster-east-01".to_string(),
        pcf_fqdn: "pcf01.east.5gc.carrier.com".to_string(),
        pcf_ip_endpoints: vec![Ipv4Address::new(10, 100, 0, 5)],
        pcf_diameter_host: None,
        pcf_diameter_realm: None,
    };

    let created = bsf
        .register_binding(&req)
        .expect("Failed to register binding");
    assert!(!created.binding_id.is_empty());

    // AF discovers serving PCF by UE IP
    let query = DiscoverBindingQuery {
        ue_ipv4_address: Some(ue_ip),
        supi: None,
        dnn: Some("internet".to_string()),
        snssai: Some(embb),
    };

    let discovered = bsf.discover_bindings(&query);
    assert_eq!(discovered.len(), 1);
    let hit = &discovered[0];
    assert_eq!(hit.pcf_instance_id, "pcf-cluster-east-01");
    assert_eq!(hit.pcf_fqdn, "pcf01.east.5gc.carrier.com");
    assert_eq!(hit.pcf_ip_endpoints, vec![Ipv4Address::new(10, 100, 0, 5)]);
}

// ---------------------------------------------------------------------------
// 2. Discover by SUPI Across Multiple Concurrent PDU Sessions
// ---------------------------------------------------------------------------

#[test]
fn test_bsf_discover_by_supi_multiple_sessions() {
    let mut bsf = BsfEngine::new("bsf-core-002");
    let supi = "imsi-208950000000002";
    let embb = Snssai { sst: 1, sd: None };
    let ims_slice = Snssai {
        sst: 1,
        sd: Some([0, 0, 1]),
    };

    // Session 1: Internet on PCF-1
    let req1 = CreateBindingRequest {
        supi: supi.to_string(),
        gpsi: None,
        ue_ipv4_address: Some(Ipv4Address::new(10, 45, 0, 201)),
        dnn: "internet".to_string(),
        snssai: embb.clone(),
        pdu_session_id: Some(1),
        pcf_instance_id: "pcf-internet-01".to_string(),
        pcf_fqdn: "pcf-internet.5gc.local".to_string(),
        pcf_ip_endpoints: vec![Ipv4Address::new(10, 10, 0, 1)],
        pcf_diameter_host: None,
        pcf_diameter_realm: None,
    };
    bsf.register_binding(&req1).unwrap();

    // Session 2: IMS Voice on dedicated PCF-IMS
    let req2 = CreateBindingRequest {
        supi: supi.to_string(),
        gpsi: None,
        ue_ipv4_address: Some(Ipv4Address::new(10, 45, 0, 202)),
        dnn: "ims".to_string(),
        snssai: ims_slice.clone(),
        pdu_session_id: Some(2),
        pcf_instance_id: "pcf-ims-voice".to_string(),
        pcf_fqdn: "pcf-ims.5gc.local".to_string(),
        pcf_ip_endpoints: vec![Ipv4Address::new(10, 20, 0, 1)],
        pcf_diameter_host: None,
        pcf_diameter_realm: None,
    };
    bsf.register_binding(&req2).unwrap();

    // Query all sessions for this SUPI
    let all_query = DiscoverBindingQuery {
        ue_ipv4_address: None,
        supi: Some(supi.to_string()),
        dnn: None,
        snssai: None,
    };
    assert_eq!(bsf.discover_bindings(&all_query).len(), 2);

    // Query specifically for IMS session
    let ims_query = DiscoverBindingQuery {
        ue_ipv4_address: None,
        supi: Some(supi.to_string()),
        dnn: Some("ims".to_string()),
        snssai: Some(ims_slice),
    };
    let ims_hits = bsf.discover_bindings(&ims_query);
    assert_eq!(ims_hits.len(), 1);
    assert_eq!(ims_hits[0].pcf_instance_id, "pcf-ims-voice");
}

// ---------------------------------------------------------------------------
// 3. Update Binding IP Address
// ---------------------------------------------------------------------------

#[test]
fn test_bsf_update_binding_ue_ip() {
    let mut bsf = BsfEngine::new("bsf-core-003");
    let old_ip = Ipv4Address::new(10, 45, 0, 50);
    let new_ip = Ipv4Address::new(10, 45, 0, 51);

    let req = CreateBindingRequest {
        supi: "imsi-208950000000003".to_string(),
        gpsi: None,
        ue_ipv4_address: Some(old_ip),
        dnn: "internet".to_string(),
        snssai: Snssai { sst: 1, sd: None },
        pdu_session_id: Some(1),
        pcf_instance_id: "pcf-01".to_string(),
        pcf_fqdn: "pcf01.5gc.local".to_string(),
        pcf_ip_endpoints: vec![],
        pcf_diameter_host: None,
        pcf_diameter_realm: None,
    };
    let binding = bsf.register_binding(&req).unwrap();

    // Update IP to new_ip
    let update_req = UpdateBindingRequest {
        binding_id: binding.binding_id.clone(),
        new_ipv4_address: Some(new_ip),
        new_pcf_ip_endpoints: None,
    };
    assert!(bsf.update_binding(&update_req).is_ok());

    // Old IP lookup fails
    let old_query = DiscoverBindingQuery {
        ue_ipv4_address: Some(old_ip),
        supi: None,
        dnn: None,
        snssai: None,
    };
    assert_eq!(bsf.discover_bindings(&old_query).len(), 0);

    // New IP lookup succeeds
    let new_query = DiscoverBindingQuery {
        ue_ipv4_address: Some(new_ip),
        supi: None,
        dnn: None,
        snssai: None,
    };
    let hits = bsf.discover_bindings(&new_query);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].binding_id, binding.binding_id);
}

// ---------------------------------------------------------------------------
// 4. Deregister Binding Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_bsf_deregister_binding_lifecycle() {
    let mut bsf = BsfEngine::new("bsf-core-004");
    let ue_ip = Ipv4Address::new(10, 45, 0, 77);

    let req = CreateBindingRequest {
        supi: "imsi-208950000000004".to_string(),
        gpsi: None,
        ue_ipv4_address: Some(ue_ip),
        dnn: "internet".to_string(),
        snssai: Snssai { sst: 1, sd: None },
        pdu_session_id: Some(1),
        pcf_instance_id: "pcf-01".to_string(),
        pcf_fqdn: "pcf01.5gc.local".to_string(),
        pcf_ip_endpoints: vec![],
        pcf_diameter_host: None,
        pcf_diameter_realm: None,
    };
    let binding = bsf.register_binding(&req).unwrap();
    assert_eq!(bsf.bindings_by_id.len(), 1);

    // Deregister
    assert!(bsf.deregister_binding(&binding.binding_id));
    assert_eq!(bsf.bindings_by_id.len(), 0);
    assert_eq!(bsf.ip_index.len(), 0);

    let query = DiscoverBindingQuery {
        ue_ipv4_address: Some(ue_ip),
        supi: None,
        dnn: None,
        snssai: None,
    };
    assert_eq!(bsf.discover_bindings(&query).len(), 0);
}

// ---------------------------------------------------------------------------
// 5. Diameter Rx PCRF Interworking Fields
// ---------------------------------------------------------------------------

#[test]
fn test_bsf_diameter_rx_pcrf_interworking() {
    let mut bsf = BsfEngine::new("bsf-core-005");
    let ue_ip = Ipv4Address::new(10, 45, 0, 88);

    let req = CreateBindingRequest {
        supi: "imsi-208950000000005".to_string(),
        gpsi: None,
        ue_ipv4_address: Some(ue_ip),
        dnn: "ims".to_string(),
        snssai: Snssai { sst: 1, sd: None },
        pdu_session_id: Some(1),
        pcf_instance_id: "pcf-pcrf-converged-01".to_string(),
        pcf_fqdn: "pcf01.carrier.net".to_string(),
        pcf_ip_endpoints: vec![Ipv4Address::new(192, 168, 1, 10)],
        pcf_diameter_host: Some("pcrf01.ims.carrier.net".to_string()),
        pcf_diameter_realm: Some("ims.carrier.net".to_string()),
    };

    bsf.register_binding(&req).unwrap();

    let query = DiscoverBindingQuery {
        ue_ipv4_address: Some(ue_ip),
        supi: None,
        dnn: None,
        snssai: None,
    };

    let hits = bsf.discover_bindings(&query);
    assert_eq!(hits.len(), 1);
    assert_eq!(
        hits[0].pcf_diameter_host.as_deref(),
        Some("pcrf01.ims.carrier.net")
    );
    assert_eq!(
        hits[0].pcf_diameter_realm.as_deref(),
        Some("ims.carrier.net")
    );
}
