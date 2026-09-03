//! Integration tests for 3GPP TS 29.558 / TS 23.558 5G Edge Enabler Server (EES) & Edge Configuration Server (ECS).

use toy_tcpip::ees_5g::*;

// ---------------------------------------------------------------------------
// 1. ECS Service Provisioning Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_ecs_service_provisioning_happy_path() {
    let mut ecs = EcsEngine::new("ecs-global-01");

    let ees_tokyo = EesProfile {
        ees_id: "ees-tokyo-01".to_string(),
        ees_endpoint_uri: "https://ees.tokyo.5gedge.net".to_string(),
        service_area: vec![
            "tai-tokyo-chiyoda".to_string(),
            "tai-tokyo-shinjuku".to_string(),
        ],
        supported_dnais: vec!["dnai-tokyo-01".to_string()],
    };

    let ees_osaka = EesProfile {
        ees_id: "ees-osaka-01".to_string(),
        ees_endpoint_uri: "https://ees.osaka.5gedge.net".to_string(),
        service_area: vec!["tai-osaka-umeda".to_string()],
        supported_dnais: vec!["dnai-osaka-01".to_string()],
    };

    ecs.register_ees(ees_tokyo);
    ecs.register_ees(ees_osaka);

    let req = EcsProvisioningRequest {
        eec_id: "eec-device-001".to_string(),
        ue_location_tai: "tai-tokyo-shinjuku".to_string(),
        app_client_id: "com.cloudgaming.client".to_string(),
    };

    let resp = ecs.provision_service(&req).expect("Provisioning failed");
    assert_eq!(
        resp.matched_ees_list,
        vec!["https://ees.tokyo.5gedge.net".to_string()]
    );
}

// ---------------------------------------------------------------------------
// 2. EES EAS Registration & Ranked Discovery
// ---------------------------------------------------------------------------

#[test]
fn test_ees_eas_registration_and_discovery_happy_path() {
    let mut ees = EesEngine::new("ees-tokyo-01", "https://ees.tokyo.5gedge.net");

    // EAS 1: Higher load (40%), lower latency (10ms)
    let eas1 = EasProfile {
        eas_id: "eas-game-instance-01".to_string(),
        app_id: "com.cloudgaming.vr".to_string(),
        eas_endpoint_uri: "https://game-01.edge.tokyo:8443".to_string(),
        dnai: "dnai-tokyo-01".to_string(),
        service_area: vec!["tai-tokyo-shinjuku".to_string()],
        max_latency_ms: 10,
        gpu_accelerated: true,
        active_load_pct: 40,
    };

    // EAS 2: Lower load (15%), slightly higher latency (12ms)
    let eas2 = EasProfile {
        eas_id: "eas-game-instance-02".to_string(),
        app_id: "com.cloudgaming.vr".to_string(),
        eas_endpoint_uri: "https://game-02.edge.tokyo:8443".to_string(),
        dnai: "dnai-tokyo-01".to_string(),
        service_area: vec!["tai-tokyo-shinjuku".to_string()],
        max_latency_ms: 12,
        gpu_accelerated: true,
        active_load_pct: 15,
    };

    ees.register_eas(eas1).unwrap();
    ees.register_eas(eas2).unwrap();

    let query = EasDiscoveryRequest {
        app_id: "com.cloudgaming.vr".to_string(),
        ue_location_tai: "tai-tokyo-shinjuku".to_string(),
        required_gpu: true,
        max_acceptable_latency_ms: Some(20),
    };

    let results = ees.discover_eas(&query).expect("Discovery failed");
    assert_eq!(results.len(), 2);
    // Ranked by load: EAS 2 (15%) must be ranked first before EAS 1 (40%)
    assert_eq!(results[0].eas_id, "eas-game-instance-02");
    assert_eq!(results[1].eas_id, "eas-game-instance-01");
}

// ---------------------------------------------------------------------------
// 3. GPU Capability Filtering
// ---------------------------------------------------------------------------

#[test]
fn test_ees_gpu_capability_filtering() {
    let mut ees = EesEngine::new("ees-edge-02", "https://ees.edge");

    let gpu_eas = EasProfile {
        eas_id: "eas-ai-inference".to_string(),
        app_id: "ai.yolo.detector".to_string(),
        eas_endpoint_uri: "https://ai.gpu.edge:9000".to_string(),
        dnai: "dnai-01".to_string(),
        service_area: vec!["zone-a".to_string()],
        max_latency_ms: 5,
        gpu_accelerated: true,
        active_load_pct: 20,
    };

    let cpu_eas = EasProfile {
        eas_id: "eas-web-cache".to_string(),
        app_id: "ai.yolo.detector".to_string(),
        eas_endpoint_uri: "https://ai.cpu.edge:9000".to_string(),
        dnai: "dnai-01".to_string(),
        service_area: vec!["zone-a".to_string()],
        max_latency_ms: 5,
        gpu_accelerated: false,
        active_load_pct: 10,
    };

    ees.register_eas(gpu_eas).unwrap();
    ees.register_eas(cpu_eas).unwrap();

    let query = EasDiscoveryRequest {
        app_id: "ai.yolo.detector".to_string(),
        ue_location_tai: "zone-a".to_string(),
        required_gpu: true,
        max_acceptable_latency_ms: None,
    };

    let results = ees.discover_eas(&query).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].eas_id, "eas-ai-inference");
}

// ---------------------------------------------------------------------------
// 4. Overload Protection (Load >= 95% Omitted)
// ---------------------------------------------------------------------------

#[test]
fn test_ees_overload_protection() {
    let mut ees = EesEngine::new("ees-edge-03", "https://ees.edge");

    let eas = EasProfile {
        eas_id: "eas-hot-server".to_string(),
        app_id: "stream.app".to_string(),
        eas_endpoint_uri: "https://stream.edge".to_string(),
        dnai: "dnai-01".to_string(),
        service_area: vec!["zone-b".to_string()],
        max_latency_ms: 10,
        gpu_accelerated: false,
        active_load_pct: 30,
    };
    ees.register_eas(eas.clone()).unwrap();

    // Now EAS spikes to 98% load
    ees.update_eas_load("eas-hot-server", 98).unwrap();

    let query = EasDiscoveryRequest {
        app_id: "stream.app".to_string(),
        ue_location_tai: "zone-b".to_string(),
        required_gpu: false,
        max_acceptable_latency_ms: None,
    };

    let err = ees.discover_eas(&query);
    assert_eq!(err, Err(EdgeAppError::NoMatchingEasFound));
}

// ---------------------------------------------------------------------------
// 5. EAS Lifecycle Deregistration
// ---------------------------------------------------------------------------

#[test]
fn test_ees_eas_lifecycle_deregistration() {
    let mut ees = EesEngine::new("ees-edge-04", "https://ees.edge");

    let eas = EasProfile {
        eas_id: "eas-transient".to_string(),
        app_id: "temp.app".to_string(),
        eas_endpoint_uri: "https://temp.edge".to_string(),
        dnai: "dnai-01".to_string(),
        service_area: vec!["zone-c".to_string()],
        max_latency_ms: 10,
        gpu_accelerated: false,
        active_load_pct: 10,
    };
    ees.register_eas(eas).unwrap();

    // Deregister
    ees.deregister_eas("eas-transient").unwrap();

    let query = EasDiscoveryRequest {
        app_id: "temp.app".to_string(),
        ue_location_tai: "zone-c".to_string(),
        required_gpu: false,
        max_acceptable_latency_ms: None,
    };
    assert_eq!(
        ees.discover_eas(&query),
        Err(EdgeAppError::NoMatchingEasFound)
    );
}
