//! Integration tests for 3GPP TS 29.522 / TS 23.502 5G Network Exposure Function (NEF) Engine.

use toy_tcpip::nef_5g::*;

// ---------------------------------------------------------------------------
// 1. Topology Hiding & Location Reporting Event Exposure Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_nef_topology_hiding_and_event_exposure() {
    let mut nef = NefEngine::new("nef-core-001");
    let gpsi = "msisdn-33600000001";
    let supi = "imsi-208950000000001";

    nef.provision_identifier_mapping(gpsi, supi);
    nef.authorize_af("fleet-af-01", vec![NefEvent::LocationReport]);

    // External AF subscribes to location changes of vehicle (using GPSI)
    let sub = NefEventSubscription {
        subscription_id: "sub-fleet-loc-01".to_string(),
        af_id: "fleet-af-01".to_string(),
        gpsi: Some(gpsi.to_string()),
        external_group_id: None,
        events: vec![NefEvent::LocationReport],
        notification_destination_uri: "https://fleet.enterprise.com/v1/webhook".to_string(),
        max_reports: None,
        reports_delivered: 0,
    };
    nef.create_event_subscription(sub)
        .expect("Subscription failed");

    // Core network ingests internal location event for SUPI
    let loc_info = LocationInfo {
        tai: 100,
        cell_id: 50123,
        geo_coordinates: Some(GeoLocation {
            latitude: 35.6895,
            longitude: 139.6917,
            altitude_m: Some(40.0),
        }),
    };
    nef.ingest_network_event(
        supi,
        NefEvent::LocationReport,
        InternalEventPayload::Location(loc_info.clone()),
        1700000000,
    );

    // Verify external notification: SUPI is concealed, only GPSI is exposed!
    assert_eq!(nef.notification_history.len(), 1);
    let notif = &nef.notification_history[0];
    assert_eq!(notif.subscription_id, "sub-fleet-loc-01");
    assert_eq!(notif.gpsi, gpsi);
    assert_eq!(notif.event, NefEvent::LocationReport);
    assert_eq!(notif.payload, InternalEventPayload::Location(loc_info));
}

// ---------------------------------------------------------------------------
// 2. Reachability & Loss of Connectivity Monitoring
// ---------------------------------------------------------------------------

#[test]
fn test_nef_reachability_and_loss_of_connectivity() {
    let mut nef = NefEngine::new("nef-core-002");
    let gpsi = "drone-01@carrier-iot.com";
    let supi = "imsi-208950000000002";

    nef.provision_identifier_mapping(gpsi, supi);
    nef.authorize_af(
        "drone-control-af",
        vec![NefEvent::LossOfConnectivity, NefEvent::UeReachability],
    );

    let sub = NefEventSubscription {
        subscription_id: "sub-drone-mon-01".to_string(),
        af_id: "drone-control-af".to_string(),
        gpsi: Some(gpsi.to_string()),
        external_group_id: None,
        events: vec![NefEvent::LossOfConnectivity, NefEvent::UeReachability],
        notification_destination_uri: "https://drone.cloud/v1/events".to_string(),
        max_reports: None,
        reports_delivered: 0,
    };
    nef.create_event_subscription(sub).unwrap();

    // 1. Ingest Loss of Connectivity
    nef.ingest_network_event(
        supi,
        NefEvent::LossOfConnectivity,
        InternalEventPayload::LossOfConnectivity {
            cause: "Radio link failure".to_string(),
        },
        1700000010,
    );

    // 2. Ingest Reachability
    nef.ingest_network_event(
        supi,
        NefEvent::UeReachability,
        InternalEventPayload::UeReachability { is_reachable: true },
        1700000020,
    );

    assert_eq!(nef.notification_history.len(), 2);
    assert_eq!(
        nef.notification_history[0].event,
        NefEvent::LossOfConnectivity
    );
    assert_eq!(nef.notification_history[1].event, NefEvent::UeReachability);
}

// ---------------------------------------------------------------------------
// 3. Subscription Auto-Expiry on Max Reports
// ---------------------------------------------------------------------------

#[test]
fn test_nef_subscription_max_reports_auto_expiry() {
    let mut nef = NefEngine::new("nef-core-003");
    let gpsi = "msisdn-33600000003";
    let supi = "imsi-208950000000003";

    nef.provision_identifier_mapping(gpsi, supi);
    nef.authorize_af("one-shot-af", vec![NefEvent::RoamingStatus]);

    let sub = NefEventSubscription {
        subscription_id: "sub-oneshot-01".to_string(),
        af_id: "one-shot-af".to_string(),
        gpsi: Some(gpsi.to_string()),
        external_group_id: None,
        events: vec![NefEvent::RoamingStatus],
        notification_destination_uri: "https://oneshot.io/notify".to_string(),
        max_reports: Some(1), // Auto-expire after 1 report
        reports_delivered: 0,
    };
    nef.create_event_subscription(sub).unwrap();
    assert_eq!(nef.subscriptions.len(), 1);

    // Trigger report
    nef.ingest_network_event(
        supi,
        NefEvent::RoamingStatus,
        InternalEventPayload::Roaming {
            vplmn_mcc: [4, 4, 0],
            vplmn_mnc: [2, 0, 0],
        },
        1700000030,
    );

    assert_eq!(nef.notification_history.len(), 1);
    // Subscription should be automatically deleted upon reaching max_reports
    assert_eq!(nef.subscriptions.len(), 0);
}

// ---------------------------------------------------------------------------
// 4. Unauthorized AF Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_nef_unauthorized_af_rejection() {
    let mut nef = NefEngine::new("nef-core-004");
    nef.provision_identifier_mapping("msisdn-001", "imsi-001");

    // AF not registered in authorized list
    let bad_sub = NefEventSubscription {
        subscription_id: "sub-rogue".to_string(),
        af_id: "rogue-af".to_string(),
        gpsi: Some("msisdn-001".to_string()),
        external_group_id: None,
        events: vec![NefEvent::LocationReport],
        notification_destination_uri: "https://rogue.org".to_string(),
        max_reports: None,
        reports_delivered: 0,
    };
    assert!(nef.create_event_subscription(bad_sub).is_err());
}

// ---------------------------------------------------------------------------
// 5. Nnef_DeviceTriggering for IoT Wakeup
// ---------------------------------------------------------------------------

#[test]
fn test_nef_device_triggering_iot_wakeup() {
    let mut nef = NefEngine::new("nef-core-005");
    let gpsi = "smartmeter-100@grid.net";
    let supi = "imsi-208950000000005";

    nef.provision_identifier_mapping(gpsi, supi);
    nef.authorize_af("smart-grid-af", vec![]);

    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD, 0x01]; // Trigger instruction
    let req = DeviceTriggerRequest {
        trigger_id: "trig-meter-001".to_string(),
        af_id: "smart-grid-af".to_string(),
        gpsi: gpsi.to_string(),
        reference_number: 42,
        trigger_payload: payload.clone(),
        validity_period_s: 3600,
        submission_time_s: 1700000000,
    };

    let status = nef
        .submit_device_trigger(&req)
        .expect("Trigger submit failed");
    assert_eq!(status, DeviceTriggerStatus::Submitted);

    // Verify record in NEF
    let rec = nef.device_triggers.get("trig-meter-001").unwrap();
    assert_eq!(rec.supi, supi);
    assert_eq!(rec.trigger_payload, payload);
    assert_eq!(rec.status, DeviceTriggerStatus::Submitted);

    // AMF confirms delivery over NAS
    assert!(nef.update_device_trigger_status("trig-meter-001", DeviceTriggerStatus::Delivered));
    assert_eq!(
        nef.device_triggers.get("trig-meter-001").unwrap().status,
        DeviceTriggerStatus::Delivered
    );
}
