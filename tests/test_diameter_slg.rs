//! Integration tests for 3GPP Diameter SLg Interface (3GPP TS 29.172 - Location Services).

use toy_tcpip::diameter_slg::{
    AccuracyFulfilmentIndicator, DIAMETER_APPLICATION_SLG, DIAMETER_CMD_LOCATION_REPORT,
    DIAMETER_CMD_PROVIDE_LOCATION, DeferredLocationType, GmlcSlgEngine, LcsQos, LcsResponseTime,
    LocationEstimate, LocationEvent, LocationReportRequest, LocationSessionState,
    ProvideLocationAnswer, SlgLocationType,
};

#[test]
fn test_slg_immediate_location_plr_pla_lifecycle() {
    let mut gmlc = GmlcSlgEngine::new(
        "gmlc.epc.mnc001.mcc310.3gppnetwork.org",
        "epc.mnc001.mcc310.3gppnetwork.org",
    );

    // 1. GMLC initiates immediate location request for subscriber
    let plr = gmlc.request_immediate_location(
        "310010123456789",
        "epc.mnc001.mcc310.3gppnetwork.org",
        LcsQos {
            horizontal_accuracy: Some(20),
            vertical_accuracy: Some(10),
            velocity_requested: false,
            response_time_category: LcsResponseTime::LowDelay,
        },
    );

    assert_eq!(plr.location_type, SlgLocationType::CurrentLocation);
    assert_eq!(plr.imsi, "310010123456789");
    assert_eq!(gmlc.total_plr_sent, 1);

    // Verify the session is in PendingLocationResponse state
    let state = gmlc.get_session_state(&plr.session_id).unwrap();
    assert!(matches!(
        state,
        LocationSessionState::PendingLocationResponse
    ));

    // 2. Encode to Diameter wire format
    let diameter_msg = plr.to_diameter_message();
    assert_eq!(diameter_msg.header.application_id, DIAMETER_APPLICATION_SLG);
    assert_eq!(
        diameter_msg.header.command_code,
        DIAMETER_CMD_PROVIDE_LOCATION
    );
    assert!(!diameter_msg.avps.is_empty());

    // 3. MME responds with PLA (success) carrying a location estimate
    let location = LocationEstimate::EllipsoidPointUncertaintyCircle {
        latitude: 40_748817,   // NYC ~40.748817°
        longitude: -73_985428, // NYC ~-73.985428°
        uncertainty_radius_m: 15,
    };
    let pla = ProvideLocationAnswer::success(
        &plr.session_id,
        "mme01.epc.mnc001.mcc310.3gppnetwork.org",
        "epc.mnc001.mcc310.3gppnetwork.org",
        location.clone(),
    );

    let accepted = gmlc.process_pla(&pla);
    assert!(accepted);
    assert_eq!(gmlc.total_pla_received, 1);

    // Verify session transitioned to LocationReceived
    let state = gmlc.get_session_state(&plr.session_id).unwrap();
    assert!(matches!(state, LocationSessionState::LocationReceived));

    // Verify location estimate is stored
    let stored_loc = gmlc.get_last_location(&plr.session_id).unwrap();
    assert_eq!(*stored_loc, location);
}

#[test]
fn test_slg_periodic_deferred_location_with_lrr() {
    let mut gmlc = GmlcSlgEngine::new("gmlc.operator.com", "operator.com");

    // 1. GMLC requests periodic location tracking (3 reports, every 60 seconds)
    let plr = gmlc.request_periodic_location(
        "310010987654321",
        "epc.operator.com",
        3,  // reporting_amount
        60, // reporting_interval_sec
    );

    assert_eq!(plr.location_type, SlgLocationType::ActivateDeferredLocation);
    assert!(plr.deferred_location_type.is_some());
    let deferred = plr.deferred_location_type.unwrap();
    assert!(deferred.has_flag(DeferredLocationType::PERIODIC_LDR));
    assert_eq!(plr.periodic_ldr.as_ref().unwrap().reporting_amount, 3);
    assert_eq!(
        plr.periodic_ldr.as_ref().unwrap().reporting_interval_sec,
        60
    );

    // Initial state should be DeferredActive with 3 reports remaining
    let state = gmlc.get_session_state(&plr.session_id).unwrap();
    assert!(matches!(
        state,
        LocationSessionState::DeferredActive {
            reports_remaining: Some(3)
        }
    ));

    // 2. PLA acknowledges the deferred request
    let pla = ProvideLocationAnswer {
        session_id: plr.session_id.clone(),
        result_code: 2001, // DIAMETER_SUCCESS
        origin_host: "mme01.epc.operator.com".to_string(),
        origin_realm: "epc.operator.com".to_string(),
        location_estimate: None, // No initial location for deferred
        accuracy_fulfilment: None,
        age_of_location_estimate_sec: None,
        velocity_estimate: None,
        eutran_positioning_data: None,
        ecgi: None,
        lcs_reference_number: None,
    };
    gmlc.process_pla(&pla);

    // 3. Simulate 3 periodic LRR events from MME
    for i in 0..3 {
        let lrr = LocationReportRequest {
            session_id: plr.session_id.clone(),
            origin_host: "mme01.epc.operator.com".to_string(),
            origin_realm: "epc.operator.com".to_string(),
            destination_realm: "operator.com".to_string(),
            destination_host: "gmlc.operator.com".to_string(),
            imsi: "310010987654321".to_string(),
            location_event: LocationEvent::DeferredMtLrResponse,
            location_estimate: Some(LocationEstimate::EllipsoidPoint {
                latitude: 40_748817 + (i * 100) as i32,
                longitude: -73_985428 + (i * 50) as i32,
            }),
            accuracy_fulfilment: Some(AccuracyFulfilmentIndicator::RequestedAccuracyFulfilled),
            age_of_location_estimate_sec: Some(0),
            lcs_reference_number: plr.lcs_reference_number,
            ecgi: None,
        };

        let lra = gmlc.process_lrr(&lrr);
        assert_eq!(lra.result_code, 2001);

        // Verify LRA can be encoded
        let lra_msg = lra.to_diameter_message();
        assert_eq!(lra_msg.header.command_code, DIAMETER_CMD_LOCATION_REPORT);
    }

    assert_eq!(gmlc.total_lrr_received, 3);
    assert_eq!(gmlc.total_lra_sent, 3);

    // After 3 reports, session should auto-complete
    let state = gmlc.get_session_state(&plr.session_id).unwrap();
    assert!(matches!(state, LocationSessionState::Completed));

    // Last location should be the 3rd report's position
    let last = gmlc.get_last_location(&plr.session_id).unwrap();
    assert!(matches!(last, LocationEstimate::EllipsoidPoint { .. }));
}

#[test]
fn test_slg_location_estimate_gad_encoding() {
    // Test that all LocationEstimate variants can be encoded into Diameter AVPs
    let gm_answer = ProvideLocationAnswer::success(
        "gmlc.test;42",
        "mme.test",
        "test",
        LocationEstimate::EllipsoidPointAltitudeUncertainty {
            latitude: 37_774929,
            longitude: -122_419418,
            altitude_m: 15,
            uncertainty_semi_major_m: 10,
            uncertainty_semi_minor_m: 10,
            orientation_major_axis_deg: 0,
            uncertainty_altitude_m: 5,
            confidence_pct: 95,
        },
    );

    let msg = gm_answer.to_diameter_message();
    // Should have Session-ID, Result-Code, Origin-Host, Origin-Realm, Location-Estimate, Accuracy, Age
    assert!(msg.avps.len() >= 5);
    assert_eq!(
        gm_answer.accuracy_fulfilment,
        Some(AccuracyFulfilmentIndicator::RequestedAccuracyFulfilled)
    );
}

#[test]
fn test_slg_emergency_location_retrieval() {
    use toy_tcpip::diameter_slg::{LcsPriority, LocationSessionState, SlgLocationType};

    let mut gmlc = GmlcSlgEngine::new("gmlc.emergency.org", "emergency.org");
    let em_plr = gmlc.request_emergency_location("310010911911911", "epc.carrier.com");

    assert_eq!(
        em_plr.location_type,
        SlgLocationType::CurrentOrLastKnownLocation
    );
    assert_eq!(em_plr.lcs_priority, LcsPriority::HighestPriority);

    let state = gmlc.get_session_state(&em_plr.session_id).unwrap();
    assert!(matches!(
        state,
        LocationSessionState::PendingLocationResponse
    ));

    // MME returns immediate fix for 911 caller
    let fix = LocationEstimate::EllipsoidPointUncertaintyCircle {
        latitude: 34_052235,
        longitude: -118_243683,
        uncertainty_radius_m: 5,
    };
    let pla = ProvideLocationAnswer::success(
        &em_plr.session_id,
        "mme01.epc.carrier.com",
        "epc.carrier.com",
        fix.clone(),
    );
    assert!(gmlc.process_pla(&pla));

    let final_state = gmlc.get_session_state(&em_plr.session_id).unwrap();
    assert!(matches!(
        final_state,
        LocationSessionState::LocationReceived
    ));
    assert_eq!(*gmlc.get_last_location(&em_plr.session_id).unwrap(), fix);
}

#[test]
fn test_slg_cancel_deferred_location() {
    use toy_tcpip::diameter_slg::{LocationSessionState, SlgLocationType};

    let mut gmlc = GmlcSlgEngine::new("gmlc.operator.com", "operator.com");

    // Start a 10-report periodic tracking session
    let plr = gmlc.request_periodic_location("310010444555666", "epc.operator.com", 10, 30);
    assert_eq!(gmlc.active_deferred_session_count(), 1);

    // Cancel the session midway
    let cancel_plr = gmlc
        .cancel_deferred_location(&plr.session_id, "epc.operator.com")
        .expect("Cancel PLR generated");

    assert_eq!(
        cancel_plr.location_type,
        SlgLocationType::CancelDeferredLocation
    );
    assert_eq!(cancel_plr.imsi, "310010444555666");

    // Session is now completed and active deferred count drops to 0
    let state = gmlc.get_session_state(&plr.session_id).unwrap();
    assert!(matches!(state, LocationSessionState::Completed));
    assert_eq!(gmlc.active_deferred_session_count(), 0);

    // Trying to cancel again returns None
    assert!(
        gmlc.cancel_deferred_location(&plr.session_id, "epc.operator.com")
            .is_none()
    );
}
