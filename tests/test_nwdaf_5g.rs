//! Integration tests for 3GPP TS 29.520 / TS 23.288 5G Network Data Analytics Function (NWDAF) Engine.

use toy_tcpip::ngap_5g::Snssai;
use toy_tcpip::nwdaf_5g::*;

// ---------------------------------------------------------------------------
// 1. Time-Series Predictive Trend Forecasting (Holt's Linear Smoothing)
// ---------------------------------------------------------------------------

#[test]
fn test_nwdaf_holt_linear_trend_forecasting() {
    let mut predictor = HoltLinearPredictor::new(0.5, 0.3);

    // Feed upward trend: 20, 30, 40, 50, 60
    for val in &[20.0, 30.0, 40.0, 50.0, 60.0] {
        predictor.update(*val);
    }

    assert!(predictor.trend > 5.0, "Trend should be positive");
    assert!(predictor.level >= 50.0, "Level should track recent values");

    // Forecast 3 steps into future
    let forecast = predictor.forecast(3);
    assert!(
        forecast > 70.0,
        "Forecast 3 steps ahead should reflect continued upward trajectory, got {}",
        forecast
    );
}

// ---------------------------------------------------------------------------
// 2. Nnwdaf_AnalyticsInfo: Slice Load Level Query
// ---------------------------------------------------------------------------

#[test]
fn test_nwdaf_query_slice_load_level() {
    let mut nwdaf = NwdafEngine::new("nwdaf-core-001");
    let embb = Snssai { sst: 1, sd: None };

    // Ingest progressive load observations
    for load in &[10, 20, 30, 40, 50, 60, 70] {
        nwdaf.ingest_slice_telemetry(embb.clone(), *load, 150, 800, 1700000000);
    }

    let req = AnalyticsInfoRequest {
        analytics_id: AnalyticsId::SliceLoadLevel,
        target_snssai: Some(embb.clone()),
        target_dnn: None,
        target_tai: None,
        target_supi: None,
        prediction_steps_ahead: 2,
    };

    let resp = nwdaf.query_analytics(&req).expect("Analytics query failed");
    assert_eq!(resp.analytics_id, AnalyticsId::SliceLoadLevel);
    assert!(resp.confidence_percent >= 75);

    let report = resp.slice_load.expect("SliceLoadReport missing");
    assert_eq!(report.s_nssai, embb);
    assert!(report.current_load_percent >= 60);
    assert!(report.predicted_load_percent > report.current_load_percent);
    assert_eq!(report.active_pdu_sessions, 150);
    assert_eq!(report.aggregate_throughput_mbps, 800);
}

// ---------------------------------------------------------------------------
// 3. Nnwdaf_AnalyticsInfo: User Plane Congestion Query
// ---------------------------------------------------------------------------

#[test]
fn test_nwdaf_user_plane_congestion_query() {
    let mut nwdaf = NwdafEngine::new("nwdaf-core-002");
    let tai = 500;

    nwdaf.ingest_congestion_telemetry(tai, 2, 85, 1700000000);

    let req = AnalyticsInfoRequest {
        analytics_id: AnalyticsId::UserPlaneCongestion,
        target_snssai: None,
        target_dnn: None,
        target_tai: Some(tai),
        target_supi: None,
        prediction_steps_ahead: 0,
    };

    let resp = nwdaf.query_analytics(&req).unwrap();
    let cong = resp.congestion.expect("Congestion report missing");
    assert_eq!(cong.tai, tai);
    assert_eq!(cong.congestion_level, 2);
    assert_eq!(cong.affected_prb_usage_percent, 85);
}

// ---------------------------------------------------------------------------
// 4. Online Z-Score Statistical Anomaly Detection
// ---------------------------------------------------------------------------

#[test]
fn test_nwdaf_anomaly_detection_z_score() {
    let mut detector = ZScoreAnomalyDetector::new();

    // Ingest baseline normal traffic: 10 Mbps +/- 0.5
    for _ in 0..50 {
        detector.update(10.0);
        detector.update(10.5);
        detector.update(9.5);
    }

    assert!(detector.std_dev() < 1.0);

    // Test a normal reading
    let z_normal = detector.compute_z_score(10.2);
    assert!(z_normal < 1.0, "Normal reading should have low Z-score");

    // Test an anomalous traffic surge (DDoS / flash crowd)
    let z_spike = detector.compute_z_score(150.0);
    assert!(
        z_spike > 20.0,
        "Sudden 150 Mbps surge should yield massive Z-score, got {}",
        z_spike
    );
}

// ---------------------------------------------------------------------------
// 5. Nnwdaf_EventsSubscription: Threshold Triggered Closed-Loop Notification
// ---------------------------------------------------------------------------

#[test]
fn test_nwdaf_events_subscription_and_threshold_notification() {
    let mut nwdaf = NwdafEngine::new("nwdaf-core-003");
    let urllc = Snssai {
        sst: 2,
        sd: Some([1, 2, 3]),
    };

    // Subscribe to Slice Load > 75%
    nwdaf.subscribe(AnalyticsSubscription {
        subscription_id: "sub-pcf-slice-sla-01".to_string(),
        analytics_id: AnalyticsId::SliceLoadLevel,
        target_snssai: Some(urllc.clone()),
        target_tai: None,
        threshold: AnalyticsThreshold::SliceLoadGreaterThan(75),
        notification_uri: "https://pcf.5gc.local/v1/sla-notifications".to_string(),
    });

    // 1. Ingest normal load (50%) -> no notification
    nwdaf.ingest_slice_telemetry(urllc.clone(), 50, 40, 200, 1700000000);
    assert!(nwdaf.notification_history.is_empty());

    // 2. Ingest elevated load (70%) -> no notification
    nwdaf.ingest_slice_telemetry(urllc.clone(), 70, 70, 350, 1700000010);
    assert!(nwdaf.notification_history.is_empty());

    // 3. Ingest congested load (88%) -> BREACH! Notification dispatched
    nwdaf.ingest_slice_telemetry(urllc.clone(), 88, 100, 500, 1700000020);
    assert_eq!(nwdaf.notification_history.len(), 1);

    let notif = &nwdaf.notification_history[0];
    assert_eq!(notif.subscription_id, "sub-pcf-slice-sla-01");
    assert_eq!(notif.analytics_id, AnalyticsId::SliceLoadLevel);
    assert_eq!(notif.breach_value, 88.0);
}
