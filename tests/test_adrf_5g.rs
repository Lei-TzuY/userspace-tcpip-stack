//! Integration tests for 3GPP TS 29.575 / TS 23.288 5G ADRF (Analytics Data Repository Function).

use std::collections::HashMap;
use toy_tcpip::adrf_5g::*;

// ---------------------------------------------------------------------------
// 1. Data Storage and Time-Window Query
// ---------------------------------------------------------------------------

#[test]
fn test_adrf_data_storage_and_time_window_query() {
    let mut adrf = AdrfEngine::new("adrf-core-01", 1000);
    let slice_id = "01-000001";

    let mut metrics1 = HashMap::new();
    metrics1.insert("load_percent".to_string(), 45.0);
    let mut metrics2 = HashMap::new();
    metrics2.insert("load_percent".to_string(), 78.0);
    let mut metrics3 = HashMap::new();
    metrics3.insert("load_percent".to_string(), 92.0);

    adrf.store_analytics_data(
        AnalyticsDomain::SliceLoadLevel,
        Some(slice_id),
        metrics1,
        1000,
    )
    .unwrap();
    adrf.store_analytics_data(
        AnalyticsDomain::SliceLoadLevel,
        Some(slice_id),
        metrics2,
        1050,
    )
    .unwrap();
    adrf.store_analytics_data(
        AnalyticsDomain::SliceLoadLevel,
        Some(slice_id),
        metrics3,
        1100,
    )
    .unwrap();

    // Query sub-window [1020..1080]
    let res_sub = adrf
        .query_analytics_data(AnalyticsDomain::SliceLoadLevel, Some(slice_id), 1020, 1080)
        .unwrap();
    assert_eq!(res_sub.len(), 1);
    assert_eq!(res_sub[0].timestamp_epoch_s, 1050);
    assert_eq!(res_sub[0].metrics.get("load_percent"), Some(&78.0));

    // Query entire range [1000..1200]
    let res_all = adrf
        .query_analytics_data(AnalyticsDomain::SliceLoadLevel, Some(slice_id), 1000, 1200)
        .unwrap();
    assert_eq!(res_all.len(), 3);
}

// ---------------------------------------------------------------------------
// 2. Storage Capacity Limit and Retention Pruning
// ---------------------------------------------------------------------------

#[test]
fn test_adrf_storage_capacity_limit_and_pruning() {
    let mut adrf = AdrfEngine::new("adrf-core-02", 3); // Max capacity 3

    let mut m = HashMap::new();
    m.insert("latency_ms".to_string(), 15.2);

    adrf.store_analytics_data(AnalyticsDomain::QosSustainability, None, m.clone(), 100)
        .unwrap();
    adrf.store_analytics_data(AnalyticsDomain::QosSustainability, None, m.clone(), 200)
        .unwrap();
    adrf.store_analytics_data(AnalyticsDomain::QosSustainability, None, m.clone(), 300)
        .unwrap();

    // 4th insert exceeds quota
    let err = adrf.store_analytics_data(AnalyticsDomain::QosSustainability, None, m.clone(), 400);
    assert_eq!(err, Err(AdrfError::StorageQuotaExceeded));

    // Prune records older than 250 (removes records at 100 and 200 -> 2 pruned)
    let pruned = adrf.prune_expired_data(250);
    assert_eq!(pruned, 2);
    assert_eq!(adrf.data_records.len(), 1);

    // Now insert succeeds
    adrf.store_analytics_data(AnalyticsDomain::QosSustainability, None, m, 400)
        .unwrap();
    assert_eq!(adrf.data_records.len(), 2);
}

// ---------------------------------------------------------------------------
// 3. Invalid Time Range Handling
// ---------------------------------------------------------------------------

#[test]
fn test_adrf_invalid_time_range() {
    let adrf = AdrfEngine::new("adrf-core-03", 100);
    let err = adrf.query_analytics_data(AnalyticsDomain::NfLoad, None, 2000, 1000);
    assert_eq!(err, Err(AdrfError::InvalidTimeRange));
}

// ---------------------------------------------------------------------------
// 4. ML Model Checkpoint Versioning and Retrieval
// ---------------------------------------------------------------------------

#[test]
fn test_adrf_ml_model_versioning_and_retrieval() {
    let mut adrf = AdrfEngine::new("adrf-core-04", 100);

    let weights_v1 = vec![0x01, 0x02, 0x03];
    let weights_v2 = vec![0x04, 0x05, 0x06, 0x07];

    adrf.store_ml_model(AnalyticsDomain::UeMobility, 1, weights_v1, 0.88, 1000);
    adrf.store_ml_model(
        AnalyticsDomain::UeMobility,
        2,
        weights_v2.clone(),
        0.96,
        2000,
    );

    // Retrieve latest model (must be v2)
    let latest = adrf
        .retrieve_latest_ml_model(AnalyticsDomain::UeMobility)
        .expect("Failed to retrieve latest model");

    assert_eq!(latest.version, 2);
    assert_eq!(latest.accuracy_score, 0.96);
    assert_eq!(latest.model_binary, weights_v2);
}

// ---------------------------------------------------------------------------
// 5. ML Model Deletion and Not Found
// ---------------------------------------------------------------------------

#[test]
fn test_adrf_ml_model_deletion_and_not_found() {
    let mut adrf = AdrfEngine::new("adrf-core-05", 100);

    let model_id = adrf.store_ml_model(
        AnalyticsDomain::AbnormalBehavior,
        1,
        vec![0xAA, 0xBB],
        0.99,
        1000,
    );

    // Delete model
    adrf.delete_ml_model(&model_id).expect("Delete failed");

    // Retrieve should now fail
    let err = adrf.retrieve_latest_ml_model(AnalyticsDomain::AbnormalBehavior);
    assert_eq!(err, Err(AdrfError::ModelNotFound));
}
