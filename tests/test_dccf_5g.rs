//! Integration tests for 3GPP TS 29.574 / TS 23.288 5G DCCF (Data Collection Coordination Function).

use toy_tcpip::dccf_5g::*;

// ---------------------------------------------------------------------------
// 1. Telemetry Subscription & Multi-Consumer Fanout Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_dccf_subscribe_and_telemetry_fanout_happy_path() {
    let mut dccf = DccfEngine::new("dccf-core-01");
    let slice_id = "01-000001";

    let filter = DataFilterSpec {
        data_domain: "SliceLoadLevel".to_string(),
        target_id: Some(slice_id.to_string()),
        min_threshold: None,
        max_threshold: None,
    };

    // Consumer 1: NWDAF Anomaly Detection (Direct HTTP/2 callback)
    let sub1 = dccf
        .subscribe(
            "nwdaf-anomaly-01",
            "SMF",
            filter.clone(),
            DataDeliveryTarget::DirectConsumer {
                callback_uri: "https://nwdaf-01/notify".to_string(),
            },
        )
        .expect("Sub 1 failed");

    // Consumer 2: NWDAF Load Forecasting (Routed to ADRF)
    let sub2 = dccf
        .subscribe(
            "nwdaf-forecasting-02",
            "SMF",
            filter,
            DataDeliveryTarget::AdrfStorage {
                adrf_id: "adrf-core-01".to_string(),
            },
        )
        .expect("Sub 2 failed");

    assert_ne!(sub1, sub2);
    // Verified: Only ONE source collector is established for SMF despite two consumers!
    assert_eq!(dccf.active_source_collectors_count(), 1);

    // SMF produces a single telemetry event
    let events = dccf.ingest_source_telemetry(
        "SMF",
        "SliceLoadLevel",
        Some(slice_id),
        "load_percentage",
        72.5,
        1000,
    );

    // Fanout: Exactly 2 events dispatched (one for each subscriber)
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].consumer_id, "nwdaf-anomaly-01");
    assert_eq!(events[1].consumer_id, "nwdaf-forecasting-02");
    assert_eq!(events[0].value, 72.5);
}

// ---------------------------------------------------------------------------
// 2. Conditional Threshold Filtering
// ---------------------------------------------------------------------------

#[test]
fn test_dccf_threshold_filtering() {
    let mut dccf = DccfEngine::new("dccf-core-02");

    let filter = DataFilterSpec {
        data_domain: "QosSustainability".to_string(),
        target_id: Some("tai-stadium".to_string()),
        min_threshold: Some(80.0), // Alert only if latency >= 80ms
        max_threshold: None,
    };

    dccf.subscribe(
        "nwdaf-qos-guard",
        "UPF",
        filter,
        DataDeliveryTarget::DirectConsumer {
            callback_uri: "https://nwdaf-qos/alert".to_string(),
        },
    )
    .unwrap();

    // Ingest normal latency (35.0ms < 80.0ms) -> Filtered out
    let normal_events = dccf.ingest_source_telemetry(
        "UPF",
        "QosSustainability",
        Some("tai-stadium"),
        "latency_ms",
        35.0,
        1000,
    );
    assert_eq!(normal_events.len(), 0);

    // Ingest spike latency (95.0ms >= 80.0ms) -> Dispatched
    let spike_events = dccf.ingest_source_telemetry(
        "UPF",
        "QosSustainability",
        Some("tai-stadium"),
        "latency_ms",
        95.0,
        1010,
    );
    assert_eq!(spike_events.len(), 1);
    assert_eq!(spike_events[0].value, 95.0);
}

// ---------------------------------------------------------------------------
// 3. Unsubscribe and Automated Collector Cleanup
// ---------------------------------------------------------------------------

#[test]
fn test_dccf_unsubscribe_and_collector_cleanup() {
    let mut dccf = DccfEngine::new("dccf-core-03");

    let filter = DataFilterSpec {
        data_domain: "NfLoad".to_string(),
        target_id: Some("amf-core-01".to_string()),
        min_threshold: None,
        max_threshold: None,
    };

    let sub1 = dccf
        .subscribe(
            "c1",
            "AMF",
            filter.clone(),
            DataDeliveryTarget::DirectConsumer {
                callback_uri: "uri1".to_string(),
            },
        )
        .unwrap();
    let sub2 = dccf
        .subscribe(
            "c2",
            "AMF",
            filter,
            DataDeliveryTarget::DirectConsumer {
                callback_uri: "uri2".to_string(),
            },
        )
        .unwrap();

    assert_eq!(dccf.active_source_collectors_count(), 1);

    // Unsubscribe sub1 -> collector still kept for sub2
    dccf.unsubscribe(&sub1).expect("Unsub 1 failed");
    assert_eq!(dccf.active_source_collectors_count(), 1);

    // Unsubscribe sub2 -> collector orphaned, automatically torn down
    dccf.unsubscribe(&sub2).expect("Unsub 2 failed");
    assert_eq!(dccf.active_source_collectors_count(), 0);
}

// ---------------------------------------------------------------------------
// 4. Wildcard Target Matching
// ---------------------------------------------------------------------------

#[test]
fn test_dccf_wildcard_target_matching() {
    let mut dccf = DccfEngine::new("dccf-core-04");

    // Wildcard subscriber: listens to UeMobility across all UEs
    let filter = DataFilterSpec {
        data_domain: "UeMobility".to_string(),
        target_id: None,
        min_threshold: None,
        max_threshold: None,
    };

    dccf.subscribe(
        "nwdaf-mobility-all",
        "AMF",
        filter,
        DataDeliveryTarget::DirectConsumer {
            callback_uri: "uri-mob".to_string(),
        },
    )
    .unwrap();

    let events = dccf.ingest_source_telemetry(
        "AMF",
        "UeMobility",
        Some("imsi-208950000000001"),
        "handover_count",
        1.0,
        1000,
    );

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].consumer_id, "nwdaf-mobility-all");
    assert_eq!(
        events[0].target_id,
        Some("imsi-208950000000001".to_string())
    );
}

// ---------------------------------------------------------------------------
// 5. Invalid Filter and Not Found Handling
// ---------------------------------------------------------------------------

#[test]
fn test_dccf_invalid_filter_and_not_found() {
    let mut dccf = DccfEngine::new("dccf-core-05");

    let bad_filter = DataFilterSpec {
        data_domain: "".to_string(), // Empty domain invalid
        target_id: None,
        min_threshold: None,
        max_threshold: None,
    };

    let err1 = dccf.subscribe(
        "c1",
        "AMF",
        bad_filter,
        DataDeliveryTarget::DirectConsumer {
            callback_uri: "uri".to_string(),
        },
    );
    assert_eq!(
        err1,
        Err(DccfError::InvalidFilterSpec("Data domain cannot be empty"))
    );

    let err2 = dccf.unsubscribe("non-existent-sub");
    assert_eq!(err2, Err(DccfError::SubscriptionNotFound));
}
