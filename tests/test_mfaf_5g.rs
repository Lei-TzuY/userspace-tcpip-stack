//! Integration tests for 3GPP TS 29.576 / TS 23.288 5G MFAF (Messaging Framework Adaptor Function).

use toy_tcpip::mfaf_5g::*;

// ---------------------------------------------------------------------------
// 1. Kafka JSON Batching Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_mfaf_kafka_json_batching_happy_path() {
    let mut mfaf = MfafEngine::new("mfaf-core-01", 1000);

    let map_id = mfaf
        .configure_mapping(
            MessagingProtocol::Kafka,
            "telemetry.5gc.slice.load",
            SerializationFormat::Json,
            2, // Batch size 2
        )
        .expect("Configuration failed");

    // 1st event -> buffered (no batch dispatched yet)
    let batch1 = mfaf
        .ingest_event(&map_id, "SMF", "SliceLoad", Some("01-000001"), 65.5, 1000)
        .unwrap();
    assert!(batch1.is_none());

    // 2nd event -> batch threshold reached, dispatches batch
    let batch2 = mfaf
        .ingest_event(&map_id, "SMF", "SliceLoad", Some("01-000001"), 82.0, 1010)
        .unwrap()
        .expect("Expected dispatched batch");

    assert_eq!(batch2.protocol, MessagingProtocol::Kafka);
    assert_eq!(batch2.destination_topic, "telemetry.5gc.slice.load");
    assert_eq!(batch2.record_count, 2);

    let json_text = String::from_utf8(batch2.payload).unwrap();
    assert!(json_text.contains("\"events\":["));
    assert!(json_text.contains("\"nf\":\"SMF\""));
    assert!(json_text.contains("\"value\":65.50"));
    assert!(json_text.contains("\"value\":82.00"));
}

// ---------------------------------------------------------------------------
// 2. MQTT Compact Binary Serialization
// ---------------------------------------------------------------------------

#[test]
fn test_mfaf_mqtt_compact_binary_serialization() {
    let mut mfaf = MfafEngine::new("mfaf-core-02", 1000);

    let map_id = mfaf
        .configure_mapping(
            MessagingProtocol::Mqtt,
            "iot/5gc/metrics",
            SerializationFormat::CompactBinary,
            1, // Batch size 1 -> instant dispatch
        )
        .unwrap();

    let batch = mfaf
        .ingest_event(&map_id, "UPF", "Throughput", None, 450.0, 2000)
        .unwrap()
        .expect("Expected instant batch");

    assert_eq!(batch.protocol, MessagingProtocol::Mqtt);
    assert_eq!(batch.record_count, 1);
    // Header: 0xFF, 0x5C, count=1 (0x00, 0x01)
    assert_eq!(batch.payload[0], 0xFF);
    assert_eq!(batch.payload[1], 0x5C);
    assert_eq!(batch.payload[2], 0x00);
    assert_eq!(batch.payload[3], 0x01);
}

// ---------------------------------------------------------------------------
// 3. Flush Pending Batches
// ---------------------------------------------------------------------------

#[test]
fn test_mfaf_flush_pending_batches() {
    let mut mfaf = MfafEngine::new("mfaf-core-03", 1000);

    let map_id = mfaf
        .configure_mapping(
            MessagingProtocol::WebSocket,
            "ws/dashboard/telemetry",
            SerializationFormat::Json,
            10, // Large batch size
        )
        .unwrap();

    // Ingest 3 events (less than batch size 10)
    mfaf.ingest_event(&map_id, "AMF", "Registration", None, 1.0, 100)
        .unwrap();
    mfaf.ingest_event(&map_id, "AMF", "Registration", None, 1.0, 101)
        .unwrap();
    mfaf.ingest_event(&map_id, "AMF", "Registration", None, 1.0, 102)
        .unwrap();

    // Manually flush buffer
    let flushed = mfaf
        .flush_pending_batches(&map_id)
        .unwrap()
        .expect("Expected flushed batch");

    assert_eq!(flushed.record_count, 3);

    // Second flush should be empty
    let empty_flush = mfaf.flush_pending_batches(&map_id).unwrap();
    assert!(empty_flush.is_none());
}

// ---------------------------------------------------------------------------
// 4. Buffer Overflow Protection
// ---------------------------------------------------------------------------

#[test]
fn test_mfaf_buffer_overflow_protection() {
    let mut mfaf = MfafEngine::new("mfaf-core-04", 2); // Max buffer limit 2

    let map_id = mfaf
        .configure_mapping(
            MessagingProtocol::Kafka,
            "topic.overflow",
            SerializationFormat::Json,
            5, // Batch size 5 > capacity 2
        )
        .unwrap();

    mfaf.ingest_event(&map_id, "N1", "E1", None, 1.0, 10)
        .unwrap();
    mfaf.ingest_event(&map_id, "N1", "E2", None, 2.0, 20)
        .unwrap();

    // 3rd event exceeds max buffer limit 2
    let err = mfaf.ingest_event(&map_id, "N1", "E3", None, 3.0, 30);
    assert_eq!(err, Err(MfafError::BufferOverflow));
}

// ---------------------------------------------------------------------------
// 5. Invalid Configuration and Deletion
// ---------------------------------------------------------------------------

#[test]
fn test_mfaf_invalid_configuration_and_deletion() {
    let mut mfaf = MfafEngine::new("mfaf-core-05", 100);

    // Empty topic rejected
    let err1 = mfaf.configure_mapping(MessagingProtocol::Kafka, "", SerializationFormat::Json, 5);
    assert_eq!(
        err1,
        Err(MfafError::InvalidConfiguration(
            "Destination topic cannot be empty"
        ))
    );

    // Batch size 0 rejected
    let err2 = mfaf.configure_mapping(
        MessagingProtocol::Kafka,
        "valid.topic",
        SerializationFormat::Json,
        0,
    );
    assert_eq!(
        err2,
        Err(MfafError::InvalidConfiguration(
            "Batch size limit must be greater than zero"
        ))
    );

    // Valid creation followed by deletion
    let map_id = mfaf
        .configure_mapping(
            MessagingProtocol::Mqtt,
            "valid.topic",
            SerializationFormat::Json,
            1,
        )
        .unwrap();

    mfaf.delete_mapping(&map_id).expect("Delete failed");

    // Ingestion on deleted mapping fails
    let err3 = mfaf.ingest_event(&map_id, "N1", "E1", None, 1.0, 10);
    assert_eq!(err3, Err(MfafError::MappingNotFound));
}
