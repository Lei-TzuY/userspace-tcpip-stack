//! Integration tests for 3GPP TS 29.598 / TS 23.501 5G Unstructured Data Storage Function (UDSF) Engine.

use std::collections::HashMap;
use toy_tcpip::udsf_5g::*;

// ---------------------------------------------------------------------------
// 1. Record CRUD & ETag Optimistic Concurrency Control
// ---------------------------------------------------------------------------

#[test]
fn test_udsf_record_crud_and_etag_optimistic_concurrency() {
    let mut udsf = UdsfEngine::new("udsf-dc1-01");
    let collection = "amf-ue-contexts";
    let record_id = "imsi-208950000000001";

    let payload1 = b"{\"amf_ue_ngap_id\": 101, \"state\": \"REGISTERED\"}".to_vec();
    let req1 = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: payload1.clone(),
        ttl_seconds: Some(3600),
        tags: HashMap::new(),
        if_match_etag: None,
        timestamp_epoch_s: 1000,
    };

    let rec1 = udsf.create_or_replace_record(&req1).expect("Create failed");
    assert_eq!(rec1.etag, 1);

    // Read back
    let read1 = udsf.get_record(collection, record_id, 1005).unwrap();
    assert_eq!(read1.payload, payload1);

    // Concurrent modification with stale ETag (expected ETag 999 instead of 1)
    let req_stale = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: b"{\"stale_update\": true}".to_vec(),
        ttl_seconds: Some(3600),
        tags: HashMap::new(),
        if_match_etag: Some(999),
        timestamp_epoch_s: 1010,
    };
    let err_stale = udsf.create_or_replace_record(&req_stale);
    assert_eq!(
        err_stale,
        Err(UdsfError::PreconditionFailed("ETag mismatch"))
    );

    // Successful update with matching ETag (ETag 1)
    let payload2 = b"{\"amf_ue_ngap_id\": 101, \"state\": \"CONNECTED\"}".to_vec();
    let req_valid = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: payload2.clone(),
        ttl_seconds: Some(3600),
        tags: HashMap::new(),
        if_match_etag: Some(1),
        timestamp_epoch_s: 1020,
    };
    let rec2 = udsf.create_or_replace_record(&req_valid).unwrap();
    assert_eq!(rec2.etag, 2);
    assert_eq!(rec2.payload, payload2);
}

// ---------------------------------------------------------------------------
// 2. Distributed Pessimistic Locking & Lease Auto-Expiration
// ---------------------------------------------------------------------------

#[test]
fn test_udsf_distributed_pessimistic_locking_and_auto_lease() {
    let mut udsf = UdsfEngine::new("udsf-dc1-02");
    let collection = "smf-pdu-sessions";
    let record_id = "session-1001";

    let req = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: b"pdu_context_data".to_vec(),
        ttl_seconds: None,
        tags: HashMap::new(),
        if_match_etag: None,
        timestamp_epoch_s: 100,
    };
    udsf.create_or_replace_record(&req).unwrap();

    // SMF-1 acquires 10-second lock at t=100
    udsf.lock_record(collection, record_id, "smf-instance-01", 10, 100)
        .expect("Lock acquisition failed");

    // SMF-2 tries to acquire lock at t=105 -> should be rejected
    let lock_res2 = udsf.lock_record(collection, record_id, "smf-instance-02", 10, 105);
    assert_eq!(
        lock_res2,
        Err(UdsfError::RecordLocked("Record locked by another NF"))
    );

    // SMF-2 tries to update record at t=105 -> should be rejected
    let update_req = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: b"illegal_overwrite".to_vec(),
        ttl_seconds: None,
        tags: HashMap::new(),
        if_match_etag: None,
        timestamp_epoch_s: 105,
    };
    let update_res = udsf.create_or_replace_record(&update_req);
    assert_eq!(
        update_res,
        Err(UdsfError::RecordLocked(
            "Record is locked by another NF instance"
        ))
    );

    // At t=112 (lease expired), SMF-2 can now acquire lock
    let lock_res3 = udsf.lock_record(collection, record_id, "smf-instance-02", 10, 112);
    assert!(lock_res3.is_ok());

    // SMF-2 releases lock
    udsf.unlock_record(collection, record_id, "smf-instance-02")
        .unwrap();
}

// ---------------------------------------------------------------------------
// 3. Tag-Based Secondary Indexing
// ---------------------------------------------------------------------------

#[test]
fn test_udsf_tag_based_secondary_indexing() {
    let mut udsf = UdsfEngine::new("udsf-dc1-03");
    let collection = "pdu-sessions";

    let mut tags1 = HashMap::new();
    tags1.insert("dnn".to_string(), "internet".to_string());
    tags1.insert("snssai".to_string(), "1:010203".to_string());

    let mut tags2 = HashMap::new();
    tags2.insert("dnn".to_string(), "ims".to_string());
    tags2.insert("snssai".to_string(), "1:010203".to_string());

    let mut tags3 = HashMap::new();
    tags3.insert("dnn".to_string(), "internet".to_string());
    tags3.insert("snssai".to_string(), "2:AABBCC".to_string());

    let r1 = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: "pdu-1".to_string(),
        payload: b"pdu-1-data".to_vec(),
        ttl_seconds: None,
        tags: tags1,
        if_match_etag: None,
        timestamp_epoch_s: 1000,
    };
    let r2 = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: "pdu-2".to_string(),
        payload: b"pdu-2-data".to_vec(),
        ttl_seconds: None,
        tags: tags2,
        if_match_etag: None,
        timestamp_epoch_s: 1000,
    };
    let r3 = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: "pdu-3".to_string(),
        payload: b"pdu-3-data".to_vec(),
        ttl_seconds: None,
        tags: tags3,
        if_match_etag: None,
        timestamp_epoch_s: 1000,
    };

    udsf.create_or_replace_record(&r1).unwrap();
    udsf.create_or_replace_record(&r2).unwrap();
    udsf.create_or_replace_record(&r3).unwrap();

    // Query all records with dnn=internet (pdu-1 and pdu-3)
    let internet_pdus = udsf.query_records_by_tag(collection, "dnn", "internet", 1000);
    assert_eq!(internet_pdus.len(), 2);
    let ids: Vec<&str> = internet_pdus.iter().map(|p| p.record_id.as_str()).collect();
    assert!(ids.contains(&"pdu-1"));
    assert!(ids.contains(&"pdu-3"));

    // Query all records with snssai=1:010203 (pdu-1 and pdu-2)
    let slice1_pdus = udsf.query_records_by_tag(collection, "snssai", "1:010203", 1000);
    assert_eq!(slice1_pdus.len(), 2);
}

// ---------------------------------------------------------------------------
// 4. TTL Auto-Expiration & Sweep
// ---------------------------------------------------------------------------

#[test]
fn test_udsf_ttl_auto_expiration_and_sweep() {
    let mut udsf = UdsfEngine::new("udsf-dc1-04");
    let collection = "transient-tokens";

    let req = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: "auth-token-99".to_string(),
        payload: b"access_token_secret".to_vec(),
        ttl_seconds: Some(5), // 5 seconds TTL
        tags: HashMap::new(),
        if_match_etag: None,
        timestamp_epoch_s: 100,
    };
    udsf.create_or_replace_record(&req).unwrap();

    // Read at t=103 (valid)
    assert!(udsf.get_record(collection, "auth-token-99", 103).is_ok());

    // Read at t=106 (expired)
    assert_eq!(
        udsf.get_record(collection, "auth-token-99", 106),
        Err(UdsfError::RecordNotFound)
    );

    // Run sweep eviction at t=110
    let evicted = udsf.sweep_expired_records(110);
    assert_eq!(evicted, 1);
    assert!(udsf.collections.get(collection).unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// 5. Delete with ETag Precondition Protection
// ---------------------------------------------------------------------------

#[test]
fn test_udsf_delete_with_etag_protection() {
    let mut udsf = UdsfEngine::new("udsf-dc1-05");
    let collection = "pcf-policies";
    let record_id = "policy-rule-88";

    let req = PutRecordRequest {
        collection_id: collection.to_string(),
        record_id: record_id.to_string(),
        payload: b"qos_profile_5qi_9".to_vec(),
        ttl_seconds: None,
        tags: HashMap::new(),
        if_match_etag: None,
        timestamp_epoch_s: 1000,
    };
    let rec = udsf.create_or_replace_record(&req).unwrap();

    // Delete with wrong ETag -> fails
    let err = udsf.delete_record(collection, record_id, Some(rec.etag + 1));
    assert_eq!(
        err,
        Err(UdsfError::PreconditionFailed("ETag mismatch on DELETE"))
    );

    // Delete with matching ETag -> succeeds
    udsf.delete_record(collection, record_id, Some(rec.etag))
        .unwrap();
    assert_eq!(
        udsf.get_record(collection, record_id, 1000),
        Err(UdsfError::RecordNotFound)
    );
}
