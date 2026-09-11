//! Comprehensive integration tests for 3GPP Rel-18/19 NTN Discontinuous Coverage
//! & Delay-Tolerant Networking (DTN) Store-and-Forward Engine.

use toy_tcpip::nr_ntn_dtn_store_forward::{
    Bundle, BundlePriority, ContactWindow, DtnError, DtnStorageBuffer, EndpointId, NtnDtnEngine,
};

// ---------------------------------------------------------------------------
// Test 1: Bundle Protocol v7 Wire Format Serialization & CRC-16 Integrity
// ---------------------------------------------------------------------------
#[test]
fn test_bundle_wire_codec_and_crc() {
    let src = EndpointId::ipn(101, 1);
    let dst = EndpointId::dtn("gateway/earth-station-alpha");
    let payload = b"Satellite remote telemetry sensor payload: T=24.5C, P=1013hPa".to_vec();

    let mut bundle = Bundle::new(
        42,
        src.clone(),
        dst.clone(),
        1000,
        60_000,
        BundlePriority::Urgent,
        payload.clone(),
    );
    bundle.flags.custody_requested = true;
    bundle.flags.report_delivery = true;

    // 1. Encode wire format
    let wire_bytes = bundle.encode_wire();
    assert!(wire_bytes.len() > 50);

    // 2. Decode wire format
    let decoded = Bundle::decode_wire(&wire_bytes).expect("Decode wire bytes");
    assert_eq!(decoded.bundle_id, 42);
    assert_eq!(decoded.source_eid, src);
    assert_eq!(decoded.destination_eid, dst);
    assert_eq!(decoded.creation_timestamp_ms, 1000);
    assert_eq!(decoded.lifetime_ttl_ms, 60_000);
    assert_eq!(decoded.priority, BundlePriority::Urgent);
    assert_eq!(decoded.flags.custody_requested, true);
    assert_eq!(decoded.flags.report_delivery, true);
    assert_eq!(decoded.payload, payload);

    // 3. Corrupt 1 byte in payload and verify CRC-16 catches error
    let mut corrupted = wire_bytes.clone();
    let idx = corrupted.len() - 10;
    corrupted[idx] ^= 0xFF;
    let err = Bundle::decode_wire(&corrupted);
    assert!(matches!(err, Err(DtnError::ChecksumMismatch { .. })));
}

// ---------------------------------------------------------------------------
// Test 2: Dynamic Contact Window & Elevation-Dependent Rate Adaptation
// ---------------------------------------------------------------------------
#[test]
fn test_contact_window_orbit_and_rate_adaptation() {
    // Window: AOS at 10_000 ms, LOS at 20_000 ms (10 sec pass), max elevation 75 degrees, nominal 10 Mbps
    let win = ContactWindow::new(1, 201, 10_000, 20_000, 75.0, 10_000_000);
    assert_eq!(win.duration_ms(), 10_000);

    // 1. Before AOS (t = 5000 ms): Closed
    assert!(!win.is_active(5000));
    assert_eq!(win.instantaneous_rate_bps(5000), 0);

    // 2. Near AOS (t = 10_500 ms, 5% into pass): Low elevation -> 35% nominal rate
    assert!(win.is_active(10_500));
    let rate_aos = win.instantaneous_rate_bps(10_500);
    assert_eq!(rate_aos, 3_500_000);

    // 3. Culmination at zenith (t = 15_000 ms, mid-pass): Elevation = 75° (>= 60°) -> 100% nominal rate
    assert!(win.is_active(15_000));
    let rate_zenith = win.instantaneous_rate_bps(15_000);
    assert_eq!(rate_zenith, 10_000_000);

    // 4. Near LOS (t = 19_500 ms): 35% nominal rate
    assert!(win.is_active(19_500));
    let rate_los = win.instantaneous_rate_bps(19_500);
    assert_eq!(rate_los, 3_500_000);

    // 5. After LOS (t = 25_000 ms): Closed
    assert!(!win.is_active(25_000));
    assert_eq!(win.instantaneous_rate_bps(25_000), 0);
}

// ---------------------------------------------------------------------------
// Test 3: Multi-Priority Queuing & Strict Urgent Preemption
// ---------------------------------------------------------------------------
#[test]
fn test_multi_priority_queueing_and_preemption() {
    let mut storage = DtnStorageBuffer::new(1024 * 1024, 100);
    let src = EndpointId::ipn(1, 1);
    let dst = EndpointId::ipn(2, 1);

    // Insert Bulk first, then Normal, then Urgent
    let b_bulk = Bundle::new(1, src.clone(), dst.clone(), 0, 10_000, BundlePriority::Bulk, vec![1; 100]);
    let b_normal = Bundle::new(2, src.clone(), dst.clone(), 0, 10_000, BundlePriority::Normal, vec![2; 100]);
    let b_urgent = Bundle::new(3, src.clone(), dst.clone(), 0, 10_000, BundlePriority::Urgent, vec![3; 100]);

    storage.store_bundle(b_bulk, 0).unwrap();
    storage.store_bundle(b_normal, 0).unwrap();
    storage.store_bundle(b_urgent, 0).unwrap();

    assert_eq!(storage.total_bundle_count(), 3);

    // Dequeue must strictly pop Urgent (3), then Normal (2), then Bulk (1)
    let p1 = storage.pop_next_bundle().unwrap();
    assert_eq!(p1.bundle_id, 3);
    assert_eq!(p1.priority, BundlePriority::Urgent);

    let p2 = storage.pop_next_bundle().unwrap();
    assert_eq!(p2.bundle_id, 2);
    assert_eq!(p2.priority, BundlePriority::Normal);

    let p3 = storage.pop_next_bundle().unwrap();
    assert_eq!(p3.bundle_id, 1);
    assert_eq!(p3.priority, BundlePriority::Bulk);

    assert!(storage.pop_next_bundle().is_none());
}

// ---------------------------------------------------------------------------
// Test 4: TTL Expiration and Automatic Purging
// ---------------------------------------------------------------------------
#[test]
fn test_ttl_expiration_and_purging() {
    let mut storage = DtnStorageBuffer::new(1024 * 1024, 100);
    let src = EndpointId::ipn(1, 1);
    let dst = EndpointId::ipn(2, 1);

    // Bundle with 500 ms TTL created at t=1000 ms
    let b = Bundle::new(1, src, dst, 1000, 500, BundlePriority::Normal, vec![0; 50]);
    storage.store_bundle(b, 1000).unwrap();

    // At t=1300 ms (age 300 ms < 500 ms TTL): Still alive
    let purged = storage.purge_expired_bundles(1300);
    assert_eq!(purged, 0);
    assert_eq!(storage.total_bundle_count(), 1);

    // At t=1600 ms (age 600 ms > 500 ms TTL): Expired and purged
    let purged2 = storage.purge_expired_bundles(1600);
    assert_eq!(purged2, 1);
    assert_eq!(storage.total_bundle_count(), 0);
}

// ---------------------------------------------------------------------------
// Test 5: Proactive Buffer Eviction on Memory Pressure
// ---------------------------------------------------------------------------
#[test]
fn test_proactive_buffer_eviction_on_overflow() {
    // Storage limited to 400 bytes
    let mut storage = DtnStorageBuffer::new(400, 10);
    let src = EndpointId::ipn(1, 1);
    let dst = EndpointId::ipn(2, 1);

    // Wire size is ~100 bytes each
    let b1 = Bundle::new(1, src.clone(), dst.clone(), 0, 100_000, BundlePriority::Bulk, vec![1; 40]);
    let b2 = Bundle::new(2, src.clone(), dst.clone(), 0, 100_000, BundlePriority::Bulk, vec![2; 40]);
    let b3 = Bundle::new(3, src.clone(), dst.clone(), 0, 100_000, BundlePriority::Bulk, vec![3; 40]);

    storage.store_bundle(b1, 0).unwrap();
    storage.store_bundle(b2, 0).unwrap();
    storage.store_bundle(b3, 0).unwrap();

    assert_eq!(storage.total_bundle_count(), 3);
    let initial_bytes = storage.current_bytes();
    assert!(initial_bytes > 250);

    // Now insert an Urgent bundle that would exceed 400 bytes without eviction
    let b_urgent = Bundle::new(99, src.clone(), dst.clone(), 0, 100_000, BundlePriority::Urgent, vec![9; 80]);
    storage.store_bundle(b_urgent, 0).expect("Eviction should free space for Urgent bundle");

    // Next popped must be the Urgent bundle
    let top = storage.pop_next_bundle().unwrap();
    assert_eq!(top.bundle_id, 99);
    assert_eq!(top.priority, BundlePriority::Urgent);
}

// ---------------------------------------------------------------------------
// Test 6: End-to-End Discontinuous NTN Store-and-Forward Orbit Simulation
// ---------------------------------------------------------------------------
#[test]
fn test_discontinuous_contact_store_and_forward_burst() {
    let sat_eid = EndpointId::ipn(501, 1);
    let mut satellite = NtnDtnEngine::new(501, sat_eid);

    let gw_node_id = 999;
    let gw_eid = EndpointId::dtn("gateway/svalbard-ground-station");

    // 1. Create a 5-minute contact window with the Svalbard gateway starting 30 minutes in the future
    // AOS: 1_800_000 ms (30 min), LOS: 2_100_000 ms (35 min)
    let contact_win = ContactWindow::new(
        1,
        gw_node_id,
        1_800_000,
        2_100_000,
        80.0,
        50_000_000, // 50 Mbps high-speed X/Ka-band feeder link
    );
    satellite.add_contact_window(contact_win);

    // 2. Ingest 10 sensor bundles while in orbital dead zone (t = 0..1_800_000 ms)
    for i in 1..=10 {
        satellite
            .create_and_store_bundle(
                gw_eid.clone(),
                BundlePriority::Normal,
                3_600_000, // 1 hour TTL
                vec![i as u8; 500],
            )
            .unwrap();
    }
    assert_eq!(satellite.storage().total_bundle_count(), 10);

    // 3. Advance clock through the 30-minute dead zone to AOS
    satellite.advance_time_ms(1_800_000);
    assert_eq!(satellite.current_time_ms(), 1_800_000);

    // 4. Execute burst transmission over Svalbard gateway link during 1-second pass slice
    let transmitted = satellite
        .transmit_burst(gw_node_id, 1000)
        .expect("Transmit burst upon AOS");

    // All 10 bundles should easily fit into the 50 Mbps link within 1000 ms
    assert_eq!(transmitted.len(), 10);
    assert_eq!(satellite.storage().total_bundle_count(), 0);

    // 5. Verify telemetry metrics
    let telem = satellite.telemetry();
    assert_eq!(telem.total_bundles_ingested, 10);
    assert_eq!(telem.total_bundles_forwarded, 10);
    assert_eq!(telem.total_bundles_expired, 0);
    assert!(telem.average_dwell_latency_ms() >= 1_800_000.0);
    assert!(telem.max_dwell_latency_ms >= 1_800_000);
}

// ---------------------------------------------------------------------------
// Test 7: Edge Cases and Error Handling
// ---------------------------------------------------------------------------
#[test]
fn test_edge_cases_and_error_handling() {
    let mut engine = NtnDtnEngine::new(1, EndpointId::ipn(1, 1));

    // 1. Transmit when contact window is closed
    let err = engine.transmit_burst(999, 1000);
    assert!(matches!(err, Err(DtnError::ContactWindowClosed { .. })));

    // 2. Attempting to decode too short buffer
    let short_buf = [0x33, 0x47];
    let err_short = Bundle::decode_wire(&short_buf);
    assert!(matches!(err_short, Err(DtnError::DeserializationError(_))));

    // 3. Storing already expired bundle
    let mut storage = DtnStorageBuffer::new(1000, 10);
    let expired_b = Bundle::new(
        10,
        EndpointId::ipn(1, 1),
        EndpointId::ipn(2, 1),
        0,
        500, // 500 ms TTL
        BundlePriority::Normal,
        vec![1; 10],
    );
    let err_exp = storage.store_bundle(expired_b, 1000); // at t=1000 ms, age 1000 > TTL 500
    assert!(matches!(err_exp, Err(DtnError::BundleExpired { .. })));
}
