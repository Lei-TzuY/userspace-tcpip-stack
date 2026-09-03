//! Integration tests for PTP Telecom Path Trace & Announce Fault Propagation.

use toy_tcpip::ptp_path_trace::{
    CLOCK_CLASS_FREERUN, CLOCK_CLASS_HOLDOVER_IN_SPEC, CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC,
    CLOCK_CLASS_LOCKED, MAX_PATH_TRACE_DEPTH, PTP_TLV_TYPE_PATH_TRACE, PathTraceRejectReason,
    PathTraceTlv, PathTraceValidation, PtpPathTraceEngine, TelecomAnnounce, UpstreamRefState,
};

#[test]
fn test_path_trace_tlv_serialize_parse_roundtrip() {
    let mut pt = PathTraceTlv::new();
    let gm_id: [u8; 8] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let bc1_id: [u8; 8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x01];
    let bc2_id: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    assert!(pt.append(gm_id));
    assert!(pt.append(bc1_id));
    assert!(pt.append(bc2_id));
    assert_eq!(pt.depth(), 3);

    // Serialize
    let bytes = pt.serialize();
    // Header (4 bytes) + 3 × 8 bytes = 28 bytes
    assert_eq!(bytes.len(), 28);
    // TLV type should be PATH_TRACE (0x0008)
    assert_eq!(
        u16::from_be_bytes([bytes[0], bytes[1]]),
        PTP_TLV_TYPE_PATH_TRACE
    );
    // Length should be 24 (3 × 8)
    assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 24);

    // Parse back
    let parsed = PathTraceTlv::parse(&bytes).unwrap();
    assert_eq!(parsed.depth(), 3);
    assert_eq!(parsed.path[0], gm_id);
    assert_eq!(parsed.path[1], bc1_id);
    assert_eq!(parsed.path[2], bc2_id);
}

#[test]
fn test_path_trace_loop_detection_and_depth_limit() {
    let mut pt = PathTraceTlv::new();
    let id_a: [u8; 8] = [1; 8];
    let id_b: [u8; 8] = [2; 8];

    pt.append(id_a);
    pt.append(id_b);

    // id_a is already in the path → loop detected
    assert!(pt.would_create_loop(&id_a));
    assert!(pt.would_create_loop(&id_b));

    // id_c is not in the path → no loop
    let id_c: [u8; 8] = [3; 8];
    assert!(!pt.would_create_loop(&id_c));

    // Static validation detects loops
    let result = PtpPathTraceEngine::validate_path_trace(&pt);
    assert!(matches!(result, PathTraceValidation::Valid { depth: 2 }));

    // Inject duplicate for validation
    let mut looped_pt = pt.clone();
    looped_pt.path.push(id_a); // Duplicate!
    let result = PtpPathTraceEngine::validate_path_trace(&looped_pt);
    assert!(matches!(
        result,
        PathTraceValidation::LoopAt { position: 2, .. }
    ));

    // Test depth limit
    let mut deep_pt = PathTraceTlv::new();
    for i in 0..MAX_PATH_TRACE_DEPTH {
        let mut id = [0u8; 8];
        id[0] = i as u8;
        id[7] = (i >> 8) as u8;
        assert!(deep_pt.append(id));
    }
    // Next append should fail
    assert!(!deep_pt.append([0xFF; 8]));
}

#[test]
fn test_three_tier_tbc_chain_path_propagation() {
    let gm_id: [u8; 8] = [0x10; 8];
    let bc1_id: [u8; 8] = [0x20; 8];
    let bc2_id: [u8; 8] = [0x30; 8];
    let bc3_id: [u8; 8] = [0x40; 8];

    // 1. T-GM generates Announce with its clock identity in path trace
    let gm_announce = TelecomAnnounce::from_grandmaster(gm_id);
    assert_eq!(gm_announce.clock_class, CLOCK_CLASS_LOCKED);
    assert_eq!(gm_announce.steps_removed, 0);
    assert_eq!(gm_announce.path_trace.depth(), 1);

    // 2. T-BC1 receives GM's Announce
    let mut bc1 = PtpPathTraceEngine::new(bc1_id, 128);
    let result = bc1.process_incoming_announce(&gm_announce);
    assert!(result.is_ok());
    assert!(matches!(bc1.upstream_state, UpstreamRefState::Locked));

    // T-BC1 generates downstream Announce
    let bc1_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(bc1_announce.steps_removed, 1);
    assert_eq!(bc1_announce.path_trace.depth(), 2); // GM + BC1
    assert_eq!(bc1_announce.path_trace.path[0], gm_id);
    assert_eq!(bc1_announce.path_trace.path[1], bc1_id);
    assert_eq!(bc1_announce.clock_class, CLOCK_CLASS_LOCKED); // Still locked

    // 3. T-BC2 receives BC1's Announce
    let mut bc2 = PtpPathTraceEngine::new(bc2_id, 128);
    bc2.process_incoming_announce(&bc1_announce).unwrap();

    let bc2_announce = bc2.generate_downstream_announce().unwrap();
    assert_eq!(bc2_announce.steps_removed, 2);
    assert_eq!(bc2_announce.path_trace.depth(), 3); // GM + BC1 + BC2

    // 4. T-BC3 receives BC2's Announce
    let mut bc3 = PtpPathTraceEngine::new(bc3_id, 128);
    bc3.process_incoming_announce(&bc2_announce).unwrap();

    let bc3_announce = bc3.generate_downstream_announce().unwrap();
    assert_eq!(bc3_announce.steps_removed, 3);
    assert_eq!(bc3_announce.path_trace.depth(), 4); // GM + BC1 + BC2 + BC3

    // 5. If BC3's announce loops back to BC1, BC1 should reject it (loop detection)
    let loop_result = bc1.process_incoming_announce(&bc3_announce);
    assert_eq!(loop_result, Err(PathTraceRejectReason::LoopDetected));
    assert_eq!(bc1.loop_detections, 1);
}

#[test]
fn test_holdover_fault_propagation_cascade() {
    let gm_id: [u8; 8] = [0x10; 8];
    let bc1_id: [u8; 8] = [0x20; 8];

    // Setup: BC1 is locked to GM
    let gm_announce = TelecomAnnounce::from_grandmaster(gm_id);
    let mut bc1 = PtpPathTraceEngine::new(bc1_id, 128);
    bc1.process_incoming_announce(&gm_announce).unwrap();

    // BC1 generates a normal locked downstream announce
    let normal_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(normal_announce.clock_class, CLOCK_CLASS_LOCKED);

    // === Upstream failure: GM reference lost ===
    bc1.signal_upstream_loss();
    assert_eq!(bc1.holdover_transitions, 1);
    assert!(matches!(
        bc1.upstream_state,
        UpstreamRefState::HoldoverInSpec { elapsed_sec: 0 }
    ));

    // Downstream announce should now show holdover-in-spec
    let holdover_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(holdover_announce.clock_class, CLOCK_CLASS_HOLDOVER_IN_SPEC);

    // Advance holdover timer past half the budget → accuracy degrades
    bc1.advance_holdover_timer(600); // 600 seconds > 1000/2 = 500
    let degraded_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(degraded_announce.clock_class, CLOCK_CLASS_HOLDOVER_IN_SPEC);
    assert_eq!(
        degraded_announce.clock_accuracy,
        bc1.holdover_budget.degraded_accuracy
    );

    // Advance past full budget → transitions to HoldoverOutOfSpec
    bc1.advance_holdover_timer(500); // Total now 1100 > 1000
    assert!(matches!(
        bc1.upstream_state,
        UpstreamRefState::HoldoverOutOfSpec
    ));

    let out_of_spec_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(
        out_of_spec_announce.clock_class,
        CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC
    );

    // === Upstream restored ===
    bc1.signal_upstream_restore();
    assert!(matches!(bc1.upstream_state, UpstreamRefState::Locked));

    // Re-ingest GM announce → locked state propagates downstream again
    bc1.process_incoming_announce(&gm_announce).unwrap();
    let restored_announce = bc1.generate_downstream_announce().unwrap();
    assert_eq!(restored_announce.clock_class, CLOCK_CLASS_LOCKED);
}

#[test]
fn test_freerun_state_clock_class() {
    let bc_id: [u8; 8] = [0x50; 8];
    let mut bc = PtpPathTraceEngine::new(bc_id, 128);

    // BC starts in FreeRun (no upstream ever acquired)
    assert!(matches!(bc.upstream_state, UpstreamRefState::FreeRun));

    // Manually set a dummy best announce to test FreeRun propagation
    let gm_id: [u8; 8] = [0x60; 8];
    let gm = TelecomAnnounce::from_grandmaster(gm_id);
    bc.process_incoming_announce(&gm).unwrap();

    // Override upstream to FreeRun
    bc.upstream_state = UpstreamRefState::FreeRun;
    let announce = bc.generate_downstream_announce().unwrap();
    assert_eq!(announce.clock_class, CLOCK_CLASS_FREERUN);
    assert_eq!(announce.clock_accuracy, 0xFE); // Unknown
}
