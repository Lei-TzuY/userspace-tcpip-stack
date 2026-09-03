//! Integration tests for IEEE 802.1Qch CQF Dual-Plane Redundancy & Active-Passive Gate Coordination Engine.

use toy_tcpip::tsn_cqf_dual_plane::{
    DualPlaneDispatchVerdict, DualPlaneMode, PlaneState, TsnCqfDualPlaneEngine, TsnPlane,
};

#[test]
fn test_tsn_cqf_dual_plane_integration() {
    let mut engine = TsnCqfDualPlaneEngine::new(100_000);

    // Initial state check
    assert_eq!(engine.active_plane, TsnPlane::PlaneA);
    assert_eq!(engine.plane_a_state, PlaneState::Active);
    assert_eq!(engine.plane_b_state, PlaneState::Standby);

    // Dispatch 5 frames on Plane A
    for i in 0..5 {
        let v = engine.dispatch_frame(10, 1000, i * 100_000);
        match v {
            DualPlaneDispatchVerdict::ForwardSinglePlane { plane, .. } => {
                assert_eq!(plane, TsnPlane::PlaneA);
            }
            _ => panic!("Expected ForwardSinglePlane on Plane A"),
        }
    }
    assert_eq!(engine.plane_a_metrics.tx_frames, 5);

    // Degrade Plane A (health drops to 30)
    engine.update_plane_telemetry(TsnPlane::PlaneA, 10, 3, 30);
    assert_eq!(engine.plane_a_state, PlaneState::Degraded);

    // Next dispatch triggers automatic failover to Plane B
    let v_failover = engine.dispatch_frame(10, 1000, 500_000);
    match v_failover {
        DualPlaneDispatchVerdict::FailoverTriggeredAndForwarded {
            from_plane,
            to_plane,
            ..
        } => {
            assert_eq!(from_plane, TsnPlane::PlaneA);
            assert_eq!(to_plane, TsnPlane::PlaneB);
        }
        _ => panic!("Expected FailoverTriggeredAndForwarded"),
    }
    assert_eq!(engine.active_plane, TsnPlane::PlaneB);
    assert_eq!(engine.plane_b_state, PlaneState::Active);
    assert_eq!(engine.total_failovers, 1);

    // Switch to DualActiveReplication mode
    engine.set_mode(DualPlaneMode::DualActiveReplication);
    engine.update_plane_telemetry(TsnPlane::PlaneA, 0, 0, 100);
    assert_eq!(engine.plane_a_state, PlaneState::Active);
    assert_eq!(engine.plane_b_state, PlaneState::Active);

    let v_dup = engine.dispatch_frame(10, 1000, 600_000);
    match v_dup {
        DualPlaneDispatchVerdict::ForwardReplicatedBothPlanes { frame_bytes, .. } => {
            assert_eq!(frame_bytes, 1000);
        }
        _ => panic!("Expected ForwardReplicatedBothPlanes"),
    }
}
