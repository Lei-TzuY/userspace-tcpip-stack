use toy_tcpip::gtpu_flow_reanchor::{
    FlowMigrationState, GTPU_MSG_END_MARKER, GtpuFlowReanchorEngine, ReanchorAction,
};

#[test]
fn test_gtpu_flow_reanchor_lifecycle() {
    let mut engine = GtpuFlowReanchorEngine::new(0x9001);
    assert_eq!(GTPU_MSG_END_MARKER, 254);

    // 1. Register flow 42 on Leg 1 (Cellular) starting at seq 500
    engine.register_flow(42, 1, 500);

    // 2. Dispatch 2 packets
    let p1 = engine.dispatch_packet(42);
    assert_eq!(
        p1,
        Some(ReanchorAction::ForwardOnLeg {
            leg_id: 1,
            assigned_seq: 500
        })
    );

    let p2 = engine.dispatch_packet(42);
    assert_eq!(
        p2,
        Some(ReanchorAction::ForwardOnLeg {
            leg_id: 1,
            assigned_seq: 501
        })
    );

    // 3. Trigger live migration to Leg 2 (Wi-Fi)
    let m = engine.trigger_migration(42, 2);
    assert_eq!(
        m,
        Some(ReanchorAction::SendEndMarker {
            source_leg_id: 1,
            final_seq: 501,
        })
    );

    // 4. Dispatch next packet -> immediately forwarded on Leg 2 with seq 502
    let p3 = engine.dispatch_packet(42);
    assert_eq!(
        p3,
        Some(ReanchorAction::ForwardOnLeg {
            leg_id: 2,
            assigned_seq: 502
        })
    );

    // 5. Complete migration
    assert!(engine.complete_migration(42));
    assert_eq!(engine.flows[0].state, FlowMigrationState::StableActive);
    assert_eq!(engine.flows[0].current_leg_id, 2);
}
