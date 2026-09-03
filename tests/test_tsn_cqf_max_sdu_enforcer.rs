use toy_tcpip::tsn_cqf_max_sdu_enforcer::{
    MaxSduAction, MaxSduVerdict, TsnCqfMaxSduEnforcerEngine,
};

#[test]
fn test_tsn_cqf_max_sdu_enforcer_integration() {
    let mut enforcer = TsnCqfMaxSduEnforcerEngine::new(100_000, 1518);

    // Add multiple rules
    enforcer.add_rule(10, 256, MaxSduAction::DropOversized, "Voice Frame Limit");
    enforcer.add_rule(20, 1024, MaxSduAction::TruncateToMax, "Bulk Stream Clamp");
    enforcer.add_rule(
        30,
        512,
        MaxSduAction::PassWithAlert,
        "Sensor Telemetry Warning",
    );

    // Conforming voice frame
    let (verdict, forwarded) = enforcer.enforce_frame(10, 1, 200, 50_000);
    assert_eq!(forwarded, 200);
    assert_eq!(
        verdict,
        MaxSduVerdict::Conforming {
            stream_id: 10,
            frame_id: 1,
            frame_bytes: 200,
            cycle_idx: 0,
        }
    );

    // Oversized voice frame (exceeds 256B) -> dropped
    let (verdict, forwarded) = enforcer.enforce_frame(10, 2, 300, 75_000);
    assert_eq!(forwarded, 0);
    assert_eq!(
        verdict,
        MaxSduVerdict::DroppedOversized {
            stream_id: 10,
            frame_id: 2,
            attempted_bytes: 300,
            max_allowed: 256,
            cycle_idx: 0,
        }
    );

    // Bulk frame (1500B > 1024B) -> truncated
    let (verdict, forwarded) = enforcer.enforce_frame(20, 3, 1500, 120_000);
    assert_eq!(forwarded, 1024);
    assert_eq!(
        verdict,
        MaxSduVerdict::Truncated {
            stream_id: 20,
            frame_id: 3,
            original_bytes: 1500,
            truncated_bytes: 1024,
            cycle_idx: 1,
        }
    );

    // Sensor frame (700B > 512B) -> alert pass
    let (verdict, forwarded) = enforcer.enforce_frame(30, 4, 700, 250_000);
    assert_eq!(forwarded, 700);
    assert_eq!(
        verdict,
        MaxSduVerdict::AlertPass {
            stream_id: 30,
            frame_id: 4,
            frame_bytes: 700,
            max_allowed: 512,
            cycle_idx: 2,
        }
    );

    // Unregistered stream (stream 99) with 2000B > default 1518B -> dropped
    let (verdict, forwarded) = enforcer.enforce_frame(99, 5, 2000, 350_000);
    assert_eq!(forwarded, 0);
    assert_eq!(
        verdict,
        MaxSduVerdict::DroppedOversized {
            stream_id: 99,
            frame_id: 5,
            attempted_bytes: 2000,
            max_allowed: 1518,
            cycle_idx: 3,
        }
    );

    assert_eq!(enforcer.total_frames_inspected, 5);
    assert_eq!(enforcer.total_conforming_frames, 1);
    assert_eq!(enforcer.total_dropped_frames, 2);
    assert_eq!(enforcer.total_truncated_frames, 1);
    assert_eq!(enforcer.total_alert_frames, 1);
    assert_eq!(
        enforcer.total_bytes_inspected,
        200 + 300 + 1500 + 700 + 2000
    );
    assert_eq!(enforcer.total_bytes_forwarded, 200 + 1024 + 700);
}
