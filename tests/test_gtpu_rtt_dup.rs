use toy_tcpip::gtpu_rtt_dup::{DupDispatchDecision, DuplicationState, GtpuRttDupEngine};

#[test]
fn test_gtpu_rtt_dup_lifecycle() {
    // Primary leg: 1 (5G), Secondary: 2 (Wi-Fi), SRTT limit: 25ms (25,000 µs), RTTVAR limit: 5ms (5,000 µs), Hysteresis: 2
    let mut engine = GtpuRttDupEngine::new(1, 2, 25_000, 5_000, 2);

    // 1. Initial State: SinglePath
    assert_eq!(
        engine.evaluate_dispatch(),
        DupDispatchDecision::SinglePrimary
    );

    // 2. Primary leg experiences jitter spike (RTTVAR = 7,000 µs) -> Transitions to Duplicating
    engine.update_primary_telemetry(20_000, 7_000);
    assert_eq!(engine.current_state, DuplicationState::Duplicating);
    assert_eq!(
        engine.evaluate_dispatch(),
        DupDispatchDecision::DuplicateBoth {
            primary_leg_id: 1,
            secondary_leg_id: 2,
        }
    );

    // 3. 1st healthy sample (SRTT = 15,000, RTTVAR = 2,000) -> Still duplicating (hysteresis count = 2)
    engine.update_primary_telemetry(15_000, 2_000);
    assert_eq!(engine.current_state, DuplicationState::Duplicating);

    // 4. 2nd healthy sample -> Reverts to SinglePath
    engine.update_primary_telemetry(14_000, 1_500);
    assert_eq!(engine.current_state, DuplicationState::SinglePath);
    assert_eq!(
        engine.evaluate_dispatch(),
        DupDispatchDecision::SinglePrimary
    );
    assert_eq!(engine.total_state_transitions, 2);
}
