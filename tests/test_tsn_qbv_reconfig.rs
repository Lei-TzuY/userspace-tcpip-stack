use toy_tcpip::tsn_qbv_reconfig::{QbvDynamicReconfigEngine, QbvGateEntry, QbvSchedule};

#[test]
fn test_tsn_qbv_dynamic_gcl_reconfiguration_cycle() {
    let oper = QbvSchedule::new(
        0,
        vec![
            QbvGateEntry {
                gate_states: 0x80,
                time_interval_ns: 20_000,
            },
            QbvGateEntry {
                gate_states: 0x01,
                time_interval_ns: 80_000,
            },
        ],
    );
    let mut engine = QbvDynamicReconfigEngine::new(oper);

    // Initial GCL check
    assert_eq!(engine.get_active_gate_states(10_000), 0x80);
    assert_eq!(engine.get_active_gate_states(30_000), 0x01);

    // Submit new Admin GCL starting at t = 500,000 ns
    let admin = QbvSchedule::new(
        500_000,
        vec![
            QbvGateEntry {
                gate_states: 0xF0,
                time_interval_ns: 50_000,
            },
            QbvGateEntry {
                gate_states: 0x0F,
                time_interval_ns: 50_000,
            },
        ],
    );
    engine.submit_admin_gcl(admin);
    assert!(engine.config_change);

    // Before activation
    assert_eq!(engine.get_active_gate_states(410_000), 0x80);

    // At/after AdminBaseTime (t = 520,000 ns) -> Swapped to Admin!
    assert_eq!(engine.get_active_gate_states(520_000), 0xF0);
    assert_eq!(engine.total_swaps_completed, 1);
    assert!(!engine.config_change);
}
