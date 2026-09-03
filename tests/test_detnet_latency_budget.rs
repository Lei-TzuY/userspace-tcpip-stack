use toy_tcpip::detnet_latency_budget::{DetNetHop, DetNetLatencyBudgetEngine, DetNetQueuingModel};

#[test]
fn test_detnet_multi_path_preof_budget_and_skew() {
    let engine = DetNetLatencyBudgetEngine::new();

    // Primary Path (faster, shorter fiber)
    let path_primary = vec![
        DetNetHop::new(
            "PE-1",
            5.0,
            0.5,
            1.0,
            DetNetQueuingModel::Cqf {
                cycle_time_us: 50.0,
            },
        ), // prop 25us, q 50..100us
        DetNetHop::new(
            "P-1",
            10.0,
            0.5,
            1.0,
            DetNetQueuingModel::Cqf {
                cycle_time_us: 50.0,
            },
        ), // prop 50us, q 50..100us
    ];

    // Secondary Path (longer fiber, ATS shaping)
    let path_secondary = vec![
        DetNetHop::new(
            "PE-1",
            15.0,
            1.0,
            2.0,
            DetNetQueuingModel::Ats {
                max_burst_bytes: 1500,
                committed_rate_mbps: 1000.0,
            },
        ), // prop 75us, q 0.5..13us
        DetNetHop::new(
            "P-2",
            20.0,
            1.0,
            2.0,
            DetNetQueuingModel::Ats {
                max_burst_bytes: 1500,
                committed_rate_mbps: 1000.0,
            },
        ), // prop 100us, q 0.5..13us
    ];

    let preof_result = engine
        .evaluate_preof_paths(&[path_primary, path_secondary], 1000.0)
        .unwrap();

    assert_eq!(preof_result.path_budgets.len(), 2);
    assert!(preof_result.overall_min_delay_us > 0.0);
    assert!(preof_result.overall_max_delay_us > preof_result.overall_min_delay_us);
    assert!(preof_result.differential_path_skew_us > 0.0);
    assert!(preof_result.recommended_pef_buffer_bytes >= 1500);
}
