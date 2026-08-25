use toy_tcpip::evpn_flap_damping::{DampState, EvpnFlapDampingEngine};

#[test]
fn test_evpn_flap_damping_lifecycle() {
    let mut engine = EvpnFlapDampingEngine::new(1000.0, 2000.0, 500.0, 5); // 5 sec half-life

    // 3 rapid flaps within 1 second
    assert_eq!(engine.record_flap("port_ce2", 0), DampState::Unsuppressed);
    assert_eq!(
        engine.record_flap("port_ce2", 500_000_000),
        DampState::Unsuppressed
    );
    assert_eq!(
        engine.record_flap("port_ce2", 1_000_000_000),
        DampState::Suppressed
    );

    // After 15 seconds (3 half-lives) -> penalty decays below 500
    assert_eq!(
        engine.evaluate_state("port_ce2", 16_000_000_000),
        DampState::Unsuppressed
    );
}
