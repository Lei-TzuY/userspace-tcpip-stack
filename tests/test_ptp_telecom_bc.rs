use toy_tcpip::ptp_telecom_bc::{
    TelecomBoundaryClockEngine, TelecomClockQuality, TelecomPortState,
};

#[test]
fn test_ptp_telecom_boundary_clock_alternate_bmca() {
    let mut bc = TelecomBoundaryClockEngine::new();

    // Port 1: Candidate slave, local_priority = 10, not_slave = false
    bc.add_port(1, 10, false);
    // Port 2: Candidate slave, local_priority = 20, not_slave = false
    bc.add_port(2, 20, false);
    // Port 3: Downstream Master-only, not_slave = true
    bc.add_port(3, 128, true);

    // Port 1 receives Class 6 PRTC announce
    bc.update_rx_announce(
        1,
        TelecomClockQuality {
            clock_class: 6,
            clock_accuracy: 0x20,
            offset_scaled_log_variance: 0x4E5D,
        },
        1,
        128,
    );

    // Port 2 receives Class 7 announce
    bc.update_rx_announce(
        2,
        TelecomClockQuality {
            clock_class: 7,
            clock_accuracy: 0x21,
            offset_scaled_log_variance: 0x5A00,
        },
        2,
        128,
    );

    let slave = bc.run_alternate_bmca().expect("elect slave port");
    assert_eq!(slave, 1);
    assert_eq!(bc.port_states.get(&1), Some(&TelecomPortState::Slave));
    assert_eq!(bc.port_states.get(&2), Some(&TelecomPortState::Passive));
    assert_eq!(bc.port_states.get(&3), Some(&TelecomPortState::Master));

    // Phase offset adjustment damping test
    let corr = bc.adjust_phase_offset(40);
    assert_eq!(corr, 20);
    assert_eq!(bc.accumulated_phase_offset_ns, 20);
}

#[test]
fn test_ptp_telecom_asymmetry_compensation() {
    let mut bc = TelecomBoundaryClockEngine::new();
    bc.add_port(1, 10, false);

    // Set PHY latency: ingress = 150ns, egress = 210ns
    // Delay asymmetry = (210 - 150) / 2 = +30ns
    bc.set_port_asymmetry(1, 150, 210);
    assert_eq!(bc.ports.get(&1).unwrap().asymmetry_compensation_ns, 30);

    let raw_mean_delay = 1000;
    let compensated = bc.compensate_measured_delay(1, raw_mean_delay);
    assert_eq!(compensated, 970);
}

#[test]
fn test_ptp_telecom_holdover_degradation_and_downstream_announce() {
    use toy_tcpip::ptp_telecom_bc::TelecomSyncState;

    let mut bc = TelecomBoundaryClockEngine::new();
    bc.add_port(1, 10, false);
    bc.add_port(2, 128, true); // Downstream master port

    // Ingest PRTC GM announce
    bc.update_rx_announce(
        1,
        TelecomClockQuality {
            clock_class: 6,
            clock_accuracy: 0x20,
            offset_scaled_log_variance: 0x4E5D,
        },
        1,
        128,
    );

    bc.run_alternate_bmca();
    assert_eq!(bc.sync_state, TelecomSyncState::Locked);
    assert_eq!(bc.current_output_clock_quality().clock_class, 6);

    // Generate downstream announce on Port 2
    let ds_ann = bc
        .generate_downstream_announce(2)
        .expect("generate announce");
    assert_eq!(ds_ann.steps_removed, 2); // 1 + 1
    assert_eq!(ds_ann.grandmaster_clock_quality.clock_class, 6);
    assert_eq!(ds_ann.time_source, 0x20); // PTP

    // Signal loss on Port 1 -> announce timeout triggers Holdover
    bc.handle_announce_timeout(1);
    assert_eq!(bc.sync_state, TelecomSyncState::HoldoverWithinSpec);
    assert_eq!(bc.slave_port, None);
    assert_eq!(bc.current_output_clock_quality().clock_class, 7);

    // Downstream announce now reflects internal oscillator and Class 7
    let ds_holdover = bc
        .generate_downstream_announce(2)
        .expect("holdover announce");
    assert_eq!(ds_holdover.grandmaster_clock_quality.clock_class, 7);
    assert_eq!(ds_holdover.time_source, 0x90); // Internal Oscillator

    // Advance holdover beyond 4-hour (14400s) specification budget
    bc.tick_holdover(15000);
    assert_eq!(bc.sync_state, TelecomSyncState::HoldoverOutOfSpec);
    // Degraded to Class 140
    assert_eq!(bc.current_output_clock_quality().clock_class, 140);
    // Phase drift accumulated: 5.0 ppb * 15000s = 75,000 ns
    assert_eq!(bc.accumulated_phase_offset_ns, 75_000);
}

#[test]
fn test_ptp_telecom_max_steps_removed_filtering() {
    let mut bc = TelecomBoundaryClockEngine::new().with_max_steps_removed(15);
    bc.add_port(1, 10, false); // Port 1 has lower local_priority (10 vs 20)
    bc.add_port(2, 20, false);

    // Port 1 receives Class 6 with 18 steps removed (exceeds limit 15 -> looping/excessive jitter)
    bc.update_rx_announce(
        1,
        TelecomClockQuality {
            clock_class: 6,
            clock_accuracy: 0x20,
            offset_scaled_log_variance: 0x4E5D,
        },
        18,
        128,
    );

    // Port 2 receives Class 6 with 8 steps removed (within limit 15)
    bc.update_rx_announce(
        2,
        TelecomClockQuality {
            clock_class: 6,
            clock_accuracy: 0x20,
            offset_scaled_log_variance: 0x4E5D,
        },
        8,
        128,
    );

    // BMCA should ignore Port 1 due to max_steps_removed violation and elect Port 2
    let slave = bc.run_alternate_bmca().expect("elect slave port");
    assert_eq!(slave, 2);
    assert_eq!(bc.port_states.get(&2), Some(&TelecomPortState::Slave));
}

#[test]
fn test_ptp_telecom_phase_step_detection_and_slew_limiting() {
    let mut bc = TelecomBoundaryClockEngine::new().with_slew_limit(25); // 25 ns/s

    // Phase step detection
    assert!(bc.detect_phase_step(120, 100));
    assert!(bc.detect_phase_step(-105, 100));
    assert!(!bc.detect_phase_step(80, 100));

    // Phase slew rate limiting:
    // Jump of +100ns over 1 second: capped to +25ns
    let adj1 = bc.slew_adjust_phase(100, 1);
    assert_eq!(adj1, 25);
    assert_eq!(bc.accumulated_phase_offset_ns, 25);

    // Jump of -100ns over 2 seconds: max slew is 50ns -> capped to -50ns
    let adj2 = bc.slew_adjust_phase(-100, 2);
    assert_eq!(adj2, -50);
    assert_eq!(bc.accumulated_phase_offset_ns, -25);

    // Small jump within limit: +10ns over 1 second (limit 25ns) -> applied in full
    let adj3 = bc.slew_adjust_phase(10, 1);
    assert_eq!(adj3, 10);
    assert_eq!(bc.accumulated_phase_offset_ns, -15);
}
