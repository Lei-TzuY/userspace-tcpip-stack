//! Integration tests for PTP Dual-Plane Redundancy & Hitless Protection Switching.

use toy_tcpip::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};
use toy_tcpip::ptp_telecom_dual_plane::{
    DualPlaneConfig, DualPlaneEngine, ProtectionSwitchMode, PtpPlaneId, PtpPlaneState, SwitchReason,
};

#[test]
fn test_dual_plane_parallel_tracking_and_phase_delta() {
    let filter_a = PtpPdvFloorFilter::new(10, 10.0, 100);
    let filter_b = PtpPdvFloorFilter::new(10, 10.0, 100);
    let mut config = DualPlaneConfig::default();
    config.max_inter_plane_phase_diff_ns = 50; // 50 ns alarm threshold

    let mut engine = DualPlaneEngine::new(config, filter_a, filter_b);

    // Plane A: Delay = 10,000 ns, Offset = 0 ns
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 10_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t2, t3, t4),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);

    // Plane B: Forward = 10,040 ns, Reverse = 9,960 ns -> Offset B = +40 ns
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_040;
        let t3 = t2 + 10_000;
        let t4 = t3 + 9_960;
        engine.push_plane_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t2, t3, t4),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    assert_eq!(engine.active_plane, PtpPlaneId::PlaneA);
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneA),
        PtpPlaneState::Active
    );
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneB),
        PtpPlaneState::Standby
    );

    // Inter-plane phase delta = Offset_A - Offset_B = 0 - 40 = -40 ns
    let delta = engine
        .inter_plane_phase_delta_ns()
        .expect("Inter-plane delta");
    assert_eq!(delta, -40);
    assert!(!engine.is_inter_plane_diverged()); // -40 <= 50ns threshold
}

#[test]
fn test_dual_plane_automatic_protection_switch_on_clock_class_degradation() {
    let filter_a = PtpPdvFloorFilter::new(10, 10.0, 100);
    let filter_b = PtpPdvFloorFilter::new(10, 10.0, 100);
    let mut engine = DualPlaneEngine::new(DualPlaneConfig::default(), filter_a, filter_b);

    // Setup both planes as healthy Class 6
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
        engine.push_plane_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);
    engine.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneA);

    // Plane A Grandmaster experiences GPS antenna failure and degrades to Class 140
    engine.update_plane_announce(PtpPlaneId::PlaneA, 140, 0x31, 0);

    // Protection switching evaluation detects Class degradation on Plane A
    let switch_event = engine.evaluate_protection_switching();
    assert_eq!(
        switch_event,
        Some((PtpPlaneId::PlaneB, SwitchReason::ClockClassDegraded))
    );

    // Plane B is now Active, Plane A is Failed
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneA),
        PtpPlaneState::Failed
    );
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneB),
        PtpPlaneState::Active
    );
    assert_eq!(engine.current_output_clock_class(), 6);
}

#[test]
fn test_dual_plane_hitless_phase_slewing_across_switchover() {
    let filter_a = PtpPdvFloorFilter::new(10, 10.0, 100);
    let filter_b = PtpPdvFloorFilter::new(10, 10.0, 100);
    let mut config = DualPlaneConfig::default();
    config.max_switchover_slew_ns_per_sec = 50; // 50 ns/s standard slew limit

    let mut engine = DualPlaneEngine::new(config, filter_a, filter_b);

    // Plane A offset = 0 ns
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);

    // Plane B offset = +60 ns (forward 10,060, reverse 9,940)
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t1 + 10_060, t1 + 20_000, t1 + 29_940),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    // Signal loss on Plane A triggers switchover to Plane B
    engine.notify_plane_signal_loss(PtpPlaneId::PlaneA);
    let switch_res = engine.evaluate_protection_switching();
    assert_eq!(
        switch_res,
        Some((PtpPlaneId::PlaneB, SwitchReason::SignalLoss))
    );
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);

    // Switchover created a +60 ns pending phase jump
    assert_eq!(engine.pending_phase_jump_ns, 60);

    // Verify hitless slewing: 0.1s interval -> max slew = ceil(50 * 0.1) = 5 ns
    let step1 = engine.compute_disciplined_phase_step(0.1);
    // Raw Plane B offset (60) + slew adjustment (5)
    assert!(step1 > 0);
    assert_eq!(engine.pending_phase_jump_ns, 55); // 60 - 5 = 55 remaining

    // Step across remaining transition until jump is completely absorbed
    for _ in 0..11 {
        engine.compute_disciplined_phase_step(0.1);
    }
    assert_eq!(engine.pending_phase_jump_ns, 0); // Completely absorbed
}

#[test]
fn test_dual_plane_revertive_wtr_damping_and_switchback() {
    let filter_a = PtpPdvFloorFilter::new(10, 10.0, 100);
    let filter_b = PtpPdvFloorFilter::new(10, 10.0, 100);
    let mut config = DualPlaneConfig::default();
    config.switch_mode = ProtectionSwitchMode::Revertive;
    config.wtr_period_secs = 60; // 60s WTR

    let mut engine = DualPlaneEngine::new(config, filter_a, filter_b);

    // Ingest initial valid samples
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
        engine.push_plane_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);
    engine.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    // Plane A fails -> switches to Plane B
    engine.notify_plane_signal_loss(PtpPlaneId::PlaneA);
    engine.evaluate_protection_switching();
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);

    // Plane A recovers!
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);
    assert!(engine.plane_a.healthy);

    // Plane A enters WTR (Wait-To-Restore) state, Plane B remains Active
    engine.tick_wtr(10);
    assert_eq!(engine.plane_state(PtpPlaneId::PlaneA), PtpPlaneState::Wtr);
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);

    // Another 40s (total 50s < 60s): still in WTR
    let switched = engine.tick_wtr(40);
    assert!(!switched);
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);

    // Advance 15s (total 65s >= 60s WTR expiry): automatically reverts to Plane A!
    let reverted = engine.tick_wtr(15);
    assert!(reverted);
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneA);
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneA),
        PtpPlaneState::Active
    );
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneB),
        PtpPlaneState::Standby
    );
}

#[test]
fn test_dual_plane_non_revertive_mode() {
    let filter_a = PtpPdvFloorFilter::new(10, 10.0, 100);
    let filter_b = PtpPdvFloorFilter::new(10, 10.0, 100);
    let mut config = DualPlaneConfig::default();
    config.switch_mode = ProtectionSwitchMode::NonRevertive;

    let mut engine = DualPlaneEngine::new(config, filter_a, filter_b);

    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        engine.push_plane_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
        engine.push_plane_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 20_000, t1 + 30_000),
        );
    }
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);
    engine.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    // Plane A fails -> switches to Plane B
    engine.notify_plane_signal_loss(PtpPlaneId::PlaneA);
    engine.evaluate_protection_switching();
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);

    // Plane A recovers
    engine.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);

    // In Non-Revertive mode, ticking WTR does nothing, clock remains on Plane B
    engine.tick_wtr(100);
    assert_eq!(engine.active_plane, PtpPlaneId::PlaneB);
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneB),
        PtpPlaneState::Active
    );
    assert_eq!(
        engine.plane_state(PtpPlaneId::PlaneA),
        PtpPlaneState::Standby
    );
}
