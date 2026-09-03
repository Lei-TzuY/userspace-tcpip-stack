//! Integration tests for SyncE + PTP Hybrid Synchronization Controller (ITU-T G.8273.2 Annex C).

use toy_tcpip::ptp_synce_hybrid::{HybridSyncConfig, HybridSyncEngine, HybridSyncMode};
use toy_tcpip::synce_esmc::QualityLevel;

#[test]
fn test_hybrid_sync_locked_mode_and_phase_slewing() {
    let mut config = HybridSyncConfig::default();
    config.max_phase_slew_ns_per_sec = 50; // 50 ns/s slew rate

    let mut hybrid = HybridSyncEngine::new(config);

    // Provide Stratum-1 traceable SyncE clock reference
    hybrid.update_synce(QualityLevel::QlPrc, true);
    assert!(hybrid.is_synce_acceptable());

    // Lock PTP clock servo by feeding small phase offsets
    for _ in 0..6 {
        hybrid.update_ptp_sample(10, 0.1);
    }

    assert_eq!(hybrid.mode, HybridSyncMode::HybridLocked);
    assert_eq!(hybrid.current_clock_class(), 6); // PRTC locked equivalent

    // In HybridLocked, frequency adjustment is exactly 0.0 (physically syntonized by SyncE)
    // Slew rate limit for 0.1s is ceil(50 * 0.1) = 5 ns
    let adj = hybrid.update_ptp_sample(25, 0.1);
    assert_eq!(adj.mode, HybridSyncMode::HybridLocked);
    assert_eq!(adj.freq_ppb, 0.0);
    assert_eq!(adj.phase_slew_ns, 5); // Slew rate clamped to 5 ns per 0.1s step
}

#[test]
fn test_hybrid_sync_synce_loss_fallback_to_ptp_only() {
    let mut config = HybridSyncConfig::default();
    config.servo_config.max_frequency_offset_ppb = 50_000.0;
    let mut hybrid = HybridSyncEngine::new(config);

    // Initial hybrid lock
    hybrid.update_synce(QualityLevel::QlSsuA, true);
    for _ in 0..6 {
        hybrid.update_ptp_sample(5, 0.1);
    }
    assert_eq!(hybrid.mode, HybridSyncMode::HybridLocked);

    // Physical link failure or SyncE signal degrades to QL-DNU (Do Not Use)
    hybrid.update_synce(QualityLevel::QlDnu, true);
    assert!(!hybrid.is_synce_acceptable());

    // Engine must fall back to PtpOnly mode
    assert_eq!(hybrid.mode, HybridSyncMode::PtpOnly);
    assert_eq!(hybrid.current_clock_class(), 7); // In-spec packet locked

    // In PtpOnly mode, the internal PTP servo takes over active frequency discipline (non-zero ppb)
    let adj = hybrid.update_ptp_sample(40, 0.1);
    assert_eq!(adj.mode, HybridSyncMode::PtpOnly);
    assert!(adj.freq_ppb < 0.0); // Negative feedback frequency correction
}

#[test]
fn test_hybrid_sync_ptp_timeout_fallback_to_synce_holdover() {
    let mut hybrid = HybridSyncEngine::new(HybridSyncConfig::default());

    // Lock hybrid
    hybrid.update_synce(QualityLevel::QlPrc, true);
    for _ in 0..6 {
        hybrid.update_ptp_sample(2, 0.1);
    }
    assert_eq!(hybrid.mode, HybridSyncMode::HybridLocked);

    // PTP packet stream times out (network congestion or packet drop)
    hybrid.notify_ptp_timeout();

    // Mode transitions to SyncEHoldover
    assert_eq!(hybrid.mode, HybridSyncMode::SyncEHoldover);
    assert_eq!(hybrid.current_clock_class(), 7); // SyncE maintains PRC frequency holdover!

    let adj = hybrid.update_ptp_sample(0, 0.1);
    assert_eq!(adj.mode, HybridSyncMode::SyncEHoldover);
    assert_eq!(adj.freq_ppb, 0.0);
    assert_eq!(adj.phase_slew_ns, 0);

    // Advance holdover timer: frequency is locked to SyncE, no drift accumulated
    hybrid.tick_holdover(100);
    let m = hybrid.metrics();
    assert_eq!(m.holdover_duration_secs, 100);
    assert_eq!(m.accumulated_holdover_drift_ns, 0);
}

#[test]
fn test_hybrid_sync_dual_loss_free_holdover() {
    let mut config = HybridSyncConfig::default();
    config.max_holdover_secs = 200;
    config.oscillator_drift_ppb = 10.0; // 10 ns/s drift

    let mut hybrid = HybridSyncEngine::new(config);

    // Neither SyncE nor PTP are valid
    hybrid.update_synce(QualityLevel::QlInvalid, false);
    hybrid.notify_ptp_timeout();

    assert_eq!(hybrid.mode, HybridSyncMode::FreeHoldover);
    assert_eq!(hybrid.current_clock_class(), 7); // Within initial budget

    // Tick holdover by 100s: drift = 100s * 10ns/s = 1000 ns
    hybrid.tick_holdover(100);
    let m1 = hybrid.metrics();
    assert_eq!(m1.holdover_duration_secs, 100);
    assert_eq!(m1.accumulated_holdover_drift_ns, 1000);
    assert_eq!(hybrid.current_clock_class(), 7);

    // Tick past 200s budget: clock class degrades to 140 (out of spec)
    hybrid.tick_holdover(150);
    let m2 = hybrid.metrics();
    assert_eq!(m2.holdover_duration_secs, 250);
    assert_eq!(m2.accumulated_holdover_drift_ns, 2500);
    assert_eq!(hybrid.current_clock_class(), 140);
}
