//! Integration tests for O-RAN WG4 Open Fronthaul Synchronization (S-Plane) Engine.

use toy_tcpip::oran_splane_sync::*;

// ---------------------------------------------------------------------------
// 1. Initial FreeRun to Locked Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_oran_splane_initial_freerun_to_locked_happy_path() {
    let mut splane = OranSplaneSyncEngine::new("o-ru-001", LlsConfig::LlsC2);
    assert_eq!(splane.state, SplaneSyncState::FreeRun);
    assert!(!splane.is_rf_tx_permitted());

    // Ingest SyncE frequency stratum
    splane.update_synce_ql(SyncEQl::QL_ePRC);
    assert_eq!(splane.synce_ql, Some(SyncEQl::QL_ePRC));

    // Ingest PTP sample with 45 ns offset (<= 130 ns lock threshold)
    let ptp_qual = PtpClockQuality {
        clock_class: 6,       // PRTC locked
        clock_accuracy: 0x21, // <= 100 ns
        offset_scaled_log_variance: 0x4800,
        steps_removed: 1,
    };
    splane.update_ptp_sample(45.0, 1200.0, ptp_qual, 1000);

    assert_eq!(splane.state, SplaneSyncState::Locked);
    assert!(splane.is_rf_tx_permitted());
    assert!(splane.rf_tx_enabled);
}

// ---------------------------------------------------------------------------
// 2. Coarse Synchronizing State
// ---------------------------------------------------------------------------

#[test]
fn test_oran_splane_coarse_synchronizing_state() {
    let mut splane = OranSplaneSyncEngine::new("o-ru-002", LlsConfig::LlsC1);

    let ptp_qual = PtpClockQuality {
        clock_class: 7,
        clock_accuracy: 0x22,
        offset_scaled_log_variance: 0x5000,
        steps_removed: 0,
    };

    // Coarse alignment with 500 ns offset (> 130 ns, but <= 1500 ns)
    splane.update_ptp_sample(500.0, 800.0, ptp_qual, 100);

    assert_eq!(splane.state, SplaneSyncState::Synchronizing);
    assert!(!splane.is_rf_tx_permitted()); // TX forbidden during coarse alignment
}

// ---------------------------------------------------------------------------
// 3. Holdover Lifecycle & Automated RF Shutoff upon Budget Violation
// ---------------------------------------------------------------------------

#[test]
fn test_oran_splane_holdover_lifecycle_and_rf_shutoff() {
    let mut splane = OranSplaneSyncEngine::new("o-ru-003", LlsConfig::LlsC2);

    let ptp_qual = PtpClockQuality {
        clock_class: 6,
        clock_accuracy: 0x21,
        offset_scaled_log_variance: 0x4800,
        steps_removed: 2,
    };

    // First lock the node
    splane.update_ptp_sample(30.0, 1500.0, ptp_qual, 1000);
    assert_eq!(splane.state, SplaneSyncState::Locked);
    assert!(splane.is_rf_tx_permitted());

    // PTP GM lost at t = 1000s
    splane.handle_ptp_loss(1000);
    assert_eq!(splane.state, SplaneSyncState::HoldoverInSpec);
    assert!(splane.is_rf_tx_permitted()); // Initial holdover still permitted

    // Advance 2000s (~33 minutes): drift = 2000 * 0.25 = 500 ns. Total TE ~ 503 ns <= 1500 ns
    splane.advance_time(3000);
    assert_eq!(splane.state, SplaneSyncState::HoldoverInSpec);
    assert!(splane.is_rf_tx_permitted());

    // Advance 6500s (~1.8 hours): drift = 6500 * 0.25 = 1625 ns. Total TE > 1500 ns!
    splane.advance_time(7500);
    assert_eq!(splane.state, SplaneSyncState::HoldoverOutOfSpec);
    assert!(!splane.is_rf_tx_permitted()); // RF TX shut off to prevent TDD cross-carrier interference
    assert!(!splane.rf_tx_enabled);
}

// ---------------------------------------------------------------------------
// 4. PTP Recovery from Holdover
// ---------------------------------------------------------------------------

#[test]
fn test_oran_splane_ptp_recovery_from_holdover() {
    let mut splane = OranSplaneSyncEngine::new("o-ru-004", LlsConfig::LlsC4);

    let ptp_qual = PtpClockQuality {
        clock_class: 6,
        clock_accuracy: 0x21,
        offset_scaled_log_variance: 0x4800,
        steps_removed: 0,
    };

    splane.update_ptp_sample(25.0, 100.0, ptp_qual, 100);
    splane.handle_ptp_loss(105);
    assert_eq!(splane.state, SplaneSyncState::HoldoverInSpec);

    // GM recovers with 40 ns offset
    splane.update_ptp_sample(40.0, 100.0, ptp_qual, 200);
    assert_eq!(splane.state, SplaneSyncState::Locked);
    assert!(splane.is_rf_tx_permitted());
    assert_eq!(splane.holdover_started_s, None);
}

// ---------------------------------------------------------------------------
// 5. Time Error Metrics Calculation
// ---------------------------------------------------------------------------

#[test]
fn test_oran_splane_time_error_metrics_calculation() {
    let mut splane = OranSplaneSyncEngine::new("o-ru-005", LlsConfig::LlsC3);

    let ptp_qual = PtpClockQuality {
        clock_class: 6,
        clock_accuracy: 0x21,
        offset_scaled_log_variance: 0x4800,
        steps_removed: 1,
    };

    splane.update_ptp_sample(60.0, 1000.0, ptp_qual, 10);
    let metrics = splane.get_time_error_metrics();

    assert!(metrics.cte_ns > 0.0);
    assert!(metrics.max_te_ns == 60.0);
}
