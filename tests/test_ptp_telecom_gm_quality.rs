use toy_tcpip::ptp_telecom_gm_quality::{
    GmOscillatorType, GmSyncState, PTP_CLOCK_CLASS_HOLDOVER_CATEGORY_1,
    PTP_CLOCK_CLASS_HOLDOVER_CATEGORY_2, PTP_CLOCK_CLASS_HOLDOVER_IN_SPEC,
    PTP_CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC, PTP_CLOCK_CLASS_PRTC_LOCKED, TelecomGrandmasterEngine,
};

#[test]
fn test_ptp_telecom_gm_rubidium_vs_ocxo_holdover_aging() {
    let clock_id = [0x08, 0x00, 0x27, 0xFF, 0xFE, 0x12, 0x34, 0x56];

    // High stability Rubidium oscillator (~1.5 ns / hr)
    let mut gm_rubidium = TelecomGrandmasterEngine::new(clock_id, GmOscillatorType::Rubidium);

    // Initial locked
    assert_eq!(gm_rubidium.state, GmSyncState::LockedPrtc);
    assert_eq!(
        gm_rubidium.get_bmca_attributes().clock_class,
        PTP_CLOCK_CLASS_PRTC_LOCKED
    );

    // GNSS outage for 24 hours
    gm_rubidium.notify_gnss_loss();
    gm_rubidium.advance_time(24.0 * 3600.0);

    // With Rubidium (1.5 ns/hr * 24h = 36 ns drift + 25ns initial = 61ns), remains In-Spec (<=250ns)
    assert_eq!(gm_rubidium.state, GmSyncState::HoldoverInSpec);
    assert_eq!(
        gm_rubidium.get_bmca_attributes().clock_class,
        PTP_CLOCK_CLASS_HOLDOVER_IN_SPEC
    );

    // TCXO oscillator (~1000 ns / hr) degrades quickly
    let mut gm_tcxo = TelecomGrandmasterEngine::new(clock_id, GmOscillatorType::Tcxo);
    gm_tcxo.notify_gnss_loss();

    // After 1 hour (1000ns drift), enters Category 1
    gm_tcxo.advance_time(3600.0);
    assert_eq!(gm_tcxo.state, GmSyncState::HoldoverDegradedCat1);
    assert_eq!(
        gm_tcxo.get_bmca_attributes().clock_class,
        PTP_CLOCK_CLASS_HOLDOVER_CATEGORY_1
    );

    // After 3 hours (3000ns drift), enters Category 2
    gm_tcxo.advance_time(2.0 * 3600.0);
    assert_eq!(gm_tcxo.state, GmSyncState::HoldoverDegradedCat2);
    assert_eq!(
        gm_tcxo.get_bmca_attributes().clock_class,
        PTP_CLOCK_CLASS_HOLDOVER_CATEGORY_2
    );

    // After 6 hours (6000ns drift), Out of Spec (>5000ns)
    gm_tcxo.advance_time(3.0 * 3600.0);
    assert_eq!(gm_tcxo.state, GmSyncState::HoldoverOutOfSpec);
    assert_eq!(
        gm_tcxo.get_bmca_attributes().clock_class,
        PTP_CLOCK_CLASS_HOLDOVER_OUT_OF_SPEC
    );
}
