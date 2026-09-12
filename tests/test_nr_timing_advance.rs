//! Integration tests for 3GPP Rel-18/19 5G-Advanced Timing Advance Management, RAR MAC PDU Assembly & Time Alignment Timer (TAT) Engine.
//! Validates:
//! - Basic time units $T_c, T_s, \kappa = 64$ and numerologies $\mu \in \{0, 1, 2, 3\}$.
//! - Initial 12-bit Timing Advance $N_{\text{TA}}$ calculation and propagation delay conversion.
//! - Closed-loop 6-bit MAC CE TA updates ($\Delta N_{\text{TA}} = (T_A - 31) \cdot 16 \cdot 64 / 2^\mu$).
//! - Time Alignment Timer (TAT) state machine, duration ticking, and sync expiry detection.
//! - Rel-18 Autonomous Timing Advance (ATA) Doppler velocity drift tracking.
//! - MAC RAR PDU subheaders (RAPID, Backoff Indicator) and 7-byte payload bit-exact serialization.
//! - Binary wire framing (`TimingAdvanceWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_timing_advance::{
    compute_initial_nta, compute_mac_ce_nta_adjustment, compute_total_advance_nanoseconds,
    delay_to_initial_ta_index, AutonomousTimingAdvanceTracker, MacRarPayload, NrNumerology,
    RarSubheader, TatState, TimeAlignmentTimer, TimeAlignmentTimerConfig, TimingAdvanceError,
    TimingAdvanceOffsetType, TimingAdvanceWirePdu, BACKOFF_TABLE_MS, KAPPA, T_C_SECONDS,
    T_S_SECONDS,
};

// ---------------------------------------------------------------------------
// 1. Basic Time Units & Numerologies Tests (TS 38.211 §4.3.1)
// ---------------------------------------------------------------------------

#[test]
fn test_basic_time_units_and_numerology() {
    assert_eq!(KAPPA, 64);

    // T_c = 1 / (480000 * 4096) s ~= 0.5086263 ns
    let tc_ns = T_C_SECONDS * 1e9;
    assert!((tc_ns - 0.5086263).abs() < 1e-6);

    // T_s = 1 / (15000 * 2048) s ~= 32.552083 ns
    let ts_ns = T_S_SECONDS * 1e9;
    assert!((ts_ns - 32.552083).abs() < 1e-5);

    // Ratio Ts / Tc must equal exactly 64
    let ratio = T_S_SECONDS / T_C_SECONDS;
    assert!((ratio - 64.0).abs() < 1e-9);

    // Numerology subcarrier spacings
    assert_eq!(NrNumerology::Mu0_15kHz.scs_khz(), 15);
    assert_eq!(NrNumerology::Mu1_30kHz.scs_khz(), 30);
    assert_eq!(NrNumerology::Mu2_60kHz.scs_khz(), 60);
    assert_eq!(NrNumerology::Mu3_120kHz.scs_khz(), 120);

    // Standardized fixed offsets
    assert_eq!(TimingAdvanceOffsetType::Fr1Fdd.offset_units(), 0);
    assert_eq!(TimingAdvanceOffsetType::Fr1TddDefault.offset_units(), 25_600);
    assert_eq!(TimingAdvanceOffsetType::Fr1TddExtended.offset_units(), 39_936);
    assert_eq!(TimingAdvanceOffsetType::Fr2MmWave.offset_units(), 13_792);
}

// ---------------------------------------------------------------------------
// 2. Initial TA & Propagation Delay Conversion Tests (TS 38.213 §4.2)
// ---------------------------------------------------------------------------

#[test]
fn test_initial_ta_calculation() {
    // For mu = 0 (15 kHz): factor = 16 * 64 / 1 = 1024
    let nta_mu0 = compute_initial_nta(1, NrNumerology::Mu0_15kHz).unwrap();
    assert_eq!(nta_mu0, 1024);

    // For mu = 1 (30 kHz): factor = 16 * 64 / 2 = 512
    let nta_mu1 = compute_initial_nta(1, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(nta_mu1, 512);

    // For mu = 2 (60 kHz): factor = 16 * 64 / 4 = 256
    let nta_mu2 = compute_initial_nta(1, NrNumerology::Mu2_60kHz).unwrap();
    assert_eq!(nta_mu2, 256);

    // Maximum initial TA index: 3846
    let nta_max = compute_initial_nta(3846, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(nta_max, 3846 * 512);

    // Invalid TA > 3846 returns error
    assert_eq!(
        compute_initial_nta(3847, NrNumerology::Mu1_30kHz),
        Err(TimingAdvanceError::InvalidInitialTaIndex(3847))
    );
}

#[test]
fn test_delay_to_initial_ta_index() {
    // 5 microseconds one-way propagation delay (~1.5 km cell radius)
    let delay_sec = 5.0e-6;
    let ta_idx_mu1 = delay_to_initial_ta_index(delay_sec, NrNumerology::Mu1_30kHz).unwrap();

    // Round-trip = 10 us. Step for mu=1 is 512 * T_c = 512 * 0.5086263 ns ~= 260.41667 ns
    // 10,000 ns / 260.41667 ns ~= 38.4 -> 38
    assert_eq!(ta_idx_mu1, 38);

    // Compute total advance time in ns
    let nta = compute_initial_nta(ta_idx_mu1, NrNumerology::Mu1_30kHz).unwrap();
    let total_ns = compute_total_advance_nanoseconds(nta, TimingAdvanceOffsetType::Fr1Fdd);
    assert!((total_ns - (38.0 * 512.0 * T_C_SECONDS * 1e9)).abs() < 1e-4);
}

// ---------------------------------------------------------------------------
// 3. Closed-Loop MAC CE Timing Advance Updates (TS 38.213 §4.2)
// ---------------------------------------------------------------------------

#[test]
fn test_mac_ce_closed_loop_nta_adjustment() {
    // Command = 31 -> zero adjustment
    let adj_zero = compute_mac_ce_nta_adjustment(31, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(adj_zero, 0);

    // Command = 32 -> advance by +1 step (+512 units for mu=1)
    let adj_adv = compute_mac_ce_nta_adjustment(32, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(adj_adv, 512);

    // Command = 30 -> retard by -1 step (-512 units for mu=1)
    let adj_ret = compute_mac_ce_nta_adjustment(30, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(adj_ret, -512);

    // Command = 63 (maximum advance): (63 - 31) * 512 = 32 * 512 = 16384
    let adj_max = compute_mac_ce_nta_adjustment(63, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(adj_max, 16384);

    // Command = 0 (maximum retard): (0 - 31) * 512 = -31 * 512 = -15872
    let adj_min = compute_mac_ce_nta_adjustment(0, NrNumerology::Mu1_30kHz).unwrap();
    assert_eq!(adj_min, -15872);

    // Invalid command > 63
    assert_eq!(
        compute_mac_ce_nta_adjustment(64, NrNumerology::Mu1_30kHz),
        Err(TimingAdvanceError::InvalidMacCeTaIndex(64))
    );
}

// ---------------------------------------------------------------------------
// 4. Time Alignment Timer (TAT) Lifecycle Tests (TS 38.321 §5.2)
// ---------------------------------------------------------------------------

#[test]
fn test_time_alignment_timer_lifecycle() {
    let mut tat = TimeAlignmentTimer::new(TimeAlignmentTimerConfig::Sf500);
    assert_eq!(tat.state, TatState::Stopped);
    assert!(!tat.is_sync_maintained());

    // Receipt of TA command restarts timer to 500 ms
    tat.restart();
    assert_eq!(tat.state, TatState::Running { remaining_ms: 500 });
    assert!(tat.is_sync_maintained());

    // Advance 300 ms -> still running
    let expired = tat.tick(300);
    assert!(!expired);
    assert_eq!(tat.state, TatState::Running { remaining_ms: 200 });
    assert!(tat.is_sync_maintained());

    // Receipt of new TA command restarts timer back to 500 ms
    tat.restart();
    assert_eq!(tat.state, TatState::Running { remaining_ms: 500 });

    // Advance 600 ms -> expires!
    let expired = tat.tick(600);
    assert!(expired);
    assert_eq!(tat.state, TatState::Expired);
    assert!(!tat.is_sync_maintained());
    assert_eq!(tat.total_expirations, 1);

    // Test Infinity config
    let mut tat_inf = TimeAlignmentTimer::new(TimeAlignmentTimerConfig::Infinity);
    tat_inf.restart();
    let expired_inf = tat_inf.tick(1_000_000);
    assert!(!expired_inf);
    assert!(tat_inf.is_sync_maintained());
}

// ---------------------------------------------------------------------------
// 5. Rel-18 Autonomous Timing Advance (ATA) Drift Tests
// ---------------------------------------------------------------------------

#[test]
fn test_autonomous_timing_advance_velocity_drift() {
    let initial_nta = 10_000u32;
    let mut tracker = AutonomousTimingAdvanceTracker::new(NrNumerology::Mu1_30kHz, initial_nta);

    // Apply MAC CE update (+1 step = +512)
    tracker.apply_mac_ce_update(32).unwrap();
    assert_eq!(tracker.current_nta, 10_512);

    // User is on a high-speed vehicle moving away at +150 m/s for 1.0 second
    // Rate of change = 2 * v / (c * T_c) = 300 / (299792458 * 0.5086263e-9) ~= 300 / 0.15248 ~= 1967.4 units
    tracker.tick_autonomous_drift(1.0, 150.0);
    let diff = (tracker.current_nta as i64) - 10512;
    assert!((diff - 1967).abs() <= 1);

    // Move towards gNB at -150 m/s for 1.0 second -> returns back to approx 10,512
    tracker.tick_autonomous_drift(1.0, -150.0);
    assert!(((tracker.current_nta as i64) - 10512).abs() <= 2);
}

// ---------------------------------------------------------------------------
// 6. MAC RAR Subheaders & Payload Tests (TS 38.321 §6.1.5, §6.2.3)
// ---------------------------------------------------------------------------

#[test]
fn test_rar_subheaders_encode_decode() {
    // RAPID subheader with is_last = false, rapid = 15
    let sh_rapid = RarSubheader::Rapid {
        is_last: false,
        rapid: 15,
    };
    let byte_rapid = sh_rapid.encode().unwrap();
    // Bit 7: E=1, Bit 6: T=1, Bits 5..0: RAPID=15 -> 0xC0 | 15 = 0xCF
    assert_eq!(byte_rapid, 0xCF);
    assert_eq!(RarSubheader::decode(byte_rapid), sh_rapid);

    // Backoff Indicator subheader with is_last = true, bi_index = 8 (160 ms)
    let sh_bi = RarSubheader::BackoffIndicator {
        is_last: true,
        bi_index: 8,
    };
    let byte_bi = sh_bi.encode().unwrap();
    // Bit 7: E=0, Bit 6: T=0, Bits 3..0: BI=8 -> 0x08
    assert_eq!(byte_bi, 0x08);
    assert_eq!(RarSubheader::decode(byte_bi), sh_bi);
    assert_eq!(BACKOFF_TABLE_MS[8], 160);

    // Invalid parameters
    assert_eq!(
        RarSubheader::Rapid { is_last: true, rapid: 64 }.encode(),
        Err(TimingAdvanceError::InvalidRapid(64))
    );
    assert_eq!(
        RarSubheader::BackoffIndicator { is_last: true, bi_index: 16 }.encode(),
        Err(TimingAdvanceError::InvalidBackoffIndicator(16))
    );
}

#[test]
fn test_mac_rar_payload_roundtrip() {
    let payload = MacRarPayload {
        ta_command: 1250,
        ul_grant: 0x035A_BEEF, // 27 bits
        temp_crnti: 0xCAFE,
    };

    let encoded = payload.encode().unwrap();
    assert_eq!(encoded.len(), 7);

    let decoded = MacRarPayload::decode(&encoded).unwrap();
    assert_eq!(decoded.ta_command, payload.ta_command);
    assert_eq!(decoded.ul_grant, payload.ul_grant);
    assert_eq!(decoded.temp_crnti, payload.temp_crnti);

    // Boundary values test
    let max_payload = MacRarPayload {
        ta_command: 3846,
        ul_grant: 0x07FF_FFFF, // 27 bits all ones
        temp_crnti: 0xFFFF,
    };
    let encoded_max = max_payload.encode().unwrap();
    let decoded_max = MacRarPayload::decode(&encoded_max).unwrap();
    assert_eq!(decoded_max, max_payload);
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (TimingAdvanceWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = TimingAdvanceWirePdu {
        numerology_mu: 1,
        current_nta: 20480,
        total_advance_ns: 10416.67,
        tat_running: true,
        tat_remaining_ms: 750,
        radial_velocity_mps: 45.5,
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert_eq!(wire_bytes.len(), 28);

    let decoded = TimingAdvanceWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.numerology_mu, pdu.numerology_mu);
    assert_eq!(decoded.current_nta, pdu.current_nta);
    assert!((decoded.total_advance_ns - pdu.total_advance_ns).abs() < 1e-4);
    assert_eq!(decoded.tat_running, pdu.tat_running);
    assert_eq!(decoded.tat_remaining_ms, pdu.tat_remaining_ms);
    assert!((decoded.radial_velocity_mps - pdu.radial_velocity_mps).abs() < 1e-4);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = TimingAdvanceWirePdu {
        numerology_mu: 0,
        current_nta: 0,
        total_advance_ns: 0.0,
        tat_running: false,
        tat_remaining_ms: 0,
        radial_velocity_mps: 0.0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0x00;

    assert!(matches!(
        TimingAdvanceWirePdu::from_wire_bytes(&wire_bytes),
        Err(TimingAdvanceError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = TimingAdvanceWirePdu {
        numerology_mu: 2,
        current_nta: 1024,
        total_advance_ns: 520.8,
        tat_running: true,
        tat_remaining_ms: 1280,
        radial_velocity_mps: -12.0,
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    let len = wire_bytes.len();
    wire_bytes[len - 4] ^= 0x88; // Corrupt payload byte

    assert!(matches!(
        TimingAdvanceWirePdu::from_wire_bytes(&wire_bytes),
        Err(TimingAdvanceError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = TimingAdvanceWirePdu {
        numerology_mu: 1,
        current_nta: 512,
        total_advance_ns: 260.4,
        tat_running: true,
        tat_remaining_ms: 500,
        radial_velocity_mps: 0.0,
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..20];

    assert!(matches!(
        TimingAdvanceWirePdu::from_wire_bytes(truncated),
        Err(TimingAdvanceError::WirePayloadTooShort { .. })
    ));
}
