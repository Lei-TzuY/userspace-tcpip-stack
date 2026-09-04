//! Integration tests for 3GPP Rel-18 Network Controlled Repeater (NCR) Protocol Engine.

use toy_tcpip::nr_ncr_engine::*;

fn create_test_profile() -> NcrHardwareProfile {
    NcrHardwareProfile::new(
        30.0,    // Max TX power: +30 dBm (1 Watt)
        40.0,    // Max RF gain: 40 dB
        5.0,     // Noise figure: 5 dB
        100.0e6, // Bandwidth: 100 MHz
        15.0,    // Tg1 (DL to UL guard): 15 µs
        15.0,    // Tg2 (UL to DL guard): 15 µs
    )
}

#[test]
fn test_sci_configuration_and_beam_steering() {
    let profile = create_test_profile();
    let mut engine = NcrForwardingEngine::new(profile);

    assert_eq!(engine.state(), NcrState::Idle);

    let mut sym_dirs = [AmplifyDirection::Downlink; SYMBOLS_PER_SLOT];
    sym_dirs[12] = AmplifyDirection::Guard;
    sym_dirs[13] = AmplifyDirection::Uplink;

    let sci = SideControlInformation::new(
        0, sym_dirs, 12,   // C-link beam 12
        34,   // A-link beam 34
        30.0, // Gain 30 dB
        0.0,  // No backoff
    )
    .expect("Valid SCI should construct");

    engine.apply_sci(sci).expect("Applying SCI should succeed");
    assert_eq!(engine.state(), NcrState::Synced);
    assert_eq!(engine.metrics().beam_switches_count, 1);

    // Update with new A-link beam 50 -> Beam switch counter increments
    let sci2 = SideControlInformation::new(1, sym_dirs, 12, 50, 30.0, 0.0).unwrap();
    engine.apply_sci(sci2).unwrap();
    assert_eq!(engine.metrics().beam_switches_count, 2);

    // Invalid beam ID > 63
    let err_beam = SideControlInformation::new(2, sym_dirs, 70, 34, 30.0, 0.0);
    assert_eq!(
        err_beam,
        Err(NcrError::InvalidBeamId {
            beam_id: 70,
            max: 63
        })
    );

    // Invalid gain exceeding hardware capability (> 40 dB)
    let err_gain_sci = SideControlInformation::new(3, sym_dirs, 12, 34, 45.0, 0.0).unwrap();
    assert_eq!(
        engine.apply_sci(err_gain_sci),
        Err(NcrError::InvalidGain {
            requested_db: 45.0,
            max_db: 40.0
        })
    );
}

#[test]
fn test_amplify_and_forward_linear_and_saturated() {
    let profile = create_test_profile();
    let mut engine = NcrForwardingEngine::new(profile);

    let sym_dirs = [AmplifyDirection::Downlink; SYMBOLS_PER_SLOT];
    let sci = SideControlInformation::new(0, sym_dirs, 5, 10, 30.0, 0.0).unwrap();
    engine.apply_sci(sci).unwrap();

    // 1. Linear amplification: input -15 dBm + 30 dB gain = +15 dBm (< 30 dBm sat)
    let out_linear = engine.process_symbol(0, -15.0).unwrap();
    assert_eq!(out_linear.state, NcrState::ActiveAmplifyDl);
    assert!((out_linear.output_power_dbm - 15.0).abs() < 1e-4);
    assert!(!out_linear.is_saturated);
    assert!(!out_linear.is_power_gated);
    assert_eq!(out_linear.active_c_beam, 5);
    assert_eq!(out_linear.active_a_beam, 10);

    // 2. Power saturation: input +5 dBm + 30 dB gain = +35 dBm -> clipped to +30 dBm
    let out_sat = engine.process_symbol(1, 5.0).unwrap();
    assert_eq!(out_sat.state, NcrState::ActiveAmplifyDl);
    assert!((out_sat.output_power_dbm - 30.0).abs() < 1e-4);
    assert!(out_sat.is_saturated);
    assert_eq!(engine.metrics().total_saturated_symbols, 1);
}

#[test]
fn test_dl_ul_switching_guard_period_enforcement() {
    let profile = create_test_profile();
    let mut engine = NcrForwardingEngine::new(profile);

    // Illegal switch: Symbol 0 is DL, Symbol 1 is UL without guard
    let mut illegal_dirs = [AmplifyDirection::Downlink; SYMBOLS_PER_SLOT];
    illegal_dirs[1] = AmplifyDirection::Uplink;

    let sci_illegal = SideControlInformation::new(0, illegal_dirs, 1, 1, 20.0, 0.0).unwrap();
    engine.apply_sci(sci_illegal).unwrap();

    // Process symbol 0 (DL) -> succeeds
    assert!(engine.process_symbol(0, -20.0).is_ok());

    // Process symbol 1 (UL directly after DL) -> GuardTimeViolation
    let res = engine.process_symbol(1, -20.0);
    assert_eq!(
        res,
        Err(NcrError::GuardTimeViolation {
            symbol_idx: 1,
            elapsed_us: 0.0,
            required_us: 15.0,
        })
    );

    // Legal switch: Symbol 0 DL, Symbol 1 Guard, Symbol 2 UL
    let mut legal_engine = NcrForwardingEngine::new(create_test_profile());
    let mut legal_dirs = [AmplifyDirection::Downlink; SYMBOLS_PER_SLOT];
    legal_dirs[1] = AmplifyDirection::Guard;
    legal_dirs[2] = AmplifyDirection::Uplink;

    let sci_legal = SideControlInformation::new(0, legal_dirs, 1, 1, 20.0, 0.0).unwrap();
    legal_engine.apply_sci(sci_legal).unwrap();

    let out0 = legal_engine.process_symbol(0, -20.0).unwrap();
    assert_eq!(out0.state, NcrState::ActiveAmplifyDl);

    let out1 = legal_engine.process_symbol(1, -20.0).unwrap();
    assert_eq!(out1.state, NcrState::GuardSwitching);
    assert!(out1.is_power_gated);

    let out2 = legal_engine.process_symbol(2, -20.0).unwrap();
    assert_eq!(out2.state, NcrState::ActiveAmplifyUl);
}

#[test]
fn test_energy_saving_power_gating() {
    let profile = create_test_profile();
    let mut engine = NcrForwardingEngine::new(profile);

    // Pattern: 6 DL, 4 Muted (power gated), 4 UL (total 14 symbols)
    let mut dirs = [AmplifyDirection::Downlink; SYMBOLS_PER_SLOT];
    for s in 6..10 {
        dirs[s] = AmplifyDirection::Muted;
    }
    for s in 10..14 {
        dirs[s] = AmplifyDirection::Uplink;
    }

    let sci = SideControlInformation::new(0, dirs, 1, 1, 25.0, 0.0).unwrap();
    engine.apply_sci(sci).unwrap();

    // Process all 14 symbols
    for s in 0..14 {
        let out = engine.process_symbol(s, -30.0).unwrap();
        if (6..10).contains(&s) {
            assert_eq!(out.state, NcrState::PowerGated);
            assert!(out.is_power_gated);
            assert_eq!(out.output_power_dbm, -120.0);
        }
    }

    let m = engine.metrics();
    assert_eq!(m.total_dl_symbols_amplified, 6);
    assert_eq!(m.total_muted_symbols, 4);
    assert_eq!(m.total_ul_symbols_amplified, 4);

    // Energy savings percentage: 4 / 14 * 100 ≈ 28.5714%
    assert!((m.energy_savings_percentage - 28.5714).abs() < 0.01);
}

#[test]
fn test_noise_amplification_and_snr_degradation() {
    let profile = create_test_profile();
    let engine = NcrForwardingEngine::new(profile);

    // Bandwidth 100 MHz -> 10 * log10(1e8) = 80 dB
    // Output noise floor with 30 dB gain:
    // N_out = -174 + 80 + 30 + 5 (NF) = -59 dBm
    let noise = engine.output_noise_floor_dbm(30.0);
    assert!((noise - (-59.0)).abs() < 1e-4);
}

#[test]
fn test_error_formatting_and_display() {
    let err_gain = NcrError::InvalidGain {
        requested_db: 45.0,
        max_db: 40.0,
    };
    assert!(
        err_gain
            .to_string()
            .contains("Requested RF gain 45.0 dB exceeds maximum capability 40.0 dB")
    );

    let err_beam = NcrError::InvalidBeamId {
        beam_id: 65,
        max: 63,
    };
    assert!(
        err_beam
            .to_string()
            .contains("Beam ID 65 exceeds maximum allowable 63")
    );

    let err_guard = NcrError::GuardTimeViolation {
        symbol_idx: 4,
        elapsed_us: 5.0,
        required_us: 15.0,
    };
    assert!(
        err_guard
            .to_string()
            .contains("without satisfying guard time")
    );

    let err_sci = NcrError::NoSciScheduledForSlot(3);
    assert!(
        err_sci
            .to_string()
            .contains("No Side Control Information (SCI) scheduled for slot 3")
    );

    let err_sym = NcrError::InvalidSymbolIndex(15);
    assert!(err_sym.to_string().contains("Invalid symbol index 15"));
}
