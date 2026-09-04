//! Integration tests for 3GPP Rel-17 5G NR Unified TCI State & Multi-TRP Beam Management Engine
//!
//! Conforms to 3GPP TS 38.214, TS 38.213, TS 38.321, and TS 38.331.

use toy_tcpip::nr_unified_tci::{
    BeamSwitchState, MAX_TCI_STATES, MTrpTransmissionMode, QclInfo, QclType, ReferenceSignal,
    TciDirectionMode, TrpChannelCondition, TrpId, UnifiedTciEngine, UnifiedTciMacCe,
    UnifiedTciState,
};

#[test]
fn test_unified_tci_state_rrc_configuration() {
    // 1. Configure a Joint TCI state with QCL-TypeA (Doppler/Delay) and QCL-TypeD (Spatial Rx beam)
    let qcl_src_1 = QclInfo::new(
        ReferenceSignal::CsiRs {
            resource_id: 12,
            is_periodic: true,
        },
        QclType::TypeA,
        0, // Cell ID 0
        0, // BWP ID 0
    );

    let qcl_src_2 = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 4 }, QclType::TypeD, 0, 0);

    let tci_joint =
        UnifiedTciState::new(1, TciDirectionMode::Joint, qcl_src_1, Some(qcl_src_2), 0, 0)
            .expect("Valid joint TCI state should be created");

    assert_eq!(tci_joint.tci_state_id, 1);
    assert_eq!(tci_joint.direction_mode, TciDirectionMode::Joint);
    assert!(tci_joint.has_spatial_beam());
    assert_eq!(tci_joint.pci, None);

    // 2. Inter-cell Multi-TRP configuration with distinct Physical Cell ID (PCI)
    let tci_inter_cell = tci_joint.clone().with_pci(502);
    assert_eq!(tci_inter_cell.pci, Some(502));

    // 3. Separate UL TCI state with SRS reference signal
    let srs_src = QclInfo::new(
        ReferenceSignal::Srs { resource_id: 8 },
        QclType::TypeD,
        0,
        0,
    );
    let tci_ul = UnifiedTciState::new(2, TciDirectionMode::SeparateUl, srs_src, None, 0, 0)
        .expect("Valid separate UL TCI state");
    assert_eq!(tci_ul.direction_mode, TciDirectionMode::SeparateUl);
    assert!(tci_ul.has_spatial_beam());

    // 4. Validate rejection of invalid combinations (e.g. two TypeD sources per TS 38.214)
    let invalid_qcl_1 = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 1 }, QclType::TypeD, 0, 0);
    let invalid_qcl_2 = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 2 }, QclType::TypeD, 0, 0);
    let err_double_typed = UnifiedTciState::new(
        3,
        TciDirectionMode::Joint,
        invalid_qcl_1,
        Some(invalid_qcl_2),
        0,
        0,
    );
    assert!(err_double_typed.is_err());

    // 5. Validate rejection of out-of-range IDs
    let err_out_of_bounds = UnifiedTciState::new(
        MAX_TCI_STATES as u8,
        TciDirectionMode::Joint,
        qcl_src_1,
        None,
        0,
        0,
    );
    assert!(err_out_of_bounds.is_err());
}

#[test]
fn test_unified_tci_mac_ce_codec() {
    // 1. Test Single-TRP MAC CE serialization and deserialization
    let mac_ce_single = UnifiedTciMacCe::new(
        3,                       // Serving cell 3
        1,                       // BWP 1
        TciDirectionMode::Joint, // Joint mode
        14,                      // TRP 0 TCI ID
        None,                    // Single-TRP
        0b0000_0111,             // CC list bitmap (CC 0, 1, 2)
    )
    .expect("Valid single-TRP MAC CE");

    let wire_bytes_single = mac_ce_single.serialize();
    assert_eq!(wire_bytes_single.len(), 4);

    let parsed_single =
        UnifiedTciMacCe::parse(&wire_bytes_single).expect("Failed to parse single-TRP MAC CE");
    assert_eq!(parsed_single.serving_cell_id, 3);
    assert_eq!(parsed_single.bwp_id, 1);
    assert_eq!(parsed_single.direction_mode, TciDirectionMode::Joint);
    assert_eq!(parsed_single.tci_state_id_trp0, 14);
    assert_eq!(parsed_single.tci_state_id_trp1, None);
    assert_eq!(parsed_single.cc_list_bitmap, 0b0000_0111);

    // 2. Test Dual-TRP Multi-Beam MAC CE serialization and deserialization
    let mac_ce_dual = UnifiedTciMacCe::new(
        7,                            // Serving cell 7
        2,                            // BWP 2
        TciDirectionMode::SeparateDl, // Separate DL mode
        20,                           // TRP 0 TCI ID
        Some(35),                     // TRP 1 TCI ID
        0b1000_0001,                  // CC bitmap (CC 0 and CC 7)
    )
    .expect("Valid dual-TRP MAC CE");

    let wire_bytes_dual = mac_ce_dual.serialize();
    assert_eq!(wire_bytes_dual.len(), 5);

    let parsed_dual =
        UnifiedTciMacCe::parse(&wire_bytes_dual).expect("Failed to parse dual-TRP MAC CE");
    assert_eq!(parsed_dual.serving_cell_id, 7);
    assert_eq!(parsed_dual.bwp_id, 2);
    assert_eq!(parsed_dual.direction_mode, TciDirectionMode::SeparateDl);
    assert_eq!(parsed_dual.tci_state_id_trp0, 20);
    assert_eq!(parsed_dual.tci_state_id_trp1, Some(35));
    assert_eq!(parsed_dual.cc_list_bitmap, 0b1000_0001);

    // 3. Test defensive boundary checks on truncated payload
    let malformed_bytes = vec![0x10, 0x20, 0x30]; // 3 bytes (too short)
    let parse_err = UnifiedTciMacCe::parse(&malformed_bytes);
    assert!(parse_err.is_err());
}

#[test]
fn test_dci_beam_indication_and_bat_timing() {
    // Numerology: 30 kHz SCS -> 20 slots per frame.
    // Beam Application Time (k_BAT) = 4 slots.
    // BFI threshold = 3.
    let mut engine = UnifiedTciEngine::new(4, 20, 3);

    // Configure RRC TCI states 10, 11, 20, 21
    let qcl_a = QclInfo::new(
        ReferenceSignal::CsiRs {
            resource_id: 1,
            is_periodic: true,
        },
        QclType::TypeA,
        0,
        0,
    );
    let qcl_d = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 2 }, QclType::TypeD, 0, 0);

    for id in [10, 11, 20, 21] {
        let state =
            UnifiedTciState::new(id, TciDirectionMode::Joint, qcl_a, Some(qcl_d), 0, 0).unwrap();
        engine.configure_tci_state(state).unwrap();
    }

    // Activate initial beams via MAC CE: TRP0 = 10, TRP1 = 20
    let mac_ce = UnifiedTciMacCe::new(0, 0, TciDirectionMode::Joint, 10, Some(20), 0x01).unwrap();
    engine.apply_mac_ce(&mac_ce).unwrap();

    let initial_beams = engine.active_beams();
    assert_eq!(initial_beams.trp0_tci, Some(10));
    assert_eq!(initial_beams.trp1_tci, Some(20));

    // Map dynamic DCI codepoint 1 to target beams: TRP0 = 11, TRP1 = 21
    engine.set_dci_codepoint_mapping(1, 11, Some(21)).unwrap();

    // Trigger DCI beam switch indication at current slot (slot 0)
    engine.receive_dci_beam_indication(1).unwrap();

    // Verify switch is pending with remaining_slots = 4
    match engine.beam_switch_state() {
        BeamSwitchState::Pending {
            target_trp0,
            target_trp1,
            remaining_slots,
            ..
        } => {
            assert_eq!(target_trp0, 11);
            assert_eq!(target_trp1, Some(21));
            assert_eq!(remaining_slots, 4);
        }
        _ => panic!("Expected Pending beam switch state"),
    }

    // Advance 3 slots: beam switch should STILL be pending, old beams active
    for _ in 0..3 {
        let switch_result = engine.advance_slot();
        assert_eq!(switch_result, None);
        assert_eq!(engine.active_beams().trp0_tci, Some(10));
        assert_eq!(engine.active_beams().trp1_tci, Some(20));
    }

    // 4th slot advance: k_BAT expires! New beam set takes effect
    let completed = engine
        .advance_slot()
        .expect("Beam switch must complete at k_BAT");
    assert_eq!(completed.trp0_tci, Some(11));
    assert_eq!(completed.trp1_tci, Some(21));
    assert_eq!(engine.active_beams().trp0_tci, Some(11));
    assert_eq!(engine.active_beams().trp1_tci, Some(21));
    assert_eq!(engine.beam_switch_state(), BeamSwitchState::Steady);
}

#[test]
fn test_multi_trp_multiplexing_and_diversity_gain() {
    let mut engine = UnifiedTciEngine::new(2, 20, 3);

    // Setup active beams for both TRPs
    let qcl = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 0 }, QclType::TypeD, 0, 0);
    engine
        .configure_tci_state(
            UnifiedTciState::new(1, TciDirectionMode::Joint, qcl, None, 0, 0).unwrap(),
        )
        .unwrap();
    engine
        .configure_tci_state(
            UnifiedTciState::new(2, TciDirectionMode::Joint, qcl, None, 0, 0).unwrap(),
        )
        .unwrap();

    let mac_ce = UnifiedTciMacCe::new(0, 0, TciDirectionMode::Joint, 1, Some(2), 0x01).unwrap();
    engine.apply_mac_ce(&mac_ce).unwrap();

    // Set channel conditions: TRP0 has 10 dB SINR, TRP1 has 13 dB SINR
    engine.trp0_channel = TrpChannelCondition {
        rsrp_dbm: -88.0,
        sinr_db: 10.0,
        path_loss_db: 75.0,
    };
    engine.trp1_channel = TrpChannelCondition {
        rsrp_dbm: -85.0,
        sinr_db: 13.0,
        path_loss_db: 72.0,
    };

    let bw_mhz = 100.0; // 100 MHz channel bandwidth

    // 1. SFN Mode (Coherent/power combining macro-diversity)
    let (sfn_sinr, sfn_cap) =
        engine.compute_link_metrics(bw_mhz, MTrpTransmissionMode::SingleFrequencyNetwork);
    // Combined linear power = 10^(1.0) + 10^(1.3) = 10 + 19.95 = 29.95 -> ~14.76 dB
    assert!(
        sfn_sinr > 13.0,
        "SFN combined SINR ({:.2} dB) must exceed individual TRP SINR (13.0 dB)",
        sfn_sinr
    );
    assert!(sfn_cap > 400.0);

    // 2. SDM Mode (Spatial Division Multiplexing - independent MIMO layers)
    let (_, sdm_cap) =
        engine.compute_link_metrics(bw_mhz, MTrpTransmissionMode::SpaceDivisionMultiplexing);
    // SDM achieves spatial layer multiplexing sum rate
    assert!(
        sdm_cap > sfn_cap,
        "SDM sum capacity ({:.2} Mbps) should exceed single-layer SFN capacity ({:.2} Mbps) at good SINRs",
        sdm_cap,
        sfn_cap
    );

    // 3. FDM Mode (50% PRB split)
    let (_, fdm_cap) =
        engine.compute_link_metrics(bw_mhz, MTrpTransmissionMode::FrequencyDivisionMultiplexing);
    assert!(fdm_cap > 0.0 && fdm_cap < sdm_cap);

    // 4. TDM Mode (50% time split)
    let (_, tdm_cap) =
        engine.compute_link_metrics(bw_mhz, MTrpTransmissionMode::TimeDivisionMultiplexing);
    assert_eq!((fdm_cap * 100.0).round(), (tdm_cap * 100.0).round());
}

#[test]
fn test_multi_trp_per_trp_beam_failure_and_fallback() {
    let mut engine = UnifiedTciEngine::new(2, 20, 3); // BFI threshold = 3

    let qcl = QclInfo::new(ReferenceSignal::Ssb { ssb_index: 0 }, QclType::TypeD, 0, 0);
    engine
        .configure_tci_state(
            UnifiedTciState::new(1, TciDirectionMode::Joint, qcl, None, 0, 0).unwrap(),
        )
        .unwrap();
    engine
        .configure_tci_state(
            UnifiedTciState::new(2, TciDirectionMode::Joint, qcl, None, 0, 0).unwrap(),
        )
        .unwrap();
    engine
        .configure_tci_state(
            UnifiedTciState::new(5, TciDirectionMode::Joint, qcl, None, 0, 0).unwrap(),
        )
        .unwrap();

    let mac_ce = UnifiedTciMacCe::new(0, 0, TciDirectionMode::Joint, 1, Some(2), 0x01).unwrap();
    engine.apply_mac_ce(&mac_ce).unwrap();

    engine.trp0_channel.sinr_db = 12.0;
    engine.trp1_channel.sinr_db = 14.0;

    assert!(!engine.in_single_trp_fallback);

    // Record 2 BFIs on TRP 1 (threshold is 3)
    assert!(!engine.record_beam_failure_instance(TrpId::Trp1));
    assert!(!engine.record_beam_failure_instance(TrpId::Trp1));
    assert_eq!(engine.trp1_bfd.bfi_count, 2);
    assert!(!engine.trp1_bfd.is_failed);
    assert!(!engine.in_single_trp_fallback);

    // 3rd BFI on TRP 1 triggers beam failure!
    let newly_failed = engine.record_beam_failure_instance(TrpId::Trp1);
    assert!(newly_failed);
    assert!(engine.trp1_bfd.is_failed);
    assert!(
        engine.in_single_trp_fallback,
        "Engine must enter autonomous single-TRP fallback"
    );

    // Verify throughput in fallback mode: relies purely on TRP 0 (SINR = 12 dB)
    let (fb_sinr, fb_cap) =
        engine.compute_link_metrics(100.0, MTrpTransmissionMode::SingleFrequencyNetwork);
    assert_eq!(fb_sinr, 12.0);
    assert!(fb_cap > 0.0);

    // Recover TRP 1 using candidate beam TCI 5
    engine
        .recover_trp_beam(TrpId::Trp1, 5)
        .expect("Recovery with valid candidate beam should succeed");

    assert!(!engine.trp1_bfd.is_failed);
    assert_eq!(engine.trp1_bfd.bfi_count, 0);
    assert_eq!(engine.active_beams().trp1_tci, Some(5));
    assert!(
        !engine.in_single_trp_fallback,
        "Engine must exit single-TRP fallback once beam is recovered"
    );
}
