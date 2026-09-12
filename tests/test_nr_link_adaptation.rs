//! Integration tests for 3GPP Rel-18/19 5G-Advanced CSI Calculation, RI/PMI/CQI Selection & Outer-Loop Link Adaptation (OLLA) Engine.
//! Validates:
//! - 3GPP CQI Tables 1, 2, and Rel-18 Table 3 (1024QAM) efficiencies, code rates, and thresholds.
//! - Effective Exponential SNR Mapping (EESM) over flat and frequency-selective fading channels.
//! - Rank Indicator (RI) selection under rank-1 (LOS) and rank-2 (rich scattering) MIMO channels.
//! - Type I dual-polarized single-panel codebook beam and co-phasing PMI selection.
//! - Wideband and Subband differential CQI generation (offsets -1, 0, +1, +2).
//! - Outer-Loop Link Adaptation (OLLA) closed-loop dynamic SINR convergence to 10% target BLER.
//! - Binary wire framing (`CsiReportWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_link_adaptation::{
    AntennaPanelGeometry, CQI_TABLE_1, CQI_TABLE_2, CQI_TABLE_3, CqiTableType, CsiReportWirePdu,
    DEFAULT_OLLA_STEP_UP_DB, DEFAULT_TARGET_BLER, LinkAdaptationError, NrModulation,
    OllaController, PmiSelection, compute_eesm_effective_sinr, generate_csi_report, select_cqi,
    select_rank_indicator, select_type1_pmi_rank1,
};

// ---------------------------------------------------------------------------
// 1. Standard 3GPP CQI Table Tests
// ---------------------------------------------------------------------------

#[test]
fn test_cqi_tables_monotonicity_and_properties() {
    let tables = [
        CqiTableType::Table1_64Qam,
        CqiTableType::Table2_256Qam,
        CqiTableType::Table3_1024Qam,
    ];

    for t in tables {
        let entries = t.entries();
        assert_eq!(entries.len(), 15);

        for i in 0..14 {
            let curr = &entries[i];
            let next = &entries[i + 1];

            // CQI index must be 1..15
            assert_eq!(curr.cqi_index as usize, i + 1);
            assert_eq!(next.cqi_index as usize, i + 2);

            // Efficiency and SNR thresholds must be strictly monotonically increasing
            assert!(
                next.efficiency > curr.efficiency,
                "Efficiency not increasing at CQI {} in table {:?}",
                curr.cqi_index,
                t
            );
            assert!(
                next.snr_threshold_db > curr.snr_threshold_db,
                "SNR threshold not increasing at CQI {} in table {:?}",
                curr.cqi_index,
                t
            );
        }
    }

    // Check maximum modulations
    assert_eq!(CQI_TABLE_1[14].modulation, NrModulation::Qam64);
    assert_eq!(CQI_TABLE_2[14].modulation, NrModulation::Qam256);
    assert_eq!(CQI_TABLE_3[14].modulation, NrModulation::Qam1024);

    // Check modulation bits per symbol
    assert_eq!(NrModulation::Qpsk.bits_per_symbol(), 2);
    assert_eq!(NrModulation::Qam16.bits_per_symbol(), 4);
    assert_eq!(NrModulation::Qam64.bits_per_symbol(), 6);
    assert_eq!(NrModulation::Qam256.bits_per_symbol(), 8);
    assert_eq!(NrModulation::Qam1024.bits_per_symbol(), 10);
}

#[test]
fn test_select_cqi_mapping() {
    // Extreme low SNR: below CQI 1 threshold (-6.7 dB)
    assert_eq!(select_cqi(-10.0, CqiTableType::Table1_64Qam), 0);

    // Exactly at CQI 1 threshold
    assert_eq!(select_cqi(-6.7, CqiTableType::Table1_64Qam), 1);

    // Between CQI 4 and CQI 5 (0.2 dB <= SNR < 2.4 dB)
    assert_eq!(select_cqi(1.0, CqiTableType::Table1_64Qam), 4);

    // Very high SNR: beyond CQI 15 (22.7 dB)
    assert_eq!(select_cqi(30.0, CqiTableType::Table1_64Qam), 15);

    // Rel-18 1024QAM table checks
    assert_eq!(select_cqi(33.0, CqiTableType::Table3_1024Qam), 12); // 1024QAM entry
    assert_eq!(select_cqi(40.0, CqiTableType::Table3_1024Qam), 15);
}

// ---------------------------------------------------------------------------
// 2. Effective Exponential SNR Mapping (EESM) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_eesm_effective_sinr_flat_channel() {
    let sinrs = [10.0, 10.0, 10.0, 10.0];
    let eff = compute_eesm_effective_sinr(&sinrs, 4.0).unwrap();
    // On a perfectly flat channel, EESM effective SINR equals the subcarrier SINR
    assert!((eff - 10.0).abs() < 1e-3);
}

#[test]
fn test_eesm_effective_sinr_frequency_selective_channel() {
    // 3 good subbands at +15 dB, 1 subband in deep fade at -5 dB
    let sinrs = [15.0, 15.0, 15.0, -5.0];
    let eff = compute_eesm_effective_sinr(&sinrs, 4.0).unwrap();

    let arith_mean = (15.0 * 3.0 - 5.0) / 4.0; // 10.0 dB
    // Because deep fades dominate the error probability, EESM gives a lower effective SINR than arithmetic mean
    assert!(
        eff < arith_mean,
        "EESM effective SINR ({}) must be less than arithmetic mean ({})",
        eff,
        arith_mean
    );
    assert!(eff > -5.0);
}

#[test]
fn test_eesm_empty_input_error() {
    let empty: [f32; 0] = [];
    assert_eq!(
        compute_eesm_effective_sinr(&empty, 4.0),
        Err(LinkAdaptationError::EmptySinrList)
    );
}

// ---------------------------------------------------------------------------
// 3. Rank Indicator (RI) Selection Tests
// ---------------------------------------------------------------------------

#[test]
fn test_rank_indicator_selection_los_and_rich_scattering() {
    // Case 1: Line-of-sight / rank-1 channel (first eigenvalue is huge, second is near zero)
    let los_eigenvalues = [20.0, 0.001];
    let rank_los = select_rank_indicator(&los_eigenvalues, 2, 15.0).unwrap();
    assert_eq!(
        rank_los, 1,
        "Rank 1 must be selected for ill-conditioned/LOS channel"
    );

    // Case 2: Rich scattering MIMO channel (both eigenvalues strong and balanced) at high SNR
    let scattering_eigenvalues = [10.0, 8.5];
    let rank_scat = select_rank_indicator(&scattering_eigenvalues, 2, 20.0).unwrap();
    assert_eq!(
        rank_scat, 2,
        "Rank 2 must be selected for rich scattering channel at high SNR"
    );

    // Case 3: Same channel at very low SNR (-5 dB) -> falls back to Rank 1 for robustness
    let rank_low_snr = select_rank_indicator(&scattering_eigenvalues, 2, -5.0).unwrap();
    assert_eq!(rank_low_snr, 1, "Rank 1 must be selected under low SNR");
}

// ---------------------------------------------------------------------------
// 4. Type I Single-Panel PMI Selection Tests
// ---------------------------------------------------------------------------

#[test]
fn test_type1_single_panel_pmi_selection() {
    let panel = AntennaPanelGeometry {
        n1: 2,
        n2: 1,
        o1: 4,
        o2: 4,
    };
    assert_eq!(panel.num_tx_ports(), 4);

    // Synthesize a channel matched to beam l = 2, m = 0, with co-phasing n = 1 (phi = j = (0, 1))
    // Beam l=2, m=0: x1=0 -> phase 0; x1=1 -> phase 2*pi*(1*2)/(2*4) = pi/2
    // v[0] = (1, 0), v[1] = (0, 1)
    // pol 1: [v0, v1] = [(1, 0), (0, 1)]
    // pol 2: phi * [v0, v1] = [(0, 1), (-1, 0)]
    // Full precoder W = [(1, 0), (0, 1), (0, 1), (-1, 0)]
    // Conjugate matched channel H = W^H = [(1, 0), (0, -1), (0, -1), (-1, 0)]
    let matched_h_row = vec![(1.0, 0.0), (0.0, -1.0), (0.0, -1.0), (-1.0, 0.0)];
    let channel_taps = vec![vec![matched_h_row]]; // 1 subband, 1 Rx antenna, 4 Tx ports

    let pmi = select_type1_pmi_rank1(&channel_taps, panel).unwrap();
    assert_eq!(pmi.beam_l, 2);
    assert_eq!(pmi.beam_m, 0);
    assert_eq!(pmi.cophase_n, 1);
}

// ---------------------------------------------------------------------------
// 5. Wideband & Subband Differential CQI Reporting Tests
// ---------------------------------------------------------------------------

#[test]
fn test_csi_report_generation() {
    let subband_sinrs = [8.5, 9.0, 14.5, 5.0]; // Subbands with varying channel quality
    let pmi = PmiSelection {
        beam_l: 1,
        beam_m: 0,
        cophase_n: 2,
    };

    let report = generate_csi_report(&subband_sinrs, 1, pmi, CqiTableType::Table1_64Qam).unwrap();

    assert_eq!(report.rank_indicator, 1);
    assert_eq!(report.pmi, pmi);
    assert!(report.wideband_cqi >= 7 && report.wideband_cqi <= 9);
    assert_eq!(report.subband_differential_cqis.len(), 4);

    // Subband 2 (14.5 dB) should have positive differential offset relative to wideband
    assert!(report.subband_differential_cqis[2] >= 0);
    // Subband 3 (5.0 dB) should have non-positive differential offset
    assert!(report.subband_differential_cqis[3] <= 0);

    // Differential values must be within 3GPP bounds [-1, 2]
    for &diff in &report.subband_differential_cqis {
        assert!(diff >= -1 && diff <= 2);
    }
}

// ---------------------------------------------------------------------------
// 6. Outer-Loop Link Adaptation (OLLA) Controller Tests
// ---------------------------------------------------------------------------

#[test]
fn test_olla_controller_convergence_to_target_bler() {
    let mut olla = OllaController::new(DEFAULT_TARGET_BLER, DEFAULT_OLLA_STEP_UP_DB);

    // Step up = 0.1 dB
    assert_eq!(olla.step_up_db, 0.1);
    // Step down = 0.1 * (1 - 0.1) / 0.1 = 0.9 dB
    assert!((olla.step_down_db - 0.9).abs() < 1e-4);

    // Feed equilibrium sequence: 9 ACKs and 1 NACK (exactly 10% BLER)
    for _ in 0..10 {
        for _ in 0..9 {
            olla.on_harq_feedback(true); // +0.1 dB * 9 = +0.9 dB
        }
        olla.on_harq_feedback(false); // -0.9 dB
    }

    // Offset should be exactly 0.0 dB at equilibrium!
    assert!((olla.offset_db - 0.0).abs() < 1e-3);
    assert_eq!(olla.ack_count, 90);
    assert_eq!(olla.nack_count, 10);
    assert!((olla.empirical_bler() - 0.10).abs() < 1e-4);

    // Burst of NACKs: offset should decrease down to min clamp (-8.0 dB)
    for _ in 0..20 {
        olla.on_harq_feedback(false);
    }
    assert_eq!(olla.offset_db, -8.0);

    // Burst of ACKs: offset should recover and increase up to max clamp (+8.0 dB)
    for _ in 0..200 {
        olla.on_harq_feedback(true);
    }
    assert_eq!(olla.offset_db, 8.0);

    // Test apply_offset
    assert_eq!(olla.apply_offset(10.0), 18.0);

    // Reset
    olla.reset();
    assert_eq!(olla.offset_db, 0.0);
    assert_eq!(olla.ack_count, 0);
    assert_eq!(olla.nack_count, 0);
}

// ---------------------------------------------------------------------------
// 7. Binary Wire Framing (CsiReportWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = CsiReportWirePdu {
        rank_indicator: 2,
        pmi_l: 3,
        pmi_m: 1,
        pmi_n: 2,
        wideband_cqi: 11,
        olla_offset_db: -1.2,
        subband_diff_cqis: vec![0, 1, -1, 2, 0, 1],
    };

    let wire_bytes = pdu.to_wire_bytes();
    assert!(wire_bytes.len() >= 17);

    let decoded = CsiReportWirePdu::from_wire_bytes(&wire_bytes).unwrap();
    assert_eq!(decoded.rank_indicator, pdu.rank_indicator);
    assert_eq!(decoded.pmi_l, pdu.pmi_l);
    assert_eq!(decoded.pmi_m, pdu.pmi_m);
    assert_eq!(decoded.pmi_n, pdu.pmi_n);
    assert_eq!(decoded.wideband_cqi, pdu.wideband_cqi);
    assert!((decoded.olla_offset_db - pdu.olla_offset_db).abs() < 1e-4);
    assert_eq!(decoded.subband_diff_cqis, pdu.subband_diff_cqis);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = CsiReportWirePdu {
        rank_indicator: 1,
        pmi_l: 0,
        pmi_m: 0,
        pmi_n: 0,
        wideband_cqi: 8,
        olla_offset_db: 0.5,
        subband_diff_cqis: vec![0, 0],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    wire_bytes[0] = 0x00;

    assert!(matches!(
        CsiReportWirePdu::from_wire_bytes(&wire_bytes),
        Err(LinkAdaptationError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = CsiReportWirePdu {
        rank_indicator: 1,
        pmi_l: 2,
        pmi_m: 0,
        pmi_n: 1,
        wideband_cqi: 9,
        olla_offset_db: 0.0,
        subband_diff_cqis: vec![1, 0, -1],
    };

    let mut wire_bytes = pdu.to_wire_bytes();
    let len = wire_bytes.len();
    wire_bytes[len - 3] ^= 0xFF; // Corrupt payload byte

    assert!(matches!(
        CsiReportWirePdu::from_wire_bytes(&wire_bytes),
        Err(LinkAdaptationError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = CsiReportWirePdu {
        rank_indicator: 1,
        pmi_l: 0,
        pmi_m: 0,
        pmi_n: 0,
        wideband_cqi: 6,
        olla_offset_db: 0.0,
        subband_diff_cqis: vec![0],
    };

    let wire_bytes = pdu.to_wire_bytes();
    let truncated = &wire_bytes[..10];

    assert!(matches!(
        CsiReportWirePdu::from_wire_bytes(truncated),
        Err(LinkAdaptationError::WirePayloadTooShort { .. })
    ));
}
