//! Comprehensive Integration Tests for 3GPP Rel-17 5G NR Cell Selection & Reselection Engine.

use std::collections::HashMap;
use toy_tcpip::nr_cell_reselection::*;

#[test]
fn test_nr_cell_selection_s_criterion_suitable_and_acceptable() {
    let home_plmn = PlmnIdentity::new("001", "01");
    let forbidden_tac = 999;
    let allowed_tac = 100;

    let engine = NrCellReselectionEngine::new(
        "ue-001",
        vec![home_plmn.clone()],
        vec![forbidden_tac],
        ServingCellConfig::default(),
    );

    let cell1 = NrCellIdentity::new(1001, 10, 630000);
    let sparams = SCriterionParams {
        q_rx_lev_min: -120,
        q_rx_lev_min_offset: 0,
        q_qual_min: -20,
        q_qual_min_offset: 0,
        p_emax: 23,
        ue_power_class: 23,
    };

    // 1. S-Criterion: RSRP = -100 dBm, RSRQ = -10 dB -> Satisfied
    let s_res = sparams.evaluate(-100, -10, 0);
    assert_eq!(s_res.s_rxlev, 20);
    assert_eq!(s_res.s_qual, 10);
    assert!(s_res.is_satisfied);

    // 2. Power compensation test: P_EMAX = 26 dBm, UE class = 23 dBm -> P_comp = 3 dB
    let high_power_params = SCriterionParams {
        p_emax: 26,
        ue_power_class: 23,
        ..sparams
    };
    let s_res_comp = high_power_params.evaluate(-118, -10, 0);
    // S_rxlev = -118 - (-120) - 3 = -1 <= 0 -> fails S-criterion!
    assert_eq!(s_res_comp.s_rxlev, -1);
    assert!(!s_res_comp.is_satisfied);

    // 3. Suitable Cell Check: home PLMN, allowed TAC, not barred -> Suitable
    let meas_good = CellMeasurement {
        cell: cell1,
        q_rx_lev_meas: -95,
        q_qual_meas: -10,
        q_offset_cell: 0,
    };
    let access_good = CellAccessInfo {
        plmn_list: vec![home_plmn.clone()],
        tac: allowed_tac,
        is_cell_barred: false,
        intra_freq_reselection_allowed: true,
        is_reserved_for_operator: false,
    };
    let suit_good = engine.check_cell_suitability(&cell1, &access_good, &sparams, &meas_good, 1000);
    assert_eq!(suit_good, CellSuitability::Suitable);

    // 4. Barred Cell Check -> Unsuitable(CellBarred)
    let access_barred = CellAccessInfo {
        is_cell_barred: true,
        ..access_good.clone()
    };
    let suit_barred =
        engine.check_cell_suitability(&cell1, &access_barred, &sparams, &meas_good, 1000);
    assert_eq!(
        suit_barred,
        CellSuitability::Unsuitable(UnsuitableReason::CellBarred)
    );

    // 5. Foreign PLMN -> Acceptable(PlmnNotAllowed) for Emergency Calls
    let access_foreign = CellAccessInfo {
        plmn_list: vec![PlmnIdentity::new("999", "99")],
        ..access_good.clone()
    };
    let suit_foreign =
        engine.check_cell_suitability(&cell1, &access_foreign, &sparams, &meas_good, 1000);
    assert_eq!(
        suit_foreign,
        CellSuitability::Acceptable(AcceptableReason::PlmnNotAllowed)
    );

    // 6. Forbidden TAC -> Acceptable(ForbiddenTrackingArea) for Emergency Calls
    let access_forbid_tac = CellAccessInfo {
        tac: forbidden_tac,
        ..access_good
    };
    let suit_tac =
        engine.check_cell_suitability(&cell1, &access_forbid_tac, &sparams, &meas_good, 1000);
    assert_eq!(
        suit_tac,
        CellSuitability::Acceptable(AcceptableReason::ForbiddenTrackingArea)
    );
}

#[test]
fn test_nr_cell_reselection_intra_freq_r_criterion() {
    let home_plmn = PlmnIdentity::new("001", "01");
    let mut engine = NrCellReselectionEngine::new(
        "ue-002",
        vec![home_plmn],
        vec![],
        ServingCellConfig {
            s_intra_search_p: 15,
            s_non_intra_search_p: 10,
            thresh_serving_low_p: 6,
            q_hyst: 4,
        },
    );

    let arfcn = 630000;
    engine.configure_frequency_layer(FrequencyLayerConfig {
        arfcn,
        priority: 5,
        thresh_x_high_p: 10,
        thresh_x_low_p: 8,
        t_reselection_s: 2,
        q_offset_freq: 0,
    });

    let serving_cell = NrCellIdentity::new(100, 1, arfcn);
    let neighbor_weak = NrCellIdentity::new(101, 2, arfcn);
    let neighbor_strong = NrCellIdentity::new(102, 3, arfcn);

    let sparams = SCriterionParams::default();
    let mut neighbor_sparams = HashMap::new();
    neighbor_sparams.insert(neighbor_weak.nci, sparams);
    neighbor_sparams.insert(neighbor_strong.nci, sparams);

    // Serving: RSRP = -108 dBm -> S_rxlev = 12 dB (<= s_intra_search_p of 15 dB -> triggers intra search!)
    // Serving R-rank: R_s = -108 + Q_hyst (4) = -104 dBm
    let serving_meas = CellMeasurement {
        cell: serving_cell,
        q_rx_lev_meas: -108,
        q_qual_meas: -12,
        q_offset_cell: 0,
    };

    // Neighbor weak: RSRP = -106 dBm -> R_n = -106 dBm < -104 dBm (not ranked better)
    let meas_weak = CellMeasurement {
        cell: neighbor_weak,
        q_rx_lev_meas: -106,
        q_qual_meas: -11,
        q_offset_cell: 0,
    };

    // Neighbor strong: RSRP = -98 dBm -> R_n = -98 dBm > -104 dBm (ranked better!)
    let meas_strong = CellMeasurement {
        cell: neighbor_strong,
        q_rx_lev_meas: -98,
        q_qual_meas: -10,
        q_offset_cell: 0,
    };

    let neighbors = vec![meas_weak, meas_strong];

    // t = 100: Condition detected, T_reselection (2s) timer begins
    let res_t0 =
        engine.evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 100);
    assert!(res_t0.is_none());

    // t = 101 (1s elapsed < 2s): timer still running
    let res_t1 =
        engine.evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 101);
    assert!(res_t1.is_none());

    // t = 102 (2s elapsed >= 2s): Reselection triggered!
    let decision = engine
        .evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 102)
        .expect("Should trigger reselection after T_reselection expiration");

    assert_eq!(decision.target_cell, neighbor_strong);
    assert_eq!(decision.cause, ReselectionCause::IntraFreqRanked);
    assert_eq!(decision.target_r_rank, Some(-98));
}

#[test]
fn test_nr_cell_reselection_high_priority_inter_freq() {
    let home_plmn = PlmnIdentity::new("001", "01");
    let mut engine = NrCellReselectionEngine::new(
        "ue-003",
        vec![home_plmn],
        vec![],
        ServingCellConfig::default(),
    );

    let serving_arfcn = 630000;
    let high_prio_arfcn = 640000;

    // Serving carrier priority 4
    engine.configure_frequency_layer(FrequencyLayerConfig {
        arfcn: serving_arfcn,
        priority: 4,
        thresh_x_high_p: 10,
        thresh_x_low_p: 8,
        t_reselection_s: 2,
        q_offset_freq: 0,
    });

    // High priority carrier priority 6 (> 4), Thresh_X,HighP = 12 dB, T_reselection = 2s
    engine.configure_frequency_layer(FrequencyLayerConfig {
        arfcn: high_prio_arfcn,
        priority: 6,
        thresh_x_high_p: 12,
        thresh_x_low_p: 8,
        t_reselection_s: 2,
        q_offset_freq: 0,
    });

    let serving_cell = NrCellIdentity::new(200, 10, serving_arfcn);
    let candidate_cell = NrCellIdentity::new(201, 20, high_prio_arfcn);

    let sparams = SCriterionParams::default();
    let mut neighbor_sparams = HashMap::new();
    neighbor_sparams.insert(candidate_cell.nci, sparams);

    // Serving cell is very strong (RSRP = -80 dBm -> S_rxlev = 40 dB)
    let serving_meas = CellMeasurement {
        cell: serving_cell,
        q_rx_lev_meas: -80,
        q_qual_meas: -8,
        q_offset_cell: 0,
    };

    // Candidate cell: RSRP = -102 dBm -> S_rxlev = 18 dB (> Thresh_X,HighP of 12 dB!)
    let cand_meas = CellMeasurement {
        cell: candidate_cell,
        q_rx_lev_meas: -102,
        q_qual_meas: -10,
        q_offset_cell: 0,
    };

    let neighbors = vec![cand_meas];

    // High priority reselection occurs regardless of serving cell quality!
    assert!(
        engine
            .evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 10)
            .is_none()
    );
    assert!(
        engine
            .evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 11)
            .is_none()
    );

    let decision = engine
        .evaluate_reselection(&serving_meas, &sparams, &neighbors, &neighbor_sparams, 12)
        .expect("High priority candidate should trigger reselection");

    assert_eq!(decision.target_cell, candidate_cell);
    assert_eq!(decision.cause, ReselectionCause::HighPriorityInterFreq);
    assert_eq!(decision.target_s_rxlev, 18);
}

#[test]
fn test_nr_cell_reselection_low_priority_inter_freq() {
    let home_plmn = PlmnIdentity::new("001", "01");
    let mut engine = NrCellReselectionEngine::new(
        "ue-004",
        vec![home_plmn],
        vec![],
        ServingCellConfig {
            thresh_serving_low_p: 8, // Serving S_rxlev must fall below 8 dB
            ..ServingCellConfig::default()
        },
    );

    let serving_arfcn = 640000;
    let low_prio_arfcn = 620000;

    // Serving layer priority 6
    engine.configure_frequency_layer(FrequencyLayerConfig {
        arfcn: serving_arfcn,
        priority: 6,
        thresh_x_high_p: 12,
        thresh_x_low_p: 8,
        t_reselection_s: 2,
        q_offset_freq: 0,
    });

    // Lower priority layer priority 3 (< 6), Thresh_X,LowP = 10 dB
    engine.configure_frequency_layer(FrequencyLayerConfig {
        arfcn: low_prio_arfcn,
        priority: 3,
        thresh_x_high_p: 14,
        thresh_x_low_p: 10,
        t_reselection_s: 2,
        q_offset_freq: 0,
    });

    let serving_cell = NrCellIdentity::new(300, 10, serving_arfcn);
    let candidate_cell = NrCellIdentity::new(301, 20, low_prio_arfcn);

    let sparams = SCriterionParams::default();
    let mut neighbor_sparams = HashMap::new();
    neighbor_sparams.insert(candidate_cell.nci, sparams);

    // Candidate cell on low-priority layer is very strong (S_rxlev = 30 dB > 10 dB)
    let cand_meas = CellMeasurement {
        cell: candidate_cell,
        q_rx_lev_meas: -90,
        q_qual_meas: -8,
        q_offset_cell: 0,
    };
    let neighbors = vec![cand_meas];

    // Case A: Serving cell is still adequate (S_rxlev = 15 dB > Thresh_Serving,LowP of 8 dB)
    // Reselection to lower priority MUST NOT happen!
    let serving_meas_ok = CellMeasurement {
        cell: serving_cell,
        q_rx_lev_meas: -105,
        q_qual_meas: -10,
        q_offset_cell: 0,
    };
    assert!(
        engine
            .evaluate_reselection(
                &serving_meas_ok,
                &sparams,
                &neighbors,
                &neighbor_sparams,
                10
            )
            .is_none()
    );
    assert!(
        engine
            .evaluate_reselection(
                &serving_meas_ok,
                &sparams,
                &neighbors,
                &neighbor_sparams,
                15
            )
            .is_none()
    );

    // Case B: Serving cell deteriorates below 8 dB (RSRP = -115 dBm -> S_rxlev = 5 dB < 8 dB)
    let serving_meas_poor = CellMeasurement {
        cell: serving_cell,
        q_rx_lev_meas: -115,
        q_qual_meas: -14,
        q_offset_cell: 0,
    };

    assert!(
        engine
            .evaluate_reselection(
                &serving_meas_poor,
                &sparams,
                &neighbors,
                &neighbor_sparams,
                20
            )
            .is_none()
    );
    assert!(
        engine
            .evaluate_reselection(
                &serving_meas_poor,
                &sparams,
                &neighbors,
                &neighbor_sparams,
                21
            )
            .is_none()
    );

    let decision = engine
        .evaluate_reselection(
            &serving_meas_poor,
            &sparams,
            &neighbors,
            &neighbor_sparams,
            22,
        )
        .expect("Should trigger lower priority reselection after serving degradation");

    assert_eq!(decision.target_cell, candidate_cell);
    assert_eq!(decision.cause, ReselectionCause::LowPriorityInterFreq);
}

#[test]
fn test_nr_cell_reselection_mobility_state_and_speed_scaling() {
    let home_plmn = PlmnIdentity::new("001", "01");
    let mut engine = NrCellReselectionEngine::new(
        "ue-005",
        vec![home_plmn],
        vec![],
        ServingCellConfig {
            q_hyst: 4,
            ..ServingCellConfig::default()
        },
    );

    // MSE config: window = 60s, Medium threshold = 4, High threshold = 8
    engine.mse_config = MseConfig {
        t_crmax_s: 60,
        n_cr_m: 4,
        n_cr_h: 8,
        q_hyst_scaling_medium_db: 2,
        q_hyst_scaling_high_db: 4,
        t_reselection_scaling_medium_percent: 75,
        t_reselection_scaling_high_percent: 50,
    };

    // 1. Initial state: Normal mobility
    assert_eq!(engine.mobility_state, MobilityState::Normal);
    assert_eq!(engine.effective_q_hyst(), 4);
    assert_eq!(engine.effective_t_reselection_s(4), 4);

    // 2. Perform 4 reselections within 30 seconds -> Medium mobility
    for i in 1..=4 {
        let cell = NrCellIdentity::new(i, i as u16, 630000);
        engine.record_reselection(cell, 10 + i * 5);
    }
    assert_eq!(engine.mobility_state, MobilityState::Medium);
    // Q_hyst scaled: 4 - 2 = 2 dB
    assert_eq!(engine.effective_q_hyst(), 2);
    // T_reselection scaled: 4 * 75% = 3s
    assert_eq!(engine.effective_t_reselection_s(4), 3);

    // 3. Perform 4 more reselections (total 8 in 60s window) -> High mobility
    for i in 5..=8 {
        let cell = NrCellIdentity::new(i, i as u16, 630000);
        engine.record_reselection(cell, 35 + (i - 4) * 4);
    }
    assert_eq!(engine.mobility_state, MobilityState::High);
    // Q_hyst scaled: 4 - 4 = 0 dB (rapid handover enabled)
    assert_eq!(engine.effective_q_hyst(), 0);
    // T_reselection scaled: 4 * 50% = 2s
    assert_eq!(engine.effective_t_reselection_s(4), 2);

    // 4. Barring and Blacklist validation
    let cell_to_bar = NrCellIdentity::new(999, 99, 630000);
    assert!(!engine.is_cell_barred(cell_to_bar.nci, 100));

    // Bar cell for 120s
    engine.bar_cell(cell_to_bar.nci, 120, 100);
    assert!(engine.is_cell_barred(cell_to_bar.nci, 150));
    // After 121s (t = 221), barring expires
    assert!(!engine.is_cell_barred(cell_to_bar.nci, 221));

    // Blacklist testing
    engine.blacklist_cell(cell_to_bar.nci);
    assert!(engine.blacklisted_cells.contains(&cell_to_bar.nci));
    engine.remove_blacklisted_cell(cell_to_bar.nci);
    assert!(!engine.blacklisted_cells.contains(&cell_to_bar.nci));
}
