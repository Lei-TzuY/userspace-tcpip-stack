//! Integration tests for 3GPP Release 18 Sidelink Dynamic HARQ Feedback & Groupcast Adaptation Engine.

use toy_tcpip::nr_sidelink_harq::{
    DistanceBasedFeedbackEvaluator, DynamicGroupcastAdapter, DynamicGroupcastConfig,
    NR_HARQ_RV_SEQUENCE, PsfchFeedbackReport, PsfchFormat0Resource, PsfchPowerConfig,
    PsfchPowerController, PsfchResourceConfig, PsfchResourceMapper, PsfchTxCandidate,
    SidelinkHarqCodebookGenerator, SidelinkHarqEngine, SlHarqError, SlHarqFeedbackScheme,
    SlHarqProcess, SlHarqState, SlZoneId,
};

#[test]
fn test_psfch_resource_mapping_and_cyclic_shifts() {
    let config = PsfchResourceConfig::new(2, 2, 10, 50, 5)
        .expect("Config creation should succeed");
    let mapper = PsfchResourceMapper::new(config);

    // Transmission at slot 1, min delay 2 -> earliest slot 3 -> next multiple of 2 is slot 4
    let psfch_slot = mapper.map_pssch_to_psfch_slot(1);
    assert_eq!(psfch_slot, 4);

    // Transmission at slot 2 -> earliest slot 4 -> slot 4
    assert_eq!(mapper.map_pssch_to_psfch_slot(2), 4);

    // Option 1 mapping: Subchannel 2 -> PRB 10 + 2 = 12, CS = 0 for NACK
    let res_opt1 = mapper
        .map_resource(1, 2, 0, SlHarqFeedbackScheme::Option1DistanceBasedNack, PsfchFeedbackReport::Nack)
        .expect("Option 1 mapping should succeed");
    assert_eq!(res_opt1.slot_idx, 4);
    assert_eq!(res_opt1.prb_idx, 12);
    assert_eq!(res_opt1.cyclic_shift_idx, 0);

    // Option 2 mapping: Member 0 and Member 1 on Subchannel 1
    let res_m0_ack = mapper
        .map_resource(1, 1, 0, SlHarqFeedbackScheme::Option2AckNack, PsfchFeedbackReport::Ack)
        .expect("Member 0 mapping should succeed");
    let res_m0_nack = mapper
        .map_resource(1, 1, 0, SlHarqFeedbackScheme::Option2AckNack, PsfchFeedbackReport::Nack)
        .expect("Member 0 mapping should succeed");

    // ACK and NACK for member 0 should share the same PRB but different CS (offset by 6)
    assert_eq!(res_m0_ack.prb_idx, res_m0_nack.prb_idx);
    assert_eq!((res_m0_ack.cyclic_shift_idx + 6) % 12, res_m0_nack.cyclic_shift_idx);
}

#[test]
fn test_groupcast_option1_distance_based_nack() {
    let evaluator = DistanceBasedFeedbackEvaluator::new();

    // 20m x 20m grid
    let tx_zone = SlZoneId::new(10, 10, 20.0, 20.0).unwrap();
    let rx_near = SlZoneId::new(11, 10, 20.0, 20.0).unwrap(); // distance = 20.0m
    let rx_far = SlZoneId::new(20, 20, 20.0, 20.0).unwrap();  // distance = sqrt(10^2 + 10^2)*20 = ~282.8m

    let mcr_meters = 100.0;

    // Near receiver with failed decoding -> Within MCR -> Must transmit NACK
    let fb_near_fail = evaluator.evaluate_feedback(&tx_zone, &rx_near, mcr_meters, false);
    assert_eq!(fb_near_fail, Some(PsfchFeedbackReport::Nack));

    // Near receiver with successful decoding -> NACK-only protocol -> Transmit Nothing
    let fb_near_succ = evaluator.evaluate_feedback(&tx_zone, &rx_near, mcr_meters, true);
    assert_eq!(fb_near_succ, None);

    // Far receiver with failed decoding -> Outside MCR -> Transmit Nothing (suppress NACK)
    let fb_far_fail = evaluator.evaluate_feedback(&tx_zone, &rx_far, mcr_meters, false);
    assert_eq!(fb_far_fail, None);
}

#[test]
fn test_dynamic_groupcast_mode_switching_cbr_and_size() {
    let config = DynamicGroupcastConfig {
        cbr_congestion_threshold: 0.60,
        max_group_size_for_option2: 6,
        ultra_low_latency_budget_ms: 15.0,
    };
    let adapter = DynamicGroupcastAdapter::new(config);

    // Case 1: High channel congestion (CBR = 0.75 > 0.60) -> Fallback to Option 1
    let scheme_congested = adapter.select_scheme(4, 0.75, 10.0);
    assert_eq!(scheme_congested, SlHarqFeedbackScheme::Option1DistanceBasedNack);

    // Case 2: Large group size (12 members > 6) in clear channel -> Fallback to Option 1
    let scheme_large_group = adapter.select_scheme(12, 0.30, 10.0);
    assert_eq!(scheme_large_group, SlHarqFeedbackScheme::Option1DistanceBasedNack);

    // Case 3: Small group (4 members) with tight latency (10 ms <= 15 ms) in clear channel -> Option 2
    let scheme_tight_platoon = adapter.select_scheme(4, 0.25, 10.0);
    assert_eq!(scheme_tight_platoon, SlHarqFeedbackScheme::Option2AckNack);
}

#[test]
fn test_sidelink_harq_codebook_generation() {
    let generator = SidelinkHarqCodebookGenerator::new();

    // Type-1 Semi-Static codebook
    let occasions = vec![
        Some(PsfchFeedbackReport::Ack),
        None,
        Some(PsfchFeedbackReport::Nack),
        Some(PsfchFeedbackReport::Dtx),
        Some(PsfchFeedbackReport::Ack),
    ];
    let type1_bits = generator.generate_type1_codebook(&occasions);
    assert_eq!(type1_bits, vec![true, false, false, false, true]);

    // Type-2 Dynamic codebook sorted by DAI
    let scheduled = vec![
        (3, PsfchFeedbackReport::Ack),
        (1, PsfchFeedbackReport::Nack),
        (2, PsfchFeedbackReport::Ack),
    ];
    let type2_bits = generator.generate_type2_codebook(&scheduled);
    // After sorting by DAI (1, 2, 3): Nack(false), Ack(true), Ack(true)
    assert_eq!(type2_bits, vec![false, true, true]);
}

#[test]
fn test_psfch_power_control_and_priority_resolution() {
    let power_cfg = PsfchPowerConfig {
        p0_psfch_dbm: -70.0,
        alpha_psfch: 0.8,
        pcmax_dbm: 23.0,
    };
    let controller = PsfchPowerController::new(power_cfg);

    // Pathloss = 90 dB -> P = min(23, -70 + 0.8 * 90) = min(23, 2.0) = 2.0 dBm
    let power_dbm = controller.calculate_power(90.0);
    assert!((power_dbm - 2.0).abs() < 1e-6);

    // Huge pathloss 150 dB -> P = min(23, -70 + 0.8 * 150) = min(23, 50.0) = 23.0 dBm (capped at PCMAX)
    let power_capped = controller.calculate_power(150.0);
    assert!((power_capped - 23.0).abs() < 1e-6);

    // Arbitration with 2 candidates: both requiring 21 dBm (sum linear power > 23 dBm)
    // Candidate 1: PPPP = 1 (higher priority)
    // Candidate 2: PPPP = 5 (lower priority)
    let dummy_res = PsfchFormat0Resource {
        slot_idx: 10,
        prb_idx: 12,
        cyclic_shift_idx: 0,
    };
    let cand1 = PsfchTxCandidate {
        candidate_id: 101,
        pppp_priority: 1,
        resource: dummy_res,
        estimated_pathloss_db: 113.75, // 21 dBm
    };
    let cand2 = PsfchTxCandidate {
        candidate_id: 102,
        pppp_priority: 5,
        resource: dummy_res,
        estimated_pathloss_db: 113.75, // 21 dBm
    };

    let (approved, dropped) = controller.arbitrate_candidates(&[cand1.clone(), cand2.clone()]);
    assert_eq!(approved.len(), 1);
    assert_eq!(approved[0].candidate_id, 101); // Higher priority kept
    assert_eq!(dropped, vec![102]);           // Lower priority dropped
}

#[test]
fn test_sidelink_harq_process_lifecycle_and_rv() {
    let mut proc = SlHarqProcess::new(1, 3, 2);
    assert_eq!(proc.state, SlHarqState::Idle);
    assert_eq!(proc.current_rv(), 0);

    // Initial transmission at slot 10
    proc.start_transmission(10);
    assert_eq!(proc.state, SlHarqState::WaitingForPsfch);
    assert_eq!(proc.transmission_count, 1);
    assert_eq!(proc.current_rv(), 0);

    // First NACK -> RV advances to 2, RetransmissionPending
    proc.handle_feedback(PsfchFeedbackReport::Nack).unwrap();
    assert_eq!(proc.state, SlHarqState::RetransmissionPending);
    assert_eq!(proc.current_rv(), NR_HARQ_RV_SEQUENCE[1]); // RV 2

    // Schedule retransmission
    proc.retransmit(14);
    assert_eq!(proc.state, SlHarqState::WaitingForPsfch);
    assert_eq!(proc.transmission_count, 2);

    // Second NACK -> RV advances to 3
    proc.handle_feedback(PsfchFeedbackReport::Nack).unwrap();
    assert_eq!(proc.state, SlHarqState::RetransmissionPending);
    assert_eq!(proc.current_rv(), NR_HARQ_RV_SEQUENCE[2]); // RV 3

    // Schedule 3rd transmission (max retransmissions = 3)
    proc.retransmit(18);
    assert_eq!(proc.transmission_count, 3);

    // Third NACK -> Exceeds max retransmissions -> Returns error and transitions to Failed
    let res = proc.handle_feedback(PsfchFeedbackReport::Nack);
    assert!(matches!(res, Err(SlHarqError::MaxRetransmissionsReached { .. })));
    assert_eq!(proc.state, SlHarqState::Failed);
}

#[test]
fn test_end_to_end_sidelink_harq_engine_coordinator() {
    let res_cfg = PsfchResourceConfig::new(1, 2, 5, 20, 4).unwrap();
    let pwr_cfg = PsfchPowerConfig::default();
    let grp_cfg = DynamicGroupcastConfig::default();

    let mut engine = SidelinkHarqEngine::new(res_cfg, pwr_cfg, grp_cfg);
    engine.register_process(5, 3, 1);

    // Transmit TB on process 5 at slot 20
    let psfch_slot = engine.transmit_tb(5, 20).unwrap();
    assert_eq!(psfch_slot, 22); // min delay 2 -> slot 22
    assert_eq!(engine.metrics.total_transmissions, 1);

    // Process receives ACK
    engine.receive_feedback(5, PsfchFeedbackReport::Ack).unwrap();
    assert_eq!(engine.metrics.acks_received, 1);

    let proc = engine.processes.get(&5).unwrap();
    assert_eq!(proc.state, SlHarqState::Delivered);
}
