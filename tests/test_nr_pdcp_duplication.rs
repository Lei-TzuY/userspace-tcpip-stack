//! Comprehensive integration tests for 3GPP Rel-18/19 PDCP Multi-Path Duplication
//! and URLLC Latency Bound Engine.

use toy_tcpip::nr_pdcp_duplication::{
    LegCellGroup, LegConfig, PdcpDuplicationEngine, PdcpDuplicationError,
    PdcpDuplicationMacCe, PdcpDuplicationPdu, PdcpSnFormat, UrllcQosProfile,
    DEFAULT_SURVIVAL_TIME_MS, DEFAULT_URLLC_PDB_US, MAX_DUPLICATION_LEGS,
};

fn create_test_engine() -> PdcpDuplicationEngine {
    let legs = vec![
        LegConfig::new(0, LegCellGroup::Mcg, 4, true),  // Leg 0: MCG Primary
        LegConfig::new(1, LegCellGroup::Mcg, 5, false), // Leg 1: MCG Secondary
        LegConfig::new(2, LegCellGroup::Scg, 6, false), // Leg 2: SCG Primary
        LegConfig::new(3, LegCellGroup::Scg, 7, false), // Leg 3: SCG Secondary
    ];

    let qos = UrllcQosProfile {
        packet_delay_budget_us: DEFAULT_URLLC_PDB_US,
        survival_time_ms: DEFAULT_SURVIVAL_TIME_MS,
        target_reliability: 0.999999,
    };

    PdcpDuplicationEngine::new(1, PdcpSnFormat::Sn12Bits, legs, 0, qos)
}

#[test]
fn test_pdcp_duplication_multi_leg_configuration() {
    let engine = create_test_engine();
    assert_eq!(engine.drb_id, 1);
    assert_eq!(engine.sn_format, PdcpSnFormat::Sn12Bits);
    assert_eq!(engine.legs().len(), MAX_DUPLICATION_LEGS);

    // Verify initial configuration: Leg 0 is primary and active; others inactive
    assert!(engine.legs()[0].is_primary);
    assert!(engine.legs()[0].is_active);
    assert_eq!(engine.legs()[0].cell_group, LegCellGroup::Mcg);

    assert!(!engine.legs()[1].is_primary);
    assert!(!engine.legs()[1].is_active);

    assert!(!engine.legs()[2].is_primary);
    assert!(!engine.legs()[2].is_active);
    assert_eq!(engine.legs()[2].cell_group, LegCellGroup::Scg);

    assert!(!engine.legs()[3].is_primary);
    assert!(!engine.legs()[3].is_active);
    assert_eq!(engine.legs()[3].cell_group, LegCellGroup::Scg);
}

#[test]
fn test_duplication_activation_mac_ce_codec() {
    // 1. Create Rel-18 Duplication Activation MAC CE activating Legs 0, 1, and 2 for DRB 5
    let mac_ce = PdcpDuplicationMacCe {
        drb_id: 5,
        leg0_active: true,
        leg1_active: true,
        leg2_active: true,
        leg3_active: false,
    };

    // 2. Binary wire serialization
    let bytes = mac_ce.serialize();
    assert_eq!(bytes.len(), 2);

    // Octet 1: 5 bits DRB ID = 0x05
    assert_eq!(bytes[0], 0x05);
    // Octet 2: D3=0, D2=1, D1=1, D0=1 -> 0b00000111 = 0x07
    assert_eq!(bytes[1], 0x07);

    // 3. Binary wire deserialization
    let parsed = PdcpDuplicationMacCe::parse(&bytes).expect("MAC CE parse failed");
    assert_eq!(parsed.drb_id, 5);
    assert!(parsed.leg0_active);
    assert!(parsed.leg1_active);
    assert!(parsed.leg2_active);
    assert!(!parsed.leg3_active);

    // Verify truncated error
    let truncated = [0x05];
    assert!(matches!(
        PdcpDuplicationMacCe::parse(&truncated),
        Err(PdcpDuplicationError::DecodingError(_))
    ));
}

#[test]
fn test_multi_leg_pdu_dispatch() {
    let mut engine = create_test_engine();

    // Activate Legs 0, 1, and 2 via MAC CE
    let mac_ce = PdcpDuplicationMacCe {
        drb_id: 1,
        leg0_active: true,
        leg1_active: true,
        leg2_active: true,
        leg3_active: false,
    };
    engine.apply_duplication_mac_ce(&mac_ce);

    // Submit SDU payload
    let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let pdus = engine.submit_sdu(payload.clone(), 10_000).expect("SDU submission failed");

    // Must generate 3 identical replicated PDUs targeting Legs 0, 1, 2
    assert_eq!(pdus.len(), 3);
    for (i, target_leg) in [0, 1, 2].iter().enumerate() {
        assert_eq!(pdus[i].leg_id, *target_leg);
        assert_eq!(pdus[i].sn, 0);
        assert_eq!(pdus[i].count, 0);
        assert_eq!(pdus[i].payload, payload);
        assert_eq!(pdus[i].timestamp_us, 10_000);
        assert_eq!(pdus[i].packet_delay_budget_us, DEFAULT_URLLC_PDB_US);
    }

    // Submit second SDU: SN must increment to 1
    let pdus2 = engine.submit_sdu(vec![0x11, 0x22], 11_000).expect("Second SDU failed");
    assert_eq!(pdus2.len(), 3);
    assert_eq!(pdus2[0].sn, 1);
    assert_eq!(pdus2[0].count, 1);
    assert_eq!(engine.metrics.total_sdus_submitted, 2);
    assert_eq!(engine.metrics.total_replicated_pdus_dispatched, 6);
}

#[test]
fn test_proactive_in_flight_fast_discard() {
    let mut tx_engine = create_test_engine();
    let mut rx_engine = create_test_engine();

    // Activate Legs 0, 1, 2 on both engines
    let mac_ce = PdcpDuplicationMacCe {
        drb_id: 1,
        leg0_active: true,
        leg1_active: true,
        leg2_active: true,
        leg3_active: false,
    };
    tx_engine.apply_duplication_mac_ce(&mac_ce);
    rx_engine.apply_duplication_mac_ce(&mac_ce);

    // Transmitter generates replicated PDUs
    let sdu = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let pdus = tx_engine.submit_sdu(sdu.clone(), 5_000).unwrap();
    assert_eq!(pdus.len(), 3);

    // Suppose Leg 2 (fast mmWave path) arrives first at receiver at t = 6_000 us
    let rx_pdu_leg2 = pdus[2].clone();
    assert_eq!(rx_pdu_leg2.leg_id, 2);

    let rx_res = rx_engine.receive_pdu(rx_pdu_leg2, 6_000).unwrap();
    assert!(rx_res.is_some(), "First arrival must deliver SDU");
    let (delivered_payload, discard_signal) = rx_res.unwrap();
    assert_eq!(delivered_payload, sdu);

    // Verify fast discard signal is generated targeting remaining active legs (Legs 0 and 1)
    assert!(discard_signal.is_some());
    let signal = discard_signal.unwrap();
    assert_eq!(signal.sn, 0);
    assert_eq!(signal.count, 0);
    assert_eq!(signal.received_leg_id, 2);
    assert_eq!(signal.target_leg_ids, vec![0, 1]);

    // Apply fast discard signal on transmitter
    tx_engine.handle_in_flight_discard(&signal, sdu.len());

    // Later, the slower replica from Leg 0 arrives at t = 7_500 us
    let rx_pdu_leg0 = pdus[0].clone();
    let rx_res_late = rx_engine.receive_pdu(rx_pdu_leg0, 7_500).unwrap();
    // Must be suppressed as redundant duplicate
    assert!(rx_res_late.is_none());
    assert_eq!(rx_engine.metrics.redundant_pdus_dropped, 1);
    assert_eq!(rx_engine.metrics.total_sdus_delivered, 1);
}

#[test]
fn test_urllc_pdb_and_survival_time_governor() {
    let mut rx_engine = create_test_engine();
    rx_engine.urllc_profile.packet_delay_budget_us = 2_000; // 2 ms PDB
    rx_engine.urllc_profile.survival_time_ms = 10;          // 10 ms survival time

    // PDU 1: Generated at t = 1_000 us, received at t = 2_500 us (elapsed 1,500 us <= 2,000 us) -> Within PDB
    let pdu1 = PdcpDuplicationPdu {
        sn: 0,
        count: 0,
        leg_id: 0,
        payload: vec![0x01],
        timestamp_us: 1_000,
        packet_delay_budget_us: 2_000,
    };
    let res1 = rx_engine.receive_pdu(pdu1, 2_500).unwrap();
    assert!(res1.is_some());
    assert_eq!(rx_engine.metrics.packets_within_pdb, 1);
    assert_eq!(rx_engine.metrics.packets_exceeding_pdb, 0);
    assert_eq!(rx_engine.metrics.current_consecutive_misses, 0);

    // PDU 2: Generated at t = 5_000 us, received at t = 8_500 us (elapsed 3,500 us > 2,000 us) -> PDB missed
    let pdu2 = PdcpDuplicationPdu {
        sn: 1,
        count: 1,
        leg_id: 0,
        payload: vec![0x02],
        timestamp_us: 5_000,
        packet_delay_budget_us: 2_000,
    };
    let res2 = rx_engine.receive_pdu(pdu2, 8_500).unwrap();
    assert!(res2.is_some());
    assert_eq!(rx_engine.metrics.packets_within_pdb, 1);
    assert_eq!(rx_engine.metrics.packets_exceeding_pdb, 1);
    assert_eq!(rx_engine.metrics.current_consecutive_misses, 1);
    assert_eq!(rx_engine.metrics.survival_time_alarms_raised, 0);

    // PDU 3: Generated at t = 10_000 us, received at t = 25_000 us (elapsed 15,000 us > 10,000 us survival time)
    let pdu3 = PdcpDuplicationPdu {
        sn: 2,
        count: 2,
        leg_id: 0,
        payload: vec![0x03],
        timestamp_us: 10_000,
        packet_delay_budget_us: 2_000,
    };
    let res3 = rx_engine.receive_pdu(pdu3, 25_000).unwrap();
    assert!(res3.is_some());
    assert_eq!(rx_engine.metrics.packets_exceeding_pdb, 2);
    assert_eq!(rx_engine.metrics.survival_time_alarms_raised, 1);
}

#[test]
fn test_dynamic_primary_path_adaptation() {
    let mut engine = create_test_engine();

    // Initially Leg 0 is primary
    assert_eq!(engine.legs()[0].is_primary, true);

    // Degrade Leg 0: high latency (8,000 us) and high loss (10% BLER)
    engine.update_leg_link_quality(0, 8_000.0, 0.10, 1.0);

    // Improve Leg 2 (SCG mmWave): ultra-low latency (500 us) and zero loss (0.001 BLER)
    engine.update_leg_link_quality(2, 500.0, 0.001, 1.0);

    // Trigger dynamic primary path adaptation
    engine.adapt_primary_path();

    // Verify Leg 2 has taken over as primary path
    assert!(!engine.legs()[0].is_primary);
    assert!(engine.legs()[2].is_primary);
}

#[test]
fn test_multi_path_joint_reliability_calculation() {
    let mut engine = create_test_engine();

    // Set individual leg BLERs: Leg 0 = 5%, Leg 1 = 5%, Leg 2 = 2%, Leg 3 = 1%
    engine.update_leg_link_quality(0, 1000.0, 0.05, 1.0);
    engine.update_leg_link_quality(1, 1000.0, 0.05, 1.0);
    engine.update_leg_link_quality(2, 1000.0, 0.02, 1.0);
    engine.update_leg_link_quality(3, 1000.0, 0.01, 1.0);

    // With only Leg 0 active: outage = 5% = 0.05
    engine.recalculate_joint_reliability();
    assert!((engine.metrics.current_joint_outage_prob - 0.05).abs() < 1e-6);

    // Activate all 4 legs via MAC CE
    let mac_ce = PdcpDuplicationMacCe {
        drb_id: 1,
        leg0_active: true,
        leg1_active: true,
        leg2_active: true,
        leg3_active: true,
    };
    engine.apply_duplication_mac_ce(&mac_ce);

    // Joint outage prob = 0.05 * 0.05 * 0.02 * 0.01 = 5.0e-7
    let expected_joint_outage = 0.05 * 0.05 * 0.02 * 0.01;
    assert!(
        (engine.metrics.current_joint_outage_prob - expected_joint_outage).abs() < 1e-10,
        "Joint outage was {}",
        engine.metrics.current_joint_outage_prob
    );

    // Reliability nines = -log10(5e-7) ~= 6.30 (six nines, exceeding 99.9999%)
    let nines = engine.reliability_nines();
    assert!(nines > 6.0, "Expected > 6 nines reliability, got {nines}");
}
