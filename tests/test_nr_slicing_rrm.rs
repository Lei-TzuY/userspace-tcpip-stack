//! Integration tests for 3GPP Rel-18/19 RAN Network Slicing & SLA Assurance Engine.

use toy_tcpip::nr_slicing_rrm::*;

#[test]
fn test_snssai_and_service_types() {
    let embb = SliceServiceType::from_u8(1).unwrap();
    assert_eq!(embb, SliceServiceType::Embb);

    let urllc = SliceServiceType::from_u8(2).unwrap();
    assert_eq!(urllc, SliceServiceType::Urllc);

    let miot = SliceServiceType::from_u8(3).unwrap();
    assert_eq!(miot, SliceServiceType::MIoT);

    let v2x = SliceServiceType::from_u8(4).unwrap();
    assert_eq!(v2x, SliceServiceType::V2x);

    let hm = SliceServiceType::from_u8(5).unwrap();
    assert_eq!(hm, SliceServiceType::HighPerformanceMachine);

    assert!(SliceServiceType::from_u8(0).is_err());
    assert!(SliceServiceType::from_u8(6).is_err());

    let snssai = Snssai::new(SliceServiceType::Urllc, 0x123456);
    let key = snssai.to_key();
    assert_eq!(key, 0x02123456);

    let reconstructed = Snssai::from_key(key).expect("reconstruction failed");
    assert_eq!(reconstructed.sst, SliceServiceType::Urllc);
    assert_eq!(reconstructed.sd, 0x123456);
}

#[test]
fn test_slice_profile_validation() {
    let snssai = Snssai::new(SliceServiceType::Embb, 0x000001);

    // Invalid quota min > max
    let bad_profile = SliceSlaProfile::new(
        snssai,
        PartitionPolicy::HardIsolated,
        50,
        30,
        100.0,
        200.0,
        20.0,
        4,
        false,
        true,
    );
    assert!(matches!(bad_profile, Err(SlicingError::InvalidQuota { .. })));

    // Valid profile
    let ok_profile = SliceSlaProfile::new(
        snssai,
        PartitionPolicy::SoftSharedWithPriority,
        20,
        60,
        100.0,
        300.0,
        20.0,
        4,
        false,
        true,
    ).unwrap();
    assert_eq!(ok_profile.min_prb_quota, 20);
    assert_eq!(ok_profile.max_prb_quota, 60);
    assert_eq!(ok_profile.priority, 4);
}

#[test]
fn test_add_slice_profile_and_quota_oversubscription() {
    let mut engine = NrSlicingRrmEngine::new(1, 100);

    let s1 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Embb, 1),
        PartitionPolicy::SoftSharedWithPriority,
        40,
        80,
        100.0,
        500.0,
        20.0,
        5,
        false,
        true,
    ).unwrap();
    engine.add_slice_profile(s1).unwrap();

    let s2 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Urllc, 2),
        PartitionPolicy::SoftSharedWithPriority,
        40,
        60,
        50.0,
        100.0,
        5.0,
        1,
        true,
        false,
    ).unwrap();
    engine.add_slice_profile(s2).unwrap();

    // Duplicate slice key attempt
    let s_dup = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Embb, 1),
        PartitionPolicy::HardIsolated,
        10,
        20,
        10.0,
        50.0,
        20.0,
        5,
        false,
        true,
    ).unwrap();
    assert!(matches!(engine.add_slice_profile(s_dup), Err(SlicingError::SliceAlreadyExists(_))));

    // Oversubscription of guaranteed minimum quotas (40 + 40 + 30 = 110 > 100)
    let s3 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::V2x, 3),
        PartitionPolicy::SoftSharedWithPriority,
        30,
        40,
        20.0,
        50.0,
        10.0,
        3,
        false,
        true,
    ).unwrap();
    assert!(matches!(engine.add_slice_profile(s3), Err(SlicingError::TotalMinQuotaExceeded { .. })));
}

#[test]
fn test_hard_slicing_strict_isolation() {
    let mut engine = NrSlicingRrmEngine::new(1, 100);

    let s1 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::HighPerformanceMachine, 1),
        PartitionPolicy::HardIsolated,
        20,
        20, // Strict 20 PRB cap
        50.0,
        50.0,
        10.0,
        2,
        false,
        false,
    ).unwrap();
    engine.add_slice_profile(s1).unwrap();

    // Demand 100,000 bytes (~1000 PRBs, far exceeding 20 PRBs)
    let demands = vec![SliceTrafficDemand {
        snssai: Snssai::new(SliceServiceType::HighPerformanceMachine, 1),
        backlog_bytes: 100_000,
        head_of_line_delay_ms: 2.0,
    }];

    let (grants, _) = engine.schedule_slot(1, &demands);
    assert_eq!(grants.len(), 1);
    // HardIsolated slice MUST NOT exceed max_prb_quota (20), even though 80 PRBs on the carrier are free!
    assert_eq!(grants[0].allocated_prb_count, 20);
    assert_eq!(grants[0].allocated_prb_start, 0);
    assert!(!grants[0].delay_budget_violated);
}

#[test]
fn test_soft_slicing_dynamic_bursting() {
    let mut engine = NrSlicingRrmEngine::new(1, 100);

    let embb = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Embb, 1),
        PartitionPolicy::SoftSharedWithPriority,
        20,
        70, // Can burst up to 70 PRBs if spare PRBs available
        100.0,
        500.0,
        30.0,
        5,
        false,
        true,
    ).unwrap();
    engine.add_slice_profile(embb).unwrap();

    let miot = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::MIoT, 2),
        PartitionPolicy::SoftSharedWithPriority,
        20,
        30,
        10.0,
        20.0,
        100.0,
        7,
        false,
        true,
    ).unwrap();
    engine.add_slice_profile(miot).unwrap();

    // MIoT has zero traffic demand; eMBB has huge traffic demand
    let demands = vec![
        SliceTrafficDemand {
            snssai: Snssai::new(SliceServiceType::Embb, 1),
            backlog_bytes: 50_000,
            head_of_line_delay_ms: 10.0,
        },
        SliceTrafficDemand {
            snssai: Snssai::new(SliceServiceType::MIoT, 2),
            backlog_bytes: 0,
            head_of_line_delay_ms: 0.0,
        },
    ];

    let (grants, _) = engine.schedule_slot(100, &demands);
    assert_eq!(grants.len(), 2);

    // eMBB gets its 20 min PRBs + 50 spare PRBs = 70 PRBs (its max_prb_quota cap)
    assert_eq!(grants[0].allocated_prb_count, 70);
    assert_eq!(grants[1].allocated_prb_count, 0);
    assert!(grants[0].throughput_mbps > 50.0);
}

#[test]
fn test_urllc_preemption_and_dci_2_1() {
    let mut engine = NrSlicingRrmEngine::new(1, 100);

    let embb_snssai = Snssai::new(SliceServiceType::Embb, 101);
    let embb = SliceSlaProfile::new(
        embb_snssai,
        PartitionPolicy::SoftSharedWithPriority,
        20,
        90, // Can burst up to 90
        100.0,
        800.0,
        50.0,
        6,     // Low priority
        false, // Cannot preempt
        true,  // Can be preempted
    ).unwrap();
    engine.add_slice_profile(embb).unwrap();

    let urllc_snssai = Snssai::new(SliceServiceType::Urllc, 202);
    let urllc = SliceSlaProfile::new(
        urllc_snssai,
        PartitionPolicy::SoftSharedWithPriority,
        10,
        50, // Up to 50 PRBs
        50.0,
        200.0,
        5.0,  // Critical 5ms latency
        1,    // Highest priority
        true, // Can preempt
        false,
    ).unwrap();
    engine.add_slice_profile(urllc).unwrap();

    // eMBB requests 80 PRBs; URLLC requests 40 PRBs
    // Total demand = 120 PRBs > 100 total carrier PRBs!
    // Stage 1: eMBB gets min 20, URLLC gets min 10 (30 total, 70 remaining)
    // Stage 2: Remaining 70 PRBs given by priority:
    //          URLLC (priority 1) takes 30 more PRBs to reach 40 (its full demand!).
    //          eMBB takes remaining 40 PRBs to reach 60 PRBs.
    // Notice: with 100 carrier PRBs, URLLC needs 40 and eMBB needs 80.
    // If eMBB was scheduled first or if demand is higher:
    // Let's test explicit preemption: eMBB demands 90 PRBs, URLLC demands 50 PRBs.
    let demands = vec![
        SliceTrafficDemand {
            snssai: embb_snssai,
            backlog_bytes: 50_000,
            head_of_line_delay_ms: 10.0,
        },
        SliceTrafficDemand {
            snssai: urllc_snssai,
            backlog_bytes: 25_000,
            head_of_line_delay_ms: 3.0,
        },
    ];

    let (grants, preemption_events) = engine.schedule_slot(200, &demands);
    assert_eq!(grants.len(), 2);

    // Verify URLLC got its full 50 PRBs
    assert_eq!(grants[1].allocated_prb_count, 50);
    // eMBB got the remaining 50 PRBs
    assert_eq!(grants[0].allocated_prb_count, 50);
    assert_eq!(grants[0].preempted_prbs, 40);

    // Verify DCI 2_1 preemption event was emitted
    assert_eq!(preemption_events.len(), 1);
    assert_eq!(preemption_events[0].punctured_prbs, 40);
    assert_eq!(preemption_events[0].preempting_snssai, urllc_snssai);
    assert_eq!(preemption_events[0].victim_snssai, embb_snssai);

    // Now test extreme preemption where eMBB occupied the shared pool
    // and an urgent URLLC burst arrives in slot 201:
    let urgent_demands = vec![
        SliceTrafficDemand {
            snssai: embb_snssai,
            backlog_bytes: 40_000,
            head_of_line_delay_ms: 15.0,
        },
        SliceTrafficDemand {
            snssai: urllc_snssai,
            backlog_bytes: 30_000,
            head_of_line_delay_ms: 4.5,
        },
    ];
    let (grants2, _) = engine.schedule_slot(201, &urgent_demands);
    assert_eq!(grants2[1].allocated_prb_count, 50);
    assert_eq!(grants2[0].allocated_prb_count, 50);
}

#[test]
fn test_delay_budget_violation_tracking() {
    let mut engine = NrSlicingRrmEngine::new(1, 100);

    let urllc_snssai = Snssai::new(SliceServiceType::Urllc, 999);
    let profile = SliceSlaProfile::new(
        urllc_snssai,
        PartitionPolicy::SoftSharedWithPriority,
        10,
        30,
        20.0,
        100.0,
        5.0, // 5ms budget
        1,
        true,
        false,
    ).unwrap();
    engine.add_slice_profile(profile).unwrap();

    // Traffic arrives with head-of-line delay of 7.2 ms (> 5.0 ms PDB!)
    let demands = vec![SliceTrafficDemand {
        snssai: urllc_snssai,
        backlog_bytes: 5_000,
        head_of_line_delay_ms: 7.2,
    }];

    let (grants, _) = engine.schedule_slot(500, &demands);
    assert_eq!(grants.len(), 1);
    assert!(grants[0].delay_budget_violated);

    // Verify telemetry
    assert_eq!(engine.telemetry().total_delay_sla_violations, 1);
    let metrics = engine.get_slice_metrics(&urllc_snssai).unwrap();
    assert_eq!(metrics.total_delay_violations, 1);
}

#[test]
fn test_slice_config_wire_codec_and_crc() {
    let p1 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Embb, 0x000100),
        PartitionPolicy::SoftSharedWithPriority,
        30,
        80,
        150.0,
        600.0,
        25.0,
        5,
        false,
        true,
    ).unwrap();
    let p2 = SliceSlaProfile::new(
        Snssai::new(SliceServiceType::Urllc, 0x000200),
        PartitionPolicy::HardIsolated,
        20,
        20,
        50.0,
        50.0,
        5.0,
        1,
        true,
        false,
    ).unwrap();

    let frame = SliceConfigFrame {
        cell_id: 101,
        total_carrier_prbs: 100,
        profiles: vec![p1, p2],
    };

    let wire = frame.encode_wire();
    // Magic 'S', 'L', 'C', 0x12
    assert_eq!(wire[0], 0x53);
    assert_eq!(wire[1], 0x4C);
    assert_eq!(wire[2], 0x43);
    assert_eq!(wire[3], 0x12);

    let decoded = SliceConfigFrame::decode_wire(&wire).expect("slice config decode failed");
    assert_eq!(decoded.cell_id, 101);
    assert_eq!(decoded.total_carrier_prbs, 100);
    assert_eq!(decoded.profiles.len(), 2);
    assert_eq!(decoded.profiles[0].snssai.sst, SliceServiceType::Embb);
    assert_eq!(decoded.profiles[0].snssai.sd, 0x000100);
    assert_eq!(decoded.profiles[1].snssai.sst, SliceServiceType::Urllc);
    assert_eq!(decoded.profiles[1].policy, PartitionPolicy::HardIsolated);

    // Corrupt CRC
    let mut bad_wire = wire.clone();
    let l = bad_wire.len() - 1;
    bad_wire[l] ^= 0xAA;
    assert!(matches!(
        SliceConfigFrame::decode_wire(&bad_wire),
        Err(SlicingError::ChecksumMismatch { .. })
    ));

    // Corrupt Magic
    let mut bad_magic = wire.clone();
    bad_magic[0] = 0x00;
    let new_crc = compute_crc16(&bad_magic[..bad_magic.len() - 2]);
    let len = bad_magic.len();
    bad_magic[len - 2..len].copy_from_slice(&new_crc.to_be_bytes());
    assert!(matches!(
        SliceConfigFrame::decode_wire(&bad_magic),
        Err(SlicingError::DeserializationError(msg)) if msg.contains("magic")
    ));

    // Truncated buffer
    assert!(SliceConfigFrame::decode_wire(&[0x53, 0x4C, 0x43]).is_err());
}

#[test]
fn test_error_display() {
    let err1 = SlicingError::TotalMinQuotaExceeded {
        total_min: 120,
        carrier_prbs: 100,
    };
    assert!(format!("{}", err1).contains("exceed carrier capacity"));

    let err2 = SlicingError::InvalidSst(99);
    assert!(format!("{}", err2).contains("99"));
}
