//! Comprehensive integration tests for 3GPP Rel-18/19 5G NR Sidelink Mode 1
//! Network-Controlled Resource Allocation & DCI 3_0 Scheduling Engine.

use toy_tcpip::nr_sidelink_mode1_allocator::{
    DciFormat3_0, SidelinkMode1Allocator, SlBsrEntry, SlBsrMacCe, SlGrantType, SlMode1Error,
    MAX_SL_SUBCHANNELS,
};

// ---------------------------------------------------------------------------
// Test 1: DCI Format 3_0 Construction & Validation
// ---------------------------------------------------------------------------
#[test]
fn test_dci_format_3_0_construction_and_validation() {
    // 1. Valid dynamic DCI 3_0: 4 sub-channels starting at index 2
    let dci = DciFormat3_0::new_dynamic(2, 4, 3, vec![0, 2], 16).expect("Valid DCI 3_0");
    assert_eq!(dci.start_subchannel, 2);
    assert_eq!(dci.num_subchannels, 4);
    assert_eq!(dci.time_gap_slots, 3);
    assert_eq!(dci.time_resource_offsets, vec![0, 2]);
    assert_eq!(dci.grant_type, SlGrantType::Dynamic);

    // 2. Out-of-bounds subchannel allocation
    let bad_alloc = DciFormat3_0::new_dynamic(MAX_SL_SUBCHANNELS - 2, 5, 2, vec![0], 10);
    assert!(matches!(bad_alloc, Err(SlMode1Error::InvalidSubchannelAllocation { .. })));

    // 3. Configured Grant Type 2 Activation & Deactivation pattern checks
    let act_dci = DciFormat3_0 {
        carrier_indicator: 0,
        resource_pool_index: 0,
        time_gap_slots: 4,
        start_subchannel: 0,
        num_subchannels: 6,
        time_resource_offsets: vec![0],
        mcs: 12,
        psfch_to_harq_timing_k: 2,
        pucch_resource_indicator: 1,
        grant_type: SlGrantType::ConfiguredGrantType2Activation { cg_id: 1 },
    };
    assert!(act_dci.is_valid_activation_dci());
    assert!(!act_dci.is_valid_deactivation_dci());

    let deact_dci = DciFormat3_0 {
        carrier_indicator: 0,
        resource_pool_index: 0,
        time_gap_slots: 0,
        start_subchannel: 0,
        num_subchannels: 0,
        time_resource_offsets: vec![],
        mcs: 0x1F, // 0b11111 per TS 38.214
        psfch_to_harq_timing_k: 0,
        pucch_resource_indicator: 0,
        grant_type: SlGrantType::ConfiguredGrantType2Deactivation { cg_id: 1 },
    };
    assert!(deact_dci.is_valid_deactivation_dci());
    assert!(!deact_dci.is_valid_activation_dci());
}

// ---------------------------------------------------------------------------
// Test 2: Sidelink BSR MAC CE Binary Codec Roundtrip
// ---------------------------------------------------------------------------
#[test]
fn test_sl_bsr_codec_roundtrip() {
    let entry1 = SlBsrEntry::new(0, 1, 15).unwrap(); // Dest 0, LCG 1, Size index 15
    let entry2 = SlBsrEntry::new(3, 4, 60).unwrap(); // Dest 3, LCG 4, Size index 60

    let bsr = SlBsrMacCe::new(vec![entry1, entry2]);
    let encoded = bsr.encode();
    assert_eq!(encoded.len(), 4); // 2 octets per entry

    // Decode back
    let decoded = SlBsrMacCe::decode(&encoded).expect("Decode SL-BSR");
    assert_eq!(decoded.entries.len(), 2);
    assert_eq!(decoded.entries[0].destination_index, 0);
    assert_eq!(decoded.entries[0].lcg_id, 1);
    assert_eq!(decoded.entries[0].buffer_size_index, 15);

    assert_eq!(decoded.entries[1].destination_index, 3);
    assert_eq!(decoded.entries[1].lcg_id, 4);
    assert_eq!(decoded.entries[1].buffer_size_index, 60);

    // Test buffer size conversion
    assert!(decoded.entries[1].buffer_size_bytes() > 2000);

    // Corrupted odd length buffer must error
    let bad_buf = vec![0x12, 0x34, 0x56];
    let err = SlBsrMacCe::decode(&bad_buf);
    assert!(matches!(err, Err(SlMode1Error::BufferTooShort { .. })));
}

// ---------------------------------------------------------------------------
// Test 3: Sidelink Configured Grant Type 1 Periodic Scheduling
// ---------------------------------------------------------------------------
#[test]
fn test_configured_grant_type1_periodic_scheduling() {
    let mut allocator = SidelinkMode1Allocator::new(MAX_SL_SUBCHANNELS);

    // Grant 1: Type 1, periodicity = 10 slots, 4 sub-channels
    allocator
        .add_configured_grant_type1(1, 10, 0, 4, 16)
        .expect("Add CG Type 1");

    let mut triggered_occasions = 0;
    for _ in 1..=35 {
        let transmissions = allocator.advance_slot();
        if !transmissions.is_empty() {
            triggered_occasions += transmissions.len();
            assert_eq!(transmissions[0].0, 1); // grant_id 1
            assert_eq!(transmissions[0].1, 0); // start_ch 0
            assert_eq!(transmissions[0].2, 4); // num_ch 4
        }
    }

    // Over 35 slots with periodicity 10, occasions should occur at slot 10, 20, 30 -> 3 occasions
    assert_eq!(triggered_occasions, 3);
    assert_eq!(allocator.telemetry().cg_type1_occasions, 3);
}

// ---------------------------------------------------------------------------
// Test 4: Sidelink Configured Grant Type 2 Dynamic Activation & Deactivation
// ---------------------------------------------------------------------------
#[test]
fn test_configured_grant_type2_activation_and_deactivation() {
    let mut allocator = SidelinkMode1Allocator::new(MAX_SL_SUBCHANNELS);

    // Add Type 2 CG (starts in ConfiguredAndSuspended state)
    allocator
        .add_configured_grant_type2(2, 8, 2, 5, 14)
        .expect("Add CG Type 2");

    // Advance 20 slots -> no transmissions should occur while suspended
    for _ in 0..20 {
        assert!(allocator.advance_slot().is_empty());
    }
    assert_eq!(allocator.telemetry().cg_type2_occasions, 0);

    // 1. Activate CG Type 2 via DCI 3_0 at slot 20 with gap 4 (first TX at slot 24)
    let act_dci = DciFormat3_0 {
        carrier_indicator: 0,
        resource_pool_index: 0,
        time_gap_slots: 4,
        start_subchannel: 2,
        num_subchannels: 5,
        time_resource_offsets: vec![0],
        mcs: 14,
        psfch_to_harq_timing_k: 2,
        pucch_resource_indicator: 1,
        grant_type: SlGrantType::ConfiguredGrantType2Activation { cg_id: 2 },
    };
    allocator.process_cg_dci(&act_dci).expect("Activate CG Type 2");

    // Advance slots: slot 24 triggers, then slot 32 triggers
    let mut occ = 0;
    for _ in 21..=35 {
        let t = allocator.advance_slot();
        occ += t.len();
    }
    assert_eq!(occ, 2); // slot 24 and 32
    assert_eq!(allocator.telemetry().cg_type2_occasions, 2);

    // 2. Deactivate CG Type 2 via DCI 3_0
    let deact_dci = DciFormat3_0 {
        carrier_indicator: 0,
        resource_pool_index: 0,
        time_gap_slots: 0,
        start_subchannel: 0,
        num_subchannels: 0,
        time_resource_offsets: vec![],
        mcs: 0x1F,
        psfch_to_harq_timing_k: 0,
        pucch_resource_indicator: 0,
        grant_type: SlGrantType::ConfiguredGrantType2Deactivation { cg_id: 2 },
    };
    allocator.process_cg_dci(&deact_dci).expect("Deactivate CG Type 2");

    // Advance further slots -> no more transmissions
    for _ in 36..=50 {
        assert!(allocator.advance_slot().is_empty());
    }
    assert_eq!(allocator.telemetry().cg_type2_occasions, 2);
}

// ---------------------------------------------------------------------------
// Test 5: Dynamic Grant Scheduling from Received SL-BSR
// ---------------------------------------------------------------------------
#[test]
fn test_dynamic_grant_scheduler_from_bsr() {
    let mut allocator = SidelinkMode1Allocator::new(10); // 10 subchannels pool

    // Submit BSR from UE 0x1001 (needs ~150 bytes -> 2 subchannels)
    let bsr1 = SlBsrMacCe::new(vec![SlBsrEntry::new(1, 0, 10).unwrap()]);
    allocator.submit_sl_bsr(0x1001, bsr1);

    // Submit BSR from UE 0x1002 (needs ~300 bytes -> 3 subchannels)
    let bsr2 = SlBsrMacCe::new(vec![SlBsrEntry::new(2, 1, 20).unwrap()]);
    allocator.submit_sl_bsr(0x1002, bsr2);

    // Schedule dynamic grants for this slot (pool limit = 10 subchannels)
    let grants = allocator.schedule_dynamic_grants(10);

    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].0, 0x1001);
    assert_eq!(grants[0].1.start_subchannel, 0);

    assert_eq!(grants[1].0, 0x1002);
    assert_eq!(grants[1].1.start_subchannel, grants[0].1.num_subchannels);

    assert_eq!(allocator.telemetry().dynamic_grants_issued, 2);
    assert!(allocator.telemetry().total_sidelink_bytes_scheduled > 400);
}

// ---------------------------------------------------------------------------
// Test 6: Cross-Interface HARQ-ACK Feedback Relaying (PC5 PSFCH -> Uu PUCCH)
// ---------------------------------------------------------------------------
#[test]
fn test_cross_interface_psfch_to_uu_harq_relay() {
    let mut allocator = SidelinkMode1Allocator::new(MAX_SL_SUBCHANNELS);

    // Sidelink TB 1 receives ACK on PSFCH, timing indicator k = 3, PRI = 2
    let report1 = allocator.relay_psfch_to_uu_harq(true, 3, 2);
    assert_eq!(report1.pc5_harq_ack, true);
    assert_eq!(report1.target_pucch_slot, allocator.current_slot() + 3);
    assert_eq!(report1.pucch_resource_indicator, 2);

    // Sidelink TB 2 receives NACK on PSFCH
    let report2 = allocator.relay_psfch_to_uu_harq(false, 3, 2);
    assert_eq!(report2.pc5_harq_ack, false);

    let telem = allocator.telemetry();
    assert_eq!(telem.cross_interface_harq_relayed, 2);
    assert_eq!(telem.successful_pc5_deliveries, 1);
    assert_eq!(telem.pc5_delivery_success_rate(), 50.0);
}

// ---------------------------------------------------------------------------
// Test 7: Edge Cases and Error Handling
// ---------------------------------------------------------------------------
#[test]
fn test_edge_cases_and_error_handling() {
    let mut allocator = SidelinkMode1Allocator::new(10);

    // Invalid LCG ID (> 7)
    let bad_lcg = SlBsrEntry::new(0, 8, 10);
    assert!(matches!(bad_lcg, Err(SlMode1Error::InvalidLcg(8))));

    // Activate non-existent CG
    let bad_act = DciFormat3_0 {
        carrier_indicator: 0,
        resource_pool_index: 0,
        time_gap_slots: 0,
        start_subchannel: 0,
        num_subchannels: 2,
        time_resource_offsets: vec![],
        mcs: 10,
        psfch_to_harq_timing_k: 0,
        pucch_resource_indicator: 0,
        grant_type: SlGrantType::ConfiguredGrantType2Activation { cg_id: 99 },
    };
    assert_eq!(
        allocator.process_cg_dci(&bad_act),
        Err(SlMode1Error::ConfiguredGrantNotFound(99))
    );
}
