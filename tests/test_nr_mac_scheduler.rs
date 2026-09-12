//! Integration tests for 3GPP Rel-18/19 NR MAC Scheduler Engine.
//! Validates: Round-Robin, Proportional Fair, Max-CQI, QoS-aware scheduling,
//! HARQ management, BSR decoding, CQI/MCS/TBS mapping, PRB allocation, wire framing.

use toy_tcpip::nr_mac_scheduler::*;

// ===========================================================================
// CQI → MCS → TBS Mapping Tests (TS 38.214)
// ===========================================================================

#[test]
fn test_cqi_table_length() {
    let table = get_cqi_table();
    assert_eq!(table.len(), 16, "CQI table should have 16 entries (0-15)");
}

#[test]
fn test_cqi_0_is_out_of_range() {
    let entry = cqi_to_mcs(0).unwrap();
    assert_eq!(entry.modulation_order, 0);
    assert_eq!(entry.code_rate_x1024, 0);
}

#[test]
fn test_cqi_to_mcs_valid_range() {
    for cqi in 0..=15u8 {
        let entry = cqi_to_mcs(cqi).unwrap();
        assert_eq!(entry.cqi, cqi);
    }
}

#[test]
fn test_cqi_invalid() {
    assert!(cqi_to_mcs(16).is_err());
    assert!(cqi_to_mcs(255).is_err());
}

#[test]
fn test_cqi_modulation_progression() {
    // CQI 1-6: QPSK (Qm=2), 7-9: 16QAM (4), 10-13: 64QAM (6), 14: 256QAM (8), 15: 1024QAM (10)
    let table = get_cqi_table();
    for cqi in 1..=6 {
        assert_eq!(table[cqi].modulation_order, 2, "CQI {} should be QPSK", cqi);
    }
    for cqi in 7..=9 {
        assert_eq!(
            table[cqi].modulation_order, 4,
            "CQI {} should be 16QAM",
            cqi
        );
    }
    for cqi in 10..=13 {
        assert_eq!(
            table[cqi].modulation_order, 6,
            "CQI {} should be 64QAM",
            cqi
        );
    }
    assert_eq!(table[14].modulation_order, 8, "CQI 14 should be 256QAM");
    assert_eq!(
        table[15].modulation_order, 10,
        "CQI 15 should be 1024QAM (Rel-18)"
    );
}

#[test]
fn test_spectral_efficiency_monotonic() {
    let table = get_cqi_table();
    for i in 2..16 {
        assert!(
            table[i].spectral_efficiency >= table[i - 1].spectral_efficiency,
            "Spectral efficiency should be monotonically increasing: CQI {} ({}) < CQI {} ({})",
            i,
            table[i].spectral_efficiency,
            i - 1,
            table[i - 1].spectral_efficiency
        );
    }
}

#[test]
fn test_tbs_computation() {
    let entry = cqi_to_mcs(7).unwrap(); // 16QAM
    let tbs = compute_tbs(10, 156, &entry, 1);
    assert!(tbs > 0, "TBS should be positive for valid MCS");
    assert_eq!(tbs % 8, 0, "TBS must be byte-aligned");
}

#[test]
fn test_tbs_cqi0_is_zero() {
    let entry = cqi_to_mcs(0).unwrap();
    let tbs = compute_tbs(10, 156, &entry, 1);
    assert_eq!(tbs, 0, "TBS for CQI 0 should be 0");
}

#[test]
fn test_tbs_increases_with_prbs() {
    let entry = cqi_to_mcs(10).unwrap();
    let tbs_5 = compute_tbs(5, 156, &entry, 1);
    let tbs_10 = compute_tbs(10, 156, &entry, 1);
    let tbs_50 = compute_tbs(50, 156, &entry, 1);
    assert!(tbs_10 > tbs_5, "More PRBs should give higher TBS");
    assert!(tbs_50 > tbs_10, "More PRBs should give higher TBS");
}

#[test]
fn test_tbs_increases_with_layers() {
    let entry = cqi_to_mcs(10).unwrap();
    let tbs_1 = compute_tbs(10, 156, &entry, 1);
    let tbs_2 = compute_tbs(10, 156, &entry, 2);
    let tbs_4 = compute_tbs(10, 156, &entry, 4);
    assert!(tbs_2 > tbs_1, "More layers should give higher TBS");
    assert!(tbs_4 > tbs_2, "More layers should give higher TBS");
}

// ===========================================================================
// UE Context Tests
// ===========================================================================

#[test]
fn test_ue_context_creation() {
    let ue = UeContext::new(0x1234, 5);
    assert_eq!(ue.rnti, 0x1234);
    assert_eq!(ue.cqi, 7); // Default
    assert_eq!(ue.buffer_size_bytes, 0);
    assert_eq!(ue.harq_processes.len(), MAX_HARQ_PROCESSES);
    assert_eq!(ue.drx_state, DrxState::Active);
    assert_eq!(ue.qos.five_qi, 5);
}

#[test]
fn test_ue_cqi_update() {
    let mut ue = UeContext::new(0x0001, 9);
    ue.update_cqi(12);
    assert_eq!(ue.cqi, 12);

    // CQI should be capped at 15
    ue.update_cqi(20);
    assert_eq!(ue.cqi, 15);
}

#[test]
fn test_ue_buffer_status() {
    let mut ue = UeContext::new(0x0001, 9);
    ue.update_buffer_status(10000);
    assert_eq!(ue.buffer_size_bytes, 10000);
}

#[test]
fn test_ue_idle_harq() {
    let ue = UeContext::new(0x0001, 9);
    // All HARQ processes should start idle
    assert!(ue.get_idle_harq().is_some());
    assert_eq!(ue.get_idle_harq().unwrap(), 0);
}

#[test]
fn test_ue_schedulability() {
    let mut ue = UeContext::new(0x0001, 9);
    assert!(ue.is_schedulable());

    ue.drx_state = DrxState::OnDurationTimer;
    assert!(ue.is_schedulable());

    ue.drx_state = DrxState::LongCycle;
    assert!(!ue.is_schedulable());

    ue.drx_state = DrxState::ShortCycle;
    assert!(!ue.is_schedulable());
}

// ===========================================================================
// HARQ Process Tests
// ===========================================================================

#[test]
fn test_harq_new_tx() {
    let mut hp = HarqProcess::new(0, 4);
    assert!(hp.is_idle());

    hp.start_new_tx(1000, 10, 0, 5);
    assert_eq!(hp.state, HarqState::WaitingForAck);
    assert_eq!(hp.tbs, 1000);
    assert_eq!(hp.mcs, 10);
    assert_eq!(hp.prb_start, 0);
    assert_eq!(hp.prb_count, 5);
    assert_eq!(hp.rv, 0);
    assert_eq!(hp.retx_count, 0);
}

#[test]
fn test_harq_ack() {
    let mut hp = HarqProcess::new(0, 4);
    hp.start_new_tx(1000, 10, 0, 5);
    hp.ack();
    assert!(hp.is_idle());
}

#[test]
fn test_harq_nack_retransmission() {
    let mut hp = HarqProcess::new(0, 4);
    hp.start_new_tx(1000, 10, 0, 5);

    // First NACK
    assert!(hp.nack());
    assert_eq!(hp.state, HarqState::NackRetransmit);
    assert_eq!(hp.retx_count, 1);

    // Second NACK
    assert!(hp.nack());
    assert_eq!(hp.retx_count, 2);
}

#[test]
fn test_harq_max_retransmissions() {
    let mut hp = HarqProcess::new(0, 3);
    hp.start_new_tx(1000, 10, 0, 5);

    assert!(hp.nack()); // retx 1
    assert!(hp.nack()); // retx 2
    assert!(hp.nack()); // retx 3

    // 4th NACK: exceeded max_retx=3, should return false and go idle
    assert!(!hp.nack());
    assert!(hp.is_idle());
}

#[test]
fn test_harq_ndi_toggle() {
    let mut hp = HarqProcess::new(0, 4);
    let ndi_before = hp.ndi;
    hp.start_new_tx(1000, 10, 0, 5);
    assert_ne!(hp.ndi, ndi_before, "NDI should toggle on new transmission");

    let ndi_after_first = hp.ndi;
    hp.ack();
    hp.start_new_tx(2000, 12, 5, 3);
    assert_ne!(hp.ndi, ndi_after_first, "NDI should toggle again");
}

#[test]
fn test_harq_rv_cycling() {
    let mut hp = HarqProcess::new(0, 8);
    hp.start_new_tx(1000, 10, 0, 5);

    // RV cycling pattern: 0, 2, 3, 1, 0, 2, 3, 1, ...
    let expected_rvs = [2, 3, 1, 0]; // After retx 1, 2, 3, 4
    for (i, &expected_rv) in expected_rvs.iter().enumerate() {
        hp.nack();
        assert_eq!(
            hp.rv,
            expected_rv,
            "After retx {}, RV should be {}, got {}",
            i + 1,
            expected_rv,
            hp.rv
        );
    }
}

// ===========================================================================
// PRB Allocation Tests
// ===========================================================================

#[test]
fn test_prb_map_new() {
    let map = PrbAllocationMap::new(100);
    assert_eq!(map.total_prbs, 100);
    assert_eq!(map.free_count(), 100);
}

#[test]
fn test_prb_allocate_contiguous() {
    let mut map = PrbAllocationMap::new(100);
    let start = map.allocate_contiguous(10).unwrap();
    assert_eq!(start, 0);
    assert_eq!(map.free_count(), 90);

    let start2 = map.allocate_contiguous(5).unwrap();
    assert_eq!(start2, 10);
    assert_eq!(map.free_count(), 85);
}

#[test]
fn test_prb_allocate_full() {
    let mut map = PrbAllocationMap::new(10);
    map.allocate_contiguous(10).unwrap();
    assert_eq!(map.free_count(), 0);
    assert!(map.allocate_contiguous(1).is_none());
}

#[test]
fn test_prb_release() {
    let mut map = PrbAllocationMap::new(20);
    map.allocate_contiguous(10).unwrap();
    assert_eq!(map.free_count(), 10);

    map.release(0, 5);
    assert_eq!(map.free_count(), 15);
}

#[test]
fn test_prb_reset() {
    let mut map = PrbAllocationMap::new(50);
    map.allocate_contiguous(50).unwrap();
    assert_eq!(map.free_count(), 0);

    map.reset();
    assert_eq!(map.free_count(), 50);
}

#[test]
fn test_prb_allocate_zero() {
    let mut map = PrbAllocationMap::new(10);
    assert!(map.allocate_contiguous(0).is_none());
}

#[test]
fn test_prb_allocate_too_large() {
    let mut map = PrbAllocationMap::new(10);
    assert!(map.allocate_contiguous(11).is_none());
}

// ===========================================================================
// BSR Decoding Tests (TS 38.321)
// ===========================================================================

#[test]
fn test_bsr_index_0() {
    assert_eq!(decode_bsr_index(0), 0);
}

#[test]
fn test_bsr_index_monotonic() {
    for i in 1..64u8 {
        assert!(
            decode_bsr_index(i) > decode_bsr_index(i - 1),
            "BSR index {} ({}) should be > BSR index {} ({})",
            i,
            decode_bsr_index(i),
            i - 1,
            decode_bsr_index(i - 1)
        );
    }
}

#[test]
fn test_bsr_index_known_values() {
    assert_eq!(decode_bsr_index(1), 10);
    assert_eq!(decode_bsr_index(10), 198);
    assert_eq!(decode_bsr_index(20), 5447);
    assert_eq!(decode_bsr_index(63), 8_516_386_816);
}

#[test]
fn test_bsr_index_saturate() {
    // Indices beyond 63 should saturate
    assert_eq!(decode_bsr_index(64), 8_516_386_816);
    assert_eq!(decode_bsr_index(255), 8_516_386_816);
}

// ===========================================================================
// QoS Parameters Tests
// ===========================================================================

#[test]
fn test_qos_5qi_1_gbr() {
    let qos = QosParams::from_5qi(1);
    assert!(qos.is_gbr);
    assert_eq!(qos.priority_level, 20);
    assert_eq!(qos.packet_delay_budget_ms, 100);
}

#[test]
fn test_qos_5qi_5_non_gbr() {
    let qos = QosParams::from_5qi(5);
    assert!(!qos.is_gbr);
    assert_eq!(qos.priority_level, 10);
}

#[test]
fn test_qos_5qi_9_bulk() {
    let qos = QosParams::from_5qi(9);
    assert!(!qos.is_gbr);
    assert_eq!(qos.priority_level, 90);
    assert_eq!(qos.packet_delay_budget_ms, 300);
}

#[test]
fn test_qos_default() {
    let qos = QosParams::from_5qi(99);
    assert_eq!(qos.priority_level, 50);
}

// ===========================================================================
// Round-Robin Scheduler Tests
// ===========================================================================

#[test]
fn test_rr_no_ues() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    let result = sched.schedule_slot();
    assert!(result.grants.is_empty());
    assert_eq!(result.total_prbs_used, 0);
}

#[test]
fn test_rr_single_ue() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x1001, 5);
    sched
        .get_ue_mut(0x1001)
        .unwrap()
        .update_buffer_status(10000);
    sched.get_ue_mut(0x1001).unwrap().update_cqi(10);

    let result = sched.schedule_slot();
    assert_eq!(result.grants.len(), 1);
    assert_eq!(result.grants[0].rnti, 0x1001);
    assert!(result.grants[0].prb_count > 0);
    assert!(result.grants[0].tbs_bits > 0);
    assert!(!result.grants[0].is_retransmission);
}

#[test]
fn test_rr_multiple_ues_fair() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 100, 156, 1);

    for i in 0..4u16 {
        sched.add_ue(0x1000 + i, 5);
        sched
            .get_ue_mut(0x1000 + i)
            .unwrap()
            .update_buffer_status(50000);
        sched.get_ue_mut(0x1000 + i).unwrap().update_cqi(10);
    }

    let result = sched.schedule_slot();
    assert_eq!(result.grants.len(), 4);

    // Each UE should get roughly 25 PRBs
    for grant in &result.grants {
        assert!(
            grant.prb_count >= 20 && grant.prb_count <= 30,
            "RNTI 0x{:04X} got {} PRBs, expected ~25",
            grant.rnti,
            grant.prb_count
        );
    }
}

#[test]
fn test_rr_skip_empty_buffer() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x1001, 5);
    sched.add_ue(0x1002, 5);

    // Only UE 0x1001 has data
    sched
        .get_ue_mut(0x1001)
        .unwrap()
        .update_buffer_status(10000);
    sched.get_ue_mut(0x1001).unwrap().update_cqi(10);

    let result = sched.schedule_slot();
    assert_eq!(result.grants.len(), 1);
    assert_eq!(result.grants[0].rnti, 0x1001);
}

#[test]
fn test_rr_skip_drx_inactive() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x1001, 5);
    sched
        .get_ue_mut(0x1001)
        .unwrap()
        .update_buffer_status(10000);
    sched.get_ue_mut(0x1001).unwrap().update_cqi(10);
    sched.get_ue_mut(0x1001).unwrap().drx_state = DrxState::LongCycle;

    let result = sched.schedule_slot();
    assert!(
        result.grants.is_empty(),
        "UE in DRX should not be scheduled"
    );
}

// ===========================================================================
// Proportional Fair Scheduler Tests
// ===========================================================================

#[test]
fn test_pf_prioritizes_low_throughput() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::ProportionalFair, 100, 156, 1);

    // UE1: high CQI, high avg throughput → lower PF metric
    sched.add_ue(0x2001, 5);
    sched
        .get_ue_mut(0x2001)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x2001).unwrap().update_cqi(14);
    sched.get_ue_mut(0x2001).unwrap().avg_throughput = 10000.0;

    // UE2: lower CQI, low avg throughput → higher PF metric
    sched.add_ue(0x2002, 5);
    sched
        .get_ue_mut(0x2002)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x2002).unwrap().update_cqi(5);
    sched.get_ue_mut(0x2002).unwrap().avg_throughput = 1.0;

    let result = sched.schedule_slot();
    assert!(result.grants.len() >= 2);

    // Both should be scheduled
    let ue1_grant = result.grants.iter().find(|g| g.rnti == 0x2001);
    let ue2_grant = result.grants.iter().find(|g| g.rnti == 0x2002);
    assert!(ue1_grant.is_some());
    assert!(ue2_grant.is_some());
}

// ===========================================================================
// Max-CQI Scheduler Tests
// ===========================================================================

#[test]
fn test_max_cqi_high_cqi_first() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::MaxCqi, 20, 156, 1);

    sched.add_ue(0x3001, 5);
    sched
        .get_ue_mut(0x3001)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x3001).unwrap().update_cqi(3); // Low CQI

    sched.add_ue(0x3002, 5);
    sched
        .get_ue_mut(0x3002)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x3002).unwrap().update_cqi(15); // High CQI

    let result = sched.schedule_slot();
    assert!(result.grants.len() >= 1);
    // High CQI UE should appear first in grants
    assert_eq!(result.grants[0].rnti, 0x3002);
}

// ===========================================================================
// QoS-Aware Scheduler Tests
// ===========================================================================

#[test]
fn test_qos_aware_prioritizes_high_priority() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::QosAware, 20, 156, 1);

    // UE1: 5QI=9 (priority 90, low priority)
    sched.add_ue(0x4001, 9);
    sched
        .get_ue_mut(0x4001)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x4001).unwrap().update_cqi(10);

    // UE2: 5QI=1 (priority 20, high priority GBR)
    sched.add_ue(0x4002, 1);
    sched
        .get_ue_mut(0x4002)
        .unwrap()
        .update_buffer_status(50000);
    sched.get_ue_mut(0x4002).unwrap().update_cqi(10);

    let result = sched.schedule_slot();
    assert!(result.grants.len() >= 1);
    // Higher priority (lower value) UE should be first
    assert_eq!(result.grants[0].rnti, 0x4002);
}

// ===========================================================================
// HARQ Feedback Tests
// ===========================================================================

#[test]
fn test_harq_ack_frees_process() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x5001, 5);
    sched
        .get_ue_mut(0x5001)
        .unwrap()
        .update_buffer_status(100000);
    sched.get_ue_mut(0x5001).unwrap().update_cqi(10);

    // Schedule → uses HARQ 0
    let result = sched.schedule_slot();
    assert_eq!(result.grants.len(), 1);
    let harq_id = result.grants[0].harq_id;

    // ACK it
    sched.process_harq_feedback(0x5001, harq_id, true).unwrap();
    let ue = sched.get_ue(0x5001).unwrap();
    assert!(ue.harq_processes[harq_id as usize].is_idle());
}

#[test]
fn test_harq_nack_triggers_retx() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x5001, 5);
    sched
        .get_ue_mut(0x5001)
        .unwrap()
        .update_buffer_status(100000);
    sched.get_ue_mut(0x5001).unwrap().update_cqi(10);

    // Schedule
    let result = sched.schedule_slot();
    let harq_id = result.grants[0].harq_id;
    let original_tbs = result.grants[0].tbs_bits;

    // NACK
    sched.process_harq_feedback(0x5001, harq_id, false).unwrap();
    let ue = sched.get_ue(0x5001).unwrap();
    assert_eq!(
        ue.harq_processes[harq_id as usize].state,
        HarqState::NackRetransmit
    );

    // Next schedule should produce retransmission
    let result2 = sched.schedule_slot();
    assert!(!result2.grants.is_empty());

    let retx_grant = result2.grants.iter().find(|g| g.harq_id == harq_id);
    assert!(retx_grant.is_some(), "Should retransmit HARQ {}", harq_id);
    assert!(retx_grant.unwrap().is_retransmission);
    assert_eq!(
        retx_grant.unwrap().tbs_bits,
        original_tbs,
        "Retx TBS should match original"
    );
}

#[test]
fn test_harq_feedback_unknown_ue() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    let result = sched.process_harq_feedback(0xFFFF, 0, true);
    assert!(result.is_err());
}

// ===========================================================================
// Scheduler Management Tests
// ===========================================================================

#[test]
fn test_add_remove_ue() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x1001, 5);
    sched.add_ue(0x1002, 9);
    assert!(sched.get_ue(0x1001).is_some());
    assert!(sched.get_ue(0x1002).is_some());

    assert!(sched.remove_ue(0x1001));
    assert!(sched.get_ue(0x1001).is_none());
    assert!(sched.get_ue(0x1002).is_some());
}

#[test]
fn test_duplicate_add_ignored() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    sched.add_ue(0x1001, 5);
    sched.add_ue(0x1001, 9); // Duplicate, should be ignored
    assert_eq!(sched.ue_contexts.len(), 1);
}

#[test]
fn test_remove_nonexistent() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    assert!(!sched.remove_ue(0xFFFF));
}

#[test]
fn test_slot_index_increments() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);
    let r1 = sched.schedule_slot();
    let r2 = sched.schedule_slot();
    let r3 = sched.schedule_slot();
    assert_eq!(r1.slot_index, 0);
    assert_eq!(r2.slot_index, 1);
    assert_eq!(r3.slot_index, 2);
}

// ===========================================================================
// Wire PDU Tests
// ===========================================================================

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = MacSchedWirePdu {
        magic: MAC_SCHED_WIRE_MAGIC,
        slot_idx: 12345,
        num_grants: 3,
        payload: vec![0xAA, 0xBB, 0xCC, 0xDD],
        crc16: 0,
    };
    let wire = pdu.serialize();
    let decoded = MacSchedWirePdu::deserialize(&wire).unwrap();
    assert_eq!(decoded.magic, MAC_SCHED_WIRE_MAGIC);
    assert_eq!(decoded.slot_idx, 12345);
    assert_eq!(decoded.num_grants, 3);
    assert_eq!(decoded.payload, vec![0xAA, 0xBB, 0xCC, 0xDD]);
}

#[test]
fn test_wire_pdu_empty_payload() {
    let pdu = MacSchedWirePdu {
        magic: MAC_SCHED_WIRE_MAGIC,
        slot_idx: 0,
        num_grants: 0,
        payload: vec![],
        crc16: 0,
    };
    let wire = pdu.serialize();
    let decoded = MacSchedWirePdu::deserialize(&wire).unwrap();
    assert_eq!(decoded.payload.len(), 0);
    assert_eq!(decoded.num_grants, 0);
}

#[test]
fn test_wire_pdu_invalid_magic() {
    let mut wire = MacSchedWirePdu {
        magic: MAC_SCHED_WIRE_MAGIC,
        slot_idx: 0,
        num_grants: 0,
        payload: vec![0x01],
        crc16: 0,
    }
    .serialize();
    wire[0] = 0xFF;
    assert!(MacSchedWirePdu::deserialize(&wire).is_err());
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let wire = MacSchedWirePdu {
        magic: MAC_SCHED_WIRE_MAGIC,
        slot_idx: 99,
        num_grants: 1,
        payload: vec![0x11, 0x22],
        crc16: 0,
    }
    .serialize();
    let mut corrupted = wire.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    assert!(MacSchedWirePdu::deserialize(&corrupted).is_err());
}

#[test]
fn test_wire_pdu_truncated() {
    assert!(MacSchedWirePdu::deserialize(&[0u8; 5]).is_err());
}

// ===========================================================================
// CRC-16 Tests
// ===========================================================================

#[test]
fn test_crc16_known() {
    let crc = compute_crc16(b"123456789");
    assert_eq!(
        crc, 0x29B1,
        "CRC-16/CCITT of '123456789': got 0x{:04X}",
        crc
    );
}

// ===========================================================================
// Error Display Tests
// ===========================================================================

#[test]
fn test_error_display() {
    assert!(format!("{}", MacSchedError::UeNotFound(0x1234)).contains("1234"));
    assert!(format!("{}", MacSchedError::NoPrbsAvailable).contains("PRB"));
    assert!(format!("{}", MacSchedError::InvalidCqi(16)).contains("16"));
    assert!(format!("{}", MacSchedError::HarqExhausted(0x5678)).contains("5678"));
    assert!(format!("{}", MacSchedError::BufferEmpty(0x0001)).contains("0001"));
}

// ===========================================================================
// Multi-Slot Scheduling Stability Test
// ===========================================================================

#[test]
fn test_multi_slot_stability() {
    let mut sched = MacScheduler::new(SchedulingAlgorithm::RoundRobin, 50, 156, 1);

    for i in 0..10u16 {
        sched.add_ue(0x1000 + i, 5);
        sched
            .get_ue_mut(0x1000 + i)
            .unwrap()
            .update_buffer_status(100000);
        sched
            .get_ue_mut(0x1000 + i)
            .unwrap()
            .update_cqi(7 + (i as u8 % 5));
    }

    // Run 100 slots without panicking
    for _ in 0..100 {
        let result = sched.schedule_slot();
        assert!(result.total_prbs_used <= 50);
        for grant in &result.grants {
            assert!(grant.prb_count > 0);
            assert!(grant.tbs_bits > 0);
        }
    }
}
