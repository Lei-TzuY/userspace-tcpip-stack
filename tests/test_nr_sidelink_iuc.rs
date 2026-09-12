//! Integration tests for 3GPP Rel-18 Sidelink Inter-UE Coordination (IUC) Engine.

use toy_tcpip::nr_sidelink_iuc::{
    DEFAULT_IUC_RSRP_THRESHOLD_DBM, IucConfig, IucSchemeType, SciFormat2C, SidelinkIucEngine,
    SidelinkReservationEntry, SidelinkSlotResource,
};

#[test]
fn test_sci_format_2c_binary_wire_codec_roundtrip() {
    let sci_pref = SciFormat2C {
        scheme_type: IucSchemeType::Scheme1Preferred,
        requesting_ue_id: 0x112233,
        coordinating_ue_id: 0x445566,
        priority: 2,
        starting_slot: 1000,
        slot_count: 16,
        resource_bitmap: vec![0xAA, 0x55, 0xF0, 0x0F],
    };

    let encoded = sci_pref.encode();
    let decoded = SciFormat2C::decode(&encoded).expect("Decode SCI 2-C failed");
    assert_eq!(sci_pref, decoded);

    let sci_conflict = SciFormat2C {
        scheme_type: IucSchemeType::Scheme2ConflictNotification,
        requesting_ue_id: 0x998877,
        coordinating_ue_id: 0x665544,
        priority: 0,
        starting_slot: 2500,
        slot_count: 4,
        resource_bitmap: vec![0xC0],
    };

    let encoded_conf = sci_conflict.encode();
    let decoded_conf = SciFormat2C::decode(&encoded_conf).expect("Decode conflict SCI failed");
    assert_eq!(sci_conflict, decoded_conf);
}

#[test]
fn test_scheme1_preferred_set_generation_and_filtering() {
    let mut ue_b = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 200,
        total_subchannels: 2,
        rsrp_threshold_dbm: DEFAULT_IUC_RSRP_THRESHOLD_DBM,
        min_candidate_ratio: 0.20,
    });

    let mut ue_a = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 100,
        total_subchannels: 2,
        rsrp_threshold_dbm: DEFAULT_IUC_RSRP_THRESHOLD_DBM,
        min_candidate_ratio: 0.20,
    });

    // Hidden node UE-C transmits and reserves slot 102 subchannel 0, slot 104 subchannel 1
    ue_b.record_peer_reservation(SidelinkReservationEntry {
        transmitting_ue_id: 300,
        target_ue_id: 0xFFFFFF,
        slot_reserved: 102,
        subchannel: 0,
        priority: 2,
        sl_rsrp_dbm: -80, // Strong signal at UE-B
        reservation_period_slots: 0,
    });
    ue_b.record_peer_reservation(SidelinkReservationEntry {
        transmitting_ue_id: 300,
        target_ue_id: 0xFFFFFF,
        slot_reserved: 104,
        subchannel: 1,
        priority: 2,
        sl_rsrp_dbm: -82,
        reservation_period_slots: 0,
    });

    // UE-B generates Scheme 1 Preferred set for UE-A across slots 100..107 (8 slots, 2 subch = 16 resources)
    let (sci_pref, preferred_set) = ue_b.generate_scheme1_coordination(
        100, // requesting UE-A
        2,   // priority
        100, // start_slot
        8,   // slot_count
        true,
    );
    assert_eq!(sci_pref.scheme_type, IucSchemeType::Scheme1Preferred);
    assert!(!preferred_set.contains(&SidelinkSlotResource {
        slot: 102,
        subchannel: 0
    }));
    assert!(!preferred_set.contains(&SidelinkSlotResource {
        slot: 104,
        subchannel: 1
    }));
    assert!(preferred_set.contains(&SidelinkSlotResource {
        slot: 100,
        subchannel: 0
    }));

    // UE-A applies the coordination to its autonomous selection window
    let mut initial_candidates = Vec::new();
    for s in 100..108 {
        for subch in 0..2 {
            initial_candidates.push(SidelinkSlotResource {
                slot: s,
                subchannel: subch,
            });
        }
    }
    assert_eq!(initial_candidates.len(), 16);

    let filtered = ue_a.apply_scheme1_filtering(&sci_pref, &initial_candidates);
    // Colliding resources (102, 0) and (104, 1) are excluded -> 14 remaining
    assert_eq!(filtered.len(), 14);
    assert!(!filtered.contains(&SidelinkSlotResource {
        slot: 102,
        subchannel: 0
    }));
    assert!(!filtered.contains(&SidelinkSlotResource {
        slot: 104,
        subchannel: 1
    }));
}

#[test]
fn test_scheme1_non_preferred_set_and_hidden_node_exclusion() {
    let mut ue_b = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 200,
        total_subchannels: 4,
        rsrp_threshold_dbm: -100,
        min_candidate_ratio: 0.20,
    });

    let mut ue_a = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 100,
        total_subchannels: 4,
        rsrp_threshold_dbm: -100,
        min_candidate_ratio: 0.20,
    });

    // Hidden node UE-C reserves slot 50 subchannel 2
    ue_b.record_peer_reservation(SidelinkReservationEntry {
        transmitting_ue_id: 300,
        target_ue_id: 0xFFFFFF,
        slot_reserved: 50,
        subchannel: 2,
        priority: 1,
        sl_rsrp_dbm: -75,
        reservation_period_slots: 0,
    });

    // UE-B generates Non-Preferred set
    let (sci_non_pref, non_pref_set) = ue_b.generate_scheme1_coordination(
        100, 3, // UE-A has lower priority (3 > 1)
        48, 6, false, // indicate non-preferred
    );
    assert_eq!(sci_non_pref.scheme_type, IucSchemeType::Scheme1NonPreferred);
    assert!(non_pref_set.contains(&SidelinkSlotResource {
        slot: 50,
        subchannel: 2
    }));

    // UE-A filters candidates
    let candidates = vec![
        SidelinkSlotResource {
            slot: 49,
            subchannel: 1,
        },
        SidelinkSlotResource {
            slot: 50,
            subchannel: 2,
        }, // colliding
        SidelinkSlotResource {
            slot: 51,
            subchannel: 0,
        },
    ];
    let filtered = ue_a.apply_scheme1_filtering(&sci_non_pref, &candidates);
    assert_eq!(filtered.len(), 2);
    assert_eq!(
        filtered[0],
        SidelinkSlotResource {
            slot: 49,
            subchannel: 1
        }
    );
    assert_eq!(
        filtered[1],
        SidelinkSlotResource {
            slot: 51,
            subchannel: 0
        }
    );
    assert_eq!(ue_a.stats_hidden_node_collisions_avoided, 1);
}

#[test]
fn test_scheme1_candidate_starvation_20_percent_fallback() {
    let mut ue_b = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 200,
        total_subchannels: 2,
        rsrp_threshold_dbm: -105,
        min_candidate_ratio: 0.20,
    });

    let mut ue_a = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 100,
        total_subchannels: 2,
        rsrp_threshold_dbm: -105,
        min_candidate_ratio: 0.20,
    });

    // Heavy congestion: hidden nodes occupy 9 out of 10 candidate resources
    for s in 10..15 {
        for subch in 0..2 {
            if s == 14 && subch == 1 {
                continue; // Only 1 resource left idle
            }
            ue_b.record_peer_reservation(SidelinkReservationEntry {
                transmitting_ue_id: 500,
                target_ue_id: 0xFFFFFF,
                slot_reserved: s,
                subchannel: subch,
                priority: 0,
                sl_rsrp_dbm: -70,
                reservation_period_slots: 0,
            });
        }
    }

    let (sci_pref, _pref) = ue_b.generate_scheme1_coordination(100, 2, 10, 5, true);

    let mut initial_candidates = Vec::new();
    for s in 10..15 {
        for subch in 0..2 {
            initial_candidates.push(SidelinkSlotResource {
                slot: s,
                subchannel: subch,
            });
        }
    }
    assert_eq!(initial_candidates.len(), 10);

    // Filtered set would only be 1 candidate (10% < 20% threshold)
    // Starvation fallback restores original candidate pool!
    let filtered = ue_a.apply_scheme1_filtering(&sci_pref, &initial_candidates);
    assert_eq!(filtered.len(), 10);
}

#[test]
fn test_scheme2_condition_triggered_conflict_detection() {
    let mut ue_b = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 200,
        total_subchannels: 4,
        rsrp_threshold_dbm: -105,
        min_candidate_ratio: 0.20,
    });

    // Peer UE-C reserved slot 80, subchannel 3
    ue_b.record_peer_reservation(SidelinkReservationEntry {
        transmitting_ue_id: 300,
        target_ue_id: 0xFFFFFF,
        slot_reserved: 80,
        subchannel: 3,
        priority: 1,
        sl_rsrp_dbm: -85,
        reservation_period_slots: 0,
    });

    // UE-A attempts to reserve the exact same resource (slot 80, subchannel 3)
    let conflict = ue_b.evaluate_scheme2_conflicts(
        100, // UE-A
        80,  // slot
        3,   // subchannel
        2,   // priority
    );

    assert!(conflict.is_some());
    let alert = conflict.unwrap();
    assert_eq!(alert.colliding_slot, 80);
    assert_eq!(alert.colliding_subchannel, 3);
    assert_eq!(alert.colliding_peer_id, 300);
    assert_eq!(ue_b.stats_scheme2_conflicts_detected, 1);
}

#[test]
fn test_scheme2_preemption_and_re_evaluation() {
    let mut ue_a = SidelinkIucEngine::new(IucConfig {
        local_ue_id: 100,
        total_subchannels: 4,
        rsrp_threshold_dbm: -105,
        min_candidate_ratio: 0.20,
    });

    // UE-A previously scheduled slot 80, subchannel 3
    ue_a.schedule_own_transmission(80, 3);
    assert_eq!(ue_a.own_reservations.len(), 1);

    let conflict = toy_tcpip::nr_sidelink_iuc::IucConflictNotification {
        colliding_slot: 80,
        colliding_subchannel: 3,
        ue_a_id: 100,
        ue_a_priority: 2,
        colliding_peer_id: 300,
        colliding_peer_priority: 1,
        reason: "Imminent collision with hidden peer",
    };

    let available_candidates = vec![
        SidelinkSlotResource {
            slot: 80,
            subchannel: 3,
        }, // colliding
        SidelinkSlotResource {
            slot: 82,
            subchannel: 1,
        }, // clean alternative
        SidelinkSlotResource {
            slot: 83,
            subchannel: 2,
        },
    ];

    let alternative = ue_a.handle_scheme2_conflict(&conflict, &available_candidates);
    assert!(alternative.is_some());
    let alt_res = alternative.unwrap();
    assert_eq!(
        alt_res,
        SidelinkSlotResource {
            slot: 82,
            subchannel: 1
        }
    );

    // Conflicting reservation on slot 80 was removed and replaced by slot 82!
    assert!(!ue_a.own_reservations.contains_key(&80));
    assert!(ue_a.own_reservations.contains_key(&82));
    assert_eq!(ue_a.stats_re_evaluations_triggered, 1);
    assert_eq!(ue_a.stats_hidden_node_collisions_avoided, 1);
}
