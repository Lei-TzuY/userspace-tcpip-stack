//! Integration Tests for 3GPP Rel-18 Sidelink Carrier Aggregation (SL-CA) Engine.
//!
//! Validates:
//! 1. Multi-carrier configuration across Primary (PSLCC) and Secondary (SSLCC) carriers.
//! 2. Cross-carrier scheduling with 3-bit Carrier Indicator Field (CIF) in SCI Format 1-A.
//! 3. Autonomous congestion offloading based on per-carrier Channel Busy Ratio ($CBR$).
//! 4. Multi-carrier capacity limits, resource allocation boundaries, and error conditions.

use toy_tcpip::nr_sidelink_ca::{
    SlCaEngine, SlCaError, SlCaSciFormat1A, SlCarrierConfig, DEFAULT_CBR_CONGESTION_THRESHOLD,
    MAX_SL_CARRIERS, PRIMARY_SL_CARRIER_ID,
};

#[test]
fn test_sl_ca_multi_carrier_registration_and_limits() {
    let p_carrier = SlCarrierConfig::new_primary(5_900_000_000.0, 10, 20);
    let mut engine = SlCaEngine::new(p_carrier);

    assert_eq!(engine.carriers.len(), 1);
    assert_eq!(MAX_SL_CARRIERS, 8);
    assert_eq!(PRIMARY_SL_CARRIER_ID, 0);

    // Register secondary carriers 1 through 7 (total 8 carriers)
    for cid in 1..8 {
        let freq = 5_900_000_000.0 + (cid as f64) * 10_000_000.0;
        let s_carrier = SlCarrierConfig::new_secondary(cid, freq, 10, 20).expect("Valid CID");
        assert!(engine.add_secondary_carrier(s_carrier).is_ok());
    }
    assert_eq!(engine.carriers.len(), 8);

    // Adding 9th carrier must fail with ExceededMaxCarriers
    let extra_carrier = SlCarrierConfig::new_secondary(7, 6_000_000_000.0, 10, 20).unwrap();
    assert_eq!(
        engine.add_secondary_carrier(extra_carrier),
        Err(SlCaError::ExceededMaxCarriers(8))
    );

    // Duplicate carrier check
    let mut small_engine = SlCaEngine::new(SlCarrierConfig::new_primary(5.9e9, 10, 20));
    let s1 = SlCarrierConfig::new_secondary(1, 5.91e9, 10, 20).unwrap();
    assert!(small_engine.add_secondary_carrier(s1.clone()).is_ok());
    assert_eq!(
        small_engine.add_secondary_carrier(s1),
        Err(SlCaError::CarrierAlreadyExists(1))
    );
}

#[test]
fn test_sci_format_1a_cif_binary_serialization_fidelity() {
    // Priority 2, CIF 3, Subchannel start 5, Num subchannels 4, MCS 22
    let sci = SlCaSciFormat1A::new(3, 2, 5, 4, 22).expect("Valid SCI");
    assert_eq!(sci.cif, 3);
    assert_eq!(sci.priority, 2);
    assert_eq!(sci.starting_subchannel, 5);
    assert_eq!(sci.num_subchannels, 4);
    assert_eq!(sci.mcs, 22);

    let bytes = sci.serialize();
    assert_eq!(bytes.len(), 6);

    let restored = SlCaSciFormat1A::deserialize(&bytes);
    assert_eq!(sci, restored);

    // Boundary check for invalid CIF (>7) and invalid Priority (>7)
    let invalid_cif = SlCaSciFormat1A::new(8, 0, 0, 1, 10);
    assert_eq!(invalid_cif, Err(SlCaError::InvalidCif(8)));

    let invalid_prio = SlCaSciFormat1A::new(1, 8, 0, 1, 10);
    assert_eq!(invalid_prio, Err(SlCaError::InvalidPriority(8)));
}

#[test]
fn test_intelligent_cross_carrier_congestion_offload() {
    let p_carrier = SlCarrierConfig::new_primary(5_900_000_000.0, 12, 20);
    let mut engine = SlCaEngine::new(p_carrier);

    // Add Secondary CC#1 and Secondary CC#2
    let s1 = SlCarrierConfig::new_secondary(1, 5_910_000_000.0, 12, 20).unwrap();
    let s2 = SlCarrierConfig::new_secondary(2, 5_920_000_000.0, 12, 20).unwrap();
    engine.add_secondary_carrier(s1).unwrap();
    engine.add_secondary_carrier(s2).unwrap();

    // 1. Primary is clear (CBR 0.30 < 0.75 threshold) -> Same-carrier scheduling on CC#0
    engine.update_congestion(0, 0.30, 0.01).unwrap();
    engine.update_congestion(1, 0.20, 0.01).unwrap();
    engine.update_congestion(2, 0.25, 0.01).unwrap();

    let tx1 = engine.schedule_transmission(1, 1000, 6, 18).unwrap();
    assert_eq!(tx1.data_carrier_id, 0);
    assert_eq!(tx1.control_carrier_id, 0);
    assert!(!tx1.is_cross_carrier);
    assert_eq!(tx1.sci.cif, 0);

    // 2. Primary CC#0 becomes heavily congested (CBR 0.88 > 0.75)
    // Secondary CC#1 is also congested (CBR 0.82 > 0.75)
    // Secondary CC#2 is clear (CBR 0.15)
    engine.update_congestion(0, 0.88, 0.04).unwrap();
    engine.update_congestion(1, 0.82, 0.03).unwrap();
    engine.update_congestion(2, 0.15, 0.01).unwrap();

    // Engine must automatically offload to least congested carrier (CC#2)
    let tx2 = engine.schedule_transmission(1, 1000, 6, 18).unwrap();
    assert_eq!(tx2.data_carrier_id, 2);
    assert_eq!(tx2.control_carrier_id, 0); // Control still transmitted on Primary CC
    assert!(tx2.is_cross_carrier);
    assert_eq!(tx2.sci.cif, 2);

    assert_eq!(engine.stats_transmissions_scheduled, 2);
    assert_eq!(engine.stats_cross_carrier_scheds, 1);
    assert_eq!(engine.stats_congestion_offloads, 1);
}

#[test]
fn test_resource_exhaustion_error_handling() {
    let p_carrier = SlCarrierConfig::new_primary(5_900_000_000.0, 8, 20);
    let mut engine = SlCaEngine::new(p_carrier);

    // Requesting 12 subchannels when only 8 are available
    let res = engine.schedule_transmission(0, 500, 12, 16);
    assert_eq!(
        res,
        Err(SlCaError::InsufficientSubchannels {
            requested: 12,
            available: 8
        })
    );

    // Updating non-existent carrier
    let bad_update = engine.update_congestion(99, 0.5, 0.01);
    assert_eq!(bad_update, Err(SlCaError::CarrierNotFound(99)));

    // Congestion threshold default check
    assert_eq!(DEFAULT_CBR_CONGESTION_THRESHOLD, 0.75);
}
