//! Integration tests for 3GPP Rel-18/19 Uplink Power Control, Pathloss & PHR Engine.

use toy_tcpip::nr_ul_power_control::{
    calculate_power_headroom, calculate_pucch_power, calculate_pusch_power, calculate_prach_power,
    calculate_srs_power, resolve_simultaneous_power_scaling, ChannelPowerRequest, ChannelPriority,
    PucchFormat, PucchPowerConfig, PuschPowerConfig, TpcLoop, TpcMode, UlPowerControlWirePdu,
    UL_PWR_WIRE_MAGIC,
};

#[test]
fn test_pusch_open_loop_and_fractional_pathloss_scaling() {
    let cfg = PuschPowerConfig {
        p_o_nominal_dbm: -90.0,
        p_o_ue_dbm: 0.0,
        alpha: 0.8,
        p_cmax_dbm: 23.0,
        numerology_mu: 1, // 30 kHz SCS
    };

    // 10 PRBs at mu=1: 10 * log10(2 * 10) = 13.0103 dB
    // Pathloss: 80 dB => alpha * PL = 0.8 * 80 = 64 dB
    // Target power: -90 + 13.0103 + 64 = -12.9897 dBm
    let power = calculate_pusch_power(&cfg, 10, 80.0, 0.0, 0.0).unwrap();
    assert!((power - (-12.9897)).abs() < 0.01);

    // High pathloss capping at P_CMAX
    let power_capped = calculate_pusch_power(&cfg, 10, 140.0, 0.0, 0.0).unwrap();
    assert_eq!(power_capped, 23.0);

    // Invalid alpha rejected
    let invalid_cfg = PuschPowerConfig { alpha: 1.5, ..cfg };
    assert!(calculate_pusch_power(&invalid_cfg, 10, 80.0, 0.0, 0.0).is_err());
}

#[test]
fn test_tpc_accumulation_and_absolute_modes() {
    // 1. Accumulated mode
    let mut tpc_accum = TpcLoop::new(TpcMode::Accumulated);
    assert_eq!(tpc_accum.current_value_db, 0.0);

    tpc_accum.apply_command(1.0);
    tpc_accum.apply_command(3.0);
    tpc_accum.apply_command(-1.0);
    assert_eq!(tpc_accum.current_value_db, 3.0);

    // Bounding at max +16 dB
    tpc_accum.apply_command(20.0);
    assert_eq!(tpc_accum.current_value_db, 16.0);

    tpc_accum.reset();
    assert_eq!(tpc_accum.current_value_db, 0.0);

    // 2. Absolute mode
    let mut tpc_abs = TpcLoop::new(TpcMode::Absolute);
    tpc_abs.apply_command(4.0);
    assert_eq!(tpc_abs.current_value_db, 4.0);
    tpc_abs.apply_command(-1.0);
    assert_eq!(tpc_abs.current_value_db, -1.0);
}

#[test]
fn test_pucch_format_power_offsets_and_tf_compensation() {
    let cfg = PucchPowerConfig {
        p_o_pucch_dbm: -100.0,
        p_cmax_dbm: 23.0,
        numerology_mu: 0, // 15 kHz SCS
    };

    // 1 PRB at mu=0: bw_term = 0 dB
    // Format 0 (delta_f = 0 dB) vs Format 2 (delta_f = 3 dB) vs Format 3 (delta_f = 4 dB)
    let p_fmt0 = calculate_pucch_power(&cfg, PucchFormat::Format0, 1, 80.0, 0.0, 0.0).unwrap();
    let p_fmt2 = calculate_pucch_power(&cfg, PucchFormat::Format2, 1, 80.0, 0.0, 0.0).unwrap();
    let p_fmt3 = calculate_pucch_power(&cfg, PucchFormat::Format3, 1, 80.0, 0.0, 0.0).unwrap();

    assert_eq!(p_fmt0, -20.0); // -100 + 0 + 80 + 0 = -20 dBm
    assert_eq!(p_fmt2, -17.0); // -100 + 0 + 80 + 3 = -17 dBm
    assert_eq!(p_fmt3, -16.0); // -100 + 0 + 80 + 4 = -16 dBm
}

#[test]
fn test_prach_power_ramping_steps() {
    let initial_target = -100.0;
    let ramping_step = 2.0;
    let pathloss = 85.0;
    let p_cmax = 23.0;

    // Transmission counter 1 (initial attempt)
    let p_att1 = calculate_prach_power(initial_target, ramping_step, 1, pathloss, p_cmax);
    assert_eq!(p_att1, -15.0); // -100 + 0 + 85 = -15 dBm

    // Transmission counter 2 (1st retransmission)
    let p_att2 = calculate_prach_power(initial_target, ramping_step, 2, pathloss, p_cmax);
    assert_eq!(p_att2, -13.0); // -100 + 2 + 85 = -13 dBm

    // Transmission counter 5 (4th retransmission)
    let p_att5 = calculate_prach_power(initial_target, ramping_step, 5, pathloss, p_cmax);
    assert_eq!(p_att5, -7.0); // -100 + 8 + 85 = -7 dBm
}

#[test]
fn test_srs_power_control_with_fractional_pathloss() {
    // p_o_srs = -105 dBm, alpha = 0.7, 4 PRBs at mu=1 => bw_term = 10 * log10(8) = 9.03 dB
    // PL = 80 dB => alpha * PL = 56 dB
    // TPC = 2.0 dB
    // Target: -105 + 9.0309 + 56 + 2.0 = -37.969 dBm
    let p_srs = calculate_srs_power(-105.0, 0.7, 4, 1, 80.0, 2.0, 23.0).unwrap();
    assert!((p_srs - (-37.969)).abs() < 0.05);

    // Invalid alpha rejected
    assert!(calculate_srs_power(-105.0, 1.2, 4, 1, 80.0, 2.0, 23.0).is_err());
}

#[test]
fn test_simultaneous_transmission_power_allocation_and_priority_curtailment() {
    let p_cmax = 23.0; // 200 mW

    // 4 simultaneous channels:
    // Req 1: PRACH (Priority 1) requesting 15 dBm (~31.62 mW)
    // Req 2: PUCCH with HARQ-ACK (Priority 2) requesting 20 dBm (100.0 mW)
    // Req 3: PUSCH Data Only (Priority 6) requesting 21 dBm (~125.89 mW)
    // Req 4: SRS (Priority 7) requesting 10 dBm (10.0 mW)
    // Total demanded: ~267.5 mW > 200 mW!
    let requests = vec![
        ChannelPowerRequest {
            channel_id: 101,
            priority: ChannelPriority::Prach,
            requested_power_dbm: 15.0,
        },
        ChannelPowerRequest {
            channel_id: 102,
            priority: ChannelPriority::PucchHarqAckSr,
            requested_power_dbm: 20.0,
        },
        ChannelPowerRequest {
            channel_id: 103,
            priority: ChannelPriority::PuschDataOnly,
            requested_power_dbm: 21.0,
        },
        ChannelPowerRequest {
            channel_id: 104,
            priority: ChannelPriority::Srs,
            requested_power_dbm: 10.0,
        },
    ];

    let grants = resolve_simultaneous_power_scaling(&requests, p_cmax);
    assert_eq!(grants.len(), 4);

    // PRACH (Priority 1): 100% granted (15 dBm)
    assert_eq!(grants[0].channel_id, 101);
    assert_eq!(grants[0].granted_power_dbm, 15.0);
    assert_eq!(grants[0].scaling_factor, 1.0);

    // PUCCH HARQ-ACK (Priority 2): 100% granted (20 dBm)
    assert_eq!(grants[1].channel_id, 102);
    assert_eq!(grants[1].granted_power_dbm, 20.0);
    assert_eq!(grants[1].scaling_factor, 1.0);

    // PUSCH Data Only (Priority 6): partially scaled down
    assert_eq!(grants[2].channel_id, 103);
    assert!(grants[2].scaling_factor > 0.5 && grants[2].scaling_factor < 0.6);
    assert!(grants[2].granted_power_dbm < 21.0);

    // SRS (Priority 7): completely muted (0 mW)
    assert_eq!(grants[3].channel_id, 104);
    assert_eq!(grants[3].scaling_factor, 0.0);
    assert_eq!(grants[3].granted_power_dbm, -140.0);
}

#[test]
fn test_phr_type1_type2_type3_headroom_calculation() {
    let p_cmax = 23.0;

    // Normal transmission with ample headroom
    let phr = calculate_power_headroom(p_cmax, Some(17.0), Some(14.0), Some(10.0));
    assert_eq!(phr.phr_type1_db, 6.0); // 23 - 17 = 6 dB
    assert!((phr.phr_type2_db.unwrap() - 4.14).abs() < 0.2); // ~18.86 dBm combined => ~4.14 dB headroom
    assert_eq!(phr.phr_type3_db.unwrap(), 13.0); // 23 - 10 = 13 dB
    assert!(!phr.is_power_limited);

    // Power limited transmission
    let phr_limited = calculate_power_headroom(p_cmax, Some(23.0), None, None);
    assert_eq!(phr_limited.phr_type1_db, 0.0);
    assert!(phr_limited.is_power_limited);
}

#[test]
fn test_binary_wire_codec_and_crc16_integrity() {
    let pdu = UlPowerControlWirePdu {
        magic: UL_PWR_WIRE_MAGIC,
        timestamp_ms: 12500,
        p_cmax_q4: (23.0 * 16.0) as i16,      // 368
        pusch_power_q4: (18.5 * 16.0) as i16, // 296
        pucch_power_q4: (14.0 * 16.0) as i16, // 224
        phr_type1_q4: (4.5 * 16.0) as i16,    // 72
        is_power_limited: 0,
        payload: vec![0x01, 0x02, 0x03, 0x04],
        crc16: 0,
    };

    let serialized = pdu.serialize();
    assert_eq!(&serialized[..4], &[0x50, 0x57, 0x52, 0x43]); // "PWRC"

    // Successful deserialization
    let deserialized = UlPowerControlWirePdu::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.timestamp_ms, 12500);
    assert_eq!(deserialized.p_cmax_q4, 368);
    assert_eq!(deserialized.pusch_power_q4, 296);
    assert_eq!(deserialized.phr_type1_q4, 72);
    assert_eq!(deserialized.payload, pdu.payload);

    // Tampered payload fails CRC
    let mut corrupted = serialized.clone();
    corrupted[20] ^= 0x01;
    assert!(UlPowerControlWirePdu::deserialize(&corrupted).is_err());
}
