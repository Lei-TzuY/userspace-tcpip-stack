//! Integration tests for 3GPP Rel-17 5G-TSN Time-Synchronization Service Function (TSCTF).

use toy_tcpip::ptp::{PTP_MSG_SYNC, PtpHeader};
use toy_tcpip::tsn_5g_clock::{
    ClockDomainType, DEFAULT_INDUSTRIAL_TSN_BUDGET_NS, ReferenceTimeInfo,
    STRICT_MOTION_CONTROL_BUDGET_NS, SyncDirection, TimeErrorBudget, TsctfEngine, TsctfError,
    TsctfSession, WorkingClockModel,
};

#[test]
fn test_reference_time_info_extrapolation() {
    let ref_time = ReferenceTimeInfo::new(
        512,        // SFN
        3,          // subframe
        2,          // slot
        1700000000, // 1.7 billion seconds epoch
        500000000,  // 500 ms (500,000,000 ns)
        15,         // uncertainty 15 ns
    );

    assert_eq!(ref_time.sfn, 512);
    assert_eq!(ref_time.subframe, 3);
    assert_eq!(ref_time.slot, 2);
    assert_eq!(ref_time.uncertainty_ns, 15);

    let epoch_ns = ref_time.to_5g_epoch_ns();
    assert_eq!(epoch_ns, 1700000000 * 1_000_000_000 + 500000000);

    // Extrapolate 10 ms (10,000,000 ns) into the future
    let current_ns = ref_time.extrapolate_current_5g_ns(10_000_000);
    assert_eq!(current_ns, epoch_ns + 10_000_000);
}

#[test]
fn test_working_clock_model_conversions_and_rate_drift() {
    let base_5g_ns = 1_000_000_000;
    let base_working_ns = 2_000_000_000; // 1 second offset

    // Perfect 1:1 aligned model
    let mut model = WorkingClockModel::new(base_5g_ns, base_working_ns, 0.0);
    assert_eq!(
        model.convert_5g_to_working(base_5g_ns + 500_000),
        base_working_ns + 500_000
    );
    assert_eq!(
        model.convert_working_to_5g(base_working_ns + 500_000),
        base_5g_ns + 500_000
    );

    // Model with +50.0 ppm frequency offset
    model.rate_offset_ppm = 50.0;
    let delta_5g = 1_000_000_000; // 1 second of 5G time
    let expected_delta_working = 1_000_050_000; // 1.000050 seconds (+50 ppm)
    let converted_working = model.convert_5g_to_working(base_5g_ns + delta_5g);
    assert_eq!(converted_working, base_working_ns + expected_delta_working);

    let round_trip_5g = model.convert_working_to_5g(converted_working);
    assert_eq!(round_trip_5g, base_5g_ns + delta_5g);

    // Calibration update test
    let new_5g_ns = base_5g_ns + 2_000_000_000; // 2 seconds later
    let new_working_ns = base_working_ns + 2_000_040_000; // +20 ppm over 2 seconds
    model.update_calibration(new_5g_ns, new_working_ns);

    assert_eq!(model.ref_5g_ns, new_5g_ns);
    assert_eq!(model.ref_working_ns, new_working_ns);
    assert!((model.rate_offset_ppm - 20.0).abs() < 1e-4);
}

#[test]
fn test_time_error_budget_audits() {
    // 1. Industrial Default profile (TS 22.104: 900 ns budget)
    let industrial = TimeErrorBudget::industrial_default();
    assert_eq!(industrial.max_budget_ns, DEFAULT_INDUSTRIAL_TSN_BUDGET_NS);
    let total_ind = industrial.total_time_error_ns();
    assert_eq!(total_ind, 80.0 + 400.0 + 200.0 + 80.0); // 760 ns
    assert!(industrial.is_compliant());
    assert!(industrial.audit().is_ok());

    // 2. Strict Motion Control profile (250 ns budget)
    let motion = TimeErrorBudget::strict_motion_control();
    assert_eq!(motion.max_budget_ns, STRICT_MOTION_CONTROL_BUDGET_NS);
    let total_motion = motion.total_time_error_ns();
    assert_eq!(total_motion, 30.0 + 120.0 + 60.0 + 30.0); // 240 ns
    assert!(motion.is_compliant());
    assert!(motion.audit().is_ok());

    // 3. Degraded budget test exceeding SLA threshold
    let degraded = TimeErrorBudget::new(80.0, 600.0, 250.0, 80.0, 900.0); // total = 1010 ns
    assert!(!degraded.is_compliant());
    let audit_res = degraded.audit();
    assert!(matches!(
        audit_res,
        Err(TsctfError::TimeErrorBudgetExceeded {
            total_ns: 1010,
            max_budget_ns: 900
        })
    ));
}

#[test]
fn test_ptp_residence_time_calculation_and_fractional_correction() {
    let mut session = TsctfSession::new(
        1, // Domain 1 (TSN Working Clock)
        ClockDomainType::TsnWorkingClock,
        SyncDirection::DownlinkFromNwTt,
        WorkingClockModel::aligned(1_000_000_000),
        TimeErrorBudget::industrial_default(),
        1, // NW-TT port 1
    );

    let mut ptp_header = PtpHeader {
        message_type: PTP_MSG_SYNC,
        version: 2,
        message_length: 44,
        domain_number: 0,
        flags: 0x0200, // two-step
        correction_field: 0,
        clock_identity: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
        source_port_id: 1,
        sequence_id: 42,
        control_field: 0,
        log_message_interval: -3,
    };

    let ingress_5g_ns = 10_000_000;
    let egress_5g_ns = 14_500_000; // 4.5 ms residence time across 5GS
    let ingress_delay_ns = 60;
    let egress_delay_ns = 40;

    let res_update = session
        .process_ptp_forward(
            1, // ingress port
            2, // egress port
            ingress_5g_ns,
            egress_5g_ns,
            ingress_delay_ns,
            egress_delay_ns,
            &mut ptp_header,
        )
        .expect("residence time update should succeed");

    assert_eq!(res_update.domain_id, 1);
    assert_eq!(res_update.residence_time_ns, 4_500_000);
    assert_eq!(res_update.total_correction_ns, 4_500_100);
    assert_eq!(ptp_header.domain_number, 1);
    assert_eq!(session.sync_sequence_counter, 1);

    // IEEE 802.1AS 16-bit fractional shift verification
    let expected_cf = (4_500_100i64) << 16;
    assert_eq!(ptp_header.correction_field, expected_cf);

    // Negative residence time error test
    let err = session.process_ptp_forward(
        1,
        2,
        20_000_000,
        15_000_000, // egress precedes ingress
        10,
        10,
        &mut ptp_header,
    );
    assert!(matches!(err, Err(TsctfError::NegativeResidenceTime { .. })));
}

#[test]
fn test_sib9_working_clock_distribution_to_ds_tt() {
    let mut engine = TsctfEngine::new();

    let session = TsctfSession::new(
        2, // Domain 2
        ClockDomainType::TsnWorkingClock,
        SyncDirection::DownlinkFromNwTt,
        WorkingClockModel::new(100_000_000, 500_000_000, 0.0), // 400 ms initial offset
        TimeErrorBudget::industrial_default(),
        10,
    );

    engine.register_session(session).expect("register session");

    // Add connected DS-TT port 101
    engine
        .get_session_mut(2)
        .expect("get session")
        .add_ds_tt(101);

    // SIB9 Reference Time broadcast
    let ref_time = ReferenceTimeInfo::new(100, 0, 0, 1700000000, 0, 10);
    engine.update_reference_time(ref_time);

    // Reconstruct Working Clock at DS-TT after 50 ms elapsed 5G time
    let elapsed_ns = 50_000_000;
    let working_time_ns = engine
        .distribute_working_clock_to_ds_tt(2, 101, elapsed_ns)
        .expect("distribute clock");

    let current_5g = ref_time.to_5g_epoch_ns() + elapsed_ns;
    // Difference between 5G time and working clock is 400 ms (400,000,000 ns)
    assert_eq!(working_time_ns, current_5g + 400_000_000);

    // Unconnected DS-TT port rejection
    let unconn_err = engine.distribute_working_clock_to_ds_tt(2, 999, elapsed_ns);
    assert_eq!(unconn_err, Err(TsctfError::DsTtNotFound(999)));

    // Unknown domain rejection
    let unk_domain_err = engine.distribute_working_clock_to_ds_tt(99, 101, elapsed_ns);
    assert_eq!(unk_domain_err, Err(TsctfError::DomainNotFound(99)));
}

#[test]
fn test_rel17_ue_to_ue_direct_time_synchronization() {
    let mut engine = TsctfEngine::new();

    let mut session = TsctfSession::new(
        5, // Domain 5 (Robot Coordination Domain)
        ClockDomainType::TsnWorkingClock,
        SyncDirection::UeToUeDirect,
        WorkingClockModel::aligned(5_000_000_000),
        TimeErrorBudget::strict_motion_control(),
        20,
    );

    // Connect DS-TT 201 (Robot Arm A) and DS-TT 202 (AGV Base B)
    session.add_ds_tt(201);
    session.add_ds_tt(202);

    engine.register_session(session).expect("register session");

    let source_time_working_ns = 10_000_000_000; // Source timestamp
    let transit_delay_5g_ns = 3_500_000; // 3.5 ms Uu-to-Uu direct transit delay

    let report = engine
        .perform_ue_to_ue_sync(5, 201, 202, source_time_working_ns, transit_delay_5g_ns)
        .expect("ue to ue sync");

    assert_eq!(report.domain_id, 5);
    assert_eq!(report.source_ds_tt, 201);
    assert_eq!(report.target_ds_tt, 202);
    assert_eq!(report.source_working_time_ns, source_time_working_ns);
    assert_eq!(
        report.target_working_time_ns,
        source_time_working_ns + transit_delay_5g_ns
    );
    assert_eq!(report.transit_delay_5g_ns, 3_500_000);
    assert_eq!(report.estimated_sync_error_ns, 240.0);
    assert!(report.within_rel17_sla);
}
