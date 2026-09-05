//! Integration tests for PTP Hardware Clock (PHC) Emulation, Cross-Timestamping, and TX/RX Ring Buffer.

use toy_tcpip::ptp::{PTP_MSG_SYNC, PtpPacket, PtpTimestamp};
use toy_tcpip::ptp_pdv_filter::{PtpClockServo, PtpClockServoConfig, PtpServoAction};
use toy_tcpip::ptp_phc::{
    PhcPacketTagger, PhcTxTimestampRing, PtpCrossTimestamp, PtpCrossTimestampError,
    PtpHardwareClock,
};

#[test]
fn test_phc_basic_progression_and_step() {
    let mut phc = PtpHardwareClock::new(100, 500_000_000);
    assert_eq!(phc.get_time(), PtpTimestamp::new(100, 500_000_000));

    // Advance 600,000,000 ns (0.6s)
    phc.tick_ns(600_000_000);
    assert_eq!(phc.get_time(), PtpTimestamp::new(101, 100_000_000));

    // Step by -200,000,000 ns (-0.2s)
    phc.step_time_ns(-200_000_000);
    assert_eq!(phc.get_time(), PtpTimestamp::new(100, 900_000_000));
    assert_eq!(phc.total_stepped_ns, -200_000_000);

    // Step positive across second boundary (+300,000,000 ns)
    phc.step_time_ns(300_000_000);
    assert_eq!(phc.get_time(), PtpTimestamp::new(101, 200_000_000));
}

#[test]
fn test_phc_frequency_adjustment_ppb() {
    let mut phc = PtpHardwareClock::new(0, 0);

    // Apply +10,000 ppb frequency steering (+10 ppm = +0.001%)
    phc.adj_freq_ppb(10_000.0);
    assert_eq!(phc.freq_adjustment_ppb, 10_000.0);

    // Tick exactly 1 second (1,000,000,000 real nanoseconds)
    phc.tick_ns(1_000_000_000);

    // At +10,000 ppb, clock should advance by 1,000,010,000 ns
    let t1 = phc.get_time();
    assert_eq!(t1.seconds, 1);
    assert_eq!(t1.nanoseconds, 10_000);

    // Now switch to -5,000 ppb (-5 ppm)
    phc.adj_freq_ppb(-5_000.0);
    phc.tick_ns(1_000_000_000);

    // Next second advances by 999,995,000 ns: 1,000,010,000 + 999,995,000 = 2,000,005,000 ns
    let t2 = phc.get_time();
    assert_eq!(t2.seconds, 2);
    assert_eq!(t2.nanoseconds, 5_000);
}

#[test]
fn test_phc_closed_loop_servo_discipline() {
    // Physical oscillator with +20,000 ppb (+20 ppm) uncalibrated hardware frequency drift
    let mut phc = PtpHardwareClock::new(0, 0);
    let drift_ppb = 20_000.0;

    let config = PtpClockServoConfig {
        kp: 0.5,
        ki: 0.05,
        step_threshold_ns: 50_000,
        lock_threshold_ns: 200,
        lock_consecutive_count: 3,
        max_frequency_offset_ppb: 100_000.0,
        max_integral_windup_ns: 1_000_000.0,
    };
    let mut servo = PtpClockServo::new(config);

    let mut master_time_ns: i64 = 0;

    // Simulate 100 1-second sync cycles
    for _ in 0..100 {
        // Advance master by 1s (1_000_000_000 ns)
        master_time_ns += 1_000_000_000;

        // Advance PHC with its natural drift + applied steering
        let natural_advance: f64 = 1_000_000_000.0 * (1.0 + (drift_ppb / 1_000_000_000.0));
        phc.tick_ns(natural_advance.round() as u64);

        let phc_ns = phc.get_time().to_total_nanoseconds() as i64;
        // PTP offset = slave - master
        let phase_offset_ns = phc_ns - master_time_ns;

        let action = servo.sample(phase_offset_ns, 1.0);
        match action {
            PtpServoAction::Step { step_ns } => {
                phc.step_time_ns(-step_ns);
            }
            PtpServoAction::AdjustFreq { freq_ppb, .. } => {
                phc.adj_freq_ppb(freq_ppb);
            }
            PtpServoAction::Holdover { .. } => {}
        }
    }

    // Closed-loop PI servo should counteract the +20,000 ppb oscillator drift:
    // Frequency adjustment should settle near -20,000 ppb
    assert!((phc.freq_adjustment_ppb - (-20_000.0)).abs() < 500.0);

    // Phase offset should be locked near 0 ns
    let final_phc_ns = phc.get_time().to_total_nanoseconds() as i64;
    let final_error = (master_time_ns - final_phc_ns).abs();
    assert!(
        final_error < 200,
        "Final phase error {} ns exceeds 200 ns",
        final_error
    );
}

#[test]
fn test_phc_cross_timestamping() {
    let dev_ts = PtpTimestamp::new(100, 500_000_000); // PHC counter = 100.5s
    let sys_before = PtpTimestamp::new(100, 499_998_000); // 100.499998s
    let sys_after = PtpTimestamp::new(100, 500_002_000); // 100.500002s

    let cross_ts = PtpCrossTimestamp::new(dev_ts, sys_before, sys_after);

    // Bus read latency = 500_002_000 - 499_998_000 = 4000 ns
    assert_eq!(cross_ts.bus_read_latency_ns(), Ok(4000));
    assert!(cross_ts.is_valid_latency(5000));
    assert!(!cross_ts.is_valid_latency(3000));

    // Midpoint of sys clock = (499_998_000 + 500_002_000) / 2 = 500_000_000 ns
    // Offset = device_ts - midpoint = 500_000_000 - 500_000_000 = 0 ns
    assert_eq!(cross_ts.compute_offset_ns(), Ok(0));

    // Test when device is ahead by +250 ns
    let dev_ahead = PtpTimestamp::new(100, 500_000_250);
    let cross_ahead = PtpCrossTimestamp::new(dev_ahead, sys_before, sys_after);
    assert_eq!(cross_ahead.compute_offset_ns(), Ok(250));
}

#[test]
fn test_phc_cross_timestamp_rejects_reversed_system_snapshots() {
    let cross_ts = PtpCrossTimestamp::new(
        PtpTimestamp::new(100, 500_000_000),
        PtpTimestamp::new(100, 500_002_000),
        PtpTimestamp::new(100, 499_998_000),
    );

    assert_eq!(
        cross_ts.bus_read_latency_ns(),
        Err(PtpCrossTimestampError::ReversedSystemTime)
    );
    assert!(!cross_ts.is_valid_latency(u64::MAX));
    assert_eq!(
        cross_ts.compute_offset_ns(),
        Err(PtpCrossTimestampError::ReversedSystemTime)
    );
}

#[test]
fn test_phc_tx_timestamp_ring_and_tagger() {
    let mut phc = PtpHardwareClock::new(50, 123_456_789);
    let mut tx_ring = PhcTxTimestampRing::new(16);

    let clock_id = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    // 1. Two-step Sync message (flags has 0x0200)
    let dummy_ts = PtpTimestamp::new(0, 0);
    let mut two_step_sync = PtpPacket::build_sync(clock_id, 101, dummy_ts);
    two_step_sync.header.flags = 0x0200; // Two-step

    let tagged_ts = PhcPacketTagger::tag_tx(&phc, &mut two_step_sync, &mut tx_ring);
    assert_eq!(tagged_ts, PtpTimestamp::new(50, 123_456_789));
    assert_eq!(tx_ring.len(), 1);

    // Retrieve egress timestamp from FIFO for Follow_Up message
    let taken_ts = tx_ring
        .take_egress_ts(101, PTP_MSG_SYNC)
        .expect("Egress timestamp found");
    assert_eq!(taken_ts, PtpTimestamp::new(50, 123_456_789));
    assert_eq!(tx_ring.len(), 0);

    // 2. One-step Sync message (flags = 0x0000)
    let mut one_step_sync = PtpPacket::build_sync(clock_id, 102, dummy_ts);
    one_step_sync.header.flags = 0x0000; // One-step

    phc.tick_ns(10_000_000);
    let one_step_ts = PhcPacketTagger::tag_tx(&phc, &mut one_step_sync, &mut tx_ring);

    // Origin timestamp is populated directly into one-step packet
    assert_eq!(one_step_sync.origin_timestamp, Some(one_step_ts));
    // No timestamp in FIFO for one-step
    assert_eq!(tx_ring.len(), 0);
}
