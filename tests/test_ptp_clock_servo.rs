//! Integration tests for PTP PI Clock Servo (IEEE 1588-2019 / ITU-T G.8275.2).

use toy_tcpip::ptp_pdv_filter::{
    PtpClockServo, PtpClockServoConfig, PtpClockServoState, PtpServoAction,
};

#[test]
fn test_ptp_clock_servo_initial_phase_step() {
    let mut servo = PtpClockServo::default();
    assert_eq!(servo.state(), PtpClockServoState::Unset);
    assert!(!servo.is_locked());

    // Initial offset of +250,000 ns (250 µs > 100 µs step threshold)
    let action = servo.sample(250_000, 0.0625);

    match action {
        PtpServoAction::Step { step_ns } => {
            assert_eq!(step_ns, 250_000);
        }
        _ => panic!("Expected immediate phase step on initial large offset"),
    }

    assert_eq!(servo.state(), PtpClockServoState::Aligning);
    assert_eq!(servo.total_step_ns(), 250_000);
}

#[test]
fn test_ptp_clock_servo_pi_frequency_discipline_and_lock() {
    let config = PtpClockServoConfig {
        kp: 0.6,
        ki: 0.2,
        step_threshold_ns: 50_000,
        lock_threshold_ns: 30, // Strict 30ns lock threshold
        lock_consecutive_count: 3,
        max_frequency_offset_ppb: 50_000.0,
        max_integral_windup_ns: 500_000.0,
    };

    let mut servo = PtpClockServo::new(config);

    // Initial small step / alignment
    servo.sample(500, 0.1);

    // Feed small converging phase offsets within lock threshold (<30ns)
    let offsets = [25, 18, 12, 8, 4, 1, 0];
    for &off in &offsets {
        let action = servo.sample(off, 0.1);
        match action {
            PtpServoAction::AdjustFreq {
                freq_ppb,
                phase_adjust_ns,
            } => {
                assert_eq!(phase_adjust_ns, off);
                // Frequency adjustment should be negative feedback to drive offset down
                assert!(freq_ppb <= 0.0);
            }
            _ => panic!("Expected frequency adjustment during slewing"),
        }
    }

    // After 3+ consecutive samples <= 30ns, clock must be Locked
    assert!(servo.is_locked());
    assert_eq!(servo.state(), PtpClockServoState::Locked);
}

#[test]
fn test_ptp_clock_servo_integral_anti_windup() {
    let config = PtpClockServoConfig {
        kp: 0.5,
        ki: 0.5,
        step_threshold_ns: 100_000,
        lock_threshold_ns: 50,
        lock_consecutive_count: 3,
        max_frequency_offset_ppb: 10_000.0, // Hard cap ±10,000 ppb
        max_integral_windup_ns: 50_000.0,   // Anti-windup cap
    };

    let mut servo = PtpClockServo::new(config);
    servo.sample(1_000, 0.1); // Initial align

    // Inject 500 iterations of +5,000 ns persistent bias
    for _ in 0..500 {
        servo.sample(5_000, 0.1);
    }

    // Anti-windup clamping must keep integrated error within bounds
    assert!(servo.integrated_error_ns <= 50_000.0);
    // Output frequency adjustment must be clamped at the maximum
    assert_eq!(servo.current_freq_ppb(), -10_000.0);
}

#[test]
fn test_ptp_clock_servo_holdover_transition() {
    let mut servo = PtpClockServo::default();

    // Align and lock with a known frequency offset
    servo.sample(40, 0.0625);
    servo.sample(30, 0.0625);
    servo.sample(20, 0.0625);
    servo.sample(10, 0.0625);
    servo.sample(5, 0.0625);

    let disciplined_ppb = servo.current_freq_ppb();
    assert!(disciplined_ppb.abs() > 0.0);

    // Enter Holdover when upstream PTP sync is lost
    let holdover_action = servo.enter_holdover();
    match holdover_action {
        PtpServoAction::Holdover { drift_ppb } => {
            assert_eq!(drift_ppb, disciplined_ppb);
        }
        _ => panic!("Expected holdover action"),
    }

    assert_eq!(servo.state(), PtpClockServoState::Holdover);
    assert!(!servo.is_locked());
}
