//! Integration tests for PTP PDV Floor Filter & Min-Delay Estimator (ITU-T G.8275.2)

use toy_tcpip::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};

#[test]
fn test_ptp_pdv_floor_filter_in_congested_network() {
    // 50-sample window, 5% floor selection, 200 ns cluster spread
    let mut filter = PtpPdvFloorFilter::new(50, 5.0, 200);

    // True physical delay = 25,000 ns (25 µs)
    // True clock offset = -1,200 ns
    // Base forward delay: 25,000 - 1,200 = 23,800 ns
    // Base reverse delay: 25,000 + 1,200 = 26,200 ns

    // 50 sync/delay_resp cycles with heavy asymmetric packet queuing bursts
    for seq in 0..50 {
        // Congested packets experience +10,000 to +150,000 ns random queuing delay
        // Clean floor packets occur periodically
        let is_clean = (seq % 10) == 0;
        let fwd_pdv = if is_clean {
            0
        } else {
            ((seq as i64 * 37) % 150) * 1_000
        };
        let rev_pdv = if is_clean {
            0
        } else {
            ((seq as i64 * 53) % 200) * 1_000
        };

        let t1 = (seq as i64) * 10_000_000;
        let t2 = t1 + 23_800 + fwd_pdv;
        let t3 = t2 + 50_000;
        let t4 = t3 + 26_200 + rev_pdv;

        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let estimate = filter.compute_estimate().expect("Estimate should converge");

    // The floor filter discards all congested queuing peaks and converges on exact base values
    assert_eq!(estimate.forward_delay_floor_ns, 23_800);
    assert_eq!(estimate.reverse_delay_floor_ns, 26_200);
    assert_eq!(estimate.mean_path_delay_ns, 25_000);
    assert_eq!(estimate.estimated_offset_ns, -1_200);
    assert_eq!(estimate.valid_samples_in_window, 50);
}

#[test]
fn test_ptp_time_error_cte_and_dte_metrics() {
    let mut filter = PtpPdvFloorFilter::new(10, 10.0, 100);

    // Constant Time Error: true offset = +50 ns
    // Some symmetrical fluctuation between +40 and +60 ns (dTE peak-to-peak = 20 ns)
    for seq in 0..10 {
        let jitter = if seq % 2 == 0 { 10 } else { -10 };
        let offset = 50 + jitter; // alternating 60 and 40
        let mean_delay = 10_000;
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + mean_delay + offset;
        let t3 = t2 + 20_000;
        let t4 = t3 + mean_delay - offset;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let metrics = filter
        .compute_time_error_metrics()
        .expect("compute time error");
    assert_eq!(metrics.cte_ns, 50.0);
    assert_eq!(metrics.dte_peak_to_peak_ns, 20);
    assert_eq!(metrics.max_abs_te_ns, 60);
    assert_eq!(metrics.sample_count, 10);
}

#[test]
fn test_ptp_pdv_filter_iqr_outlier_rejection() {
    // Normal delay distribution clustered around 10,000 ns with a few extreme outliers
    let delays = vec![
        9_900, 9_950, 10_000, 10_050, 10_100, 10_020, 9_980, 10_010,
        500_000, // 500us outlier spike (microburst)
        999_999, // 1ms outlier spike
    ];

    let filtered = PtpPdvFloorFilter::filter_iqr_outliers(&delays);
    // Outliers 500,000 and 999,999 must be stripped
    assert!(!filtered.contains(&500_000));
    assert!(!filtered.contains(&999_999));
    assert_eq!(filtered.len(), 8);
}

#[test]
fn test_ptp_pdv_subwindow_lucky_packet_estimation() {
    let mut filter = PtpPdvFloorFilter::new(20, 10.0, 100);

    // True delay = 15,000 ns, offset = 0
    // Every subwindow of 5 samples contains at least 1 clean lucky packet
    for seq in 0..20 {
        let is_lucky = (seq % 5) == 2;
        let queuing = if is_lucky { 0 } else { 50_000 };

        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 15_000 + queuing;
        let t3 = t2 + 10_000;
        let t4 = t3 + 15_000 + queuing;

        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let lucky_estimate = filter
        .compute_subwindow_lucky_estimate(4)
        .expect("lucky estimate");

    assert_eq!(lucky_estimate.forward_delay_floor_ns, 15_000);
    assert_eq!(lucky_estimate.reverse_delay_floor_ns, 15_000);
    assert_eq!(lucky_estimate.mean_path_delay_ns, 15_000);
    assert_eq!(lucky_estimate.estimated_offset_ns, 0);
}

#[test]
fn test_ptp_pdv_floor_asymmetry_compensation() {
    // True symmetric physical path delay = 20,000 ns, known static asymmetry = +400 ns
    let mut filter = PtpPdvFloorFilter::new(10, 10.0, 100).with_asymmetry_compensation(400);

    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 20_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 20_000;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let estimate = filter.compute_estimate().expect("estimate");
    // Without compensation offset would be 0. With +400ns asymmetry compensation:
    // offset = (0 - 400) / 2 = -200 ns
    assert_eq!(estimate.estimated_offset_ns, -200);
    assert_eq!(estimate.mean_path_delay_ns, 20_000);
}

#[test]
fn test_ptp_pdv_floor_rate_monitoring_and_ema_smoothing() {
    let mut filter = PtpPdvFloorFilter::new(20, 10.0, 100);

    // 20 samples: 4 are clean floor (20%), 16 suffer +500ns queuing
    for seq in 0..20 {
        let is_floor = seq % 5 == 0;
        let queuing = if is_floor { 0 } else { 500 };

        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000 + queuing;
        let t3 = t2 + 5_000;
        let t4 = t3 + 10_000 + queuing;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    // Floor packet percentage within 50ns of minimum delay
    let (fwd_pct, rev_pct) = filter.floor_packet_percentage(50);
    assert_eq!(fwd_pct, 20.0);
    assert_eq!(rev_pct, 20.0);

    // Adequacy check
    assert!(filter.is_floor_rate_adequate(15.0, 50));
    assert!(!filter.is_floor_rate_adequate(25.0, 50));

    // EMA smoothing
    let s1 = filter.update_smoothed_offset(0.5).expect("smooth 1");
    assert_eq!(s1, 0.0); // raw offset is 0
}

#[test]
fn test_ptp_pdv_wdm_fiber_asymmetry_ratio_compensation() {
    // 1310nm vs 1550nm BiDi optical fiber with asymmetry ratio alpha = 0.96
    // Round trip delay = 50,000 ns fwd + 50,000 ns rev = 100,000 ns
    // Dynamic asymmetry = ((1 - 0.96) / (1 + 0.96)) * 100,000 = (0.04 / 1.96) * 100,000 = 2041 ns
    let mut filter = PtpPdvFloorFilter::new(10, 10.0, 100).with_delay_asymmetry_ratio(0.96);

    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 50_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 50_000;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let estimate = filter.compute_estimate().expect("estimate");
    assert_eq!(estimate.mean_path_delay_ns, 50_000);
    // Offset = (0 - 2041) / 2 = -1020 ns
    assert_eq!(estimate.estimated_offset_ns, -1020);

    // Now combine with static PHY hardware calibration of +400 ns:
    // Total asymmetry = 400 + 2041 = 2441 ns -> Offset = (0 - 2441) / 2 = -1220 ns
    let mut combined_filter = PtpPdvFloorFilter::new(10, 10.0, 100)
        .with_asymmetry_compensation(400)
        .with_delay_asymmetry_ratio(0.96);

    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 50_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 50_000;
        combined_filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let combined_estimate = combined_filter
        .compute_estimate()
        .expect("combined estimate");
    assert_eq!(combined_estimate.estimated_offset_ns, -1220);
}
