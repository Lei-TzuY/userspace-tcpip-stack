use toy_tcpip::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};

#[test]
fn test_ptp_time_error_metrics_calculation() {
    let mut filter = PtpPdvFloorFilter::new(10, 10.0, 100);

    // Physical one-way delay = 20,000 ns
    // Injected time offset = +250 ns
    // Forward delay base = 20,250 ns
    // Reverse delay base = 19,750 ns
    // Observed offset = (20,250 - 19,750) / 2 = +250 ns
    for i in 0..10 {
        let t1 = (i as i64) * 1_000_000;
        let t2 = t1 + 20_250;
        let t3 = t2 + 50_000;
        let t4 = t3 + 19_750;

        filter.push_sample(PtpTimestampSample::new(i as u16, t1, t2, t3, t4));
    }

    let te = filter
        .compute_time_error_metrics()
        .expect("Time error metrics");
    assert_eq!(te.cte_ns, 250.0);
    assert_eq!(te.dte_peak_to_peak_ns, 0);
    assert_eq!(te.max_abs_te_ns, 250);
    assert_eq!(te.sample_count, 10);
}

#[test]
fn test_ptp_iqr_outlier_filtering() {
    // Standard queuing delays between 10,000 and 12,000 ns, with two massive buffer exhaustion spikes (1,000,000 ns)
    let delays = vec![
        10_000, 10_200, 10_150, 10_300, 10_500, 10_450, 10_600, 10_550, 11_000, 11_200, 11_100,
        11_300, 11_500, 11_400, 11_600, 11_550, 1_000_000, 1_500_000, // Severe outliers
    ];

    let filtered = PtpPdvFloorFilter::filter_iqr_outliers(&delays);
    assert!(!filtered.contains(&1_000_000));
    assert!(!filtered.contains(&1_500_000));
    assert!(filtered.len() >= 16);
}

#[test]
fn test_ptp_subwindow_lucky_packet_selection() {
    let mut filter = PtpPdvFloorFilter::new(40, 5.0, 150);

    // True forward delay floor = 15,000 ns
    // True reverse delay floor = 18,000 ns
    // True offset = (15,000 - 18,000) / 2 = -1,500 ns
    // True mean delay = (15,000 + 18,000) / 2 = 16,500 ns

    // 4 subwindows of 10 packets each.
    // In each subwindow, exactly packet #0 has clean floor (0 queuing delay).
    // Remaining packets experience random bursty queuing delay.
    for i in 0..40 {
        let is_lucky = (i % 10) == 0;
        let q_fwd = if is_lucky {
            0
        } else {
            ((i as i64 * 31) % 100) * 1_000
        };
        let q_rev = if is_lucky {
            0
        } else {
            ((i as i64 * 47) % 120) * 1_000
        };

        let t1 = (i as i64) * 10_000_000;
        let t2 = t1 + 15_000 + q_fwd;
        let t3 = t2 + 25_000;
        let t4 = t3 + 18_000 + q_rev;

        filter.push_sample(PtpTimestampSample::new(i as u16, t1, t2, t3, t4));
    }

    let estimate = filter
        .compute_subwindow_lucky_estimate(4)
        .expect("Subwindow lucky estimate");

    assert_eq!(estimate.forward_delay_floor_ns, 15_000);
    assert_eq!(estimate.reverse_delay_floor_ns, 18_000);
    assert_eq!(estimate.estimated_offset_ns, -1_500);
    assert_eq!(estimate.mean_path_delay_ns, 16_500);
}

#[test]
fn test_ptp_histogram_floor_cluster_estimation() {
    let mut filter = PtpPdvFloorFilter::new(30, 10.0, 100);

    // Multi-modal delay distribution:
    // Cluster 1 (Floor): 10 packets around 10,020 ns (base floor ~10,000 ns)
    // Cluster 2 (Mid-queue burst): 10 packets around 35,000 ns
    // Cluster 3 (Heavy burst): 10 packets around 120,000 ns
    for i in 0..30 {
        let (fwd_delay, rev_delay) = if i < 10 {
            (10_000 + (i as i64 * 4), 10_000 + (i as i64 * 4)) // Floor cluster (10,000 - 10,036 ns)
        } else if i < 20 {
            (35_000 + (i as i64 * 50), 35_000 + (i as i64 * 50))
        } else {
            (120_000 + (i as i64 * 100), 120_000 + (i as i64 * 100))
        };

        let t1 = (i as i64) * 1_000_000;
        let t2 = t1 + fwd_delay;
        let t3 = t2 + 10_000;
        let t4 = t3 + rev_delay;
        filter.push_sample(PtpTimestampSample::new(i as u16, t1, t2, t3, t4));
    }

    // Bin width = 50 ns (groups the 10,000-10,036 ns cluster into bin 0)
    let estimate = filter
        .compute_histogram_floor_estimate(50)
        .expect("Histogram floor estimate");

    // The histogram estimator isolates the primary floor peak near 10,018 ns
    assert!(estimate.forward_delay_floor_ns >= 10_000 && estimate.forward_delay_floor_ns <= 10_036);
    assert!(estimate.reverse_delay_floor_ns >= 10_000 && estimate.reverse_delay_floor_ns <= 10_036);
    assert_eq!(estimate.estimated_offset_ns, 0);
}

#[test]
fn test_ptp_pdv_correlation_and_stability_score() {
    let mut filter = PtpPdvFloorFilter::new(20, 10.0, 100);

    // Highly correlated symmetrical queuing delays:
    // Forward and reverse queues congest and drain synchronously
    for seq in 0..20 {
        let burst = (seq as i64) * 500;
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000 + burst;
        let t3 = t2 + 5_000;
        let t4 = t3 + 10_000 + burst;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let report = filter
        .compute_pdv_correlation_and_stability(1_000)
        .expect("Stability report");

    // Forward and reverse delays are perfectly positively correlated (r = 1.0)
    assert!((report.pearson_correlation - 1.0).abs() < 1e-4);
    assert!(report.path_stability_score > 0.0);
    assert!(report.forward_pdv_variance_ns2 > 0.0);
}
