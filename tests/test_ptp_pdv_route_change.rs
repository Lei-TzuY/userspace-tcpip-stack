//! Integration tests for PTP PDV Network Route Step Detection and Auto-Flushing.

use toy_tcpip::ptp_pdv_filter::{PtpPdvFloorFilter, PtpTimestampSample};

#[test]
fn test_ptp_pdv_route_step_detection_and_flush() {
    // 24-sample window, 10% floor, 100ns cluster spread
    let mut filter = PtpPdvFloorFilter::new(24, 10.0, 100);

    // Initial Path: forward delay = 12,000 ns, reverse delay = 12,000 ns, offset = 0
    for seq in 0..16 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 12_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 12_000;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    let initial_estimate = filter.compute_estimate().expect("Initial estimate");
    assert_eq!(initial_estimate.forward_delay_floor_ns, 12_000);
    assert_eq!(initial_estimate.reverse_delay_floor_ns, 12_000);
    assert_eq!(initial_estimate.estimated_offset_ns, 0);

    // No step detected under normal path conditions
    assert!(filter.detect_delay_step(5_000).is_none());

    // Path Reroute occurs: network path switches to a longer backup route
    // Forward delay jumps by +35,000 ns (to 47,000 ns), reverse delay jumps by +35,000 ns (to 47,000 ns)
    for seq in 16..24 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 47_000;
        let t3 = t2 + 10_000;
        let t4 = t3 + 47_000;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    // Step detector identifies the +35,000 ns reroute jump
    let step_event = filter
        .detect_delay_step(20_000)
        .expect("Route step must be detected");
    assert_eq!(step_event.forward_step_ns, 35_000);
    assert_eq!(step_event.reverse_step_ns, 35_000);
    assert_eq!(step_event.detected_at_seq, 23);

    // Auto-flush stale pre-reroute 12,000ns samples
    let flush_res = filter.flush_on_route_step(20_000);
    assert!(flush_res.is_some());

    // New estimate converges immediately on the new route without being anchored by old 12,000ns samples
    let new_estimate = filter.compute_estimate().expect("New estimate after flush");
    assert_eq!(new_estimate.forward_delay_floor_ns, 47_000);
    assert_eq!(new_estimate.reverse_delay_floor_ns, 47_000);
    assert_eq!(new_estimate.estimated_offset_ns, 0);
}

#[test]
fn test_ptp_pdv_no_false_step_on_queuing_jitter() {
    let mut filter = PtpPdvFloorFilter::new(20, 10.0, 100);

    // Base delay is 10,000 ns. Queuing adds random transient noise up to 3,000 ns,
    // but the clean floor remains at 10,000 ns.
    for seq in 0..20 {
        let jitter = if seq % 3 == 0 {
            0
        } else {
            ((seq as i64 * 31) % 3) * 1_000
        };
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000 + jitter;
        let t3 = t2 + 5_000;
        let t4 = t3 + 10_000 + jitter;
        filter.push_sample(PtpTimestampSample::new(seq, t1, t2, t3, t4));
    }

    // With a threshold of 10,000 ns, transient queuing noise must NOT trigger a route step
    assert!(filter.detect_delay_step(10_000).is_none());
    assert!(filter.flush_on_route_step(10_000).is_none());
}
