use toy_tcpip::tsn_cqf_cycle_scale::{CycleScaleResult, MIN_CYCLE_NS, TsnCqfCycleScaleEngine};

#[test]
fn test_tsn_cqf_cycle_scale_hitless_transition() {
    // Create engine with 500 µs cycle, 125 µs granularity.
    let mut engine = TsnCqfCycleScaleEngine::new(500_000, MIN_CYCLE_NS);
    assert_eq!(engine.oper_period_ns(), 500_000);
    assert_eq!(engine.cycle_index(), 0);

    // ── Step 1: Request scale-down to 250 µs ────────────────────────────
    assert_eq!(engine.request_scale(250_000), CycleScaleResult::Accepted);
    assert_eq!(engine.admin_period_ns(), Some(250_000));

    // Enqueue some frames — transition must wait for drain.
    engine.enqueue_frames(10);
    engine.advance_cycle();
    assert_eq!(engine.oper_period_ns(), 500_000, "swap blocked by drain");

    // Partially drain.
    engine.drain_frames(7);
    engine.advance_cycle();
    assert_eq!(engine.oper_period_ns(), 500_000, "still 3 frames pending");

    // Full drain.
    engine.drain_frames(3);
    assert_eq!(engine.drain_pending(), 0);
    engine.advance_cycle();
    assert_eq!(engine.oper_period_ns(), 250_000, "swap completed");
    assert!(engine.admin_period_ns().is_none());

    // ── Step 2: Verify transition log ────────────────────────────────────
    let log = engine.transition_log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].old_period_ns, 500_000);
    assert_eq!(log[0].new_period_ns, 250_000);

    // ── Step 3: Reject invalid requests ──────────────────────────────────
    // Non-aligned period.
    assert_eq!(
        engine.request_scale(300_000),
        CycleScaleResult::InvalidAlignment
    );
    // Out of range.
    assert_eq!(engine.request_scale(50_000), CycleScaleResult::OutOfRange);

    // ── Step 4: Scale back up to 1 ms ────────────────────────────────────
    assert_eq!(engine.request_scale(1_000_000), CycleScaleResult::Accepted);
    // Second request while pending → rejected.
    assert_eq!(
        engine.request_scale(500_000),
        CycleScaleResult::TransitionPending
    );
    // Advance to swap.
    engine.advance_cycle();
    assert_eq!(engine.oper_period_ns(), 1_000_000);
    assert_eq!(engine.transition_log().len(), 2);

    // ── Step 5: advance_time with sub-cycle increments ───────────────────
    assert_eq!(engine.request_scale(500_000), CycleScaleResult::Accepted);
    let b1 = engine.advance_time(400_000);
    assert_eq!(b1, 0, "not yet at boundary");
    let b2 = engine.advance_time(600_000);
    assert!(b2 >= 1, "crossed boundary");
    assert_eq!(engine.oper_period_ns(), 500_000);
}
