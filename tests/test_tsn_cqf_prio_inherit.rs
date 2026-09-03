use toy_tcpip::tsn_cqf_prio_inherit::{PriorityInheritVerdict, TsnCqfPrioInheritEngine};

#[test]
fn test_tsn_cqf_prio_inherit_lifecycle() {
    let mut engine = TsnCqfPrioInheritEngine::new();

    // 1. Low-priority Stream 10 (PCP 1) locks resource 100
    engine.acquire_resource(100, 10, 1);

    // 2. High-priority Stream 20 (PCP 6) requests resource 100 -> Priority inheritance
    let v1 = engine.request_resource(100, 20, 6);
    assert_eq!(
        v1,
        PriorityInheritVerdict::Inherited {
            base_pcp: 1,
            inherited_pcp: 6,
            blocking_stream_id: 10,
        }
    );

    // 3. Critical Stream 30 (PCP 7) requests resource 100 -> Priority elevated to PCP 7
    let v2 = engine.request_resource(100, 30, 7);
    assert_eq!(
        v2,
        PriorityInheritVerdict::Inherited {
            base_pcp: 1,
            inherited_pcp: 7,
            blocking_stream_id: 10,
        }
    );

    // 4. Stream 10 finishes transmission and releases resource
    let old_holder = engine.release_resource(100);
    assert_eq!(old_holder, Some(10));

    // Stream 30 now holds resource at PCP 7
    let res = &engine.resources[0];
    assert_eq!(res.holder_stream_id, 30);
    assert_eq!(res.effective_pcp, 7);
    assert_eq!(engine.total_inversion_events, 2);
}
