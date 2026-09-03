use toy_tcpip::geneve_security::{
    GENEVE_OPT_CLASS_GBP, GENEVE_OPT_TYPE_GBP, GenevePolicyEngine, MicrosegAction,
    MicrosegDecision, MicrosegRule, SecurityGroupTag,
};

#[test]
fn test_geneve_gbp_option_constants_and_codec() {
    assert_eq!(GENEVE_OPT_CLASS_GBP, 0x0108);
    assert_eq!(GENEVE_OPT_TYPE_GBP, 0x01);

    let sgt = SecurityGroupTag::new(500, 600, 9999);
    let bytes = sgt.serialize();
    assert_eq!(bytes.len(), 8);

    let parsed = SecurityGroupTag::parse(&bytes).expect("Valid parse");
    assert_eq!(parsed.src_sgt, 500);
    assert_eq!(parsed.dst_sgt, 600);
    assert_eq!(parsed.tenant_id, 9999);
}

#[test]
fn test_geneve_microsegmentation_matrix_policies() {
    let mut engine = GenevePolicyEngine::new(MicrosegAction::Deny);

    // Rule 1: Allow Front-end (SGT 100) -> API Gateway (SGT 200) on TCP 443
    engine.add_rule(MicrosegRule::new(
        1,
        Some(100),
        Some(200),
        Some(6), // TCP
        Some(443),
        MicrosegAction::Allow,
    ));

    // Rule 2: Rate-limit API Gateway (SGT 200) -> Database (SGT 300) on TCP 5432 (Postgres)
    engine.add_rule(MicrosegRule::new(
        2,
        Some(200),
        Some(300),
        Some(6), // TCP
        Some(5432),
        MicrosegAction::RateLimitBps(10_000_000), // 10 Mbps
    ));

    // Test 1: Front-end to API Gateway on 443 -> Permit
    let dec1 = engine.evaluate(100, 200, 6, Some(443));
    assert_eq!(dec1, MicrosegDecision::Permit);

    // Test 2: API Gateway to DB on 5432 -> RateLimit
    let dec2 = engine.evaluate(200, 300, 6, Some(5432));
    assert_eq!(dec2, MicrosegDecision::RateLimit(10_000_000));

    // Test 3: Direct Front-end to DB on 5432 -> Drop (Zero-trust isolation)
    let dec3 = engine.evaluate(100, 300, 6, Some(5432));
    assert_eq!(dec3, MicrosegDecision::Drop);

    assert_eq!(engine.total_evaluated, 3);
    assert_eq!(engine.total_permitted, 2);
    assert_eq!(engine.total_dropped, 1);
}
