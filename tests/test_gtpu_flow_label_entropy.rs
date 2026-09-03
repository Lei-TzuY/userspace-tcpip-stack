use toy_tcpip::gtpu_flow_label_entropy::{
    FlowLabelAlgorithm, GtpuFlowLabelEntropyEngine, InnerPacketTuple,
};

#[test]
fn test_gtpu_flow_label_entropy_integration() {
    let mut engine = GtpuFlowLabelEntropyEngine::new(FlowLabelAlgorithm::Fnv1aEntropy, 16);

    // Simulate 50 distinct flows across 16 ECMP bins
    for i in 0..50 {
        let tuple = InnerPacketTuple::new(
            [10, 0, (i / 256) as u8, (i % 256) as u8],
            [172, 16, 0, 1],
            (50000 + i) as u16,
            8080,
            6,
            0x10000 + i as u32,
            9,
        );

        let verdict = engine.compute_flow_label(&tuple);
        assert!(verdict.flow_label_20bit > 0);
        assert!(verdict.flow_label_20bit <= 0x000F_FFFF);
        assert!(verdict.ecmp_bin < 16);
    }

    assert_eq!(engine.total_computations, 50);

    // Verify entropy spreads across multiple ECMP buckets
    let non_empty_buckets = engine.bucket_counts.iter().filter(|&&c| c > 0).count();
    assert!(
        non_empty_buckets >= 8,
        "Expected good distribution across ECMP buckets, got {}",
        non_empty_buckets
    );
}
