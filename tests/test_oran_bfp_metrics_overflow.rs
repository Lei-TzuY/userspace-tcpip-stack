use toy_tcpip::oran_bfp_compression::{ComplexIq, OranBfpEngine};

#[test]
fn test_oran_bfp_quality_metrics_handle_full_i16_delta_without_overflow() {
    let original = [ComplexIq {
        i: i16::MIN,
        q: i16::MAX,
    }];
    let reconstructed = [ComplexIq {
        i: i16::MAX,
        q: i16::MIN,
    }];

    let metrics = OranBfpEngine::calculate_quality_metrics(&original, &reconstructed, 4);

    assert!(metrics.evm_percent.is_finite());
    assert!(metrics.sqnr_db.is_finite());
    assert_eq!(metrics.compression_ratio, 1.0);
}
