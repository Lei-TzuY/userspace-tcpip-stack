use toy_tcpip::tsn_cqf_trtcm::{TsnCqfTrTcmEngine, TrTcmColor};

#[test]
fn test_tsn_cqf_trtcm_metering_lifecycle() {
    let mut engine = TsnCqfTrTcmEngine::new(
        100_000_000, // 100 Mbps CIR
        1500,        // 1500 B CBS
        200_000_000, // 200 Mbps PIR
        3000,        // 3000 B PBS
    );

    // Initial bursts
    let c1 = engine.ingest_frame(1, 1000, 0);
    assert_eq!(c1, TrTcmColor::Green);

    let c2 = engine.ingest_frame(1, 1000, 0);
    assert_eq!(c2, TrTcmColor::Yellow);

    let c3 = engine.ingest_frame(1, 1500, 0);
    assert_eq!(c3, TrTcmColor::Red);

    assert_eq!(engine.total_green_admitted, 1);
    assert_eq!(engine.total_yellow_admitted, 1);
    assert_eq!(engine.total_red_dropped, 1);
}
