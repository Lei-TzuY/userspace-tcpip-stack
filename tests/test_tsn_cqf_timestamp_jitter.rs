use toy_tcpip::tsn_cqf_timestamp_jitter::{
    JitterAnalyzerVerdict, StreamJitterStats, TsnCqfTimestampJitterEngine,
};

#[test]
fn test_tsn_cqf_timestamp_jitter_lifecycle() {
    let mut engine = TsnCqfTimestampJitterEngine::new(50);

    // Stream 1: Telemetry Stream (Max Latency 80 µs, Max Jitter 8 µs)
    engine.register_stream(StreamJitterStats::new(1, "Lidar-Sensors", 80_000, 8_000));

    // 1. First packet: Latency = 40 µs, Jitter = 0 µs
    let v1 = engine.record_frame(1, 1, 10_000, 50_000);
    assert_eq!(
        v1,
        JitterAnalyzerVerdict::Compliant {
            latency_ns: 40_000,
            jitter_ns: 0,
        }
    );

    // 2. Second packet: Latency = 45 µs, Jitter = 5 µs (<= 8 µs)
    let v2 = engine.record_frame(2, 1, 100_000, 145_000);
    assert_eq!(
        v2,
        JitterAnalyzerVerdict::Compliant {
            latency_ns: 45_000,
            jitter_ns: 5_000,
        }
    );

    // 3. Third packet: Latency = 58 µs, Jitter = |58 - 45| = 13 µs (> 8 µs Jitter breach)
    let v3 = engine.record_frame(3, 1, 200_000, 258_000);
    assert_eq!(
        v3,
        JitterAnalyzerVerdict::JitterBreached {
            jitter_ns: 13_000,
            allowed_jitter_ns: 8_000,
        }
    );

    // 4. Fourth packet: Latency = 95 µs (> 80 µs Latency deadline breach)
    let v4 = engine.record_frame(4, 1, 300_000, 395_000);
    assert_eq!(
        v4,
        JitterAnalyzerVerdict::LatencyBreached {
            latency_ns: 95_000,
            allowed_latency_ns: 80_000,
        }
    );

    let stream = &engine.streams[0];
    assert_eq!(stream.total_frames_processed, 4);
    assert_eq!(stream.min_latency_ns, 40_000);
    assert_eq!(stream.max_latency_ns, 95_000);
    assert_eq!(stream.jitter_breach_count, 1);
    assert_eq!(stream.latency_breach_count, 1);
}
