use toy_tcpip::geneve_telemetry_opt::{
    GeneveTelemetryEngine, GeneveTelemetryOption, GENEVE_OPT_CLASS_INT_TELEMETRY,
    GENEVE_OPT_TYPE_INT_HOP_METADATA,
};

#[test]
fn test_geneve_int_option_codec_and_telemetry_collection() {
    let mut sw1 = GeneveTelemetryEngine::new(0x0A000101);
    let mut sw2 = GeneveTelemetryEngine::new(0x0A000102);

    let mut opt = GeneveTelemetryOption::new();

    // Node 1 inserts hop metadata
    sw1.insert_hop(&mut opt, 1, 48, 250, 8192);

    // Node 2 inserts transit hop metadata
    sw2.insert_hop(&mut opt, 48, 2, 180, 4096);

    let geneve_opt = opt.to_geneve_option();
    assert_eq!(geneve_opt.class, GENEVE_OPT_CLASS_INT_TELEMETRY);
    assert_eq!(geneve_opt.opt_type, GENEVE_OPT_TYPE_INT_HOP_METADATA);
    assert_eq!(geneve_opt.data.len(), 32); // 2 hops * 16 bytes

    // Collector at egress parses Geneve option TLV
    let parsed_opt = GeneveTelemetryOption::from_geneve_option(&geneve_opt).expect("parse option");
    assert_eq!(parsed_opt.hops.len(), 2);

    assert_eq!(parsed_opt.hops[0].switch_id, 0x0A000101);
    assert_eq!(parsed_opt.hops[0].ingress_port, 1);
    assert_eq!(parsed_opt.hops[0].egress_port, 48);
    assert_eq!(parsed_opt.hops[0].hop_latency_ns, 250);
    assert_eq!(parsed_opt.hops[0].queue_occupancy_bytes, 8192);

    assert_eq!(parsed_opt.hops[1].switch_id, 0x0A000102);
    assert_eq!(parsed_opt.hops[1].ingress_port, 48);
    assert_eq!(parsed_opt.hops[1].egress_port, 2);
    assert_eq!(parsed_opt.hops[1].hop_latency_ns, 180);
    assert_eq!(parsed_opt.hops[1].queue_occupancy_bytes, 4096);
}
