use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tsn_qcz_congestion::{FlowTuple, QczCongestionEngine};

#[test]
fn test_tsn_qcz_congestion_isolation_mitigation() {
    let cp_mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mut engine = QczCongestionEngine::new(cp_mac, 1500);

    let flow_heavy = FlowTuple::new(
        Ipv4Address::new(10, 1, 1, 1),
        Ipv4Address::new(10, 2, 2, 2),
        8000,
        8000,
        17,
    );

    let flow_latency_sensitive = FlowTuple::new(
        Ipv4Address::new(10, 3, 3, 3),
        Ipv4Address::new(10, 4, 4, 4),
        9000,
        9000,
        17,
    );

    // Initial packet 1000B on heavy flow -> UQ = 1000B (<= 1500B)
    assert!(
        engine
            .enqueue_packet(flow_heavy, vec![0x11; 1000])
            .is_none()
    );
    assert_eq!(engine.uncongested_queue.len(), 1);
    assert_eq!(engine.isolated_queue.len(), 0);

    // Second packet 800B on heavy flow -> 1000 + 800 = 1800B > 1500B threshold!
    // Triggers flow isolation into CIQ and emits CNM
    let cnm = engine
        .enqueue_packet(flow_heavy, vec![0x11; 800])
        .expect("CNM must be generated");
    assert_eq!(cnm.offending_flow, flow_heavy);
    assert_eq!(cnm.cp_mac, cp_mac);
    assert_eq!(engine.isolated_queue.len(), 1);
    assert_eq!(engine.total_isolated, 1);

    // Latency sensitive packet 200B -> Enters UQ immediately without suffering HoL blocking!
    assert!(
        engine
            .enqueue_packet(flow_latency_sensitive, vec![0x22; 200])
            .is_none()
    );
    assert_eq!(engine.uncongested_queue.len(), 2);

    let drained_uq = engine.drain_uncongested();
    assert_eq!(drained_uq.len(), 2);
    assert_eq!(drained_uq[1].flow, flow_latency_sensitive);
}

#[test]
fn test_tsn_qcz_clear_isolation() {
    let mut engine = QczCongestionEngine::new([0; 6], 500);
    let flow = FlowTuple::new(
        Ipv4Address::new(1, 1, 1, 1),
        Ipv4Address::new(2, 2, 2, 2),
        100,
        100,
        6,
    );

    engine.enqueue_packet(flow, vec![0; 600]);
    assert!(engine.isolated_flows.contains(&flow));

    assert!(engine.clear_isolated_flow(&flow));
    assert!(!engine.isolated_flows.contains(&flow));
}
