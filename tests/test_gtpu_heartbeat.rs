use toy_tcpip::gtpu_heartbeat::{GtpuEchoMessage, GtpuPathEngine, GtpuPathState, GTPU_MSG_ECHO_REQUEST};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_gtpu_heartbeat_echo_roundtrip_and_recovery_ie() {
    let mut engine = GtpuPathEngine::new(7);
    let peer_ip = Ipv4Address::new(10, 20, 30, 40);
    engine.add_peer(peer_ip, 3);

    // 1. Initiate Echo Request
    let req = engine.send_echo_request(peer_ip).unwrap();
    assert_eq!(req.message_type, GTPU_MSG_ECHO_REQUEST);
    assert_eq!(req.restart_counter, 7);

    // 2. Peer replies with Echo Response containing its restart counter (e.g. 15)
    let resp = GtpuEchoMessage::new_response(req.sequence_number, 15);
    assert!(engine.handle_echo_response(peer_ip, &resp));

    let peer = &engine.peers[0];
    assert_eq!(peer.state, GtpuPathState::Active);
    assert_eq!(peer.peer_restart_counter, Some(15));
    assert_eq!(peer.total_echo_requests_sent, 1);
    assert_eq!(peer.total_echo_responses_recv, 1);
}

#[test]
fn test_gtpu_heartbeat_timeout_path_failure() {
    let mut engine = GtpuPathEngine::new(1);
    let peer_ip = Ipv4Address::new(192, 168, 1, 254);
    engine.add_peer(peer_ip, 2); // Max 2 retries

    // Probe 1
    engine.send_echo_request(peer_ip);
    assert_eq!(engine.peers[0].state, GtpuPathState::Active);

    // Probe 2 -> Degraded
    engine.send_echo_request(peer_ip);
    assert_eq!(engine.peers[0].state, GtpuPathState::Degraded);

    // Probe 3 -> Exceeds max retries 2 -> Failed!
    engine.send_echo_request(peer_ip);
    assert_eq!(engine.peers[0].state, GtpuPathState::Failed);
    assert_eq!(engine.peers[0].total_path_failures, 1);
}
