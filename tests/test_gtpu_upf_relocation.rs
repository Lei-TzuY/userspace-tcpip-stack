use toy_tcpip::gtpu_upf_relocation::{
    GTPU_MSG_END_MARKER, HandoverGtpuPacket, TargetUpfRelocationEngine, UpfHandoverState,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_gtpu_upf_relocation_and_end_marker_transition() {
    let mut t_upf = TargetUpfRelocationEngine::new(
        99,
        0xDEADBEEF, // Indirect tunnel TEID
        0xCAFEBABE, // Direct gNodeB TEID
        Ipv4Address::new(10, 10, 10, 1),
        Ipv4Address::new(10, 10, 10, 2),
    );

    // Initial state: Indirect forwarding
    assert_eq!(t_upf.state, UpfHandoverState::IndirectForwarding);

    // Incoming indirect data
    let d1 = t_upf.handle_indirect_packet(HandoverGtpuPacket::new_gpdu(0xDEADBEEF, vec![1, 2, 3]));
    assert_eq!(d1.len(), 0);
    assert_eq!(t_upf.indirect_buffer.len(), 1);

    // End Marker packet arrives!
    let marker = HandoverGtpuPacket::new_end_marker(0xDEADBEEF);
    assert_eq!(marker.message_type, GTPU_MSG_END_MARKER);

    let delivered = t_upf.handle_indirect_packet(marker);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].teid, 0xCAFEBABE);
    assert_eq!(t_upf.state, UpfHandoverState::SwitchedToDirect);

    // Subsequent packets directly forwarded
    let d2 = t_upf.handle_indirect_packet(HandoverGtpuPacket::new_gpdu(0xDEADBEEF, vec![4, 5, 6]));
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].teid, 0xCAFEBABE);
}
