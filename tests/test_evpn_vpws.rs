use toy_tcpip::evpn_vpws_fxc::{
    AttachmentCircuit, EVPN_VPWS_FLAG_CONTROL_WORD, EVPN_VPWS_FLAG_PRIMARY,
    EvpnL2AttributesExtCommunity, EvpnVpwsEngine, EvpnVpwsService,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_vpws_cross_connect_and_mtu_checks() {
    let ext_comm = EvpnL2AttributesExtCommunity::new(true, 1500);
    let bytes = ext_comm.serialize();
    assert_ne!(bytes[2] & EVPN_VPWS_FLAG_CONTROL_WORD, 0);
    assert_ne!(bytes[2] & EVPN_VPWS_FLAG_PRIMARY, 0);

    let mut engine = EvpnVpwsEngine::new();

    let service = EvpnVpwsService {
        vpws_service_id: 500,
        remote_service_id: 600,
        remote_pe: Ipv4Address::new(192, 168, 10, 1),
        local_label: 10500,
        remote_label: 10600,
        control_word_enabled: true,
        mtu: 1500,
    };

    engine.bind_cross_connect("xe-0/0/0", 50, service);

    // 1. Normal frame
    let frame = vec![0x00; 100];
    let encap = engine.encapsulate_l2_frame("xe-0/0/0", 50, &frame).unwrap();
    assert_eq!(encap.remote_pe, Ipv4Address::new(192, 168, 10, 1));
    assert_eq!(encap.mpls_label, 10600);
    assert_eq!(encap.control_word, Some(0));

    let (ac, delivered) = engine.decapsulate_vpws_packet(500, &encap).unwrap();
    assert_eq!(
        ac,
        AttachmentCircuit {
            if_name: "xe-0/0/0".to_string(),
            vlan_id: 50
        }
    );
    assert_eq!(delivered, frame);

    // 2. MTU violation on ingress
    let oversized_frame = vec![0x00; 1600];
    let err = engine.encapsulate_l2_frame("xe-0/0/0", 50, &oversized_frame);
    assert!(err.is_err());
}
