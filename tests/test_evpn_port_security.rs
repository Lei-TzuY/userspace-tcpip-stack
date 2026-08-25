use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::evpn_port_security::{EvpnPortSecurityEngine, PortSecurityViolationAction, PortState};

#[test]
fn test_evpn_port_security_lifecycle() {
    let mut sec = EvpnPortSecurityEngine::new();
    sec.configure_port("ge0/1", 1, PortSecurityViolationAction::Shutdown, 60);

    let m1 = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01]);
    let m2 = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x02]);

    // 1st MAC -> OK
    assert!(sec.ingress_frame("ge0/1", m1, 100));

    // 2nd MAC -> Triggers shutdown!
    assert!(!sec.ingress_frame("ge0/1", m2, 100));

    let p = sec.ports.get("ge0/1").unwrap();
    assert_eq!(p.state, PortState::ErrDisabled);
}
