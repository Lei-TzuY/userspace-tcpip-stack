//! Integration tests for SRv6 End.DT46 Multi-VRF Dual-Stack Routing (RFC 8986).

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;
use toy_tcpip::srv6::Srv6Header;
use toy_tcpip::srv6_end_dt46::{EndDt46Engine, EndDt46ForwardResult, VrfNextHop};

#[test]
fn test_srv6_end_dt46_multi_vrf_isolation() {
    let mut engine = EndDt46Engine::new();

    let sid_vrf10 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
    let sid_vrf20 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20]);

    engine.register_dt46_sid(sid_vrf10, 10);
    engine.register_dt46_sid(sid_vrf20, 20);

    // VRF 10 routing table
    let vrf10 = engine.get_vrf_mut(10);
    vrf10.add_ipv4_route(
        Ipv4Address::new(172, 16, 0, 0),
        16,
        VrfNextHop::DirectLocal {
            out_if: "vrf10_eth0".to_string(),
        },
    );
    vrf10.add_ipv6_route(
        Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
        64,
        VrfNextHop::DirectLocal {
            out_if: "vrf10_eth6".to_string(),
        },
    );

    // VRF 20 routing table (disjoint tenant space)
    let vrf20 = engine.get_vrf_mut(20);
    vrf20.add_ipv4_route(
        Ipv4Address::new(172, 16, 0, 0),
        16,
        VrfNextHop::DirectLocal {
            out_if: "vrf20_eth0".to_string(),
        },
    );

    let srh_vrf10 = Srv6Header::build(41, &[sid_vrf10]);
    let srh_vrf20 = Srv6Header::build(41, &[sid_vrf20]);

    // Packet targeting 172.16.5.99 on VRF 10
    let mut pkt_v4 = vec![0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0];
    pkt_v4.extend_from_slice(&[10, 0, 0, 1]);
    pkt_v4.extend_from_slice(&[172, 16, 5, 99]);
    pkt_v4.extend_from_slice(b"Tenant10");

    let res10 = engine.process_packet(sid_vrf10, srh_vrf10, &pkt_v4);
    match res10 {
        EndDt46ForwardResult::RoutedIpv4 {
            vrf_id, next_hop, ..
        } => {
            assert_eq!(vrf_id, 10);
            assert_eq!(
                next_hop,
                VrfNextHop::DirectLocal {
                    out_if: "vrf10_eth0".to_string()
                }
            );
        }
        other => panic!("Expected RoutedIpv4 for VRF 10, got {:?}", other),
    }

    // Identical target address sent to VRF 20 SID -> routes to VRF 20 interface
    let res20 = engine.process_packet(sid_vrf20, srh_vrf20, &pkt_v4);
    match res20 {
        EndDt46ForwardResult::RoutedIpv4 {
            vrf_id, next_hop, ..
        } => {
            assert_eq!(vrf_id, 20);
            assert_eq!(
                next_hop,
                VrfNextHop::DirectLocal {
                    out_if: "vrf20_eth0".to_string()
                }
            );
        }
        other => panic!("Expected RoutedIpv4 for VRF 20, got {:?}", other),
    }
}

#[test]
fn test_srv6_end_dt46_no_route_and_malformed() {
    let mut engine = EndDt46Engine::new();
    let sid = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x46]);
    engine.register_dt46_sid(sid, 50);

    let srh = Srv6Header::build(41, &[sid]);

    // Unrouted IPv4 destination
    let mut unrouted_pkt = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0];
    unrouted_pkt.extend_from_slice(&[1, 1, 1, 1]);
    unrouted_pkt.extend_from_slice(&[8, 8, 8, 8]); // No route in VRF 50

    let res = engine.process_packet(sid, srh.clone(), &unrouted_pkt);
    match res {
        EndDt46ForwardResult::NoRoute { vrf_id, ip_version } => {
            assert_eq!(vrf_id, 50);
            assert_eq!(ip_version, 4);
        }
        other => panic!("Expected NoRoute, got {:?}", other),
    }

    // Invalid non-IP payload
    let invalid_pkt = vec![0x12, 0x34, 0x56];
    let res_inv = engine.process_packet(sid, srh, &invalid_pkt);
    match res_inv {
        EndDt46ForwardResult::Dropped(_) => {}
        other => panic!("Expected Dropped for invalid payload, got {:?}", other),
    }
}
