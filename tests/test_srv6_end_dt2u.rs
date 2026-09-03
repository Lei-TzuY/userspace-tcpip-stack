//! Integration tests for SRv6 End.DT2U L2 EVPN Unicast Lookup (RFC 8986 §4.13)

use std::net::Ipv6Addr;
use toy_tcpip::ethernet::{ETHERTYPE_IPV4, EthernetFrame, MacAddress};
use toy_tcpip::srv6_end_dt2u::{
    EndDt2uResult, Srv6EndDt2uEngine, TenantAttachmentCircuit, TenantMacVrf, UnknownUnicastPolicy,
};

#[test]
fn test_srv6_end_dt2u_multi_tenant_and_flooding_policy() {
    let tenant_red_sid: Ipv6Addr = "2001:db8:1::d720:10".parse().unwrap();
    let tenant_blue_sid: Ipv6Addr = "2001:db8:2::d720:20".parse().unwrap();

    let mut engine = Srv6EndDt2uEngine::new("2001:db8::1".parse().unwrap());

    // 1. Tenant RED (Policy: Drop unknown unicast)
    let mut vrf_red = TenantMacVrf::new(10, "RED".to_string(), UnknownUnicastPolicy::Drop);
    vrf_red.add_ac(TenantAttachmentCircuit {
        ac_id: 101,
        port_name: "xe-0/0/1".to_string(),
        vlan_id: Some(10),
    });
    let red_mac1 = MacAddress::new([0x00, 0x11, 0x11, 0x11, 0x11, 0x11]);
    vrf_red.learn_mac(red_mac1, 101);
    engine.bind_sid(tenant_red_sid, vrf_red);

    // 2. Tenant BLUE (Policy: Flood to access circuits)
    let mut vrf_blue = TenantMacVrf::new(
        20,
        "BLUE".to_string(),
        UnknownUnicastPolicy::FloodToAccessCircuits,
    );
    vrf_blue.add_ac(TenantAttachmentCircuit {
        ac_id: 201,
        port_name: "xe-0/0/2".to_string(),
        vlan_id: Some(20),
    });
    vrf_blue.add_ac(TenantAttachmentCircuit {
        ac_id: 202,
        port_name: "xe-0/0/3".to_string(),
        vlan_id: Some(20),
    });
    let blue_mac1 = MacAddress::new([0x00, 0x22, 0x22, 0x22, 0x22, 0x22]);
    vrf_blue.learn_mac(blue_mac1, 201);
    engine.bind_sid(tenant_blue_sid, vrf_blue);

    // Test Known Unicast forwarding in RED
    let src_mac = MacAddress::new([0x00, 0x99, 0x99, 0x99, 0x99, 0x99]);
    let packet = EthernetFrame::serialize(red_mac1, src_mac, ETHERTYPE_IPV4, b"RED Tenant Data");

    let res_red = engine.process_end_dt2u(&tenant_red_sid, &packet, false);
    match res_red {
        EndDt2uResult::ForwardedToAc {
            table_id,
            ac_id,
            dst_mac,
            ..
        } => {
            assert_eq!(table_id, 10);
            assert_eq!(ac_id, 101);
            assert_eq!(dst_mac, red_mac1);
        }
        _ => panic!("Expected ForwardedToAc for RED"),
    }

    // Test Unknown Unicast in BLUE (Triggers Flooding across both AC 201 and 202)
    let unknown_blue = MacAddress::new([0x00, 0x88, 0x88, 0x88, 0x88, 0x88]);
    let packet_blue_unk = EthernetFrame::serialize(
        unknown_blue,
        src_mac,
        ETHERTYPE_IPV4,
        b"BLUE Tenant Broadcast/Unknown",
    );

    let res_blue_unk = engine.process_end_dt2u(&tenant_blue_sid, &packet_blue_unk, false);
    match res_blue_unk {
        EndDt2uResult::FloodedToAcs {
            table_id,
            mut ac_ids,
            dst_mac,
            ..
        } => {
            assert_eq!(table_id, 20);
            assert_eq!(dst_mac, unknown_blue);
            ac_ids.sort();
            assert_eq!(ac_ids, vec![201, 202]);
        }
        _ => panic!("Expected FloodedToAcs for BLUE unknown unicast"),
    }
}
