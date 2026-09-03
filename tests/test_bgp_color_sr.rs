//! Integration tests for BGP Color-Aware SR-TE Steering (RFC 9012 / RFC 9256).

use toy_tcpip::bgp_color_sr::{
    BGP_EXT_COMM_SUBTYPE_COLOR, BGP_EXT_COMM_TYPE_OPAQUE, BgpColorCommunity, CoBitsMode,
    ColorAwareSrEngine, ColorSrPolicy, ColorSrSegmentList, SrSteeringVerdict,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;

#[test]
fn test_bgp_color_constants() {
    assert_eq!(BGP_EXT_COMM_TYPE_OPAQUE, 0x03);
    assert_eq!(BGP_EXT_COMM_SUBTYPE_COLOR, 0x0B);
}

#[test]
fn test_bgp_color_srv6_candidate_path_preference_selection() {
    let mut engine = ColorAwareSrEngine::new();
    let egress_node = Ipv4Address::new(10, 255, 0, 1);
    let color_ultra_low_jitter = 500;

    let sid1 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let sid2 = Ipv6Address([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

    // Primary Path: Pref 200
    engine.add_policy(ColorSrPolicy {
        color: color_ultra_low_jitter,
        endpoint: egress_node,
        preference: 200,
        is_active: true,
        segment_list: ColorSrSegmentList::Srv6Sids(vec![sid1]),
    });

    // Secondary Path: Pref 100
    engine.add_policy(ColorSrPolicy {
        color: color_ultra_low_jitter,
        endpoint: egress_node,
        preference: 100,
        is_active: true,
        segment_list: ColorSrSegmentList::Srv6Sids(vec![sid2]),
    });

    let comm = BgpColorCommunity::new(color_ultra_low_jitter, CoBitsMode::FallbackBestEffort);

    // Should choose highest preference (Pref 200 -> sid1)
    let steer1 = engine.steer_route(egress_node, Some(&comm));
    match steer1 {
        SrSteeringVerdict::SteeredOverPolicy { segments, .. } => {
            assert_eq!(segments, ColorSrSegmentList::Srv6Sids(vec![sid1]));
        }
        other => panic!("Expected SteeredOverPolicy with sid1, got {:?}", other),
    }
}
