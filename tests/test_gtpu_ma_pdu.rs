use toy_tcpip::gtpu_ma_pdu::{AccessLegType, AtsssMode, MaPduSessionEngine};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_gtpu_ma_pdu_atsss_load_balancing_and_fallback() {
    let mut ma_sess = MaPduSessionEngine::new(
        1001,
        AtsssMode::LoadBalancing {
            ratio_3gpp_percent: 50,
        },
        Ipv4Address::new(10, 0, 0, 1),
        0x1111,
        Ipv4Address::new(192, 168, 1, 1),
        0x2222,
    );

    // Test 100 packets distribution: 50% 3GPP and 50% Non-3GPP
    let mut three_gpp_count = 0;
    let mut non_three_gpp_count = 0;
    for _ in 0..100 {
        let (leg, _, _) = ma_sess.steer_packet().unwrap();
        if leg == AccessLegType::ThreeGpp {
            three_gpp_count += 1;
        } else {
            non_three_gpp_count += 1;
        }
    }
    assert_eq!(three_gpp_count, 50);
    assert_eq!(non_three_gpp_count, 50);

    // If 3GPP fails, fallback to Non-3GPP 100%
    ma_sess.set_leg_availability(AccessLegType::ThreeGpp, false);
    for _ in 0..10 {
        let (leg, _, _) = ma_sess.steer_packet().unwrap();
        assert_eq!(leg, AccessLegType::NonThreeGpp);
    }
}
