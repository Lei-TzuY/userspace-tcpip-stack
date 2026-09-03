// tests/test_diameter_s13_geo_fence.rs

use toy_tcpip::diameter_s13_geo_fence::{
    DIAMETER_AUTHORIZATION_REJECTED, DIAMETER_SUCCESS, GeoVerdict, S13GeoFenceEngine,
};

#[test]
fn test_diameter_s13_geo_fence_lifecycle() {
    let mut engine = S13GeoFenceEngine::new(900); // 900 km/h commercial airliner max
    engine.add_allowed_plmn("310410"); // AT&T USA

    // TAC 100: New York (40.71 deg N, -74.00 deg W)
    engine.register_tracking_area(100, "310410", 40_710_000, -74_000_000, false);
    // TAC 200: Los Angeles (34.05 deg N, -118.24 deg W -> ~3900 km)
    engine.register_tracking_area(200, "310410", 34_050_000, -118_240_000, false);
    // TAC 666: Prohibited border testing zone
    engine.register_tracking_area(666, "310410", 32_000_000, -110_000_000, true);

    let imei = "358900001234567";

    // 1. Initial check in NY at t = 10,000s -> Legitimate
    let v1 = engine.inspect_equipment_location(imei, 100, "310410", 10_000);
    assert_eq!(
        v1,
        GeoVerdict::LegitimateLocation {
            tac: 100,
            plmn_id: "310410".to_string(),
            result_code: DIAMETER_SUCCESS,
        }
    );

    // 2. Immediate check in LA after 100 seconds (3900 km in 100s -> ~140,000 km/h) -> Impossible travel fraud
    let v2 = engine.inspect_equipment_location(imei, 200, "310410", 10_100);
    match v2 {
        GeoVerdict::ImpossibleTravelFraud {
            imei: res_imei,
            calculated_speed_kmh,
            result_code,
            ..
        } => {
            assert_eq!(res_imei, imei);
            assert!(calculated_speed_kmh > 10_000);
            assert_eq!(result_code, DIAMETER_AUTHORIZATION_REJECTED);
        }
        _ => panic!("Expected ImpossibleTravelFraud verdict"),
    }

    // 3. Prohibited TAC 666 -> RestrictedZoneViolation
    let v3 = engine.inspect_equipment_location("358900009999999", 666, "310410", 10_000);
    match v3 {
        GeoVerdict::RestrictedZoneViolation { result_code, .. } => {
            assert_eq!(result_code, DIAMETER_AUTHORIZATION_REJECTED);
        }
        _ => panic!("Expected RestrictedZoneViolation"),
    }

    // 4. Unauthorized foreign PLMN "99999" -> UnauthorizedPlmn
    let v4 = engine.inspect_equipment_location("358900009999999", 100, "99999", 10_000);
    match v4 {
        GeoVerdict::UnauthorizedPlmn { result_code, .. } => {
            assert_eq!(result_code, DIAMETER_AUTHORIZATION_REJECTED);
        }
        _ => panic!("Expected UnauthorizedPlmn"),
    }
}
