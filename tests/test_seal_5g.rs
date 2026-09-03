//! Integration tests for 3GPP TS 29.538 / TS 23.434 5G SEAL (Service Enabler Architecture Layer).

use toy_tcpip::seal_5g::*;

// ---------------------------------------------------------------------------
// 1. Group Management Lifecycle Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_seal_group_management_lifecycle() {
    let mut seal = SealServerEngine::new("seal-server-01");

    let group_id = "val-group-v2x-platoon-alpha";
    seal.create_val_group(group_id, ValDomain::V2xAutomotive, 3)
        .unwrap();

    // Add 3 members
    seal.add_group_member(group_id, "car-01").unwrap();
    seal.add_group_member(group_id, "car-02").unwrap();
    seal.add_group_member(group_id, "car-03").unwrap();

    // 4th member exceeds capacity
    let err = seal.add_group_member(group_id, "car-04");
    assert_eq!(err, Err(SealError::GroupCapacityExceeded));

    // Remove car-02
    seal.remove_group_member(group_id, "car-02").unwrap();

    // Now car-04 can be added
    seal.add_group_member(group_id, "car-04").unwrap();

    let members = &seal.groups.get(group_id).unwrap().members;
    assert_eq!(
        members,
        &vec![
            "car-01".to_string(),
            "car-03".to_string(),
            "car-04".to_string()
        ]
    );
}

// ---------------------------------------------------------------------------
// 2. Geofencing Entry and Exit Transitions
// ---------------------------------------------------------------------------

#[test]
fn test_seal_geofencing_entry_and_exit_alerts() {
    let mut seal = SealServerEngine::new("seal-server-02");

    let zone_id = "no-fly-zone-airport";
    let airport_center = GeoPoint {
        latitude_e6: 35_549_400,
        longitude_e6: 139_779_800,
    };
    seal.register_geofence(zone_id, airport_center, 500); // 500m radius

    let drone_id = "drone-delivery-88";

    // Step 1: Drone starts far away (~1500m north)
    let outside_pos = GeoPoint {
        latitude_e6: 35_563_000,
        longitude_e6: 139_779_800,
    };
    let alerts1 = seal.update_device_location(drone_id, outside_pos);
    assert!(alerts1.is_empty());

    // Step 2: Drone flies inside airport perimeter (~100m from center)
    let inside_pos = GeoPoint {
        latitude_e6: 35_550_200,
        longitude_e6: 139_779_800,
    };
    let alerts2 = seal.update_device_location(drone_id, inside_pos);
    assert_eq!(alerts2.len(), 1);
    assert_eq!(
        alerts2[0],
        SealAlertEvent::GeofenceEntry {
            val_user_id: drone_id.to_string(),
            zone_id: zone_id.to_string(),
        }
    );

    // Step 3: Drone exits the zone
    let alerts3 = seal.update_device_location(drone_id, outside_pos);
    assert_eq!(alerts3.len(), 1);
    assert_eq!(
        alerts3[0],
        SealAlertEvent::GeofenceExit {
            val_user_id: drone_id.to_string(),
            zone_id: zone_id.to_string(),
        }
    );
}

// ---------------------------------------------------------------------------
// 3. Proximity Detection
// ---------------------------------------------------------------------------

#[test]
fn test_seal_proximity_detection() {
    let mut seal = SealServerEngine::new("seal-server-03");

    let car_a = "car-tesla-01";
    let car_b = "car-toyota-02";

    // Position Car A
    seal.update_device_location(
        car_a,
        GeoPoint {
            latitude_e6: 35_680_000,
            longitude_e6: 139_760_000,
        },
    );

    // Position Car B close by (~30 meters apart)
    seal.update_device_location(
        car_b,
        GeoPoint {
            latitude_e6: 35_680_250,
            longitude_e6: 139_760_000,
        },
    );

    // Proximity threshold 100 meters -> Detected
    let res = seal.check_proximity(car_a, car_b, 100).unwrap();
    assert!(res.is_some());
    match res.unwrap() {
        SealAlertEvent::ProximityDetected {
            val_user_id_a,
            val_user_id_b,
            distance_meters,
        } => {
            assert_eq!(val_user_id_a, car_a);
            assert_eq!(val_user_id_b, car_b);
            assert!(distance_meters < 50);
        }
        _ => panic!("Expected ProximityDetected event"),
    }

    // Proximity threshold 10 meters -> Not detected
    let res2 = seal.check_proximity(car_a, car_b, 10).unwrap();
    assert!(res2.is_none());
}

// ---------------------------------------------------------------------------
// 4. Network Resource Reservation and Release
// ---------------------------------------------------------------------------

#[test]
fn test_seal_network_resource_reservation_and_release() {
    let mut seal = SealServerEngine::new("seal-server-04");

    let group_id = "val-drone-swarm-01";
    seal.create_val_group(group_id, ValDomain::UasDroneSwarm, 10)
        .unwrap();

    // Reserve QoS resources
    let res_id = seal.reserve_network_resources(group_id, 250, 8).unwrap();
    let res = seal.qos_reservations.get(&res_id).unwrap();
    assert_eq!(res.required_bandwidth_mbps, 250);
    assert_eq!(res.max_latency_ms, 8);
    assert_eq!(res.active, true);

    // Release reservation
    seal.release_network_resources(&res_id)
        .expect("Release failed");
    assert_eq!(seal.qos_reservations.get(&res_id).unwrap().active, false);
}

// ---------------------------------------------------------------------------
// 5. Error Handling
// ---------------------------------------------------------------------------

#[test]
fn test_seal_error_handling() {
    let mut seal = SealServerEngine::new("seal-server-05");

    // Add member to unknown group
    let err1 = seal.add_group_member("ghost-group", "user-1");
    assert_eq!(err1, Err(SealError::GroupNotFound));

    seal.create_val_group("g1", ValDomain::SmartCity, 5)
        .unwrap();
    seal.add_group_member("g1", "user-1").unwrap();

    // Duplicate member
    let err2 = seal.add_group_member("g1", "user-1");
    assert_eq!(err2, Err(SealError::MemberAlreadyInGroup));

    // Remove non-existent member
    let err3 = seal.remove_group_member("g1", "user-99");
    assert_eq!(err3, Err(SealError::MemberNotFound));

    // Check proximity for unregistered device
    let err4 = seal.check_proximity("user-1", "user-unknown", 50);
    assert_eq!(err4, Err(SealError::DeviceLocationNotFound));
}
