use toy_tcpip::S13EquipmentStatus;
use toy_tcpip::diameter_s13_tac_whitelist_expiry::{
    DiameterS13TacWhitelistExpiryEngine, LeaseVerdict,
};

#[test]
fn test_diameter_s13_tac_whitelist_expiry_integration() {
    let mut engine = DiameterS13TacWhitelistExpiryEngine::new();

    // Lease #1: TAC 86000000..86000099, starts t=500, dur=100s, grace=30s, fallback GreyListed
    let id1 = engine.grant_lease(
        86000000,
        86000099,
        500,
        100,
        30,
        S13EquipmentStatus::GrayListed,
        "Trial 5G Routers",
    );
    assert_eq!(id1, 1);

    // Active query at t=550
    let v1 = engine.evaluate_imei("860000001234567", 550);
    assert_eq!(
        v1,
        LeaseVerdict::LeaseActive {
            lease_id: 1,
            imei: "860000001234567".to_string(),
            tac: 86000000,
            remaining_s: 50,
            status: S13EquipmentStatus::WhiteListed,
        }
    );

    // Grace period query at t=615 (expired at 600, grace until 630)
    let v2 = engine.evaluate_imei("860000001234567", 615);
    assert_eq!(
        v2,
        LeaseVerdict::LeaseInGracePeriod {
            lease_id: 1,
            imei: "860000001234567".to_string(),
            tac: 86000000,
            grace_remaining_s: 15,
            status: S13EquipmentStatus::GrayListed,
        }
    );

    // Fully expired query at t=650 -> Fallback GrayListed
    let v3 = engine.evaluate_imei("860000001234567", 650);
    assert_eq!(
        v3,
        LeaseVerdict::LeaseExpiredFallback {
            lease_id: 1,
            imei: "860000001234567".to_string(),
            tac: 86000000,
            fallback_status: S13EquipmentStatus::GrayListed,
        }
    );

    // Sweep expired leases at t=650
    let expired_list = engine.sweep_expired_leases(650);
    assert_eq!(expired_list, vec![1]);

    // Unregistered IMEI -> Default WhiteListed
    let v4 = engine.evaluate_imei("353918001234567", 650);
    assert_eq!(
        v4,
        LeaseVerdict::NoLeaseFound {
            imei: "353918001234567".to_string(),
            tac: 35391800,
            default_status: S13EquipmentStatus::WhiteListed,
        }
    );
}
