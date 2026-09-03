use toy_tcpip::diameter_s13_cache::{
    DiameterS13CacheEngine, EirCacheLookupResult, EirEquipmentStatus,
};

#[test]
fn test_diameter_s13_cache_lifecycle() {
    let mut cache = DiameterS13CacheEngine::new(1800, 20); // 1800s TTL

    let imei1 = "860123450000001";
    let imei2 = "860123450000002";
    let imei3 = "860123450000003";

    cache.insert(imei1, EirEquipmentStatus::WhiteListed, 5000, None);
    cache.insert(imei2, EirEquipmentStatus::BlackListed, 5000, None);
    cache.insert(imei3, EirEquipmentStatus::GrayListed, 5000, Some(100)); // 100s custom TTL

    // 1. Check active hits
    assert_eq!(
        cache.query(imei1, 5050),
        EirCacheLookupResult::Hit(EirEquipmentStatus::WhiteListed)
    );
    assert_eq!(
        cache.query(imei2, 5050),
        EirCacheLookupResult::Hit(EirEquipmentStatus::BlackListed)
    );
    assert_eq!(
        cache.query(imei3, 5050),
        EirCacheLookupResult::Hit(EirEquipmentStatus::GrayListed)
    );

    // 2. Check cache miss
    assert_eq!(
        cache.query("999999999999999", 5050),
        EirCacheLookupResult::Miss
    );

    // 3. Check expiration at t=5150 (> 5000 + 100)
    assert_eq!(
        cache.query(imei3, 5150),
        EirCacheLookupResult::Expired {
            previous_status: EirEquipmentStatus::GrayListed,
            expired_secs_ago: 50,
        }
    );

    // 4. Purge expired entries
    let purged_count = cache.purge_expired(5150);
    assert_eq!(purged_count, 1);
    assert_eq!(cache.entries.len(), 2);
}
