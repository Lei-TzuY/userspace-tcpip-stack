use toy_tcpip::S13EquipmentStatus;
use toy_tcpip::diameter_s13_imei_range::{DiameterS13ImeiRangeEngine, ImeiRangeVerdict};

#[test]
fn test_diameter_s13_imei_range_integration() {
    let mut engine = DiameterS13ImeiRangeEngine::new();

    // Register test rules
    engine.add_rule(
        35391800,
        35391899,
        S13EquipmentStatus::BlackListed,
        "Stolen batch from Logistics Hub A",
        100,
    );
    engine.add_rule(
        35300000,
        35399999,
        S13EquipmentStatus::GrayListed,
        "Carrier audit monitoring range",
        50,
    );
    engine.add_rule(
        86000000,
        86999999,
        S13EquipmentStatus::WhiteListed,
        "Authorized Enterprise Fleet",
        80,
    );

    // 1. High priority blacklist rule matches first within overlapping graylist
    let v_black = engine.evaluate_imei("353918441234567");
    assert_eq!(
        v_black,
        ImeiRangeVerdict::RangeMatched {
            imei: "353918441234567".to_string(),
            tac: 35391844,
            status: S13EquipmentStatus::BlackListed,
            description: "Stolen batch from Logistics Hub A".to_string(),
            priority: 100,
        }
    );

    // 2. Graylist matches non-blacklisted member of wider range
    let v_gray = engine.evaluate_imei("353123451234567");
    assert_eq!(
        v_gray,
        ImeiRangeVerdict::RangeMatched {
            imei: "353123451234567".to_string(),
            tac: 35312345,
            status: S13EquipmentStatus::GrayListed,
            description: "Carrier audit monitoring range".to_string(),
            priority: 50,
        }
    );

    // 3. Explicit whitelist match
    let v_white = engine.evaluate_imei("861234560000111");
    assert_eq!(
        v_white,
        ImeiRangeVerdict::RangeMatched {
            imei: "861234560000111".to_string(),
            tac: 86123456,
            status: S13EquipmentStatus::WhiteListed,
            description: "Authorized Enterprise Fleet".to_string(),
            priority: 80,
        }
    );

    // 4. Default unlisted device
    let v_def = engine.evaluate_imei("490154201234567");
    assert_eq!(
        v_def,
        ImeiRangeVerdict::DefaultWhiteListed {
            imei: "490154201234567".to_string(),
            tac: 49015420,
        }
    );

    // 5. Invalid IMEI input
    let v_inv = engine.evaluate_imei("invalid_imei");
    assert_eq!(
        v_inv,
        ImeiRangeVerdict::InvalidImeiFormat {
            input: "invalid_imei".to_string(),
        }
    );

    assert_eq!(engine.total_queries, 5);
    assert_eq!(engine.total_range_matches, 3);
    assert_eq!(engine.total_default_matches, 1);
    assert_eq!(engine.total_invalid_queries, 1);
}
