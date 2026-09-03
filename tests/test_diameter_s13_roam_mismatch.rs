// tests/test_diameter_s13_roam_mismatch.rs

use toy_tcpip::diameter_s13_roam_mismatch::{RoamingValidationVerdict, S13RoamingMismatchEngine};

#[test]
fn test_diameter_s13_roam_mismatch_integration() {
    let mut engine = S13RoamingMismatchEngine::new();
    engine.add_tac_country_mapping("86", "CN", "460", 30);
    engine.add_tac_country_mapping("8888", "HIGH_RISK", "999", 90);
    engine.add_blacklisted_origin_country("SANCTIONED");
    engine.add_tac_country_mapping("7777", "SANCTIONED", "777", 95);

    // 1. Domestic pass (CN TAC on CN network 460-01)
    let v_dom = engine.evaluate_roaming_equipment("861234567890123", "46001");
    assert_eq!(
        v_dom,
        RoamingValidationVerdict::DomesticConformant {
            imei: "861234567890123".to_string(),
            tac: "86123456".to_string(),
            serving_mcc: "460".to_string(),
        }
    );

    // 2. Authorized international roaming (UK TAC on CN network 460-01)
    let v_roam = engine.evaluate_roaming_equipment("353918001234567", "46001");
    assert_eq!(
        v_roam,
        RoamingValidationVerdict::AuthorizedInternationalRoaming {
            imei: "353918001234567".to_string(),
            tac: "35391800".to_string(),
            tac_origin_country: "UK".to_string(),
            serving_mcc: "460".to_string(),
        }
    );

    // 3. Suspicious high-risk TAC mismatch
    let v_susp = engine.evaluate_roaming_equipment("888812345678901", "46001");
    assert_eq!(
        v_susp,
        RoamingValidationVerdict::SuspiciousCountryMismatch {
            imei: "888812345678901".to_string(),
            tac: "88881234".to_string(),
            tac_origin_country: "HIGH_RISK".to_string(),
            serving_mcc: "460".to_string(),
            risk_score: 90,
        }
    );

    // 4. Sanctioned / Blacklisted country blocked
    let v_block = engine.evaluate_roaming_equipment("777712345678901", "46001");
    assert_eq!(
        v_block,
        RoamingValidationVerdict::BlacklistedCountryBlocked {
            imei: "777712345678901".to_string(),
            tac: "77771234".to_string(),
            tac_origin_country: "SANCTIONED".to_string(),
            serving_mcc: "460".to_string(),
        }
    );

    // 5. Invalid format
    let v_inv = engine.evaluate_roaming_equipment("123", "46001");
    assert_eq!(
        v_inv,
        RoamingValidationVerdict::InvalidImeiFormat {
            input: "123".to_string(),
        }
    );

    assert_eq!(engine.total_validations, 5);
    assert_eq!(engine.total_domestic_passes, 1);
    assert_eq!(engine.total_authorized_roaming, 1);
    assert_eq!(engine.total_suspicious_mismatches, 1);
    assert_eq!(engine.total_blocked_roamers, 1);
}
