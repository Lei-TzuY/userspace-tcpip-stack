// tests/test_diameter_s13_imei_tamper.rs

use toy_tcpip::diameter_s13_imei_tamper::{
    IMEI_LENGTH, IMEI_SV_LENGTH, ImeiValidationVerdict, S13ImeiTamperEngine,
};

#[test]
fn test_diameter_s13_imei_tamper_lifecycle() {
    let mut engine = S13ImeiTamperEngine::new();

    // 1. Valid 15-digit IMEI with correct Luhn check digit
    let payload = "86001111222233";
    let cd = S13ImeiTamperEngine::calculate_luhn_check_digit(payload).unwrap();
    let imei = format!("{}{}", payload, cd);

    let v1 = engine.validate_equipment_id(&imei);
    assert_eq!(
        v1,
        ImeiValidationVerdict::ValidImei {
            imei: imei.clone(),
            tac: "86001111".to_string(),
            snr: "222233".to_string(),
            check_digit: cd,
        }
    );

    // 2. Corrupted check digit (Luhn Failure)
    let bad_imei = format!("{}{}", payload, (cd + 5) % 10);
    let v2 = engine.validate_equipment_id(&bad_imei);
    match v2 {
        ImeiValidationVerdict::LuhnChecksumFailed {
            expected_cd,
            actual_cd,
            ..
        } => {
            assert_eq!(expected_cd, cd);
            assert_eq!(actual_cd, (cd + 5) % 10);
        }
        _ => panic!("Expected LuhnChecksumFailed"),
    }

    // 3. Valid 16-digit IMEI-SV
    let imei_sv = "3598765432109812";
    let v3 = engine.validate_equipment_id(imei_sv);
    assert_eq!(
        v3,
        ImeiValidationVerdict::ValidImeiSv {
            imei_sv: imei_sv.to_string(),
            tac: "35987654".to_string(),
            snr: "321098".to_string(),
            svn: "12".to_string(),
        }
    );

    // 4. Dummy repetitive cloned hardware pattern
    let dummy_imei = "000000000000000";
    let v4 = engine.validate_equipment_id(dummy_imei);
    match v4 {
        ImeiValidationVerdict::HardwareTamperedCloned { .. } => {}
        _ => panic!("Expected HardwareTamperedCloned"),
    }

    // 5. Invalid length (e.g. 10 digits)
    let short_imei = "1234567890";
    let v5 = engine.validate_equipment_id(short_imei);
    assert_eq!(
        v5,
        ImeiValidationVerdict::InvalidLength {
            input: short_imei.to_string(),
            length: 10,
        }
    );

    // 6. Invalid characters (e.g. letters)
    let bad_chars = "35391800ABCD123";
    let v6 = engine.validate_equipment_id(bad_chars);
    assert_eq!(
        v6,
        ImeiValidationVerdict::InvalidCharacters {
            input: bad_chars.to_string(),
        }
    );

    assert_eq!(engine.total_validations, 6);
    assert_eq!(engine.total_valid_imeis, 1);
    assert_eq!(engine.total_valid_imeisv, 1);
    assert_eq!(engine.total_luhn_failures, 1);
    assert_eq!(engine.total_tampered_cloned, 1);
}

#[test]
fn test_imei_constants() {
    assert_eq!(IMEI_LENGTH, 15);
    assert_eq!(IMEI_SV_LENGTH, 16);
}
