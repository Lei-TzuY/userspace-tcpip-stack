//! Integration tests for 3GPP TS 29.511 / TS 23.501 5G Equipment Identity Register (5G-EIR) Engine.

use toy_tcpip::eir_5g::*;

// ---------------------------------------------------------------------------
// 1. Luhn Checksum & PEI Parsing
// ---------------------------------------------------------------------------

#[test]
fn test_eir_luhn_checksum_and_pei_parsing() {
    let body = "86432104123456"; // 14 digits
    let cd = calculate_luhn_check_digit(body).expect("Valid 14 digits");
    let valid_imei = format!("{}{}", body, cd);

    let pei = Pei::parse(&valid_imei).expect("Valid IMEI should parse");
    assert_eq!(pei.tac, "86432104");
    assert_eq!(pei.snr, "123456");
    assert!(!pei.is_imeisv);

    // Corrupt one digit to fail Luhn checksum
    let corrupted_imei = format!("{}{}", body, (cd + 1) % 10);
    let res = Pei::parse(&corrupted_imei);
    assert_eq!(res, Err(EirError::LuhnChecksumFailed));

    // 16-digit IMEISV (no Luhn required on 16 digits)
    let imeisv = "8643210412345612";
    let pei_sv = Pei::parse(imeisv).expect("Valid IMEISV should parse");
    assert!(pei_sv.is_imeisv);
    assert_eq!(pei_sv.cd_or_svn, "12");
}

// ---------------------------------------------------------------------------
// 2. Blacklist by PEI and TAC
// ---------------------------------------------------------------------------

#[test]
fn test_eir_blacklist_by_pei_and_tac() {
    let mut eir = EirEngine::new("5g-eir-01");

    let body1 = "86432104123456";
    let cd1 = calculate_luhn_check_digit(body1).unwrap();
    let stolen_imei = format!("{}{}", body1, cd1);

    eir.blacklist_pei(&stolen_imei, "Reported stolen at Metro station")
        .unwrap();

    let req1 = EquipmentCheckRequest {
        pei: stolen_imei.clone(),
        supi: Some("imsi-208950000000001".to_string()),
        tracking_area_code: Some(101),
        timestamp_epoch_s: 1700000000,
    };

    let resp1 = eir.check_equipment_status(&req1).unwrap();
    assert_eq!(resp1.status, EquipmentStatus::Blacklisted);
    assert!(resp1.reason.unwrap().contains("Reported stolen"));

    // Blacklist entire TAC
    let rogue_tac = "99887766";
    eir.blacklist_tac(rogue_tac, "Counterfeit modem chipset");

    let body2 = format!("{}112233", rogue_tac);
    let cd2 = calculate_luhn_check_digit(&body2).unwrap();
    let counterfeit_imei = format!("{}{}", body2, cd2);

    let req2 = EquipmentCheckRequest {
        pei: counterfeit_imei,
        supi: Some("imsi-208950000000002".to_string()),
        tracking_area_code: Some(102),
        timestamp_epoch_s: 1700000000,
    };

    let resp2 = eir.check_equipment_status(&req2).unwrap();
    assert_eq!(resp2.status, EquipmentStatus::Blacklisted);
    assert!(resp2.reason.unwrap().contains("Counterfeit modem"));
}

// ---------------------------------------------------------------------------
// 3. Greylist with Expiration
// ---------------------------------------------------------------------------

#[test]
fn test_eir_greylist_expiration() {
    let mut eir = EirEngine::new("5g-eir-02");

    let body = "86432104998877";
    let cd = calculate_luhn_check_digit(body).unwrap();
    let imei = format!("{}{}", body, cd);

    // Greylist until epoch 1000
    eir.greylist_pei(&imei, "Unusual traffic spike observation", 1000)
        .unwrap();

    // Query before expiry: t = 900
    let req_active = EquipmentCheckRequest {
        pei: imei.clone(),
        supi: None,
        tracking_area_code: None,
        timestamp_epoch_s: 900,
    };
    let resp_active = eir.check_equipment_status(&req_active).unwrap();
    assert_eq!(resp_active.status, EquipmentStatus::Greylisted);

    // Query after expiry: t = 1100
    let req_expired = EquipmentCheckRequest {
        pei: imei.clone(),
        supi: None,
        tracking_area_code: None,
        timestamp_epoch_s: 1100,
    };
    let resp_expired = eir.check_equipment_status(&req_expired).unwrap();
    assert_eq!(resp_expired.status, EquipmentStatus::Whitelisted);
}

// ---------------------------------------------------------------------------
// 4. Cloned PEI / Anti-Spoofing Anomaly Detection
// ---------------------------------------------------------------------------

#[test]
fn test_eir_cloned_pei_spoofing_detection() {
    let mut eir = EirEngine::new("5g-eir-03");

    let body = "86432104554433";
    let cd = calculate_luhn_check_digit(body).unwrap();
    let imei = format!("{}{}", body, cd);

    // Legitimate registration in Cell 100
    let req1 = EquipmentCheckRequest {
        pei: imei.clone(),
        supi: Some("imsi-208950000000010".to_string()),
        tracking_area_code: Some(100),
        timestamp_epoch_s: 500,
    };
    let resp1 = eir.check_equipment_status(&req1).unwrap();
    assert_eq!(resp1.status, EquipmentStatus::Whitelisted);

    // 10 seconds later, same IMEI appears with different SUPI in distant Cell 200
    let req2 = EquipmentCheckRequest {
        pei: imei.clone(),
        supi: Some("imsi-208950000000099".to_string()),
        tracking_area_code: Some(200),
        timestamp_epoch_s: 510,
    };
    let resp2 = eir.check_equipment_status(&req2).unwrap();
    assert_eq!(resp2.status, EquipmentStatus::Blacklisted);
    assert!(resp2.reason.unwrap().contains("Cloned PEI anomaly"));
}

// ---------------------------------------------------------------------------
// 5. Explicit Whitelist Override
// ---------------------------------------------------------------------------

#[test]
fn test_eir_explicit_whitelist_override() {
    let mut eir = EirEngine::new("5g-eir-04");

    let blocked_tac = "77665544";
    eir.blacklist_tac(blocked_tac, "Restricted prototype hardware");

    let body = format!("{}123456", blocked_tac);
    let cd = calculate_luhn_check_digit(&body).unwrap();
    let test_device_imei = format!("{}{}", body, cd);

    // Whitelist this specific lab device
    eir.whitelist_pei(&test_device_imei, "Authorized lab test equipment")
        .unwrap();

    let req = EquipmentCheckRequest {
        pei: test_device_imei,
        supi: Some("imsi-208950000000088".to_string()),
        tracking_area_code: Some(50),
        timestamp_epoch_s: 1700000000,
    };

    let resp = eir.check_equipment_status(&req).unwrap();
    assert_eq!(resp.status, EquipmentStatus::Whitelisted);
    assert_eq!(
        resp.reason,
        Some("Authorized lab test equipment".to_string())
    );
}
