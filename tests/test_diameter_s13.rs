use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_s13::{
    DIAMETER_APPLICATION_S13, DIAMETER_CMD_ME_IDENTITY_CHECK, EirS13Engine, EquipmentStatus,
};

#[test]
fn test_diameter_s13_ecr_and_status_checks() {
    let mut eir = EirS13Engine::new();
    let imei_ok = "867912040000001";
    let imei_stolen = "354890091234567";

    eir.set_imei_status(imei_ok, EquipmentStatus::Whitelisted);
    eir.set_imei_status(imei_stolen, EquipmentStatus::Blacklisted);

    // 1. Check whitelisted phone
    let eca_ok = eir.handle_ecr(imei_ok);
    assert_eq!(eca_ok.header.command_code, DIAMETER_CMD_ME_IDENTITY_CHECK);
    assert_eq!(eca_ok.header.application_id, DIAMETER_APPLICATION_S13);
    assert_eq!(
        eca_ok.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(eir.query_imei(imei_ok), EquipmentStatus::Whitelisted);

    // 2. Check stolen phone
    let eca_stolen = eir.handle_ecr(imei_stolen);
    assert_eq!(
        eca_stolen.header.command_code,
        DIAMETER_CMD_ME_IDENTITY_CHECK
    );
    assert_eq!(eir.query_imei(imei_stolen), EquipmentStatus::Blacklisted);
    assert!(eir.blacklisted_drops_count >= 1);
}
