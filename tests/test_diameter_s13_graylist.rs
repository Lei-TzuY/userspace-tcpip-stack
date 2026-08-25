use toy_tcpip::diameter_s13_graylist::{
    EirGraylistEngine, EirQosAction, EirStatus, S13GraylistAvp, S13GraylistMessage,
    DIAMETER_APPLICATION_S13, DIAMETER_CMD_ME_IDENTITY_CHECK,
};

#[test]
fn test_diameter_s13_graylist_decision() {
    let mut eir = EirGraylistEngine::new("eir01.carrier.com", 128);
    eir.set_imei_status("352099001122334", EirStatus::GreyListed);

    let ecr = S13GraylistMessage::new_ecr("s13-test-sess", "352099001122334");
    assert_eq!(ecr.application_id, DIAMETER_APPLICATION_S13);
    assert_eq!(ecr.command_code, DIAMETER_CMD_ME_IDENTITY_CHECK);

    let (eca, qos) = eir.handle_ecr(&ecr);
    let st = eca.avps.iter().find_map(|a| if let S13GraylistAvp::EquipmentStatus(s) = a { Some(*s) } else { None });
    assert_eq!(st, Some(EirStatus::GreyListed));
    assert_eq!(qos, EirQosAction::ThrottledAccess { max_kbps: 128 });
}
