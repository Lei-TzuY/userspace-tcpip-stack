use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_s9::{
    DIAMETER_APPLICATION_S9, DIAMETER_CMD_CC, PcrfS9Engine, SubsessionEnforcementInfo,
};

#[test]
fn test_diameter_s9_subsession_grouped_avp_and_ccr() {
    let sub = SubsessionEnforcementInfo::new(1005, 64_000, 256_000);
    let avp = sub.to_grouped_avp();

    let parsed = SubsessionEnforcementInfo::from_grouped_avp(&avp).expect("parse S9 AVP");
    assert_eq!(parsed.subsession_id, 1005);
    assert_eq!(parsed.max_bandwidth_ul_kbps, 64_000);
    assert_eq!(parsed.max_bandwidth_dl_kbps, 256_000);

    let mut pcrf = PcrfS9Engine::new(true);
    let cca = pcrf.handle_ccr(sub);

    assert_eq!(cca.header.command_code, DIAMETER_CMD_CC);
    assert_eq!(cca.header.application_id, DIAMETER_APPLICATION_S9);
    assert_eq!(
        cca.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(pcrf.roaming_subsessions.len(), 1);
}
