use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_sh::{
    DATA_REF_REPOSITORY_DATA, DIAMETER_APPLICATION_SH, DIAMETER_CMD_SUBSCRIBE_NOTIFICATIONS,
    DIAMETER_CMD_USER_DATA, HssShEngine, HssShSubscriberProfile,
};

#[test]
fn test_diameter_sh_udr_and_snr() {
    let mut hss = HssShEngine::new();
    let public_id = "sip:bob@ims.example.com";
    let profile = HssShSubscriberProfile::new(
        public_id,
        "<RepositoryData><ServiceData>HD-Voice</ServiceData></RepositoryData>",
        "REGISTERED",
    );
    hss.register_subscriber(profile);

    // 1. User-Data-Request (UDR)
    let uda = hss.handle_udr(public_id, DATA_REF_REPOSITORY_DATA);
    assert_eq!(uda.header.command_code, DIAMETER_CMD_USER_DATA);
    assert_eq!(uda.header.application_id, DIAMETER_APPLICATION_SH);
    assert_eq!(
        uda.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(
        uda.get_avp(702).unwrap().as_string().unwrap(),
        "<RepositoryData><ServiceData>HD-Voice</ServiceData></RepositoryData>"
    );

    // 2. Subscribe-Notifications-Request (SNR)
    let sna = hss.handle_snr("as-telephony-01", public_id, 0);
    assert_eq!(
        sna.header.command_code,
        DIAMETER_CMD_SUBSCRIBE_NOTIFICATIONS
    );
    assert_eq!(
        sna.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(hss.subscriptions.get(public_id).unwrap().len(), 1);
}
