use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_s6a::{
    DIAMETER_APPLICATION_S6A, DIAMETER_CMD_AUTH_INFO, DIAMETER_CMD_UPDATE_LOCATION, EpsAuthVector,
    HssS6aEngine, HssSubscriberProfile,
};

#[test]
fn test_eps_auth_vector_grouped_avp_codec() {
    let rand = [0x11; 16];
    let xres = [0x22; 8];
    let autn = [0x33; 16];
    let kasme = [0x44; 32];

    let vector = EpsAuthVector::new(rand, xres, autn, kasme);
    let avp = vector.to_grouped_avp();

    let parsed = EpsAuthVector::from_grouped_avp(&avp).expect("parse EPS auth vector");
    assert_eq!(parsed.rand, rand);
    assert_eq!(parsed.xres, xres);
    assert_eq!(parsed.autn, autn);
    assert_eq!(parsed.kasme, kasme);
}

#[test]
fn test_hss_s6a_air_and_ulr_flows() {
    let mut hss = HssS6aEngine::new("hss.epc.example.com");
    let imsi = "208950000000001";

    hss.provision_subscriber(HssSubscriberProfile {
        imsi: imsi.to_string(),
        msisdn: "33612345678".to_string(),
        default_apn: "internet".to_string(),
        subscribed_ambr_ul_kbps: 50_000,
        subscribed_ambr_dl_kbps: 200_000,
        registered_mme: None,
    });

    // 1. Authentication-Information-Request (AIR) -> AIA
    let plmn = [0x02, 0xF8, 0x59];
    let aia = hss
        .handle_auth_info_request(imsi, &plmn)
        .expect("handle AIR");
    assert_eq!(aia.header.command_code, DIAMETER_CMD_AUTH_INFO);
    assert_eq!(aia.header.application_id, DIAMETER_APPLICATION_S6A);
    assert_eq!(
        aia.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(hss.auth_vectors_generated_count, 1);

    // 2. Update-Location-Request (ULR) -> ULA
    let mme = "mme01.epc.example.com";
    let ula = hss
        .handle_update_location_request(imsi, mme)
        .expect("handle ULR");
    assert_eq!(ula.header.command_code, DIAMETER_CMD_UPDATE_LOCATION);
    assert_eq!(ula.header.application_id, DIAMETER_APPLICATION_S6A);
    assert_eq!(
        hss.subscribers.get(imsi).unwrap().registered_mme,
        Some(mme.to_string())
    );
    assert_eq!(hss.location_updates_count, 1);
}
