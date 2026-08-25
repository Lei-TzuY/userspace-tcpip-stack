use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_rx::{
    AaRequest, MediaComponentDescription, MediaSubComponent, MediaType, PcrfRxEngine,
    AVP_SPECIFIC_ACTION, DIAMETER_APPLICATION_RX, DIAMETER_CMD_AA,
};

#[test]
fn test_diameter_rx_aar_and_media_subcomponent_codec() {
    let mut req = AaRequest::new("ims-session-1234", "ims-voice");
    let mut mc = MediaComponentDescription::new(1, MediaType::Audio);
    mc.max_bandwidth_ul = 64_000;
    mc.max_bandwidth_dl = 64_000;

    let mut sub = MediaSubComponent::new(1);
    sub.flow_descriptions.push("permit in ip from 192.168.1.10 to 192.168.1.20".to_string());
    mc.sub_components.push(sub);
    req.media_components.push(mc);

    let diam_msg = req.to_diameter_message(10, 20);
    assert_eq!(diam_msg.header.command_code, DIAMETER_CMD_AA);
    assert_eq!(diam_msg.header.application_id, DIAMETER_APPLICATION_RX);

    let parsed = AaRequest::from_diameter_message(&diam_msg).expect("parse AAR");
    assert_eq!(parsed.session_id, "ims-session-1234");
    assert_eq!(parsed.af_application_identifier, "ims-voice");
    assert_eq!(parsed.media_components.len(), 1);
    assert_eq!(parsed.media_components[0].media_type, MediaType::Audio);
    assert_eq!(parsed.media_components[0].sub_components.len(), 1);
}

#[test]
fn test_pcrf_rx_engine_admission_and_qci_authorization() {
    let mut pcrf = PcrfRxEngine::new(10_000_000); // 10 Mbps total capacity

    // 1. Send AAR for IMS Voice (QCI 1) + Video (QCI 2)
    let mut req1 = AaRequest::new("sess-call-01", "ims-multimedia");
    let mut audio = MediaComponentDescription::new(1, MediaType::Audio);
    audio.max_bandwidth_ul = 64_000;
    audio.max_bandwidth_dl = 64_000;

    let mut video = MediaComponentDescription::new(2, MediaType::Video);
    video.max_bandwidth_ul = 1_000_000;
    video.max_bandwidth_dl = 1_000_000;

    req1.media_components.push(audio);
    req1.media_components.push(video);

    let resp1 = pcrf.process_aar(&req1);
    assert_eq!(resp1.get_avp(268).unwrap().as_u32().unwrap(), DIAMETER_SUCCESS);
    assert_eq!(resp1.get_avp(AVP_SPECIFIC_ACTION).unwrap().as_u32().unwrap(), 1); // QCI 1 (Conversational Voice highest)

    let state = pcrf.sessions.get("sess-call-01").unwrap();
    assert_eq!(state.authorized_qci, 1);
    assert_eq!(state.granted_bandwidth_ul_bps, 1_064_000);
    assert_eq!(state.granted_bandwidth_dl_bps, 1_064_000);
    assert_eq!(pcrf.allocated_bandwidth_bps, 2_128_000);

    // 2. Terminate session
    let term_resp = pcrf.process_str("sess-call-01");
    assert_eq!(term_resp.get_avp(268).unwrap().as_u32().unwrap(), DIAMETER_SUCCESS);
    assert_eq!(pcrf.allocated_bandwidth_bps, 0);
    assert_eq!(pcrf.sessions.len(), 0);
}
