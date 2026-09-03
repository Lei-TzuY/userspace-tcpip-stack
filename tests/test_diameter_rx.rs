use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_rx::{
    AVP_SPECIFIC_ACTION, AaRequest, DIAMETER_APPLICATION_RX, DIAMETER_CMD_AA,
    MediaComponentDescription, MediaSubComponent, MediaType, PcrfRxEngine,
};

#[test]
fn test_diameter_rx_aar_and_media_subcomponent_codec() {
    let mut req = AaRequest::new("ims-session-1234", "ims-voice");
    let mut mc = MediaComponentDescription::new(1, MediaType::Audio);
    mc.max_bandwidth_ul = 64_000;
    mc.max_bandwidth_dl = 64_000;

    let mut sub = MediaSubComponent::new(1);
    sub.flow_descriptions
        .push("permit in ip from 192.168.1.10 to 192.168.1.20".to_string());
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
    assert_eq!(
        resp1.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(
        resp1
            .get_avp(AVP_SPECIFIC_ACTION)
            .unwrap()
            .as_u32()
            .unwrap(),
        1
    ); // QCI 1 (Conversational Voice highest)

    let state = pcrf.sessions.get("sess-call-01").unwrap();
    assert_eq!(state.authorized_qci, 1);
    assert_eq!(state.granted_bandwidth_ul_bps, 1_064_000);
    assert_eq!(state.granted_bandwidth_dl_bps, 1_064_000);
    assert_eq!(pcrf.allocated_bandwidth_bps, 2_128_000);

    // 2. Terminate session
    let term_resp = pcrf.process_str("sess-call-01");
    assert_eq!(
        term_resp.get_avp(268).unwrap().as_u32().unwrap(),
        DIAMETER_SUCCESS
    );
    assert_eq!(pcrf.allocated_bandwidth_bps, 0);
    assert_eq!(pcrf.sessions.len(), 0);
}

#[test]
fn test_diameter_rx_rar_raa_wire_codec() {
    use toy_tcpip::diameter_rx::{
        DIAMETER_CMD_RE_AUTH, ReAuthAnswer, ReAuthRequest,
        SPECIFIC_ACTION_INDICATION_OF_LOSS_OF_BEARER,
    };

    let rar = ReAuthRequest {
        session_id: "ims-rar-999".to_string(),
        origin_host: "pcrf01.operator.com".to_string(),
        origin_realm: "operator.com".to_string(),
        destination_host: "pcscf01.operator.com".to_string(),
        destination_realm: "operator.com".to_string(),
        specific_action: SPECIFIC_ACTION_INDICATION_OF_LOSS_OF_BEARER,
        abort_cause: None,
    };

    let msg = rar.to_diameter_message(100, 200);
    assert_eq!(msg.header.command_code, DIAMETER_CMD_RE_AUTH);
    assert!(msg.header.is_request());

    let parsed_rar = ReAuthRequest::from_diameter_message(&msg).expect("parse RAR");
    assert_eq!(parsed_rar, rar);

    let raa = ReAuthAnswer::success("ims-rar-999", "pcscf01.operator.com", "operator.com");
    let ans_msg = raa.to_diameter_message(100, 200);
    assert_eq!(ans_msg.header.command_code, DIAMETER_CMD_RE_AUTH);
    assert!(!ans_msg.header.is_request());

    let parsed_raa = ReAuthAnswer::from_diameter_message(&ans_msg).expect("parse RAA");
    assert_eq!(parsed_raa, raa);
}

#[test]
fn test_diameter_rx_rar_raa_bearer_loss_and_release_lifecycle() {
    use toy_tcpip::diameter_rx::{
        AaRequest, MediaComponentDescription, MediaType, PcrfRxEngine, PcscfRxClient,
        SPECIFIC_ACTION_INDICATION_OF_LOSS_OF_BEARER,
        SPECIFIC_ACTION_INDICATION_OF_RELEASE_OF_BEARER,
    };

    let mut pcrf = PcrfRxEngine::new(5_000_000);
    let mut pcscf = PcscfRxClient::new(
        "pcscf.ims.mnc001.mcc310.3gppnetwork.org",
        "ims.mnc001.mcc310.3gppnetwork.org",
    );

    let sess_id = "ims-voice-session-42";
    pcscf.register_session(sess_id, "VoLTE-Voice");
    assert!(pcscf.is_session_active(sess_id));

    // PCRF authorizes call
    let mut aar = AaRequest::new(sess_id, "VoLTE-Voice");
    let mut audio = MediaComponentDescription::new(1, MediaType::Audio);
    audio.max_bandwidth_ul = 32_000;
    audio.max_bandwidth_dl = 32_000;
    aar.media_components.push(audio);
    let aaa = pcrf.process_aar(&aar);
    assert_eq!(aaa.get_avp(268).unwrap().as_u32().unwrap(), 2001);

    // 1. Radio bearer is temporarily lost -> PCRF sends RAR (Loss of Bearer)
    let rar_loss = pcrf
        .generate_rar(
            sess_id,
            SPECIFIC_ACTION_INDICATION_OF_LOSS_OF_BEARER,
            "pcrf.epc.mnc001.mcc310.3gppnetwork.org",
            "epc.mnc001.mcc310.3gppnetwork.org",
            &pcscf.local_host,
            &pcscf.local_realm,
        )
        .expect("generate RAR");

    let raa = pcscf.handle_rar(&rar_loss);
    assert_eq!(raa.result_code, 2001);
    assert_eq!(pcscf.bearer_loss_events_received, 1);
    assert!(pcscf.is_session_active(sess_id)); // Call still held during temporary loss

    // PCRF processes the RAA
    let ok = pcrf.process_raa(sess_id, raa.result_code);
    assert!(ok);

    // 2. Radio bearer cannot recover and is released -> PCRF sends RAR (Release of Bearer)
    let rar_release = pcrf
        .generate_rar(
            sess_id,
            SPECIFIC_ACTION_INDICATION_OF_RELEASE_OF_BEARER,
            "pcrf.epc.mnc001.mcc310.3gppnetwork.org",
            "epc.mnc001.mcc310.3gppnetwork.org",
            &pcscf.local_host,
            &pcscf.local_realm,
        )
        .expect("generate RAR");

    let raa2 = pcscf.handle_rar(&rar_release);
    assert_eq!(raa2.result_code, 2001);
    assert_eq!(pcscf.bearer_release_events_received, 1);
    // Session is now terminated on P-CSCF
    assert!(!pcscf.is_session_active(sess_id));
}

#[test]
fn test_diameter_rx_asr_asa_wire_codec() {
    use toy_tcpip::diameter_rx::{
        ABORT_CAUSE_INSUFFICIENT_SERVER_RESOURCES, AbortSessionAnswer, AbortSessionRequest,
        DIAMETER_CMD_ABORT_SESSION,
    };

    let asr = AbortSessionRequest {
        session_id: "ims-asr-007".to_string(),
        origin_host: "pcrf.carrier.com".to_string(),
        origin_realm: "carrier.com".to_string(),
        destination_host: "pcscf.carrier.com".to_string(),
        destination_realm: "carrier.com".to_string(),
        abort_cause: ABORT_CAUSE_INSUFFICIENT_SERVER_RESOURCES,
    };

    let msg = asr.to_diameter_message(50, 60);
    assert_eq!(msg.header.command_code, DIAMETER_CMD_ABORT_SESSION);
    assert!(msg.header.is_request());

    let parsed_asr = AbortSessionRequest::from_diameter_message(&msg).expect("parse ASR");
    assert_eq!(parsed_asr, asr);

    let asa = AbortSessionAnswer::success("ims-asr-007", "pcscf.carrier.com", "carrier.com");
    let ans_msg = asa.to_diameter_message(50, 60);
    assert_eq!(ans_msg.header.command_code, DIAMETER_CMD_ABORT_SESSION);
    assert!(!ans_msg.header.is_request());

    let parsed_asa = AbortSessionAnswer::from_diameter_message(&ans_msg).expect("parse ASA");
    assert_eq!(parsed_asa, asa);
}

#[test]
fn test_diameter_rx_asr_asa_session_abort_lifecycle() {
    use toy_tcpip::diameter_rx::{
        ABORT_CAUSE_INSUFFICIENT_SERVER_RESOURCES, AaRequest, MediaComponentDescription, MediaType,
        PcrfRxEngine, PcscfRxClient,
    };

    let mut pcrf = PcrfRxEngine::new(10_000_000);
    let mut pcscf = PcscfRxClient::new("pcscf.ims.carrier.org", "ims.carrier.org");

    let sess_id = "ims-emergency-call-112";
    pcscf.register_session(sess_id, "IMS-Voice-Call");

    // Establish call via AAR
    let mut aar = AaRequest::new(sess_id, "IMS-Voice-Call");
    let mut audio = MediaComponentDescription::new(1, MediaType::Audio);
    audio.max_bandwidth_ul = 64_000;
    audio.max_bandwidth_dl = 64_000;
    aar.media_components.push(audio);
    let aaa = pcrf.process_aar(&aar);
    assert_eq!(aaa.get_avp(268).unwrap().as_u32().unwrap(), 2001);
    assert_eq!(pcrf.allocated_bandwidth_bps, 128_000);

    // Severe PCRF congestion -> PCRF issues ASR
    let asr = pcrf
        .generate_asr(
            sess_id,
            ABORT_CAUSE_INSUFFICIENT_SERVER_RESOURCES,
            "pcrf.ims.carrier.org",
            "ims.carrier.org",
            &pcscf.local_host,
            &pcscf.local_realm,
        )
        .expect("generate ASR");

    assert_eq!(asr.abort_cause, ABORT_CAUSE_INSUFFICIENT_SERVER_RESOURCES);
    // PCRF deactivates the session and frees reserved bandwidth
    assert_eq!(pcrf.allocated_bandwidth_bps, 0);

    // P-CSCF handles ASR, tears down call, and responds with ASA
    let asa = pcscf.handle_asr(&asr);
    assert_eq!(asa.result_code, 2001);
    assert_eq!(pcscf.abort_events_received, 1);
    assert!(!pcscf.is_session_active(sess_id));

    // PCRF finalizes ASA processing
    assert!(pcrf.process_asa(sess_id, asa.result_code));
    assert_eq!(pcrf.sessions.len(), 0);
}
