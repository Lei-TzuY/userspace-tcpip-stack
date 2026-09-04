//! Integration tests for 3GPP TS 29.544 / TS 23.501 / TS 23.502 / TS 29.274
//! 5G-EPS Interworking & N26 Handover Forwarding Engine.

use toy_tcpip::eps_interworking_5g::{
    EpsInterworkingEngine, EpsInterworkingError, FTEID_S1_U_ENB, FTEID_S1_U_FORWARDING,
    ForwardRelocationResponse, Fteid, MIN_EBI, N26HandoverState, VoiceCallAction,
    derive_k_asme_from_k_amf, map_5qi_to_qci, map_qci_to_5qi,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ngap_5g::Snssai;

#[test]
fn test_eps_interworking_session_binding_and_ebi_allocation() {
    let pgw_c_ip = Ipv4Address::new(10, 200, 0, 1);
    let pgw_u_ip = Ipv4Address::new(10, 200, 0, 2);
    let mut engine = EpsInterworkingEngine::new("smf-pgw-combined-01", pgw_c_ip, pgw_u_ip);

    let supi = "208950000000001";
    let imsi = "208950000000001";
    let ue_ip = Ipv4Address::new(10, 45, 0, 100);
    let snssai = Snssai { sst: 1, sd: None };

    // 1. Establish combined session (PDU session 1, default 5QI 9 -> QCI 9)
    let session = engine
        .establish_combined_session(supi, imsi, 1, "internet", snssai, ue_ip, 9)
        .expect("Combined session establishment should succeed");

    assert_eq!(session.default_ebi, MIN_EBI); // EBI 5
    assert_eq!(session.bearers.len(), 1);

    let default_bearer = session
        .bearers
        .get(&MIN_EBI)
        .expect("Default bearer 5 must exist");
    assert_eq!(default_bearer.ebi, 5);
    assert_eq!(default_bearer.linked_ebi, None);
    assert_eq!(default_bearer.qos.qci, 9);
    assert_eq!(default_bearer.qos.arp_priority, 9);
    assert_eq!(session.qfi_to_ebi.get(&1), Some(&5));

    // 2. Allocate dedicated bearer for video flow (QFI 3, 5QI 2 -> QCI 2, ARP 2)
    let dedicated_ebi = engine
        .allocate_dedicated_bearer(supi, 3, 2, 2)
        .expect("Dedicated bearer allocation must succeed");

    assert_eq!(dedicated_ebi, 6); // Next available EBI is 6

    let session_updated = engine.sessions.get(supi).unwrap();
    assert_eq!(session_updated.bearers.len(), 2);

    let dedicated_bearer = session_updated.bearers.get(&6).unwrap();
    assert_eq!(dedicated_bearer.ebi, 6);
    assert_eq!(dedicated_bearer.linked_ebi, Some(5)); // Linked to default bearer
    assert_eq!(dedicated_bearer.qos.qci, 2);
    assert_eq!(dedicated_bearer.qos.arp_priority, 2);
    assert_eq!(session_updated.qfi_to_ebi.get(&3), Some(&6));

    // Verify 5QI <-> QCI mapping functions
    assert_eq!(map_5qi_to_qci(1), 1);
    assert_eq!(map_5qi_to_qci(5), 5);
    assert_eq!(map_5qi_to_qci(85), 7);
    assert_eq!(map_qci_to_5qi(1), 1);
    assert_eq!(map_qci_to_5qi(9), 9);
}

#[test]
fn test_eps_interworking_5g_to_eps_n26_handover_preparation() {
    let pgw_c_ip = Ipv4Address::new(10, 200, 0, 10);
    let pgw_u_ip = Ipv4Address::new(10, 200, 0, 20);
    let mut engine = EpsInterworkingEngine::new("smf-pgw-n26-node", pgw_c_ip, pgw_u_ip);

    let supi = "208950000000002";
    let imsi = "208950000000002";
    let ue_ip = Ipv4Address::new(10, 45, 0, 102);

    engine
        .establish_combined_session(supi, imsi, 1, "ims", Snssai { sst: 1, sd: None }, ue_ip, 5)
        .unwrap();

    let k_amf = [0xAAu8; 32];
    let nas_ul_count = 12;

    // Step 1: Prepare N26 Forward Relocation Request
    let req = engine
        .prepare_n26_handover_to_eps(
            supi,
            "amf-node-01.5gc.mnc095.mcc208.3gppnetwork.org",
            "mme-node-01.epc.mnc095.mcc208.3gppnetwork.org",
            "208-95-0001",
            &k_amf,
            nas_ul_count,
        )
        .expect("Handover preparation must succeed");

    assert_eq!(req.imsi, imsi);
    assert_eq!(
        req.derived_k_asme,
        derive_k_asme_from_k_amf(&k_amf, nas_ul_count)
    );
    assert_eq!(
        engine.handover_states.get(supi),
        Some(&N26HandoverState::Prepared)
    );

    // Step 2: Simulate Target MME Response admitting EBI 5
    let target_enb_fteid = Fteid::new(
        FTEID_S1_U_ENB,
        0x5000_1111,
        Ipv4Address::new(10, 100, 1, 50),
    );
    let sgw_dl_fwd_fteid = Fteid::new(
        FTEID_S1_U_FORWARDING,
        0x6000_2222,
        Ipv4Address::new(10, 100, 1, 60),
    );

    let mut enb_fteids = std::collections::HashMap::new();
    enb_fteids.insert(5, target_enb_fteid.clone());

    let mut dl_fwd_fteids = std::collections::HashMap::new();
    dl_fwd_fteids.insert(5, sgw_dl_fwd_fteid.clone());

    let mme_response = ForwardRelocationResponse {
        accepted: true,
        cause: 16, // CAUSE_REQUEST_ACCEPTED
        admitted_ebis: vec![5],
        enb_s1u_fteids: enb_fteids,
        dl_forwarding_fteids: dl_fwd_fteids,
    };

    engine
        .process_n26_handover_response(supi, &mme_response)
        .expect("Response processing must succeed");

    assert_eq!(
        engine.handover_states.get(supi),
        Some(&N26HandoverState::Executing)
    );

    let session = engine.sessions.get(supi).unwrap();
    let bearer = session.bearers.get(&5).unwrap();
    assert_eq!(bearer.enb_fteid, Some(target_enb_fteid));
    assert_eq!(bearer.dl_forwarding_fteid, Some(sgw_dl_fwd_fteid));
    assert!(engine.forwarding_tunnels.contains_key(&5));
}

#[test]
fn test_eps_interworking_data_forwarding_tunnels() {
    let pgw_c_ip = Ipv4Address::new(10, 200, 0, 11);
    let pgw_u_ip = Ipv4Address::new(10, 200, 0, 21);
    let mut engine = EpsInterworkingEngine::new("smf-fwd-engine", pgw_c_ip, pgw_u_ip);

    let supi = "208950000000003";
    let imsi = "208950000000003";
    let ue_ip = Ipv4Address::new(10, 45, 0, 103);

    engine
        .establish_combined_session(
            supi,
            imsi,
            1,
            "internet",
            Snssai { sst: 1, sd: None },
            ue_ip,
            9,
        )
        .unwrap();

    let k_amf = [0xBBu8; 32];
    engine
        .prepare_n26_handover_to_eps(supi, "amf-01", "mme-01", "208-95-0001", &k_amf, 1)
        .unwrap();

    let mut dl_fwd = std::collections::HashMap::new();
    dl_fwd.insert(
        5,
        Fteid::new(
            FTEID_S1_U_FORWARDING,
            0x7777_8888,
            Ipv4Address::new(10, 100, 2, 1),
        ),
    );

    let mme_response = ForwardRelocationResponse {
        accepted: true,
        cause: 16,
        admitted_ebis: vec![5],
        enb_s1u_fteids: std::collections::HashMap::new(),
        dl_forwarding_fteids: dl_fwd,
    };
    engine
        .process_n26_handover_response(supi, &mme_response)
        .unwrap();

    // In-flight packets forwarded from 5G gNB/UPF
    let packet1 = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01];
    let packet2 = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x02];

    engine
        .forward_in_flight_packet(5, packet1.clone())
        .expect("Packet 1 forwarding must succeed");
    engine
        .forward_in_flight_packet(5, packet2.clone())
        .expect("Packet 2 forwarding must succeed");

    assert_eq!(
        engine
            .forwarding_tunnels
            .get(&5)
            .unwrap()
            .buffered_packets
            .len(),
        2
    );

    // Complete Handover: UE attached to target LTE eNB
    let delivered = engine
        .complete_n26_handover(supi)
        .expect("Handover completion must succeed");

    assert_eq!(
        engine.handover_states.get(supi),
        Some(&N26HandoverState::Completed)
    );

    let packets = delivered.get(&5).expect("EBI 5 packets must be delivered");
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[0], packet1);
    assert_eq!(packets[1], packet2);
    assert!(!engine.forwarding_tunnels.contains_key(&5)); // Flushed & removed
}

#[test]
fn test_eps_interworking_voice_eps_fallback() {
    let pgw_c_ip = Ipv4Address::new(10, 200, 0, 1);
    let pgw_u_ip = Ipv4Address::new(10, 200, 0, 2);
    let mut engine = EpsInterworkingEngine::new("smf-voice-fallback", pgw_c_ip, pgw_u_ip);

    let supi = "208950000000004";
    let imsi = "208950000000004";
    let ue_ip = Ipv4Address::new(10, 45, 0, 104);

    engine
        .establish_combined_session(supi, imsi, 1, "ims", Snssai { sst: 1, sd: None }, ue_ip, 5)
        .unwrap();

    // Case 1: Serving 5G cell DOES NOT support VoNR -> Trigger EPS Fallback to LTE
    let action_fallback = engine
        .handle_voice_call_request(supi, false)
        .expect("Voice handling must succeed");

    match action_fallback {
        VoiceCallAction::TriggerEpsFallback {
            target_qci,
            dedicated_ebi,
        } => {
            assert_eq!(target_qci, 1); // Conversational Voice QCI 1
            assert_eq!(dedicated_ebi, 6); // Pre-reserved dedicated EBI 6
        }
        _ => panic!("Expected TriggerEpsFallback"),
    }

    // Case 2: Serving 5G cell DOES support VoNR -> Maintain 5G VoNR
    let supi2 = "208950000000005";
    engine
        .establish_combined_session(
            supi2,
            "208950000000005",
            1,
            "ims",
            Snssai { sst: 1, sd: None },
            ue_ip,
            5,
        )
        .unwrap();

    let action_vonr = engine
        .handle_voice_call_request(supi2, true)
        .expect("Voice handling must succeed");

    match action_vonr {
        VoiceCallAction::Maintain5gVoNr { dedicated_ebi } => {
            assert_eq!(dedicated_ebi, 6);
        }
        _ => panic!("Expected Maintain5gVoNr"),
    }
}

#[test]
fn test_eps_interworking_ebi_exhaustion_and_handover_rejection() {
    let pgw_c_ip = Ipv4Address::new(10, 200, 0, 1);
    let pgw_u_ip = Ipv4Address::new(10, 200, 0, 2);
    let mut engine = EpsInterworkingEngine::new("smf-error-tests", pgw_c_ip, pgw_u_ip);

    let supi = "208950000000006";
    let imsi = "208950000000006";
    let ue_ip = Ipv4Address::new(10, 45, 0, 106);

    engine
        .establish_combined_session(
            supi,
            imsi,
            1,
            "internet",
            Snssai { sst: 1, sd: None },
            ue_ip,
            9,
        )
        .unwrap();

    // Allocate 10 dedicated bearers (EBIs 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    for qfi in 2..=11 {
        let ebi = engine
            .allocate_dedicated_bearer(supi, qfi, 9, 10)
            .expect("Bearer allocation should succeed");
        assert_eq!(ebi as usize, (qfi + 4) as usize);
    }

    assert_eq!(engine.sessions.get(supi).unwrap().bearers.len(), 11); // EBIs 5..15 (11 bearers total)

    // Attempt to allocate a 12th bearer when EBI pool 5..15 is completely full
    let err = engine.allocate_dedicated_bearer(supi, 12, 9, 10);
    assert_eq!(err, Err(EpsInterworkingError::EbiPoolExhausted));

    // Test Target MME rejection handling
    let k_amf = [0xCCu8; 32];
    engine
        .prepare_n26_handover_to_eps(supi, "amf-01", "mme-01", "208-95-0001", &k_amf, 1)
        .unwrap();

    let rejection_response = ForwardRelocationResponse {
        accepted: false,
        cause: 73, // CAUSE_NO_RESOURCES_AVAILABLE
        admitted_ebis: Vec::new(),
        enb_s1u_fteids: std::collections::HashMap::new(),
        dl_forwarding_fteids: std::collections::HashMap::new(),
    };

    let reject_res = engine.process_n26_handover_response(supi, &rejection_response);
    assert!(reject_res.is_err());
    assert_eq!(
        engine.handover_states.get(supi),
        Some(&N26HandoverState::Failed)
    );

    // Cannot complete failed handover
    let complete_err = engine.complete_n26_handover(supi);
    assert!(complete_err.is_err());
}
