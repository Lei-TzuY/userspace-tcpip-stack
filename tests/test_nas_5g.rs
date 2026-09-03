//! Integration tests for 3GPP TS 24.501 5G Non-Access Stratum (NAS) Protocol Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::nas_5g::*;
use toy_tcpip::ngap_5g::{PlmnId, Snssai};
use toy_tcpip::rrc_5g::{RrcEngine, RrcRole, RrcSetup};

fn test_plmn() -> PlmnId {
    PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    }
}

fn test_k_secret() -> [u8; 16] {
    [
        0x46, 0x5B, 0x5C, 0xE8, 0xB1, 0x99, 0xB4, 0x9F, 0xAA, 0x5F, 0x0A, 0x2E, 0xE2, 0x38, 0xA6,
        0xBC,
    ]
}

// ---------------------------------------------------------------------------
// 1. Full 5G Registration Procedure (Initial Registration -> 5G-AKA -> Security -> Accept)
// ---------------------------------------------------------------------------

#[test]
fn test_nas_registration_procedure_happy_path() {
    let mut ue_nas = NasEngine::new(test_k_secret());
    let mut net_nas = NasEngine::new(test_k_secret());

    assert_eq!(ue_nas.gmm_state, GmmState::Deregistered);

    // 1. UE creates SUCI and builds Registration Request
    let suci = MobileIdentity5Gs::Suci {
        plmn: test_plmn(),
        routing_indicator: 0x0000,
        protection_scheme_id: 0, // Null scheme
        home_network_pki: 1,
        scheme_output: vec![0x01, 0x02, 0x03, 0x04, 0x05], // MSIN
    };
    let slices = vec![Snssai { sst: 1, sd: None }, Snssai { sst: 2, sd: None }];
    let reg_req_pdu = ue_nas.ue_build_registration_request(suci.clone(), slices.clone());
    assert_eq!(ue_nas.gmm_state, GmmState::RegisteredInitiated);

    // Test wire serialization of Registration Request
    let reg_req_bytes = reg_req_pdu.to_bytes();
    let parsed_req_pdu =
        NasPdu::from_bytes(&reg_req_bytes).expect("Failed to parse Registration Request");
    assert_eq!(parsed_req_pdu.security_header_type, SHT_PLAIN_NAS);

    // 2. Network generates 5G-AKA Authentication Challenge (RAND & AUTN)
    let rand = [0x11u8; 16];
    let autn = [0x22u8; 16];
    let auth_req_pdu = net_nas.net_build_authentication_request(rand, autn);

    // Wire roundtrip
    let auth_req_bytes = auth_req_pdu.to_bytes();
    let parsed_auth_req = NasPdu::from_bytes(&auth_req_bytes).unwrap();
    let auth_req = match parsed_auth_req.gmm_message {
        Some(Nas5GmmMessage::AuthenticationRequest(r)) => r,
        _ => panic!("Expected AuthenticationRequest"),
    };

    // 3. UE receives Authentication Request, validates challenge and computes RES*
    let auth_resp_pdu = ue_nas.ue_handle_authentication_request(&auth_req);
    let auth_resp_bytes = auth_resp_pdu.to_bytes();
    let parsed_auth_resp = NasPdu::from_bytes(&auth_resp_bytes).unwrap();
    let auth_resp = match parsed_auth_resp.gmm_message {
        Some(Nas5GmmMessage::AuthenticationResponse(r)) => r,
        _ => panic!("Expected AuthenticationResponse"),
    };

    // 4. Network verifies RES*
    assert!(net_nas.net_verify_authentication_response(&auth_resp, &rand, &autn));

    // 5. Network sends Security Mode Command
    let smc_pdu = net_nas.net_build_security_mode_command();
    let smc_bytes = smc_pdu.to_bytes();
    let parsed_smc = NasPdu::from_bytes(&smc_bytes).unwrap();
    let smc = match parsed_smc.gmm_message {
        Some(Nas5GmmMessage::SecurityModeCommand(c)) => c,
        _ => panic!("Expected SecurityModeCommand"),
    };

    // 6. UE handles Security Mode Command and returns Security Mode Complete
    let smc_comp_pdu = ue_nas.ue_handle_security_mode_command(&smc);
    assert_eq!(smc_comp_pdu.security_header_type, SHT_INTEGRITY_PROTECTED);
    assert!(ue_nas.security_active);

    // 7. Network issues Registration Accept with allocated 5G-GUTI
    let allocated_guti = MobileIdentity5Gs::Guti5Gs {
        plmn: test_plmn(),
        amf_region_id: 2,
        amf_set_id: 1,
        amf_pointer: 1,
        tmsi_5g: 0xCAFE_BABE,
    };
    let reg_acc_pdu = net_nas.net_build_registration_accept(allocated_guti.clone(), slices);
    let reg_acc_bytes = reg_acc_pdu.to_bytes();
    let parsed_reg_acc = NasPdu::from_bytes(&reg_acc_bytes).unwrap();
    let reg_acc = match parsed_reg_acc.gmm_message {
        Some(Nas5GmmMessage::RegistrationAccept(a)) => a,
        _ => panic!("Expected RegistrationAccept"),
    };

    // 8. UE handles Registration Accept, updates state to Registered, returns Registration Complete
    let reg_comp_pdu = ue_nas.ue_handle_registration_accept(&reg_acc);
    assert_eq!(ue_nas.gmm_state, GmmState::Registered);
    assert_eq!(ue_nas.allocated_guti, Some(allocated_guti));
    assert_eq!(reg_comp_pdu.security_header_type, SHT_INTEGRITY_PROTECTED);
}

// ---------------------------------------------------------------------------
// 2. 5GSM PDU Session Establishment (UL/DL NAS Transport multiplexing)
// ---------------------------------------------------------------------------

#[test]
fn test_nas_pdu_session_establishment_procedure() {
    let mut ue_nas = NasEngine::new(test_k_secret());
    let mut net_nas = NasEngine::new(test_k_secret());

    // Pretend UE is registered
    ue_nas.gmm_state = GmmState::Registered;

    // 1. UE requests PDU Session Establishment (session_id=1, IPv4, SSC1)
    let ul_transport_pdu =
        ue_nas.ue_build_pdu_session_establishment_request(1, PduSessionType::Ipv4, SscMode::Ssc1);
    assert_eq!(
        ul_transport_pdu.security_header_type,
        SHT_INTEGRITY_PROTECTED
    );
    assert_eq!(
        ue_nas.pdu_sessions.get(&1).unwrap().state,
        GsmState::ActivePending
    );

    // Wire serialization roundtrip
    let ul_bytes = ul_transport_pdu.to_bytes();
    let parsed_ul_pdu = NasPdu::from_bytes(&ul_bytes).unwrap();
    let ul_transport = match parsed_ul_pdu.gmm_message {
        Some(Nas5GmmMessage::UlNasTransport(t)) => t,
        _ => panic!("Expected UlNasTransport"),
    };
    assert_eq!(ul_transport.pdu_session_id, 1);

    // 2. Network (AMF/SMF) processes UL NAS Transport, assigns IP 10.45.0.2 and QFI 9
    let assigned_ip = Ipv4Address::new(10, 45, 0, 2);
    let dl_transport_pdu = net_nas
        .net_handle_pdu_session_establishment_request(&ul_transport, assigned_ip, 9)
        .expect("Network handle PDU session request failed");

    // Wire serialization roundtrip
    let dl_bytes = dl_transport_pdu.to_bytes();
    let parsed_dl_pdu = NasPdu::from_bytes(&dl_bytes).unwrap();
    let dl_transport = match parsed_dl_pdu.gmm_message {
        Some(Nas5GmmMessage::DlNasTransport(t)) => t,
        _ => panic!("Expected DlNasTransport"),
    };
    assert_eq!(dl_transport.pdu_session_id, 1);

    // 3. UE handles DL NAS Transport, verifies allocated IP address and QFI
    let allocated_ip = ue_nas
        .ue_handle_dl_nas_transport(&dl_transport)
        .expect("UE handle DL NAS transport failed");
    assert_eq!(allocated_ip, assigned_ip);

    let sess_ctx = ue_nas.pdu_sessions.get(&1).unwrap();
    assert_eq!(sess_ctx.state, GsmState::Active);
    assert_eq!(sess_ctx.allocated_ip, Some(assigned_ip));
    assert_eq!(sess_ctx.qfi, 9);
}

// ---------------------------------------------------------------------------
// 3. NAS Security Header Types & MAC Verification
// ---------------------------------------------------------------------------

#[test]
fn test_nas_security_headers_and_integrity() {
    let plain_pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::RegistrationComplete);
    let plain_bytes = plain_pdu.to_bytes();
    assert_eq!(plain_bytes[0], EPD_5GS_MOBILITY_MANAGEMENT);
    assert_eq!(plain_bytes[1], SHT_PLAIN_NAS);
    assert_eq!(plain_bytes[2], NAS_5GMM_REGISTRATION_COMPLETE);

    let integrity_pdu = plain_pdu.with_integrity(0x1234_5678, 5);
    let integrity_bytes = integrity_pdu.to_bytes();
    assert_eq!(integrity_bytes[0], EPD_5GS_MOBILITY_MANAGEMENT);
    assert_eq!(integrity_bytes[1], SHT_INTEGRITY_PROTECTED);

    let parsed = NasPdu::from_bytes(&integrity_bytes).unwrap();
    assert_eq!(parsed.security_header_type, SHT_INTEGRITY_PROTECTED);
    assert_eq!(parsed.message_authentication_code, 0x1234_5678);
    assert_eq!(parsed.sequence_number, 5);
    assert_eq!(
        parsed.gmm_message,
        Some(Nas5GmmMessage::RegistrationComplete)
    );
}

// ---------------------------------------------------------------------------
// 4. De-registration Procedure
// ---------------------------------------------------------------------------

#[test]
fn test_nas_deregistration_procedure() {
    let mut ue_nas = NasEngine::new(test_k_secret());
    ue_nas.gmm_state = GmmState::Registered;
    ue_nas.allocated_guti = Some(MobileIdentity5Gs::Guti5Gs {
        plmn: test_plmn(),
        amf_region_id: 1,
        amf_set_id: 1,
        amf_pointer: 1,
        tmsi_5g: 0x9999,
    });

    let dereg_req_pdu = ue_nas
        .ue_build_deregistration_request()
        .expect("Build deregistration failed");
    assert_eq!(ue_nas.gmm_state, GmmState::DeregisteredInitiated);

    let wire = dereg_req_pdu.to_bytes();
    let parsed = NasPdu::from_bytes(&wire).unwrap();
    match parsed.gmm_message {
        Some(Nas5GmmMessage::DeregistrationRequest(r)) => {
            assert!(!r.switch_off);
        }
        _ => panic!("Expected DeregistrationRequest"),
    }
}

// ---------------------------------------------------------------------------
// 5. Causes & Error Handling
// ---------------------------------------------------------------------------

#[test]
fn test_nas_causes_and_rejection() {
    let rej = RegistrationReject {
        cause: Nas5GmmCause::IllegalUe,
    };
    let pdu = NasPdu::new_plain_gmm(Nas5GmmMessage::RegistrationReject(rej));
    let bytes = pdu.to_bytes();
    let parsed = NasPdu::from_bytes(&bytes).unwrap();

    match parsed.gmm_message {
        Some(Nas5GmmMessage::RegistrationReject(r)) => {
            assert_eq!(r.cause, Nas5GmmCause::IllegalUe);
        }
        _ => panic!("Expected RegistrationReject"),
    }

    let gsm_rej = PduSessionEstablishmentReject {
        pdu_session_id: 2,
        pti: 7,
        cause: Nas5GsmCause::InsufficientResources,
    };
    let gsm_pdu = NasPdu::new_plain_gsm(Nas5GsmMessage::EstablishmentReject(gsm_rej));
    let gsm_bytes = gsm_pdu.to_bytes();
    let parsed_gsm = NasPdu::from_bytes(&gsm_bytes).unwrap();

    match parsed_gsm.gsm_message {
        Some(Nas5GsmMessage::EstablishmentReject(r)) => {
            assert_eq!(r.pdu_session_id, 2);
            assert_eq!(r.cause, Nas5GsmCause::InsufficientResources);
        }
        _ => panic!("Expected EstablishmentReject"),
    }
}

// ---------------------------------------------------------------------------
// 6. Cross-Layer Integration: NAS PDU transport in RRC Setup Complete
// ---------------------------------------------------------------------------

#[test]
fn test_nas_rrc_setup_complete_container_integration() {
    let mut ue_nas = NasEngine::new(test_k_secret());
    let mut ue_rrc = RrcEngine::new(RrcRole::Ue);

    // 1. UE NAS generates Registration Request
    let suci = MobileIdentity5Gs::Suci {
        plmn: test_plmn(),
        routing_indicator: 0x0000,
        protection_scheme_id: 0,
        home_network_pki: 1,
        scheme_output: vec![0x12, 0x34],
    };
    let nas_pdu = ue_nas.ue_build_registration_request(suci, vec![]);
    let nas_bytes = nas_pdu.to_bytes();

    // 2. UE RRC initiates Setup Request and receives RrcSetup
    let _req = ue_rrc.ue_initiate_setup_request(
        0x11223344,
        toy_tcpip::rrc_5g::RrcEstablishmentCause::MoSignalling,
    );
    let rrc_setup = RrcSetup {
        rrc_transaction_identifier: 1,
        radio_bearer_config: toy_tcpip::rrc_5g::RadioBearerConfig::new(),
        master_cell_group_allocated_crnti: 0x4001,
    };

    // 3. UE RRC puts NAS PDU inside RrcSetupComplete!
    let rrc_comp = ue_rrc
        .ue_handle_setup(&rrc_setup, test_plmn(), nas_bytes.clone())
        .unwrap();
    assert_eq!(rrc_comp.dedicated_nas_message, nas_bytes);

    // 4. Verify the extracted NAS PDU inside RRC matches the original NAS message
    let extracted_nas = NasPdu::from_bytes(&rrc_comp.dedicated_nas_message).unwrap();
    match extracted_nas.gmm_message {
        Some(Nas5GmmMessage::RegistrationRequest(_)) => {}
        _ => panic!("Expected RegistrationRequest inside RRC container"),
    }
}
