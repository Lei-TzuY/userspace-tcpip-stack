//! Integration tests for 3GPP TS 29.509 / TS 29.503 / TS 33.501 5G AUSF & UDM Engine.

use toy_tcpip::ausf_udm_5g::*;
use toy_tcpip::nas_5g::{PduSessionType, SscMode, verify_5g_aka_challenge};
use toy_tcpip::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// 1. Pure Rust SHA-256 NIST Vector Verification
// ---------------------------------------------------------------------------

#[test]
fn test_sha256_known_fips_vectors() {
    // NIST standard vector for "abc"
    let d = sha256(b"abc");
    let hex: String = d.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // NIST standard vector for "" (empty string)
    let d_empty = sha256(b"");
    let hex_empty: String = d_empty.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex_empty,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

// ---------------------------------------------------------------------------
// 2. UDM Provisioning & SUCI De-concealing
// ---------------------------------------------------------------------------

#[test]
fn test_udm_provisioning_and_suci_deconceal() {
    let mut udm = UdmEngine::new();
    let k = [0x11; 16];
    let opc = [0x22; 16];
    let snssais = vec![Snssai { sst: 1, sd: None }, Snssai { sst: 2, sd: None }];
    let dnn_cfg = vec![(
        "internet".to_string(),
        DnnConfiguration {
            allowed_pdu_session_types: vec![PduSessionType::Ipv4],
            default_ssc_mode: SscMode::Ssc1,
            session_ambr_dl_kbps: 100_000,
            session_ambr_ul_kbps: 50_000,
            default_5qi: 9,
        },
    )];

    udm.provision_subscriber("imsi-208950000000001", k, opc, snssais, dnn_cfg);

    // Test SUCI Null scheme de-concealing
    let suci = "suci-0-208-95-0-0-0-0000000001";
    let deconcealed = udm.deconceal_suci(suci);
    assert_eq!(deconcealed, "imsi-208950000000001");

    // Test already plain SUPI
    assert_eq!(
        udm.deconceal_suci("imsi-208950000000001"),
        "imsi-208950000000001"
    );
}

// ---------------------------------------------------------------------------
// 3. Nausf_UEAuthentication 5G-AKA Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_nausf_ue_authentication_happy_path() {
    let mut udm = UdmEngine::new();
    let k = [0x5A; 16];
    let opc = [0x3C; 16];
    udm.provision_subscriber("imsi-208950000000001", k, opc, Vec::new(), Vec::new());

    let mut ausf = AusfEngine::new("ausf-core-001", udm);

    // 1. AMF sends Nausf_UEAuthentication Request
    let req = UeAuthenticationRequest {
        supi_or_suci: "suci-0-208-95-0-0-0-0000000001".to_string(),
        serving_network_name: "5G:mnc095.mcc208.3gppnetwork.org".to_string(),
    };

    let resp = ausf
        .handle_authenticate_request(&req)
        .expect("AUSF authentication request failed");

    assert!(!resp.auth_context_ref.is_empty());
    assert_ne!(resp.rand, [0u8; 16]);
    assert_ne!(resp.autn, [0u8; 16]);

    // 2. UE side computes RES* upon receiving RAND & AUTN
    let ue_res_star = verify_5g_aka_challenge(&resp.rand, &resp.autn, &k);

    // 3. AMF submits Nausf_UEAuthentication Confirmation with UE RES*
    let confirm_req = UeAuthenticationConfirmationRequest {
        auth_context_ref: resp.auth_context_ref,
        res_star: ue_res_star,
    };

    let confirm_resp = ausf
        .handle_authenticate_confirmation(&confirm_req)
        .expect("Confirmation failed");

    assert!(confirm_resp.success);
    assert_eq!(confirm_resp.supi, "imsi-208950000000001");
    assert!(confirm_resp.k_seaf.is_some());
    assert_ne!(confirm_resp.k_seaf.unwrap(), [0u8; 32]);
}

// ---------------------------------------------------------------------------
// 4. Nausf_UEAuthentication Rejection on Mismatched RES*
// ---------------------------------------------------------------------------

#[test]
fn test_nausf_ue_authentication_rejection_on_mismatched_res() {
    let mut udm = UdmEngine::new();
    let k = [0x5A; 16];
    let opc = [0x3C; 16];
    udm.provision_subscriber("imsi-208950000000002", k, opc, Vec::new(), Vec::new());

    let mut ausf = AusfEngine::new("ausf-core-002", udm);

    let req = UeAuthenticationRequest {
        supi_or_suci: "imsi-208950000000002".to_string(),
        serving_network_name: "5G:mnc095.mcc208.3gppnetwork.org".to_string(),
    };
    let resp = ausf.handle_authenticate_request(&req).unwrap();

    // UE sends wrong RES*
    let bad_res = [0xFF; 16];
    let confirm_req = UeAuthenticationConfirmationRequest {
        auth_context_ref: resp.auth_context_ref,
        res_star: bad_res,
    };

    let confirm_resp = ausf.handle_authenticate_confirmation(&confirm_req).unwrap();
    assert!(!confirm_resp.success);
    assert!(confirm_resp.k_seaf.is_none());
}

// ---------------------------------------------------------------------------
// 5. Nudm_SDM Subscription Retrieval
// ---------------------------------------------------------------------------

#[test]
fn test_nudm_sdm_am_and_sm_subscription_retrieval() {
    let mut udm = UdmEngine::new();
    let k = [0xAA; 16];
    let opc = [0xBB; 16];
    let snssais = vec![Snssai { sst: 1, sd: None }];
    let dnn_cfg = vec![(
        "internet".to_string(),
        DnnConfiguration {
            allowed_pdu_session_types: vec![PduSessionType::Ipv4],
            default_ssc_mode: SscMode::Ssc1,
            session_ambr_dl_kbps: 200_000,
            session_ambr_ul_kbps: 100_000,
            default_5qi: 9,
        },
    )];

    udm.provision_subscriber("imsi-208950000000003", k, opc, snssais, dnn_cfg);

    // Query AM Data
    let am_data = udm
        .get_am_data("imsi-208950000000003")
        .expect("AM data missing");
    assert_eq!(am_data.supported_snssais.len(), 1);
    assert_eq!(am_data.supported_snssais[0].sst, 1);

    // Query SM Data
    let sm_data = udm
        .get_sm_data("imsi-208950000000003", "internet")
        .expect("SM data missing");
    assert_eq!(sm_data.session_ambr_dl_kbps, 200_000);
    assert_eq!(sm_data.default_5qi, 9);
}

// ---------------------------------------------------------------------------
// 6. Full 5G Registration Security Pipeline (SUCI -> UDM -> AUSF -> 5G-AKA)
// ---------------------------------------------------------------------------

#[test]
fn test_full_5g_registration_security_pipeline() {
    let mut udm = UdmEngine::new();
    let k = [0x77; 16];
    let opc = [0x88; 16];
    let suci = "suci-0-208-95-0-0-0-0000000099";
    let snssais = vec![Snssai { sst: 1, sd: None }];
    udm.provision_subscriber("imsi-208950000000099", k, opc, snssais, Vec::new());

    let mut ausf = AusfEngine::new("ausf-sec-pipeline", udm);

    // 1. UE sends Registration Request with SUCI to AMF
    // AMF invokes Nausf_UEAuthentication with the SUCI
    let auth_req = UeAuthenticationRequest {
        supi_or_suci: suci.to_string(),
        serving_network_name: "5G:mnc095.mcc208.3gppnetwork.org".to_string(),
    };
    let auth_resp = ausf
        .handle_authenticate_request(&auth_req)
        .expect("Auth request failed");

    // 2. AMF delivers 5GMM Authentication Request (carrying RAND and AUTN) to UE over NAS
    let rand = auth_resp.rand;
    let autn = auth_resp.autn;

    // 3. UE validates AUTN and derives RES* using USIM key K
    let res_star = verify_5g_aka_challenge(&rand, &autn, &k);

    // 4. AMF submits RES* to AUSF Confirmation
    let confirm_req = UeAuthenticationConfirmationRequest {
        auth_context_ref: auth_resp.auth_context_ref,
        res_star,
    };
    let confirm_resp = ausf
        .handle_authenticate_confirmation(&confirm_req)
        .expect("Confirmation failed");

    assert!(confirm_resp.success);
    assert_eq!(confirm_resp.supi, "imsi-208950000000099");

    // 5. AMF receives K_seaf and derives K_nas_int & K_nas_enc for Security Mode Control
    let k_seaf = confirm_resp.k_seaf.unwrap();
    let mut k_nas_int = [0u8; 16];
    k_nas_int.copy_from_slice(&k_seaf[0..16]);
    assert_ne!(k_nas_int, [0u8; 16]);
}
