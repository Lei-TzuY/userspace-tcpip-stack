//! Integration tests for 3GPP TS 29.573 / TS 33.501 5G Security Edge Protection Proxy (SEPP) Engine.

use std::collections::HashMap;

use toy_tcpip::ngap_5g::PlmnId;
use toy_tcpip::sepp_5g::*;

// ---------------------------------------------------------------------------
// 1. N32-c Handshake & N32-f PRINS End-to-End Protection Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_sepp_n32c_handshake_and_n32f_prins_happy_path() {
    let vplmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };
    let hplmn = PlmnId {
        mcc: [2, 0, 8],
        mnc: [0, 1, 0],
    };

    let mut egress_sepp = SeppEngine::new("sepp.vplmn.net", vplmn);
    let mut ingress_sepp = SeppEngine::new("sepp.hplmn.net", hplmn);

    let session_id = "n32-sess-v2h-001";
    let shared_key = [0x5au8; 32];

    let caps = SecurityCapability {
        prins_supported: true,
        cipher_suites: vec![PrinsCipherSuite::AesGcm256Sha384],
        ipx_provider_id: Some("IPX-Global-Transit".to_string()),
    };

    // Both SEPPs establish N32 session
    egress_sepp
        .establish_n32_session(session_id, hplmn, "sepp.hplmn.net", &caps, shared_key)
        .expect("Egress handshake failed");
    ingress_sepp
        .establish_n32_session(session_id, vplmn, "sepp.vplmn.net", &caps, shared_key)
        .expect("Ingress handshake failed");

    // Ingress SEPP registers telescopic FQDN route to internal UDM
    let telescopic_fqdn = "udm-telescopic.sepp.hplmn.net";
    let internal_udm_fqdn = "udm01.hplmn.5gc.carrier.internal";
    ingress_sepp.register_telescopic_route(telescopic_fqdn, internal_udm_fqdn);

    // Egress SEPP protects outgoing SBI message
    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());
    headers.insert("Via".to_string(), "1.1 sepp.vplmn.net".to_string());

    let payload = b"{\"supi\":\"imsi-208950000000001\",\"authType\":\"5G_AKA\"}";

    let protected_msg = egress_sepp
        .n32f_protect(
            session_id,
            "POST",
            telescopic_fqdn,
            headers.clone(),
            payload,
        )
        .expect("PRINS protection failed");

    assert_ne!(protected_msg.encrypted_payload, payload); // Ciphertext check

    // Ingress SEPP decapsulates & verifies
    let decapsulated = ingress_sepp
        .n32f_decapsulate(&protected_msg)
        .expect("PRINS decapsulation failed");

    assert_eq!(decapsulated.internal_target_fqdn, internal_udm_fqdn);
    assert_eq!(decapsulated.http_method, "POST");
    assert_eq!(decapsulated.payload, payload);
}

// ---------------------------------------------------------------------------
// 2. IPX Intermediary Authorized Header Modifications
// ---------------------------------------------------------------------------

#[test]
fn test_sepp_ipx_authorized_modifications() {
    let plmn1 = PlmnId {
        mcc: [3, 1, 0],
        mnc: [4, 1, 0],
    };
    let plmn2 = PlmnId {
        mcc: [4, 4, 0],
        mnc: [2, 0, 0],
    };

    let mut egress = SeppEngine::new("sepp.us.net", plmn1);
    let mut ingress = SeppEngine::new("sepp.jp.net", plmn2);

    let session_id = "n32-sess-us-jp-002";
    let shared_key = [0x7bu8; 32];
    let caps = SecurityCapability {
        prins_supported: true,
        cipher_suites: vec![PrinsCipherSuite::AesGcm256Sha384],
        ipx_provider_id: None,
    };

    egress
        .establish_n32_session(session_id, plmn2, "sepp.jp.net", &caps, shared_key)
        .unwrap();
    ingress
        .establish_n32_session(session_id, plmn1, "sepp.us.net", &caps, shared_key)
        .unwrap();
    ingress.register_telescopic_route("ausf-tele.jp.net", "ausf01.core.jp.net");

    let mut msg = egress
        .n32f_protect(
            session_id,
            "GET",
            "ausf-tele.jp.net",
            HashMap::new(),
            b"query-auth",
        )
        .unwrap();

    // Transit IPX modifies authorized header "Via"
    msg.ipx_modifications.push(IpxModification {
        ipx_id: "ipx-syniverse-hop1".to_string(),
        modified_header: "Via".to_string(),
        old_value: "1.1 sepp.us.net".to_string(),
        new_value: "1.1 sepp.us.net, 1.1 ipx-transit.syniverse.com".to_string(),
    });

    // Ingress SEPP permits authorized modification
    let decapsulated = ingress.n32f_decapsulate(&msg);
    assert!(decapsulated.is_ok());
}

// ---------------------------------------------------------------------------
// 3. Prohibited IPX Modification Tampering Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_sepp_ipx_prohibited_header_tampering_rejection() {
    let plmn1 = PlmnId {
        mcc: [3, 1, 0],
        mnc: [4, 1, 0],
    };
    let plmn2 = PlmnId {
        mcc: [4, 4, 0],
        mnc: [2, 0, 0],
    };

    let mut egress = SeppEngine::new("sepp.us.net", plmn1);
    let mut ingress = SeppEngine::new("sepp.jp.net", plmn2);

    let session_id = "n32-sess-us-jp-003";
    let shared_key = [0x8cu8; 32];
    let caps = SecurityCapability {
        prins_supported: true,
        cipher_suites: vec![PrinsCipherSuite::AesGcm256Sha384],
        ipx_provider_id: None,
    };

    egress
        .establish_n32_session(session_id, plmn2, "sepp.jp.net", &caps, shared_key)
        .unwrap();
    ingress
        .establish_n32_session(session_id, plmn1, "sepp.us.net", &caps, shared_key)
        .unwrap();
    ingress.register_telescopic_route("pcf-tele.jp.net", "pcf01.core.jp.net");

    let mut msg = egress
        .n32f_protect(
            session_id,
            "POST",
            "pcf-tele.jp.net",
            HashMap::new(),
            b"pcc-request",
        )
        .unwrap();

    // Malicious or misconfigured IPX tampers with prohibited header
    msg.ipx_modifications.push(IpxModification {
        ipx_id: "rogue-ipx".to_string(),
        modified_header: "Authorization".to_string(),
        old_value: "Bearer token-1".to_string(),
        new_value: "Bearer rogue-token".to_string(),
    });

    let res = ingress.n32f_decapsulate(&msg);
    match res {
        Err(SeppError::UnauthorizedIpxModification(err)) => {
            assert!(err.contains("prohibited header"));
        }
        other => panic!("Expected UnauthorizedIpxModification, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// 4. Transit Tampered Payload Integrity MAC Failure
// ---------------------------------------------------------------------------

#[test]
fn test_sepp_tampered_payload_mac_failure() {
    let plmn1 = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };
    let plmn2 = PlmnId {
        mcc: [2, 0, 8],
        mnc: [0, 1, 0],
    };

    let mut egress = SeppEngine::new("sepp.v.net", plmn1);
    let mut ingress = SeppEngine::new("sepp.h.net", plmn2);

    let session_id = "n32-sess-tamper-004";
    let shared_key = [0x9du8; 32];
    let caps = SecurityCapability {
        prins_supported: true,
        cipher_suites: vec![PrinsCipherSuite::AesGcm256Sha384],
        ipx_provider_id: None,
    };

    egress
        .establish_n32_session(session_id, plmn2, "sepp.h.net", &caps, shared_key)
        .unwrap();
    ingress
        .establish_n32_session(session_id, plmn1, "sepp.v.net", &caps, shared_key)
        .unwrap();
    ingress.register_telescopic_route("udm-tele.h.net", "udm.core.h.net");

    let mut msg = egress
        .n32f_protect(
            session_id,
            "GET",
            "udm-tele.h.net",
            HashMap::new(),
            b"sensitive-data",
        )
        .unwrap();

    // Adversary tampers with one byte in ciphertext during transit
    if let Some(b) = msg.encrypted_payload.first_mut() {
        *b ^= 0xFF;
    }

    let res = ingress.n32f_decapsulate(&msg);
    assert_eq!(res, Err(SeppError::IntegrityMacFailure));
}

// ---------------------------------------------------------------------------
// 5. Invalid Telescopic FQDN Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_sepp_invalid_telescopic_fqdn_rejection() {
    let plmn1 = PlmnId {
        mcc: [2, 0, 8],
        mnc: [9, 5, 0],
    };
    let plmn2 = PlmnId {
        mcc: [2, 0, 8],
        mnc: [0, 1, 0],
    };

    let mut egress = SeppEngine::new("sepp.v.net", plmn1);
    let mut ingress = SeppEngine::new("sepp.h.net", plmn2);

    let session_id = "n32-sess-unmapped-005";
    let shared_key = [0xa1u8; 32];
    let caps = SecurityCapability {
        prins_supported: true,
        cipher_suites: vec![PrinsCipherSuite::AesGcm256Sha384],
        ipx_provider_id: None,
    };

    egress
        .establish_n32_session(session_id, plmn2, "sepp.h.net", &caps, shared_key)
        .unwrap();
    ingress
        .establish_n32_session(session_id, plmn1, "sepp.v.net", &caps, shared_key)
        .unwrap();

    // Target unmapped telescopic FQDN
    let msg = egress
        .n32f_protect(
            session_id,
            "GET",
            "unregistered.sepp.h.net",
            HashMap::new(),
            b"ping",
        )
        .unwrap();

    let res = ingress.n32f_decapsulate(&msg);
    assert_eq!(res, Err(SeppError::InvalidTelescopicFqdn));
}
