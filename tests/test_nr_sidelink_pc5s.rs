//! Integration tests for 3GPP Rel-18 Sidelink PC5-S Unicast Session & Direct Security Engine.

use toy_tcpip::nr_sidelink_pc5s::{
    hmac_sha256, kdf_3gpp, Pc5QosFlow, Pc5SecurityContext, Pc5sEngine, Pc5sLinkState,
    Pc5sMessage, Pc5sRejectCause, Sha256, SidelinkCipheringAlgorithm, SidelinkIntegrityAlgorithm,
    DEFAULT_T4111_KEEPALIVE_MS, DEFAULT_T4112_TIMEOUT_MS, MAX_PC5S_RETRANSMISSIONS,
};

#[test]
fn test_pure_rust_sha256_and_hmac_sha256_test_vectors() {
    // FIPS 180-4 / RFC 6234 standard test vector for "abc"
    let digest = Sha256::digest(b"abc");
    let hex_digest = digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    assert_eq!(
        hex_digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // RFC 2104 test vector 1: Key = 0x0b repeated 20 times, Data = "Hi There"
    let key = [0x0b; 20];
    let data = b"Hi There";
    let mac = hmac_sha256(&key, data);
    let hex_mac = mac.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    assert_eq!(
        hex_mac,
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );

    // 3GPP KDF determinism
    let kdf_out = kdf_3gpp(&key, 0x70, &[b"param0", b"param1"]);
    assert_ne!(kdf_out, [0u8; 32]);
}

#[test]
fn test_pc5s_pdu_binary_wire_codecs_roundtrip() {
    let dcr = Pc5sMessage::DirectCommunicationRequest {
        initiator_l2_id: 0x00AABB,
        target_l2_id: 0x00CCDD,
        application_id: 0x12345678,
        initiator_nonce: [0x11; 16],
        supported_ciphers: 0x07,
        supported_integs: 0x07,
        ip_address_config: 2,
        qos_flows: vec![
            Pc5QosFlow {
                pqfi: 1,
                pc5_5qi: 23,
                range_meters: 150,
            },
            Pc5QosFlow {
                pqfi: 2,
                pc5_5qi: 24,
                range_meters: 300,
            },
        ],
    };

    let encoded = dcr.encode();
    let decoded = Pc5sMessage::decode(&encoded).expect("Decode DCR failed");
    assert_eq!(dcr, decoded);

    let dsmc = Pc5sMessage::DirectSecurityModeCommand {
        link_id: 42,
        selected_cipher: SidelinkCipheringAlgorithm::Nea2,
        selected_integ: SidelinkIntegrityAlgorithm::Nia2,
        responder_nonce: [0x22; 16],
        mac_i: [0xAA, 0xBB, 0xCC, 0xDD],
    };
    let encoded_dsmc = dsmc.encode();
    let decoded_dsmc = Pc5sMessage::decode(&encoded_dsmc).expect("Decode DSMC failed");
    assert_eq!(dsmc, decoded_dsmc);

    let dsm_comp = Pc5sMessage::DirectSecurityModeComplete {
        link_id: 42,
        mac_i: [0x12, 0x34, 0x56, 0x78],
    };
    let encoded_comp = dsm_comp.encode();
    let decoded_comp = Pc5sMessage::decode(&encoded_comp).expect("Decode Complete failed");
    assert_eq!(dsm_comp, decoded_comp);

    let dca = Pc5sMessage::DirectCommunicationAccept {
        link_id: 42,
        responder_l2_id: 0x00CCDD,
        ip_address_config: 2,
        admitted_pqfis: vec![1, 2],
    };
    let encoded_dca = dca.encode();
    let decoded_dca = Pc5sMessage::decode(&encoded_dca).expect("Decode DCA failed");
    assert_eq!(dca, decoded_dca);

    let keepalive = Pc5sMessage::DirectLinkKeepalive {
        link_id: 42,
        seq_num: 7,
    };
    let encoded_ka = keepalive.encode();
    let decoded_ka = Pc5sMessage::decode(&encoded_ka).expect("Decode Keepalive failed");
    assert_eq!(keepalive, decoded_ka);
}

#[test]
fn test_end_to_end_unicast_link_establishment_handshake() {
    let shared_root_key = [0x5A; 32];
    let ue1_l2_id = 0x111111;
    let ue2_l2_id = 0x222222;

    let mut ue1 = Pc5sEngine::new(
        ue1_l2_id,
        shared_root_key,
        vec![
            SidelinkCipheringAlgorithm::Nea2,
            SidelinkCipheringAlgorithm::Nea1,
        ],
        vec![
            SidelinkIntegrityAlgorithm::Nia2,
            SidelinkIntegrityAlgorithm::Nia1,
        ],
    );

    let mut ue2 = Pc5sEngine::new(
        ue2_l2_id,
        shared_root_key,
        vec![
            SidelinkCipheringAlgorithm::Nea2,
            SidelinkCipheringAlgorithm::Nea1,
        ],
        vec![
            SidelinkIntegrityAlgorithm::Nia2,
            SidelinkIntegrityAlgorithm::Nia1,
        ],
    );

    let now_ms = 1_000;

    // Step 1: UE-1 initiates link towards UE-2
    let initiator_nonce = [0xA1; 16];
    let qos_flows = vec![Pc5QosFlow {
        pqfi: 5,
        pc5_5qi: 50,
        range_meters: 200,
    }];
    let (ue1_link_id, dcr) = ue1.initiate_link(ue2_l2_id, 0xBEEF, qos_flows, initiator_nonce, now_ms);
    assert_eq!(ue1_link_id, 1);
    assert_eq!(
        ue1.links[&ue1_link_id].state,
        Pc5sLinkState::DirectCommRequested
    );

    // Step 2: UE-2 receives DCR and responds with DirectSecurityModeCommand
    let responder_nonce = [0xB2; 16];
    let (ue2_link_id, dsmc) = ue2
        .handle_direct_comm_request(&dcr, responder_nonce, now_ms + 10)
        .expect("UE-2 handle DCR failed");
    assert_eq!(ue2.links[&ue2_link_id].state, Pc5sLinkState::Securing);

    // Step 3: UE-1 processes DSMC and emits DirectSecurityModeComplete
    let dsm_comp = ue1
        .handle_security_mode_command(ue1_link_id, &dsmc, now_ms + 20)
        .expect("UE-1 handle DSMC failed");
    assert_eq!(
        ue1.links[&ue1_link_id].state,
        Pc5sLinkState::DirectCommEstablished
    );

    // Step 4: UE-2 processes DirectSecurityModeComplete and emits DirectCommunicationAccept
    let dca = ue2
        .handle_security_mode_complete(ue2_link_id, &dsm_comp, now_ms + 30)
        .expect("UE-2 handle Complete failed");
    assert_eq!(
        ue2.links[&ue2_link_id].state,
        Pc5sLinkState::DirectCommEstablished
    );

    // Verify negotiated keys match on both sides
    let sec1 = ue1.links[&ue1_link_id].security_context.as_ref().unwrap();
    let sec2 = ue2.links[&ue2_link_id].security_context.as_ref().unwrap();
    assert_eq!(sec1.k_enc, sec2.k_enc);
    assert_eq!(sec1.k_int, sec2.k_int);
    assert_eq!(sec1.ciphering_algorithm, SidelinkCipheringAlgorithm::Nea2);
    assert_eq!(sec1.integrity_algorithm, SidelinkIntegrityAlgorithm::Nia2);

    match dca {
        Pc5sMessage::DirectCommunicationAccept {
            admitted_pqfis, ..
        } => {
            assert_eq!(admitted_pqfis, vec![5]);
        }
        _ => panic!("Expected DirectCommunicationAccept"),
    }
}

#[test]
fn test_authenticated_encryption_and_tamper_detection() {
    let shared_root_key = [0x99; 32];
    let mut ue1 = Pc5sEngine::new(
        10,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea2],
        vec![SidelinkIntegrityAlgorithm::Nia2],
    );
    let mut ue2 = Pc5sEngine::new(
        20,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea2],
        vec![SidelinkIntegrityAlgorithm::Nia2],
    );

    // Establish link
    let (l1, dcr) = ue1.initiate_link(20, 1, vec![], [1; 16], 100);
    let (l2, dsmc) = ue2.handle_direct_comm_request(&dcr, [2; 16], 110).unwrap();
    let comp = ue1.handle_security_mode_command(l1, &dsmc, 120).unwrap();
    let _dca = ue2.handle_security_mode_complete(l2, &comp, 130).unwrap();

    let original_payload = b"3GPP Rel-18 Sidelink V2X Emergency Brake Warning Payload";

    // UE-1 encrypts and signs payload
    let protected = ue1
        .protect_pdu(l1, 1, 0, original_payload)
        .expect("Protect failed");
    assert_ne!(&protected[4..protected.len() - 4], original_payload); // Confirmed ciphertext

    // UE-2 decrypts and verifies
    let recovered = ue2
        .unprotect_pdu(l2, 1, 0, &protected)
        .expect("Unprotect failed");
    assert_eq!(recovered, original_payload);

    // Replay test: re-sending the same packet (count = 0) must trigger anti-replay drop
    let replay_err = ue2.unprotect_pdu(l2, 1, 0, &protected);
    assert!(replay_err.is_err());
    assert_eq!(ue2.stats_replays_detected, 1);

    // Tamper test: transmit a second packet with fresh Count = 1, then tamper its ciphertext
    let mut protected2 = ue1
        .protect_pdu(l1, 1, 0, b"Fresh Packet with Count 1")
        .expect("Protect packet 2 failed");
    protected2[10] ^= 0x01; // flip bit in ciphertext
    let tamper_err = ue2.unprotect_pdu(l2, 1, 0, &protected2);
    assert!(tamper_err.is_err());
    assert_eq!(ue2.stats_security_failures, 1);
}

#[test]
fn test_anti_replay_sliding_window_protection() {
    let mut sec_ctx = Pc5SecurityContext::derive_new(
        [0x33; 32],
        &[0x11; 16],
        &[0x22; 16],
        1,
        SidelinkCipheringAlgorithm::Nea2,
        SidelinkIntegrityAlgorithm::Nia2,
    );

    // In-order packets
    assert!(sec_ctx.check_anti_replay(1));
    assert!(sec_ctx.check_anti_replay(2));
    assert!(sec_ctx.check_anti_replay(3));

    // Replay of count 2 must fail
    assert!(!sec_ctx.check_anti_replay(2));

    // Advance window forward to count 70
    assert!(sec_ctx.check_anti_replay(70));

    // Packet with count 1 is now outside window (70 - 1 = 69 >= 64)
    assert!(!sec_ctx.check_anti_replay(1));

    // Packet with count 68 is inside window and not yet seen
    assert!(sec_ctx.check_anti_replay(68));

    // Replay of count 68 must fail
    assert!(!sec_ctx.check_anti_replay(68));
}

#[test]
fn test_keepalive_heartbeat_and_timeout_teardown() {
    let shared_root_key = [0x77; 32];
    let mut ue1 = Pc5sEngine::new(
        100,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea0],
        vec![SidelinkIntegrityAlgorithm::Nia0],
    );
    let mut ue2 = Pc5sEngine::new(
        200,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea0],
        vec![SidelinkIntegrityAlgorithm::Nia0],
    );

    let (l1, dcr) = ue1.initiate_link(200, 1, vec![], [1; 16], 0);
    let (l2, dsmc) = ue2.handle_direct_comm_request(&dcr, [2; 16], 10).unwrap();
    let comp = ue1.handle_security_mode_command(l1, &dsmc, 20).unwrap();
    let _dca = ue2.handle_security_mode_complete(l2, &comp, 30).unwrap();

    let mut current_time = 30 + DEFAULT_T4111_KEEPALIVE_MS;

    // Tick 1: Keepalive due
    let outgoing = ue1.tick_timers(current_time);
    assert_eq!(outgoing.len(), 1);
    let (target_lid, ka_msg) = &outgoing[0];
    assert_eq!(*target_lid, l1);

    // UE-2 acks
    match ka_msg {
        Pc5sMessage::DirectLinkKeepalive { seq_num, .. } => {
            let ack = ue2.handle_keepalive(l2, *seq_num, current_time).unwrap();
            match ack {
                Pc5sMessage::DirectLinkKeepaliveAck { seq_num, .. } => {
                    ue1.handle_keepalive_ack(l1, seq_num, current_time);
                    assert_eq!(ue1.stats_keepalives_acked, 1);
                }
                _ => panic!("Expected KeepaliveAck"),
            }
        }
        _ => panic!("Expected Keepalive"),
    }

    // Now simulate heartbeat failure by advancing time without answering pings
    current_time += DEFAULT_T4111_KEEPALIVE_MS + 100;
    for _ in 0..MAX_PC5S_RETRANSMISSIONS {
        let _ = ue1.tick_timers(current_time);
        current_time += DEFAULT_T4112_TIMEOUT_MS + 50;
    }

    // Next tick should trigger link release due to keepalive timeout
    let teardown = ue1.tick_timers(current_time);
    assert_eq!(teardown.len(), 1);
    match &teardown[0].1 {
        Pc5sMessage::DirectLinkReleaseRequest { cause, .. } => {
            assert_eq!(*cause, Pc5sRejectCause::KeepaliveTimeout);
        }
        _ => panic!("Expected DirectLinkReleaseRequest"),
    }
    assert_eq!(ue1.links[&l1].state, Pc5sLinkState::DirectCommReleasing);
}

#[test]
fn test_security_capabilities_mismatch_rejection() {
    let shared_root_key = [0x88; 32];
    let mut ue1 = Pc5sEngine::new(
        1,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea1],
        vec![SidelinkIntegrityAlgorithm::Nia1],
    );
    // UE-2 only supports Nea2 / Nia2 (disjoint)
    let mut ue2 = Pc5sEngine::new(
        2,
        shared_root_key,
        vec![SidelinkCipheringAlgorithm::Nea2],
        vec![SidelinkIntegrityAlgorithm::Nia2],
    );

    let (_l1, dcr) = ue1.initiate_link(2, 1, vec![], [1; 16], 0);
    let result = ue2.handle_direct_comm_request(&dcr, [2; 16], 10);
    assert!(result.is_err());
    match result.unwrap_err() {
        Pc5sMessage::DirectCommunicationReject { cause, .. } => {
            assert_eq!(cause, Pc5sRejectCause::SecurityCapabilitiesMismatch);
        }
        _ => panic!("Expected DirectCommunicationReject"),
    }
}
