//! Integration tests for 3GPP TS 33.501 / TS 23.501 / TS 38.323 5G User Plane Integrity Protection (UPIP).

use toy_tcpip::upip_5g::*;

// ---------------------------------------------------------------------------
// 1. UPIP Protect and Verify Happy Path
// ---------------------------------------------------------------------------

#[test]
fn test_upip_full_rate_mac_i_protect_and_verify_happy_path() {
    let mut upip = UpipEngine::new("upip-core-01");

    let sess_id = "sess-pdu-001";
    let k_up_int = [0x5A; 16];
    let bearer_id = 1;

    upip.create_security_context(
        sess_id,
        k_up_int,
        UpIntegrityAlgorithm::Nia2AesCmac,
        UpIntegrityPolicy::Required,
        MaxDataRatePerUe::FullRate,
        bearer_id,
    );

    // Step 1: Downlink Protection
    let dl_data = b"Critical Bank Transaction Wire Transfer Payload";
    let protected_dl = upip.protect_downlink_packet(sess_id, dl_data).unwrap();

    // 4 bytes MAC-I appended
    assert_eq!(protected_dl.len(), dl_data.len() + 4);
    assert_eq!(&protected_dl[..dl_data.len()], dl_data);

    // Step 2: Uplink Verification
    let ul_data = b"Confirmed User Payment Authorization";
    let expected_maci = compute_mac_i(&k_up_int, 0, bearer_id, true, ul_data);
    let mut ul_packet = ul_data.to_vec();
    ul_packet.extend_from_slice(&expected_maci.to_be_bytes());

    let verified_payload = upip.verify_uplink_packet(sess_id, &ul_packet).unwrap();
    assert_eq!(verified_payload, ul_data);

    let ctx = upip.contexts.get(sess_id).unwrap();
    assert_eq!(ctx.uplink_count, 1);
    assert_eq!(ctx.integrity_failures, 0);
    assert_eq!(ctx.packets_protected, 2);
}

// ---------------------------------------------------------------------------
// 2. Tamper Detection and Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_upip_tamper_detection_and_rejection() {
    let mut upip = UpipEngine::new("upip-core-02");

    let sess_id = "sess-tamper";
    let k_up_int = [0x11; 16];
    let bearer_id = 2;

    upip.create_security_context(
        sess_id,
        k_up_int,
        UpIntegrityAlgorithm::Nia1Snow3G,
        UpIntegrityPolicy::Required,
        MaxDataRatePerUe::FullRate,
        bearer_id,
    );

    let original_data = b"Account balance: $1,000,000";
    let mac_i = compute_mac_i(&k_up_int, 0, bearer_id, true, original_data);
    let mut tampered_pkt = original_data.to_vec();
    tampered_pkt.extend_from_slice(&mac_i.to_be_bytes());

    // Tamper 1 byte in payload ($1 -> $9)
    tampered_pkt[18] = b'9';

    let err = upip.verify_uplink_packet(sess_id, &tampered_pkt);
    match err {
        Err(UpipError::IntegrityVerificationFailed { observed_maci, .. }) => {
            assert_eq!(observed_maci, mac_i);
        }
        _ => panic!("Expected IntegrityVerificationFailed"),
    }

    assert_eq!(upip.contexts.get(sess_id).unwrap().integrity_failures, 1);
}

// ---------------------------------------------------------------------------
// 3. Replay Protection Window Sliding
// ---------------------------------------------------------------------------

#[test]
fn test_upip_replay_protection_window() {
    let mut upip = UpipEngine::new("upip-core-03");

    let sess_id = "sess-replay";
    let k_up_int = [0x33; 16];
    let bearer_id = 3;

    upip.create_security_context(
        sess_id,
        k_up_int,
        UpIntegrityAlgorithm::Nia3Zuc,
        UpIntegrityPolicy::Required,
        MaxDataRatePerUe::FullRate,
        bearer_id,
    );

    // Simulate advancing uplink COUNT past the replay window (size 128)
    let ctx = upip.contexts.get_mut(sess_id).unwrap();
    ctx.uplink_count = 200;
    ctx.replay_window_bottom = 200 - 128; // bottom = 72

    // If an attacker replays a packet when uplink_count was manually set low (e.g. 50 < 72)
    ctx.uplink_count = 50; // below window bottom

    let payload = b"Replayed ancient packet";
    let mut pkt = payload.to_vec();
    pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    let err = upip.verify_uplink_packet(sess_id, &pkt);
    assert_eq!(
        err,
        Err(UpipError::ReplayDetected {
            received_count: 50,
            window_bottom: 72,
        })
    );
}

// ---------------------------------------------------------------------------
// 4. Policy NotNeeded Pass-Through
// ---------------------------------------------------------------------------

#[test]
fn test_upip_policy_not_needed() {
    let mut upip = UpipEngine::new("upip-core-04");

    let sess_id = "sess-pass-thru";
    upip.create_security_context(
        sess_id,
        [0x00; 16],
        UpIntegrityAlgorithm::Nia0Null,
        UpIntegrityPolicy::NotNeeded,
        MaxDataRatePerUe::FullRate,
        1,
    );

    let raw_payload = b"Unprotected Public Web Traffic";
    let dl = upip.protect_downlink_packet(sess_id, raw_payload).unwrap();
    assert_eq!(dl, raw_payload);

    let ul = upip.verify_uplink_packet(sess_id, raw_payload).unwrap();
    assert_eq!(ul, raw_payload);
}

// ---------------------------------------------------------------------------
// 5. Error Handling: Short Packet and Session Not Found
// ---------------------------------------------------------------------------

#[test]
fn test_upip_error_handling() {
    let mut upip = UpipEngine::new("upip-core-05");

    let sess_id = "sess-err";
    upip.create_security_context(
        sess_id,
        [0x99; 16],
        UpIntegrityAlgorithm::Nia2AesCmac,
        UpIntegrityPolicy::Required,
        MaxDataRatePerUe::Rate64Kbps,
        1,
    );

    // Truncated packet (< 4 bytes)
    let err1 = upip.verify_uplink_packet(sess_id, &[0x01, 0x02]);
    assert_eq!(err1, Err(UpipError::PacketTooShortForMaci));

    // Unknown session
    let err2 = upip.protect_downlink_packet("ghost-session", b"test");
    assert_eq!(err2, Err(UpipError::SessionNotFound));

    // Remove session
    upip.remove_security_context(sess_id)
        .expect("Removal failed");
    assert_eq!(
        upip.verify_uplink_packet(sess_id, b"1234"),
        Err(UpipError::SessionNotFound)
    );
}
