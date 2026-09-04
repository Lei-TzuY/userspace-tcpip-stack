//! Integration tests for the 5G UPIP negotiation/state model.
//!
//! The crate currently executes only NIA0. NIA1/NIA2/NIA3 are negotiation
//! identifiers and must fail closed until conformant implementations exist.

use toy_tcpip::upip_5g::*;

#[test]
fn unsupported_nia_algorithms_fail_closed_without_installing_state() {
    for algorithm in [
        UpIntegrityAlgorithm::Nia1Snow3G,
        UpIntegrityAlgorithm::Nia2AesCmac,
        UpIntegrityAlgorithm::Nia3Zuc,
    ] {
        let mut upip = UpipEngine::new("upip-unsupported");
        let result = upip.create_security_context(
            "session",
            [0x5a; 16],
            algorithm,
            UpIntegrityPolicy::Required,
            MaxDataRatePerUe::FullRate,
            1,
        );

        assert_eq!(
            result,
            Err(UpipError::UnsupportedIntegrityAlgorithm { algorithm })
        );
        assert!(upip.contexts.is_empty());
    }
}

#[test]
fn nia0_cannot_satisfy_required_integrity() {
    let mut upip = UpipEngine::new("upip-required");

    let result = upip.create_security_context(
        "session",
        [0; 16],
        UpIntegrityAlgorithm::Nia0Null,
        UpIntegrityPolicy::Required,
        MaxDataRatePerUe::FullRate,
        1,
    );

    assert_eq!(result, Err(UpipError::IntegrityProtectionUnavailable));
    assert!(upip.contexts.is_empty());
}

#[test]
fn nia0_not_needed_is_explicit_pass_through() {
    let mut upip = UpipEngine::new("upip-null");
    upip.create_security_context(
        "session",
        [0; 16],
        UpIntegrityAlgorithm::Nia0Null,
        UpIntegrityPolicy::NotNeeded,
        MaxDataRatePerUe::FullRate,
        1,
    )
    .unwrap();

    let payload = b"unprotected payload";
    assert_eq!(
        upip.protect_downlink_packet("session", payload).unwrap(),
        payload
    );
    assert_eq!(
        upip.verify_uplink_packet("session", payload).unwrap(),
        payload
    );

    let ctx = upip.contexts.get("session").unwrap();
    assert_eq!(ctx.packets_protected, 0);
    assert_eq!(ctx.integrity_failures, 0);
}

#[test]
fn nia0_preferred_is_explicit_pass_through() {
    let mut upip = UpipEngine::new("upip-preferred");
    upip.create_security_context(
        "session",
        [0; 16],
        UpIntegrityAlgorithm::Nia0Null,
        UpIntegrityPolicy::Preferred,
        MaxDataRatePerUe::Rate64Kbps,
        31,
    )
    .unwrap();

    let payload = [0, 1, 2, 3, 4, 5, 255];
    assert_eq!(
        upip.protect_downlink_packet("session", &payload).unwrap(),
        payload
    );
    assert_eq!(
        upip.verify_uplink_packet("session", &payload).unwrap(),
        payload
    );
}

#[test]
fn directly_injected_unsupported_context_still_fails_closed() {
    let mut upip = UpipEngine::new("upip-forged");
    upip.contexts.insert(
        "session".to_string(),
        UpSecurityContext {
            session_id: "session".to_string(),
            k_up_int: [0x11; 16],
            algorithm: UpIntegrityAlgorithm::Nia2AesCmac,
            policy: UpIntegrityPolicy::Required,
            max_rate: MaxDataRatePerUe::FullRate,
            bearer_id: 1,
            uplink_count: 0,
            downlink_count: 0,
            replay_window_bottom: 0,
            replay_window_size: 128,
            packets_protected: 0,
            integrity_failures: 0,
        },
    );

    let expected = Err(UpipError::UnsupportedIntegrityAlgorithm {
        algorithm: UpIntegrityAlgorithm::Nia2AesCmac,
    });
    assert_eq!(
        upip.protect_downlink_packet("session", b"payload"),
        expected
    );
    assert_eq!(upip.verify_uplink_packet("session", b"payload"), expected);
}

#[test]
fn session_lifecycle_and_missing_session_errors_remain_deterministic() {
    let mut upip = UpipEngine::new("upip-lifecycle");

    assert_eq!(
        upip.protect_downlink_packet("missing", b"payload"),
        Err(UpipError::SessionNotFound)
    );

    upip.create_security_context(
        "session",
        [0; 16],
        UpIntegrityAlgorithm::Nia0Null,
        UpIntegrityPolicy::NotNeeded,
        MaxDataRatePerUe::FullRate,
        1,
    )
    .unwrap();
    upip.remove_security_context("session").unwrap();

    assert_eq!(
        upip.verify_uplink_packet("session", b"payload"),
        Err(UpipError::SessionNotFound)
    );
}
