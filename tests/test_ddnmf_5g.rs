//! Integration tests for 3GPP TS 29.579 / TS 23.304 5G-DDNMF (Direct Discovery Name Management Function).

use toy_tcpip::ddnmf_5g::*;

// ---------------------------------------------------------------------------
// 1. Announce & Match Report Happy Path (PC5 ProSe Discovery)
// ---------------------------------------------------------------------------

#[test]
fn test_ddnmf_announce_and_match_report_happy_path() {
    let mut ddnmf = DdnmfEngine::new("ddnmf-core-01", "208-95");
    let app_id = "org.publicsafety.fire.rescue";

    let announcer = "imsi-208950000000001";
    let monitor = "imsi-208950000000002";

    // Grant permissions
    ddnmf.grant_permission(announcer, app_id);
    ddnmf.grant_permission(monitor, app_id);

    // 1. Announcer requests ProSe App Code (valid for 3600s)
    let pac = ddnmf
        .authorize_announce(announcer, app_id, 3600, 1000)
        .expect("Announce authorization failed");

    assert_eq!(pac.plmn_id, "208-95");
    assert_eq!(pac.app_prefix, "ORG");
    let pac_hex = pac.to_hex_string();
    assert!(pac_hex.starts_with("PAC-20895-ORG-"));

    // 2. Monitor requests monitoring authorization
    ddnmf
        .authorize_monitor(monitor, app_id, 3600, 1000)
        .expect("Monitor authorization failed");

    // 3. Monitor overhears PAC on PC5 Sidelink and submits Match Report at t = 1500s
    let match_res = ddnmf
        .match_report(monitor, &pac_hex, 1500)
        .expect("Match report failed");

    assert_eq!(match_res.prose_app_id, app_id);
    assert_eq!(match_res.announcing_supi, announcer);
    assert_eq!(match_res.validity_time_remaining_s, 3100); // 3600 - (1500 - 1000) = 3100
}

// ---------------------------------------------------------------------------
// 2. Unauthorized Announcer Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_ddnmf_unauthorized_announcer_rejection() {
    let mut ddnmf = DdnmfEngine::new("ddnmf-core-02", "208-95");
    let err = ddnmf.authorize_announce("imsi-rogue-user", "com.banking.private", 1000, 100);
    assert_eq!(err, Err(DdnmfError::UnauthorizedAppId));
}

// ---------------------------------------------------------------------------
// 3. Unauthorized Monitor Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_ddnmf_unauthorized_monitor_rejection() {
    let mut ddnmf = DdnmfEngine::new("ddnmf-core-03", "208-95");
    let app_id = "com.ride.sharing.fleet";
    let announcer = "imsi-driver-01";
    let rogue_monitor = "imsi-snoop-02";

    ddnmf.grant_permission(announcer, app_id);
    let pac = ddnmf
        .authorize_announce(announcer, app_id, 3600, 1000)
        .unwrap();
    let pac_hex = pac.to_hex_string();

    // Rogue monitor did not receive monitor authorization
    let err = ddnmf.match_report(rogue_monitor, &pac_hex, 1100);
    assert_eq!(err, Err(DdnmfError::UnauthorizedMonitor));
}

// ---------------------------------------------------------------------------
// 4. Expired Code Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_ddnmf_expired_code_rejection() {
    let mut ddnmf = DdnmfEngine::new("ddnmf-core-04", "208-95");
    let app_id = "org.temp.chat";
    let announcer = "imsi-user-01";
    let monitor = "imsi-user-02";

    ddnmf.grant_permission(announcer, app_id);
    ddnmf.grant_permission(monitor, app_id);

    // Code valid for only 300s (expires at t = 1300)
    let pac = ddnmf
        .authorize_announce(announcer, app_id, 300, 1000)
        .unwrap();
    ddnmf
        .authorize_monitor(monitor, app_id, 3600, 1000)
        .unwrap();

    // Query at t = 1350s (expired)
    let err = ddnmf.match_report(monitor, &pac.to_hex_string(), 1350);
    assert_eq!(err, Err(DdnmfError::ProSeCodeExpired));
}

// ---------------------------------------------------------------------------
// 5. Announcement Revocation Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_ddnmf_revocation_lifecycle() {
    let mut ddnmf = DdnmfEngine::new("ddnmf-core-05", "208-95");
    let app_id = "org.ambulance.tracking";
    let announcer = "imsi-medic-01";
    let monitor = "imsi-hospital-01";

    ddnmf.grant_permission(announcer, app_id);
    ddnmf.grant_permission(monitor, app_id);

    let pac = ddnmf
        .authorize_announce(announcer, app_id, 3600, 1000)
        .unwrap();
    let pac_hex = pac.to_hex_string();
    ddnmf
        .authorize_monitor(monitor, app_id, 3600, 1000)
        .unwrap();

    // Immediately revoke
    ddnmf
        .revoke_announcement(&pac_hex)
        .expect("Revocation failed");

    // Subsequent match report must fail
    let err = ddnmf.match_report(monitor, &pac_hex, 1050);
    assert_eq!(err, Err(DdnmfError::ProSeCodeNotFound));
}
