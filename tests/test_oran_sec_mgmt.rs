//! Integration tests for O-RAN WG4 Open Fronthaul M-Plane Security Management & Certificate / TLS Lifecycle Engine
//!
//! Conforms to O-RAN.WG4.MP.0 Section 6, o-ran-usermgmt.yang, o-ran-certificates.yang, and RFC 8341.

use toy_tcpip::oran_sec_mgmt::{
    AccessPermission, CertificateType, Cmpv2Message, Cmpv2MessageType, Cmpv2Status,
    OranSecurityManager, SecurityEventSeverity, UserRole, X509CertRecord,
};

#[test]
fn test_user_management_authentication_and_lockout() {
    let mut mgr = OranSecurityManager::new();
    let now = 1_700_000_000u64;

    // 1. Add operator user
    assert!(
        mgr.add_user("operator1", "SecurePass@123", UserRole::Operator, 42)
            .is_ok()
    );

    // 2. Successful authentication
    let auth_result = mgr.authenticate_user("operator1", "SecurePass@123", "192.168.1.50", now);
    assert_eq!(auth_result, Ok(UserRole::Operator));

    // 3. Four consecutive failed password attempts (max allowed is 5)
    for _ in 0..4 {
        let res = mgr.authenticate_user("operator1", "WrongPass", "192.168.1.50", now);
        assert!(res.is_err());
    }

    // 4. Fifth failed attempt triggers account lockout
    let lock_res = mgr.authenticate_user("operator1", "WrongPass", "192.168.1.50", now);
    assert_eq!(lock_res, Err("Password incorrect; account locked out"));

    // 5. Subsequent attempt even with correct password is rejected during lockout window
    let during_lock =
        mgr.authenticate_user("operator1", "SecurePass@123", "192.168.1.50", now + 100);
    assert_eq!(
        during_lock,
        Err("Account is locked due to excessive failed attempts")
    );

    // 6. Advance time past lockout duration (900 seconds) -> account unlocks automatically
    let after_lock =
        mgr.authenticate_user("operator1", "SecurePass@123", "192.168.1.50", now + 905);
    assert_eq!(after_lock, Ok(UserRole::Operator));
}

#[test]
fn test_nacm_role_based_access_control() {
    let mgr = OranSecurityManager::new();

    // 1. SuperUser: full administrative access
    assert!(mgr.check_nacm_access(
        UserRole::SuperUser,
        "/o-ran-usermgmt/users",
        AccessPermission::ReadWrite
    ));
    assert!(mgr.check_nacm_access(
        UserRole::SuperUser,
        "/o-ran-certificates/cert",
        AccessPermission::Execute
    ));

    // 2. Operator: allowed configuration on U-Plane / Delay / ALD, but NOT security credentials
    assert!(mgr.check_nacm_access(
        UserRole::Operator,
        "/o-ran-uplane-conf/tx-carrier",
        AccessPermission::ReadWrite
    ));
    assert!(mgr.check_nacm_access(
        UserRole::Operator,
        "/o-ran-usermgmt/users",
        AccessPermission::Read
    ));
    assert!(!mgr.check_nacm_access(
        UserRole::Operator,
        "/o-ran-usermgmt/users",
        AccessPermission::ReadWrite
    ));
    assert!(!mgr.check_nacm_access(
        UserRole::Operator,
        "/o-ran-certificates/install",
        AccessPermission::ReadWrite
    ));

    // 3. Installer: read-only on inventory, execute on self-tests, no configuration write
    assert!(mgr.check_nacm_access(
        UserRole::Installer,
        "/o-ran-hardware/status",
        AccessPermission::Read
    ));
    assert!(mgr.check_nacm_access(
        UserRole::Installer,
        "/o-ran-diagnostics:self-test",
        AccessPermission::Execute
    ));
    assert!(!mgr.check_nacm_access(
        UserRole::Installer,
        "/o-ran-uplane-conf/tx-carrier",
        AccessPermission::ReadWrite
    ));

    // 4. Auditor: strict read-only access everywhere
    assert!(mgr.check_nacm_access(
        UserRole::Auditor,
        "/o-ran-fm/alarms",
        AccessPermission::Read
    ));
    assert!(!mgr.check_nacm_access(
        UserRole::Auditor,
        "/o-ran-fm/alarms",
        AccessPermission::ReadWrite
    ));
    assert!(!mgr.check_nacm_access(
        UserRole::Auditor,
        "/o-ran-diagnostics:self-test",
        AccessPermission::Execute
    ));
}

#[test]
fn test_x509_certificate_lifecycle_and_expiry_warning() {
    let mut mgr = OranSecurityManager::new();
    let now = 1_700_000_000u64;

    // 1. Install valid Root CA certificate
    let root_ca = X509CertRecord {
        cert_id: "root-ca-01".to_string(),
        subject: "CN=Telecom-Root-CA,O=Telco,C=US".to_string(),
        issuer: "CN=Telecom-Root-CA,O=Telco,C=US".to_string(),
        cert_type: CertificateType::TrustAnchor,
        serial_number: 10001,
        not_before_epoch: now - 86400 * 365,
        not_after_epoch: now + 86400 * 3650, // 10 years
        is_revoked: false,
        fingerprint_sha256: [0x11; 32],
    };
    mgr.install_certificate(root_ca);
    assert!(mgr.validate_certificate("root-ca-01", now).is_ok());

    // 2. Install O-RU device identity cert expiring in 20 days (within 30-day warning threshold)
    let device_cert = X509CertRecord {
        cert_id: "oru-id-01".to_string(),
        subject: "CN=ORU-SERIAL-9988,O=Telco,C=US".to_string(),
        issuer: "CN=Telecom-Root-CA,O=Telco,C=US".to_string(),
        cert_type: CertificateType::DeviceIdentity,
        serial_number: 20002,
        not_before_epoch: now - 86400 * 345,
        not_after_epoch: now + 86400 * 20, // 20 days remaining
        is_revoked: false,
        fingerprint_sha256: [0x22; 32],
    };
    mgr.install_certificate(device_cert);
    assert!(mgr.validate_certificate("oru-id-01", now).is_ok());

    // 3. Install already expired cert
    let expired_cert = X509CertRecord {
        cert_id: "tls-old-01".to_string(),
        subject: "CN=ORU-TLS-OLD,O=Telco,C=US".to_string(),
        issuer: "CN=Telecom-Root-CA,O=Telco,C=US".to_string(),
        cert_type: CertificateType::TlsServer,
        serial_number: 30003,
        not_before_epoch: now - 86400 * 400,
        not_after_epoch: now - 86400 * 5, // Expired 5 days ago
        is_revoked: false,
        fingerprint_sha256: [0x33; 32],
    };
    mgr.install_certificate(expired_cert);
    assert_eq!(
        mgr.validate_certificate("tls-old-01", now),
        Err("Certificate has expired")
    );

    // 4. Revoke root-ca-01
    assert!(
        mgr.revoke_certificate("root-ca-01", "192.168.1.1", now)
            .is_ok()
    );
    assert_eq!(
        mgr.validate_certificate("root-ca-01", now),
        Err("Certificate is revoked")
    );

    // 5. Audit summary verification
    let summary = mgr.audit_summary(now);
    assert_eq!(summary.total_certificates, 3);
    assert_eq!(summary.revoked_certificates, 1);
    assert_eq!(summary.expiring_certificates, 1); // oru-id-01 has 20 days <= 30
}

#[test]
fn test_cmpv2_certificate_enrollment_and_renewal() {
    let mut mgr = OranSecurityManager::new();
    let now = 1_700_000_000u64;

    // 1. Initialization Request (IR)
    let ir_msg = Cmpv2Message {
        transaction_id: 12345,
        msg_type: Cmpv2MessageType::InitializationRequest,
        status: Cmpv2Status::Accepted,
        sender_nonce: 9999,
        recipient_nonce: 0,
        cert_data: Some(vec![0xAA, 0xBB, 0xCC]),
    };

    // Serialize and parse back
    let wire = ir_msg.serialize();
    let parsed = Cmpv2Message::parse(&wire).expect("Should parse valid CMPv2 message");
    assert_eq!(parsed.transaction_id, 12345);
    assert_eq!(parsed.msg_type, Cmpv2MessageType::InitializationRequest);

    // Process IR request
    let ip_resp = mgr
        .process_cmpv2_request(&ir_msg, now)
        .expect("CMPv2 IR processing should succeed");
    assert_eq!(ip_resp.transaction_id, 12345);
    assert_eq!(ip_resp.msg_type, Cmpv2MessageType::CertificationResponse);
    assert_eq!(ip_resp.status, Cmpv2Status::Accepted);
    assert_eq!(ip_resp.recipient_nonce, 9999);
    assert!(ip_resp.cert_data.is_some());

    // 2. Key Update Request (KUR)
    let kur_msg = Cmpv2Message {
        transaction_id: 54321,
        msg_type: Cmpv2MessageType::KeyUpdateRequest,
        status: Cmpv2Status::Accepted,
        sender_nonce: 8888,
        recipient_nonce: 7777,
        cert_data: None,
    };

    let kup_resp = mgr
        .process_cmpv2_request(&kur_msg, now)
        .expect("CMPv2 KUR processing should succeed");
    assert_eq!(kup_resp.transaction_id, 54321);
    assert_eq!(kup_resp.msg_type, Cmpv2MessageType::KeyUpdateResponse);
    assert_eq!(kup_resp.status, Cmpv2Status::Accepted);
}

#[test]
fn test_security_audit_logging_and_alarms() {
    let mut mgr = OranSecurityManager::new();
    let now = 1_700_000_000u64;

    mgr.add_user("testuser", "Pass@999", UserRole::Operator, 123)
        .unwrap();

    // Trigger multiple failed logins to cause Critical audit event
    for _ in 0..5 {
        let _ = mgr.authenticate_user("testuser", "WrongPassword", "10.0.0.15", now);
    }

    let summary = mgr.audit_summary(now);
    assert_eq!(summary.locked_users, 1);
    assert!(summary.critical_events_count >= 1);
    assert!(summary.total_audit_events >= 5);

    // Verify last audit entry is Critical lockout
    let logs = mgr.audit_log();
    let last_log = logs.last().expect("Audit log must contain entries");
    assert_eq!(last_log.severity, SecurityEventSeverity::Critical);
    assert_eq!(last_log.username, Some("testuser".to_string()));
    assert_eq!(last_log.source_ip, "10.0.0.15");
}
