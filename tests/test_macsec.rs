//! Integration tests for IEEE 802.1AE MACsec

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::macsec::{
    ConfidentialityMode, MacsecCipherSuite, MacsecProtectResult, MacsecSecY, MacsecValidateResult,
    SecureAssociation, SecureChannelId, ETHERTYPE_MACSEC,
};

#[test]
fn test_macsec_multi_sa_key_rotation() {
    let local_sci = SecureChannelId::new(
        MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
        1,
    );
    let remote_sci = SecureChannelId::new(
        MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        1,
    );

    let sak_0 = vec![0x01u8; 16];
    let sak_1 = vec![0x02u8; 16];

    // Sender
    let mut sender = MacsecSecY::new(local_sci, ConfidentialityMode::EncryptAndAuthenticate, true);
    sender.install_tx_sa(SecureAssociation::new(0, sak_0.clone(), MacsecCipherSuite::GcmAes128));
    sender.install_tx_sa(SecureAssociation::new(1, sak_1.clone(), MacsecCipherSuite::GcmAes128));

    // Receiver
    let mut receiver = MacsecSecY::new(remote_sci, ConfidentialityMode::EncryptAndAuthenticate, true);
    receiver.add_receive_sc(local_sci);
    receiver
        .install_rx_sa(local_sci, SecureAssociation::new(0, sak_0.clone(), MacsecCipherSuite::GcmAes128))
        .unwrap();
    receiver
        .install_rx_sa(local_sci, SecureAssociation::new(1, sak_1.clone(), MacsecCipherSuite::GcmAes128))
        .unwrap();

    let dst = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let src = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Send 3 frames with SA AN=0
    for i in 0..3 {
        let payload = format!("Frame {} with SA 0", i);
        let (frame, result) = sender
            .protect_frame(&dst, &src, 0x0800, payload.as_bytes())
            .unwrap();

        match result {
            MacsecProtectResult::Protected { an, pn, encrypted, .. } => {
                assert_eq!(an, 0);
                assert_eq!(pn, (i + 1) as u64);
                assert!(encrypted);
            }
            _ => panic!("Expected Protected"),
        }

        let vresult = receiver.validate_frame(&frame);
        match vresult {
            MacsecValidateResult::Valid { an, pn, .. } => {
                assert_eq!(an, 0);
                assert_eq!(pn, (i + 1) as u64);
            }
            MacsecValidateResult::Invalid { reason } => {
                panic!("Validation failed: {:?}", reason);
            }
        }
    }

    // Key rotation: switch to SA AN=1
    sender.tx_sc.set_encoding_sa(1).unwrap();

    let (frame_new_sa, result_new) = sender
        .protect_frame(&dst, &src, 0x0800, b"Frame with SA 1")
        .unwrap();

    match result_new {
        MacsecProtectResult::Protected { an, pn, .. } => {
            assert_eq!(an, 1);
            assert_eq!(pn, 1); // PN restarts for new SA
        }
        _ => panic!("Expected Protected"),
    }

    let vresult_new = receiver.validate_frame(&frame_new_sa);
    match vresult_new {
        MacsecValidateResult::Valid { an, .. } => {
            assert_eq!(an, 1);
        }
        MacsecValidateResult::Invalid { reason } => {
            panic!("Validation failed after key rotation: {:?}", reason);
        }
    }

    assert_eq!(sender.stats_protected, 4);
    assert_eq!(receiver.stats_validated, 4);
    assert_eq!(receiver.stats_invalid, 0);
}

#[test]
fn test_macsec_integrity_only_mode() {
    let local_sci = SecureChannelId::new(
        MacAddress::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]),
        1,
    );
    let remote_sci = SecureChannelId::new(
        MacAddress::new([0x60, 0x50, 0x40, 0x30, 0x20, 0x10]),
        1,
    );

    let sak = vec![0xABu8; 16];

    // Integrity-only mode (no encryption)
    let mut sender = MacsecSecY::new(local_sci, ConfidentialityMode::IntegrityOnly, true);
    sender.install_tx_sa(SecureAssociation::new(0, sak.clone(), MacsecCipherSuite::GcmAes128));

    let mut receiver = MacsecSecY::new(remote_sci, ConfidentialityMode::IntegrityOnly, true);
    receiver.add_receive_sc(local_sci);
    receiver
        .install_rx_sa(local_sci, SecureAssociation::new(0, sak.clone(), MacsecCipherSuite::GcmAes128))
        .unwrap();

    let dst = MacAddress::new([0x60, 0x50, 0x40, 0x30, 0x20, 0x10]);
    let src = MacAddress::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);

    let (frame, result) = sender
        .protect_frame(&dst, &src, 0x0800, b"Integrity-only data")
        .unwrap();

    match result {
        MacsecProtectResult::Protected { encrypted, .. } => {
            assert!(!encrypted, "Should not be encrypted in integrity-only mode");
        }
        _ => panic!("Expected Protected"),
    }

    // Verify EtherType is MACsec
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    assert_eq!(ethertype, ETHERTYPE_MACSEC);

    let vresult = receiver.validate_frame(&frame);
    match vresult {
        MacsecValidateResult::Valid { was_encrypted, .. } => {
            assert!(!was_encrypted);
        }
        MacsecValidateResult::Invalid { reason } => {
            panic!("Validation failed: {:?}", reason);
        }
    }
}
