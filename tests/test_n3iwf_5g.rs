//! Integration tests for 3GPP TS 24.502 / TS 23.501 / TS 33.501 5G Non-3GPP Interworking Function (N3IWF) Engine.

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::n3iwf_5g::*;

// ---------------------------------------------------------------------------
// 1. IKEv2 / EAP-5G Handshake & Authentication Key Derivation
// ---------------------------------------------------------------------------

#[test]
fn test_n3iwf_ike_sa_init_and_authentication_handshake() {
    let n3iwf_ip = Ipv4Address::new(172, 16, 0, 1);
    let mut n3iwf = N3iwfEngine::new(n3iwf_ip);

    let ue_wifi_ip = Ipv4Address::new(192, 168, 1, 50);
    let ue_id = n3iwf.handle_ike_sa_init(ue_wifi_ip);
    assert!(ue_id > 0);

    // AMF supplies derived K_N3IWF and internal virtual IP
    let k_n3iwf = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
        0x2e, 0x2f,
    ];
    let virtual_ip = Ipv4Address::new(10, 45, 0, 2);

    let (spi_in, spi_out) = n3iwf
        .complete_authentication_and_establish_sa(ue_wifi_ip, k_n3iwf, virtual_ip)
        .expect("Authentication failed");

    assert_ne!(spi_in, spi_out);

    let ctx = n3iwf.ue_contexts_by_ip.get(&ue_wifi_ip).unwrap();
    assert!(ctx.authenticated);
    assert_eq!(ctx.assigned_virtual_ip, Some(virtual_ip));
    assert!(ctx.child_sas.contains_key(&spi_in));
}

// ---------------------------------------------------------------------------
// 2. N2 PDU Session Resource Setup
// ---------------------------------------------------------------------------

#[test]
fn test_n3iwf_pdu_session_setup_resource_allocation() {
    let mut n3iwf = N3iwfEngine::new(Ipv4Address::new(172, 16, 0, 1));
    let ue_wifi_ip = Ipv4Address::new(192, 168, 1, 60);

    n3iwf.handle_ike_sa_init(ue_wifi_ip);
    n3iwf
        .complete_authentication_and_establish_sa(
            ue_wifi_ip,
            [0xaa; 32],
            Ipv4Address::new(10, 45, 0, 3),
        )
        .unwrap();

    let upf_ip = Ipv4Address::new(10, 100, 0, 1);
    let pdu_session = n3iwf
        .setup_pdu_session(ue_wifi_ip, 1, 9, 0x2001_0001, upf_ip)
        .expect("PDU session setup failed");

    assert_eq!(pdu_session.pdu_session_id, 1);
    assert_eq!(pdu_session.qfi, 9);
    assert_eq!(pdu_session.upf_teid, 0x2001_0001);
    assert!(pdu_session.n3_dl_teid > 0);
}

// ---------------------------------------------------------------------------
// 3. User Plane Uplink Translation (IPsec ESP -> N3 GTP-U)
// ---------------------------------------------------------------------------

#[test]
fn test_n3iwf_uplink_esp_to_gtpu_translation() {
    let mut n3iwf = N3iwfEngine::new(Ipv4Address::new(172, 16, 0, 1));
    let ue_wifi_ip = Ipv4Address::new(192, 168, 1, 70);

    n3iwf.handle_ike_sa_init(ue_wifi_ip);
    n3iwf
        .complete_authentication_and_establish_sa(
            ue_wifi_ip,
            [0x55; 32],
            Ipv4Address::new(10, 45, 0, 4),
        )
        .unwrap();

    let _pdu = n3iwf
        .setup_pdu_session(ue_wifi_ip, 1, 9, 0x3001, Ipv4Address::new(10, 100, 0, 2))
        .unwrap();

    let test_data = b"HTTP/1.1 200 OK - Untrusted WiFi Upload";
    let ul_esp = n3iwf
        .encrypt_uplink_esp(ue_wifi_ip, 1, 1, test_data)
        .expect("Encryption failed");

    // N3IWF translates uplink ESP -> GTP-U to UPF
    let translated_gtpu = n3iwf
        .uplink_esp_to_gtpu(&ul_esp)
        .expect("Uplink translation failed");

    assert_eq!(translated_gtpu.teid, 0x3001); // UPF TEID
    assert_eq!(translated_gtpu.qfi, 9);
    assert_eq!(translated_gtpu.payload, test_data);
}

// ---------------------------------------------------------------------------
// 4. User Plane Downlink Translation (N3 GTP-U -> IPsec ESP)
// ---------------------------------------------------------------------------

#[test]
fn test_n3iwf_downlink_gtpu_to_esp_translation() {
    let mut n3iwf = N3iwfEngine::new(Ipv4Address::new(172, 16, 0, 1));
    let ue_wifi_ip = Ipv4Address::new(192, 168, 1, 80);

    n3iwf.handle_ike_sa_init(ue_wifi_ip);
    n3iwf
        .complete_authentication_and_establish_sa(
            ue_wifi_ip,
            [0x77; 32],
            Ipv4Address::new(10, 45, 0, 5),
        )
        .unwrap();

    let pdu = n3iwf
        .setup_pdu_session(ue_wifi_ip, 1, 5, 0x4001, Ipv4Address::new(10, 100, 0, 3))
        .unwrap();

    let app_payload = b"VoNR Downlink Audio Frame";
    let gtpu = GtpuPacket {
        teid: pdu.n3_dl_teid,
        qfi: 5,
        payload: app_payload.to_vec(),
    };

    let esp = n3iwf
        .downlink_gtpu_to_esp(&gtpu, 100)
        .expect("Downlink translation failed");

    assert_eq!(esp.spi, pdu.child_spi_out);
    assert_eq!(esp.seq_num, 100);
    assert_ne!(esp.encrypted_payload, app_payload); // Ciphertext check
}

// ---------------------------------------------------------------------------
// 5. Tampered ESP Integrity Check Value (ICV) Failure
// ---------------------------------------------------------------------------

#[test]
fn test_n3iwf_tampered_esp_icv_failure() {
    let mut n3iwf = N3iwfEngine::new(Ipv4Address::new(172, 16, 0, 1));
    let ue_wifi_ip = Ipv4Address::new(192, 168, 1, 90);

    n3iwf.handle_ike_sa_init(ue_wifi_ip);
    n3iwf
        .complete_authentication_and_establish_sa(
            ue_wifi_ip,
            [0x88; 32],
            Ipv4Address::new(10, 45, 0, 6),
        )
        .unwrap();

    let pdu = n3iwf
        .setup_pdu_session(ue_wifi_ip, 1, 9, 0x5001, Ipv4Address::new(10, 100, 0, 4))
        .unwrap();

    let esp = EspPacket {
        spi: pdu.child_spi_in,
        seq_num: 1,
        encrypted_payload: b"encrypted-data".to_vec(),
        icv: [0u8; 16], // Invalid ICV
    };

    // Adversary injects invalid packet
    let res = n3iwf.uplink_esp_to_gtpu(&esp);
    assert_eq!(res, Err(N3iwfError::IntegrityCheckFailed));
}
