//! Integration tests for `sdap_5g` — 3GPP TS 37.324 5G NR SDAP Protocol Engine.

use toy_tcpip::sdap_5g::*;

// ---------------------------------------------------------------------------
// 1. QoS Flow → DRB mapping with default DRB fallback
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_qos_flow_mapping_and_default_drb_fallback() {
    let mut sdap = SdapEntity::new(1, SdapRole::Gnb, /* default_drb */ 5);

    // Initially no explicit mappings — everything goes to default DRB 5
    assert_eq!(sdap.resolve_drb(9), 5);
    assert_eq!(sdap.resolve_drb(0), 5);
    assert_eq!(sdap.resolve_drb(63), 5);

    // Configure explicit mappings
    sdap.configure_mapping(9, 3); // QFI 9 → DRB 3
    sdap.configure_mapping(15, 7); // QFI 15 → DRB 7

    assert_eq!(sdap.resolve_drb(9), 3);
    assert_eq!(sdap.resolve_drb(15), 7);
    // Unmapped QFI still goes to default
    assert_eq!(sdap.resolve_drb(20), 5);

    // Verify mapping table
    let table = sdap.get_mapping_table();
    assert_eq!(table.len(), 2);
    assert_eq!(table[0].qfi, 9);
    assert_eq!(table[0].drb_id, 3);
    assert_eq!(table[0].origin, MappingOrigin::RrcConfigured);
    assert_eq!(table[1].qfi, 15);
    assert_eq!(table[1].drb_id, 7);
}

// ---------------------------------------------------------------------------
// 2. Build & receive SDAP Data PDU roundtrip (DL with header)
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_dl_data_pdu_build_receive_roundtrip() {
    // gNB side: build a DL PDU
    let gnb = SdapEntity::new(1, SdapRole::Gnb, 5);
    let ip_packet = vec![0x45, 0x00, 0x00, 0x3C, 0xAA, 0xBB, 0xCC, 0xDD];

    let (drb_id, pdu_bytes) = gnb.build_pdu(9, &ip_packet, SdapDirection::Downlink, false);
    assert_eq!(drb_id, 5); // QFI 9 not mapped → default DRB 5

    // Verify SDAP header in wire bytes
    assert_eq!(pdu_bytes.len(), 1 + ip_packet.len());
    let hdr = SdapHeader::decode(pdu_bytes[0]);
    assert!(hdr.is_data);
    assert!(!hdr.rqi);
    assert_eq!(hdr.qfi, 9);
    assert_eq!(&pdu_bytes[1..], &ip_packet);

    // UE side: receive the DL PDU
    let mut ue = SdapEntity::new(1, SdapRole::Ue, 5);
    let result = ue.receive_pdu(5, &pdu_bytes, SdapDirection::Downlink);
    assert!(result.is_some());
    let (qfi, sdu) = result.unwrap();
    assert_eq!(qfi, 9);
    assert_eq!(sdu, ip_packet);
    assert_eq!(ue.delivered_sdus.len(), 1);
}

// ---------------------------------------------------------------------------
// 3. Reflective QoS mapping (DL RQI=1 triggers UE UL mapping)
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_reflective_qos_mapping() {
    let mut gnb = SdapEntity::new(1, SdapRole::Gnb, 5);
    gnb.enable_reflective_qos();
    gnb.configure_mapping(20, 8); // QFI 20 → DRB 8

    // Build DL PDU with RQI=1
    let ip_payload = vec![0x60, 0x00, 0x00, 0x00]; // IPv6 header start
    let (drb_id, pdu_bytes) = gnb.build_pdu(
        20,
        &ip_payload,
        SdapDirection::Downlink,
        /* rqi */ true,
    );
    assert_eq!(drb_id, 8);

    // Verify RQI is set in wire
    let hdr = SdapHeader::decode(pdu_bytes[0]);
    assert!(hdr.rqi);
    assert_eq!(hdr.qfi, 20);

    // UE receives DL with RQI=1 → should create reflective mapping QFI 20 → DRB 8
    let mut ue = SdapEntity::new(1, SdapRole::Ue, 5);
    ue.enable_reflective_qos();
    // Before: QFI 20 resolves to default DRB 5
    assert_eq!(ue.resolve_drb(20), 5);

    let result = ue.receive_pdu(8, &pdu_bytes, SdapDirection::Downlink);
    assert!(result.is_some());

    // After reflective mapping: QFI 20 → DRB 8
    assert_eq!(ue.resolve_drb(20), 8);
    let mapping = ue.qos_flow_map.get(&20).unwrap();
    assert_eq!(mapping.origin, MappingOrigin::Reflective);
    assert_eq!(mapping.drb_id, 8);
}

// ---------------------------------------------------------------------------
// 4. End-Marker generation on QoS Flow remapping
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_end_marker_on_remap() {
    let mut sdap = SdapEntity::new(1, SdapRole::Gnb, 5);

    // Initial mapping: QFI 10 → DRB 3
    sdap.configure_mapping(10, 3);
    assert_eq!(sdap.generated_end_markers.len(), 0);

    // Remap QFI 10 → DRB 7 (different DRB) → should generate End-Marker
    sdap.configure_mapping(10, 7);
    assert_eq!(sdap.generated_end_markers.len(), 1);
    let em = &sdap.generated_end_markers[0];
    assert_eq!(em.qfi, 10);
    assert_eq!(em.pdu_type, SdapControlPduType::EndMarker);

    // Verify End-Marker wire encoding
    let wire = em.to_bytes();
    assert_eq!(wire.len(), 1);
    // D/C=0, type=0, QFI=10 → 0x0A
    assert_eq!(wire[0], 0x0A);

    // Remap to same DRB → should NOT generate another End-Marker
    sdap.configure_mapping(10, 7);
    assert_eq!(sdap.generated_end_markers.len(), 1);
}

// ---------------------------------------------------------------------------
// 5. End-Marker reception clears mapping (UE side)
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_end_marker_reception_clears_mapping() {
    let mut ue = SdapEntity::new(1, SdapRole::Ue, 5);
    ue.configure_mapping(10, 3);
    assert_eq!(ue.resolve_drb(10), 3);

    // Receive an End-Marker control PDU for QFI 10 on DRB 3
    let em_pdu = SdapControlPdu {
        pdu_type: SdapControlPduType::EndMarker,
        qfi: 10,
    };
    let wire = em_pdu.to_bytes();

    let result = ue.receive_pdu(3, &wire, SdapDirection::Downlink);
    // Control PDU → returns None (no SDU delivered)
    assert!(result.is_none());

    // QFI 10 mapping should be cleared → falls back to default DRB 5
    assert_eq!(ue.resolve_drb(10), 5);
}

// ---------------------------------------------------------------------------
// 6. Transparent mode (no SDAP header)
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_transparent_mode_no_header() {
    let mut sdap = SdapEntity::new(1, SdapRole::Gnb, 5);
    sdap.header_config = SdapHeaderConfig {
        ul_header: false,
        dl_header: false,
    };

    let ip_packet = vec![0x45, 0x00, 0x00, 0x28];

    // Build PDU without header
    let (drb_id, pdu_bytes) = sdap.build_pdu(9, &ip_packet, SdapDirection::Downlink, false);
    assert_eq!(drb_id, 5);
    // No header prepended — PDU == raw IP
    assert_eq!(pdu_bytes, ip_packet);

    // Receive PDU without header
    let result = sdap.receive_pdu(5, &pdu_bytes, SdapDirection::Downlink);
    assert!(result.is_some());
    let (qfi, sdu) = result.unwrap();
    assert_eq!(qfi, 0); // Default QFI in transparent mode
    assert_eq!(sdu, ip_packet);
}

// ---------------------------------------------------------------------------
// 7. QFI boundary validation
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_qfi_boundary_rejection() {
    let mut sdap = SdapEntity::new(1, SdapRole::Gnb, 5);

    // QFI=64 is invalid (6-bit max = 63)
    sdap.configure_mapping(64, 3);
    assert!(sdap.qos_flow_map.get(&64).is_none());

    // QFI=63 is valid (maximum)
    sdap.configure_mapping(63, 3);
    assert_eq!(sdap.resolve_drb(63), 3);

    // QFI=0 is valid (minimum)
    sdap.configure_mapping(0, 2);
    assert_eq!(sdap.resolve_drb(0), 2);
}

// ---------------------------------------------------------------------------
// 8. Release clears all state
// ---------------------------------------------------------------------------

#[test]
fn test_sdap_release_clears_state() {
    let mut sdap = SdapEntity::new(1, SdapRole::Gnb, 5);
    sdap.configure_mapping(9, 3);
    sdap.configure_mapping(15, 7);
    sdap.configure_mapping(9, 4); // remap → generates end-marker

    let ip = vec![0x45];
    let (_, pdu) = sdap.build_pdu(9, &ip, SdapDirection::Downlink, false);
    sdap.receive_pdu(4, &pdu, SdapDirection::Downlink);

    assert!(!sdap.qos_flow_map.is_empty());
    assert!(!sdap.delivered_sdus.is_empty());
    assert!(!sdap.generated_end_markers.is_empty());

    sdap.release();

    assert!(sdap.qos_flow_map.is_empty());
    assert!(sdap.delivered_sdus.is_empty());
    assert!(sdap.generated_end_markers.is_empty());
}
