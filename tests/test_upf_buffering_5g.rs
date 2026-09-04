//! Integration tests for 3GPP Rel-17 5G UPF Downlink Data Buffering Engine.

use std::net::Ipv4Addr;
use toy_tcpip::upf_buffering_5g::{BarConfig, BufferDropPolicy, UpfBufferingEngine, derive_ppi};

#[test]
fn test_upf_buffering_and_ddn_emission() {
    let mut engine = UpfBufferingEngine::new();
    let seid = 0x1000_5001;
    let pdr_id = 1;
    let bar_config = BarConfig {
        bar_id: 1,
        ddn_delay_ms: 0, // Immediate DDN
        suggested_packet_count: 10,
        max_hold_time_ms: 30_000,
    };

    engine.configure_session_buffer(
        seid,
        pdr_id,
        bar_config,
        10,
        64 * 1024,
        BufferDropPolicy::DropOldest,
    );

    let start_time_ms = 1000;

    // Packet 1: Voice RTP (QFI 1, DSCP EF = 46) -> Triggers immediate DDN with PPI 1
    let pkt1 = b"RTP Voice Data Packet 1".to_vec();
    let ddn1 = engine
        .buffer_downlink_packet(seid, pkt1.clone(), 1, 46, start_time_ms)
        .expect("Buffering packet 1 should succeed");

    assert!(ddn1.is_some(), "First packet must trigger DDN report");
    let report = ddn1.unwrap();
    assert_eq!(report.seid, seid);
    assert_eq!(report.pdr_id, pdr_id);
    assert_eq!(report.qfi, 1);
    assert_eq!(report.ppi, Some(1));
    assert_eq!(report.first_packet_timestamp_ms, start_time_ms);
    assert_eq!(derive_ppi(1, 46), Some(1));
    assert_eq!(derive_ppi(9, 0), None);

    // Packet 2: IMS Signalling (QFI 5, DSCP CS5 = 40) -> Already notified, suppressed
    let pkt2 = b"SIP INVITE Signalling Packet 2".to_vec();
    let ddn2 = engine
        .buffer_downlink_packet(seid, pkt2.clone(), 5, 40, start_time_ms + 10)
        .expect("Buffering packet 2 should succeed");
    assert!(
        ddn2.is_none(),
        "Subsequent packets must not trigger duplicate DDN"
    );

    // Packet 3: Best-effort background data (QFI 9, DSCP 0) -> Suppressed
    let pkt3 = b"Background Sync Packet 3".to_vec();
    let ddn3 = engine
        .buffer_downlink_packet(seid, pkt3.clone(), 9, 0, start_time_ms + 20)
        .expect("Buffering packet 3 should succeed");
    assert!(ddn3.is_none());

    // Verify session buffer stats
    let (count, bytes) = engine.get_session_stats(seid).unwrap();
    assert_eq!(count, 3);
    assert_eq!(bytes, pkt1.len() + pkt2.len() + pkt3.len());

    let stats = engine.stats;
    assert_eq!(stats.total_buffered_packets, 3);
    assert_eq!(stats.total_ddn_reports_generated, 1);
}

#[test]
fn test_upf_buffer_flush_on_paging_success() {
    let mut engine = UpfBufferingEngine::new();
    let seid = 0x1000_5002;
    let pdr_id = 2;
    engine.configure_session_buffer(
        seid,
        pdr_id,
        BarConfig::default(),
        10,
        64 * 1024,
        BufferDropPolicy::DropOldest,
    );

    let pkt1_payload = b"Payload One (VoNR)".to_vec();
    let pkt2_payload = b"Payload Two (IMS)".to_vec();
    let pkt3_payload = b"Payload Three (Internet)".to_vec();

    engine
        .buffer_downlink_packet(seid, pkt1_payload.clone(), 1, 46, 2000)
        .unwrap();
    engine
        .buffer_downlink_packet(seid, pkt2_payload.clone(), 5, 40, 2005)
        .unwrap();
    engine
        .buffer_downlink_packet(seid, pkt3_payload.clone(), 9, 0, 2010)
        .unwrap();

    // UE wakes up and sends Service Request; SMF updates FAR to FORW with gNodeB TEID and IP
    let gnb_teid = 0xDEAD_BEEF;
    let gnb_ip = Ipv4Addr::new(10, 20, 0, 1);

    let flushed = engine
        .flush_buffer(seid, gnb_teid, gnb_ip)
        .expect("Buffer flush must succeed");

    assert_eq!(
        flushed.len(),
        3,
        "All 3 packets must be flushed in chronological order"
    );

    // Verify Packet 1 GTP-U encapsulation
    assert_eq!(flushed[0].teid, gnb_teid);
    assert_eq!(flushed[0].gnb_ip, gnb_ip);
    assert_eq!(flushed[0].qfi, 1);
    let gtpu1 = &flushed[0].gtpu_packet;
    assert_eq!(gtpu1[0], 0x34); // Version 1, Extension Header flag
    assert_eq!(gtpu1[1], 0xFF); // G-PDU
    assert_eq!(&gtpu1[4..8], &gnb_teid.to_be_bytes()); // TEID
    assert_eq!(gtpu1[10], 0x85); // Next Ext Type: PDU Session Container
    assert_eq!(gtpu1[12] & 0x3F, 1); // QFI = 1
    assert_eq!(&gtpu1[16..], &pkt1_payload[..]); // Original payload intact

    // Verify Packet 2 QFI
    assert_eq!(flushed[1].qfi, 5);
    assert_eq!(flushed[1].gtpu_packet[12] & 0x3F, 5);
    assert_eq!(&flushed[1].gtpu_packet[16..], &pkt2_payload[..]);

    // Verify Packet 3 QFI
    assert_eq!(flushed[2].qfi, 9);
    assert_eq!(flushed[2].gtpu_packet[12] & 0x3F, 9);
    assert_eq!(&flushed[2].gtpu_packet[16..], &pkt3_payload[..]);

    // Verify buffer is empty and reset
    let (count, bytes) = engine.get_session_stats(seid).unwrap();
    assert_eq!(count, 0);
    assert_eq!(bytes, 0);

    // After flush, new packet should trigger a fresh DDN
    let ddn_fresh = engine
        .buffer_downlink_packet(seid, b"New Burst".to_vec(), 1, 46, 2100)
        .unwrap();
    assert!(
        ddn_fresh.is_some(),
        "New burst after flush must trigger DDN again"
    );
}

#[test]
fn test_upf_buffer_drop_policies() {
    let mut engine = UpfBufferingEngine::new();

    // 1. DropNewest Policy
    let seid_dn = 0x1000_5003;
    engine.configure_session_buffer(
        seid_dn,
        1,
        BarConfig::default(),
        2, // Max 2 packets
        1024,
        BufferDropPolicy::DropNewest,
    );
    engine
        .buffer_downlink_packet(seid_dn, b"P1".to_vec(), 9, 0, 3000)
        .unwrap();
    engine
        .buffer_downlink_packet(seid_dn, b"P2".to_vec(), 9, 0, 3001)
        .unwrap();
    engine
        .buffer_downlink_packet(seid_dn, b"P3".to_vec(), 9, 0, 3002)
        .unwrap(); // Should be dropped

    let flushed_dn = engine
        .flush_buffer(seid_dn, 0x111, Ipv4Addr::new(10, 0, 0, 1))
        .unwrap();
    assert_eq!(flushed_dn.len(), 2);
    assert_eq!(&flushed_dn[0].gtpu_packet[16..], b"P1");
    assert_eq!(&flushed_dn[1].gtpu_packet[16..], b"P2");

    // 2. DropOldest Policy
    let seid_do = 0x1000_5004;
    engine.configure_session_buffer(
        seid_do,
        1,
        BarConfig::default(),
        2, // Max 2 packets
        1024,
        BufferDropPolicy::DropOldest,
    );
    engine
        .buffer_downlink_packet(seid_do, b"P1".to_vec(), 9, 0, 3100)
        .unwrap();
    engine
        .buffer_downlink_packet(seid_do, b"P2".to_vec(), 9, 0, 3101)
        .unwrap();
    engine
        .buffer_downlink_packet(seid_do, b"P3".to_vec(), 9, 0, 3102)
        .unwrap(); // P1 dropped, P3 added

    let flushed_do = engine
        .flush_buffer(seid_do, 0x222, Ipv4Addr::new(10, 0, 0, 1))
        .unwrap();
    assert_eq!(flushed_do.len(), 2);
    assert_eq!(&flushed_do[0].gtpu_packet[16..], b"P2");
    assert_eq!(&flushed_do[1].gtpu_packet[16..], b"P3");

    // 3. PriorityDrop Policy
    let seid_pd = 0x1000_5005;
    engine.configure_session_buffer(
        seid_pd,
        1,
        BarConfig::default(),
        2, // Max 2 packets
        1024,
        BufferDropPolicy::PriorityDrop,
    );
    // Ingest Packet 1 with Low Priority (QFI 9 = Best Effort)
    engine
        .buffer_downlink_packet(seid_pd, b"LowPrio".to_vec(), 9, 0, 3200)
        .unwrap();
    // Ingest Packet 2 with High Priority (QFI 1 = Voice)
    engine
        .buffer_downlink_packet(seid_pd, b"HighPrioVoice".to_vec(), 1, 46, 3201)
        .unwrap();
    // Ingest Packet 3 with Medium Priority (QFI 2 = Video)
    // PriorityDrop drops LowPrio (QFI 9) and keeps QFI 1 and QFI 2!
    engine
        .buffer_downlink_packet(seid_pd, b"MedPrioVideo".to_vec(), 2, 34, 3202)
        .unwrap();

    let flushed_pd = engine
        .flush_buffer(seid_pd, 0x333, Ipv4Addr::new(10, 0, 0, 1))
        .unwrap();
    assert_eq!(flushed_pd.len(), 2);
    assert_eq!(flushed_pd[0].qfi, 1);
    assert_eq!(&flushed_pd[0].gtpu_packet[16..], b"HighPrioVoice");
    assert_eq!(flushed_pd[1].qfi, 2);
    assert_eq!(&flushed_pd[1].gtpu_packet[16..], b"MedPrioVideo");
}

#[test]
fn test_upf_buffer_purge_on_paging_timeout() {
    let mut engine = UpfBufferingEngine::new();
    let seid = 0x1000_5006;
    engine.configure_session_buffer(
        seid,
        1,
        BarConfig::default(),
        10,
        64 * 1024,
        BufferDropPolicy::DropOldest,
    );

    for i in 0..5 {
        let payload = format!("Buffered packet {}", i).into_bytes();
        engine
            .buffer_downlink_packet(seid, payload, 9, 0, 4000 + i)
            .unwrap();
    }

    assert_eq!(engine.get_session_stats(seid).unwrap().0, 5);

    // Paging timeout triggers buffer purge
    let (purged_count, purged_bytes) = engine.purge_buffer(seid).unwrap();
    assert_eq!(purged_count, 5);
    assert!(purged_bytes > 0);

    assert_eq!(engine.get_session_stats(seid).unwrap().0, 0);
    assert_eq!(engine.stats.total_purged_packets, 5);
}

#[test]
fn test_upf_buffering_ddn_delay_timer() {
    let mut engine = UpfBufferingEngine::new();
    let seid = 0x1000_5007;
    let ddn_delay_ms = 100; // 100ms delay timer

    let bar_config = BarConfig {
        bar_id: 1,
        ddn_delay_ms,
        suggested_packet_count: 5,
        max_hold_time_ms: 30_000,
    };

    engine.configure_session_buffer(
        seid,
        1,
        bar_config,
        10,
        64 * 1024,
        BufferDropPolicy::DropOldest,
    );

    let start_time_ms = 5000;
    // Packet arrives: because DDND is 100ms, buffer_downlink_packet returns None
    let immediate_ddn = engine
        .buffer_downlink_packet(seid, b"Delayed Packet".to_vec(), 1, 46, start_time_ms)
        .unwrap();
    assert!(
        immediate_ddn.is_none(),
        "DDN must be delayed per DDND timer"
    );

    // Tick at 5050ms (elapsed 50ms < 100ms) -> No report yet
    let reports_50 = engine.check_delayed_ddn(5050);
    assert!(reports_50.is_empty(), "50ms is less than 100ms delay");

    // Tick at 5105ms (elapsed 105ms >= 100ms) -> Report emitted!
    let reports_105 = engine.check_delayed_ddn(5105);
    assert_eq!(reports_105.len(), 1, "Delayed DDN report must be emitted");
    assert_eq!(reports_105[0].seid, seid);
    assert_eq!(reports_105[0].qfi, 1);
    assert_eq!(reports_105[0].ppi, Some(1));
    assert_eq!(reports_105[0].first_packet_timestamp_ms, start_time_ms);

    // Subsequent tick does not re-emit
    let reports_later = engine.check_delayed_ddn(5200);
    assert!(reports_later.is_empty());
}
