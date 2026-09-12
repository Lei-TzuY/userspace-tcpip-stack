//! Integration tests for 3GPP Rel-18/19 Multi-Radio Dual Connectivity (MR-DC) Split Bearer & Dynamic Uplink Path Routing Engine.
//! Validates:
//! - Primary path routing when buffer $\le$ `ul-DataSplitThreshold`.
//! - Dynamic split routing across MCG and SCG via Round-Robin, Proportional Load, and Latency-Optimal policies when buffer > threshold.
//! - PDCP Duplication activation and deactivation behavior.
//! - Rel-18 SCG deactivation / power saving override to primary path.
//! - Downlink out-of-order packet reordering and sliding delivery window.
//! - Downlink duplicate detection and discarding for duplicated legs.
//! - Binary wire framing (`MrdcSplitBearerWirePdu`) with CRC-16 CCITT validation.

use toy_tcpip::nr_mrdc_split_bearer::{
    BearerTermination, CellGroup, MrdcError, MrdcReorderingBuffer, MrdcSplitBearerEngine,
    MrdcSplitBearerWirePdu, PrimaryPathConfig, ScgState, SplitBearerConfig, SplitPolicy,
    TransmissionPath, UlDataSplitThreshold,
};

// ---------------------------------------------------------------------------
// 1. UL Split Bearer Threshold & Primary Path Routing (TS 38.323 §5.2.1)
// ---------------------------------------------------------------------------

#[test]
fn test_split_bearer_below_threshold_routes_to_primary() {
    let config = SplitBearerConfig {
        bearer_id: 3,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(1000),
        duplication_configured: false,
    };

    let mut engine = MrdcSplitBearerEngine::new(config, SplitPolicy::RoundRobin);

    // Buffer = 500 bytes <= threshold (1000 bytes) -> Must route strictly to primary path (MCG)
    let pdu1 = engine.route_packet(vec![1, 2, 3], 500);
    assert_eq!(pdu1.path, TransmissionPath::McgOnly);
    assert_eq!(pdu1.sn, 0);

    let pdu2 = engine.route_packet(vec![4, 5, 6], 1000);
    assert_eq!(pdu2.path, TransmissionPath::McgOnly);
    assert_eq!(pdu2.sn, 1);
}

#[test]
fn test_split_bearer_threshold_infinity_always_primary() {
    let config = SplitBearerConfig {
        bearer_id: 4,
        termination: BearerTermination::SnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Scg,
            logical_channel_id: 2,
        },
        split_threshold: UlDataSplitThreshold::Infinity,
        duplication_configured: false,
    };

    let mut engine = MrdcSplitBearerEngine::new(config, SplitPolicy::RoundRobin);

    // Any buffer size routes to primary (SCG)
    let pdu = engine.route_packet(vec![10, 20], 500_000);
    assert_eq!(pdu.path, TransmissionPath::ScgOnly);
}

// ---------------------------------------------------------------------------
// 2. Dynamic Split Routing Above Threshold: Round-Robin, Proportional, Latency
// ---------------------------------------------------------------------------

#[test]
fn test_split_bearer_above_threshold_round_robin() {
    let config = SplitBearerConfig {
        bearer_id: 1,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(500),
        duplication_configured: false,
    };

    let mut engine = MrdcSplitBearerEngine::new(config, SplitPolicy::RoundRobin);

    // Buffer = 2000 bytes > 500 bytes -> Alternates MCG and SCG
    let p0 = engine.route_packet(vec![1], 2000);
    assert_eq!(p0.path, TransmissionPath::McgOnly);

    let p1 = engine.route_packet(vec![2], 2000);
    assert_eq!(p1.path, TransmissionPath::ScgOnly);

    let p2 = engine.route_packet(vec![3], 2000);
    assert_eq!(p2.path, TransmissionPath::McgOnly);

    let p3 = engine.route_packet(vec![4], 2000);
    assert_eq!(p3.path, TransmissionPath::ScgOnly);
}

#[test]
fn test_split_bearer_proportional_policy() {
    let config = SplitBearerConfig {
        bearer_id: 2,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(0), // Always split
        duplication_configured: false,
    };

    // 3:1 ratio (75% MCG, 25% SCG)
    let policy = SplitPolicy::ProportionalLoad {
        mcg_ratio: 3,
        scg_ratio: 1,
    };
    let mut engine = MrdcSplitBearerEngine::new(config, policy);

    let p0 = engine.route_packet(vec![0], 100);
    let p1 = engine.route_packet(vec![1], 100);
    let p2 = engine.route_packet(vec![2], 100);
    let p3 = engine.route_packet(vec![3], 100);

    assert_eq!(p0.path, TransmissionPath::McgOnly);
    assert_eq!(p1.path, TransmissionPath::McgOnly);
    assert_eq!(p2.path, TransmissionPath::McgOnly);
    assert_eq!(p3.path, TransmissionPath::ScgOnly);
}

#[test]
fn test_split_bearer_latency_optimal_policy() {
    let config = SplitBearerConfig {
        bearer_id: 5,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(100),
        duplication_configured: false,
    };

    // MCG lower latency
    let mut engine = MrdcSplitBearerEngine::new(
        config.clone(),
        SplitPolicy::LatencyOptimal {
            mcg_rtt_ms: 12,
            scg_rtt_ms: 35,
        },
    );
    let p0 = engine.route_packet(vec![1], 500);
    assert_eq!(p0.path, TransmissionPath::McgOnly);

    // SCG lower latency
    let mut engine2 = MrdcSplitBearerEngine::new(
        config,
        SplitPolicy::LatencyOptimal {
            mcg_rtt_ms: 50,
            scg_rtt_ms: 15,
        },
    );
    let p1 = engine2.route_packet(vec![2], 500);
    assert_eq!(p1.path, TransmissionPath::ScgOnly);
}

// ---------------------------------------------------------------------------
// 3. PDCP Duplication & Rel-18 SCG Deactivation Tests
// ---------------------------------------------------------------------------

#[test]
fn test_pdcp_duplication_active() {
    let config = SplitBearerConfig {
        bearer_id: 6,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(1000),
        duplication_configured: true,
    };

    let mut engine = MrdcSplitBearerEngine::new(config, SplitPolicy::RoundRobin);
    engine.set_duplication(true);

    let pdu = engine.route_packet(vec![0xAA, 0xBB], 500);
    assert_eq!(pdu.path, TransmissionPath::DuplicatedBoth);

    // Toggle off duplication -> returns to normal threshold routing
    engine.set_duplication(false);
    let pdu2 = engine.route_packet(vec![0xCC], 500);
    assert_eq!(pdu2.path, TransmissionPath::McgOnly);
}

#[test]
fn test_rel18_scg_deactivation_power_saving() {
    let config = SplitBearerConfig {
        bearer_id: 7,
        termination: BearerTermination::MnTerminated,
        primary_path: PrimaryPathConfig {
            cell_group: CellGroup::Mcg,
            logical_channel_id: 1,
        },
        split_threshold: UlDataSplitThreshold::Bytes(100),
        duplication_configured: false,
    };

    let mut engine = MrdcSplitBearerEngine::new(config, SplitPolicy::RoundRobin);

    // Deactivate SCG for power saving
    engine.set_scg_state(ScgState::Deactivated);

    // Buffer is large (5000 bytes > 100), but SCG is deactivated -> Must route to primary path (MCG)
    let pdu1 = engine.route_packet(vec![1], 5000);
    assert_eq!(pdu1.path, TransmissionPath::McgOnly);

    let pdu2 = engine.route_packet(vec![2], 5000);
    assert_eq!(pdu2.path, TransmissionPath::McgOnly);

    // Reactivate SCG -> Resumes dynamic split
    engine.set_scg_state(ScgState::Active);
    let pdu3 = engine.route_packet(vec![3], 5000);
    assert_eq!(pdu3.path, TransmissionPath::McgOnly);
    let pdu4 = engine.route_packet(vec![4], 5000);
    assert_eq!(pdu4.path, TransmissionPath::ScgOnly);
}

// ---------------------------------------------------------------------------
// 4. Downlink Reordering & Duplicate Discard Tests (TS 38.323 §5.2.2.2)
// ---------------------------------------------------------------------------

#[test]
fn test_dl_reordering_buffer_in_order_delivery() {
    let mut reord = MrdcReorderingBuffer::new(64);

    let del0 = reord.receive_pdu(0, vec![10]).unwrap();
    assert_eq!(del0, vec![vec![10]]);
    assert_eq!(reord.next_expected_sn(), 1);

    let del1 = reord.receive_pdu(1, vec![20]).unwrap();
    assert_eq!(del1, vec![vec![20]]);
    assert_eq!(reord.next_expected_sn(), 2);
}

#[test]
fn test_dl_reordering_buffer_out_of_order_assembly() {
    let mut reord = MrdcReorderingBuffer::new(64);

    // Packet 2 arrives first (from faster SCG path)
    let del2 = reord.receive_pdu(2, vec![30]).unwrap();
    assert!(del2.is_empty());
    assert_eq!(reord.buffered_count(), 1);

    // Packet 0 arrives (from slower MCG path) -> del0 delivers packet 0
    let del0 = reord.receive_pdu(0, vec![10]).unwrap();
    assert_eq!(del0, vec![vec![10]]);
    assert_eq!(reord.next_expected_sn(), 1);

    // Packet 1 arrives -> delivers BOTH packet 1 and previously buffered packet 2!
    let del1 = reord.receive_pdu(1, vec![20]).unwrap();
    assert_eq!(del1, vec![vec![20], vec![30]]);
    assert_eq!(reord.next_expected_sn(), 3);
    assert_eq!(reord.buffered_count(), 0);
}

#[test]
fn test_dl_reordering_duplicate_packet_discard() {
    let mut reord = MrdcReorderingBuffer::new(64);

    // First arrival of SN 0 via MCG
    let del0 = reord.receive_pdu(0, vec![100]).unwrap();
    assert_eq!(del0, vec![vec![100]]);

    // Duplicated arrival of SN 0 via SCG -> cleanly dropped
    let del0_dup = reord.receive_pdu(0, vec![100]).unwrap();
    assert!(del0_dup.is_empty());

    // Buffered duplicate discard
    reord.receive_pdu(2, vec![200]).unwrap();
    let dup2 = reord.receive_pdu(2, vec![200]).unwrap();
    assert!(dup2.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Binary Wire Framing (MrdcSplitBearerWirePdu) Tests
// ---------------------------------------------------------------------------

#[test]
fn test_wire_pdu_roundtrip() {
    let pdu = MrdcSplitBearerWirePdu {
        bearer_id: 5,
        path: TransmissionPath::DuplicatedBoth,
        sn: 1048,
        payload: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let bytes = pdu.to_wire_bytes();
    assert_eq!(bytes.len(), 12 + 5 + 2); // Header (12) + payload (5) + CRC (2)

    let decoded = MrdcSplitBearerWirePdu::from_wire_bytes(&bytes).unwrap();
    assert_eq!(decoded.bearer_id, pdu.bearer_id);
    assert_eq!(decoded.path, pdu.path);
    assert_eq!(decoded.sn, pdu.sn);
    assert_eq!(decoded.payload, pdu.payload);
}

#[test]
fn test_wire_pdu_magic_corruption() {
    let pdu = MrdcSplitBearerWirePdu {
        bearer_id: 1,
        path: TransmissionPath::McgOnly,
        sn: 0,
        payload: vec![1, 2, 3],
    };

    let mut bytes = pdu.to_wire_bytes();
    bytes[0] = 0x00;

    assert!(matches!(
        MrdcSplitBearerWirePdu::from_wire_bytes(&bytes),
        Err(MrdcError::InvalidWireMagic(_))
    ));
}

#[test]
fn test_wire_pdu_crc_corruption() {
    let pdu = MrdcSplitBearerWirePdu {
        bearer_id: 2,
        path: TransmissionPath::ScgOnly,
        sn: 12,
        payload: vec![9, 8, 7],
    };

    let mut bytes = pdu.to_wire_bytes();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    assert!(matches!(
        MrdcSplitBearerWirePdu::from_wire_bytes(&bytes),
        Err(MrdcError::WireCrcMismatch { .. })
    ));
}

#[test]
fn test_wire_pdu_truncated() {
    let pdu = MrdcSplitBearerWirePdu {
        bearer_id: 1,
        path: TransmissionPath::McgOnly,
        sn: 5,
        payload: vec![10, 20, 30],
    };

    let bytes = pdu.to_wire_bytes();
    let truncated = &bytes[..8];

    assert!(matches!(
        MrdcSplitBearerWirePdu::from_wire_bytes(truncated),
        Err(MrdcError::WirePayloadTooShort { .. })
    ));
}
