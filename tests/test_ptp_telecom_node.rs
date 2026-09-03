//! Integration tests for Integrated 5G Telecom Synchronization Node System (TelecomSyncNode).

use toy_tcpip::ptp_5g_tdd_sync::AntennaPortMeasurement;
use toy_tcpip::ptp_pdv_filter::PtpTimestampSample;
use toy_tcpip::ptp_synce_hybrid::HybridSyncMode;
use toy_tcpip::ptp_telecom_dual_plane::{PtpPlaneId, SwitchReason};
use toy_tcpip::ptp_telecom_node::{TelecomAlarm, TelecomSyncNode};
use toy_tcpip::synce_esmc::QualityLevel;

#[test]
fn test_telecom_node_healthy_hybrid_locked_startup() {
    let mut node = TelecomSyncNode::with_default_config();

    // 1. SyncE Physical Layer: Lock to QL-PRC (Primary Reference Clock)
    node.update_synce_ql(QualityLevel::QlPrc);

    // 2. Packet Layer PTP: Plane A & Plane B parallel ingestion
    // Plane A: Delay = 10,000 ns, Offset = 0 ns
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000;
        let t3 = t2 + 5_000;
        let t4 = t3 + 10_000;
        node.ingest_ptp_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t2, t3, t4),
        );
    }
    node.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);

    // Plane B: Delay = 10,000 ns, Offset = +25 ns
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        let t2 = t1 + 10_000 + 25;
        let t3 = t2 + 5_000;
        let t4 = t3 + 10_000 - 25;
        node.ingest_ptp_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t2, t3, t4),
        );
    }
    node.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    // 3. Antenna Ports: 4T4R MIMO array within TAE <= 65 ns
    node.update_antenna_measurement(AntennaPortMeasurement::new(101, 1, 3500.0, 110));
    node.update_antenna_measurement(AntennaPortMeasurement::new(102, 1, 3500.0, 135));
    node.update_antenna_measurement(AntennaPortMeasurement::new(103, 1, 3500.0, 120));
    node.update_antenna_measurement(AntennaPortMeasurement::new(104, 1, 3500.0, 140));

    // Execute synchronization cycle (100 ms)
    let result = node.process_sync_cycle(0.1);

    assert_eq!(result.active_plane, PtpPlaneId::PlaneA);
    assert_eq!(result.hybrid_mode, HybridSyncMode::HybridLocked);
    // In HybridLocked mode, SyncE provides physical syntonization (0.0 ppb)
    assert_eq!(result.frequency_ppb, 0.0);
    assert!(result.alarms_triggered.is_empty());

    let status = node.get_status_report();
    assert_eq!(status.active_gm_clock_class, 6);
    assert_eq!(status.synce_ql, Some(QualityLevel::QlPrc));
    assert!(status.cell_sync_compliant);
    assert!(status.mimo_tae_compliant);
    assert!(status.active_alarms.is_empty());
}

#[test]
fn test_telecom_node_dual_plane_failover_and_alarm() {
    let mut node = TelecomSyncNode::with_default_config();
    node.update_synce_ql(QualityLevel::QlPrc);

    // Initialize healthy Plane A and Plane B
    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        node.ingest_ptp_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 15_000, t1 + 25_000),
        );
        node.ingest_ptp_sample(
            PtpPlaneId::PlaneB,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 15_000, t1 + 25_000),
        );
    }
    node.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);
    node.update_plane_announce(PtpPlaneId::PlaneB, 6, 0x20, 0);

    node.process_sync_cycle(0.1);
    assert_eq!(node.dual_plane.active_plane, PtpPlaneId::PlaneA);

    // Degrade Plane A: Grandmaster loses GNSS and enters out-of-spec holdover (Class 140)
    node.update_plane_announce(PtpPlaneId::PlaneA, 140, 0xFE, 0);

    // Next cycle triggers protection switchover to Plane B
    let result = node.process_sync_cycle(0.1);

    assert_eq!(result.active_plane, PtpPlaneId::PlaneB);
    assert!(result.alarms_triggered.iter().any(|a| matches!(
        a,
        TelecomAlarm::PtpPlaneFailover {
            from: PtpPlaneId::PlaneA,
            to: PtpPlaneId::PlaneB,
            reason: SwitchReason::ClockClassDegraded,
        }
    )));
}

#[test]
fn test_telecom_node_synce_loss_fallback() {
    let mut node = TelecomSyncNode::with_default_config();
    node.update_synce_ql(QualityLevel::QlPrc);

    for seq in 0..10 {
        let t1 = (seq as i64) * 1_000_000;
        node.ingest_ptp_sample(
            PtpPlaneId::PlaneA,
            PtpTimestampSample::new(seq, t1, t1 + 10_000, t1 + 15_000, t1 + 25_000),
        );
    }
    node.update_plane_announce(PtpPlaneId::PlaneA, 6, 0x20, 0);

    node.process_sync_cycle(0.1);
    assert_eq!(node.hybrid.mode, HybridSyncMode::HybridLocked);

    // Clear SyncE signal (fiber cut or ESMC timeout)
    node.clear_synce();

    let result = node.process_sync_cycle(0.1);
    assert_eq!(result.hybrid_mode, HybridSyncMode::PtpOnly);
    assert!(result.alarms_triggered.contains(&TelecomAlarm::SyncELost));
}

#[test]
fn test_telecom_node_mimo_tae_alarm() {
    let mut node = TelecomSyncNode::with_default_config();

    // Antenna Group 1: 4T4R MIMO array
    // Port 101: 100 ns, Port 102: 180 ns -> TAE = |180 - 100| = 80 ns > 65 ns limit
    node.update_antenna_measurement(AntennaPortMeasurement::new(101, 1, 3500.0, 100));
    node.update_antenna_measurement(AntennaPortMeasurement::new(102, 1, 3500.0, 180));

    let result = node.process_sync_cycle(0.1);

    assert!(
        result
            .alarms_triggered
            .contains(&TelecomAlarm::MimoTaeExceeded {
                measured_tae_ns: 80,
                limit_ns: 65,
            })
    );

    let status = node.get_status_report();
    assert!(!status.mimo_tae_compliant);
}
