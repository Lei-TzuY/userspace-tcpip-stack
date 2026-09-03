//! Integration tests for O-RAN WG4 M-Plane NETCONF / YANG & FCAPS Engine.

use toy_tcpip::oran_mplane_fcaps::{
    AlarmSeverity, DatastoreTarget, EditConfigOp, OranMplaneEngine, OranMplaneRpc,
    OranMplaneRpcReply, OruOperationalState, YangValue,
};
use toy_tcpip::oran_packet_proc::OranStreamStats;

#[test]
fn test_oru_startup_state_machine_happy_path_and_guard_rejection() {
    let mut engine = OranMplaneEngine::new();
    assert_eq!(engine.state, OruOperationalState::PowerOn);

    // Cannot jump directly from PowerOn to Operational
    assert!(
        engine
            .transition_state(OruOperationalState::Operational)
            .is_err()
    );

    // Step-by-step normal startup lifecycle
    assert!(
        engine
            .transition_state(OruOperationalState::DhcpDiscovered)
            .is_ok()
    );
    assert!(
        engine
            .transition_state(OruOperationalState::NetconfConnected)
            .is_ok()
    );
    assert!(
        engine
            .transition_state(OruOperationalState::SoftwareInventoryVerified)
            .is_ok()
    );
    assert!(
        engine
            .transition_state(OruOperationalState::CarrierConfigured)
            .is_ok()
    );
    assert!(
        engine
            .transition_state(OruOperationalState::Synchronized)
            .is_ok()
    );
    assert!(
        engine
            .transition_state(OruOperationalState::Operational)
            .is_ok()
    );
    assert_eq!(engine.state, OruOperationalState::Operational);

    // Degraded fallback and recovery
    assert!(
        engine
            .transition_state(OruOperationalState::Degraded)
            .is_ok()
    );
    assert_eq!(engine.state, OruOperationalState::Degraded);
    assert!(
        engine
            .transition_state(OruOperationalState::Operational)
            .is_ok()
    );

    // Fault transition
    assert!(
        engine
            .transition_state(OruOperationalState::Faulted)
            .is_ok()
    );
    assert_eq!(engine.state, OruOperationalState::Faulted);

    // Recovery from Faulted resets to PowerOn
    assert!(
        engine
            .transition_state(OruOperationalState::PowerOn)
            .is_ok()
    );
}

#[test]
fn test_oru_operational_state_blocked_by_critical_alarm() {
    let mut engine = OranMplaneEngine::new();

    // Advance to Synchronized
    engine
        .transition_state(OruOperationalState::DhcpDiscovered)
        .unwrap();
    engine
        .transition_state(OruOperationalState::NetconfConnected)
        .unwrap();
    engine
        .transition_state(OruOperationalState::SoftwareInventoryVerified)
        .unwrap();
    engine
        .transition_state(OruOperationalState::CarrierConfigured)
        .unwrap();
    engine
        .transition_state(OruOperationalState::Synchronized)
        .unwrap();

    // Raise Critical optical loss-of-signal alarm
    let fault_id = engine.fault_mgr.raise_alarm(
        "sfp-0",
        AlarmSeverity::Critical,
        "loss-of-signal",
        "Fiber optic cable disconnected or RX power below threshold",
        1_700_000_000,
    );
    assert!(fault_id > 0);

    // Attempt to enter Operational must be rejected due to active Critical alarm!
    let res = engine.transition_state(OruOperationalState::Operational);
    assert!(res.is_err());

    // Clear alarm
    assert!(engine.fault_mgr.clear_alarm(fault_id, 1_700_000_050));

    // Now transition to Operational succeeds!
    assert!(
        engine
            .transition_state(OruOperationalState::Operational)
            .is_ok()
    );
}

#[test]
fn test_netconf_candidate_edit_and_commit() {
    let mut engine = OranMplaneEngine::new();

    let path =
        "/o-ran-uplane-conf:user-plane-configuration/tx-array-carriers[name='tx-0']/e-axc-id"
            .to_string();

    // 1. Verify path does not exist in Running
    let get_running = OranMplaneRpc::GetConfig {
        source: DatastoreTarget::Running,
        filter_prefix: Some(path.clone()),
    };
    if let OranMplaneRpcReply::Data { entries, .. } = engine.execute_netconf_rpc(get_running) {
        assert!(entries.is_empty());
    } else {
        panic!("Expected Data reply");
    }

    // 2. EditConfig on Candidate
    let edit_candidate = OranMplaneRpc::EditConfig {
        target: DatastoreTarget::Candidate,
        operation: EditConfigOp::Create,
        path: path.clone(),
        value: Some(YangValue::Uint64(0x1001)),
    };
    let reply = engine.execute_netconf_rpc(edit_candidate);
    assert!(matches!(reply, OranMplaneRpcReply::Ok { .. }));

    // 3. Verify Candidate has it, but Running still does not!
    assert!(engine.candidate_ds.get(&path).is_some());
    assert!(engine.running_ds.get(&path).is_none());

    // 4. Commit candidate to running
    let commit_reply = engine.execute_netconf_rpc(OranMplaneRpc::Commit);
    assert!(matches!(commit_reply, OranMplaneRpcReply::Ok { .. }));

    // 5. Now Running has the value!
    assert_eq!(
        engine.running_ds.get(&path),
        Some(&YangValue::Uint64(0x1001))
    );
}

#[test]
fn test_netconf_discard_changes() {
    let mut engine = OranMplaneEngine::new();

    let path = "/o-ran-hardware:hardware/component[name='ant-0']/serial-no".to_string();

    // Edit candidate
    engine.execute_netconf_rpc(OranMplaneRpc::EditConfig {
        target: DatastoreTarget::Candidate,
        operation: EditConfigOp::Merge,
        path: path.clone(),
        value: Some(YangValue::String("SN-99887766".to_string())),
    });
    assert!(engine.candidate_ds.get(&path).is_some());

    // Discard changes reverts candidate back to running
    let reply = engine.execute_netconf_rpc(OranMplaneRpc::DiscardChanges);
    assert!(matches!(reply, OranMplaneRpcReply::Ok { .. }));
    assert!(engine.candidate_ds.get(&path).is_none());
}

#[test]
fn test_fault_management_alarm_lifecycle_and_deduplication() {
    let mut engine = OranMplaneEngine::new();

    // Raise Major power supply alarm
    let id1 = engine.fault_mgr.raise_alarm(
        "psu-1",
        AlarmSeverity::Major,
        "input-voltage-low",
        "PSU-1 input voltage dropped below 42V",
        1000,
    );
    assert_eq!(id1, 1);
    assert_eq!(engine.fault_mgr.get_active_alarms().len(), 1);

    // Raise same alarm again with escalated severity -> deduplicated to id 1
    let id2 = engine.fault_mgr.raise_alarm(
        "psu-1",
        AlarmSeverity::Critical,
        "input-voltage-low",
        "PSU-1 input voltage dropped below 36V",
        2000,
    );
    assert_eq!(id1, id2);
    assert_eq!(engine.fault_mgr.get_active_alarms().len(), 1);
    assert_eq!(
        engine.fault_mgr.active_alarms.get(&id1).unwrap().severity,
        AlarmSeverity::Critical
    );

    // Operator acknowledges alarm
    assert!(engine.fault_mgr.acknowledge_alarm(id1));
    assert!(
        engine
            .fault_mgr
            .active_alarms
            .get(&id1)
            .unwrap()
            .is_acknowledged
    );

    // Clear alarm
    assert!(engine.fault_mgr.clear_alarm(id1, 3000));
    assert!(engine.fault_mgr.get_active_alarms().is_empty());
    assert_eq!(engine.fault_mgr.alarm_history.len(), 2);
}

#[test]
fn test_performance_management_15min_bin_accumulation() {
    let mut engine = OranMplaneEngine::new();

    let mut stats = OranStreamStats::default();
    stats.total_uplane_packets = 1_000_000;
    stats.late_dropped_packets = 80;
    stats.early_dropped_packets = 20;
    stats.total_cplane_packets = 50_000;
    stats.total_decompressed_samples = 48_000_000;

    engine.pm_collector.ingest_stream_stats(&stats);

    assert_eq!(
        engine.pm_collector.current_bin.total_uplane_packets,
        1_000_000
    );
    assert_eq!(engine.pm_collector.current_bin.late_dropped_packets, 80);
    assert_eq!(engine.pm_collector.current_bin.early_dropped_packets, 20);
    // 100 drops / 1,000,000 packets = 100 PPM
    assert_eq!(engine.pm_collector.current_bin.drop_rate_ppm, 100);

    // Roll 15-minute interval
    engine.pm_collector.roll_interval(900_000);

    assert_eq!(engine.pm_collector.historical_bins.len(), 1);
    assert_eq!(engine.pm_collector.historical_bins[0].drop_rate_ppm, 100);
    assert_eq!(engine.pm_collector.current_bin.total_uplane_packets, 0);
    assert_eq!(
        engine.pm_collector.current_bin.interval_start_epoch_ms,
        900_000
    );
}
