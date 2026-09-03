//! O-RAN WG4 Open Fronthaul M-Plane (Management Plane) NETCONF / YANG & FCAPS Engine.
//!
//! Provides the O-RU startup state machine, hierarchical YANG datastore with NETCONF
//! candidate-to-running two-phase commit, ITU-T X.733 / 3GPP TS 28.532 Fault Management
//! (FM) alarm tracking, and 15-minute Performance Management (PM) bin collection.

use std::collections::HashMap;

use crate::oran_packet_proc::OranStreamStats;

/// O-RU Operational Lifecycle States (O-RAN.WG4.MP.0 Section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OruOperationalState {
    /// O-RU power applied, bootloader executing.
    PowerOn,
    /// DHCP completed, IP address and VLAN configured.
    DhcpDiscovered,
    /// NETCONF call-home connection established to SMO / O-DU.
    NetconfConnected,
    /// Software version, build hash, and inventory validated.
    SoftwareInventoryVerified,
    /// TX/RX carrier endpoints and eAxC routing provisioned.
    CarrierConfigured,
    /// PTP ITU-T G.8275.1 and SyncE frequency/phase locked.
    Synchronized,
    /// Full operational status: ready for U-Plane & C-Plane streaming.
    Operational,
    /// Degraded state (e.g. SyncE loss fallback to holdover).
    Degraded,
    /// Critical hardware or software fault halted radio transmission.
    Faulted,
}

impl OruOperationalState {
    /// Validates whether a state transition follows the O-RAN initialization sequence.
    pub fn can_transition_to(&self, next: OruOperationalState) -> bool {
        match (*self, next) {
            (OruOperationalState::PowerOn, OruOperationalState::DhcpDiscovered) => true,
            (OruOperationalState::DhcpDiscovered, OruOperationalState::NetconfConnected) => true,
            (
                OruOperationalState::NetconfConnected,
                OruOperationalState::SoftwareInventoryVerified,
            ) => true,
            (
                OruOperationalState::SoftwareInventoryVerified,
                OruOperationalState::CarrierConfigured,
            ) => true,
            (OruOperationalState::CarrierConfigured, OruOperationalState::Synchronized) => true,
            (OruOperationalState::Synchronized, OruOperationalState::Operational) => true,
            (OruOperationalState::Operational, OruOperationalState::Degraded) => true,
            (OruOperationalState::Degraded, OruOperationalState::Operational) => true,
            (_, OruOperationalState::Faulted) => true,
            (OruOperationalState::Faulted, OruOperationalState::PowerOn) => true,
            _ => false,
        }
    }
}

/// Target datastore for NETCONF operations (RFC 6241).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DatastoreTarget {
    Running,
    Candidate,
    Startup,
}

/// Standard YANG value representation.
#[derive(Debug, Clone, PartialEq)]
pub enum YangValue {
    String(String),
    Int64(i64),
    Uint64(u64),
    Float64(f64),
    Boolean(bool),
    List(Vec<String>),
}

/// Hierarchical YANG datastore supporting XPath-style path lookups.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct YangDatastore {
    pub entries: HashMap<String, YangValue>,
}

impl YangDatastore {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<&YangValue> {
        self.entries.get(path)
    }

    pub fn set(&mut self, path: impl Into<String>, value: YangValue) {
        self.entries.insert(path.into(), value);
    }

    pub fn delete(&mut self, path: &str) -> bool {
        self.entries.remove(path).is_some()
    }

    pub fn filter_by_prefix(&self, prefix: &str) -> Vec<(String, YangValue)> {
        self.entries
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub fn clone_from(&mut self, other: &YangDatastore) {
        self.entries = other.entries.clone();
    }
}

/// NETCONF `<edit-config>` operation semantics (RFC 6241 Section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditConfigOp {
    Merge,
    Replace,
    Create,
    Delete,
}

/// M-Plane NETCONF RPC request.
#[derive(Debug, Clone, PartialEq)]
pub enum OranMplaneRpc {
    GetConfig {
        source: DatastoreTarget,
        filter_prefix: Option<String>,
    },
    EditConfig {
        target: DatastoreTarget,
        operation: EditConfigOp,
        path: String,
        value: Option<YangValue>,
    },
    Validate {
        source: DatastoreTarget,
    },
    Commit,
    DiscardChanges,
    CopyConfig {
        source: DatastoreTarget,
        target: DatastoreTarget,
    },
}

/// M-Plane NETCONF RPC response.
#[derive(Debug, Clone, PartialEq)]
pub enum OranMplaneRpcReply {
    Ok {
        message_id: u32,
    },
    Data {
        message_id: u32,
        entries: Vec<(String, YangValue)>,
    },
    Error {
        message_id: u32,
        error_tag: &'static str,
        error_message: String,
    },
}

/// Alarm perceived severity per ITU-T X.733 and 3GPP TS 28.532.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlarmSeverity {
    Cleared,
    Warning,
    Minor,
    Major,
    Critical,
}

/// Individual fault alarm record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlarmRecord {
    pub fault_id: u32,
    pub source: String,
    pub severity: AlarmSeverity,
    pub probable_cause: &'static str,
    pub description: String,
    pub timestamp_epoch_ms: u64,
    pub is_acknowledged: bool,
}

/// Fault Management (FM) subsystem.
#[derive(Debug, Clone, Default)]
pub struct FaultManager {
    pub active_alarms: HashMap<u32, AlarmRecord>,
    pub alarm_history: Vec<AlarmRecord>,
    next_fault_id: u32,
}

impl FaultManager {
    pub fn new() -> Self {
        Self {
            active_alarms: HashMap::new(),
            alarm_history: Vec::new(),
            next_fault_id: 1,
        }
    }

    /// Raises an alarm or updates existing active alarm if same source & cause.
    pub fn raise_alarm(
        &mut self,
        source: &str,
        severity: AlarmSeverity,
        probable_cause: &'static str,
        description: impl Into<String>,
        timestamp_epoch_ms: u64,
    ) -> u32 {
        if severity == AlarmSeverity::Cleared {
            return 0;
        }

        // Deduplicate against existing active alarms from the same source & cause
        for alarm in self.active_alarms.values_mut() {
            if alarm.source == source && alarm.probable_cause == probable_cause {
                alarm.severity = severity;
                alarm.timestamp_epoch_ms = timestamp_epoch_ms;
                return alarm.fault_id;
            }
        }

        let fault_id = self.next_fault_id;
        self.next_fault_id += 1;

        let record = AlarmRecord {
            fault_id,
            source: source.to_string(),
            severity,
            probable_cause,
            description: description.into(),
            timestamp_epoch_ms,
            is_acknowledged: false,
        };

        self.active_alarms.insert(fault_id, record.clone());
        self.alarm_history.push(record);
        fault_id
    }

    /// Marks an alarm as acknowledged by the operator.
    pub fn acknowledge_alarm(&mut self, fault_id: u32) -> bool {
        if let Some(alarm) = self.active_alarms.get_mut(&fault_id) {
            alarm.is_acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Clears an active alarm and retires it to history.
    pub fn clear_alarm(&mut self, fault_id: u32, timestamp_epoch_ms: u64) -> bool {
        if let Some(mut alarm) = self.active_alarms.remove(&fault_id) {
            alarm.severity = AlarmSeverity::Cleared;
            alarm.timestamp_epoch_ms = timestamp_epoch_ms;
            self.alarm_history.push(alarm);
            true
        } else {
            false
        }
    }

    /// Returns list of active alarms.
    pub fn get_active_alarms(&self) -> Vec<&AlarmRecord> {
        self.active_alarms.values().collect()
    }
}

/// 15-minute Performance Management (PM) measurement bin (O-RAN.WG4.MP.0 Section 10).
#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceMeasurementBin {
    pub interval_start_epoch_ms: u64,
    pub interval_duration_sec: u32,
    pub total_uplane_packets: u64,
    pub late_dropped_packets: u64,
    pub early_dropped_packets: u64,
    pub drop_rate_ppm: u32,
    pub total_cplane_packets: u64,
    pub total_decompressed_samples: u64,
    pub optical_tx_power_dbm: f64,
    pub optical_rx_power_dbm: f64,
    pub temperature_celsius: f64,
}

impl Default for PerformanceMeasurementBin {
    fn default() -> Self {
        Self {
            interval_start_epoch_ms: 0,
            interval_duration_sec: 900, // 15 minutes = 900s
            total_uplane_packets: 0,
            late_dropped_packets: 0,
            early_dropped_packets: 0,
            drop_rate_ppm: 0,
            total_cplane_packets: 0,
            total_decompressed_samples: 0,
            optical_tx_power_dbm: 1.5,
            optical_rx_power_dbm: -3.2,
            temperature_celsius: 42.0,
        }
    }
}

/// Performance Management Collector.
#[derive(Debug, Clone)]
pub struct PerformanceManagementCollector {
    pub current_bin: PerformanceMeasurementBin,
    pub historical_bins: Vec<PerformanceMeasurementBin>,
    pub max_history_bins: usize,
}

impl PerformanceManagementCollector {
    pub fn new(start_epoch_ms: u64, max_history_bins: usize) -> Self {
        let mut bin = PerformanceMeasurementBin::default();
        bin.interval_start_epoch_ms = start_epoch_ms;
        Self {
            current_bin: bin,
            historical_bins: Vec::new(),
            max_history_bins,
        }
    }

    /// Ingests live telemetry from an eAxC stream.
    pub fn ingest_stream_stats(&mut self, stats: &OranStreamStats) {
        self.current_bin.total_uplane_packets += stats.total_uplane_packets;
        self.current_bin.late_dropped_packets += stats.late_dropped_packets;
        self.current_bin.early_dropped_packets += stats.early_dropped_packets;
        self.current_bin.total_cplane_packets += stats.total_cplane_packets;
        self.current_bin.total_decompressed_samples += stats.total_decompressed_samples;

        let total_drops =
            self.current_bin.late_dropped_packets + self.current_bin.early_dropped_packets;
        if self.current_bin.total_uplane_packets > 0 {
            self.current_bin.drop_rate_ppm = ((total_drops as f64
                / self.current_bin.total_uplane_packets as f64)
                * 1_000_000.0) as u32;
        }
    }

    /// Rolls the current measurement interval into history and resets the active bin.
    pub fn roll_interval(&mut self, next_start_epoch_ms: u64) {
        self.historical_bins.push(self.current_bin.clone());
        if self.historical_bins.len() > self.max_history_bins {
            self.historical_bins.remove(0);
        }

        let mut next_bin = PerformanceMeasurementBin::default();
        next_bin.interval_start_epoch_ms = next_start_epoch_ms;
        self.current_bin = next_bin;
    }
}

/// High-level O-RAN Management Plane (M-Plane) Engine.
pub struct OranMplaneEngine {
    pub state: OruOperationalState,
    pub running_ds: YangDatastore,
    pub candidate_ds: YangDatastore,
    pub startup_ds: YangDatastore,
    pub fault_mgr: FaultManager,
    pub pm_collector: PerformanceManagementCollector,
    next_msg_id: u32,
}

impl OranMplaneEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            state: OruOperationalState::PowerOn,
            running_ds: YangDatastore::new(),
            candidate_ds: YangDatastore::new(),
            startup_ds: YangDatastore::new(),
            fault_mgr: FaultManager::new(),
            pm_collector: PerformanceManagementCollector::new(0, 96), // 96 * 15min = 24 hours
            next_msg_id: 1,
        };
        engine.init_default_yang_tree();
        engine
    }

    fn init_default_yang_tree(&mut self) {
        // o-ran-hardware
        self.running_ds.set(
            "/o-ran-hardware:hardware/component[name='sfp-0']/temperature",
            YangValue::Float64(45.2),
        );
        self.running_ds.set(
            "/o-ran-hardware:hardware/component[name='sfp-0']/tx-power-dbm",
            YangValue::Float64(1.8),
        );
        self.running_ds.set(
            "/o-ran-hardware:hardware/component[name='sfp-0']/rx-power-dbm",
            YangValue::Float64(-3.4),
        );

        // o-ran-sync
        self.running_ds.set(
            "/o-ran-sync:sync/sync-status/state",
            YangValue::String("FREERUN".to_string()),
        );

        // Sync Candidate and Startup with Running
        self.candidate_ds.clone_from(&self.running_ds);
        self.startup_ds.clone_from(&self.running_ds);
    }

    /// Attempts state transition with guard checks.
    pub fn transition_state(&mut self, next: OruOperationalState) -> Result<(), &'static str> {
        if !self.state.can_transition_to(next) {
            return Err("Invalid state transition according to O-RAN startup lifecycle");
        }

        // Additional guard conditions
        if next == OruOperationalState::Operational {
            if self
                .fault_mgr
                .get_active_alarms()
                .iter()
                .any(|a| a.severity == AlarmSeverity::Critical)
            {
                return Err("Cannot enter Operational state with active Critical alarms");
            }
        }

        self.state = next;
        Ok(())
    }

    /// Executes a NETCONF RPC against the requested datastore.
    pub fn execute_netconf_rpc(&mut self, rpc: OranMplaneRpc) -> OranMplaneRpcReply {
        let message_id = self.next_msg_id;
        self.next_msg_id += 1;

        match rpc {
            OranMplaneRpc::GetConfig {
                source,
                filter_prefix,
            } => {
                let ds = match source {
                    DatastoreTarget::Running => &self.running_ds,
                    DatastoreTarget::Candidate => &self.candidate_ds,
                    DatastoreTarget::Startup => &self.startup_ds,
                };
                let entries = match filter_prefix {
                    Some(prefix) => ds.filter_by_prefix(&prefix),
                    None => ds
                        .entries
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                };
                OranMplaneRpcReply::Data {
                    message_id,
                    entries,
                }
            }
            OranMplaneRpc::EditConfig {
                target,
                operation,
                path,
                value,
            } => {
                let ds = match target {
                    DatastoreTarget::Candidate => &mut self.candidate_ds,
                    DatastoreTarget::Running => &mut self.running_ds,
                    DatastoreTarget::Startup => &mut self.startup_ds,
                };

                match operation {
                    EditConfigOp::Merge | EditConfigOp::Replace => {
                        if let Some(val) = value {
                            ds.set(path, val);
                            OranMplaneRpcReply::Ok { message_id }
                        } else {
                            OranMplaneRpcReply::Error {
                                message_id,
                                error_tag: "missing-element",
                                error_message: "Value required for merge/replace".to_string(),
                            }
                        }
                    }
                    EditConfigOp::Create => {
                        if ds.get(&path).is_some() {
                            OranMplaneRpcReply::Error {
                                message_id,
                                error_tag: "data-exists",
                                error_message: format!("Node {} already exists", path),
                            }
                        } else if let Some(val) = value {
                            ds.set(path, val);
                            OranMplaneRpcReply::Ok { message_id }
                        } else {
                            OranMplaneRpcReply::Error {
                                message_id,
                                error_tag: "missing-element",
                                error_message: "Value required for create".to_string(),
                            }
                        }
                    }
                    EditConfigOp::Delete => {
                        if ds.delete(&path) {
                            OranMplaneRpcReply::Ok { message_id }
                        } else {
                            OranMplaneRpcReply::Error {
                                message_id,
                                error_tag: "data-missing",
                                error_message: format!("Node {} does not exist", path),
                            }
                        }
                    }
                }
            }
            OranMplaneRpc::Validate { source } => {
                let ds = match source {
                    DatastoreTarget::Running => &self.running_ds,
                    DatastoreTarget::Candidate => &self.candidate_ds,
                    DatastoreTarget::Startup => &self.startup_ds,
                };
                // Validate required namespaces
                if ds.get("/o-ran-sync:sync/sync-status/state").is_none() {
                    OranMplaneRpcReply::Error {
                        message_id,
                        error_tag: "missing-mandatory-node",
                        error_message: "Missing mandatory sync status node".to_string(),
                    }
                } else {
                    OranMplaneRpcReply::Ok { message_id }
                }
            }
            OranMplaneRpc::Commit => {
                // Two-phase commit: validate candidate, then copy candidate to running
                if self
                    .candidate_ds
                    .get("/o-ran-sync:sync/sync-status/state")
                    .is_none()
                {
                    return OranMplaneRpcReply::Error {
                        message_id,
                        error_tag: "validation-failed",
                        error_message: "Validation failed during commit".to_string(),
                    };
                }
                self.running_ds.clone_from(&self.candidate_ds);
                OranMplaneRpcReply::Ok { message_id }
            }
            OranMplaneRpc::DiscardChanges => {
                // Revert candidate back to running
                self.candidate_ds.clone_from(&self.running_ds);
                OranMplaneRpcReply::Ok { message_id }
            }
            OranMplaneRpc::CopyConfig { source, target } => {
                let source_ds = match source {
                    DatastoreTarget::Running => self.running_ds.clone(),
                    DatastoreTarget::Candidate => self.candidate_ds.clone(),
                    DatastoreTarget::Startup => self.startup_ds.clone(),
                };
                let target_ds = match target {
                    DatastoreTarget::Running => &mut self.running_ds,
                    DatastoreTarget::Candidate => &mut self.candidate_ds,
                    DatastoreTarget::Startup => &mut self.startup_ds,
                };
                target_ds.clone_from(&source_ds);
                OranMplaneRpcReply::Ok { message_id }
            }
        }
    }
}
