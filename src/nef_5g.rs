//! 3GPP TS 29.522 / TS 23.502 5G Network Exposure Function (NEF) Engine.
//!
//! Implements 5G Core northbound exposure operations for external Application Functions (AF):
//! - Topology Hiding & Identifier Translation (TS 29.522 Section 4.4):
//!   - Bidirectional mapping between External Identifiers (GPSI / MSISDN) and Internal Identifiers (SUPI / IMSI)
//!   - Concealment of internal network architecture and NF addressing
//! - Nnef_EventExposure Service (TS 29.522 Section 5.3):
//!   - Subscriptions to UE network events:
//!     - `LocationReport` (Tracking Area, Cell ID, geographic coordinates)
//!     - `LossOfConnectivity` (Radio link loss, PSM sleep)
//!     - `UeReachability` (RRC Connected, waking from DRX)
//!     - `RoamingStatus` (VPLMN roaming detection)
//!     - `CommunicationFailure` (Signalling/bearer drop)
//!   - Real-time notification dispatching to external AF webhooks with anonymized GPSI
//! - Nnef_DeviceTriggering Service (TS 29.522 Section 5.2):
//!   - Delivery of application trigger payloads to dormant IoT devices via NAS / SMS

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G NEF Event Types & Enums (TS 29.522 Section 6)
// ---------------------------------------------------------------------------

/// 3GPP Standard NEF Exposure Event Type (TS 29.522 Section 6.1.6.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NefEvent {
    LocationReport,
    LossOfConnectivity,
    UeReachability,
    RoamingStatus,
    CommunicationFailure,
}

/// Geographic coordinates for UE Location reporting.
#[derive(Debug, Clone, PartialEq)]
pub struct GeoLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub altitude_m: Option<f32>,
}

/// Detailed location data reported by 5G Core.
#[derive(Debug, Clone, PartialEq)]
pub struct LocationInfo {
    pub tai: u32,
    pub cell_id: u32,
    pub geo_coordinates: Option<GeoLocation>,
}

/// Internal 5G Core network event payload ingested by NEF.
#[derive(Debug, Clone, PartialEq)]
pub enum InternalEventPayload {
    Location(LocationInfo),
    LossOfConnectivity {
        cause: String,
    },
    UeReachability {
        is_reachable: bool,
    },
    Roaming {
        vplmn_mcc: [u8; 3],
        vplmn_mnc: [u8; 3],
    },
    CommunicationFailure {
        failure_code: u16,
    },
}

/// External notification dispatched by NEF to AF (TS 29.522 Section 6.1.6.2.3).
#[derive(Debug, Clone, PartialEq)]
pub struct NefEventNotification {
    pub subscription_id: String,
    pub gpsi: String, // Anonymized external identifier (SUPI never exposed!)
    pub event: NefEvent,
    pub payload: InternalEventPayload,
    pub timestamp_epoch_s: u64,
}

// ---------------------------------------------------------------------------
// Nnef_EventExposure Service Operations (TS 29.522 Section 5.3)
// ---------------------------------------------------------------------------

/// Subscription created by an external AF (POST /subscriptions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NefEventSubscription {
    pub subscription_id: String,
    pub af_id: String,
    pub gpsi: Option<String>,
    pub external_group_id: Option<String>,
    pub events: Vec<NefEvent>,
    pub notification_destination_uri: String,
    pub max_reports: Option<u32>,
    pub reports_delivered: u32,
}

// ---------------------------------------------------------------------------
// Nnef_DeviceTriggering Service Operations (TS 29.522 Section 5.2)
// ---------------------------------------------------------------------------

/// Device Trigger status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceTriggerStatus {
    Submitted,
    Delivered,
    DeviceUnreachable,
    Expired,
}

/// Device trigger request from AF (POST /device-trigger).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTriggerRequest {
    pub trigger_id: String,
    pub af_id: String,
    pub gpsi: String,
    pub reference_number: u32,
    pub trigger_payload: Vec<u8>,
    pub validity_period_s: u32,
    pub submission_time_s: u64,
}

/// Device trigger delivery record maintained in NEF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTriggerRecord {
    pub trigger_id: String,
    pub af_id: String,
    pub gpsi: String,
    pub supi: String,
    pub reference_number: u32,
    pub trigger_payload: Vec<u8>,
    pub status: DeviceTriggerStatus,
    pub expires_at_s: u64,
}

// ---------------------------------------------------------------------------
// Top-Level NEF Engine
// ---------------------------------------------------------------------------

/// 5G Network Exposure Function (NEF) Engine.
pub struct NefEngine {
    pub nef_instance_id: String,
    /// Topology Hiding: GPSI (External) <-> SUPI (Internal)
    pub gpsi_to_supi: HashMap<String, String>,
    pub supi_to_gpsi: HashMap<String, String>,
    /// Authorized Application Functions: af_id -> allowed_events
    pub authorized_afs: HashMap<String, Vec<NefEvent>>,
    /// Active Event Subscriptions: sub_id -> subscription
    pub subscriptions: HashMap<String, NefEventSubscription>,
    /// Device Trigger records: trigger_id -> record
    pub device_triggers: HashMap<String, DeviceTriggerRecord>,
    pub notification_history: Vec<NefEventNotification>,
}

impl NefEngine {
    /// Create a new NEF engine instance.
    pub fn new(nef_instance_id: &str) -> Self {
        NefEngine {
            nef_instance_id: nef_instance_id.to_string(),
            gpsi_to_supi: HashMap::new(),
            supi_to_gpsi: HashMap::new(),
            authorized_afs: HashMap::new(),
            subscriptions: HashMap::new(),
            device_triggers: HashMap::new(),
            notification_history: Vec::new(),
        }
    }

    /// Provision bidirectional mapping between external GPSI and internal SUPI.
    pub fn provision_identifier_mapping(&mut self, gpsi: &str, supi: &str) {
        self.gpsi_to_supi.insert(gpsi.to_string(), supi.to_string());
        self.supi_to_gpsi.insert(supi.to_string(), gpsi.to_string());
    }

    /// Authorize an external Application Function (AF) for specific exposure events.
    pub fn authorize_af(&mut self, af_id: &str, allowed_events: Vec<NefEvent>) {
        self.authorized_afs
            .insert(af_id.to_string(), allowed_events);
    }

    // -----------------------------------------------------------------------
    // Nnef_EventExposure Service (TS 29.522 Section 5.3)
    // -----------------------------------------------------------------------

    /// Nnef_EventExposure_Subscribe: Register event subscription requested by AF.
    pub fn create_event_subscription(
        &mut self,
        sub: NefEventSubscription,
    ) -> Result<String, &'static str> {
        // 1. Validate AF authorization
        let allowed = self
            .authorized_afs
            .get(&sub.af_id)
            .ok_or("Unauthorized Application Function (AF)")?;

        for ev in &sub.events {
            if !allowed.contains(ev) {
                return Err("AF not authorized for requested event type");
            }
        }

        // 2. If GPSI is provided, verify it translates to a valid SUPI
        if let Some(gpsi) = &sub.gpsi {
            if !self.gpsi_to_supi.contains_key(gpsi) {
                return Err("Unknown GPSI identifier");
            }
        }

        let sub_id = sub.subscription_id.clone();
        self.subscriptions.insert(sub_id.clone(), sub);

        Ok(sub_id)
    }

    /// Nnef_EventExposure_Unsubscribe.
    pub fn delete_event_subscription(&mut self, sub_id: &str) -> bool {
        self.subscriptions.remove(sub_id).is_some()
    }

    /// Ingest internal 5G Core network event (from AMF/SMF/UDM) and notify matching AFs.
    pub fn ingest_network_event(
        &mut self,
        supi: &str,
        event: NefEvent,
        payload: InternalEventPayload,
        timestamp_epoch_s: u64,
    ) {
        // Topology hiding: resolve internal SUPI to external GPSI
        let gpsi = match self.supi_to_gpsi.get(supi) {
            Some(g) => g.clone(),
            None => return, // Unknown subscriber to external domain
        };

        let mut expired_subs = Vec::new();

        for (sub_id, sub) in self.subscriptions.iter_mut() {
            // Check if subscription matches target GPSI
            if let Some(target_gpsi) = &sub.gpsi {
                if target_gpsi != &gpsi {
                    continue;
                }
            }

            // Check if event type matches
            if sub.events.contains(&event) {
                sub.reports_delivered += 1;

                self.notification_history.push(NefEventNotification {
                    subscription_id: sub_id.clone(),
                    gpsi: gpsi.clone(), // Topology hiding: SUPI is concealed!
                    event,
                    payload: payload.clone(),
                    timestamp_epoch_s,
                });

                if let Some(max) = sub.max_reports {
                    if sub.reports_delivered >= max {
                        expired_subs.push(sub_id.clone());
                    }
                }
            }
        }

        for id in expired_subs {
            self.subscriptions.remove(&id);
        }
    }

    // -----------------------------------------------------------------------
    // Nnef_DeviceTriggering Service (TS 29.522 Section 5.2)
    // -----------------------------------------------------------------------

    /// Submit a device trigger to wake or send payload to an IoT device.
    pub fn submit_device_trigger(
        &mut self,
        req: &DeviceTriggerRequest,
    ) -> Result<DeviceTriggerStatus, &'static str> {
        // 1. Verify AF authorization
        if !self.authorized_afs.contains_key(&req.af_id) {
            return Err("Unauthorized Application Function for Device Triggering");
        }

        // 2. Resolve GPSI to internal SUPI
        let supi = self
            .gpsi_to_supi
            .get(&req.gpsi)
            .ok_or("Unknown target device GPSI")?;

        let record = DeviceTriggerRecord {
            trigger_id: req.trigger_id.clone(),
            af_id: req.af_id.clone(),
            gpsi: req.gpsi.clone(),
            supi: supi.clone(),
            reference_number: req.reference_number,
            trigger_payload: req.trigger_payload.clone(),
            status: DeviceTriggerStatus::Submitted,
            expires_at_s: req.submission_time_s + req.validity_period_s as u64,
        };

        self.device_triggers.insert(req.trigger_id.clone(), record);

        Ok(DeviceTriggerStatus::Submitted)
    }

    /// Update status of a device trigger (e.g. after AMF delivers over NAS).
    pub fn update_device_trigger_status(
        &mut self,
        trigger_id: &str,
        new_status: DeviceTriggerStatus,
    ) -> bool {
        if let Some(rec) = self.device_triggers.get_mut(trigger_id) {
            rec.status = new_status;
            true
        } else {
            false
        }
    }
}
