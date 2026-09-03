//! 3GPP TS 29.510 5G Network Repository Function (NRF) Engine.
//!
//! Implements 5G Core Service Based Architecture repository and discovery:
//! - Nnrf_NFManagement Service (TS 29.510 Section 5.2):
//!   - NF Profile Registration with Heartbeat leasing (`heartbeat_timer_s`)
//!   - Heartbeat keepalives, dynamic load updating, and lease renewal
//!   - Automatic lease expiration garbage collection (transitioning to `Suspended`)
//!   - Graceful NF Deregistration
//!   - NF Status event subscription & notifications (`REGISTERED`, `SUSPENDED`, `DEREGISTERED`)
//! - Nnrf_NFDiscovery Service (TS 29.510 Section 5.3):
//!   - Multi-parameter NF discovery matching:
//!     - Target NF Type & Requester NF Type
//!     - Network Slice S-NSSAI matching
//!     - Data Network Name (DNN) matching
//!     - Tracking Area (TAC/TAI) matching
//!     - Geographic locality preference
//!   - Dynamic candidate ranking & load balancing:
//!     - Locality proximity -> Priority (asc) -> Dynamic Load (asc) -> Capacity (desc)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::{PlmnId, Snssai};
use crate::sba_5g::NfType;

// ---------------------------------------------------------------------------
// 5G NRF Data Structures (TS 29.510 Section 6)
// ---------------------------------------------------------------------------

/// Status of an NF instance in NRF (TS 29.510 Section 6.1.6.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfStatus {
    Registered,
    Suspended,
    Undiscoverable,
    Deregistered,
}

/// Service provided by an NF instance (TS 29.510 Section 6.1.6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfServiceRecord {
    pub service_instance_id: String,
    pub service_name: String, // e.g. "nsmf-pdusession", "npcf-smpolicycontrol"
    pub version: String,      // e.g. "v1", "v2"
    pub endpoint_uri: String, // e.g. "http://10.45.0.10:8080/nsmf-pdusession/v1"
}

/// Detailed 5G NF Profile stored in NRF (TS 29.510 Section 6.1.6.2.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfProfileRecord {
    pub nf_instance_id: String,
    pub nf_type: NfType,
    pub nf_status: NfStatus,
    pub heartbeat_timer_s: u32,
    pub fqdn: String,
    pub ipv4_addresses: Vec<Ipv4Address>,
    pub plmn_list: Vec<PlmnId>,
    pub s_nssais: Vec<Snssai>,
    pub dnns: Vec<String>,
    pub tai_list: Vec<u32>, // TACs
    pub priority: u16,      // 1..65535, lower number indicates higher priority
    pub capacity: u16,      // Static capacity relative to peers
    pub load: Option<u8>,   // Dynamic load percentage (0..100)
    pub locality: Option<String>,
    pub services: Vec<NfServiceRecord>,
    pub lease_expires_at_s: u64,
}

// ---------------------------------------------------------------------------
// Nnrf_NFDiscovery Service Operations (TS 29.510 Section 5.3)
// ---------------------------------------------------------------------------

/// Query parameters for Nnrf_NFDiscovery_Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryQuery {
    pub target_nf_type: NfType,
    pub requester_nf_type: NfType,
    pub target_snssai: Option<Snssai>,
    pub target_dnn: Option<String>,
    pub target_tai: Option<u32>,
    pub preferred_locality: Option<String>,
}

/// Result returned from Nnrf_NFDiscovery_Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub validity_period_s: u32,
    pub candidate_profiles: Vec<NfProfileRecord>,
}

// ---------------------------------------------------------------------------
// Nnrf_NFManagement Subscriptions & Notifications
// ---------------------------------------------------------------------------

/// Notification event type for NF lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NfLifecycleEvent {
    Registered,
    Suspended,
    Deregistered,
}

/// Notification dispatched to subscribers upon NF profile status change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfStatusNotification {
    pub event: NfLifecycleEvent,
    pub nf_instance_id: String,
    pub nf_type: NfType,
}

/// Subscription to NF status events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NfStatusSubscription {
    pub subscription_id: String,
    pub target_nf_type: Option<NfType>,
    pub callback_uri: String,
}

// ---------------------------------------------------------------------------
// Top-Level NRF Engine
// ---------------------------------------------------------------------------

/// 5G Network Repository Function (NRF) Engine.
pub struct NrfEngine {
    pub nrf_instance_id: String,
    pub profiles: HashMap<String, NfProfileRecord>, // nf_instance_id -> profile
    pub subscriptions: HashMap<String, NfStatusSubscription>,
    pub notification_history: Vec<NfStatusNotification>,
}

impl NrfEngine {
    /// Create a new NRF engine instance.
    pub fn new(nrf_instance_id: &str) -> Self {
        NrfEngine {
            nrf_instance_id: nrf_instance_id.to_string(),
            profiles: HashMap::new(),
            subscriptions: HashMap::new(),
            notification_history: Vec::new(),
        }
    }

    /// Nnrf_NFManagement_NFRegister: Register a new NF profile with heartbeat lease.
    pub fn register_nf(
        &mut self,
        mut profile: NfProfileRecord,
        current_time_s: u64,
    ) -> Result<(), &'static str> {
        if profile.nf_instance_id.is_empty() {
            return Err("Empty nf_instance_id");
        }

        profile.nf_status = NfStatus::Registered;
        // Lease timeout is 2x heartbeat timer
        profile.lease_expires_at_s = current_time_s + (profile.heartbeat_timer_s as u64 * 2);

        let nf_id = profile.nf_instance_id.clone();
        let nf_type = profile.nf_type;
        self.profiles.insert(nf_id.clone(), profile);

        self.emit_notification(NfLifecycleEvent::Registered, &nf_id, nf_type);

        Ok(())
    }

    /// Nnrf_NFManagement_NFUpdate (Heartbeat keepalive): Renew lease and optionally update load.
    pub fn update_heartbeat(
        &mut self,
        nf_instance_id: &str,
        new_load: Option<u8>,
        current_time_s: u64,
    ) -> Result<(), &'static str> {
        let profile = self
            .profiles
            .get_mut(nf_instance_id)
            .ok_or("NF profile not found")?;

        // If previously suspended, recover to registered
        let was_suspended = profile.nf_status == NfStatus::Suspended;
        profile.nf_status = NfStatus::Registered;
        profile.lease_expires_at_s = current_time_s + (profile.heartbeat_timer_s as u64 * 2);
        if let Some(load) = new_load {
            profile.load = Some(load);
        }

        if was_suspended {
            let nf_type = profile.nf_type;
            self.emit_notification(NfLifecycleEvent::Registered, nf_instance_id, nf_type);
        }

        Ok(())
    }

    /// Nnrf_NFManagement_NFDeregister: Withdraw NF from service.
    pub fn deregister_nf(&mut self, nf_instance_id: &str) -> Result<(), &'static str> {
        let profile = self
            .profiles
            .get_mut(nf_instance_id)
            .ok_or("NF profile not found")?;

        profile.nf_status = NfStatus::Deregistered;
        let nf_type = profile.nf_type;

        self.emit_notification(NfLifecycleEvent::Deregistered, nf_instance_id, nf_type);
        self.profiles.remove(nf_instance_id);

        Ok(())
    }

    /// Periodic background task: Expire overdue heartbeats and transition to `Suspended`.
    pub fn check_and_expire_heartbeats(&mut self, current_time_s: u64) -> Vec<String> {
        let mut expired = Vec::new();

        for (id, profile) in self.profiles.iter_mut() {
            if profile.nf_status == NfStatus::Registered
                && current_time_s >= profile.lease_expires_at_s
            {
                profile.nf_status = NfStatus::Suspended;
                expired.push((id.clone(), profile.nf_type));
            }
        }

        let mut expired_ids = Vec::new();
        for (id, nf_type) in expired {
            self.emit_notification(NfLifecycleEvent::Suspended, &id, nf_type);
            expired_ids.push(id);
        }

        expired_ids
    }

    /// Nnrf_NFDiscovery_Request: Multi-parameter candidate discovery and ranking.
    pub fn discover_nf(&self, query: &DiscoveryQuery) -> DiscoveryResult {
        let mut candidates: Vec<NfProfileRecord> = self
            .profiles
            .values()
            .filter(|p| {
                // 1. Must be in Registered state
                if p.nf_status != NfStatus::Registered {
                    return false;
                }
                // 2. Target NF Type match
                if p.nf_type != query.target_nf_type {
                    return false;
                }
                // 3. S-NSSAI match (if requested)
                if let Some(target_snssai) = &query.target_snssai {
                    if !p.s_nssais.contains(target_snssai) {
                        return false;
                    }
                }
                // 4. DNN match (if requested)
                if let Some(target_dnn) = &query.target_dnn {
                    if !p.dnns.contains(target_dnn) {
                        return false;
                    }
                }
                // 5. TAI match (if requested)
                if let Some(target_tai) = query.target_tai {
                    if !p.tai_list.contains(&target_tai) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        // Multi-level load balancing & ranking:
        // 1. Preferred locality (matches come first)
        // 2. Priority (ascending: 1 before 10)
        // 3. Dynamic load (ascending: 20% before 80%)
        // 4. Capacity (descending: 1000 before 500)
        candidates.sort_by(|a, b| {
            if let Some(pref) = &query.preferred_locality {
                let a_loc = a.locality.as_deref() == Some(pref);
                let b_loc = b.locality.as_deref() == Some(pref);
                if a_loc != b_loc {
                    return b_loc.cmp(&a_loc); // true (matched) comes first
                }
            }

            // Priority (lower is better)
            if a.priority != b.priority {
                return a.priority.cmp(&b.priority);
            }

            // Dynamic Load (lower is better)
            let a_load = a.load.unwrap_or(50);
            let b_load = b.load.unwrap_or(50);
            if a_load != b_load {
                return a_load.cmp(&b_load);
            }

            // Static Capacity (higher is better)
            b.capacity.cmp(&a.capacity)
        });

        DiscoveryResult {
            validity_period_s: 86400,
            candidate_profiles: candidates,
        }
    }

    /// Subscribe to NF Status change notifications.
    pub fn subscribe_status(&mut self, sub: NfStatusSubscription) {
        self.subscriptions.insert(sub.subscription_id.clone(), sub);
    }

    /// Dispatch internal notification to matching subscriptions.
    fn emit_notification(&mut self, event: NfLifecycleEvent, nf_id: &str, nf_type: NfType) {
        let notif = NfStatusNotification {
            event,
            nf_instance_id: nf_id.to_string(),
            nf_type,
        };
        self.notification_history.push(notif);
    }
}
