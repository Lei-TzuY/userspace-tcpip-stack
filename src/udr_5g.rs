//! 3GPP TS 29.504 / TS 29.505 5G Unified Data Repository (UDR) Engine.
//!
//! Implements cloud-native 5G decoupled state and storage operations:
//! - Nudr_DataRepository Service (TS 29.504 Section 5.2):
//!   - Subscription Data Management (UDM backing):
//!     - Authentication data (5G-AKA credentials: K, OPc, SQN)
//!     - Access & Mobility data (Subscribed S-NSSAIs, Subscribed UE-AMBR)
//!     - Session Management data (DNN configs, default 5QI, Session-AMBR, ARP)
//!   - Policy Data Management (PCF backing):
//!     - SM Policy data, UE Route Selection Policies (URSP)
//!   - Exposure Data Management (NEF backing):
//!     - AF Traffic Influence data, DNAI steering rules, Edge Breakout paths
//!   - Application Data Management (AF/NEF backing):
//!     - Packet Flow Descriptions (PFD) for Layer-7 Deep Packet Inspection (DPI)
//!   - Asynchronous Data Change Subscriptions & Notifications (`Nudr_DataRepository_Notify`)

use std::collections::HashMap;

use crate::ipv4::Ipv4Address;
use crate::ngap_5g::Snssai;

// ---------------------------------------------------------------------------
// 5G UDR Data Models (TS 29.505 Section 5 & 6)
// ---------------------------------------------------------------------------

/// 5G Authentication Method (TS 29.503 Section 6.1.6.3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    FiveGAka,
    EapAkaPrime,
}

/// Authentication credential data stored in UDR for UDM/AUSF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationData {
    pub supi: String,
    pub auth_method: AuthMethod,
    pub k: [u8; 16],
    pub opc: [u8; 16],
    pub sqn: u64,
}

/// Access and Mobility subscription data stored in UDR for AMF/UDM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessAndMobilityData {
    pub supi: String,
    pub subscribed_snssais: Vec<Snssai>,
    pub ue_ambr_dl_kbps: u32,
    pub ue_ambr_ul_kbps: u32,
}

/// Session Management subscription data stored in UDR for SMF/UDM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionManagementData {
    pub supi: String,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub default_5qi: u8,
    pub session_ambr_dl_kbps: u32,
    pub session_ambr_ul_kbps: u32,
    pub arp_priority_level: u8,
}

/// Policy Data stored in UDR for PCF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmPolicyData {
    pub supi: String,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub authorized_pcc_rules: Vec<String>,
    pub max_bandwidth_dl_kbps: Option<u32>,
    pub max_bandwidth_ul_kbps: Option<u32>,
}

/// Exposure Data stored in UDR for NEF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficInfluenceData {
    pub af_trans_id: String,
    pub dnn: String,
    pub s_nssai: Snssai,
    pub target_dnai: String,
    pub edge_breakout_ip: Ipv4Address,
}

/// Application Data Packet Flow Description (PFD) for L7 DPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFlowDescription {
    pub app_id: String,
    pub flow_descriptions: Vec<String>,
    pub domain_names: Vec<String>, // e.g. ["*.youtube.com", "*.googlevideo.com"]
}

// ---------------------------------------------------------------------------
// Nudr_DataRepository Notifications (TS 29.504 Section 5.3)
// ---------------------------------------------------------------------------

/// Type of data modified in UDR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdrDataType {
    SubscriptionAuth,
    SubscriptionAm,
    SubscriptionSm,
    PolicySm,
    ExposureTrafficInfluence,
    ApplicationPfd,
}

/// Subscription to data change events in UDR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdrDataChangeSubscription {
    pub subscription_id: String,
    pub supi: Option<String>,
    pub data_type: UdrDataType,
    pub callback_uri: String,
}

/// Notification dispatched when data in UDR changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdrDataChangeNotification {
    pub subscription_id: String,
    pub data_type: UdrDataType,
    pub supi: Option<String>,
    pub timestamp_epoch_s: u64,
}

// ---------------------------------------------------------------------------
// Top-Level UDR Engine
// ---------------------------------------------------------------------------

/// 5G Unified Data Repository (UDR) Engine.
pub struct UdrEngine {
    pub udr_instance_id: String,
    /// Subscription Data: supi -> AuthenticationData
    pub auth_data: HashMap<String, AuthenticationData>,
    /// Access & Mobility: supi -> AccessAndMobilityData
    pub am_data: HashMap<String, AccessAndMobilityData>,
    /// Session Management: (supi, dnn, Snssai) -> SessionManagementData
    pub sm_data: HashMap<(String, String, Snssai), SessionManagementData>,
    /// Policy Data: (supi, dnn, Snssai) -> SmPolicyData
    pub policy_data: HashMap<(String, String, Snssai), SmPolicyData>,
    /// Exposure Data: af_trans_id -> TrafficInfluenceData
    pub exposure_data: HashMap<String, TrafficInfluenceData>,
    /// Application Data: app_id -> PacketFlowDescription
    pub pfd_data: HashMap<String, PacketFlowDescription>,
    /// Data change event subscriptions
    pub subscriptions: HashMap<String, UdrDataChangeSubscription>,
    pub notification_history: Vec<UdrDataChangeNotification>,
}

impl UdrEngine {
    /// Create a new UDR engine instance.
    pub fn new(udr_instance_id: &str) -> Self {
        UdrEngine {
            udr_instance_id: udr_instance_id.to_string(),
            auth_data: HashMap::new(),
            am_data: HashMap::new(),
            sm_data: HashMap::new(),
            policy_data: HashMap::new(),
            exposure_data: HashMap::new(),
            pfd_data: HashMap::new(),
            subscriptions: HashMap::new(),
            notification_history: Vec::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Subscription Data Management (TS 29.505 Section 5.2)
    // -----------------------------------------------------------------------

    pub fn set_auth_data(&mut self, data: AuthenticationData, timestamp_s: u64) {
        let supi = data.supi.clone();
        self.auth_data.insert(supi.clone(), data);
        self.notify_change(UdrDataType::SubscriptionAuth, Some(&supi), timestamp_s);
    }

    pub fn get_auth_data(&self, supi: &str) -> Option<&AuthenticationData> {
        self.auth_data.get(supi)
    }

    pub fn set_am_data(&mut self, data: AccessAndMobilityData, timestamp_s: u64) {
        let supi = data.supi.clone();
        self.am_data.insert(supi.clone(), data);
        self.notify_change(UdrDataType::SubscriptionAm, Some(&supi), timestamp_s);
    }

    pub fn get_am_data(&self, supi: &str) -> Option<&AccessAndMobilityData> {
        self.am_data.get(supi)
    }

    pub fn set_sm_data(&mut self, data: SessionManagementData, timestamp_s: u64) {
        let key = (data.supi.clone(), data.dnn.clone(), data.s_nssai.clone());
        let supi = data.supi.clone();
        self.sm_data.insert(key, data);
        self.notify_change(UdrDataType::SubscriptionSm, Some(&supi), timestamp_s);
    }

    pub fn get_sm_data(
        &self,
        supi: &str,
        dnn: &str,
        snssai: &Snssai,
    ) -> Option<&SessionManagementData> {
        self.sm_data
            .get(&(supi.to_string(), dnn.to_string(), snssai.clone()))
    }

    // -----------------------------------------------------------------------
    // Policy Data Management (TS 29.505 Section 5.3)
    // -----------------------------------------------------------------------

    pub fn set_policy_data(&mut self, data: SmPolicyData, timestamp_s: u64) {
        let key = (data.supi.clone(), data.dnn.clone(), data.s_nssai.clone());
        let supi = data.supi.clone();
        self.policy_data.insert(key, data);
        self.notify_change(UdrDataType::PolicySm, Some(&supi), timestamp_s);
    }

    pub fn get_policy_data(&self, supi: &str, dnn: &str, snssai: &Snssai) -> Option<&SmPolicyData> {
        self.policy_data
            .get(&(supi.to_string(), dnn.to_string(), snssai.clone()))
    }

    // -----------------------------------------------------------------------
    // Exposure Data Management (TS 29.505 Section 5.4)
    // -----------------------------------------------------------------------

    pub fn set_exposure_data(&mut self, data: TrafficInfluenceData, timestamp_s: u64) {
        let trans_id = data.af_trans_id.clone();
        self.exposure_data.insert(trans_id, data);
        self.notify_change(UdrDataType::ExposureTrafficInfluence, None, timestamp_s);
    }

    pub fn get_exposure_data(&self, af_trans_id: &str) -> Option<&TrafficInfluenceData> {
        self.exposure_data.get(af_trans_id)
    }

    pub fn find_traffic_influence(&self, dnn: &str, snssai: &Snssai) -> Vec<&TrafficInfluenceData> {
        self.exposure_data
            .values()
            .filter(|d| d.dnn == dnn && &d.s_nssai == snssai)
            .collect()
    }

    // -----------------------------------------------------------------------
    // Application Data Management (PFD / L7 DPI) (TS 29.505 Section 5.5)
    // -----------------------------------------------------------------------

    pub fn set_pfd(&mut self, pfd: PacketFlowDescription, timestamp_s: u64) {
        let app_id = pfd.app_id.clone();
        self.pfd_data.insert(app_id, pfd);
        self.notify_change(UdrDataType::ApplicationPfd, None, timestamp_s);
    }

    pub fn get_pfd(&self, app_id: &str) -> Option<&PacketFlowDescription> {
        self.pfd_data.get(app_id)
    }

    /// Match incoming L7 domain name against provisioned PFDs for deep packet inspection.
    pub fn match_app_by_domain(&self, host: &str) -> Option<String> {
        for pfd in self.pfd_data.values() {
            for domain in &pfd.domain_names {
                if domain.starts_with("*.") {
                    let suffix = &domain[2..];
                    if host == suffix || host.ends_with(&format!(".{}", suffix)) {
                        return Some(pfd.app_id.clone());
                    }
                } else if domain == host {
                    return Some(pfd.app_id.clone());
                }
            }
        }
        None
    }

    // -----------------------------------------------------------------------
    // Subscriptions & Change Notifications
    // -----------------------------------------------------------------------

    pub fn subscribe(&mut self, sub: UdrDataChangeSubscription) {
        self.subscriptions.insert(sub.subscription_id.clone(), sub);
    }

    pub fn unsubscribe(&mut self, subscription_id: &str) -> bool {
        self.subscriptions.remove(subscription_id).is_some()
    }

    fn notify_change(&mut self, data_type: UdrDataType, supi: Option<&str>, timestamp_s: u64) {
        let mut triggered = Vec::new();

        for (id, sub) in self.subscriptions.iter() {
            if sub.data_type == data_type {
                if let (Some(sub_supi), Some(curr_supi)) = (&sub.supi, supi) {
                    if sub_supi != curr_supi {
                        continue;
                    }
                }
                triggered.push(id.clone());
            }
        }

        for id in triggered {
            self.notification_history.push(UdrDataChangeNotification {
                subscription_id: id,
                data_type,
                supi: supi.map(|s| s.to_string()),
                timestamp_epoch_s: timestamp_s,
            });
        }
    }
}
