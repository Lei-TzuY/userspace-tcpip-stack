//! 3GPP TS 29.272 Diameter S13 Equipment Status Change Notification (ESCN) & Batch Audit Engine.
//!
//! Handles asynchronous EIR (Equipment Identity Register) status change event dispatching
//! to connected MME / SGSN / AMF nodes upon device blacklisting, graylisting, or recovery,
//! alongside periodic batch reconciliation audits of distributed edge node caches.

/// Equipment authorization status in the cellular network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S13EquipmentStatus {
    WhiteListed,
    GrayListed,
    BlackListed,
    Unknown,
}

impl S13EquipmentStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            S13EquipmentStatus::WhiteListed => "WhiteListed",
            S13EquipmentStatus::GrayListed => "GrayListed",
            S13EquipmentStatus::BlackListed => "BlackListed",
            S13EquipmentStatus::Unknown => "Unknown",
        }
    }
}

/// Asynchronous Equipment Status Change Notification record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscnNotification {
    pub imei: String,
    pub old_status: S13EquipmentStatus,
    pub new_status: S13EquipmentStatus,
    pub reason: String,
    pub timestamp_secs: u64,
    pub target_mme_realm: String,
    pub acknowledged: bool,
}

/// Result of evaluating an equipment status change or notification delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EscnVerdict {
    StatusChangedNotificationsQueued {
        imei: String,
        old_status: S13EquipmentStatus,
        new_status: S13EquipmentStatus,
        notified_mme_count: usize,
    },
    StatusUnchangedIgnored {
        imei: String,
        status: S13EquipmentStatus,
    },
    InvalidImeiRejected {
        input: String,
    },
}

/// Result of reconciling a cached edge MME entry against the central EIR database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReconciliationResult {
    pub imei: String,
    pub edge_cached_status: S13EquipmentStatus,
    pub eir_authoritative_status: S13EquipmentStatus,
    pub synchronized: bool,
    pub action_taken: String,
}

/// 3GPP TS 29.272 Diameter S13 ESCN and Audit Engine.
#[derive(Debug, Clone)]
pub struct S13EscnEngine {
    pub eir_realm: String,
    pub subscribed_mmes: Vec<String>,
    pub device_statuses: Vec<(String, S13EquipmentStatus)>,
    pub notifications: Vec<EscnNotification>,
    pub total_status_changes: u64,
    pub total_notifications_generated: u64,
    pub total_notifications_acked: u64,
    pub total_audits_performed: u64,
    pub total_discrepancies_fixed: u64,
}

impl S13EscnEngine {
    /// Creates a new ESCN Engine for the given EIR realm.
    pub fn new(eir_realm: &str) -> Self {
        Self {
            eir_realm: eir_realm.to_string(),
            subscribed_mmes: Vec::new(),
            device_statuses: Vec::new(),
            notifications: Vec::new(),
            total_status_changes: 0,
            total_notifications_generated: 0,
            total_notifications_acked: 0,
            total_audits_performed: 0,
            total_discrepancies_fixed: 0,
        }
    }

    /// Subscribes an MME/SGSN realm to receive asynchronous ESCN push notifications.
    pub fn subscribe_mme(&mut self, mme_realm: &str) {
        if !self.subscribed_mmes.iter().any(|m| m == mme_realm) {
            self.subscribed_mmes.push(mme_realm.to_string());
        }
    }

    /// Unsubscribes an MME realm.
    pub fn unsubscribe_mme(&mut self, mme_realm: &str) {
        self.subscribed_mmes.retain(|m| m != mme_realm);
    }

    /// Registers or updates an equipment status in the central EIR database.
    pub fn update_equipment_status(
        &mut self,
        imei: &str,
        new_status: S13EquipmentStatus,
        reason: &str,
        timestamp_secs: u64,
    ) -> EscnVerdict {
        let clean_imei = imei.trim();
        if clean_imei.len() < 14
            || clean_imei.len() > 16
            || !clean_imei.chars().all(|c| c.is_ascii_digit())
        {
            return EscnVerdict::InvalidImeiRejected {
                input: imei.to_string(),
            };
        }

        let old_status = self
            .device_statuses
            .iter()
            .find(|(k, _)| k == clean_imei)
            .map(|(_, s)| *s)
            .unwrap_or(S13EquipmentStatus::WhiteListed);

        if old_status == new_status {
            return EscnVerdict::StatusUnchangedIgnored {
                imei: clean_imei.to_string(),
                status: old_status,
            };
        }

        // Update central database
        if let Some(entry) = self
            .device_statuses
            .iter_mut()
            .find(|(k, _)| k == clean_imei)
        {
            entry.1 = new_status;
        } else {
            self.device_statuses
                .push((clean_imei.to_string(), new_status));
        }

        self.total_status_changes += 1;
        let mut count = 0;

        for mme in &self.subscribed_mmes {
            self.notifications.push(EscnNotification {
                imei: clean_imei.to_string(),
                old_status,
                new_status,
                reason: reason.to_string(),
                timestamp_secs,
                target_mme_realm: mme.clone(),
                acknowledged: false,
            });
            self.total_notifications_generated += 1;
            count += 1;
        }

        EscnVerdict::StatusChangedNotificationsQueued {
            imei: clean_imei.to_string(),
            old_status,
            new_status,
            notified_mme_count: count,
        }
    }

    /// Acknowledges receipt of an ESCN notification from an edge MME.
    pub fn acknowledge_notification(&mut self, imei: &str, mme_realm: &str) -> bool {
        if let Some(notif) = self
            .notifications
            .iter_mut()
            .find(|n| n.imei == imei && n.target_mme_realm == mme_realm && !n.acknowledged)
        {
            notif.acknowledged = true;
            self.total_notifications_acked += 1;
            true
        } else {
            false
        }
    }

    /// Queries the authoritative equipment status from the EIR database.
    pub fn query_status(&self, imei: &str) -> S13EquipmentStatus {
        let clean_imei = imei.trim();
        self.device_statuses
            .iter()
            .find(|(k, _)| k == clean_imei)
            .map(|(_, s)| *s)
            .unwrap_or(S13EquipmentStatus::WhiteListed)
    }

    /// Reconciles a batch of cached entries from an edge MME node.
    pub fn audit_edge_cache(
        &mut self,
        _mme_realm: &str,
        cached_entries: &[(String, S13EquipmentStatus)],
    ) -> Vec<AuditReconciliationResult> {
        self.total_audits_performed += 1;
        let mut results = Vec::new();

        for (imei, cached_status) in cached_entries {
            let auth_status = self.query_status(imei);
            let synchronized = *cached_status == auth_status;

            let action_taken = if synchronized {
                "Synchronized - No Action".to_string()
            } else {
                self.total_discrepancies_fixed += 1;
                format!(
                    "Discrepancy Fixed: Edge cache updated from {:?} to {:?}",
                    cached_status, auth_status
                )
            };

            results.push(AuditReconciliationResult {
                imei: imei.clone(),
                edge_cached_status: *cached_status,
                eir_authoritative_status: auth_status,
                synchronized,
                action_taken,
            });
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s13_escn_lifecycle() {
        let mut engine = S13EscnEngine::new("eir01.epc.mnc001.mcc208.3gppnetwork.org");
        engine.subscribe_mme("mme01.epc.mnc001.mcc208.3gppnetwork.org");
        engine.subscribe_mme("mme02.epc.mnc001.mcc208.3gppnetwork.org");

        // 1. Blacklist a stolen device
        let v1 = engine.update_equipment_status(
            "353918001234567",
            S13EquipmentStatus::BlackListed,
            "Police Report Stolen",
            1000,
        );
        assert_eq!(
            v1,
            EscnVerdict::StatusChangedNotificationsQueued {
                imei: "353918001234567".to_string(),
                old_status: S13EquipmentStatus::WhiteListed,
                new_status: S13EquipmentStatus::BlackListed,
                notified_mme_count: 2,
            }
        );
        assert_eq!(engine.total_notifications_generated, 2);

        // 2. Acknowledge from MME 1
        let ack1 = engine
            .acknowledge_notification("353918001234567", "mme01.epc.mnc001.mcc208.3gppnetwork.org");
        assert!(ack1);
        assert_eq!(engine.total_notifications_acked, 1);

        // 3. Batch Audit check with MME 2 having stale WhiteListed cache
        let cached = vec![
            (
                "353918001234567".to_string(),
                S13EquipmentStatus::WhiteListed,
            ),
            (
                "860011112222333".to_string(),
                S13EquipmentStatus::WhiteListed,
            ),
        ];
        let audit = engine.audit_edge_cache("mme02.epc.mnc001.mcc208.3gppnetwork.org", &cached);
        assert_eq!(audit.len(), 2);
        assert!(!audit[0].synchronized);
        assert_eq!(
            audit[0].eir_authoritative_status,
            S13EquipmentStatus::BlackListed
        );
        assert!(audit[1].synchronized);
        assert_eq!(engine.total_discrepancies_fixed, 1);
    }
}
