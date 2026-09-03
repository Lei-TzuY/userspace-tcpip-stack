//! 3GPP TS 29.574 / TS 23.288 Release 17 5G Data Collection Coordination Function (DCCF) Engine.
//!
//! Implements 5G Centralized Telemetry Coordination & Redundancy Elimination:
//! - Ndccf_DataManagement Service (TS 29.574 Section 5.2):
//!   - Telemetry subscription lifecycle with deduplication across multiple consumers (`subscribe` / `unsubscribe`)
//!   - Multi-consumer data fanout (collect once from AMF/SMF/UPF, distribute to multiple NWDAF instances)
//!   - Conditional threshold filtering (e.g. only trigger on high slice load or QoS degradation)
//!   - Dual delivery targeting: Direct consumer callback vs Direct ADRF big-data lake routing
//!   - Automatic source collector tear-down when all consumer subscriptions expire

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G DCCF Enums & Data Structures (TS 29.574 Section 6 / TS 23.288)
// ---------------------------------------------------------------------------

/// Data Delivery Target Destination (TS 29.574 Section 6.1.6.2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDeliveryTarget {
    /// Direct delivery to consumer NF (e.g. NWDAF HTTP/2 notification callback).
    DirectConsumer { callback_uri: String },
    /// Routing to ADRF instance for long-term historical storage.
    AdrfStorage { adrf_id: String },
}

/// Telemetry Filtering Specification.
#[derive(Debug, Clone, PartialEq)]
pub struct DataFilterSpec {
    pub data_domain: String, // e.g. "SliceLoadLevel", "UeMobility", "NfLoad"
    pub target_id: Option<String>, // e.g. S-NSSAI "01-000001" or SUPI
    pub min_threshold: Option<f64>, // Filter out values below min
    pub max_threshold: Option<f64>, // Filter out values above max
}

/// Active Consumer Subscription Record.
#[derive(Debug, Clone, PartialEq)]
pub struct DccfSubscription {
    pub sub_id: String,
    pub consumer_id: String,
    pub filter: DataFilterSpec,
    pub target: DataDeliveryTarget,
}

/// Dispatched Telemetry Notification Event.
#[derive(Debug, Clone, PartialEq)]
pub struct TelemetryEvent {
    pub sub_id: String,
    pub consumer_id: String,
    pub target: DataDeliveryTarget,
    pub data_domain: String,
    pub target_id: Option<String>,
    pub metric_name: String,
    pub value: f64,
    pub timestamp_epoch_s: u64,
}

/// DCCF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DccfError {
    SubscriptionNotFound,
    InvalidFilterSpec(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level 5G-DCCF Engine
// ---------------------------------------------------------------------------

/// 5G Data Collection Coordination Function (DCCF).
pub struct DccfEngine {
    pub dccf_id: String,
    pub next_sub_counter: u64,
    /// Active Subscriptions: sub_id -> DccfSubscription
    pub subscriptions: HashMap<String, DccfSubscription>,
    /// Multiplexed Source Collectors: (source_nf, data_domain, target_id) -> Vec<sub_id>
    pub source_to_subscribers: HashMap<(String, String, Option<String>), Vec<String>>,
}

impl DccfEngine {
    /// Create a new 5G-DCCF engine instance.
    pub fn new(dccf_id: &str) -> Self {
        DccfEngine {
            dccf_id: dccf_id.to_string(),
            next_sub_counter: 1,
            subscriptions: HashMap::new(),
            source_to_subscribers: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Ndccf_DataManagement Service Operations (TS 29.574 Section 5.2)
    // -----------------------------------------------------------------------

    /// Subscribe to coordinated data collection (TS 29.574 Section 5.2.2.2).
    /// Deduplicates source NF collection if identical filters already exist.
    pub fn subscribe(
        &mut self,
        consumer_id: &str,
        source_nf_type: &str,
        filter: DataFilterSpec,
        target: DataDeliveryTarget,
    ) -> Result<String, DccfError> {
        if filter.data_domain.is_empty() {
            return Err(DccfError::InvalidFilterSpec("Data domain cannot be empty"));
        }

        let sub_id = format!("dccf-sub-{:08x}", self.next_sub_counter);
        self.next_sub_counter += 1;

        let key = (
            source_nf_type.to_uppercase(),
            filter.data_domain.clone(),
            filter.target_id.clone(),
        );

        self.source_to_subscribers
            .entry(key)
            .or_default()
            .push(sub_id.clone());

        let sub = DccfSubscription {
            sub_id: sub_id.clone(),
            consumer_id: consumer_id.to_string(),
            filter,
            target,
        };

        self.subscriptions.insert(sub_id.clone(), sub);
        Ok(sub_id)
    }

    /// Unsubscribe from data collection and automatically tear down source collector if orphaned.
    pub fn unsubscribe(&mut self, sub_id: &str) -> Result<(), DccfError> {
        let sub = self
            .subscriptions
            .remove(sub_id)
            .ok_or(DccfError::SubscriptionNotFound)?;

        // Clean up multiplexed source map
        for subs in self.source_to_subscribers.values_mut() {
            subs.retain(|s| s != sub_id);
        }

        // Retain only non-empty collectors
        self.source_to_subscribers
            .retain(|_, subs| !subs.is_empty());

        let _ = sub;
        Ok(())
    }

    /// Ingest raw metric from a Source NF and distribute to matching subscribers.
    /// Returns the list of dispatched telemetry events.
    pub fn ingest_source_telemetry(
        &self,
        source_nf_type: &str,
        data_domain: &str,
        target_id: Option<&str>,
        metric_name: &str,
        value: f64,
        timestamp_epoch_s: u64,
    ) -> Vec<TelemetryEvent> {
        let mut events = Vec::new();
        let target_string = target_id.map(|s| s.to_string());

        // Check specific target subscription or wildcard target
        let candidates = [
            (
                source_nf_type.to_uppercase(),
                data_domain.to_string(),
                target_string.clone(),
            ),
            (source_nf_type.to_uppercase(), data_domain.to_string(), None),
        ];

        for key in &candidates {
            if let Some(sub_ids) = self.source_to_subscribers.get(key) {
                for sub_id in sub_ids {
                    if let Some(sub) = self.subscriptions.get(sub_id) {
                        // Apply threshold filtering
                        if let Some(min) = sub.filter.min_threshold {
                            if value < min {
                                continue;
                            }
                        }
                        if let Some(max) = sub.filter.max_threshold {
                            if value > max {
                                continue;
                            }
                        }

                        events.push(TelemetryEvent {
                            sub_id: sub.sub_id.clone(),
                            consumer_id: sub.consumer_id.clone(),
                            target: sub.target.clone(),
                            data_domain: data_domain.to_string(),
                            target_id: target_string.clone(),
                            metric_name: metric_name.to_string(),
                            value,
                            timestamp_epoch_s,
                        });
                    }
                }
            }
        }

        events
    }

    /// Get active source collector count (measures de-duplication efficiency).
    pub fn active_source_collectors_count(&self) -> usize {
        self.source_to_subscribers.len()
    }
}
