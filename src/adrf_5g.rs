//! 3GPP TS 29.575 / TS 23.288 Release 17 5G Analytics Data Repository Function (ADRF) Engine.
//!
//! Implements 5G NWDAF Big Data & AI/ML Model Persistence decoupling:
//! - Nadrf_DataManagement Service (TS 29.575 Section 5.2):
//!   - Bulk historical network telemetry & analytics data storage (`store_analytics_data`)
//!   - Time-windowed domain & target retrieval for AI model training (`query_analytics_data`)
//!   - Automated retention pruning (`prune_expired_data`)
//! - Nadrf_MLModelManagement Service (TS 29.575 Section 5.3):
//!   - NWDAF-MTLF (Model Training Logical Function) trained model checkpoint upload (`store_ml_model`)
//!   - NWDAF-AnLF (Analytics Logical Function) latest/best accuracy model retrieval (`retrieve_latest_ml_model`)
//!   - Obsolete model version deprecation & purging (`delete_ml_model`)

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G ADRF Enums & Data Structures (TS 29.575 Section 6 / TS 23.288)
// ---------------------------------------------------------------------------

/// Standardized 5G Analytics Event / Domain (TS 29.520 / TS 29.575).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnalyticsDomain {
    SliceLoadLevel,
    NfLoad,
    UeMobility,
    QosSustainability,
    AbnormalBehavior,
    UserDataCongestion,
}

impl AnalyticsDomain {
    pub fn as_str(&self) -> &'static str {
        match self {
            AnalyticsDomain::SliceLoadLevel => "SliceLoadLevel",
            AnalyticsDomain::NfLoad => "NfLoad",
            AnalyticsDomain::UeMobility => "UeMobility",
            AnalyticsDomain::QosSustainability => "QosSustainability",
            AnalyticsDomain::AbnormalBehavior => "AbnormalBehavior",
            AnalyticsDomain::UserDataCongestion => "UserDataCongestion",
        }
    }
}

/// Historical Analytics Data Record (TS 29.575 Section 6.1.6.2).
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyticsDataRecord {
    pub record_id: String,
    pub domain: AnalyticsDomain,
    pub target_id: Option<String>, // e.g. SUPI, S-NSSAI, NF Instance ID
    pub timestamp_epoch_s: u64,
    pub metrics: HashMap<String, f64>,
}

/// ML Model Checkpoint Record (TS 29.575 Section 6.2.6.2).
#[derive(Debug, Clone, PartialEq)]
pub struct MlModelRecord {
    pub model_id: String,
    pub domain: AnalyticsDomain,
    pub version: u32,
    pub model_binary: Vec<u8>,
    pub accuracy_score: f64,
    pub trained_epoch_s: u64,
}

/// ADRF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdrfError {
    RecordNotFound,
    ModelNotFound,
    InvalidTimeRange,
    StorageQuotaExceeded,
}

// ---------------------------------------------------------------------------
// Top-Level 5G-ADRF Engine
// ---------------------------------------------------------------------------

/// 5G Analytics Data Repository Function (ADRF).
pub struct AdrfEngine {
    pub adrf_id: String,
    pub next_record_counter: u64,
    /// Stored Analytics Records: record_id -> AnalyticsDataRecord
    pub data_records: HashMap<String, AnalyticsDataRecord>,
    /// Stored ML Models: model_id -> MlModelRecord
    pub ml_models: HashMap<String, MlModelRecord>,
    /// Maximum record limit for storage protection
    pub max_records_capacity: usize,
}

impl AdrfEngine {
    /// Create a new 5G-ADRF engine instance.
    pub fn new(adrf_id: &str, max_records_capacity: usize) -> Self {
        AdrfEngine {
            adrf_id: adrf_id.to_string(),
            next_record_counter: 1,
            data_records: HashMap::new(),
            ml_models: HashMap::new(),
            max_records_capacity,
        }
    }

    // -----------------------------------------------------------------------
    // Nadrf_DataManagement Service Operations (TS 29.575 Section 5.2)
    // -----------------------------------------------------------------------

    /// Store a telemetry / analytics record into the repository.
    pub fn store_analytics_data(
        &mut self,
        domain: AnalyticsDomain,
        target_id: Option<&str>,
        metrics: HashMap<String, f64>,
        timestamp_epoch_s: u64,
    ) -> Result<String, AdrfError> {
        if self.data_records.len() >= self.max_records_capacity {
            return Err(AdrfError::StorageQuotaExceeded);
        }

        let record_id = format!("rec-{:012x}", self.next_record_counter);
        self.next_record_counter += 1;

        let record = AnalyticsDataRecord {
            record_id: record_id.clone(),
            domain,
            target_id: target_id.map(|s| s.to_string()),
            timestamp_epoch_s,
            metrics,
        };

        self.data_records.insert(record_id.clone(), record);
        Ok(record_id)
    }

    /// Query historical analytics data across a specified time window.
    pub fn query_analytics_data(
        &self,
        domain: AnalyticsDomain,
        target_id: Option<&str>,
        start_epoch_s: u64,
        end_epoch_s: u64,
    ) -> Result<Vec<AnalyticsDataRecord>, AdrfError> {
        if start_epoch_s > end_epoch_s {
            return Err(AdrfError::InvalidTimeRange);
        }

        let matched: Vec<AnalyticsDataRecord> = self
            .data_records
            .values()
            .filter(|rec| {
                rec.domain == domain
                    && (target_id.is_none() || rec.target_id.as_deref() == target_id)
                    && rec.timestamp_epoch_s >= start_epoch_s
                    && rec.timestamp_epoch_s <= end_epoch_s
            })
            .cloned()
            .collect();

        Ok(matched)
    }

    /// Prune expired analytics records older than the retention threshold.
    pub fn prune_expired_data(&mut self, retention_threshold_epoch_s: u64) -> usize {
        let before_len = self.data_records.len();
        self.data_records
            .retain(|_, rec| rec.timestamp_epoch_s >= retention_threshold_epoch_s);
        before_len - self.data_records.len()
    }

    // -----------------------------------------------------------------------
    // Nadrf_MLModelManagement Service Operations (TS 29.575 Section 5.3)
    // -----------------------------------------------------------------------

    /// Store a trained ML model checkpoint from NWDAF-MTLF.
    pub fn store_ml_model(
        &mut self,
        domain: AnalyticsDomain,
        version: u32,
        model_binary: Vec<u8>,
        accuracy_score: f64,
        trained_epoch_s: u64,
    ) -> String {
        let model_id = format!("model-{}-v{}", domain.as_str(), version);

        let record = MlModelRecord {
            model_id: model_id.clone(),
            domain,
            version,
            model_binary,
            accuracy_score,
            trained_epoch_s,
        };

        self.ml_models.insert(model_id.clone(), record);
        model_id
    }

    /// Retrieve the optimal (highest version) ML model checkpoint for NWDAF-AnLF.
    pub fn retrieve_latest_ml_model(
        &self,
        domain: AnalyticsDomain,
    ) -> Result<MlModelRecord, AdrfError> {
        self.ml_models
            .values()
            .filter(|m| m.domain == domain)
            .max_by_key(|m| m.version)
            .cloned()
            .ok_or(AdrfError::ModelNotFound)
    }

    /// Delete an obsolete ML model checkpoint.
    pub fn delete_ml_model(&mut self, model_id: &str) -> Result<(), AdrfError> {
        self.ml_models
            .remove(model_id)
            .map(|_| ())
            .ok_or(AdrfError::ModelNotFound)
    }
}
