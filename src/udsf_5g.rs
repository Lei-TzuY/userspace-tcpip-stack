//! 3GPP TS 29.598 / TS 23.501 Section 6.2.14 5G Unstructured Data Storage Function (UDSF) Engine.
//!
//! Implements the 5G cloud-native stateless SBA storage repository:
//! - Nudsf_DataRepository Service (TS 29.598 Section 5.2):
//!   - `CreateOrReplaceRecord` with ETag precondition verification (If-Match)
//!   - `ReadRecord`, `UpdateRecord`, and `DeleteRecord` lifecycle operations
//!   - Tag-based secondary index queries (e.g. lookup sessions by S-NSSAI or DNN)
//!   - Distributed pessimistic record locking (`LockRecord` / `UnlockRecord`) with auto-lease timeouts
//!   - High-throughput TTL (Time-To-Live) expiration and sweep eviction

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G UDSF Data Structures & Enums (TS 29.598 Section 6)
// ---------------------------------------------------------------------------

/// UDSF Stored Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdsfRecord {
    pub collection_id: String,
    pub record_id: String,
    pub payload: Vec<u8>,
    pub etag: u64,
    pub ttl_seconds: Option<u32>,
    pub expires_at_epoch_s: Option<u64>,
    pub tags: HashMap<String, String>,
    pub lock_owner: Option<String>,
    pub lock_expires_at_epoch_s: Option<u64>,
}

/// Request to create or update a record in UDSF.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutRecordRequest {
    pub collection_id: String,
    pub record_id: String,
    pub payload: Vec<u8>,
    pub ttl_seconds: Option<u32>,
    pub tags: HashMap<String, String>,
    pub if_match_etag: Option<u64>,
    pub timestamp_epoch_s: u64,
}

/// UDSF Processing Errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdsfError {
    RecordNotFound,
    PreconditionFailed(&'static str), // ETag mismatch (HTTP 412)
    RecordLocked(&'static str),       // Locked by another NF (HTTP 423)
    LockNotOwned,
    InvalidParameters(&'static str),
}

// ---------------------------------------------------------------------------
// Top-Level UDSF Engine
// ---------------------------------------------------------------------------

/// 5G Unstructured Data Storage Function (UDSF) Engine.
pub struct UdsfEngine {
    pub udsf_id: String,
    pub next_etag: u64,
    /// Storage hierarchy: collection_id -> (record_id -> UdsfRecord)
    pub collections: HashMap<String, HashMap<String, UdsfRecord>>,
    /// Secondary index: (collection_id, tag_key, tag_value) -> Vec<record_id>
    pub tag_index: HashMap<(String, String, String), Vec<String>>,
}

impl UdsfEngine {
    /// Create a new UDSF engine instance.
    pub fn new(udsf_id: &str) -> Self {
        UdsfEngine {
            udsf_id: udsf_id.to_string(),
            next_etag: 1,
            collections: HashMap::new(),
            tag_index: HashMap::new(),
        }
    }

    /// Nudsf_DataRepository CreateOrReplaceRecord operation (TS 29.598 Section 5.2.2.2).
    pub fn create_or_replace_record(
        &mut self,
        req: &PutRecordRequest,
    ) -> Result<UdsfRecord, UdsfError> {
        let collection = self
            .collections
            .entry(req.collection_id.clone())
            .or_insert_with(HashMap::new);

        // Check if existing record exists
        if let Some(existing) = collection.get_mut(&req.record_id) {
            // 1. Check if record is currently locked by someone else
            if existing.lock_owner.is_some() {
                let lock_exp = existing.lock_expires_at_epoch_s.unwrap_or(0);
                if req.timestamp_epoch_s < lock_exp {
                    return Err(UdsfError::RecordLocked(
                        "Record is locked by another NF instance",
                    ));
                } else {
                    // Lock has expired, clear it
                    existing.lock_owner = None;
                    existing.lock_expires_at_epoch_s = None;
                }
            }

            // 2. Optimistic Concurrency Control (If-Match ETag)
            if let Some(expected_etag) = req.if_match_etag {
                if existing.etag != expected_etag {
                    return Err(UdsfError::PreconditionFailed("ETag mismatch"));
                }
            }
        } else if req.if_match_etag.is_some() {
            // If-Match requested on non-existent record
            return Err(UdsfError::PreconditionFailed(
                "Target record does not exist",
            ));
        }

        let new_etag = self.next_etag;
        self.next_etag += 1;

        let expires_at = req
            .ttl_seconds
            .map(|ttl| req.timestamp_epoch_s.saturating_add(ttl as u64));

        let new_record = UdsfRecord {
            collection_id: req.collection_id.clone(),
            record_id: req.record_id.clone(),
            payload: req.payload.clone(),
            etag: new_etag,
            ttl_seconds: req.ttl_seconds,
            expires_at_epoch_s: expires_at,
            tags: req.tags.clone(),
            lock_owner: None,
            lock_expires_at_epoch_s: None,
        };

        // Update secondary tag indexes
        for (k, v) in &req.tags {
            let key = (req.collection_id.clone(), k.clone(), v.clone());
            let list = self.tag_index.entry(key).or_insert_with(Vec::new);
            if !list.contains(&req.record_id) {
                list.push(req.record_id.clone());
            }
        }

        // Store into collection
        let col = self.collections.get_mut(&req.collection_id).unwrap();
        col.insert(req.record_id.clone(), new_record.clone());

        Ok(new_record)
    }

    /// Nudsf_DataRepository ReadRecord operation (TS 29.598 Section 5.2.2.3).
    pub fn get_record(
        &self,
        collection_id: &str,
        record_id: &str,
        timestamp_s: u64,
    ) -> Result<UdsfRecord, UdsfError> {
        let col = self
            .collections
            .get(collection_id)
            .ok_or(UdsfError::RecordNotFound)?;

        let record = col.get(record_id).ok_or(UdsfError::RecordNotFound)?;

        // Check if expired
        if let Some(exp) = record.expires_at_epoch_s {
            if timestamp_s >= exp {
                return Err(UdsfError::RecordNotFound);
            }
        }

        Ok(record.clone())
    }

    /// Nudsf_DataRepository DeleteRecord operation (TS 29.598 Section 5.2.2.5).
    pub fn delete_record(
        &mut self,
        collection_id: &str,
        record_id: &str,
        if_match_etag: Option<u64>,
    ) -> Result<(), UdsfError> {
        let col = self
            .collections
            .get_mut(collection_id)
            .ok_or(UdsfError::RecordNotFound)?;

        let record = col.get(record_id).ok_or(UdsfError::RecordNotFound)?;

        if let Some(expected_etag) = if_match_etag {
            if record.etag != expected_etag {
                return Err(UdsfError::PreconditionFailed("ETag mismatch on DELETE"));
            }
        }

        col.remove(record_id);
        Ok(())
    }

    /// Query records by secondary tag attribute.
    pub fn query_records_by_tag(
        &self,
        collection_id: &str,
        tag_key: &str,
        tag_val: &str,
        timestamp_s: u64,
    ) -> Vec<UdsfRecord> {
        let idx_key = (
            collection_id.to_string(),
            tag_key.to_string(),
            tag_val.to_string(),
        );

        let mut results = Vec::new();
        if let Some(record_ids) = self.tag_index.get(&idx_key) {
            for id in record_ids {
                if let Ok(rec) = self.get_record(collection_id, id, timestamp_s) {
                    results.push(rec);
                }
            }
        }
        results
    }

    // -----------------------------------------------------------------------
    // Distributed Concurrency Record Locking (Section 5.2.2.8)
    // -----------------------------------------------------------------------

    /// Acquire a distributed lock on a record.
    pub fn lock_record(
        &mut self,
        collection_id: &str,
        record_id: &str,
        nf_instance_id: &str,
        lock_duration_s: u32,
        timestamp_s: u64,
    ) -> Result<u64, UdsfError> {
        let col = self
            .collections
            .get_mut(collection_id)
            .ok_or(UdsfError::RecordNotFound)?;

        let record = col.get_mut(record_id).ok_or(UdsfError::RecordNotFound)?;

        // Check if already locked by another NF
        if let Some(ref current_owner) = record.lock_owner {
            let exp = record.lock_expires_at_epoch_s.unwrap_or(0);
            if timestamp_s < exp && current_owner != nf_instance_id {
                return Err(UdsfError::RecordLocked("Record locked by another NF"));
            }
        }

        // Grant lock
        record.lock_owner = Some(nf_instance_id.to_string());
        record.lock_expires_at_epoch_s = Some(timestamp_s.saturating_add(lock_duration_s as u64));

        Ok(record.etag)
    }

    /// Release an acquired lock on a record.
    pub fn unlock_record(
        &mut self,
        collection_id: &str,
        record_id: &str,
        nf_instance_id: &str,
    ) -> Result<(), UdsfError> {
        let col = self
            .collections
            .get_mut(collection_id)
            .ok_or(UdsfError::RecordNotFound)?;

        let record = col.get_mut(record_id).ok_or(UdsfError::RecordNotFound)?;

        if let Some(ref current_owner) = record.lock_owner {
            if current_owner != nf_instance_id {
                return Err(UdsfError::LockNotOwned);
            }
            record.lock_owner = None;
            record.lock_expires_at_epoch_s = None;
            Ok(())
        } else {
            Ok(()) // Already unlocked
        }
    }

    /// Sweep expired records across all collections. Returns number of records evicted.
    pub fn sweep_expired_records(&mut self, timestamp_s: u64) -> usize {
        let mut evicted = 0;
        for col in self.collections.values_mut() {
            let expired_keys: Vec<String> = col
                .iter()
                .filter(|(_, rec)| {
                    if let Some(exp) = rec.expires_at_epoch_s {
                        timestamp_s >= exp
                    } else {
                        false
                    }
                })
                .map(|(k, _)| k.clone())
                .collect();

            for k in expired_keys {
                col.remove(&k);
                evicted += 1;
            }
        }
        evicted
    }
}
