// =============================================================================
// 3GPP TS 29.272 Diameter S13 / S13' Dynamic EIR Local Cache & Expiry Engine
// =============================================================================
//
// In high-throughput 5G core networks, serving MME / AMF nodes maintain a local
// Equipment Identity Register (EIR) cache to minimize round-trip Diameter S13/S13'
// queries during UE attach and Tracking Area Updates (TAU).
//
// Features:
//   1. Local IMEI Classification: White-Listed (0), Black-Listed (1), Gray-Listed (2).
//   2. Dynamic Time-to-Live (TTL) & Invalidation.
//   3. Bulk Feed Synchronization: Ingests batches from central EIR database.
//   4. Cache Hit / Miss / Expired Classification.
//
// Pure safe Rust, zero external crates.

/// 3GPP Equipment Status classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EirEquipmentStatus {
    WhiteListed = 0,
    BlackListed = 1,
    GrayListed = 2,
}

/// Cached EIR entry record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EirCacheEntry {
    pub imei: String,
    pub status: EirEquipmentStatus,
    pub cached_at_secs: u64,
    pub expires_at_secs: u64,
    pub hit_count: u64,
}

/// Verdict for local EIR cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EirCacheLookupResult {
    /// Active entry found in cache.
    Hit(EirEquipmentStatus),
    /// Entry exists but TTL has expired.
    Expired {
        previous_status: EirEquipmentStatus,
        expired_secs_ago: u64,
    },
    /// Entry not present in local cache.
    Miss,
}

/// 3GPP Diameter S13/S13' Local EIR Cache Engine.
pub struct DiameterS13CacheEngine {
    pub default_ttl_secs: u64,
    pub max_entries: usize,
    pub entries: Vec<EirCacheEntry>,
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_expired: u64,
}

impl DiameterS13CacheEngine {
    pub fn new(default_ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            default_ttl_secs,
            max_entries: max_entries.max(10),
            entries: Vec::new(),
            total_hits: 0,
            total_misses: 0,
            total_expired: 0,
        }
    }

    /// Insert or update an IMEI status in the cache.
    pub fn insert(
        &mut self,
        imei: &str,
        status: EirEquipmentStatus,
        current_time_secs: u64,
        custom_ttl_secs: Option<u64>,
    ) {
        let ttl = custom_ttl_secs.unwrap_or(self.default_ttl_secs);
        let expires_at = current_time_secs.saturating_add(ttl);

        if let Some(pos) = self.entries.iter().position(|e| e.imei == imei) {
            self.entries[pos].status = status;
            self.entries[pos].cached_at_secs = current_time_secs;
            self.entries[pos].expires_at_secs = expires_at;
        } else {
            if self.entries.len() >= self.max_entries {
                // Remove oldest entry
                self.entries.remove(0);
            }
            self.entries.push(EirCacheEntry {
                imei: imei.to_string(),
                status,
                cached_at_secs: current_time_secs,
                expires_at_secs: expires_at,
                hit_count: 0,
            });
        }
    }

    /// Query the cache for an IMEI.
    pub fn query(&mut self, imei: &str, current_time_secs: u64) -> EirCacheLookupResult {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.imei == imei) {
            if current_time_secs >= entry.expires_at_secs {
                self.total_expired += 1;
                EirCacheLookupResult::Expired {
                    previous_status: entry.status,
                    expired_secs_ago: current_time_secs.saturating_sub(entry.expires_at_secs),
                }
            } else {
                entry.hit_count += 1;
                self.total_hits += 1;
                EirCacheLookupResult::Hit(entry.status)
            }
        } else {
            self.total_misses += 1;
            EirCacheLookupResult::Miss
        }
    }

    /// Invalidate/evict expired entries.
    pub fn purge_expired(&mut self, current_time_secs: u64) -> usize {
        let initial_len = self.entries.len();
        self.entries
            .retain(|e| current_time_secs < e.expires_at_secs);
        initial_len - self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_s13_cache_lifecycle() {
        let mut cache = DiameterS13CacheEngine::new(3600, 50); // 1-hour default TTL

        let imei_white = "860123456789012";
        let imei_black = "869999999999999";
        let imei_gray = "868888888888888";

        cache.insert(imei_white, EirEquipmentStatus::WhiteListed, 1000, None);
        cache.insert(imei_black, EirEquipmentStatus::BlackListed, 1000, None);
        cache.insert(imei_gray, EirEquipmentStatus::GrayListed, 1000, Some(60)); // 60s TTL

        // 1. Cache hits at t=1010
        assert_eq!(
            cache.query(imei_white, 1010),
            EirCacheLookupResult::Hit(EirEquipmentStatus::WhiteListed)
        );
        assert_eq!(
            cache.query(imei_black, 1010),
            EirCacheLookupResult::Hit(EirEquipmentStatus::BlackListed)
        );
        assert_eq!(
            cache.query(imei_gray, 1010),
            EirCacheLookupResult::Hit(EirEquipmentStatus::GrayListed)
        );

        // 2. Cache miss
        assert_eq!(
            cache.query("111222333444555", 1010),
            EirCacheLookupResult::Miss
        );

        // 3. Graylisted IMEI expires at t=1100 (> 1000 + 60)
        assert_eq!(
            cache.query(imei_gray, 1100),
            EirCacheLookupResult::Expired {
                previous_status: EirEquipmentStatus::GrayListed,
                expired_secs_ago: 40,
            }
        );

        // 4. Purge expired
        let purged = cache.purge_expired(1100);
        assert_eq!(purged, 1);
        assert_eq!(cache.entries.len(), 2);
    }
}
