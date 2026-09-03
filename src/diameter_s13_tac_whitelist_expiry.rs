//! 3GPP TS 29.272 Diameter S13 Temporary TAC Whitelist & Lease Expiry Engine
//!
//! Manages time-bounded equipment authorization leases for temporary trial devices,
//! testing batches, and short-term rental roaming IMEIs with grace period handling and automatic fallback.

use crate::diameter_s13_escn::S13EquipmentStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    Active,
    GracePeriod,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemporaryTacLease {
    pub lease_id: u32,
    pub start_tac: u64,
    pub end_tac: u64,
    pub granted_at_s: u64,
    pub duration_s: u64,
    pub grace_period_s: u64,
    pub fallback_status: S13EquipmentStatus,
    pub description: String,
    pub is_revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseVerdict {
    LeaseActive {
        lease_id: u32,
        imei: String,
        tac: u64,
        remaining_s: u64,
        status: S13EquipmentStatus,
    },
    LeaseInGracePeriod {
        lease_id: u32,
        imei: String,
        tac: u64,
        grace_remaining_s: u64,
        status: S13EquipmentStatus,
    },
    LeaseExpiredFallback {
        lease_id: u32,
        imei: String,
        tac: u64,
        fallback_status: S13EquipmentStatus,
    },
    NoLeaseFound {
        imei: String,
        tac: u64,
        default_status: S13EquipmentStatus,
    },
    InvalidImeiFormat {
        input: String,
    },
}

#[derive(Debug, Clone)]
pub struct DiameterS13TacWhitelistExpiryEngine {
    pub leases: Vec<TemporaryTacLease>,
    pub next_lease_id: u32,
    pub total_queries: usize,
    pub total_active_matches: usize,
    pub total_grace_matches: usize,
    pub total_expired_fallbacks: usize,
    pub total_default_matches: usize,
    pub total_invalid_queries: usize,
}

impl Default for DiameterS13TacWhitelistExpiryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterS13TacWhitelistExpiryEngine {
    pub fn new() -> Self {
        Self {
            leases: Vec::new(),
            next_lease_id: 1,
            total_queries: 0,
            total_active_matches: 0,
            total_grace_matches: 0,
            total_expired_fallbacks: 0,
            total_default_matches: 0,
            total_invalid_queries: 0,
        }
    }

    /// Grants a new temporary TAC range authorization lease.
    pub fn grant_lease(
        &mut self,
        start_tac: u64,
        end_tac: u64,
        granted_at_s: u64,
        duration_s: u64,
        grace_period_s: u64,
        fallback_status: S13EquipmentStatus,
        description: &str,
    ) -> u32 {
        let (min_tac, max_tac) = if start_tac <= end_tac {
            (start_tac, end_tac)
        } else {
            (end_tac, start_tac)
        };

        let lease_id = self.next_lease_id;
        self.next_lease_id += 1;

        self.leases.push(TemporaryTacLease {
            lease_id,
            start_tac: min_tac,
            end_tac: max_tac,
            granted_at_s,
            duration_s: duration_s.max(1),
            grace_period_s,
            fallback_status,
            description: description.to_string(),
            is_revoked: false,
        });

        lease_id
    }

    /// Renews an existing lease by extending its duration.
    pub fn renew_lease(&mut self, lease_id: u32, extension_s: u64) -> bool {
        if let Some(lease) = self.leases.iter_mut().find(|l| l.lease_id == lease_id) {
            if !lease.is_revoked {
                lease.duration_s += extension_s;
                return true;
            }
        }
        false
    }

    /// Manually revokes an active lease.
    pub fn revoke_lease(&mut self, lease_id: u32) -> bool {
        if let Some(lease) = self.leases.iter_mut().find(|l| l.lease_id == lease_id) {
            lease.is_revoked = true;
            return true;
        }
        false
    }

    /// Evaluates an IMEI at a specific timestamp.
    pub fn evaluate_imei(&mut self, imei: &str, current_time_s: u64) -> LeaseVerdict {
        self.total_queries += 1;

        let clean_imei = imei.trim();
        if clean_imei.len() < 8 || !clean_imei.chars().all(|c| c.is_ascii_digit()) {
            self.total_invalid_queries += 1;
            return LeaseVerdict::InvalidImeiFormat {
                input: imei.to_string(),
            };
        }

        let tac = match clean_imei[..8].parse::<u64>() {
            Ok(v) => v,
            Err(_) => {
                self.total_invalid_queries += 1;
                return LeaseVerdict::InvalidImeiFormat {
                    input: imei.to_string(),
                };
            }
        };

        for lease in &self.leases {
            if tac >= lease.start_tac && tac <= lease.end_tac {
                if lease.is_revoked {
                    self.total_expired_fallbacks += 1;
                    return LeaseVerdict::LeaseExpiredFallback {
                        lease_id: lease.lease_id,
                        imei: clean_imei.to_string(),
                        tac,
                        fallback_status: lease.fallback_status,
                    };
                }

                let elapsed = current_time_s.saturating_sub(lease.granted_at_s);
                if elapsed < lease.duration_s {
                    let remaining = lease.duration_s - elapsed;
                    self.total_active_matches += 1;
                    return LeaseVerdict::LeaseActive {
                        lease_id: lease.lease_id,
                        imei: clean_imei.to_string(),
                        tac,
                        remaining_s: remaining,
                        status: S13EquipmentStatus::WhiteListed,
                    };
                } else if elapsed < lease.duration_s + lease.grace_period_s {
                    let grace_remaining = (lease.duration_s + lease.grace_period_s) - elapsed;
                    self.total_grace_matches += 1;
                    return LeaseVerdict::LeaseInGracePeriod {
                        lease_id: lease.lease_id,
                        imei: clean_imei.to_string(),
                        tac,
                        grace_remaining_s: grace_remaining,
                        status: S13EquipmentStatus::GrayListed,
                    };
                } else {
                    self.total_expired_fallbacks += 1;
                    return LeaseVerdict::LeaseExpiredFallback {
                        lease_id: lease.lease_id,
                        imei: clean_imei.to_string(),
                        tac,
                        fallback_status: lease.fallback_status,
                    };
                }
            }
        }

        self.total_default_matches += 1;
        LeaseVerdict::NoLeaseFound {
            imei: clean_imei.to_string(),
            tac,
            default_status: S13EquipmentStatus::WhiteListed,
        }
    }

    /// Sweeps and returns IDs of all fully expired leases.
    pub fn sweep_expired_leases(&self, current_time_s: u64) -> Vec<u32> {
        self.leases
            .iter()
            .filter(|l| {
                l.is_revoked
                    || current_time_s.saturating_sub(l.granted_at_s)
                        >= (l.duration_s + l.grace_period_s)
            })
            .map(|l| l.lease_id)
            .collect()
    }

    /// Resets all state.
    pub fn reset(&mut self) {
        self.leases.clear();
        self.next_lease_id = 1;
        self.total_queries = 0;
        self.total_active_matches = 0;
        self.total_grace_matches = 0;
        self.total_expired_fallbacks = 0;
        self.total_default_matches = 0;
        self.total_invalid_queries = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tac_lease_lifecycle() {
        let mut engine = DiameterS13TacWhitelistExpiryEngine::new();

        // Grant lease #1 for TAC 35391800..35391899: duration 100s, grace period 20s, fallback BlackListed
        let id1 = engine.grant_lease(
            35391800,
            35391899,
            1000,
            100,
            20,
            S13EquipmentStatus::BlackListed,
            "Manufacturer Pilot Test Batch",
        );
        assert_eq!(id1, 1);

        // 1. At t=1050 (active)
        let v1 = engine.evaluate_imei("353918001234567", 1050);
        assert_eq!(
            v1,
            LeaseVerdict::LeaseActive {
                lease_id: 1,
                imei: "353918001234567".to_string(),
                tac: 35391800,
                remaining_s: 50,
                status: S13EquipmentStatus::WhiteListed,
            }
        );

        // 2. At t=1110 (grace period, duration expired at 1100, grace until 1120)
        let v2 = engine.evaluate_imei("353918001234567", 1110);
        assert_eq!(
            v2,
            LeaseVerdict::LeaseInGracePeriod {
                lease_id: 1,
                imei: "353918001234567".to_string(),
                tac: 35391800,
                grace_remaining_s: 10,
                status: S13EquipmentStatus::GrayListed,
            }
        );

        // 3. At t=1125 (fully expired -> fallback to BlackListed)
        let v3 = engine.evaluate_imei("353918001234567", 1125);
        assert_eq!(
            v3,
            LeaseVerdict::LeaseExpiredFallback {
                lease_id: 1,
                imei: "353918001234567".to_string(),
                tac: 35391800,
                fallback_status: S13EquipmentStatus::BlackListed,
            }
        );

        // 4. Renew lease by +200s
        assert!(engine.renew_lease(1, 200));
        // Now duration is 300s (ends at 1300s). At t=1125 it should be active again!
        let v4 = engine.evaluate_imei("353918001234567", 1125);
        assert_eq!(
            v4,
            LeaseVerdict::LeaseActive {
                lease_id: 1,
                imei: "353918001234567".to_string(),
                tac: 35391800,
                remaining_s: 175,
                status: S13EquipmentStatus::WhiteListed,
            }
        );

        // 5. Revoke lease
        assert!(engine.revoke_lease(1));
        let v5 = engine.evaluate_imei("353918001234567", 1125);
        assert_eq!(
            v5,
            LeaseVerdict::LeaseExpiredFallback {
                lease_id: 1,
                imei: "353918001234567".to_string(),
                tac: 35391800,
                fallback_status: S13EquipmentStatus::BlackListed,
            }
        );
    }
}
