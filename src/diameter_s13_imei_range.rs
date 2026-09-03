//! 3GPP TS 29.272 Diameter S13 TAC / IMEI Range Matching Engine
//!
//! Provides high-throughput range categorization and wildcard TAC (Type Allocation Code)
//! lookup for large-scale equipment authorization, regulatory blocklists, and manufacturer profiling.

use crate::diameter_s13_escn::S13EquipmentStatus;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImeiRangeRule {
    pub start_tac: u64,
    pub end_tac: u64,
    pub status: S13EquipmentStatus,
    pub description: String,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImeiRangeVerdict {
    RangeMatched {
        imei: String,
        tac: u64,
        status: S13EquipmentStatus,
        description: String,
        priority: u32,
    },
    DefaultWhiteListed {
        imei: String,
        tac: u64,
    },
    InvalidImeiFormat {
        input: String,
    },
}

#[derive(Debug, Clone)]
pub struct DiameterS13ImeiRangeEngine {
    pub rules: Vec<ImeiRangeRule>,
    pub total_queries: usize,
    pub total_range_matches: usize,
    pub total_default_matches: usize,
    pub total_invalid_queries: usize,
}

impl Default for DiameterS13ImeiRangeEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterS13ImeiRangeEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            total_queries: 0,
            total_range_matches: 0,
            total_default_matches: 0,
            total_invalid_queries: 0,
        }
    }

    /// Adds a TAC range rule (sorted by priority descending).
    pub fn add_rule(
        &mut self,
        start_tac: u64,
        end_tac: u64,
        status: S13EquipmentStatus,
        description: &str,
        priority: u32,
    ) {
        let (min_tac, max_tac) = if start_tac <= end_tac {
            (start_tac, end_tac)
        } else {
            (end_tac, start_tac)
        };

        self.rules.push(ImeiRangeRule {
            start_tac: min_tac,
            end_tac: max_tac,
            status,
            description: description.to_string(),
            priority,
        });

        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluates an IMEI / IMEISV against registered TAC range rules.
    pub fn evaluate_imei(&mut self, imei: &str) -> ImeiRangeVerdict {
        self.total_queries += 1;

        let clean_imei = imei.trim();
        if clean_imei.len() < 8 || !clean_imei.chars().all(|c| c.is_ascii_digit()) {
            self.total_invalid_queries += 1;
            return ImeiRangeVerdict::InvalidImeiFormat {
                input: imei.to_string(),
            };
        }

        let tac_str = &clean_imei[..8];
        let tac = match tac_str.parse::<u64>() {
            Ok(val) => val,
            Err(_) => {
                self.total_invalid_queries += 1;
                return ImeiRangeVerdict::InvalidImeiFormat {
                    input: imei.to_string(),
                };
            }
        };

        for rule in &self.rules {
            if tac >= rule.start_tac && tac <= rule.end_tac {
                self.total_range_matches += 1;
                return ImeiRangeVerdict::RangeMatched {
                    imei: clean_imei.to_string(),
                    tac,
                    status: rule.status,
                    description: rule.description.clone(),
                    priority: rule.priority,
                };
            }
        }

        self.total_default_matches += 1;
        ImeiRangeVerdict::DefaultWhiteListed {
            imei: clean_imei.to_string(),
            tac,
        }
    }

    /// Clears all registered rules.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Resets all statistics.
    pub fn reset_stats(&mut self) {
        self.total_queries = 0;
        self.total_range_matches = 0;
        self.total_default_matches = 0;
        self.total_invalid_queries = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_rule_matching() {
        let mut engine = DiameterS13ImeiRangeEngine::new();
        engine.add_rule(
            35391800,
            35391899,
            S13EquipmentStatus::BlackListed,
            "Compromised Batch",
            100,
        );
        engine.add_rule(
            35300000,
            35399999,
            S13EquipmentStatus::GrayListed,
            "Vendor Observation",
            50,
        );

        let v1 = engine.evaluate_imei("353918551234567");
        assert!(matches!(
            v1,
            ImeiRangeVerdict::RangeMatched {
                status: S13EquipmentStatus::BlackListed,
                ..
            }
        ));

        let v2 = engine.evaluate_imei("353500001234567");
        assert!(matches!(
            v2,
            ImeiRangeVerdict::RangeMatched {
                status: S13EquipmentStatus::GrayListed,
                ..
            }
        ));

        let v3 = engine.evaluate_imei("860000001234567");
        assert!(matches!(v3, ImeiRangeVerdict::DefaultWhiteListed { .. }));
    }
}
