// src/diameter_s13_roam_mismatch.rs
//
// 3GPP TS 29.272 Diameter S13 / S13' International Roaming TAC Country Code Mismatch Engine.
//
// Validates equipment identity (IMEI Type Allocation Code) against serving network PLMN
// Mobile Country Code (MCC). Identifies cross-border device cloning anomalies, unauthorized
// grey-market hardware, and high-risk roaming fraud profiles.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TacCountryMapping {
    pub tac_prefix: String,
    pub allocated_country_iso: String,
    pub allocated_mcc: String,
    pub risk_weight: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoamingValidationVerdict {
    DomesticConformant {
        imei: String,
        tac: String,
        serving_mcc: String,
    },
    AuthorizedInternationalRoaming {
        imei: String,
        tac: String,
        tac_origin_country: String,
        serving_mcc: String,
    },
    SuspiciousCountryMismatch {
        imei: String,
        tac: String,
        tac_origin_country: String,
        serving_mcc: String,
        risk_score: u8,
    },
    BlacklistedCountryBlocked {
        imei: String,
        tac: String,
        tac_origin_country: String,
        serving_mcc: String,
    },
    InvalidImeiFormat {
        input: String,
    },
}

#[derive(Debug, Clone)]
pub struct S13RoamingMismatchEngine {
    pub country_mappings: Vec<TacCountryMapping>,
    pub blacklisted_origin_countries: Vec<String>,
    pub total_validations: u64,
    pub total_domestic_passes: u64,
    pub total_authorized_roaming: u64,
    pub total_suspicious_mismatches: u64,
    pub total_blocked_roamers: u64,
}

impl S13RoamingMismatchEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            country_mappings: Vec::new(),
            blacklisted_origin_countries: Vec::new(),
            total_validations: 0,
            total_domestic_passes: 0,
            total_authorized_roaming: 0,
            total_suspicious_mismatches: 0,
            total_blocked_roamers: 0,
        };

        // Pre-seed standard GSMA Reporting Body Identifier (RBI) prefixes
        engine.add_tac_country_mapping("01", "US", "310", 10);
        engine.add_tac_country_mapping("35", "UK", "234", 10);
        engine.add_tac_country_mapping("86", "CN", "460", 20);
        engine.add_tac_country_mapping("49", "DE", "262", 10);
        engine.add_tac_country_mapping("44", "GB", "234", 10);
        engine.add_tac_country_mapping("99", "TEST", "001", 80);

        engine
    }

    pub fn add_tac_country_mapping(
        &mut self,
        tac_prefix: &str,
        allocated_country_iso: &str,
        allocated_mcc: &str,
        risk_weight: u8,
    ) {
        if let Some(existing) = self
            .country_mappings
            .iter_mut()
            .find(|m| m.tac_prefix == tac_prefix)
        {
            existing.allocated_country_iso = allocated_country_iso.to_string();
            existing.allocated_mcc = allocated_mcc.to_string();
            existing.risk_weight = risk_weight;
        } else {
            self.country_mappings.push(TacCountryMapping {
                tac_prefix: tac_prefix.to_string(),
                allocated_country_iso: allocated_country_iso.to_string(),
                allocated_mcc: allocated_mcc.to_string(),
                risk_weight,
            });
        }
    }

    pub fn add_blacklisted_origin_country(&mut self, country_iso: &str) {
        let iso = country_iso.to_uppercase();
        if !self.blacklisted_origin_countries.contains(&iso) {
            self.blacklisted_origin_countries.push(iso);
        }
    }

    pub fn evaluate_roaming_equipment(
        &mut self,
        imei: &str,
        serving_plmn: &str,
    ) -> RoamingValidationVerdict {
        self.total_validations += 1;

        if imei.len() < 8 || !imei.chars().all(|c| c.is_ascii_digit()) {
            return RoamingValidationVerdict::InvalidImeiFormat {
                input: imei.to_string(),
            };
        }

        let tac = &imei[0..8];
        let serving_mcc = if serving_plmn.len() >= 3 {
            &serving_plmn[0..3]
        } else {
            serving_plmn
        };

        // Find best matching TAC country allocation (longest prefix match)
        let mapping = self
            .country_mappings
            .iter()
            .filter(|m| tac.starts_with(&m.tac_prefix))
            .max_by_key(|m| m.tac_prefix.len());

        let (country_iso, allocated_mcc, risk) = match mapping {
            Some(m) => (
                m.allocated_country_iso.clone(),
                m.allocated_mcc.clone(),
                m.risk_weight,
            ),
            None => ("UNKNOWN".to_string(), "000".to_string(), 50),
        };

        // Check if origin country is on national security / sanctions blacklist
        if self
            .blacklisted_origin_countries
            .contains(&country_iso.to_uppercase())
        {
            self.total_blocked_roamers += 1;
            return RoamingValidationVerdict::BlacklistedCountryBlocked {
                imei: imei.to_string(),
                tac: tac.to_string(),
                tac_origin_country: country_iso,
                serving_mcc: serving_mcc.to_string(),
            };
        }

        // Domestic match (Serving network MCC == TAC allocated MCC)
        if serving_mcc == allocated_mcc {
            self.total_domestic_passes += 1;
            RoamingValidationVerdict::DomesticConformant {
                imei: imei.to_string(),
                tac: tac.to_string(),
                serving_mcc: serving_mcc.to_string(),
            }
        } else if risk > 60 {
            self.total_suspicious_mismatches += 1;
            RoamingValidationVerdict::SuspiciousCountryMismatch {
                imei: imei.to_string(),
                tac: tac.to_string(),
                tac_origin_country: country_iso,
                serving_mcc: serving_mcc.to_string(),
                risk_score: risk,
            }
        } else {
            self.total_authorized_roaming += 1;
            RoamingValidationVerdict::AuthorizedInternationalRoaming {
                imei: imei.to_string(),
                tac: tac.to_string(),
                tac_origin_country: country_iso,
                serving_mcc: serving_mcc.to_string(),
            }
        }
    }

    pub fn reset(&mut self) {
        self.total_validations = 0;
        self.total_domestic_passes = 0;
        self.total_authorized_roaming = 0;
        self.total_suspicious_mismatches = 0;
        self.total_blocked_roamers = 0;
    }
}

impl Default for S13RoamingMismatchEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s13_roaming_mismatch_lifecycle() {
        let mut engine = S13RoamingMismatchEngine::new();
        engine.add_blacklisted_origin_country("TEST");

        // Domestic check (US TAC on US network 310-410)
        let v1 = engine.evaluate_roaming_equipment("012345678901234", "310410");
        assert!(matches!(
            v1,
            RoamingValidationVerdict::DomesticConformant { .. }
        ));

        // International roaming (UK TAC on US network 310-410)
        let v2 = engine.evaluate_roaming_equipment("353918001234567", "310410");
        assert!(matches!(
            v2,
            RoamingValidationVerdict::AuthorizedInternationalRoaming { .. }
        ));

        // Blacklisted country origin
        let v3 = engine.evaluate_roaming_equipment("990012345678901", "310410");
        assert!(matches!(
            v3,
            RoamingValidationVerdict::BlacklistedCountryBlocked { .. }
        ));
    }
}
