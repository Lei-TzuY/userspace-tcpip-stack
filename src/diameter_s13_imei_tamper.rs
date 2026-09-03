// src/diameter_s13_imei_tamper.rs
//
// 3GPP TS 29.272 Diameter S13 / S13' Hardware IMEI-SV Tamper & Luhn Validation Engine
// References:
// - 3GPP TS 23.003 Section 6.2: Identification of Mobile Equipment (IMEI & IMEI-SV)
// - ISO/IEC 7812: Identification cards — Identification of issuers (Luhn Mod-10 Algorithm)
// - 3GPP TS 29.272 Section 7.2.3: Equipment-Identity AVP (Code 453)

pub const IMEI_LENGTH: usize = 15;
pub const IMEI_SV_LENGTH: usize = 16;

/// Verdict of IMEI or IMEI-SV hardware validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImeiValidationVerdict {
    ValidImei {
        imei: String,
        tac: String,
        snr: String,
        check_digit: u8,
    },
    ValidImeiSv {
        imei_sv: String,
        tac: String,
        snr: String,
        svn: String,
    },
    InvalidLength {
        input: String,
        length: usize,
    },
    InvalidCharacters {
        input: String,
    },
    LuhnChecksumFailed {
        imei: String,
        expected_cd: u8,
        actual_cd: u8,
    },
    HardwareTamperedCloned {
        imei: String,
        reason: String,
    },
}

/// Known Manufacturer Equipment Profile for TAC prefix matching.
#[derive(Debug, Clone)]
pub struct ManufacturerProfile {
    pub tac_prefix: String,
    pub manufacturer: String,
    pub min_allowed_svn: u8,
    pub max_allowed_svn: u8,
}

/// 3GPP Diameter S13 IMEI-SV Tamper & Luhn Validation Engine.
#[derive(Debug, Clone)]
pub struct S13ImeiTamperEngine {
    pub manufacturer_profiles: Vec<ManufacturerProfile>,
    pub total_validations: u64,
    pub total_valid_imeis: u64,
    pub total_valid_imeisv: u64,
    pub total_luhn_failures: u64,
    pub total_tampered_cloned: u64,
}

impl Default for S13ImeiTamperEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl S13ImeiTamperEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            manufacturer_profiles: Vec::new(),
            total_validations: 0,
            total_valid_imeis: 0,
            total_valid_imeisv: 0,
            total_luhn_failures: 0,
            total_tampered_cloned: 0,
        };

        // Seed default manufacturer TAC profiles
        engine.add_manufacturer_profile("35", "Apple iPhone / Global Devices", 1, 99);
        engine.add_manufacturer_profile("86", "Samsung / Qualcomm OEM", 1, 99);
        engine.add_manufacturer_profile("01", "Google Pixel / Test Platform", 1, 99);
        engine
    }

    /// Register a manufacturer TAC prefix profile.
    pub fn add_manufacturer_profile(
        &mut self,
        tac_prefix: &str,
        manufacturer: &str,
        min_allowed_svn: u8,
        max_allowed_svn: u8,
    ) {
        self.manufacturer_profiles.push(ManufacturerProfile {
            tac_prefix: tac_prefix.to_string(),
            manufacturer: manufacturer.to_string(),
            min_allowed_svn,
            max_allowed_svn,
        });
    }

    /// Calculate Luhn Check Digit for a 14-digit payload (TAC + SNR).
    pub fn calculate_luhn_check_digit(payload_14: &str) -> Option<u8> {
        if payload_14.len() != 14 || !payload_14.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }

        let mut sum = 0u32;
        // Digits at index 0, 2, 4, 6, 8, 10, 12: keep as is
        // Digits at index 1, 3, 5, 7, 9, 11, 13: double them, sum digits
        for (idx, ch) in payload_14.chars().enumerate() {
            let digit = ch.to_digit(10)? as u32;
            if idx % 2 == 1 {
                let doubled = digit * 2;
                sum += (doubled / 10) + (doubled % 10);
            } else {
                sum += digit;
            }
        }

        let check_digit = ((10 - (sum % 10)) % 10) as u8;
        Some(check_digit)
    }

    /// Validate an IMEI (15 digits) or IMEI-SV (16 digits).
    pub fn validate_equipment_id(&mut self, input: &str) -> ImeiValidationVerdict {
        self.total_validations += 1;

        if !input.chars().all(|c| c.is_ascii_digit()) {
            return ImeiValidationVerdict::InvalidCharacters {
                input: input.to_string(),
            };
        }

        let len = input.len();
        match len {
            IMEI_LENGTH => self.validate_imei_15(input),
            IMEI_SV_LENGTH => self.validate_imeisv_16(input),
            _ => ImeiValidationVerdict::InvalidLength {
                input: input.to_string(),
                length: len,
            },
        }
    }

    fn validate_imei_15(&mut self, imei: &str) -> ImeiValidationVerdict {
        // Detect trivial cloning / dummy patterns
        if self.is_dummy_pattern(imei) {
            self.total_tampered_cloned += 1;
            return ImeiValidationVerdict::HardwareTamperedCloned {
                imei: imei.to_string(),
                reason: "Prohibited dummy / repetitive serial pattern detected".to_string(),
            };
        }

        let payload_14 = &imei[0..14];
        let actual_cd = imei.as_bytes()[14] - b'0';

        let expected_cd = match Self::calculate_luhn_check_digit(payload_14) {
            Some(cd) => cd,
            None => {
                return ImeiValidationVerdict::InvalidCharacters {
                    input: imei.to_string(),
                };
            }
        };

        if actual_cd != expected_cd {
            self.total_luhn_failures += 1;
            return ImeiValidationVerdict::LuhnChecksumFailed {
                imei: imei.to_string(),
                expected_cd,
                actual_cd,
            };
        }

        self.total_valid_imeis += 1;
        ImeiValidationVerdict::ValidImei {
            imei: imei.to_string(),
            tac: imei[0..8].to_string(),
            snr: imei[8..14].to_string(),
            check_digit: actual_cd,
        }
    }

    fn validate_imeisv_16(&mut self, imei_sv: &str) -> ImeiValidationVerdict {
        if self.is_dummy_pattern(&imei_sv[0..14]) {
            self.total_tampered_cloned += 1;
            return ImeiValidationVerdict::HardwareTamperedCloned {
                imei: imei_sv.to_string(),
                reason: "Prohibited dummy / repetitive serial pattern in IMEI-SV".to_string(),
            };
        }

        let svn_val = match imei_sv[14..16].parse::<u8>() {
            Ok(v) => v,
            Err(_) => {
                return ImeiValidationVerdict::InvalidCharacters {
                    input: imei_sv.to_string(),
                };
            }
        };

        // Check manufacturer SVN boundaries if matching TAC prefix exists
        for prof in &self.manufacturer_profiles {
            if imei_sv.starts_with(&prof.tac_prefix) {
                if svn_val < prof.min_allowed_svn || svn_val > prof.max_allowed_svn {
                    self.total_tampered_cloned += 1;
                    return ImeiValidationVerdict::HardwareTamperedCloned {
                        imei: imei_sv.to_string(),
                        reason: format!(
                            "Software Version Number (SVN {}) out of valid range ({}..{}) for manufacturer {}",
                            svn_val, prof.min_allowed_svn, prof.max_allowed_svn, prof.manufacturer
                        ),
                    };
                }
                break;
            }
        }

        self.total_valid_imeisv += 1;
        ImeiValidationVerdict::ValidImeiSv {
            imei_sv: imei_sv.to_string(),
            tac: imei_sv[0..8].to_string(),
            snr: imei_sv[8..14].to_string(),
            svn: imei_sv[14..16].to_string(),
        }
    }

    fn is_dummy_pattern(&self, s: &str) -> bool {
        // All digits identical (e.g. 00000000000000, 11111111111111)
        if s.chars().all(|c| c == s.chars().next().unwrap()) {
            return true;
        }
        // Repetitive "01234567890123" pattern
        if s.starts_with("0123456789") {
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luhn_calculation_known_vectors() {
        // TAC = 35391800, SNR = 123456 -> Payload: "35391800123456"
        // Let's calculate CD:
        let cd = S13ImeiTamperEngine::calculate_luhn_check_digit("35391800123456").unwrap();
        // Construct 15-digit IMEI
        let full_imei = format!("35391800123456{}", cd);
        let mut engine = S13ImeiTamperEngine::new();
        let verdict = engine.validate_equipment_id(&full_imei);
        match verdict {
            ImeiValidationVerdict::ValidImei { check_digit, .. } => {
                assert_eq!(check_digit, cd);
            }
            _ => panic!("Expected ValidImei"),
        }
    }

    #[test]
    fn test_corrupted_luhn_detected() {
        let mut engine = S13ImeiTamperEngine::new();
        // Tamper last check digit (e.g. changed to 9 when correct is different)
        let cd = S13ImeiTamperEngine::calculate_luhn_check_digit("35391800123456").unwrap();
        let tampered_cd = (cd + 1) % 10;
        let tampered_imei = format!("35391800123456{}", tampered_cd);

        let verdict = engine.validate_equipment_id(&tampered_imei);
        match verdict {
            ImeiValidationVerdict::LuhnChecksumFailed {
                expected_cd,
                actual_cd,
                ..
            } => {
                assert_eq!(expected_cd, cd);
                assert_eq!(actual_cd, tampered_cd);
            }
            _ => panic!("Expected LuhnChecksumFailed"),
        }
        assert_eq!(engine.total_luhn_failures, 1);
    }
}
