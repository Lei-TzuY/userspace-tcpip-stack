//! SRv6 Mobile User Plane (MUP) 5QI-to-DSCP QoS Flow Mapping (3GPP TS 23.501 / draft-ietf-dmm-srv6-mobile-uplane).
//!
//! Maps 5G Standardized QoS Identifiers (5QI 1..9, 65..86) to Differentiated Services
//! Code Points (DSCP), IPv6 Traffic Class octets, and SRv6 Color attributes for SLA enforcement.

use std::collections::HashMap;

/// 5G QoS Resource Type (3GPP TS 23.501 Table 5.7.4-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiveQiResourceType {
    GuaranteedBitRate,
    NonGuaranteedBitRate,
    DelayCriticalGbr,
}

/// 5G Standardized 5QI Profile Characteristics.
#[derive(Debug, Clone, PartialEq)]
pub struct FiveQiProfile {
    pub five_qi: u8,
    pub resource_type: FiveQiResourceType,
    pub default_priority_level: u8,
    pub packet_delay_budget_ms: u32,
    pub packet_error_rate_exp: i8, // e.g. -2 for 10^-2, -6 for 10^-6
    pub default_dscp: u8,
    pub srv6_slice_color: u32,
}

/// Result of 5QI to SRv6 Outer Header QoS classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Srv6QosClassification {
    pub dscp: u8,
    pub ecn: u8,
    pub ipv6_traffic_class: u8,
    pub srv6_color: u32,
}

/// SRv6 MUP QoS Classification & SLA Engine.
#[derive(Debug, Clone)]
pub struct Srv6MupQosEngine {
    pub profiles: HashMap<u8, FiveQiProfile>,
}

impl Default for Srv6MupQosEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Srv6MupQosEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            profiles: HashMap::new(),
        };
        engine.init_standard_3gpp_profiles();
        engine
    }

    /// Populates standard 3GPP TS 23.501 5QI characteristics.
    fn init_standard_3gpp_profiles(&mut self) {
        // 5QI 1: Conversational Voice (GBR, PDB 100ms, PER 10^-2) -> DSCP EF (46 / 0x2E)
        self.register_profile(FiveQiProfile {
            five_qi: 1,
            resource_type: FiveQiResourceType::GuaranteedBitRate,
            default_priority_level: 20,
            packet_delay_budget_ms: 100,
            packet_error_rate_exp: -2,
            default_dscp: 46,      // EF
            srv6_slice_color: 200, // Voice Slice
        });

        // 5QI 2: Conversational Video (GBR, PDB 150ms, PER 10^-3) -> DSCP AF41 (34)
        self.register_profile(FiveQiProfile {
            five_qi: 2,
            resource_type: FiveQiResourceType::GuaranteedBitRate,
            default_priority_level: 40,
            packet_delay_budget_ms: 150,
            packet_error_rate_exp: -3,
            default_dscp: 34, // AF41
            srv6_slice_color: 210,
        });

        // 5QI 5: IMS Signalling (Non-GBR, PDB 100ms, PER 10^-6) -> DSCP CS5 (40)
        self.register_profile(FiveQiProfile {
            five_qi: 5,
            resource_type: FiveQiResourceType::NonGuaranteedBitRate,
            default_priority_level: 10,
            packet_delay_budget_ms: 100,
            packet_error_rate_exp: -6,
            default_dscp: 40, // CS5
            srv6_slice_color: 220,
        });

        // 5QI 9: Default Internet / Best Effort (Non-GBR, PDB 300ms, PER 10^-6) -> DSCP CS0 (0)
        self.register_profile(FiveQiProfile {
            five_qi: 9,
            resource_type: FiveQiResourceType::NonGuaranteedBitRate,
            default_priority_level: 90,
            packet_delay_budget_ms: 300,
            packet_error_rate_exp: -6,
            default_dscp: 0, // Best Effort
            srv6_slice_color: 300,
        });

        // 5QI 82: Discrete Automation / URLLC (Delay Critical GBR, PDB 10ms, PER 10^-4) -> DSCP CS7 (56)
        self.register_profile(FiveQiProfile {
            five_qi: 82,
            resource_type: FiveQiResourceType::DelayCriticalGbr,
            default_priority_level: 19,
            packet_delay_budget_ms: 10,
            packet_error_rate_exp: -4,
            default_dscp: 56,      // CS7
            srv6_slice_color: 100, // URLLC Low-Latency Slice
        });

        // 5QI 85: Electricity Distribution Smart Grid (Delay Critical GBR, PDB 5ms, PER 10^-5) -> DSCP CS7 (56)
        self.register_profile(FiveQiProfile {
            five_qi: 85,
            resource_type: FiveQiResourceType::DelayCriticalGbr,
            default_priority_level: 21,
            packet_delay_budget_ms: 5,
            packet_error_rate_exp: -5,
            default_dscp: 56,      // CS7
            srv6_slice_color: 100, // URLLC Low-Latency Slice
        });
    }

    pub fn register_profile(&mut self, profile: FiveQiProfile) {
        self.profiles.insert(profile.five_qi, profile);
    }

    /// Classifies a 5G QoS Flow into DSCP, IPv6 Traffic Class, and SRv6 color attribute.
    pub fn classify_qos_flow(&self, five_qi: u8, ecn: u8) -> Result<Srv6QosClassification, String> {
        let profile = match self.profiles.get(&five_qi) {
            Some(p) => p,
            None => return Err(format!("Unrecognized 5QI identifier {}", five_qi)),
        };

        let ecn_bits = ecn & 0x03;
        let traffic_class = (profile.default_dscp << 2) | ecn_bits;

        Ok(Srv6QosClassification {
            dscp: profile.default_dscp,
            ecn: ecn_bits,
            ipv6_traffic_class: traffic_class,
            srv6_color: profile.srv6_slice_color,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_mup_qos_mapping() {
        let engine = Srv6MupQosEngine::new();

        // 1. Voice (5QI 1) with ECN = 0 (Not-ECT)
        let voice_qos = engine.classify_qos_flow(1, 0).unwrap();
        assert_eq!(voice_qos.dscp, 46); // EF
        assert_eq!(voice_qos.ipv6_traffic_class, 46 << 2);
        assert_eq!(voice_qos.srv6_color, 200);

        // 2. URLLC (5QI 85) with ECN = 1 (ECT0)
        let urllc_qos = engine.classify_qos_flow(85, 1).unwrap();
        assert_eq!(urllc_qos.dscp, 56); // CS7
        assert_eq!(urllc_qos.ipv6_traffic_class, (56 << 2) | 1);
        assert_eq!(urllc_qos.srv6_color, 100);

        // 3. Best Effort (5QI 9)
        let be_qos = engine.classify_qos_flow(9, 0).unwrap();
        assert_eq!(be_qos.dscp, 0);
        assert_eq!(be_qos.ipv6_traffic_class, 0);
        assert_eq!(be_qos.srv6_color, 300);
    }
}
