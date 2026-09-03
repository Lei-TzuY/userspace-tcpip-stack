// src/gtpu_qos_marking.rs
//
// 3GPP TS 29.281 / TS 38.415 5G GTP-U Outer IP DSCP / 802.1p PCP Dynamic
// QoS Mapping & Translation Engine.
//
// Standard Reference:
//   - 3GPP TS 23.501 (System Architecture for the 5G System) Section 5.7 (5G QoS Model)
//   - 3GPP TS 38.415 (PDU Session User Plane Protocol) Section 5.5 (QoS Flow Identifier - QFI)
//   - 3GPP TS 29.281 (General Packet Radio System GTPv1-U)
//   - RFC 2474 (Definition of the Differentiated Services Field in the IPv4 and IPv6 Headers)
//   - IEEE 802.1Q / 802.1p (Priority Code Point - PCP)
//
// Concepts:
//   1. 6-bit QoS Flow Identifier (QFI 1..64) mapping to 5G 5QI profiles.
//   2. Outer IP ToS/Traffic Class DSCP marking (Bits 2..7) + ECN preservation (Bits 0..1).
//   3. Layer 2 IEEE 802.1Q PCP (3-bit Priority Code Point 0..7) calculation.
//   4. Delay-critical URLLC and GBR traffic identification.
//
// Pure safe Rust, zero external crates.

/// 5G QoS Resource Type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FiveQiResourceType {
    GuaranteedBitRate,
    NonGuaranteedBitRate,
    DelayCriticalGbr,
}

/// Standard or custom 5QI QoS Profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveQiProfile {
    pub five_qi: u32,
    pub resource_type: FiveQiResourceType,
    pub default_dscp: u8,
    pub default_pcp: u8,
    pub packet_delay_budget_ms: u32,
    pub description: String,
}

/// Output marking result for GTP-U outer encapsulating headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosMarkingResult {
    pub qfi: u8,
    pub five_qi: u32,
    pub dscp: u8,
    pub pcp: u8,
    pub tos_byte: u8,
    pub is_delay_critical: bool,
    pub delay_budget_ms: u32,
}

/// 5G GTP-U Outer QoS Marking & Translation Engine.
#[derive(Debug, Clone)]
pub struct GtpuQosMarkingEngine {
    /// 5QI profiles lookup table.
    pub profiles: Vec<FiveQiProfile>,
    /// Custom QFI -> 5QI bindings (QFI 1..64 -> 5QI number).
    pub qfi_to_5qi: Vec<(u8, u32)>,
    /// Statistics: total packets marked.
    pub total_packets_marked: u64,
    /// Statistics: total delay-critical / URLLC packets processed.
    pub total_delay_critical: u64,
}

impl GtpuQosMarkingEngine {
    /// Creates a new QoS Marking Engine pre-seeded with standard 3GPP 5QI profiles.
    pub fn new() -> Self {
        let mut engine = Self {
            profiles: Vec::new(),
            qfi_to_5qi: Vec::new(),
            total_packets_marked: 0,
            total_delay_critical: 0,
        };

        // Standard 3GPP TS 23.501 Table 5.7.4-1 Standardized 5QI to QoS mapping
        // 5QI 1: Conversational Voice (GBR, 100ms) -> DSCP EF (46), PCP 5
        engine.register_profile(FiveQiProfile {
            five_qi: 1,
            resource_type: FiveQiResourceType::GuaranteedBitRate,
            default_dscp: 46, // Expedited Forwarding (EF)
            default_pcp: 5,   // Voice (< 10ms latency)
            packet_delay_budget_ms: 100,
            description: "Conversational Voice".to_string(),
        });

        // 5QI 2: Conversational Video (GBR, 150ms) -> DSCP AF41 (34), PCP 4
        engine.register_profile(FiveQiProfile {
            five_qi: 2,
            resource_type: FiveQiResourceType::GuaranteedBitRate,
            default_dscp: 34, // Assured Forwarding AF41
            default_pcp: 4,   // Video (< 100ms latency)
            packet_delay_budget_ms: 150,
            description: "Conversational Video".to_string(),
        });

        // 5QI 80: Low Latency eMBB / Gaming (Non-GBR, 10ms) -> DSCP AF31 (26), PCP 6
        engine.register_profile(FiveQiProfile {
            five_qi: 80,
            resource_type: FiveQiResourceType::NonGuaranteedBitRate,
            default_dscp: 26, // Assured Forwarding AF31
            default_pcp: 6,   // Internetwork Control
            packet_delay_budget_ms: 10,
            description: "Low Latency eMBB / AR / Gaming".to_string(),
        });

        // 5QI 82: Delay-Critical GBR / URLLC (5ms) -> DSCP CS6 (48), PCP 7
        engine.register_profile(FiveQiProfile {
            five_qi: 82,
            resource_type: FiveQiResourceType::DelayCriticalGbr,
            default_dscp: 48, // Class Selector 6 (CS6)
            default_pcp: 7,   // Network Control / URLLC
            packet_delay_budget_ms: 5,
            description: "V2X / Discrete Automation URLLC".to_string(),
        });

        // 5QI 9: Default Internet (Non-GBR, 300ms) -> DSCP CS0 (0), PCP 0
        engine.register_profile(FiveQiProfile {
            five_qi: 9,
            resource_type: FiveQiResourceType::NonGuaranteedBitRate,
            default_dscp: 0, // Best Effort (CS0)
            default_pcp: 0,  // Best Effort
            packet_delay_budget_ms: 300,
            description: "Default Internet eMBB".to_string(),
        });

        // Default standard QFI bindings (QFI = 5QI for common standard IDs)
        engine.bind_qfi(1, 1);
        engine.bind_qfi(2, 2);
        engine.bind_qfi(9, 9);
        engine.bind_qfi(80, 80);
        engine.bind_qfi(82, 82);

        engine
    }

    /// Registers or updates a 5QI QoS profile.
    pub fn register_profile(&mut self, profile: FiveQiProfile) {
        if let Some(pos) = self
            .profiles
            .iter()
            .position(|p| p.five_qi == profile.five_qi)
        {
            self.profiles[pos] = profile;
        } else {
            self.profiles.push(profile);
        }
    }

    /// Binds a 6-bit QFI (1..64) to a 5QI profile.
    pub fn bind_qfi(&mut self, qfi: u8, five_qi: u32) {
        if let Some(pos) = self.qfi_to_5qi.iter().position(|(q, _)| *q == qfi) {
            self.qfi_to_5qi[pos].1 = five_qi;
        } else {
            self.qfi_to_5qi.push((qfi, five_qi));
        }
    }

    /// Computes the outer IP ToS byte and Ethernet 802.1p PCP for a given GTP-U packet.
    pub fn evaluate_marking(&mut self, qfi: u8, ecn_bits: u8) -> QosMarkingResult {
        self.total_packets_marked += 1;

        let five_qi = self
            .qfi_to_5qi
            .iter()
            .find(|(q, _)| *q == qfi)
            .map(|(_, fq)| *fq)
            .unwrap_or(9); // fallback to 5QI 9

        let profile = self
            .profiles
            .iter()
            .find(|p| p.five_qi == five_qi)
            .cloned()
            .unwrap_or_else(|| FiveQiProfile {
                five_qi,
                resource_type: FiveQiResourceType::NonGuaranteedBitRate,
                default_dscp: 0,
                default_pcp: 0,
                packet_delay_budget_ms: 300,
                description: "Fallback Best Effort".to_string(),
            });

        let dscp = profile.default_dscp & 0x3F;
        let pcp = profile.default_pcp & 0x07;
        let ecn = ecn_bits & 0x03;

        // ToS byte = (DSCP << 2) | ECN
        let tos_byte = (dscp << 2) | ecn;
        let is_delay_critical = profile.resource_type == FiveQiResourceType::DelayCriticalGbr;

        if is_delay_critical {
            self.total_delay_critical += 1;
        }

        QosMarkingResult {
            qfi,
            five_qi,
            dscp,
            pcp,
            tos_byte,
            is_delay_critical,
            delay_budget_ms: profile.packet_delay_budget_ms,
        }
    }

    /// Infers the likely 5QI based on observed outer DSCP marking.
    pub fn infer_5qi_from_dscp(&self, dscp: u8) -> u32 {
        self.profiles
            .iter()
            .find(|p| p.default_dscp == dscp)
            .map(|p| p.five_qi)
            .unwrap_or(9)
    }
}

impl Default for GtpuQosMarkingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_qos_marking_lifecycle() {
        let mut engine = GtpuQosMarkingEngine::new();

        // 1. Mark Voice QFI 1 (5QI 1, DSCP 46 EF, PCP 5, ECN 0)
        let m1 = engine.evaluate_marking(1, 0);
        assert_eq!(m1.five_qi, 1);
        assert_eq!(m1.dscp, 46);
        assert_eq!(m1.pcp, 5);
        assert_eq!(m1.tos_byte, (46 << 2)); // 184 = 0xB8
        assert!(!m1.is_delay_critical);
        assert_eq!(m1.delay_budget_ms, 100);

        // 2. Mark URLLC QFI 82 (5QI 82, DSCP 48 CS6, PCP 7, ECN 1 - ECT1)
        let m2 = engine.evaluate_marking(82, 1);
        assert_eq!(m2.five_qi, 82);
        assert_eq!(m2.dscp, 48);
        assert_eq!(m2.pcp, 7);
        assert_eq!(m2.tos_byte, (48 << 2) | 1); // 193 = 0xC1
        assert!(m2.is_delay_critical);
        assert_eq!(m2.delay_budget_ms, 5);

        // 3. Mark Default QFI 9 (5QI 9, DSCP 0, PCP 0)
        let m3 = engine.evaluate_marking(9, 0);
        assert_eq!(m3.five_qi, 9);
        assert_eq!(m3.dscp, 0);
        assert_eq!(m3.pcp, 0);
        assert_eq!(m3.tos_byte, 0);

        // 4. DSCP inference
        assert_eq!(engine.infer_5qi_from_dscp(46), 1);
        assert_eq!(engine.infer_5qi_from_dscp(48), 82);
        assert_eq!(engine.infer_5qi_from_dscp(0), 9);
    }
}
