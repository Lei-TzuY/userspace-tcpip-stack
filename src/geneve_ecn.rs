//! Geneve Explicit Congestion Notification (ECN) & DiffServ Tunneling (RFC 8926 Section 4.5 / RFC 6040).
//!
//! Implements RFC 6040 compliant ECN encapsulation/decapsulation combining rules
//! and DiffServ (RFC 2983) Uniform / Pipe tunnel QoS behavior for Geneve overlays.

/// 2-bit ECN Codepoints (RFC 3168 / RFC 6040).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EcnCodepoint {
    NotEct = 0b00,
    Ect1 = 0b01,
    Ect0 = 0b10,
    Ce = 0b11,
}

impl EcnCodepoint {
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => EcnCodepoint::NotEct,
            0b01 => EcnCodepoint::Ect1,
            0b10 => EcnCodepoint::Ect0,
            0b11 => EcnCodepoint::Ce,
            _ => unreachable!(),
        }
    }

    pub fn to_bits(self) -> u8 {
        self as u8
    }
}

/// DiffServ Tunnel QoS Propagation Mode (RFC 2983).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffServTunnelMode {
    /// Outer DSCP is copied directly from Inner DSCP; Inner DSCP remains untouched.
    Uniform,
    /// Outer DSCP is set according to tunnel traffic class policy (independent of inner).
    Pipe { tunnel_dscp: u8 },
}

/// ECN Tunnel Encapsulation Mode (RFC 6040 Section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneveEcnMode {
    /// Normal Mode (RFC 6040 §4.1): Outer ECN reflects Inner ECN.
    Normal,
    /// Compatibility Mode (RFC 6040 §4.3): Outer is Not-ECT if inner is Not-ECT, or ECT(0) otherwise.
    Compatibility,
}

/// Decapsulation action verdict according to RFC 6040 §4.2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcnDecapResult {
    /// Admitted with synthesized inner ECN codepoint and restored inner IP packet.
    Admitted {
        inner_packet: Vec<u8>,
        final_ecn: EcnCodepoint,
        final_dscp: u8,
    },
    /// Congestion Encountered on Not-ECT stream - packet MUST be dropped to avoid silent loss.
    DroppedNotEctCongestion,
    /// Malformed or invalid inner IP packet.
    InvalidPacket,
}

/// Geneve Tunnel ECN & QoS Forwarding Engine.
#[derive(Debug, Clone)]
pub struct GeneveEcnPipeline {
    pub ecn_mode: GeneveEcnMode,
    pub diffserv_mode: DiffServTunnelMode,
}

impl GeneveEcnPipeline {
    pub fn new(ecn_mode: GeneveEcnMode, diffserv_mode: DiffServTunnelMode) -> Self {
        GeneveEcnPipeline {
            ecn_mode,
            diffserv_mode,
        }
    }

    /// Extract DSCP (6-bit) and ECN (2-bit) from IPv4/IPv6 packet header.
    pub fn extract_tos(ip_packet: &[u8]) -> Option<(u8, EcnCodepoint)> {
        if ip_packet.is_empty() {
            return None;
        }
        let version = ip_packet[0] >> 4;
        if version == 4 {
            if ip_packet.len() < 20 {
                return None;
            }
            let tos = ip_packet[1];
            let dscp = tos >> 2;
            let ecn = EcnCodepoint::from_bits(tos & 0b11);
            Some((dscp, ecn))
        } else if version == 6 {
            if ip_packet.len() < 40 {
                return None;
            }
            let tc = ((ip_packet[0] & 0x0F) << 4) | (ip_packet[1] >> 4);
            let dscp = tc >> 2;
            let ecn = EcnCodepoint::from_bits(tc & 0b11);
            Some((dscp, ecn))
        } else {
            None
        }
    }

    /// Ingress: Calculate outer IP ToS / Traffic Class byte based on Inner IP and Tunnel Policies.
    pub fn calculate_outer_tos(&self, inner_packet: &[u8]) -> Option<u8> {
        let (inner_dscp, inner_ecn) = Self::extract_tos(inner_packet)?;

        // 1. Calculate Outer DSCP
        let outer_dscp = match self.diffserv_mode {
            DiffServTunnelMode::Uniform => inner_dscp,
            DiffServTunnelMode::Pipe { tunnel_dscp } => tunnel_dscp & 0x3F,
        };

        // 2. Calculate Outer ECN (RFC 6040 §4.1 / §4.3)
        let outer_ecn = match self.ecn_mode {
            GeneveEcnMode::Normal => inner_ecn,
            GeneveEcnMode::Compatibility => match inner_ecn {
                EcnCodepoint::NotEct => EcnCodepoint::NotEct,
                _ => EcnCodepoint::Ect0,
            },
        };

        let outer_tos = (outer_dscp << 2) | outer_ecn.to_bits();
        Some(outer_tos)
    }

    /// Egress: Decapsulate outer IP/Geneve and apply RFC 6040 §4.2 ECN combining rules.
    pub fn decapsulate_and_combine_ecn(
        &self,
        outer_tos: u8,
        mut inner_packet: Vec<u8>,
    ) -> EcnDecapResult {
        let (inner_dscp, inner_ecn) = match Self::extract_tos(&inner_packet) {
            Some(res) => res,
            None => return EcnDecapResult::InvalidPacket,
        };

        let outer_ecn = EcnCodepoint::from_bits(outer_tos & 0b11);

        // RFC 6040 Table 4: Egress ECN Decapsulation Combination Matrix
        let final_ecn = match (inner_ecn, outer_ecn) {
            // Inner Not-ECT
            (EcnCodepoint::NotEct, EcnCodepoint::NotEct) => EcnCodepoint::NotEct,
            (EcnCodepoint::NotEct, EcnCodepoint::Ect0) => EcnCodepoint::NotEct,
            (EcnCodepoint::NotEct, EcnCodepoint::Ect1) => EcnCodepoint::NotEct,
            (EcnCodepoint::NotEct, EcnCodepoint::Ce) => {
                // RFC 6040 Section 4.2.2: Cannot propagate CE to Not-ECT inner -> Drop
                return EcnDecapResult::DroppedNotEctCongestion;
            }

            // Inner ECT(0)
            (EcnCodepoint::Ect0, EcnCodepoint::NotEct) => EcnCodepoint::Ect0,
            (EcnCodepoint::Ect0, EcnCodepoint::Ect0) => EcnCodepoint::Ect0,
            (EcnCodepoint::Ect0, EcnCodepoint::Ect1) => EcnCodepoint::Ect0,
            (EcnCodepoint::Ect0, EcnCodepoint::Ce) => EcnCodepoint::Ce,

            // Inner ECT(1)
            (EcnCodepoint::Ect1, EcnCodepoint::NotEct) => EcnCodepoint::Ect1,
            (EcnCodepoint::Ect1, EcnCodepoint::Ect0) => EcnCodepoint::Ect1,
            (EcnCodepoint::Ect1, EcnCodepoint::Ect1) => EcnCodepoint::Ect1,
            (EcnCodepoint::Ect1, EcnCodepoint::Ce) => EcnCodepoint::Ce,

            // Inner CE
            (EcnCodepoint::Ce, _) => EcnCodepoint::Ce,
        };

        // Rewrite inner packet ToS/Traffic Class with final_ecn and final_dscp
        let final_dscp = match self.diffserv_mode {
            DiffServTunnelMode::Uniform => (outer_tos >> 2) & 0x3F,
            DiffServTunnelMode::Pipe { .. } => inner_dscp,
        };

        let final_tos = (final_dscp << 2) | final_ecn.to_bits();
        let version = inner_packet[0] >> 4;
        if version == 4 {
            inner_packet[1] = final_tos;
            // Recalculate IPv4 Checksum
            inner_packet[10] = 0;
            inner_packet[11] = 0;
            let mut sum = 0u32;
            let ihl = (inner_packet[0] & 0x0F) as usize * 4;
            for i in (0..ihl).step_by(2) {
                let word = u16::from_be_bytes([inner_packet[i], inner_packet[i + 1]]);
                sum = sum.wrapping_add(word as u32);
            }
            while (sum >> 16) > 0 {
                sum = (sum & 0xFFFF) + (sum >> 16);
            }
            let csum = !(sum as u16);
            inner_packet[10..12].copy_from_slice(&csum.to_be_bytes());
        } else if version == 6 {
            inner_packet[0] = 0x60 | (final_tos >> 4);
            inner_packet[1] = (final_tos << 4) | (inner_packet[1] & 0x0F);
        }

        EcnDecapResult::Admitted {
            inner_packet,
            final_ecn,
            final_dscp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_ecn_ingress_normal_and_compat() {
        let pipeline_normal =
            GeneveEcnPipeline::new(GeneveEcnMode::Normal, DiffServTunnelMode::Uniform);

        // IPv4 packet with DSCP EF (46) and ECN ECT(0) (2) -> ToS = (46 << 2) | 2 = 186 (0xBA)
        let mut ip_pkt = vec![0x45, 0xBA, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
        ip_pkt.extend_from_slice(&[10, 0, 0, 1]);
        ip_pkt.extend_from_slice(&[10, 0, 0, 2]);

        let outer_tos = pipeline_normal.calculate_outer_tos(&ip_pkt).unwrap();
        assert_eq!(outer_tos, 0xBA);

        // Pipe mode with fixed tunnel DSCP AF11 (10 -> 0x0A)
        let pipeline_pipe = GeneveEcnPipeline::new(
            GeneveEcnMode::Normal,
            DiffServTunnelMode::Pipe { tunnel_dscp: 10 },
        );
        let outer_tos_pipe = pipeline_pipe.calculate_outer_tos(&ip_pkt).unwrap();
        assert_eq!(outer_tos_pipe, (10 << 2) | 0b10);
    }

    #[test]
    fn test_geneve_ecn_egress_combining_rules_and_ce_drop() {
        let pipeline = GeneveEcnPipeline::new(
            GeneveEcnMode::Normal,
            DiffServTunnelMode::Pipe { tunnel_dscp: 0 },
        );

        // 1. Inner ECT(0) (2), Outer CE (3) -> Combined to Inner CE (3)
        let mut ip_ect0 = vec![0x45, 0x02, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
        ip_ect0.extend_from_slice(&[10, 0, 0, 1]);
        ip_ect0.extend_from_slice(&[10, 0, 0, 2]);

        let outer_ce_tos = 0b11; // CE
        let res1 = pipeline.decapsulate_and_combine_ecn(outer_ce_tos, ip_ect0);
        match res1 {
            EcnDecapResult::Admitted {
                final_ecn,
                inner_packet,
                ..
            } => {
                assert_eq!(final_ecn, EcnCodepoint::Ce);
                assert_eq!(inner_packet[1] & 0b11, 0b11);
            }
            other => panic!("Expected Admitted CE, got {:?}", other),
        }

        // 2. Inner Not-ECT (0), Outer CE (3) -> Must Drop!
        let mut ip_not_ect = vec![0x45, 0x00, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
        ip_not_ect.extend_from_slice(&[10, 0, 0, 1]);
        ip_not_ect.extend_from_slice(&[10, 0, 0, 2]);

        let res2 = pipeline.decapsulate_and_combine_ecn(outer_ce_tos, ip_not_ect);
        assert_eq!(res2, EcnDecapResult::DroppedNotEctCongestion);
    }
}
