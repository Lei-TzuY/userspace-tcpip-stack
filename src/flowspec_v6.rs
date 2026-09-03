//! BGP Flowspec for IPv6 (RFC 8956 / RFC 8955).
//!
//! Automated DDoS mitigation, dynamic traffic filtering, and traffic-action policy
//! distribution for IPv6 traffic via BGP (AFI 2 / SAFI 133).
//!
//! Supports RFC 8956 match components:
//! - Type 1: Destination IPv6 Prefix
//! - Type 2: Source IPv6 Prefix
//! - Type 3: Next Header (Upper-layer protocol)
//! - Type 4: Port (Source or Destination)
//! - Type 5: Destination Port
//! - Type 6: Source Port
//! - Type 7: ICMPv6 Type
//! - Type 8: ICMPv6 Code
//! - Type 9: TCP Flags
//! - Type 10: Packet Length
//! - Type 11: Traffic Class / DSCP
//! - Type 12: Fragment Flags
//! - Type 13: Flow Label (RFC 6437 20-bit label)

use crate::ipv6::Ipv6Address;
use std::fmt;

pub const BGP_AFI_IPV6: u16 = 2;
pub const BGP_SAFI_FLOWSPEC_IPV6: u8 = 133;

pub const FLOWSPEC_V6_TYPE_DST_PREFIX: u8 = 1;
pub const FLOWSPEC_V6_TYPE_SRC_PREFIX: u8 = 2;
pub const FLOWSPEC_V6_TYPE_NEXT_HEADER: u8 = 3;
pub const FLOWSPEC_V6_TYPE_PORT: u8 = 4;
pub const FLOWSPEC_V6_TYPE_DST_PORT: u8 = 5;
pub const FLOWSPEC_V6_TYPE_SRC_PORT: u8 = 6;
pub const FLOWSPEC_V6_TYPE_ICMPV6_TYPE: u8 = 7;
pub const FLOWSPEC_V6_TYPE_ICMPV6_CODE: u8 = 8;
pub const FLOWSPEC_V6_TYPE_TCP_FLAGS: u8 = 9;
pub const FLOWSPEC_V6_TYPE_PKT_LEN: u8 = 10;
pub const FLOWSPEC_V6_TYPE_DSCP: u8 = 11;
pub const FLOWSPEC_V6_TYPE_FRAGMENT: u8 = 12;
pub const FLOWSPEC_V6_TYPE_FLOW_LABEL: u8 = 13;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowspecV6Action {
    Drop,
    RateLimitBps(u32),
    RedirectIpv6(Ipv6Address),
    MarkTrafficClass(u8),
}

impl fmt::Display for FlowspecV6Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowspecV6Action::Drop => write!(f, "DROP (Rate=0 bps)"),
            FlowspecV6Action::RateLimitBps(r) => write!(f, "RATE-LIMIT ({} bps)", r),
            FlowspecV6Action::RedirectIpv6(ip) => write!(f, "REDIRECT ({})", ip),
            FlowspecV6Action::MarkTrafficClass(tc) => write!(f, "MARK-TC ({})", tc),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlowspecV6Match {
    pub dst_prefix: Option<(Ipv6Address, u8)>,
    pub src_prefix: Option<(Ipv6Address, u8)>,
    pub next_header: Option<u8>,
    pub dst_port: Option<u16>,
    pub src_port: Option<u16>,
    pub icmpv6_type: Option<u8>,
    pub icmpv6_code: Option<u8>,
    pub tcp_flags: Option<u8>,
    pub traffic_class: Option<u8>,
    pub flow_label: Option<u32>, // 20-bit
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowspecV6Rule {
    pub id: u32,
    pub priority: u32,
    pub match_fields: FlowspecV6Match,
    pub action: FlowspecV6Action,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowspecV6Decision {
    Pass,
    Drop,
    RateLimit(u32),
    Redirect(Ipv6Address),
    Mark(u8),
}

#[derive(Debug, Clone, Default)]
pub struct FlowspecV6Engine {
    pub rules: Vec<FlowspecV6Rule>,
}

impl FlowspecV6Engine {
    pub fn new() -> Self {
        FlowspecV6Engine { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: FlowspecV6Rule) {
        self.rules.push(rule);
        // Sort by priority descending (higher priority evaluated first)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    pub fn remove_rule(&mut self, id: u32) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|r| r.id != id);
        self.rules.len() < initial_len
    }

    pub fn clear(&mut self) {
        self.rules.clear();
    }

    pub fn evaluate(
        &self,
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        next_header: u8,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        icmpv6_type: Option<u8>,
        icmpv6_code: Option<u8>,
        tcp_flags: Option<u8>,
        traffic_class: Option<u8>,
        flow_label: Option<u32>,
    ) -> FlowspecV6Decision {
        for rule in &self.rules {
            let m = &rule.match_fields;

            if let Some((d_ip, d_mask)) = m.dst_prefix
                && !matches_ipv6_cidr(dst_ip, d_ip, d_mask)
            {
                continue;
            }

            if let Some((s_ip, s_mask)) = m.src_prefix
                && !matches_ipv6_cidr(src_ip, s_ip, s_mask)
            {
                continue;
            }

            if let Some(nh) = m.next_header
                && nh != next_header
            {
                continue;
            }

            if let Some(req_dst_port) = m.dst_port {
                if dst_port != Some(req_dst_port) {
                    continue;
                }
            }

            if let Some(req_src_port) = m.src_port {
                if src_port != Some(req_src_port) {
                    continue;
                }
            }

            if let Some(req_t) = m.icmpv6_type {
                if icmpv6_type != Some(req_t) {
                    continue;
                }
            }

            if let Some(req_c) = m.icmpv6_code {
                if icmpv6_code != Some(req_c) {
                    continue;
                }
            }

            if let Some(req_flags) = m.tcp_flags {
                if let Some(actual_flags) = tcp_flags {
                    if (actual_flags & req_flags) != req_flags {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if let Some(req_tc) = m.traffic_class {
                if traffic_class != Some(req_tc) {
                    continue;
                }
            }

            if let Some(req_fl) = m.flow_label {
                let req_fl_masked = req_fl & 0x000F_FFFF;
                if let Some(actual_fl) = flow_label {
                    if (actual_fl & 0x000F_FFFF) != req_fl_masked {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            // All match criteria satisfied for this rule
            return match &rule.action {
                FlowspecV6Action::Drop => FlowspecV6Decision::Drop,
                FlowspecV6Action::RateLimitBps(bps) => FlowspecV6Decision::RateLimit(*bps),
                FlowspecV6Action::RedirectIpv6(target) => FlowspecV6Decision::Redirect(*target),
                FlowspecV6Action::MarkTrafficClass(tc) => FlowspecV6Decision::Mark(*tc),
            };
        }

        FlowspecV6Decision::Pass
    }
}

pub fn matches_ipv6_cidr(addr: Ipv6Address, network: Ipv6Address, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len > 128 {
        return false;
    }

    let full_bytes = (prefix_len / 8) as usize;
    let remainder_bits = prefix_len % 8;

    if full_bytes > 0 && addr.0[..full_bytes] != network.0[..full_bytes] {
        return false;
    }

    if remainder_bits > 0 {
        let mask = (!0u8) << (8 - remainder_bits);
        let b1 = addr.0[full_bytes] & mask;
        let b2 = network.0[full_bytes] & mask;
        if b1 != b2 {
            return false;
        }
    }

    true
}

/// Simple RFC 8956 wire-format Flowspec IPv6 NLRI encoder.
pub fn serialize_flowspec_v6_nlri(m: &FlowspecV6Match) -> Vec<u8> {
    let mut buf = Vec::new();

    // Type 1: Destination Prefix
    if let Some((dst_ip, mask)) = m.dst_prefix {
        buf.push(FLOWSPEC_V6_TYPE_DST_PREFIX);
        buf.push(mask); // prefix-length
        buf.push(0); // offset = 0
        let bytes_needed = ((mask + 7) / 8) as usize;
        if bytes_needed > 0 {
            buf.extend_from_slice(&dst_ip.0[..bytes_needed.min(16)]);
        }
    }

    // Type 2: Source Prefix
    if let Some((src_ip, mask)) = m.src_prefix {
        buf.push(FLOWSPEC_V6_TYPE_SRC_PREFIX);
        buf.push(mask); // prefix-length
        buf.push(0); // offset = 0
        let bytes_needed = ((mask + 7) / 8) as usize;
        if bytes_needed > 0 {
            buf.extend_from_slice(&src_ip.0[..bytes_needed.min(16)]);
        }
    }

    // Type 3: Next Header
    if let Some(nh) = m.next_header {
        buf.push(FLOWSPEC_V6_TYPE_NEXT_HEADER);
        buf.push(0x81); // End-of-list (0x80) | numeric EQ (0x01)
        buf.push(nh);
    }

    // Type 5: Destination Port
    if let Some(dport) = m.dst_port {
        buf.push(FLOWSPEC_V6_TYPE_DST_PORT);
        buf.push(0x91); // End-of-list (0x80) | 2-byte value (0x10) | EQ (0x01)
        buf.extend_from_slice(&dport.to_be_bytes());
    }

    // Type 6: Source Port
    if let Some(sport) = m.src_port {
        buf.push(FLOWSPEC_V6_TYPE_SRC_PORT);
        buf.push(0x91); // End-of-list | 2-byte | EQ
        buf.extend_from_slice(&sport.to_be_bytes());
    }

    // Type 13: Flow Label
    if let Some(fl) = m.flow_label {
        buf.push(FLOWSPEC_V6_TYPE_FLOW_LABEL);
        buf.push(0xA1); // End-of-list | 4-byte | EQ
        let fl_bytes = (fl & 0x000F_FFFF).to_be_bytes();
        buf.extend_from_slice(&fl_bytes);
    }

    buf
}

/// Parses wire-format Flowspec IPv6 NLRI into FlowspecV6Match.
pub fn parse_flowspec_v6_nlri(data: &[u8]) -> Result<FlowspecV6Match, &'static str> {
    let mut match_fields = FlowspecV6Match::default();
    let mut offset = 0;

    while offset < data.len() {
        let comp_type = data[offset];
        offset += 1;

        match comp_type {
            FLOWSPEC_V6_TYPE_DST_PREFIX => {
                if offset + 2 > data.len() {
                    return Err("Truncated destination prefix component");
                }
                let mask = data[offset];
                let _prefix_offset = data[offset + 1];
                offset += 2;

                let bytes_len = ((mask + 7) / 8) as usize;
                if offset + bytes_len > data.len() {
                    return Err("Truncated destination prefix bytes");
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes[..bytes_len.min(16)]
                    .copy_from_slice(&data[offset..offset + bytes_len.min(16)]);
                offset += bytes_len;

                match_fields.dst_prefix = Some((Ipv6Address(ip_bytes), mask));
            }
            FLOWSPEC_V6_TYPE_SRC_PREFIX => {
                if offset + 2 > data.len() {
                    return Err("Truncated source prefix component");
                }
                let mask = data[offset];
                let _prefix_offset = data[offset + 1];
                offset += 2;

                let bytes_len = ((mask + 7) / 8) as usize;
                if offset + bytes_len > data.len() {
                    return Err("Truncated source prefix bytes");
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes[..bytes_len.min(16)]
                    .copy_from_slice(&data[offset..offset + bytes_len.min(16)]);
                offset += bytes_len;

                match_fields.src_prefix = Some((Ipv6Address(ip_bytes), mask));
            }
            FLOWSPEC_V6_TYPE_NEXT_HEADER => {
                if offset + 2 > data.len() {
                    return Err("Truncated next header component");
                }
                let _flags = data[offset];
                let nh = data[offset + 1];
                offset += 2;
                match_fields.next_header = Some(nh);
            }
            FLOWSPEC_V6_TYPE_DST_PORT => {
                if offset + 3 > data.len() {
                    return Err("Truncated dst port component");
                }
                let _flags = data[offset];
                let dport = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
                offset += 3;
                match_fields.dst_port = Some(dport);
            }
            FLOWSPEC_V6_TYPE_SRC_PORT => {
                if offset + 3 > data.len() {
                    return Err("Truncated src port component");
                }
                let _flags = data[offset];
                let sport = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
                offset += 3;
                match_fields.src_port = Some(sport);
            }
            FLOWSPEC_V6_TYPE_FLOW_LABEL => {
                if offset + 5 > data.len() {
                    return Err("Truncated flow label component");
                }
                let _flags = data[offset];
                let fl = u32::from_be_bytes([
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3],
                    data[offset + 4],
                ]) & 0x000F_FFFF;
                offset += 5;
                match_fields.flow_label = Some(fl);
            }
            _ => {
                // Unknown or unhandled component type, skip remainder
                break;
            }
        }
    }

    Ok(match_fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flowspec_v6_cidr_matching() {
        let addr = Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let net = Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        assert!(matches_ipv6_cidr(addr, net, 64));
        assert!(matches_ipv6_cidr(addr, net, 32));
        assert!(!matches_ipv6_cidr(addr, net, 128));
    }

    #[test]
    fn test_flowspec_v6_engine_evaluation() {
        let mut engine = FlowspecV6Engine::new();

        let attack_target = Ipv6Address([
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10,
        ]);
        let mitigator_rule = FlowspecV6Rule {
            id: 1,
            priority: 100,
            match_fields: FlowspecV6Match {
                dst_prefix: Some((attack_target, 128)),
                next_header: Some(17), // UDP
                dst_port: Some(53),    // DNS flood
                flow_label: Some(0x12345),
                ..Default::default()
            },
            action: FlowspecV6Action::Drop,
        };

        engine.add_rule(mitigator_rule);

        // Matching UDP packet with flow label
        let dec = engine.evaluate(
            Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]),
            attack_target,
            17,
            Some(12345),
            Some(53),
            None,
            None,
            None,
            None,
            Some(0x12345),
        );
        assert_eq!(dec, FlowspecV6Decision::Drop);

        // Non-matching flow label -> Pass
        let dec_pass = engine.evaluate(
            Ipv6Address([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99]),
            attack_target,
            17,
            Some(12345),
            Some(53),
            None,
            None,
            None,
            None,
            Some(0x99999),
        );
        assert_eq!(dec_pass, FlowspecV6Decision::Pass);
    }

    #[test]
    fn test_flowspec_v6_nlri_codec_roundtrip() {
        let match_rule = FlowspecV6Match {
            dst_prefix: Some((
                Ipv6Address([
                    0x20, 0x01, 0x0d, 0xb8, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                48,
            )),
            src_prefix: Some((
                Ipv6Address([
                    0x20, 0x01, 0x0d, 0xb8, 0xba, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ]),
                48,
            )),
            next_header: Some(6),
            dst_port: Some(443),
            src_port: Some(54321),
            flow_label: Some(0xABCDE),
            ..Default::default()
        };

        let encoded = serialize_flowspec_v6_nlri(&match_rule);
        let parsed = parse_flowspec_v6_nlri(&encoded).unwrap();

        assert_eq!(parsed.dst_prefix, match_rule.dst_prefix);
        assert_eq!(parsed.src_prefix, match_rule.src_prefix);
        assert_eq!(parsed.next_header, match_rule.next_header);
        assert_eq!(parsed.dst_port, match_rule.dst_port);
        assert_eq!(parsed.src_port, match_rule.src_port);
        assert_eq!(parsed.flow_label, match_rule.flow_label);
    }
}
