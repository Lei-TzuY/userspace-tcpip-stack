// =============================================================================
// EVPN Layer 2 Dynamic ARP Inspection (DAI) & Rate-Limiter Engine (RFC 7432)
// =============================================================================
//
// Dynamic ARP Inspection (DAI) prevents ARP poisoning and man-in-the-middle (MitM)
// attacks on multi-tenant EVPN bridges by intercepting ARP packets on untrusted
// ports and validating them against authorized IP-MAC binding tables.
//
// Features:
//   1. Port Trust Hierarchy: Trusted ports (uplinks, core spines) bypass DAI.
//   2. Sender MAC & IP Validation: Ensures ARP header Sender MAC matches Ethernet
//      source MAC and is bound to the claimed IPv4 address in the active VNI.
//   3. Per-Port ARP Rate Policing: Token bucket limits ARP packet rate per second
//      to prevent control plane CPU exhaustion.
//
// Pure safe Rust, zero external crates.

use crate::ethernet::MacAddress;
use crate::ipv4::Ipv4Address;

/// DAI inspection verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaiVerdict {
    /// Valid ARP packet allowed to be forwarded / processed.
    Permit,
    /// Bypassed inspection because arriving on a trusted port.
    BypassTrusted,
    /// Dropped because ARP sender rate exceeds token bucket burst limit.
    DropRateLimitExceeded,
    /// Dropped because ARP payload sender MAC does not match Ethernet source MAC.
    DropMacMismatch,
    /// Dropped because (VNI, Port, MAC, IP) tuple does not exist in binding table.
    DropBindingNotFound,
}

/// Token bucket state for per-port ARP rate limiting.
#[derive(Debug, Clone)]
pub struct ArpRateBucket {
    pub max_tokens: u32,
    pub current_tokens: u32,
    pub refill_rate_per_sec: u32,
    pub last_refill_secs: u64,
}

impl ArpRateBucket {
    pub fn new(max_tokens: u32, refill_rate_per_sec: u32) -> Self {
        Self {
            max_tokens,
            current_tokens: max_tokens,
            refill_rate_per_sec,
            last_refill_secs: 0,
        }
    }

    pub fn consume(&mut self, current_time_secs: u64) -> bool {
        let elapsed = current_time_secs.saturating_sub(self.last_refill_secs);
        if elapsed > 0 {
            let added = (elapsed as u32).saturating_mul(self.refill_rate_per_sec);
            self.current_tokens = self
                .current_tokens
                .saturating_add(added)
                .min(self.max_tokens);
            self.last_refill_secs = current_time_secs;
        }

        if self.current_tokens > 0 {
            self.current_tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Authorized IP-MAC Binding Entry for DAI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaiBinding {
    pub vni: u32,
    pub port_id: u32,
    pub mac: MacAddress,
    pub ip: Ipv4Address,
}

/// EVPN Layer 2 Dynamic ARP Inspection (DAI) Engine.
pub struct EvpnDaiEngine {
    pub trusted_ports: Vec<u32>,
    pub bindings: Vec<DaiBinding>,
    pub port_rate_limiters: Vec<(u32, ArpRateBucket)>,
    pub default_rate_limit_pps: u32,
    pub total_permitted: u64,
    pub total_bypassed: u64,
    pub total_ratelimit_drops: u64,
    pub total_validation_drops: u64,
}

impl EvpnDaiEngine {
    pub fn new(default_rate_limit_pps: u32) -> Self {
        Self {
            trusted_ports: Vec::new(),
            bindings: Vec::new(),
            port_rate_limiters: Vec::new(),
            default_rate_limit_pps,
            total_permitted: 0,
            total_bypassed: 0,
            total_ratelimit_drops: 0,
            total_validation_drops: 0,
        }
    }

    /// Set trusted status for a port.
    pub fn set_port_trusted(&mut self, port_id: u32, trusted: bool) {
        if trusted {
            if !self.trusted_ports.contains(&port_id) {
                self.trusted_ports.push(port_id);
            }
        } else {
            self.trusted_ports.retain(|&p| p != port_id);
        }
    }

    /// Add an authorized binding.
    pub fn add_binding(&mut self, binding: DaiBinding) {
        if !self.bindings.contains(&binding) {
            self.bindings.push(binding);
        }
    }

    /// Inspect an ingress ARP packet.
    pub fn inspect_arp(
        &mut self,
        vni: u32,
        port_id: u32,
        eth_src_mac: MacAddress,
        arp_sender_mac: MacAddress,
        arp_sender_ip: Ipv4Address,
        current_time_secs: u64,
    ) -> DaiVerdict {
        // 1. Check if port is trusted
        if self.trusted_ports.contains(&port_id) {
            self.total_bypassed += 1;
            return DaiVerdict::BypassTrusted;
        }

        // 2. Per-port rate limiting
        let bucket = if let Some(pos) = self
            .port_rate_limiters
            .iter()
            .position(|(p, _)| *p == port_id)
        {
            &mut self.port_rate_limiters[pos].1
        } else {
            self.port_rate_limiters.push((
                port_id,
                ArpRateBucket::new(self.default_rate_limit_pps * 2, self.default_rate_limit_pps),
            ));
            let last_idx = self.port_rate_limiters.len() - 1;
            &mut self.port_rate_limiters[last_idx].1
        };

        if !bucket.consume(current_time_secs) {
            self.total_ratelimit_drops += 1;
            return DaiVerdict::DropRateLimitExceeded;
        }

        // 3. Validate Ethernet source MAC == ARP sender MAC
        if eth_src_mac != arp_sender_mac {
            self.total_validation_drops += 1;
            return DaiVerdict::DropMacMismatch;
        }

        // 4. Validate (VNI, Port, MAC, IP) against binding database
        let is_bound = self.bindings.iter().any(|b| {
            b.vni == vni && b.port_id == port_id && b.mac == arp_sender_mac && b.ip == arp_sender_ip
        });

        if is_bound {
            self.total_permitted += 1;
            DaiVerdict::Permit
        } else {
            self.total_validation_drops += 1;
            DaiVerdict::DropBindingNotFound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dai_inspection_lifecycle() {
        let mut dai = EvpnDaiEngine::new(10); // 10 pps limit

        let vni = 100;
        let access_port = 1;
        let trusted_uplink = 10;
        let mac = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        let ip = Ipv4Address::new(10, 0, 0, 55);

        dai.set_port_trusted(trusted_uplink, true);
        dai.add_binding(DaiBinding {
            vni,
            port_id: access_port,
            mac,
            ip,
        });

        // 1. Legitimate ARP on untrusted port -> Permit
        assert_eq!(
            dai.inspect_arp(vni, access_port, mac, mac, ip, 1000),
            DaiVerdict::Permit
        );

        // 2. ARP arriving on trusted uplink -> Bypass
        assert_eq!(
            dai.inspect_arp(vni, trusted_uplink, mac, mac, ip, 1000),
            DaiVerdict::BypassTrusted
        );

        // 3. MAC mismatch attack -> DropMacMismatch
        let fake_eth_mac = MacAddress([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        assert_eq!(
            dai.inspect_arp(vni, access_port, fake_eth_mac, mac, ip, 1000),
            DaiVerdict::DropMacMismatch
        );

        // 4. Spoofed IP address -> DropBindingNotFound
        let spoofed_ip = Ipv4Address::new(10, 0, 0, 1);
        assert_eq!(
            dai.inspect_arp(vni, access_port, mac, mac, spoofed_ip, 1000),
            DaiVerdict::DropBindingNotFound
        );
    }
}
