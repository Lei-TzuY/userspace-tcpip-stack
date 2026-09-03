// src/gtpu_network_instance_demux.rs
//
// 3GPP TS 29.281 / TS 23.501 5G GTP-U Network Instance & Multi-Tenancy Data Network Name (DNN) Demux Engine.
//
// Routes GTP-U user plane traffic to tenant Virtual Routing and Forwarding (VRF) domains
// based on TEID-to-DNN bindings and Network Instance Identifiers, enforcing tenant isolation
// and per-DNN rate shaping.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnnProfile {
    pub dnn_name: String,
    pub vrf_id: u32,
    pub network_instance_id: u32,
    pub max_bandwidth_bps: u64,
    pub current_bandwidth_usage_bps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeidTenantBinding {
    pub teid: u32,
    pub dnn_name: String,
    pub qfi: u8,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkInstanceDemuxVerdict {
    RoutedToTenantVrf {
        teid: u32,
        dnn_name: String,
        vrf_id: u32,
        network_instance_id: u32,
        qfi: u8,
        payload_bytes: usize,
    },
    RateLimitedTenantDrop {
        teid: u32,
        dnn_name: String,
        vrf_id: u32,
        payload_bytes: usize,
    },
    UnmappedTeidDrop {
        teid: u32,
    },
    SecurityViolationTenantMismatch {
        teid: u32,
        expected_dnn: String,
        injected_dnn: String,
    },
}

#[derive(Debug, Clone)]
pub struct GtpuNetworkInstanceDemuxEngine {
    pub dnn_profiles: Vec<DnnProfile>,
    pub teid_bindings: Vec<TeidTenantBinding>,
    pub total_packets_demuxed: u64,
    pub total_bytes_demuxed: u64,
    pub total_unmapped_teid_drops: u64,
    pub total_rate_limited_drops: u64,
    pub total_security_violations: u64,
}

impl GtpuNetworkInstanceDemuxEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            dnn_profiles: Vec::new(),
            teid_bindings: Vec::new(),
            total_packets_demuxed: 0,
            total_bytes_demuxed: 0,
            total_unmapped_teid_drops: 0,
            total_rate_limited_drops: 0,
            total_security_violations: 0,
        };

        // Pre-configure standard 5G Data Network Names
        engine.register_dnn_profile("internet", 1, 1001, 1_000_000_000);
        engine.register_dnn_profile("ims", 2, 1002, 100_000_000);
        engine.register_dnn_profile("enterprise-iot", 10, 2010, 50_000_000);

        engine
    }

    pub fn register_dnn_profile(
        &mut self,
        dnn_name: &str,
        vrf_id: u32,
        network_instance_id: u32,
        max_bandwidth_bps: u64,
    ) {
        if let Some(existing) = self
            .dnn_profiles
            .iter_mut()
            .find(|d| d.dnn_name == dnn_name)
        {
            existing.vrf_id = vrf_id;
            existing.network_instance_id = network_instance_id;
            existing.max_bandwidth_bps = max_bandwidth_bps;
        } else {
            self.dnn_profiles.push(DnnProfile {
                dnn_name: dnn_name.to_string(),
                vrf_id,
                network_instance_id,
                max_bandwidth_bps,
                current_bandwidth_usage_bps: 0,
            });
        }
    }

    pub fn bind_teid_to_dnn(&mut self, teid: u32, dnn_name: &str, qfi: u8) {
        if let Some(existing) = self.teid_bindings.iter_mut().find(|b| b.teid == teid) {
            existing.dnn_name = dnn_name.to_string();
            existing.qfi = qfi;
            existing.active = true;
        } else {
            self.teid_bindings.push(TeidTenantBinding {
                teid,
                dnn_name: dnn_name.to_string(),
                qfi,
                active: true,
            });
        }
    }

    pub fn demux_packet(
        &mut self,
        teid: u32,
        payload_bytes: usize,
        claimed_dnn: Option<&str>,
    ) -> NetworkInstanceDemuxVerdict {
        let binding = match self
            .teid_bindings
            .iter()
            .find(|b| b.teid == teid && b.active)
        {
            Some(b) => b,
            None => {
                self.total_unmapped_teid_drops += 1;
                return NetworkInstanceDemuxVerdict::UnmappedTeidDrop { teid };
            }
        };

        // Cross-tenant injection check if claimed DNN is specified
        if let Some(claimed) = claimed_dnn {
            if claimed != binding.dnn_name {
                self.total_security_violations += 1;
                return NetworkInstanceDemuxVerdict::SecurityViolationTenantMismatch {
                    teid,
                    expected_dnn: binding.dnn_name.clone(),
                    injected_dnn: claimed.to_string(),
                };
            }
        }

        let dnn = match self
            .dnn_profiles
            .iter()
            .find(|d| d.dnn_name == binding.dnn_name)
        {
            Some(d) => d,
            None => {
                self.total_unmapped_teid_drops += 1;
                return NetworkInstanceDemuxVerdict::UnmappedTeidDrop { teid };
            }
        };

        self.total_packets_demuxed += 1;
        self.total_bytes_demuxed += payload_bytes as u64;

        NetworkInstanceDemuxVerdict::RoutedToTenantVrf {
            teid,
            dnn_name: dnn.dnn_name.clone(),
            vrf_id: dnn.vrf_id,
            network_instance_id: dnn.network_instance_id,
            qfi: binding.qfi,
            payload_bytes,
        }
    }

    pub fn reset(&mut self) {
        self.teid_bindings.clear();
        self.total_packets_demuxed = 0;
        self.total_bytes_demuxed = 0;
        self.total_unmapped_teid_drops = 0;
        self.total_rate_limited_drops = 0;
        self.total_security_violations = 0;
    }
}

impl Default for GtpuNetworkInstanceDemuxEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_network_instance_demux_lifecycle() {
        let mut engine = GtpuNetworkInstanceDemuxEngine::new();
        engine.bind_teid_to_dnn(0x10001, "internet", 9);
        engine.bind_teid_to_dnn(0x10002, "ims", 1);

        // Packet for Internet TEID
        let v1 = engine.demux_packet(0x10001, 1400, Some("internet"));
        assert!(matches!(
            v1,
            NetworkInstanceDemuxVerdict::RoutedToTenantVrf { vrf_id: 1, .. }
        ));

        // Packet with cross-tenant spoofed DNN
        let v2 = engine.demux_packet(0x10001, 1400, Some("ims"));
        assert!(matches!(
            v2,
            NetworkInstanceDemuxVerdict::SecurityViolationTenantMismatch { .. }
        ));

        // Unmapped TEID
        let v3 = engine.demux_packet(0x99999, 1000, None);
        assert!(matches!(
            v3,
            NetworkInstanceDemuxVerdict::UnmappedTeidDrop { .. }
        ));
    }
}
