//! Geneve Network Service Header (NSH) SFC Option Co-existence (RFC 8926 / RFC 8300).
//!
//! Implements Geneve Option Class 0x0104 carrying Network Service Header (NSH)
//! metadata for Service Function Chaining (SFC) across Geneve overlay tunnels.

use crate::geneve::GeneveOption;

/// Geneve Option Class for Service Function Chaining (NSH).
pub const GENEVE_OPT_CLASS_NSH: u16 = 0x0104;

/// Geneve Option Type for NSH MD Type 1.
pub const GENEVE_OPT_TYPE_NSH_MD1: u8 = 0x01;

/// NSH Next Protocol codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NshNextProto {
    Ipv4 = 0x01,
    Ipv6 = 0x02,
    Ethernet = 0x03,
    Nsh = 0x04,
    Mpls = 0x05,
    Experiment = 0xFE,
}

impl NshNextProto {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0x01 => Some(NshNextProto::Ipv4),
            0x02 => Some(NshNextProto::Ipv6),
            0x03 => Some(NshNextProto::Ethernet),
            0x04 => Some(NshNextProto::Nsh),
            0x05 => Some(NshNextProto::Mpls),
            0xFE => Some(NshNextProto::Experiment),
            _ => None,
        }
    }
}

/// NSH MD Type 1 Fixed 16-byte Context Header (RFC 8300).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NshMdType1Context {
    pub c1_platform_context: u32,
    pub c2_network_shared_context: u32,
    pub c3_service_node_context: u32,
    pub c4_service_id_context: u32,
}

impl NshMdType1Context {
    pub fn new(c1: u32, c2: u32, c3: u32, c4: u32) -> Self {
        NshMdType1Context {
            c1_platform_context: c1,
            c2_network_shared_context: c2,
            c3_service_node_context: c3,
            c4_service_id_context: c4,
        }
    }

    pub fn serialize(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.c1_platform_context.to_be_bytes());
        buf[4..8].copy_from_slice(&self.c2_network_shared_context.to_be_bytes());
        buf[8..12].copy_from_slice(&self.c3_service_node_context.to_be_bytes());
        buf[12..16].copy_from_slice(&self.c4_service_id_context.to_be_bytes());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 16 {
            return None;
        }
        let c1 = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let c2 = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let c3 = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let c4 = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Some(NshMdType1Context {
            c1_platform_context: c1,
            c2_network_shared_context: c2,
            c3_service_node_context: c3,
            c4_service_id_context: c4,
        })
    }
}

/// Complete NSH MD Type 1 Header (20 bytes total: 4-byte base + 4-byte path + 16-byte context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NshMd1Header {
    pub oam: bool,
    pub critical: bool,
    pub next_proto: NshNextProto,
    pub spi: u32, // 24-bit Service Path ID
    pub si: u8,   // 8-bit Service Index (decremented at each hop)
    pub context: NshMdType1Context,
}

impl NshMd1Header {
    pub fn new(spi: u32, si: u8, next_proto: NshNextProto, context: NshMdType1Context) -> Self {
        NshMd1Header {
            oam: false,
            critical: false,
            next_proto,
            spi: spi & 0x00FF_FFFF,
            si,
            context,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24);
        // Base Header: 4 bytes
        // Ver=0 (2 bits), OAM (1 bit), Unassigned (1 bit), Critical (1 bit), Reserved (1 bit), Length=6 (6 bits: 6 * 4 = 24 bytes total NSH), MD Type=1 (4 bits), Next Proto (8 bits)
        let mut b0 = 0u8;
        if self.oam {
            b0 |= 0x20;
        }
        if self.critical {
            b0 |= 0x08;
        }
        let b1 = 0x06; // Length = 6 (words)
        let b2 = 0x10; // MD Type = 1 (upper 4 bits)
        let b3 = self.next_proto as u8;

        buf.extend_from_slice(&[b0, b1, b2, b3]);

        // Service Path Header: 4 bytes (24-bit SPI + 8-bit SI)
        let spi_bytes = self.spi.to_be_bytes(); // [b0, b1, b2, b3] -> we use b1, b2, b3
        buf.push(spi_bytes[1]);
        buf.push(spi_bytes[2]);
        buf.push(spi_bytes[3]);
        buf.push(self.si);

        // Context Header: 16 bytes
        buf.extend_from_slice(&self.context.serialize());
        buf
    }

    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 24 {
            return None;
        }
        let b0 = buf[0];
        let oam = (b0 & 0x20) != 0;
        let critical = (b0 & 0x08) != 0;
        let md_type = (buf[2] >> 4) & 0x0F;
        if md_type != 1 {
            return None;
        }
        let next_proto = NshNextProto::from_u8(buf[3])?;

        let spi = ((buf[4] as u32) << 16) | ((buf[5] as u32) << 8) | (buf[6] as u32);
        let si = buf[7];
        let context = NshMdType1Context::parse(&buf[8..24])?;

        Some(NshMd1Header {
            oam,
            critical,
            next_proto,
            spi,
            si,
            context,
        })
    }

    /// Converts this NSH Header into a standard `GeneveOption`.
    pub fn to_geneve_option(&self) -> GeneveOption {
        let nsh_data = self.serialize();
        GeneveOption {
            class: GENEVE_OPT_CLASS_NSH,
            opt_type: GENEVE_OPT_TYPE_NSH_MD1,
            critical: self.critical,
            data: nsh_data,
        }
    }

    /// Parses an NSH Header from a `GeneveOption`.
    pub fn from_geneve_option(opt: &GeneveOption) -> Option<Self> {
        if opt.class != GENEVE_OPT_CLASS_NSH || opt.opt_type != GENEVE_OPT_TYPE_NSH_MD1 {
            return None;
        }
        Self::parse(&opt.data)
    }
}

/// Forwarding action taken by a Service Function Forwarder (SFF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SffForwardAction {
    ForwardToSf {
        spi: u32,
        si: u8,
        sf_instance: String,
        updated_nsh: NshMd1Header,
    },
    ForwardNextSff {
        spi: u32,
        si: u8,
        next_sff_tunnel: u32, // Next VNI
        updated_nsh: NshMd1Header,
    },
    ChainEgress {
        next_proto: NshNextProto,
        c1: u32,
        c2: u32,
    },
    Drop(String),
}

/// Service Function Forwarder (SFF) Routing Table.
#[derive(Debug, Clone, Default)]
pub struct SffEngine {
    /// Maps (SPI, SI) -> SF Instance or Next Hop
    pub hops: std::collections::HashMap<(u32, u8), SffHopTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SffHopTarget {
    LocalSf { sf_name: String },
    NextSff { next_vni: u32 },
    Egress,
}

impl SffEngine {
    pub fn new() -> Self {
        SffEngine {
            hops: std::collections::HashMap::new(),
        }
    }

    pub fn add_hop(&mut self, spi: u32, si: u8, target: SffHopTarget) {
        self.hops.insert((spi, si), target);
    }

    /// Processes an incoming Geneve NSH Option at an SFF node.
    pub fn process_nsh(&self, nsh: NshMd1Header) -> SffForwardAction {
        if nsh.si == 0 {
            return SffForwardAction::Drop("Service Index underflow (SI=0)".to_string());
        }

        let current_target = match self.hops.get(&(nsh.spi, nsh.si)) {
            Some(t) => t.clone(),
            None => {
                return SffForwardAction::Drop(format!(
                    "No SFC route for SPI {} SI {}",
                    nsh.spi, nsh.si
                ));
            }
        };

        match current_target {
            SffHopTarget::LocalSf { sf_name } => {
                // SFF sends to Local SF, SI is decremented for the next hop
                let mut next_nsh = nsh.clone();
                next_nsh.si -= 1;
                SffForwardAction::ForwardToSf {
                    spi: nsh.spi,
                    si: nsh.si,
                    sf_instance: sf_name,
                    updated_nsh: next_nsh,
                }
            }
            SffHopTarget::NextSff { next_vni } => {
                let mut next_nsh = nsh.clone();
                next_nsh.si -= 1;
                SffForwardAction::ForwardNextSff {
                    spi: nsh.spi,
                    si: nsh.si,
                    next_sff_tunnel: next_vni,
                    updated_nsh: next_nsh,
                }
            }
            SffHopTarget::Egress => SffForwardAction::ChainEgress {
                next_proto: nsh.next_proto,
                c1: nsh.context.c1_platform_context,
                c2: nsh.context.c2_network_shared_context,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_nsh_codec_and_option_roundtrip() {
        let ctx = NshMdType1Context::new(0x0A000001, 0x00000100, 0xCAFE0001, 0x12345678);
        let nsh = NshMd1Header::new(1001, 255, NshNextProto::Ipv4, ctx);

        let opt = nsh.to_geneve_option();
        assert_eq!(opt.class, GENEVE_OPT_CLASS_NSH);
        assert_eq!(opt.opt_type, GENEVE_OPT_TYPE_NSH_MD1);
        assert_eq!(opt.data.len(), 24);

        let parsed_nsh = NshMd1Header::from_geneve_option(&opt).unwrap();
        assert_eq!(parsed_nsh.spi, 1001);
        assert_eq!(parsed_nsh.si, 255);
        assert_eq!(parsed_nsh.next_proto, NshNextProto::Ipv4);
        assert_eq!(parsed_nsh.context, ctx);
    }

    #[test]
    fn test_sff_engine_chain_traversal() {
        let mut sff = SffEngine::new();
        let spi = 500;

        // Hop 255 -> Firewall
        sff.add_hop(
            spi,
            255,
            SffHopTarget::LocalSf {
                sf_name: "WAF_Cluster_1".to_string(),
            },
        );
        // Hop 254 -> DPI
        sff.add_hop(
            spi,
            254,
            SffHopTarget::LocalSf {
                sf_name: "DPI_Inspector".to_string(),
            },
        );
        // Hop 253 -> Egress
        sff.add_hop(spi, 253, SffHopTarget::Egress);

        let ctx = NshMdType1Context::new(10, 20, 30, 40);
        let nsh0 = NshMd1Header::new(spi, 255, NshNextProto::Ipv4, ctx);

        // Step 1: Hop 255
        let action1 = sff.process_nsh(nsh0);
        let nsh1 = match action1 {
            SffForwardAction::ForwardToSf {
                sf_instance,
                updated_nsh,
                ..
            } => {
                assert_eq!(sf_instance, "WAF_Cluster_1");
                assert_eq!(updated_nsh.si, 254);
                updated_nsh
            }
            other => panic!("Expected ForwardToSf, got {:?}", other),
        };

        // Step 2: Hop 254
        let action2 = sff.process_nsh(nsh1);
        let nsh2 = match action2 {
            SffForwardAction::ForwardToSf {
                sf_instance,
                updated_nsh,
                ..
            } => {
                assert_eq!(sf_instance, "DPI_Inspector");
                assert_eq!(updated_nsh.si, 253);
                updated_nsh
            }
            other => panic!("Expected ForwardToSf, got {:?}", other),
        };

        // Step 3: Hop 253 (Egress)
        let action3 = sff.process_nsh(nsh2);
        match action3 {
            SffForwardAction::ChainEgress { next_proto, c1, c2 } => {
                assert_eq!(next_proto, NshNextProto::Ipv4);
                assert_eq!(c1, 10);
                assert_eq!(c2, 20);
            }
            other => panic!("Expected ChainEgress, got {:?}", other),
        }
    }
}
