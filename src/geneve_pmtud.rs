//! Geneve Path MTU Discovery (PMTUD) & Active Flow Probe Option (RFC 8926 §4.4 / RFC 1191).
//!
//! Provides in-band active path MTU probing and tunnel bottleneck discovery
//! through specialized Geneve Variable Length Options.

use crate::geneve_opts::GeneveOptionTlv;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

pub const GENEVE_CLASS_PMTUD_OAM: u16 = 0x0109;
pub const GENEVE_TYPE_PMTUD_PROBE: u8 = 0x10;

pub const GENEVE_PMTUD_FLAG_REQ: u8 = 0x01;
pub const GENEVE_PMTUD_FLAG_REPLY: u8 = 0x02;
pub const GENEVE_PMTUD_FLAG_FRAG_DETECTED: u8 = 0x04;

/// Geneve PMTUD & Active Probe Option Payload (8 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenevePmtudOption {
    pub probe_sequence: u32,
    pub probed_mtu_size: u16,
    pub flags: u8,
    pub min_supported_mtu: u16,
}

impl GenevePmtudOption {
    pub fn new_request(probe_sequence: u32, probed_mtu_size: u16) -> Self {
        Self {
            probe_sequence,
            probed_mtu_size,
            flags: GENEVE_PMTUD_FLAG_REQ,
            min_supported_mtu: probed_mtu_size,
        }
    }

    pub fn new_reply(probe_sequence: u32, probed_mtu_size: u16, min_supported_mtu: u16) -> Self {
        Self {
            probe_sequence,
            probed_mtu_size,
            flags: GENEVE_PMTUD_FLAG_REPLY,
            min_supported_mtu,
        }
    }

    /// Converts to a standard Geneve Option TLV.
    pub fn to_tlv(&self) -> GeneveOptionTlv {
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&self.probe_sequence.to_be_bytes());
        data.extend_from_slice(&self.probed_mtu_size.to_be_bytes());
        data.push(self.flags);
        data.push(0); // Reserved byte
        data.extend_from_slice(&self.min_supported_mtu.to_be_bytes());
        data.extend_from_slice(&[0, 0]); // Pad to 12 bytes (multiple of 4)

        GeneveOptionTlv::new(
            GENEVE_CLASS_PMTUD_OAM,
            GENEVE_TYPE_PMTUD_PROBE,
            false, // Non-critical option
            &data,
        )
    }

    /// Parses from a Geneve Option TLV.
    pub fn from_tlv(tlv: &GeneveOptionTlv) -> Option<Self> {
        if tlv.class != GENEVE_CLASS_PMTUD_OAM || tlv.type_code != GENEVE_TYPE_PMTUD_PROBE {
            return None;
        }
        if tlv.data.len() < 10 {
            return None;
        }
        let probe_sequence =
            u32::from_be_bytes([tlv.data[0], tlv.data[1], tlv.data[2], tlv.data[3]]);
        let probed_mtu_size = u16::from_be_bytes([tlv.data[4], tlv.data[5]]);
        let flags = tlv.data[6];
        let min_supported_mtu = u16::from_be_bytes([tlv.data[8], tlv.data[9]]);

        Some(Self {
            probe_sequence,
            probed_mtu_size,
            flags,
            min_supported_mtu,
        })
    }
}

/// PMTUD Probe Processing Result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenevePmtudResult {
    /// Ingress generated a probe request to transmit
    SendProbeRequest {
        dest_vtep: Ipv4Address,
        probe: GenevePmtudOption,
        tlv: GeneveOptionTlv,
    },
    /// Egress received a probe request and generated a reply
    SendProbeReply {
        dest_vtep: Ipv4Address,
        reply: GenevePmtudOption,
        tlv: GeneveOptionTlv,
    },
    /// Ingress received a probe reply and learned the Path MTU
    PmtuConfirmed {
        dest_vtep: Ipv4Address,
        path_mtu: u16,
    },
    /// Probe dropped or unhandled
    Ignored,
}

/// Geneve PMTUD & Active Probe Engine.
#[derive(Debug, Clone)]
pub struct GenevePmtudEngine {
    pub local_max_mtu: u16,
    pub next_probe_seq: u32,
    /// Destination VTEP -> Confirmed Path MTU
    pub pmtu_cache: HashMap<Ipv4Address, u16>,
}

impl Default for GenevePmtudEngine {
    fn default() -> Self {
        Self::new(9000)
    }
}

impl GenevePmtudEngine {
    pub fn new(local_max_mtu: u16) -> Self {
        Self {
            local_max_mtu,
            next_probe_seq: 1,
            pmtu_cache: HashMap::new(),
        }
    }

    /// Initiates a PMTUD probe request targeting a remote VTEP.
    pub fn start_probe(&mut self, dest_vtep: Ipv4Address, target_mtu: u16) -> GenevePmtudResult {
        let seq = self.next_probe_seq;
        self.next_probe_seq = self.next_probe_seq.wrapping_add(1);

        let probe = GenevePmtudOption::new_request(seq, target_mtu);
        let tlv = probe.to_tlv();

        GenevePmtudResult::SendProbeRequest {
            dest_vtep,
            probe,
            tlv,
        }
    }

    /// Handles an incoming Geneve Option TLV from a remote VTEP.
    pub fn process_incoming_tlv(
        &mut self,
        source_vtep: Ipv4Address,
        tlv: &GeneveOptionTlv,
    ) -> GenevePmtudResult {
        let probe = match GenevePmtudOption::from_tlv(tlv) {
            Some(p) => p,
            None => return GenevePmtudResult::Ignored,
        };

        if probe.flags & GENEVE_PMTUD_FLAG_REQ != 0 {
            // Egress side receives request: verify local supported MTU
            let supported = probe.probed_mtu_size.min(self.local_max_mtu);
            let reply = GenevePmtudOption::new_reply(
                probe.probe_sequence,
                probe.probed_mtu_size,
                supported,
            );
            let reply_tlv = reply.to_tlv();

            GenevePmtudResult::SendProbeReply {
                dest_vtep: source_vtep,
                reply,
                tlv: reply_tlv,
            }
        } else if probe.flags & GENEVE_PMTUD_FLAG_REPLY != 0 {
            // Ingress side receives reply: record confirmed PMTU
            let confirmed = probe.min_supported_mtu;
            self.pmtu_cache.insert(source_vtep, confirmed);

            GenevePmtudResult::PmtuConfirmed {
                dest_vtep: source_vtep,
                path_mtu: confirmed,
            }
        } else {
            GenevePmtudResult::Ignored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geneve_pmtud_option_codec() {
        let probe = GenevePmtudOption::new_request(1001, 1500);
        let tlv = probe.to_tlv();

        assert_eq!(tlv.class, GENEVE_CLASS_PMTUD_OAM);
        assert_eq!(tlv.type_code, GENEVE_TYPE_PMTUD_PROBE);

        let parsed = GenevePmtudOption::from_tlv(&tlv).unwrap();
        assert_eq!(parsed.probe_sequence, 1001);
        assert_eq!(parsed.probed_mtu_size, 1500);
        assert_eq!(parsed.flags, GENEVE_PMTUD_FLAG_REQ);
        assert_eq!(parsed.min_supported_mtu, 1500);
    }

    #[test]
    fn test_geneve_pmtud_engine_probing_cycle() {
        let mut sender = GenevePmtudEngine::new(9000);
        let mut receiver = GenevePmtudEngine::new(1450); // Bottleneck receiver MTU = 1450

        let vtep_sender = Ipv4Address::new(10, 0, 0, 1);
        let vtep_receiver = Ipv4Address::new(10, 0, 0, 2);

        // 1. Sender starts probe for 1500 MTU
        let res1 = sender.start_probe(vtep_receiver, 1500);
        let probe_tlv = match res1 {
            GenevePmtudResult::SendProbeRequest { tlv, .. } => tlv,
            other => panic!("Expected SendProbeRequest, got {:?}", other),
        };

        // 2. Receiver processes request -> responds with min MTU 1450
        let res2 = receiver.process_incoming_tlv(vtep_sender, &probe_tlv);
        let reply_tlv = match res2 {
            GenevePmtudResult::SendProbeReply { reply, tlv, .. } => {
                assert_eq!(reply.min_supported_mtu, 1450);
                tlv
            }
            other => panic!("Expected SendProbeReply, got {:?}", other),
        };

        // 3. Sender receives reply -> PMTU is confirmed at 1450
        let res3 = sender.process_incoming_tlv(vtep_receiver, &reply_tlv);
        match res3 {
            GenevePmtudResult::PmtuConfirmed { path_mtu, .. } => {
                assert_eq!(path_mtu, 1450);
            }
            other => panic!("Expected PmtuConfirmed, got {:?}", other),
        }

        assert_eq!(sender.pmtu_cache.get(&vtep_receiver), Some(&1450));
    }
}
