//! BGP EVPN Preference-Based Designated Forwarder (DF) Election (RFC 8584).
//!
//! Implements the DF Election Extended Community (Type 0x06, Subtype 0x06),
//! Algorithm 0x02 (Preference-based DF election), Sticky Bit (S-bit), Don't Preempt
//! Bit (DP-bit), and deterministic highest-IP tie-breaking for multihomed Ethernet Segments.

use crate::evpn_synch::EthernetSegmentId;
use crate::ipv4::Ipv4Address;
use std::collections::HashMap;

/// EVPN DF Election Extended Community Type & Subtype (RFC 8584 Section 3).
pub const BGP_EXT_COMM_TYPE_EVPN: u8 = 0x06;
pub const BGP_EXT_COMM_SUBTYPE_DF_ELECTION: u8 = 0x06;

/// DF Election Algorithms (RFC 8584 Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfElectionAlgorithm {
    DefaultModulo = 0x00,
    HighestRandomWeight = 0x01,
    PreferenceBased = 0x02,
}

/// EVPN DF Election Extended Community (RFC 8584).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnDfElectionExtCommunity {
    pub algorithm: DfElectionAlgorithm,
    pub dont_preempt: bool,
    pub sticky: bool,
    pub preference: u16,
}

impl EvpnDfElectionExtCommunity {
    pub fn new_preference(preference: u16, dont_preempt: bool, sticky: bool) -> Self {
        EvpnDfElectionExtCommunity {
            algorithm: DfElectionAlgorithm::PreferenceBased,
            dont_preempt,
            sticky,
            preference,
        }
    }

    /// Serializes the 8-octet BGP Extended Community.
    pub fn serialize(&self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0] = BGP_EXT_COMM_TYPE_EVPN;
        buf[1] = BGP_EXT_COMM_SUBTYPE_DF_ELECTION;
        buf[2] = self.algorithm as u8;

        let mut flags = 0u8;
        if self.dont_preempt {
            flags |= 0x01;
        }
        if self.sticky {
            flags |= 0x02;
        }
        buf[3] = flags;

        buf[4..6].copy_from_slice(&self.preference.to_be_bytes());
        buf[6] = 0x00; // Reserved
        buf[7] = 0x00; // Reserved
        buf
    }

    /// Parses the 8-octet BGP Extended Community.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        if data[0] != BGP_EXT_COMM_TYPE_EVPN || data[1] != BGP_EXT_COMM_SUBTYPE_DF_ELECTION {
            return None;
        }

        let algo = match data[2] {
            0x00 => DfElectionAlgorithm::DefaultModulo,
            0x01 => DfElectionAlgorithm::HighestRandomWeight,
            0x02 => DfElectionAlgorithm::PreferenceBased,
            _ => return None,
        };

        let dont_preempt = (data[3] & 0x01) != 0;
        let sticky = (data[3] & 0x02) != 0;
        let preference = u16::from_be_bytes([data[4], data[5]]);

        Some(EvpnDfElectionExtCommunity {
            algorithm: algo,
            dont_preempt,
            sticky,
            preference,
        })
    }
}

/// Candidate PE participating in Preference-based DF election on an ESI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePe {
    pub pe_ip: Ipv4Address,
    pub preference: u16,
    pub dont_preempt: bool,
    pub sticky: bool,
}

/// DF Election Timer State (RFC 8584 Section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DfTimerState {
    Idle,
    Waiting { remaining_ms: u32 },
    Elected,
}

/// Computes 32-bit Highest Random Weight (HRW) for a given Ethernet Tag / VLAN and Candidate PE (RFC 8584 Section 3.1).
pub fn compute_hrw_weight(vlan_id: u32, pe_ip: Ipv4Address) -> u32 {
    let mut h = (vlan_id as u64) ^ ((u32::from_be_bytes(pe_ip.0) as u64) << 16);
    h = h.wrapping_mul(0x5bd1e995);
    h ^= h >> 15;
    h = h.wrapping_mul(0x5bd1e995);
    h ^= h >> 15;
    (h & 0xFFFFFFFF) as u32
}

/// EVPN Preference-Based DF Election Protocol Engine.
#[derive(Debug, Clone)]
pub struct EvpnPrefDfEngine {
    pub candidates: HashMap<EthernetSegmentId, Vec<CandidatePe>>,
    pub elected_df: HashMap<EthernetSegmentId, Ipv4Address>,
    pub elections_run_count: usize,
    pub election_wait_time_ms: u32,
    pub timer_state: HashMap<EthernetSegmentId, DfTimerState>,
}

impl Default for EvpnPrefDfEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl EvpnPrefDfEngine {
    pub fn new() -> Self {
        EvpnPrefDfEngine {
            candidates: HashMap::new(),
            elected_df: HashMap::new(),
            elections_run_count: 0,
            election_wait_time_ms: 3000, // Default 3 seconds (RFC 8584)
            timer_state: HashMap::new(),
        }
    }

    /// Adds or updates a candidate PE for an Ethernet Segment (ESI).
    pub fn add_or_update_candidate(&mut self, esi: EthernetSegmentId, candidate: CandidatePe) {
        let list = self.candidates.entry(esi).or_default();
        if let Some(pos) = list.iter().position(|c| c.pe_ip == candidate.pe_ip) {
            list[pos] = candidate;
        } else {
            list.push(candidate);
        }
    }

    /// Removes a candidate PE from an ESI upon link/node failure.
    pub fn remove_candidate(&mut self, esi: EthernetSegmentId, pe_ip: Ipv4Address) {
        if let Some(list) = self.candidates.get_mut(&esi) {
            list.retain(|c| c.pe_ip != pe_ip);
        }
        if self.elected_df.get(&esi) == Some(&pe_ip) {
            self.elected_df.remove(&esi);
        }
    }

    /// Starts DF election wait timer for an ESI (RFC 8584 Section 3.2).
    pub fn start_election_timer(&mut self, esi: EthernetSegmentId, wait_ms: u32) {
        self.timer_state.insert(
            esi,
            DfTimerState::Waiting {
                remaining_ms: wait_ms,
            },
        );
    }

    /// Ticks election timers by `elapsed_ms`. If a timer reaches 0, runs election.
    /// Returns a list of (ESI, Elected DF) that transitioned to Elected.
    pub fn tick_timer(&mut self, elapsed_ms: u32) -> Vec<(EthernetSegmentId, Ipv4Address)> {
        let mut newly_elected = Vec::new();
        let esis: Vec<EthernetSegmentId> = self.timer_state.keys().copied().collect();

        for esi in esis {
            let state = self.timer_state.get_mut(&esi).unwrap();
            match state {
                DfTimerState::Waiting { remaining_ms } => {
                    if *remaining_ms <= elapsed_ms {
                        *state = DfTimerState::Elected;
                        if let Some(df) = self.elect_df(esi) {
                            newly_elected.push((esi, df));
                        }
                    } else {
                        *remaining_ms -= elapsed_ms;
                    }
                }
                _ => {}
            }
        }

        newly_elected
    }

    /// Performs Preference-based DF Election according to RFC 8584 Section 4.
    pub fn elect_df(&mut self, esi: EthernetSegmentId) -> Option<Ipv4Address> {
        let list = self.candidates.get(&esi)?;
        if list.is_empty() {
            self.elected_df.remove(&esi);
            return None;
        }

        self.elections_run_count += 1;

        // Check if an existing elected DF is still alive and has DP (Don't Preempt) or Sticky active
        if let Some(&current_df_ip) = self.elected_df.get(&esi) {
            if let Some(current_cand) = list.iter().find(|c| c.pe_ip == current_df_ip) {
                if current_cand.dont_preempt || current_cand.sticky {
                    return Some(current_df_ip);
                }
            }
        }

        // Elect candidate with:
        // 1. Highest Preference value
        // 2. Highest IPv4 numeric value (RFC 8584 tie-breaker)
        let mut best: Option<&CandidatePe> = None;
        for c in list {
            match best {
                None => best = Some(c),
                Some(b) => {
                    if c.preference > b.preference {
                        best = Some(c);
                    } else if c.preference == b.preference {
                        let c_ip_val = u32::from_be_bytes(c.pe_ip.0);
                        let b_ip_val = u32::from_be_bytes(b.pe_ip.0);
                        if c_ip_val > b_ip_val {
                            best = Some(c);
                        }
                    }
                }
            }
        }

        if let Some(winner) = best {
            self.elected_df.insert(esi, winner.pe_ip);
            Some(winner.pe_ip)
        } else {
            None
        }
    }

    /// Performs Highest Random Weight (HRW) DF election for a specific VLAN / Ethernet Tag (RFC 8584 Algorithm 0x01).
    pub fn elect_df_hrw(&self, esi: EthernetSegmentId, vlan_id: u32) -> Option<Ipv4Address> {
        let list = self.candidates.get(&esi)?;
        if list.is_empty() {
            return None;
        }

        let mut best_pe: Option<(u32, Ipv4Address)> = None;
        for c in list {
            let weight = compute_hrw_weight(vlan_id, c.pe_ip);
            match best_pe {
                None => best_pe = Some((weight, c.pe_ip)),
                Some((best_weight, best_ip)) => {
                    if weight > best_weight {
                        best_pe = Some((weight, c.pe_ip));
                    } else if weight == best_weight {
                        let c_val = u32::from_be_bytes(c.pe_ip.0);
                        let b_val = u32::from_be_bytes(best_ip.0);
                        if c_val > b_val {
                            best_pe = Some((weight, c.pe_ip));
                        }
                    }
                }
            }
        }

        best_pe.map(|(_, ip)| ip)
    }

    /// Performs Default Modulo DF election for a specific VLAN / Ethernet Tag (RFC 8584 Algorithm 0x00 / RFC 7432).
    pub fn elect_df_modulo(&self, esi: EthernetSegmentId, vlan_id: u32) -> Option<Ipv4Address> {
        let list = self.candidates.get(&esi)?;
        if list.is_empty() {
            return None;
        }

        let mut sorted_ips: Vec<Ipv4Address> = list.iter().map(|c| c.pe_ip).collect();
        sorted_ips.sort_by_key(|ip| u32::from_be_bytes(ip.0));

        let index = (vlan_id as usize) % sorted_ips.len();
        Some(sorted_ips[index])
    }

    /// Performs per-VLAN DF Carving across a list of Ethernet Tags (VLANs).
    pub fn elect_df_per_vlan(
        &self,
        esi: EthernetSegmentId,
        vlan_ids: &[u32],
        algo: DfElectionAlgorithm,
    ) -> HashMap<u32, Ipv4Address> {
        let mut map = HashMap::new();
        for &vlan in vlan_ids {
            let winner = match algo {
                DfElectionAlgorithm::HighestRandomWeight => self.elect_df_hrw(esi, vlan),
                DfElectionAlgorithm::DefaultModulo => self.elect_df_modulo(esi, vlan),
                DfElectionAlgorithm::PreferenceBased => self.elected_df.get(&esi).copied(),
            };
            if let Some(pe) = winner {
                map.insert(vlan, pe);
            }
        }
        map
    }
}
