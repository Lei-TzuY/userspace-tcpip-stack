// src/evpn_ssm_dr_election.rs
//
// EVPN Layer 2 Source-Specific Multicast (SSM) Designated Router (DR) Election
// & IGMP Querier Synchronization Engine.
//
// Standard Reference:
//   - RFC 9251 (BGP EVPN for IPv4 and IPv6 Multicast) Section 5 & 6
//   - RFC 8584 (Framework for EVPN Designated Forwarder Election)
//   - RFC 3376 / RFC 3810 (IGMPv3 / MLDv2 Querier Election)
//
// Concepts:
//   1. Multi-Homed Ethernet Segment (ESI) Multicast Forwarder Resolution.
//   2. Priority-Based DR / Querier Election with Deterministic IP Tie-Breaking:
//      Highest configured priority wins; if equal, highest IPv4 address wins.
//   3. Non-DR Standby Monitoring & Failover Timer:
//      Standby PEs monitor DR Query heartbeats; timeout triggers immediate failover.
//   4. Per-(ESI, VNI) Forwarding State Synchronization.
//
// Pure safe Rust, zero external crates.

use crate::ipv4::Ipv4Address;

/// Verdict of an election or keepalive evaluation on an Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrElectionVerdict {
    /// Local PE is elected as the Designated Router / Querier for this (ESI, VNI).
    ElectedAsDr {
        esi: [u8; 10],
        vni: u32,
        dr_ip: Ipv4Address,
        priority: u32,
    },
    /// Local PE is in Standby / Non-DR mode (remote PE is active DR).
    StandbyNonDr {
        esi: [u8; 10],
        vni: u32,
        active_dr_ip: Ipv4Address,
        active_dr_priority: u32,
    },
    /// DR heartbeat timed out, triggering an automatic failover election.
    DrFailoverTriggered {
        esi: [u8; 10],
        vni: u32,
        new_dr_ip: Ipv4Address,
        new_dr_priority: u32,
        is_local_elected: bool,
    },
}

/// Candidate PE router advertising membership on an Ethernet Segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePe {
    pub pe_ip: Ipv4Address,
    pub priority: u32,
    pub last_seen_secs: u64,
    pub is_active: bool,
}

/// Managed Multi-Homed Ethernet Segment Multicast context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentMulticastContext {
    pub esi: [u8; 10],
    pub vni: u32,
    pub candidates: Vec<CandidatePe>,
    pub current_dr_ip: Option<Ipv4Address>,
    pub current_dr_priority: u32,
    pub last_dr_query_timestamp_secs: u64,
}

/// EVPN SSM Designated Router Election Engine.
#[derive(Debug, Clone)]
pub struct EvpnSsmDrElectionEngine {
    /// Local PE IP address.
    pub local_pe_ip: Ipv4Address,
    /// Local configured default DR priority (0..65535, higher is preferred).
    pub local_priority: u32,
    /// Querier timeout duration in seconds (default: 120s).
    pub querier_timeout_secs: u64,
    /// Managed segment contexts.
    pub segments: Vec<SegmentMulticastContext>,
    /// Statistics: total election runs.
    pub total_elections: u64,
    /// Statistics: total failover events.
    pub total_failovers: u64,
}

impl EvpnSsmDrElectionEngine {
    /// Creates a new EVPN SSM DR Election Engine.
    pub fn new(local_pe_ip: Ipv4Address, local_priority: u32, querier_timeout_secs: u64) -> Self {
        Self {
            local_pe_ip,
            local_priority,
            querier_timeout_secs,
            segments: Vec::new(),
            total_elections: 0,
            total_failovers: 0,
        }
    }

    /// Registers a segment (ESI, VNI) and seeds the local PE as a candidate.
    pub fn register_segment(&mut self, esi: [u8; 10], vni: u32, timestamp_secs: u64) {
        if !self.segments.iter().any(|s| s.esi == esi && s.vni == vni) {
            let mut candidates = Vec::new();
            candidates.push(CandidatePe {
                pe_ip: self.local_pe_ip,
                priority: self.local_priority,
                last_seen_secs: timestamp_secs,
                is_active: true,
            });

            self.segments.push(SegmentMulticastContext {
                esi,
                vni,
                candidates,
                current_dr_ip: None,
                current_dr_priority: 0,
                last_dr_query_timestamp_secs: timestamp_secs,
            });
        }
    }

    /// Adds or updates a remote candidate PE on a segment.
    pub fn add_or_update_remote_pe(
        &mut self,
        esi: [u8; 10],
        vni: u32,
        remote_pe_ip: Ipv4Address,
        priority: u32,
        timestamp_secs: u64,
    ) {
        self.register_segment(esi, vni, timestamp_secs);

        if let Some(seg) = self
            .segments
            .iter_mut()
            .find(|s| s.esi == esi && s.vni == vni)
        {
            if let Some(cand) = seg.candidates.iter_mut().find(|c| c.pe_ip == remote_pe_ip) {
                cand.priority = priority;
                cand.last_seen_secs = timestamp_secs;
                cand.is_active = true;
            } else {
                seg.candidates.push(CandidatePe {
                    pe_ip: remote_pe_ip,
                    priority,
                    last_seen_secs: timestamp_secs,
                    is_active: true,
                });
            }
        }
    }

    /// Executes the DR election algorithm for a given (ESI, VNI).
    pub fn run_election(&mut self, esi: [u8; 10], vni: u32) -> Option<DrElectionVerdict> {
        let seg = self
            .segments
            .iter_mut()
            .find(|s| s.esi == esi && s.vni == vni)?;
        self.total_elections += 1;

        // Filter active candidates
        let mut active_cands: Vec<&CandidatePe> =
            seg.candidates.iter().filter(|c| c.is_active).collect();
        if active_cands.is_empty() {
            seg.current_dr_ip = None;
            seg.current_dr_priority = 0;
            return None;
        }

        // Sort descending: highest priority first; if equal, highest IP address (u32 big-endian)
        active_cands.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| ip_to_u32(b.pe_ip).cmp(&ip_to_u32(a.pe_ip)))
        });

        let winner = active_cands[0];
        let winner_ip = winner.pe_ip;
        let winner_prio = winner.priority;

        seg.current_dr_ip = Some(winner_ip);
        seg.current_dr_priority = winner_prio;

        if winner_ip == self.local_pe_ip {
            Some(DrElectionVerdict::ElectedAsDr {
                esi,
                vni,
                dr_ip: winner_ip,
                priority: winner_prio,
            })
        } else {
            Some(DrElectionVerdict::StandbyNonDr {
                esi,
                vni,
                active_dr_ip: winner_ip,
                active_dr_priority: winner_prio,
            })
        }
    }

    /// Ingests an IGMP/MLD Query or keepalive received from the active DR.
    pub fn record_dr_query(
        &mut self,
        esi: [u8; 10],
        vni: u32,
        sender_ip: Ipv4Address,
        timestamp_secs: u64,
    ) {
        if let Some(seg) = self
            .segments
            .iter_mut()
            .find(|s| s.esi == esi && s.vni == vni)
        {
            if let Some(cand) = seg.candidates.iter_mut().find(|c| c.pe_ip == sender_ip) {
                cand.last_seen_secs = timestamp_secs;
                cand.is_active = true;
            }
            if seg.current_dr_ip == Some(sender_ip) {
                seg.last_dr_query_timestamp_secs = timestamp_secs;
            }
        }
    }

    /// Periodic heartbeat check to detect failed DR and trigger failover election.
    pub fn check_timeouts(&mut self, current_time_secs: u64) -> Vec<DrElectionVerdict> {
        let mut failover_verdicts = Vec::new();

        for seg in &mut self.segments {
            // Mark timed-out candidates as inactive
            for cand in &mut seg.candidates {
                if cand.pe_ip != self.local_pe_ip
                    && current_time_secs.saturating_sub(cand.last_seen_secs)
                        > self.querier_timeout_secs
                {
                    cand.is_active = false;
                }
            }

            // Check if current DR is timed out or inactive
            let dr_failed = match seg.current_dr_ip {
                Some(dr_ip) => {
                    if dr_ip != self.local_pe_ip {
                        current_time_secs.saturating_sub(seg.last_dr_query_timestamp_secs)
                            > self.querier_timeout_secs
                    } else {
                        false
                    }
                }
                None => true,
            };

            if dr_failed {
                self.total_failovers += 1;
                // Re-run election among remaining active candidates
                let mut active_cands: Vec<&CandidatePe> =
                    seg.candidates.iter().filter(|c| c.is_active).collect();

                if !active_cands.is_empty() {
                    active_cands.sort_by(|a, b| {
                        b.priority
                            .cmp(&a.priority)
                            .then_with(|| ip_to_u32(b.pe_ip).cmp(&ip_to_u32(a.pe_ip)))
                    });

                    let new_dr = active_cands[0];
                    let new_dr_ip = new_dr.pe_ip;
                    let new_dr_prio = new_dr.priority;

                    seg.current_dr_ip = Some(new_dr_ip);
                    seg.current_dr_priority = new_dr_prio;
                    seg.last_dr_query_timestamp_secs = current_time_secs;

                    failover_verdicts.push(DrElectionVerdict::DrFailoverTriggered {
                        esi: seg.esi,
                        vni: seg.vni,
                        new_dr_ip,
                        new_dr_priority: new_dr_prio,
                        is_local_elected: new_dr_ip == self.local_pe_ip,
                    });
                }
            }
        }

        failover_verdicts
    }
}

fn ip_to_u32(ip: Ipv4Address) -> u32 {
    let o = ip.0;
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssm_dr_election_lifecycle() {
        let local_ip = Ipv4Address::new(10, 0, 0, 1);
        let mut engine = EvpnSsmDrElectionEngine::new(local_ip, 100, 60);

        let esi = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        let vni = 1000;

        // 1. Initially local PE only -> Elected as DR
        engine.register_segment(esi, vni, 1000);
        let v1 = engine.run_election(esi, vni);
        assert_eq!(
            v1,
            Some(DrElectionVerdict::ElectedAsDr {
                esi,
                vni,
                dr_ip: local_ip,
                priority: 100,
            })
        );

        // 2. Add Remote PE 10.0.0.2 with higher priority 200 -> Remote PE elected DR
        let remote_ip = Ipv4Address::new(10, 0, 0, 2);
        engine.add_or_update_remote_pe(esi, vni, remote_ip, 200, 1000);
        let v2 = engine.run_election(esi, vni);
        assert_eq!(
            v2,
            Some(DrElectionVerdict::StandbyNonDr {
                esi,
                vni,
                active_dr_ip: remote_ip,
                active_dr_priority: 200,
            })
        );

        // 3. Remote DR stops sending queries (time advances to 1100s -> timeout > 60s)
        let failovers = engine.check_timeouts(1100);
        assert_eq!(failovers.len(), 1);
        assert_eq!(
            failovers[0],
            DrElectionVerdict::DrFailoverTriggered {
                esi,
                vni,
                new_dr_ip: local_ip,
                new_dr_priority: 100,
                is_local_elected: true,
            }
        );
    }
}
