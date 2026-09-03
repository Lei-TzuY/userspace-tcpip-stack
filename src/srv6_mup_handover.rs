//! SRv6 Mobile User Plane (MUP) Session Handover & Anchor Re-allocation State Machine (draft-ietf-dmm-srv6-mobile-uplane).
//!
//! Manages 5G UE PDU session handovers between distributed gNodeBs and SRv6 MUP user plane anchors,
//! providing buffered indirect forwarding, atomic SID re-binding, and lossless cell transition.

use crate::ipv4::Ipv4Address;
use crate::ipv6::Ipv6Address;
use std::collections::{HashMap, VecDeque};

/// State of a 5G UE MUP PDU Session during mobility and handover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MupSessionState {
    Active,
    HandoverPreparing,
    HandoverExecuting,
    Relocated,
    Released,
}

/// 5G UE Session Parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupUeSession {
    pub session_id: u32,
    pub ue_ip: Ipv4Address,
    pub gnb_ip: Ipv4Address,
    pub teid: u32,
    pub mup_sid: Ipv6Address,
    pub qfi: u8,
    pub state: MupSessionState,
}

/// Handover Command specifying target base station and MUP anchor SID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupHandoverCommand {
    pub session_id: u32,
    pub target_gnb_ip: Ipv4Address,
    pub target_teid: u32,
    pub target_mup_sid: Ipv6Address,
}

/// In-flight buffered packet waiting for handover completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MupBufferedPacket {
    pub is_uplink: bool,
    pub payload: Vec<u8>,
}

/// Event emission from the MUP Handover State Machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MupHandoverEvent {
    Prepared {
        session_id: u32,
    },
    Executing {
        session_id: u32,
        target_sid: Ipv6Address,
    },
    Completed {
        session_id: u32,
        flushed_packets: usize,
    },
    Released {
        session_id: u32,
    },
    Error(String),
}

/// Complete SRv6 MUP Session Handover & Anchor Re-allocation Engine.
#[derive(Debug, Clone, Default)]
pub struct MupHandoverEngine {
    /// Active sessions indexed by session ID
    pub sessions: HashMap<u32, MupUeSession>,
    /// Fast lookup: (gnb_ip, teid) -> session_id
    pub gnb_teid_to_session: HashMap<(Ipv4Address, u32), u32>,
    /// Fast lookup: mup_sid -> session_id
    pub sid_to_session: HashMap<Ipv6Address, u32>,
    /// Handover in-flight buffer: session_id -> queue of packets
    pub in_flight_buffers: HashMap<u32, VecDeque<MupBufferedPacket>>,
    /// Maximum buffered packets per session to avoid unbounded memory usage
    pub max_buffer_per_session: usize,
}

impl MupHandoverEngine {
    pub fn new(max_buffer_per_session: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            gnb_teid_to_session: HashMap::new(),
            sid_to_session: HashMap::new(),
            in_flight_buffers: HashMap::new(),
            max_buffer_per_session: if max_buffer_per_session == 0 {
                100
            } else {
                max_buffer_per_session
            },
        }
    }

    /// Creates and registers an initial active UE PDU session.
    pub fn create_session(
        &mut self,
        session_id: u32,
        ue_ip: Ipv4Address,
        gnb_ip: Ipv4Address,
        teid: u32,
        mup_sid: Ipv6Address,
        qfi: u8,
    ) -> Result<(), String> {
        if self.sessions.contains_key(&session_id) {
            return Err("Session ID already exists".to_string());
        }

        let session = MupUeSession {
            session_id,
            ue_ip,
            gnb_ip,
            teid,
            mup_sid,
            qfi,
            state: MupSessionState::Active,
        };

        self.gnb_teid_to_session.insert((gnb_ip, teid), session_id);
        self.sid_to_session.insert(mup_sid, session_id);
        self.sessions.insert(session_id, session);
        Ok(())
    }

    /// Step 1: Handover Preparation - Reserves target anchor resources.
    pub fn prepare_handover(&mut self, session_id: u32) -> MupHandoverEvent {
        let session = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return MupHandoverEvent::Error("Session not found".to_string()),
        };

        if session.state != MupSessionState::Active {
            return MupHandoverEvent::Error(format!(
                "Invalid state {:?} for prepare",
                session.state
            ));
        }

        session.state = MupSessionState::HandoverPreparing;
        MupHandoverEvent::Prepared { session_id }
    }

    /// Step 2: Handover Execution - Directs UE to target gNodeB and buffers in-flight traffic.
    pub fn execute_handover(&mut self, cmd: MupHandoverCommand) -> MupHandoverEvent {
        let session = match self.sessions.get_mut(&cmd.session_id) {
            Some(s) => s,
            None => return MupHandoverEvent::Error("Session not found".to_string()),
        };

        if session.state != MupSessionState::HandoverPreparing
            && session.state != MupSessionState::Active
        {
            return MupHandoverEvent::Error(format!(
                "Invalid state {:?} for execution",
                session.state
            ));
        }

        session.state = MupSessionState::HandoverExecuting;
        self.in_flight_buffers.entry(cmd.session_id).or_default();

        MupHandoverEvent::Executing {
            session_id: cmd.session_id,
            target_sid: cmd.target_mup_sid,
        }
    }

    /// Ingress packet handler during handover execution - buffers in-flight packets.
    pub fn handle_packet(
        &mut self,
        session_id: u32,
        is_uplink: bool,
        payload: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, String> {
        let session = self.sessions.get(&session_id).ok_or("Session not found")?;

        match session.state {
            MupSessionState::Active => {
                // Directly forwarded
                Ok(Some(payload))
            }
            MupSessionState::HandoverPreparing | MupSessionState::HandoverExecuting => {
                // Buffer in-flight traffic
                let queue = self.in_flight_buffers.entry(session_id).or_default();
                if queue.len() < self.max_buffer_per_session {
                    queue.push_back(MupBufferedPacket { is_uplink, payload });
                }
                Ok(None)
            }
            MupSessionState::Relocated => Ok(Some(payload)),
            MupSessionState::Released => Err("Session released".to_string()),
        }
    }

    /// Step 3: Complete Handover (End Marker received) - Re-binds to target gNB/SID and flushes buffer.
    pub fn complete_handover(
        &mut self,
        cmd: MupHandoverCommand,
    ) -> (MupHandoverEvent, Vec<MupBufferedPacket>) {
        let session = match self.sessions.get_mut(&cmd.session_id) {
            Some(s) => s,
            None => {
                return (
                    MupHandoverEvent::Error("Session not found".to_string()),
                    Vec::new(),
                );
            }
        };

        // Remove old lookups
        self.gnb_teid_to_session
            .remove(&(session.gnb_ip, session.teid));
        self.sid_to_session.remove(&session.mup_sid);

        // Update to target
        session.gnb_ip = cmd.target_gnb_ip;
        session.teid = cmd.target_teid;
        session.mup_sid = cmd.target_mup_sid;
        session.state = MupSessionState::Active;

        // Insert new lookups
        self.gnb_teid_to_session
            .insert((cmd.target_gnb_ip, cmd.target_teid), cmd.session_id);
        self.sid_to_session
            .insert(cmd.target_mup_sid, cmd.session_id);

        // Flush in-flight buffer
        let flushed: Vec<MupBufferedPacket> = self
            .in_flight_buffers
            .remove(&cmd.session_id)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default();

        let count = flushed.len();
        (
            MupHandoverEvent::Completed {
                session_id: cmd.session_id,
                flushed_packets: count,
            },
            flushed,
        )
    }

    /// Step 4: Release / Teardown Session.
    pub fn release_session(&mut self, session_id: u32) -> MupHandoverEvent {
        if let Some(session) = self.sessions.remove(&session_id) {
            self.gnb_teid_to_session
                .remove(&(session.gnb_ip, session.teid));
            self.sid_to_session.remove(&session.mup_sid);
            self.in_flight_buffers.remove(&session_id);
            MupHandoverEvent::Released { session_id }
        } else {
            MupHandoverEvent::Error("Session not found".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv6_mup_session_handover_state_machine() {
        let mut engine = MupHandoverEngine::new(50);

        let ue_ip = Ipv4Address::new(10, 45, 0, 100);
        let gnb1 = Ipv4Address::new(192, 168, 10, 1);
        let gnb2 = Ipv4Address::new(192, 168, 20, 1);
        let sid1 =
            Ipv6Address::from_bytes([0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let sid2 =
            Ipv6Address::from_bytes([0x20, 0x01, 0x0d, 0xb8, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        // Create Session
        engine
            .create_session(1, ue_ip, gnb1, 10001, sid1, 9)
            .unwrap();

        // 1. In Active state, packet forwards immediately
        let pkt = engine.handle_packet(1, true, b"Ping1".to_vec()).unwrap();
        assert_eq!(pkt, Some(b"Ping1".to_vec()));

        // 2. Prepare Handover
        let prep = engine.prepare_handover(1);
        assert_eq!(prep, MupHandoverEvent::Prepared { session_id: 1 });

        // 3. Execute Handover
        let cmd = MupHandoverCommand {
            session_id: 1,
            target_gnb_ip: gnb2,
            target_teid: 20002,
            target_mup_sid: sid2,
        };
        let exec = engine.execute_handover(cmd.clone());
        assert_eq!(
            exec,
            MupHandoverEvent::Executing {
                session_id: 1,
                target_sid: sid2
            }
        );

        // 4. In-flight packets during execution are buffered
        let pkt_inflight1 = engine
            .handle_packet(1, true, b"InFlight1".to_vec())
            .unwrap();
        assert_eq!(pkt_inflight1, None);

        let pkt_inflight2 = engine
            .handle_packet(1, false, b"InFlight2".to_vec())
            .unwrap();
        assert_eq!(pkt_inflight2, None);

        // 5. Complete Handover
        let (comp, flushed) = engine.complete_handover(cmd);
        match comp {
            MupHandoverEvent::Completed {
                session_id,
                flushed_packets,
            } => {
                assert_eq!(session_id, 1);
                assert_eq!(flushed_packets, 2);
            }
            other => panic!("Expected Completed, got {:?}", other),
        }
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].payload, b"InFlight1");
        assert_eq!(flushed[1].payload, b"InFlight2");

        // 6. Active on target gNB
        let active_pkt = engine
            .handle_packet(1, true, b"ActiveTarget".to_vec())
            .unwrap();
        assert_eq!(active_pkt, Some(b"ActiveTarget".to_vec()));

        assert_eq!(engine.gnb_teid_to_session.get(&(gnb2, 20002)), Some(&1));
        assert_eq!(engine.sid_to_session.get(&sid2), Some(&1));
        assert_eq!(engine.gnb_teid_to_session.get(&(gnb1, 10001)), None);
    }
}
