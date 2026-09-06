//! 3GPP TS 23.247 / TS 29.581 / TS 29.244 Annex G Release 17 5G Multicast/Broadcast UPF (MB-UPF) Engine.
//!
//! Implements 5G Multicast/Broadcast User Plane Function (MB-UPF):
//! - N6mb IP Multicast Stream Ingestion (Source Specific Multicast SSM / IGMPv3)
//! - TMGI (Temporary Mobile Group Identity) binding to Shared N3mb GTP-U Tunnels
//! - Point-to-Multipoint (PTM) copy-based packet replication across active gNodeB cell branches
//! - Dynamic branch addition and pruning on UE join/leave
//! - MB-UPF traffic accounting telemetry (packets & bytes forwarded)

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G MB-UPF Enums & Data Structures (TS 23.247 / TS 29.244 Annex G)
// ---------------------------------------------------------------------------

/// MBS Session Delivery Mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbsSessionType {
    Broadcast,
    Multicast,
}

/// Ingress Multicast Flow Specification (N6mb).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MulticastFlowSpec {
    pub source_ip: [u8; 4],
    pub group_ip: [u8; 4],
    pub port: u16,
}

/// Active gNodeB Downlink Branch Endpoint (N3mb).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnbBranchEndpoint {
    pub gnb_id: String,
    pub n3mb_downlink_ip: [u8; 4],
    pub n3mb_downlink_teid: u32,
}

/// MB-UPF Session Context for a Multicast/Broadcast Stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MbUpfSessionContext {
    pub session_id: String,
    pub tmgi: String,
    pub session_type: MbsSessionType,
    pub flow_spec: MulticastFlowSpec,
    pub shared_teid: u32,
    pub branches: HashMap<String, GnbBranchEndpoint>,
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
}

/// Replicated Downlink GTP-U Packet destined for a gNodeB branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedGtpPacket {
    pub gnb_id: String,
    pub dest_ip: [u8; 4],
    pub gtp_packet: Vec<u8>,
}

/// MB-UPF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MbUpfError {
    SessionNotFound,
    BranchAlreadyExists,
    BranchNotFound,
    EmptyPayload,
    PayloadTooLarge,
}

// ---------------------------------------------------------------------------
// Top-Level 5G MB-UPF Engine
// ---------------------------------------------------------------------------

/// 5G Multicast/Broadcast User Plane Function (MB-UPF).
pub struct MbUpfEngine {
    pub upf_id: String,
    /// Active MBS Sessions: session_id -> MbUpfSessionContext
    pub sessions: HashMap<String, MbUpfSessionContext>,
    /// Flow lookup: MulticastFlowSpec -> session_id
    pub flow_to_session: HashMap<MulticastFlowSpec, String>,
}

impl MbUpfEngine {
    /// Create a new 5G MB-UPF engine instance.
    pub fn new(upf_id: &str) -> Self {
        MbUpfEngine {
            upf_id: upf_id.to_string(),
            sessions: HashMap::new(),
            flow_to_session: HashMap::new(),
        }
    }

    /// Provision a new Multicast/Broadcast User Plane Session (N6mb to N3mb).
    pub fn create_mbs_session(
        &mut self,
        session_id: &str,
        tmgi: &str,
        session_type: MbsSessionType,
        flow_spec: MulticastFlowSpec,
        shared_teid: u32,
    ) {
        let ctx = MbUpfSessionContext {
            session_id: session_id.to_string(),
            tmgi: tmgi.to_string(),
            session_type,
            flow_spec: flow_spec.clone(),
            shared_teid,
            branches: HashMap::new(),
            packets_forwarded: 0,
            bytes_forwarded: 0,
        };

        self.flow_to_session
            .insert(flow_spec, session_id.to_string());
        self.sessions.insert(session_id.to_string(), ctx);
    }

    /// Add an active gNodeB cell branch to receive replicated multicast packets.
    pub fn add_gnb_branch(
        &mut self,
        session_id: &str,
        gnb_id: &str,
        n3mb_downlink_ip: [u8; 4],
        n3mb_downlink_teid: u32,
    ) -> Result<(), MbUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbUpfError::SessionNotFound)?;
        if sess.branches.contains_key(gnb_id) {
            return Err(MbUpfError::BranchAlreadyExists);
        }

        let branch = GnbBranchEndpoint {
            gnb_id: gnb_id.to_string(),
            n3mb_downlink_ip,
            n3mb_downlink_teid,
        };

        sess.branches.insert(gnb_id.to_string(), branch);
        Ok(())
    }

    /// Remove a gNodeB branch when no active UEs remain in that cell.
    pub fn remove_gnb_branch(&mut self, session_id: &str, gnb_id: &str) -> Result<(), MbUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbUpfError::SessionNotFound)?;
        sess.branches
            .remove(gnb_id)
            .ok_or(MbUpfError::BranchNotFound)?;
        Ok(())
    }

    /// Ingest an N6mb multicast packet and replicate across all registered gNodeB branches.
    pub fn ingest_and_replicate(
        &mut self,
        session_id: &str,
        payload: &[u8],
    ) -> Result<Vec<ReplicatedGtpPacket>, MbUpfError> {
        if payload.is_empty() {
            return Err(MbUpfError::EmptyPayload);
        }
        let payload_len = u16::try_from(payload.len()).map_err(|_| MbUpfError::PayloadTooLarge)?;

        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(MbUpfError::SessionNotFound)?;
        let mut replicated = Vec::with_capacity(sess.branches.len());

        for (gnb_id, branch) in &sess.branches {
            // Standard GTP-U v1 Header (8 bytes):
            // Flags: 0x30 (v1), MsgType: 0xFF (G-PDU), Length (2 bytes), TEID (4 bytes)
            let mut gtp_packet = Vec::with_capacity(8 + payload.len());
            gtp_packet.push(0x30);
            gtp_packet.push(0xFF);
            gtp_packet.extend_from_slice(&payload_len.to_be_bytes());
            gtp_packet.extend_from_slice(&branch.n3mb_downlink_teid.to_be_bytes());
            gtp_packet.extend_from_slice(payload);

            replicated.push(ReplicatedGtpPacket {
                gnb_id: gnb_id.clone(),
                dest_ip: branch.n3mb_downlink_ip,
                gtp_packet,
            });
        }

        sess.packets_forwarded += 1;
        sess.bytes_forwarded += (payload.len() * sess.branches.len()) as u64;

        Ok(replicated)
    }

    /// Terminate an MBS session and clean up state.
    pub fn terminate_mbs_session(&mut self, session_id: &str) -> Result<(), MbUpfError> {
        let sess = self
            .sessions
            .remove(session_id)
            .ok_or(MbUpfError::SessionNotFound)?;
        self.flow_to_session.remove(&sess.flow_spec);
        Ok(())
    }
}
