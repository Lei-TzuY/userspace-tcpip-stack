//! 3GPP TS 23.501 Section 5.6.4 / TS 23.502 / TS 29.244 Release 17 5G Intermediate UPF (I-UPF) & Uplink Classifier (ULCL) Engine.
//!
//! Implements 5G I-UPF and Multi-Homed PDU Session Branching Point:
//! - N3 (gNodeB <-> I-UPF) and N9 (I-UPF <-> PSA UPF) GTP-U tunnel stitching
//! - Uplink Classifier (ULCL) destination IP prefix inspection:
//!   - Diverts local MEC / Edge computing traffic to Local PDU Session Anchor (Local PSA)
//!   - Forwards general Internet / Cloud traffic to Central PDU Session Anchor (Central PSA)
//! - Seamless I-UPF / gNodeB Handover Relocation with in-flight packet buffering

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 5G I-UPF & ULCL Enums & Data Structures (TS 23.501 Section 5.6.4)
// ---------------------------------------------------------------------------

/// Destination PDU Session Anchor (PSA) target for N9 forwarding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingTarget {
    LocalEdgePsa {
        n9_teid: u32,
        edge_upf_ip: [u8; 4],
    },
    CentralInternetPsa {
        n9_teid: u32,
        central_upf_ip: [u8; 4],
    },
}

/// Uplink Classifier (ULCL) Traffic Filter Rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UlclFilterRule {
    pub rule_id: u32,
    pub dest_ip_prefix: [u8; 4],
    pub dest_ip_mask: [u8; 4],
    pub target: RoutingTarget,
}

impl UlclFilterRule {
    /// Check if target IP matches prefix/mask.
    pub fn matches(&self, ip: [u8; 4]) -> bool {
        for i in 0..4 {
            if (ip[i] & self.dest_ip_mask[i]) != (self.dest_ip_prefix[i] & self.dest_ip_mask[i]) {
                return false;
            }
        }
        true
    }
}

/// I-UPF Session Context for a connected UE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IUpfSessionContext {
    pub session_id: String,
    pub ue_ip: [u8; 4],
    pub n3_access_teid: u32, // TEID allocated by I-UPF for uplink from gNodeB
    pub gnb_downlink_teid: u32, // TEID allocated by gNodeB for downlink from I-UPF
    pub ulcl_rules: Vec<UlclFilterRule>,
    pub default_target: RoutingTarget,
    pub buffered_downlink_packets: Vec<Vec<u8>>,
    pub handover_active: bool,
}

/// Forwarded N9 Packet outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchedN9Packet {
    pub target: RoutingTarget,
    pub gtp_packet: Vec<u8>,
}

/// I-UPF Error Types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IUpfError {
    SessionNotFound,
    InvalidGtpPacket(&'static str),
    HandoverAlreadyActive,
}

// ---------------------------------------------------------------------------
// Top-Level 5G I-UPF Engine
// ---------------------------------------------------------------------------

/// 5G Intermediate UPF & Uplink Classifier (ULCL) Engine.
pub struct IUpfEngine {
    pub upf_id: String,
    pub sessions: HashMap<String, IUpfSessionContext>,
    /// N3 Ingress TEID to session_id lookup
    pub n3_teid_to_session: HashMap<u32, String>,
}

impl IUpfEngine {
    /// Create a new 5G I-UPF engine instance.
    pub fn new(upf_id: &str) -> Self {
        IUpfEngine {
            upf_id: upf_id.to_string(),
            sessions: HashMap::new(),
            n3_teid_to_session: HashMap::new(),
        }
    }

    /// Create an I-UPF Session context with N3 / N9 tunnel bindings.
    pub fn create_session(
        &mut self,
        session_id: &str,
        ue_ip: [u8; 4],
        n3_access_teid: u32,
        gnb_downlink_teid: u32,
        default_target: RoutingTarget,
    ) {
        let ctx = IUpfSessionContext {
            session_id: session_id.to_string(),
            ue_ip,
            n3_access_teid,
            gnb_downlink_teid,
            ulcl_rules: Vec::new(),
            default_target,
            buffered_downlink_packets: Vec::new(),
            handover_active: false,
        };

        self.n3_teid_to_session
            .insert(n3_access_teid, session_id.to_string());
        self.sessions.insert(session_id.to_string(), ctx);
    }

    /// Add an Uplink Classifier (ULCL) filter rule for local edge steering.
    pub fn add_ulcl_rule(
        &mut self,
        session_id: &str,
        rule: UlclFilterRule,
    ) -> Result<(), IUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(IUpfError::SessionNotFound)?;
        sess.ulcl_rules.push(rule);
        Ok(())
    }

    /// Process an inbound uplink N3 GTP-U packet from gNodeB and steer via ULCL.
    pub fn process_uplink_n3_packet(
        &self,
        n3_gtp_packet: &[u8],
    ) -> Result<DispatchedN9Packet, IUpfError> {
        if n3_gtp_packet.len() < 8 {
            return Err(IUpfError::InvalidGtpPacket(
                "GTP-U packet shorter than 8 bytes",
            ));
        }

        // Parse N3 TEID
        let n3_teid = u32::from_be_bytes([
            n3_gtp_packet[4],
            n3_gtp_packet[5],
            n3_gtp_packet[6],
            n3_gtp_packet[7],
        ]);

        let session_id = self
            .n3_teid_to_session
            .get(&n3_teid)
            .ok_or(IUpfError::SessionNotFound)?;

        let sess = self
            .sessions
            .get(session_id)
            .ok_or(IUpfError::SessionNotFound)?;
        let user_ip_payload = &n3_gtp_packet[8..];

        if user_ip_payload.len() < 20 {
            return Err(IUpfError::InvalidGtpPacket(
                "IP payload too short for IPv4 header",
            ));
        }

        // Extract Destination IPv4 address (bytes 16..20 in IPv4 header)
        let dest_ip = [
            user_ip_payload[16],
            user_ip_payload[17],
            user_ip_payload[18],
            user_ip_payload[19],
        ];

        // Evaluate ULCL rules
        let mut target = &sess.default_target;
        for rule in &sess.ulcl_rules {
            if rule.matches(dest_ip) {
                target = &rule.target;
                break;
            }
        }

        let n9_teid = match target {
            RoutingTarget::LocalEdgePsa { n9_teid, .. } => *n9_teid,
            RoutingTarget::CentralInternetPsa { n9_teid, .. } => *n9_teid,
        };

        // Construct Outbound N9 GTP-U packet (8-byte header + user IP payload)
        let mut n9_packet = Vec::with_capacity(8 + user_ip_payload.len());
        n9_packet.push(0x30); // GTPv1 G-PDU
        n9_packet.push(0xFF);
        n9_packet.extend_from_slice(&(user_ip_payload.len() as u16).to_be_bytes());
        n9_packet.extend_from_slice(&n9_teid.to_be_bytes());
        n9_packet.extend_from_slice(user_ip_payload);

        Ok(DispatchedN9Packet {
            target: target.clone(),
            gtp_packet: n9_packet,
        })
    }

    /// Initiate Handover Relocation: pauses downlink and starts buffering in-flight packets.
    pub fn initiate_handover(&mut self, session_id: &str) -> Result<(), IUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(IUpfError::SessionNotFound)?;
        if sess.handover_active {
            return Err(IUpfError::HandoverAlreadyActive);
        }
        sess.handover_active = true;
        Ok(())
    }

    /// Process inbound downlink packet from PSA: forwards immediately or buffers if in handover.
    pub fn process_downlink_packet(
        &mut self,
        session_id: &str,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, IUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(IUpfError::SessionNotFound)?;

        if sess.handover_active {
            // Buffer packet until target gNodeB path is confirmed
            sess.buffered_downlink_packets.push(payload.to_vec());
            Ok(None)
        } else {
            // Immediately encapsulate and forward to active gNodeB
            let mut gtp = Vec::with_capacity(8 + payload.len());
            gtp.push(0x30);
            gtp.push(0xFF);
            gtp.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            gtp.extend_from_slice(&sess.gnb_downlink_teid.to_be_bytes());
            gtp.extend_from_slice(payload);
            Ok(Some(gtp))
        }
    }

    /// Complete Handover: updates gNodeB Downlink TEID and flushes all buffered packets!
    pub fn complete_handover(
        &mut self,
        session_id: &str,
        new_gnb_teid: u32,
    ) -> Result<Vec<Vec<u8>>, IUpfError> {
        let sess = self
            .sessions
            .get_mut(session_id)
            .ok_or(IUpfError::SessionNotFound)?;
        sess.gnb_downlink_teid = new_gnb_teid;
        sess.handover_active = false;

        let mut flushed_packets = Vec::with_capacity(sess.buffered_downlink_packets.len());
        for pkt in sess.buffered_downlink_packets.drain(..) {
            let mut gtp = Vec::with_capacity(8 + pkt.len());
            gtp.push(0x30);
            gtp.push(0xFF);
            gtp.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
            gtp.extend_from_slice(&new_gnb_teid.to_be_bytes());
            gtp.extend_from_slice(&pkt);
            flushed_packets.push(gtp);
        }

        Ok(flushed_packets)
    }

    /// Remove an I-UPF session.
    pub fn remove_session(&mut self, session_id: &str) -> Result<(), IUpfError> {
        let sess = self
            .sessions
            .remove(session_id)
            .ok_or(IUpfError::SessionNotFound)?;
        self.n3_teid_to_session.remove(&sess.n3_access_teid);
        Ok(())
    }
}
