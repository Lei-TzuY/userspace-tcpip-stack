//! BGP Graceful Restart (RFC 4724 / RFC 8538)
//!
//! Implements the BGP Graceful Restart capability negotiation, stale route
//! retention during session restart, End-of-RIB (EoR) marker detection,
//! restart timer management, and notification-based Graceful Restart
//! (RFC 8538 "Hard Reset" avoidance).
//!
//! Reference: RFC 4724 §3-4, RFC 8538 §3

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// BGP Capability Code for Graceful Restart.
pub const BGP_CAP_GRACEFUL_RESTART: u8 = 64;

/// BGP Capability Code for Long-Lived Graceful Restart (LLGR, RFC 9494).
pub const BGP_CAP_LLGR: u8 = 71;

/// AFI for IPv4.
pub const AFI_IPV4: u16 = 1;

/// AFI for IPv6.
pub const AFI_IPV6: u16 = 2;

/// AFI for L2VPN.
pub const AFI_L2VPN: u16 = 25;

/// SAFI for Unicast.
pub const SAFI_UNICAST: u8 = 1;

/// SAFI for Multicast.
pub const SAFI_MULTICAST: u8 = 2;

/// SAFI for EVPN.
pub const SAFI_EVPN: u8 = 70;

/// Graceful Restart flag: Restart State (R) bit in capability.
pub const GR_FLAG_RESTART: u8 = 0x80;

/// Graceful Restart flag: Notification (N) bit (RFC 8538).
pub const GR_FLAG_NOTIFICATION: u8 = 0x40;

/// Per-AFI/SAFI flag: Forwarding State preserved (F) bit.
pub const GR_AFI_FLAG_FORWARDING: u8 = 0x80;

/// Default Restart Time (seconds) — how long the restarting router
/// expects to take before it re-establishes BGP sessions.
pub const DEFAULT_RESTART_TIME_SECS: u16 = 120;

/// Default Stale Routes Time — how long the helper retains stale
/// routes before purging (selection timer).
pub const DEFAULT_STALE_ROUTES_TIME_SECS: u32 = 360;

/// Address Family key for GR capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFamily {
    pub afi: u16,
    pub safi: u8,
}

impl AddressFamily {
    pub fn new(afi: u16, safi: u8) -> Self {
        Self { afi, safi }
    }

    pub fn ipv4_unicast() -> Self {
        Self::new(AFI_IPV4, SAFI_UNICAST)
    }

    pub fn ipv6_unicast() -> Self {
        Self::new(AFI_IPV6, SAFI_UNICAST)
    }

    pub fn l2vpn_evpn() -> Self {
        Self::new(AFI_L2VPN, SAFI_EVPN)
    }
}

/// Per-AFI/SAFI Graceful Restart capability entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrAddressFamilyEntry {
    /// Address family.
    pub af: AddressFamily,
    /// Forwarding State preserved flag.
    pub forwarding_preserved: bool,
}

/// Graceful Restart Capability (sent in BGP OPEN).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrCapability {
    /// Restart flags (R, N bits).
    pub flags: u8,
    /// Restart Time in seconds (12 bits, max 4095).
    pub restart_time_secs: u16,
    /// Per-AFI/SAFI entries.
    pub families: Vec<GrAddressFamilyEntry>,
}

impl GrCapability {
    /// Create a new GR capability with default restart time.
    pub fn new(restart_time: u16, restart_state: bool, notification_support: bool) -> Self {
        let mut flags = 0u8;
        if restart_state {
            flags |= GR_FLAG_RESTART;
        }
        if notification_support {
            flags |= GR_FLAG_NOTIFICATION;
        }
        Self {
            flags,
            restart_time_secs: restart_time & 0x0FFF,
            families: Vec::new(),
        }
    }

    /// Add an address family entry.
    pub fn add_family(&mut self, af: AddressFamily, forwarding_preserved: bool) {
        self.families.push(GrAddressFamilyEntry {
            af,
            forwarding_preserved,
        });
    }

    /// Check if the Restart State (R) bit is set.
    pub fn is_restarting(&self) -> bool {
        (self.flags & GR_FLAG_RESTART) != 0
    }

    /// Check if the Notification (N) bit is set (RFC 8538).
    pub fn supports_notification_gr(&self) -> bool {
        (self.flags & GR_FLAG_NOTIFICATION) != 0
    }

    /// Serialize the GR Capability to bytes (capability value only).
    pub fn serialize(&self) -> Vec<u8> {
        // First 2 bytes: [Restart Flags (4 bits) | Restart Time (12 bits)]
        let restart_field =
            ((self.flags as u16) << 8) | (self.restart_time_secs & 0x0FFF);
        let mut buf = Vec::new();
        buf.extend_from_slice(&restart_field.to_be_bytes());

        // Each family: AFI(2) + SAFI(1) + Flags(1) = 4 bytes
        for entry in &self.families {
            buf.extend_from_slice(&entry.af.afi.to_be_bytes());
            buf.push(entry.af.safi);
            buf.push(if entry.forwarding_preserved {
                GR_AFI_FLAG_FORWARDING
            } else {
                0
            });
        }

        buf
    }

    /// Parse GR Capability from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, GrError> {
        if data.len() < 2 {
            return Err(GrError::CapabilityTooShort(data.len()));
        }

        let restart_field = u16::from_be_bytes([data[0], data[1]]);
        let flags = (restart_field >> 8) as u8 & 0xF0;
        let restart_time = restart_field & 0x0FFF;

        let mut families = Vec::new();
        let mut offset = 2;
        while offset + 4 <= data.len() {
            let afi = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let safi = data[offset + 2];
            let af_flags = data[offset + 3];
            families.push(GrAddressFamilyEntry {
                af: AddressFamily::new(afi, safi),
                forwarding_preserved: (af_flags & GR_AFI_FLAG_FORWARDING) != 0,
            });
            offset += 4;
        }

        Ok(Self {
            flags,
            restart_time_secs: restart_time,
            families,
        })
    }
}

/// Stale route entry — a route marked as stale during GR.
#[derive(Debug, Clone)]
pub struct StaleRoute {
    /// Prefix (IPv4).
    pub prefix: Ipv4Addr,
    /// Prefix length.
    pub prefix_len: u8,
    /// Next hop.
    pub next_hop: Ipv4Addr,
    /// AS path.
    pub as_path: Vec<u32>,
    /// Local preference.
    pub local_pref: u32,
    /// Whether forwarding state is preserved for this route.
    pub forwarding_preserved: bool,
    /// Timestamp (epoch seconds) when the route was marked stale.
    pub stale_since: u64,
}

/// GR Session State for a single BGP peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrSessionState {
    /// Normal operation — no GR in progress.
    Normal,
    /// Helper mode — the peer has restarted, we retain stale routes.
    Helper {
        /// Restart timer deadline (epoch seconds).
        restart_deadline: u64,
        /// AFIs for which End-of-RIB has been received.
        eor_received: Vec<AddressFamily>,
    },
    /// Restarting mode — this router has restarted and is re-learning.
    Restarting {
        /// Selection deferral timer deadline.
        deferral_deadline: u64,
        /// AFIs for which End-of-RIB has been sent.
        eor_sent: Vec<AddressFamily>,
    },
}

/// GR processing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrError {
    /// Capability data too short to parse.
    CapabilityTooShort(usize),
    /// Peer does not support GR for the given AFI/SAFI.
    AfNotSupported(AddressFamily),
    /// Restart timer expired — stale routes must be purged.
    RestartTimerExpired,
    /// Selection deferral timer expired.
    DeferralTimerExpired,
    /// Peer session not found.
    PeerNotFound(Ipv4Addr),
}

impl std::fmt::Display for GrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapabilityTooShort(len) => {
                write!(f, "GR capability too short: {} bytes", len)
            }
            Self::AfNotSupported(af) => {
                write!(f, "AFI/SAFI {:?} not supported for GR", af)
            }
            Self::RestartTimerExpired => write!(f, "GR restart timer expired"),
            Self::DeferralTimerExpired => write!(f, "GR deferral timer expired"),
            Self::PeerNotFound(addr) => write!(f, "Peer {} not found", addr),
        }
    }
}

/// End-of-RIB marker detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EorMarkerResult {
    /// This UPDATE is an End-of-RIB marker for the given AF.
    IsEor(AddressFamily),
    /// This UPDATE is a normal route update, not EoR.
    NotEor,
}

/// BGP Graceful Restart Engine.
///
/// Manages GR state for all peers, stale route retention,
/// restart/selection timers, and End-of-RIB tracking.
#[derive(Debug)]
pub struct BgpGracefulRestartEngine {
    /// Local GR capability (advertised in OPEN).
    pub local_capability: GrCapability,
    /// Per-peer GR state.
    pub peer_states: HashMap<Ipv4Addr, GrSessionState>,
    /// Per-peer negotiated GR capabilities.
    pub peer_capabilities: HashMap<Ipv4Addr, GrCapability>,
    /// Stale routes retained during GR, keyed by peer address.
    pub stale_routes: HashMap<Ipv4Addr, Vec<StaleRoute>>,
    /// Default stale route retention time (seconds).
    pub stale_routes_time_secs: u32,
}

impl BgpGracefulRestartEngine {
    /// Create a new GR engine with the given local capability.
    pub fn new(local_capability: GrCapability) -> Self {
        Self {
            local_capability,
            peer_states: HashMap::new(),
            peer_capabilities: HashMap::new(),
            stale_routes: HashMap::new(),
            stale_routes_time_secs: DEFAULT_STALE_ROUTES_TIME_SECS,
        }
    }

    /// Register a peer and store its GR capability received in OPEN.
    pub fn register_peer(&mut self, peer: Ipv4Addr, capability: GrCapability) {
        self.peer_capabilities.insert(peer, capability);
        self.peer_states.insert(peer, GrSessionState::Normal);
    }

    /// Check if a peer supports GR for a given address family.
    pub fn peer_supports_af(&self, peer: &Ipv4Addr, af: &AddressFamily) -> bool {
        self.peer_capabilities
            .get(peer)
            .map(|cap| cap.families.iter().any(|e| &e.af == af))
            .unwrap_or(false)
    }

    /// Handle peer session drop — enter Helper mode if GR is negotiated.
    ///
    /// Returns the list of stale routes that should be retained.
    pub fn handle_peer_down(
        &mut self,
        peer: Ipv4Addr,
        current_time: u64,
        routes: Vec<StaleRoute>,
    ) -> Result<GrSessionState, GrError> {
        let cap = self
            .peer_capabilities
            .get(&peer)
            .ok_or(GrError::PeerNotFound(peer))?;

        let restart_deadline = current_time + cap.restart_time_secs as u64;

        // Mark all routes as stale
        let mut stale = Vec::with_capacity(routes.len());
        for mut route in routes {
            route.stale_since = current_time;
            // Check if forwarding is preserved for this route's AF
            route.forwarding_preserved = cap
                .families
                .iter()
                .any(|e| e.forwarding_preserved);
            stale.push(route);
        }
        self.stale_routes.insert(peer, stale);

        let state = GrSessionState::Helper {
            restart_deadline,
            eor_received: Vec::new(),
        };
        self.peer_states.insert(peer, state.clone());

        Ok(state)
    }

    /// Handle peer session re-establishment — peer sends OPEN with R bit.
    pub fn handle_peer_reestablished(
        &mut self,
        peer: &Ipv4Addr,
        new_capability: GrCapability,
    ) -> Result<(), GrError> {
        if !self.peer_states.contains_key(peer) {
            return Err(GrError::PeerNotFound(*peer));
        }

        self.peer_capabilities.insert(*peer, new_capability);
        // State remains Helper until EoR received for all AFIs
        Ok(())
    }

    /// Detect End-of-RIB marker in a BGP UPDATE message.
    ///
    /// An EoR marker is an UPDATE with:
    /// - Empty withdrawn routes
    /// - Empty NLRI
    /// - For IPv4 unicast: completely empty UPDATE
    /// - For other AFIs: MP_UNREACH_NLRI with empty list
    pub fn detect_eor(
        &self,
        withdrawn_len: u16,
        path_attr_len: u16,
        nlri_len: u16,
        af: AddressFamily,
    ) -> EorMarkerResult {
        if af == AddressFamily::ipv4_unicast() {
            // IPv4 Unicast EoR: UPDATE with no withdrawn, no attributes, no NLRI
            if withdrawn_len == 0 && path_attr_len == 0 && nlri_len == 0 {
                return EorMarkerResult::IsEor(af);
            }
        } else {
            // Other AFIs: UPDATE with MP_UNREACH_NLRI containing just AFI/SAFI
            // Approximation: zero withdrawn and zero NLRI with minimal attrs
            if withdrawn_len == 0 && nlri_len == 0 && path_attr_len <= 6 {
                return EorMarkerResult::IsEor(af);
            }
        }
        EorMarkerResult::NotEor
    }

    /// Record that an End-of-RIB was received from a peer for a given AF.
    pub fn record_eor_received(
        &mut self,
        peer: &Ipv4Addr,
        af: AddressFamily,
    ) -> Result<bool, GrError> {
        let state = self
            .peer_states
            .get_mut(peer)
            .ok_or(GrError::PeerNotFound(*peer))?;

        match state {
            GrSessionState::Helper { eor_received, .. } => {
                if !eor_received.contains(&af) {
                    eor_received.push(af);
                }

                // Check if all negotiated AFIs have received EoR
                let cap = self
                    .peer_capabilities
                    .get(peer)
                    .ok_or(GrError::PeerNotFound(*peer))?;
                let all_received = cap
                    .families
                    .iter()
                    .all(|entry| eor_received.contains(&entry.af));

                if all_received {
                    // GR complete for this peer — purge stale routes and return to Normal
                    // (In practice, we'd do route selection first)
                    return Ok(true);
                }
                Ok(false)
            }
            _ => Ok(false),
        }
    }

    /// Complete GR for a peer — remove stale routes and transition to Normal.
    pub fn complete_gr(&mut self, peer: &Ipv4Addr) -> Result<usize, GrError> {
        if !self.peer_states.contains_key(peer) {
            return Err(GrError::PeerNotFound(*peer));
        }

        let purged = self
            .stale_routes
            .remove(peer)
            .map(|routes| routes.len())
            .unwrap_or(0);

        self.peer_states.insert(*peer, GrSessionState::Normal);
        Ok(purged)
    }

    /// Check and expire restart timer — purge stale routes if timer has expired.
    pub fn check_restart_timer(
        &mut self,
        peer: &Ipv4Addr,
        current_time: u64,
    ) -> Result<Option<usize>, GrError> {
        let state = self
            .peer_states
            .get(peer)
            .ok_or(GrError::PeerNotFound(*peer))?
            .clone();

        match state {
            GrSessionState::Helper {
                restart_deadline, ..
            } => {
                if current_time >= restart_deadline {
                    // Timer expired — purge stale routes
                    let purged = self.complete_gr(peer)?;
                    return Ok(Some(purged));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Get the count of stale routes for a peer.
    pub fn stale_route_count(&self, peer: &Ipv4Addr) -> usize {
        self.stale_routes
            .get(peer)
            .map(|routes| routes.len())
            .unwrap_or(0)
    }

    /// Purge stale routes that have exceeded the stale routes time limit.
    pub fn purge_expired_stale_routes(
        &mut self,
        peer: &Ipv4Addr,
        current_time: u64,
    ) -> usize {
        let stale_limit = self.stale_routes_time_secs as u64;
        let mut purged = 0;

        if let Some(routes) = self.stale_routes.get_mut(peer) {
            let before = routes.len();
            routes.retain(|r| current_time - r.stale_since < stale_limit);
            purged = before - routes.len();
        }

        purged
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gr_capability_serialize_and_parse() {
        let mut cap = GrCapability::new(120, true, true);
        cap.add_family(AddressFamily::ipv4_unicast(), true);
        cap.add_family(AddressFamily::ipv6_unicast(), false);

        let bytes = cap.serialize();
        let parsed = GrCapability::parse(&bytes).unwrap();

        assert!(parsed.is_restarting());
        assert!(parsed.supports_notification_gr());
        assert_eq!(parsed.restart_time_secs, 120);
        assert_eq!(parsed.families.len(), 2);
        assert!(parsed.families[0].forwarding_preserved);
        assert!(!parsed.families[1].forwarding_preserved);
    }

    #[test]
    fn test_gr_helper_mode_and_eor_completion() {
        let local_cap = GrCapability::new(120, false, true);
        let mut engine = BgpGracefulRestartEngine::new(local_cap);

        let peer: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mut peer_cap = GrCapability::new(60, true, true);
        peer_cap.add_family(AddressFamily::ipv4_unicast(), true);

        engine.register_peer(peer, peer_cap);

        // Simulate peer going down with 3 stale routes
        let stale_routes = vec![
            StaleRoute {
                prefix: "192.168.1.0".parse().unwrap(),
                prefix_len: 24,
                next_hop: peer,
                as_path: vec![65001],
                local_pref: 100,
                forwarding_preserved: false,
                stale_since: 0,
            },
            StaleRoute {
                prefix: "10.10.0.0".parse().unwrap(),
                prefix_len: 16,
                next_hop: peer,
                as_path: vec![65001, 65002],
                local_pref: 200,
                forwarding_preserved: false,
                stale_since: 0,
            },
            StaleRoute {
                prefix: "172.16.0.0".parse().unwrap(),
                prefix_len: 12,
                next_hop: peer,
                as_path: vec![65001],
                local_pref: 100,
                forwarding_preserved: false,
                stale_since: 0,
            },
        ];

        let state = engine.handle_peer_down(peer, 1000, stale_routes).unwrap();
        assert!(matches!(state, GrSessionState::Helper { .. }));
        assert_eq!(engine.stale_route_count(&peer), 3);

        // Timer not expired yet
        assert_eq!(engine.check_restart_timer(&peer, 1050).unwrap(), None);

        // Receive EoR for IPv4 unicast
        let all_done = engine
            .record_eor_received(&peer, AddressFamily::ipv4_unicast())
            .unwrap();
        assert!(all_done);

        // Complete GR
        let purged = engine.complete_gr(&peer).unwrap();
        assert_eq!(purged, 3);
        assert_eq!(
            engine.peer_states.get(&peer).unwrap(),
            &GrSessionState::Normal
        );
    }

    #[test]
    fn test_gr_restart_timer_expiry_purges_stale() {
        let local_cap = GrCapability::new(120, false, false);
        let mut engine = BgpGracefulRestartEngine::new(local_cap);

        let peer: Ipv4Addr = "10.0.0.2".parse().unwrap();
        let mut peer_cap = GrCapability::new(30, true, false);
        peer_cap.add_family(AddressFamily::ipv4_unicast(), true);
        engine.register_peer(peer, peer_cap);

        let routes = vec![StaleRoute {
            prefix: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            next_hop: peer,
            as_path: vec![65100],
            local_pref: 100,
            forwarding_preserved: false,
            stale_since: 0,
        }];

        engine.handle_peer_down(peer, 1000, routes).unwrap();

        // Timer expires at t=1030 (restart_time=30)
        let result = engine.check_restart_timer(&peer, 1031).unwrap();
        assert_eq!(result, Some(1)); // 1 stale route purged
        assert_eq!(engine.stale_route_count(&peer), 0);
    }
}
