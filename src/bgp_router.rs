//! Packet-driven BGP-4 control plane (RFC 4271).
//!
//! This is a real BGP speaker, not a model of one. Every message it exchanges travels
//! over this repository's own reliable TCP runtime on port 179:
//!
//! ```text
//! BgpRouter -> TcpListener / TcpStream :179 -> SocketRuntime -> IPv4 / ARP / Ethernet
//! ```
//!
//! and every route it selects is installed into the same `RoutingTable` the IPv4
//! forwarding path consults:
//!
//! ```text
//! UPDATE -> Adj-RIB-In -> best path -> Loc-RIB -> RoutingTable -> IPv4 forwarding
//! ```
//!
//! The speaker never shuttles messages between peer objects in memory, never sleeps,
//! never spawns a thread, and never reads a wall clock. `poll` is driven with a
//! simulated timestamp, which is what makes the whole control plane reproducible.

use crate::bgp::{
    BGP_DEFAULT_LOCAL_PREF, BGP_ERR_CEASE, BGP_ERR_FSM, BGP_ERR_HOLD_TIMER_EXPIRED,
    BGP_ERR_UPDATE_MESSAGE, BGP_MIN_HOLD_TIME, BGP_PORT, BGP_SUB_BAD_BGP_IDENTIFIER,
    BGP_SUB_BAD_PEER_AS, BGP_SUB_INVALID_NEXT_HOP, BGP_SUB_MALFORMED_AS_PATH,
    BGP_SUB_OPTIONAL_ATTRIBUTE_ERROR, BGP_SUB_UNACCEPTABLE_HOLD_TIME, BGP_SUB_UNSUPPORTED_VERSION,
    BGP_VERSION, BgpFramer, BgpNotificationMessage, BgpOpenMessage, BgpParseError,
    BgpPathAttributes, BgpPdu, BgpRouteRefreshMessage, BgpUpdateMessage, Ipv4Prefix,
    MAX_CLUSTER_LIST_LEN,
};
use crate::bgp_caps::{
    AfiSafi, BGP_SUB_UNSUPPORTED_CAPABILITY, BgpCapability, BgpCapabilitySet,
    BgpGracefulRestartCapability, BgpGracefulRestartFamily, NegotiatedCapabilities, negotiate,
};
use crate::bgp_evpn::{
    EvpnAdjRibIn, EvpnAdjRibOut, EvpnAdvertisedRoute, EvpnLocRib, EvpnPath, EvpnRoute,
    EvpnRouteKey, MAX_EVPN_ROUTES, RouteTarget, decode_evpn_nlri_list, encode_evpn_nlri_list,
    mac_mobility_from_communities, other_ext_communities, route_targets_from_communities,
    select_best_evpn,
};
use crate::bgp_mp::{MpReachNlri, MpUnreachNlri};
use crate::bgp_rib::{
    AdjRibIn, AdjRibOut, AdvertisedRoute, BgpPath, LocRib, PathSource, PolicyOutcome, RoutePolicy,
    select_best,
};
use crate::ipv4::Ipv4Address;
use crate::router::{RouteSource, RoutingTable};
use crate::socket::{SocketError, SocketRuntime, TcpListenerHandle, TcpStreamHandle};
use crate::tcp::{SocketAddrV4, TcpState};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Default ConnectRetryTime, in simulated milliseconds (RFC 4271 suggests 120 s;
/// the lab runs a shorter one so convergence tests stay brisk in logical time).
pub const DEFAULT_CONNECT_RETRY_MS: u64 = 5_000;
/// Hold time proposed in OPEN, in seconds.
pub const DEFAULT_HOLD_TIME: u16 = 90;
/// Hold time applied while waiting for the peer's OPEN, before one is negotiated
/// (RFC 4271 section 8.2.2 "large value", 4 minutes).
pub const INITIAL_HOLD_MS: u64 = 240_000;
/// Bytes drained from the socket per read call.
const READ_CHUNK: usize = 2_048;
/// Upper bound on retained control-plane log lines.
pub const MAX_EVENT_LOG: usize = 512;
/// Default per-peer prefix limit. A neighbour that advertises more than this has its
/// session closed rather than being allowed to exhaust memory (RFC 4486 subcode 1).
pub const DEFAULT_MAX_PREFIXES: usize = 4_096;
/// NOTIFICATION subcode for "Maximum Number of Prefixes Reached" (RFC 4486).
pub const BGP_SUB_MAX_PREFIXES: u8 = 1;
/// Default RFC 4724 helper retention time advertised in OPEN, in seconds.
pub const DEFAULT_GRACEFUL_RESTART_TIME: u16 = 120;

/// BGP finite state machine states (RFC 4271 section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BgpState {
    Idle,
    Connect,
    Active,
    OpenSent,
    OpenConfirm,
    Established,
}

impl BgpState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BgpState::Idle => "Idle",
            BgpState::Connect => "Connect",
            BgpState::Active => "Active",
            BgpState::OpenSent => "OpenSent",
            BgpState::OpenConfirm => "OpenConfirm",
            BgpState::Established => "Established",
        }
    }
}

impl fmt::Display for BgpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether this speaker opens the TCP connection to the peer or waits for it.
///
/// Configuring one end of every session passive is standard operational practice and
/// removes connection-collision ambiguity, which keeps the simulation deterministic.
/// An inbound connection that arrives for a peer already past `Active` is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BgpPeerMode {
    Active,
    Passive,
}

/// What this neighbour is to the local speaker, for route reflection (RFC 4456).
///
/// The role is configured, never inferred from the shape of the topology. A
/// speaker that guessed "this looks like a hub" would silently start reflecting
/// between peers an operator had deliberately kept apart, and the difference
/// between a client and a non-client is precisely what stops a reflection loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum BgpPeerRole {
    /// An ordinary neighbour. Routes learned from an internal peer are not
    /// passed on to it, which is the plain RFC 4271 rule.
    #[default]
    Normal,
    /// A route reflector client. The local speaker reflects to it, and reflects
    /// what it hears from it on to every other internal peer.
    RouteReflectorClient,
}

impl BgpPeerRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            BgpPeerRole::Normal => "non-client",
            BgpPeerRole::RouteReflectorClient => "client",
        }
    }

    pub fn is_client(&self) -> bool {
        *self == BgpPeerRole::RouteReflectorClient
    }
}

impl fmt::Display for BgpPeerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-peer message counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BgpPeerCounters {
    pub opens_sent: u64,
    pub opens_received: u64,
    pub updates_sent: u64,
    pub updates_received: u64,
    pub keepalives_sent: u64,
    pub keepalives_received: u64,
    /// RFC 2918 requests sent to this peer.
    pub route_refreshes_sent: u64,
    /// RFC 2918 requests received from this peer.
    pub route_refreshes_received: u64,
    pub notifications_sent: u64,
    pub notifications_received: u64,
    /// NLRI discarded because the local ASN already appeared in AS_PATH.
    pub as_loops_rejected: u64,
    /// NLRI discarded by the import policy.
    pub policy_rejected: u64,
    /// NLRI discarded because the NEXT_HOP was unusable.
    pub next_hop_rejected: u64,
    /// UPDATEs refused because the AS_PATH was not acceptable on this session.
    pub as_path_rejected: u64,
    /// EVPN routes received from this peer.
    pub evpn_received: u64,
    /// EVPN routes advertised to this peer.
    pub evpn_advertised: u64,
    /// EVPN NLRI discarded because no configured import Route Target matched.
    pub evpn_rt_rejected: u64,
    /// Routes discarded because ORIGINATOR_ID named this speaker (RFC 4456
    /// section 7): the route has already been here and has come back.
    pub originator_loops_rejected: u64,
    /// Routes discarded because CLUSTER_LIST already contained the local cluster
    /// ID, meaning the route has already been reflected by this cluster.
    pub cluster_loops_rejected: u64,
    /// Routes reflected to this peer under the RFC 4456 rules, counted at the
    /// point the UPDATE was actually written.
    pub routes_reflected: u64,
    /// Routes withheld from this peer because the RFC 4456 propagation rules do
    /// not allow it: an internally learned path with neither end a client.
    pub rr_suppressed: u64,
    /// Inbound connections refused or resolved away by collision handling.
    pub collisions_resolved: u64,
    /// Unexpected transport losses for which RFC 4724 stale-route retention began.
    pub graceful_restarts_started: u64,
    /// Address-family End-of-RIB markers that completed graceful restart early.
    pub graceful_restart_eors: u64,
    /// Graceful-restart procedures that reached the Restart Time deadline.
    pub graceful_restart_expirations: u64,
}

/// One configured BGP neighbour and the session state that belongs to it.
pub struct BgpPeer {
    pub addr: Ipv4Address,
    pub remote_as: u32,
    /// Local address used as the source of the session (the "update source").
    pub local_addr: Ipv4Address,
    pub mode: BgpPeerMode,
    /// Route reflection role. Changing it changes what this speaker will pass on
    /// to the neighbour, and nothing else.
    pub role: BgpPeerRole,
    pub admin_up: bool,
    pub state: BgpState,
    pub stream: Option<TcpStreamHandle>,
    /// True when the transport in `stream` was opened by the peer rather than by
    /// us. Collision resolution (RFC 4271 section 6.8) is stated in terms of
    /// which side initiated, so which side did has to be remembered.
    stream_inbound: bool,
    framer: BgpFramer,
    /// A second, colliding connection held while the winner is decided.
    collision: Option<CollisionConn>,
    connect_retry_deadline: Option<u64>,
    hold_deadline: Option<u64>,
    keepalive_deadline: Option<u64>,
    pub negotiated_hold_ms: u64,
    pub keepalive_interval_ms: u64,
    /// What the two OPENs agreed to carry. Empty until the peer's OPEN arrives,
    /// which is what stops an EVPN route being advertised before negotiation.
    pub negotiated: NegotiatedCapabilities,
    /// Families the peer asked us to replay. Keeping this separate from the
    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.
    refresh_pending: BTreeSet<AfiSafi>,
    /// Families whose routes are retained as RFC 4724 stale state after an
    /// unexpected transport failure.
    graceful_restart_stale: BTreeSet<AfiSafi>,
    /// Absolute simulated deadline for stale-route retention.
    graceful_restart_deadline: Option<u64>,
    /// Time the restarting peer's replacement OPEN was accepted. Routes received
    /// at or after this point are fresh; older ones remain stale until EOR.
    graceful_restart_refresh_started_ms: Option<u64>,
    pub remote_router_id: Option<Ipv4Address>,
    pub established_since_ms: Option<u64>,
    pub import_policy: RoutePolicy,
    pub export_policy: RoutePolicy,
    /// Advertise our own session address as the NEXT_HOP instead of passing on the one
    /// we were told. Always done on eBGP sessions; optional on iBGP ones, where it is
    /// what lets a peer with no IGP resolve the next hop.
    pub next_hop_self: bool,
    /// Largest number of prefixes this neighbour may hold in the Adj-RIB-In.
    pub max_prefixes: usize,
    /// Require an eBGP UPDATE to lead with this neighbour's own ASN (RFC 4271
    /// section 6.3). On by default, as it is on modern production routers.
    pub enforce_first_as: bool,
    /// Set when a BGP message could only be written to the transport in part. The
    /// stream then carries half a message and cannot be repaired by retrying, so the
    /// session is reset instead of being allowed to desynchronise the peer's framer.
    tx_desynced: bool,
    pub counters: BgpPeerCounters,
    pub last_error: Option<String>,
    /// How many times this peer has reached ESTABLISHED.
    pub establishment_count: u32,
}

impl BgpPeer {
    fn new(addr: Ipv4Address, remote_as: u32, local_addr: Ipv4Address, mode: BgpPeerMode) -> Self {
        BgpPeer {
            addr,
            remote_as,
            local_addr,
            mode,
            role: BgpPeerRole::Normal,
            admin_up: true,
            state: BgpState::Idle,
            stream: None,
            stream_inbound: false,
            framer: BgpFramer::new(),
            collision: None,
            connect_retry_deadline: None,
            hold_deadline: None,
            keepalive_deadline: None,
            negotiated_hold_ms: 0,
            keepalive_interval_ms: 0,
            negotiated: NegotiatedCapabilities::default(),
            refresh_pending: BTreeSet::new(),
            graceful_restart_stale: BTreeSet::new(),
            graceful_restart_deadline: None,
            graceful_restart_refresh_started_ms: None,
            remote_router_id: None,
            established_since_ms: None,
            import_policy: RoutePolicy::new(),
            export_policy: RoutePolicy::new(),
            next_hop_self: false,
            max_prefixes: DEFAULT_MAX_PREFIXES,
            enforce_first_as: true,
            tx_desynced: false,
            counters: BgpPeerCounters::default(),
            last_error: None,
            establishment_count: 0,
        }
    }

    pub fn is_established(&self) -> bool {
        self.state == BgpState::Established
    }

    /// True when this session negotiated `family` and is up. Both halves matter:
    /// a family agreed on a session that has since dropped must not be used.
    pub fn carries(&self, family: AfiSafi) -> bool {
        self.is_established() && self.negotiated.supports(family)
    }

    /// True when EVPN NLRI may travel on this session.
    pub fn carries_evpn(&self) -> bool {
        self.carries(AfiSafi::L2VPN_EVPN)
    }

    /// The address families this session agreed to carry.
    pub fn negotiated_families(&self) -> Vec<AfiSafi> {
        self.negotiated.families.iter().copied().collect()
    }

    /// Simulated milliseconds since the session came up.
    pub fn uptime_ms(&self, now_ms: u64) -> Option<u64> {
        self.established_since_ms.map(|t| now_ms.saturating_sub(t))
    }

    /// Milliseconds left before the HoldTimer fires.
    pub fn hold_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.hold_deadline.map(|d| d.saturating_sub(now_ms))
    }

    /// Milliseconds left before the next KEEPALIVE is due.
    pub fn keepalive_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.keepalive_deadline.map(|d| d.saturating_sub(now_ms))
    }

    /// Bytes currently held in the stream reassembly buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.framer.buffered()
    }

    /// True when this neighbour is a route reflector client of ours.
    pub fn is_client(&self) -> bool {
        self.role.is_client()
    }

    /// True while a second connection to this neighbour is being held pending
    /// collision resolution.
    pub fn has_collision(&self) -> bool {
        self.collision.is_some()
    }

    /// True while routes from this peer are being retained by RFC 4724 helper mode.
    pub fn graceful_restart_active(&self) -> bool {
        self.graceful_restart_deadline.is_some() && !self.graceful_restart_stale.is_empty()
    }

    pub fn graceful_restart_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.graceful_restart_deadline
            .map(|d| d.saturating_sub(now_ms))
    }

    pub fn graceful_restart_stale_families(&self) -> Vec<AfiSafi> {
        self.graceful_restart_stale.iter().copied().collect()
    }
}

/// A second TCP connection to a peer that already has one, held until RFC 4271
/// section 6.8 can say which of the two survives.
///
/// Only the framer runs on it. No OPEN is sent and no FSM state belongs to it:
/// all that is wanted from this connection before the decision is the peer's BGP
/// identifier, and that arrives in the OPEN the peer sends unprompted.
struct CollisionConn {
    stream: TcpStreamHandle,
    framer: BgpFramer,
}

/// A control-plane log line, retained for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgpEvent {
    pub time_ms: u64,
    pub peer: Ipv4Address,
    pub text: String,
}

impl fmt::Display for BgpEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:>8}ms] {} {}", self.time_ms, self.peer, self.text)
    }
}

/// Snapshot of one peer for `show bgp summary` style output.
#[derive(Debug, Clone)]
pub struct BgpPeerSummary {
    pub addr: Ipv4Address,
    pub remote_as: u32,
    pub local_addr: Ipv4Address,
    pub state: BgpState,
    pub router_id: Option<Ipv4Address>,
    pub uptime_ms: Option<u64>,
    pub hold_ms: u64,
    pub hold_remaining_ms: Option<u64>,
    pub keepalive_interval_ms: u64,
    pub keepalive_remaining_ms: Option<u64>,
    pub prefixes_received: usize,
    pub prefixes_advertised: usize,
    pub counters: BgpPeerCounters,
    pub last_error: Option<String>,
    pub establishment_count: u32,
}

/// Why a received route was discarded by the RFC 4456 loop checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReflectionLoop {
    /// ORIGINATOR_ID is this speaker's own BGP identifier.
    Originator,
    /// CLUSTER_LIST already contains this speaker's cluster ID.
    Cluster,
}

/// What the RFC 4456 rules say about sending one path to one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Propagation {
    /// Not allowed: an internally learned path with neither end a client.
    Deny,
    /// Allowed as an ordinary advertisement, with no reflection metadata.
    Plain,
    /// Allowed as a reflection, so ORIGINATOR_ID and CLUSTER_LIST go with it.
    Reflect,
}

/// Why a session is being torn down.
enum Teardown {
    /// The transport went away; no NOTIFICATION can be delivered.
    Transport(String),
    /// A protocol violation; tell the peer before closing.
    Protocol(BgpNotificationMessage, String),
    /// The peer told us it is going away.
    PeerNotification(String),
}

/// A BGP-4 speaker: one local AS, one BGP identifier, a set of peers, three RIBs,
/// and the decision process that connects them to the forwarding table.
pub struct BgpRouter {
    pub local_as: u32,
    pub router_id: Ipv4Address,
    /// Hold time proposed in our OPEN, in seconds.
    pub hold_time: u16,
    pub connect_retry_ms: u64,
    /// Whether this speaker advertises and acts as an RFC 4724 helper.
    pub graceful_restart_enabled: bool,
    /// Restart Time advertised in the Graceful Restart capability.
    pub graceful_restart_time: u16,
    peers: Vec<BgpPeer>,
    listener: Option<TcpListenerHandle>,
    pub adj_rib_in: AdjRibIn,
    pub loc_rib: LocRib,
    pub adj_rib_out: AdjRibOut,
    /// Address families offered in OPEN.
    families: BTreeSet<AfiSafi>,
    /// EVPN routes received from every peer, before Route Target import.
    pub evpn_adj_rib_in: EvpnAdjRibIn,
    /// The best EVPN path per route, and the only thing the VTEP is programmed from.
    pub evpn_loc_rib: EvpnLocRib,
    /// The best EVPN path per route among *everything* received, whether this
    /// speaker imports the tenant or not. This is what advertisement and
    /// reflection are computed from.
    ///
    /// A route reflector owns no tenant and imports no tenant Route Target, so
    /// its `evpn_loc_rib` is empty and would reflect nothing. Separating "the
    /// best path I could pass on" from "the best path I can use myself" is what
    /// lets the reflector do its job without being configured as a tenant.
    pub evpn_advertise_rib: EvpnLocRib,
    /// EVPN routes advertised to each peer.
    pub evpn_adj_rib_out: EvpnAdjRibOut,
    /// EVPN routes this speaker originates for its own local hosts.
    evpn_originated: BTreeMap<EvpnRouteKey, EvpnRoute>,
    /// Route Targets this speaker will import an EVPN route on. A route whose
    /// Extended Communities match none of these is not accepted into the Loc-RIB.
    import_rts: BTreeSet<RouteTarget>,
    /// Set when the EVPN RIBs changed, so the EVPN decision process runs once per
    /// poll rather than once per route.
    evpn_dirty: bool,
    originated: BTreeMap<Ipv4Prefix, Ipv4Address>,
    /// Prefixes this speaker currently has installed in the FIB.
    installed: BTreeSet<Ipv4Prefix>,
    /// Best paths whose NEXT_HOP could not be resolved to an egress interface.
    unresolved: BTreeSet<Ipv4Prefix>,
    events: Vec<BgpEvent>,
    /// Set whenever the Adj-RIB-In or the originated set changes, so the decision
    /// process runs once per poll instead of once per UPDATE.
    dirty: bool,
    pub decision_runs: u64,
    /// How many times the EVPN decision process has run.
    pub evpn_decision_runs: u64,
    /// The cluster identifier used in CLUSTER_LIST. `None` means "use the router
    /// ID", which is what RFC 4456 section 7 recommends for a cluster with one
    /// reflector in it.
    cluster_id: Option<Ipv4Address>,
    /// Retain EVPN routes whose Route Targets match no local import, so they can
    /// still be reflected. Implied by being a route reflector.
    retain_all_rts: bool,
}

impl BgpRouter {
    pub fn new(local_as: u32, router_id: Ipv4Address) -> Self {
        BgpRouter {
            local_as,
            router_id,
            hold_time: DEFAULT_HOLD_TIME,
            connect_retry_ms: DEFAULT_CONNECT_RETRY_MS,
            graceful_restart_enabled: true,
            graceful_restart_time: DEFAULT_GRACEFUL_RESTART_TIME,
            peers: Vec::new(),
            listener: None,
            adj_rib_in: AdjRibIn::new(),
            loc_rib: LocRib::new(),
            adj_rib_out: AdjRibOut::new(),
            families: BTreeSet::from([AfiSafi::IPV4_UNICAST]),
            evpn_adj_rib_in: EvpnAdjRibIn::new(),
            evpn_loc_rib: EvpnLocRib::new(),
            evpn_advertise_rib: EvpnLocRib::new(),
            evpn_adj_rib_out: EvpnAdjRibOut::new(),
            evpn_originated: BTreeMap::new(),
            import_rts: BTreeSet::new(),
            evpn_dirty: true,
            originated: BTreeMap::new(),
            installed: BTreeSet::new(),
            unresolved: BTreeSet::new(),
            events: Vec::new(),
            dirty: true,
            decision_runs: 0,
            evpn_decision_runs: 0,
            cluster_id: None,
            retain_all_rts: false,
        }
    }

    // ========================================================================
    // Route reflection (RFC 4456)
    // ========================================================================

    /// The cluster identifier this speaker prepends to CLUSTER_LIST when it
    /// reflects. Defaults to the BGP identifier, which RFC 4456 section 7 allows
    /// for a cluster served by a single reflector.
    pub fn cluster_id(&self) -> Ipv4Address {
        self.cluster_id.unwrap_or(self.router_id)
    }

    /// Sets an explicit cluster identifier.
    ///
    /// Two reflectors serving the same set of clients should share one, so that
    /// a route reflected by either is recognised as already seen by the other.
    ///
    /// The Adj-RIB-Out is deliberately *not* cleared. It is the record of what
    /// each peer was actually told, and both it and the EVPN equivalent store the
    /// reflection metadata alongside the route - so recomputing against it finds
    /// every advertisement whose CLUSTER_LIST has changed and re-sends exactly
    /// those. Discarding the record instead would leave the speaker unable to
    /// tell a peer anything had changed at all.
    pub fn set_cluster_id(&mut self, id: Ipv4Address) {
        if self.cluster_id == Some(id) {
            return;
        }
        self.cluster_id = Some(id);
        self.dirty = true;
        self.evpn_dirty = true;
    }

    /// Marks `peer` as a route reflector client, or back to an ordinary peer.
    ///
    /// Returns false if no such neighbour is configured.
    ///
    /// Changing one peer's role changes what *several* peers may hear, because
    /// the rules are stated over the pair of ends: routes this peer advertises
    /// become reflectable to everybody, and routes from non-clients stop being
    /// advertisable to this one. Every stored path from this peer therefore has
    /// its `from_client` flag rewritten, and both decision processes rerun.
    ///
    /// The Adj-RIB-Out is left alone on purpose. It records what each peer was
    /// actually told, and it is what the next advertisement run diffs against to
    /// produce the withdrawals a demotion implies. Clearing it would make the
    /// speaker forget it had ever sent those routes, and they would sit in the
    /// demoted peer's RIB for ever.
    pub fn set_route_reflector_client(&mut self, peer: Ipv4Address, on: bool) -> bool {
        let role = if on {
            BgpPeerRole::RouteReflectorClient
        } else {
            BgpPeerRole::Normal
        };
        let Some(p) = self.peers.iter_mut().find(|p| p.addr == peer) else {
            return false;
        };
        if p.role == role {
            return true;
        }
        p.role = role;

        // Paths already learned from this peer were stamped with the old role.
        let is_client = role.is_client();
        if let Some(table) = self.adj_rib_in.peer_table_mut(peer) {
            for path in table.values_mut() {
                path.from_client = is_client;
            }
        }
        if let Some(table) = self.evpn_adj_rib_in.peer_table_mut(peer) {
            for path in table.values_mut() {
                path.from_client = is_client;
            }
        }

        self.dirty = true;
        self.evpn_dirty = true;
        true
    }

    /// True when at least one neighbour is a client, which is what makes this
    /// speaker a route reflector.
    pub fn is_route_reflector(&self) -> bool {
        self.peers.iter().any(|p| p.is_client())
    }

    /// The addresses of every configured route reflector client.
    pub fn route_reflector_clients(&self) -> Vec<Ipv4Address> {
        self.peers
            .iter()
            .filter(|p| p.is_client())
            .map(|p| p.addr)
            .collect()
    }

    /// The role configured for one neighbour.
    pub fn peer_role(&self, peer: Ipv4Address) -> Option<BgpPeerRole> {
        self.peer(peer).map(|p| p.role)
    }

    /// Whether EVPN routes are retained even when no local Route Target matches.
    ///
    /// A route reflector does this unconditionally: it has no tenant of its own,
    /// so filtering on import would leave it nothing to reflect. An ordinary
    /// speaker can be told to as well, which is what a transit speaker with no
    /// local instances would be configured to do.
    pub fn retains_all_route_targets(&self) -> bool {
        self.retain_all_rts || self.is_route_reflector()
    }

    /// Forces Route Target retention on independently of the reflector role.
    pub fn set_retain_all_route_targets(&mut self, on: bool) {
        if self.retain_all_rts == on {
            return;
        }
        self.retain_all_rts = on;
        self.evpn_dirty = true;
    }

    /// Sets the hold time proposed in OPEN. Values of 1 or 2 seconds are illegal
    /// (RFC 4271 section 4.2) and are raised to the minimum.
    pub fn set_hold_time(&mut self, seconds: u16) {
        self.hold_time = if seconds == 0 {
            0
        } else {
            seconds.max(BGP_MIN_HOLD_TIME)
        };
    }

    pub fn set_connect_retry_ms(&mut self, ms: u64) {
        self.connect_retry_ms = ms.max(1);
    }

    pub fn set_graceful_restart_enabled(&mut self, enabled: bool) {
        self.graceful_restart_enabled = enabled;
    }

    pub fn set_graceful_restart_time(&mut self, seconds: u16) {
        self.graceful_restart_time = seconds.min(crate::bgp_caps::BGP_GR_MAX_RESTART_TIME);
    }

    /// Configures a neighbour. Peers are kept sorted by address so every iteration
    /// over them, and therefore every message ordering, is deterministic.
    pub fn add_peer(
        &mut self,
        addr: Ipv4Address,
        remote_as: u32,
        local_addr: Ipv4Address,
        mode: BgpPeerMode,
    ) {
        if self.peers.iter().any(|p| p.addr == addr) {
            return;
        }
        self.peers
            .push(BgpPeer::new(addr, remote_as, local_addr, mode));
        self.peers.sort_by_key(|p| p.addr);
    }

    pub fn peers(&self) -> &[BgpPeer] {
        &self.peers
    }

    pub fn peer(&self, addr: Ipv4Address) -> Option<&BgpPeer> {
        self.peers.iter().find(|p| p.addr == addr)
    }

    pub fn peer_mut(&mut self, addr: Ipv4Address) -> Option<&mut BgpPeer> {
        self.peers.iter_mut().find(|p| p.addr == addr)
    }

    pub fn peer_state(&self, addr: Ipv4Address) -> Option<BgpState> {
        self.peer(addr).map(|p| p.state)
    }

    pub fn established_peer_count(&self) -> usize {
        self.peers.iter().filter(|p| p.is_established()).count()
    }

    /// Sets the import policy applied to routes received from `addr`.
    pub fn set_import_policy(&mut self, addr: Ipv4Address, policy: RoutePolicy) {
        if let Some(p) = self.peer_mut(addr) {
            p.import_policy = policy;
        }
    }

    /// Sets the export policy applied to routes advertised to `addr`.
    pub fn set_export_policy(&mut self, addr: Ipv4Address, policy: RoutePolicy) {
        if let Some(p) = self.peer_mut(addr) {
            p.export_policy = policy;
        }
    }

    /// Turns next-hop-self on or off for `addr`. eBGP sessions always rewrite the
    /// NEXT_HOP regardless; this is what makes an iBGP peer usable without an IGP.
    pub fn set_next_hop_self(&mut self, addr: Ipv4Address, on: bool) {
        if let Some(p) = self.peer_mut(addr) {
            p.next_hop_self = on;
        }
    }

    /// Caps how many prefixes `addr` may install in the Adj-RIB-In.
    pub fn set_max_prefixes(&mut self, addr: Ipv4Address, limit: usize) {
        if let Some(p) = self.peer_mut(addr) {
            p.max_prefixes = limit;
        }
    }

    /// Turns the eBGP leading-AS check on or off for `addr`. Turning it off still
    /// leaves an empty AS_PATH from an external peer refused, because that is not a
    /// policy preference: a zero-length path would beat every real route.
    pub fn set_enforce_first_as(&mut self, addr: Ipv4Address, on: bool) {
        if let Some(p) = self.peer_mut(addr) {
            p.enforce_first_as = on;
        }
    }

    /// Originates a prefix into BGP, the equivalent of a `network` statement.
    /// `next_hop` is the address advertised to iBGP peers; eBGP advertisements use
    /// the session's own local address instead.
    pub fn originate(&mut self, prefix: Ipv4Prefix, next_hop: Ipv4Address) {
        self.originated.insert(prefix, next_hop);
        self.dirty = true;
    }

    /// Stops originating a prefix. The withdrawal propagates to every peer on the
    /// next poll and the FIB entry, if any, is removed.
    pub fn withdraw_originated(&mut self, prefix: Ipv4Prefix) -> bool {
        let removed = self.originated.remove(&prefix).is_some();
        if removed {
            self.dirty = true;
        }
        removed
    }

    pub fn originated_prefixes(&self) -> Vec<Ipv4Prefix> {
        self.originated.keys().copied().collect()
    }

    /// Administratively shuts a peer down: NOTIFICATION (Cease), TCP teardown, and
    /// removal of everything learned from it.
    pub fn shutdown_peer(&mut self, addr: Ipv4Address, now_ms: u64, sockets: &mut SocketRuntime) {
        let Some(idx) = self.peers.iter().position(|p| p.addr == addr) else {
            return;
        };
        self.peers[idx].admin_up = false;
        self.teardown(
            idx,
            now_ms,
            sockets,
            Teardown::Protocol(
                BgpNotificationMessage::new(BGP_ERR_CEASE, 0),
                "administratively shut down".to_string(),
            ),
        );
        self.peers[idx].connect_retry_deadline = None;
    }

    /// Re-enables a peer that was administratively shut down.
    pub fn enable_peer(&mut self, addr: Ipv4Address) {
        if let Some(p) = self.peer_mut(addr) {
            p.admin_up = true;
            p.connect_retry_deadline = None;
        }
    }

    /// Requests a soft outbound replay from a peer without resetting the TCP/BGP
    /// session. The request is sent only for a negotiated family and only when
    /// both ends advertised the RFC 2918 capability.
    pub fn request_route_refresh(
        &mut self,
        addr: Ipv4Address,
        family: AfiSafi,
        now_ms: u64,
        sockets: &mut SocketRuntime,
    ) -> bool {
        let Some(idx) = self.peers.iter().position(|p| p.addr == addr) else {
            return false;
        };
        let allowed = {
            let peer = &self.peers[idx];
            peer.is_established()
                && peer.negotiated.supports_route_refresh()
                && peer.negotiated.supports(family)
        };
        if !allowed {
            return false;
        }

        let pdu = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(family));
        if !self.send_pdu(idx, sockets, &pdu) {
            return false;
        }
        self.peers[idx].counters.route_refreshes_sent += 1;
        self.log(now_ms, addr, format!("sent ROUTE-REFRESH for {}", family));
        true
    }

    pub fn events(&self) -> &[BgpEvent] {
        &self.events
    }

    fn log(&mut self, now_ms: u64, peer: Ipv4Address, text: impl Into<String>) {
        self.events.push(BgpEvent {
            time_ms: now_ms,
            peer,
            text: text.into(),
        });
        if self.events.len() > MAX_EVENT_LOG {
            let excess = self.events.len() - MAX_EVENT_LOG;
            self.events.drain(..excess);
        }
    }

    // ========================================================================
    // Main pump
    // ========================================================================

    /// Advances the whole control plane one step at simulated time `now_ms`.
    ///
    /// Accepts inbound connections, services every peer's FSM and timers, decodes
    /// whatever the TCP streams delivered, reruns the decision process if anything
    /// changed, syncs the FIB, and emits any UPDATEs the peers are owed.
    pub fn poll(&mut self, now_ms: u64, sockets: &mut SocketRuntime, fib: &mut RoutingTable) {
        self.ensure_listener(now_ms, sockets);
        self.accept_inbound(now_ms, sockets);

        for idx in 0..self.peers.len() {
            self.service_peer(idx, now_ms, sockets);
        }

        self.expire_graceful_restarts(now_ms);

        if self.dirty {
            self.run_decision_process(now_ms);
            self.dirty = false;
        }

        if self.evpn_dirty {
            self.run_evpn_decision_process(now_ms);
            self.evpn_dirty = false;
        }

        // The FIB is reconciled every poll, not only when the RIB changed. A NEXT_HOP
        // that was unresolvable earlier can become resolvable later, and reconciling
        // unconditionally also repairs the table if anything else disturbs it. Entries
        // that already match are left alone, so a steady state costs nothing.
        self.sync_fib(now_ms, fib);

        // Advertisement runs every poll: a peer that has just reached ESTABLISHED
        // needs the full Loc-RIB even when nothing about the RIB itself changed.
        for idx in 0..self.peers.len() {
            self.advertise_to_peer(idx, now_ms, sockets);
            self.advertise_evpn_to_peer(idx, now_ms, sockets);
        }
    }

    fn ensure_listener(&mut self, now_ms: u64, sockets: &mut SocketRuntime) {
        if self.listener.is_some() {
            return;
        }
        match sockets.tcp_listen_any(BGP_PORT) {
            Ok(h) => {
                self.listener = Some(h);
                self.log(
                    now_ms,
                    Ipv4Address::UNSPECIFIED,
                    format!("listening on TCP port {}", BGP_PORT),
                );
            }
            Err(e) => {
                self.log(
                    now_ms,
                    Ipv4Address::UNSPECIFIED,
                    format!("cannot listen on port {}: {}", BGP_PORT, e),
                );
            }
        }
    }

    fn accept_inbound(&mut self, now_ms: u64, sockets: &mut SocketRuntime) {
        let Some(listener) = self.listener else {
            return;
        };
        let retry = self.connect_retry_ms;
        while let Ok((stream, remote)) = sockets.tcp_accept(listener) {
            let Some(idx) = self.peers.iter().position(|p| p.addr == remote.ip) else {
                self.log(
                    now_ms,
                    remote.ip,
                    "refused inbound session from an unconfigured neighbour",
                );
                Self::abandon_stream(sockets, stream, now_ms);
                continue;
            };

            let peer = &mut self.peers[idx];
            if !peer.admin_up {
                self.log(
                    now_ms,
                    remote.ip,
                    "refused inbound session: neighbour is administratively down",
                );
                Self::abandon_stream(sockets, stream, now_ms);
                continue;
            }

            // No transport yet: this is simply the peer calling us.
            if peer.stream.is_none() && matches!(peer.state, BgpState::Idle | BgpState::Active) {
                peer.stream = Some(stream);
                peer.stream_inbound = true;
                peer.framer.reset();
                peer.state = BgpState::Active;
                // Bound the wait: an accepted connection whose handshake never
                // finishes must not hold the peer in Active forever.
                peer.connect_retry_deadline = Some(now_ms + retry);
                self.log(
                    now_ms,
                    remote.ip,
                    "accepted inbound TCP session on port 179",
                );
                continue;
            }

            // A second connection to a neighbour that already has one. RFC 4271
            // section 6.8 resolves this by comparing BGP identifiers, and the
            // peer's identifier is not known until its OPEN arrives - so the
            // connection is held rather than judged now. Refusing it outright,
            // which is what a plain active/passive guard does, throws away the
            // very connection the RFC may require this speaker to keep.
            let state = peer.state;
            let collidable =
                peer.collision.is_none() && state != BgpState::Established && peer.stream.is_some();
            if collidable {
                peer.collision = Some(CollisionConn {
                    stream,
                    framer: BgpFramer::new(),
                });
                self.log(
                    now_ms,
                    remote.ip,
                    format!(
                        "connection collision in {}: holding the inbound connection until the \
                         peer's OPEN says which one survives",
                        state
                    ),
                );
                continue;
            }

            // Established, or already holding one collision candidate. A third
            // connection is not a collision to resolve, it is noise.
            peer.counters.collisions_resolved += 1;
            self.log(
                now_ms,
                remote.ip,
                format!("refused a further inbound session while in {}", state),
            );
            Self::abandon_stream(sockets, stream, now_ms);
        }
    }

    /// Runs the held collision candidate, if there is one.
    ///
    /// Nothing is sent on it. All that is wanted before the decision is the BGP
    /// identifier out of the peer's OPEN, and the peer sends that unprompted the
    /// moment its own TCP connection comes up. The OPEN is read without being
    /// consumed, so that if this connection wins the ordinary FSM still gets to
    /// process it.
    fn service_collision(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        let Some(collision) = self.peers[idx].collision.as_ref() else {
            return;
        };
        let stream = collision.stream;
        let addr = self.peers[idx].addr;

        if !sockets.tcp_is_live(stream) {
            self.peers[idx].collision = None;
            sockets.tcp_abort(stream, now_ms);
            self.log(
                now_ms,
                addr,
                "the colliding connection went away on its own",
            );
            return;
        }

        // Drain into the collision framer.
        let mut buf = [0u8; READ_CHUNK];
        loop {
            match sockets.tcp_read(stream, &mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let Some(c) = self.peers[idx].collision.as_mut() else {
                        return;
                    };
                    if c.framer.push(&buf[..n]).is_err() {
                        self.peers[idx].collision = None;
                        sockets.tcp_abort(stream, now_ms);
                        self.log(now_ms, addr, "the colliding connection was not framing BGP");
                        return;
                    }
                }
                Err(SocketError::WouldBlock) => break,
                Err(_) => break,
            }
        }

        let Some(c) = self.peers[idx].collision.as_ref() else {
            return;
        };
        let peeked = match c.framer.peek_frame() {
            Ok(Some(frame)) => frame.to_vec(),
            Ok(None) => return,
            Err(_) => {
                self.peers[idx].collision = None;
                sockets.tcp_abort(stream, now_ms);
                self.log(
                    now_ms,
                    addr,
                    "the colliding connection sent an unframable message",
                );
                return;
            }
        };
        let remote_id = match BgpPdu::parse_width(&peeked, false) {
            Ok(BgpPdu::Open(open)) => open.bgp_id,
            _ => {
                // Anything other than an OPEN first is a protocol error on a
                // connection this speaker never adopted; drop it.
                self.peers[idx].collision = None;
                sockets.tcp_abort(stream, now_ms);
                self.log(
                    now_ms,
                    addr,
                    "the colliding connection led with something other than an OPEN",
                );
                return;
            }
        };

        self.resolve_collision(idx, now_ms, sockets, remote_id);
    }

    /// Decides which of two connections to a neighbour survives (RFC 4271
    /// section 6.8).
    ///
    /// The rule is stated in terms of who opened what: the speaker with the
    /// *higher* BGP identifier keeps the connection it initiated, and the other
    /// keeps the one it accepted. Both ends applying it to the same pair of
    /// identifiers pick the same connection, which is what makes the outcome a
    /// single session rather than a reconnect loop.
    ///
    /// Two inbound connections are not a real collision - this speaker initiated
    /// neither - so the older one simply keeps its place.
    fn resolve_collision(
        &mut self,
        idx: usize,
        now_ms: u64,
        sockets: &mut SocketRuntime,
        remote_id: Ipv4Address,
    ) {
        let Some(collision) = self.peers[idx].collision.take() else {
            return;
        };
        let addr = self.peers[idx].addr;
        self.peers[idx].counters.collisions_resolved += 1;

        // The held connection is inbound by construction; keep the peer-initiated
        // one only when our identifier is the lower of the two.
        let keep_inbound = !self.peers[idx].stream_inbound && self.router_id < remote_id;

        if !keep_inbound {
            sockets.tcp_abort(collision.stream, now_ms);
            self.log(
                now_ms,
                addr,
                format!(
                    "collision resolved: keeping our connection (local id {} vs remote {})",
                    self.router_id, remote_id
                ),
            );
            return;
        }

        // The inbound connection wins. Drop ours and adopt theirs, framer and all,
        // with the OPEN still unread: the FSM restarts on it from Active and will
        // send our own OPEN and then process the buffered one exactly as it would
        // on any freshly accepted connection.
        if let Some(old) = self.peers[idx].stream.take() {
            sockets.tcp_abort(old, now_ms);
        }
        let peer = &mut self.peers[idx];
        peer.stream = Some(collision.stream);
        peer.stream_inbound = true;
        peer.framer = collision.framer;
        peer.state = BgpState::Active;
        peer.hold_deadline = None;
        peer.keepalive_deadline = None;
        peer.negotiated = NegotiatedCapabilities::default();
        peer.connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
        self.log(
            now_ms,
            addr,
            format!(
                "collision resolved: adopting the peer's connection (local id {} vs remote {})",
                self.router_id, remote_id
            ),
        );
    }

    /// Drops a connection this speaker will not use: an inbound session from an
    /// unconfigured neighbour, or one that collides with a session already in progress.
    fn abandon_stream(sockets: &mut SocketRuntime, stream: TcpStreamHandle, now_ms: u64) {
        sockets.tcp_abort(stream, now_ms);
    }

    // ========================================================================
    // Per-peer FSM
    // ========================================================================

    fn service_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        if !self.peers[idx].admin_up {
            if self.peers[idx].state != BgpState::Idle {
                self.teardown(
                    idx,
                    now_ms,
                    sockets,
                    Teardown::Transport("administratively down".to_string()),
                );
            }
            return;
        }

        // A half-written message means the peer's framer is about to lose sync with
        // us. Nothing can be salvaged by writing more, so reset the session.
        if self.peers[idx].tx_desynced {
            self.teardown(
                idx,
                now_ms,
                sockets,
                Teardown::Transport(
                    "a BGP message was only partially written; the stream is desynchronised"
                        .to_string(),
                ),
            );
            return;
        }

        // Resolve any collision before the FSM runs, so the state machine only
        // ever sees the one connection that survived.
        if self.peers[idx].collision.is_some() {
            self.service_collision(idx, now_ms, sockets);
        }

        // A dead transport ends the session from any state that owns one.
        if let Some(stream) = self.peers[idx].stream
            && !sockets.tcp_is_live(stream)
        {
            self.teardown(
                idx,
                now_ms,
                sockets,
                Teardown::Transport("TCP connection failed".to_string()),
            );
            return;
        }

        match self.peers[idx].state {
            BgpState::Idle => self.start_peer(idx, now_ms, sockets),
            BgpState::Connect | BgpState::Active => self.progress_transport(idx, now_ms, sockets),
            BgpState::OpenSent | BgpState::OpenConfirm | BgpState::Established => {
                self.run_session(idx, now_ms, sockets)
            }
        }
    }

    /// Idle -> Connect (we dial) or Idle -> Active (we wait), once the
    /// ConnectRetryTimer allows another attempt.
    fn start_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        let ready = self.peers[idx]
            .connect_retry_deadline
            .is_none_or(|d| now_ms >= d);
        if !ready {
            return;
        }

        match self.peers[idx].mode {
            BgpPeerMode::Passive => {
                self.peers[idx].state = BgpState::Active;
                self.peers[idx].connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
                self.log(now_ms, self.peers[idx].addr, "Idle -> Active (passive)");
            }
            BgpPeerMode::Active => self.dial(idx, now_ms, sockets),
        }
    }

    fn dial(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        let peer_addr = self.peers[idx].addr;
        let local = SocketAddrV4 {
            ip: self.peers[idx].local_addr,
            port: 0,
        };
        let remote = SocketAddrV4 {
            ip: peer_addr,
            port: BGP_PORT,
        };
        let isn = 1_000 + (now_ms % 100_000) as u32 * 7;
        match sockets.tcp_connect_from(local, remote, isn) {
            Ok(stream) => {
                self.peers[idx].stream = Some(stream);
                self.peers[idx].stream_inbound = false;
                self.peers[idx].framer.reset();
                self.peers[idx].state = BgpState::Connect;
                self.peers[idx].connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
                self.log(now_ms, peer_addr, "Idle -> Connect (TCP SYN sent to :179)");
            }
            Err(e) => {
                self.peers[idx].state = BgpState::Active;
                self.peers[idx].connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
                self.peers[idx].last_error = Some(format!("connect failed: {}", e));
                self.log(now_ms, peer_addr, format!("TCP connect failed: {}", e));
            }
        }
    }

    /// Connect / Active: waiting for the three-way handshake to complete, either the
    /// one we started or the one the peer started.
    fn progress_transport(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        if let Some(stream) = self.peers[idx].stream {
            if sockets.tcp_state(stream) == Ok(TcpState::Established) {
                self.send_open(idx, now_ms, sockets);
                return;
            }
            // Handshake still in flight; the ConnectRetryTimer bounds how long we wait.
            if self.peers[idx]
                .connect_retry_deadline
                .is_some_and(|d| now_ms >= d)
            {
                self.teardown(
                    idx,
                    now_ms,
                    sockets,
                    Teardown::Transport("ConnectRetryTimer expired during handshake".to_string()),
                );
            }
            return;
        }

        // No transport yet.
        if self.peers[idx].mode == BgpPeerMode::Active
            && self.peers[idx]
                .connect_retry_deadline
                .is_none_or(|d| now_ms >= d)
        {
            self.dial(idx, now_ms, sockets);
        } else if self.peers[idx]
            .connect_retry_deadline
            .is_some_and(|d| now_ms >= d)
        {
            // Passive: just re-arm and keep waiting for the peer to call.
            self.peers[idx].connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
        }
    }

    fn send_open(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        let caps = self.local_capabilities();
        let open =
            BgpOpenMessage::with_capabilities(self.local_as, self.hold_time, self.router_id, &caps);
        if !self.send_pdu(idx, sockets, &BgpPdu::Open(open)) {
            return;
        }
        self.peers[idx].counters.opens_sent += 1;
        self.peers[idx].state = BgpState::OpenSent;
        self.peers[idx].connect_retry_deadline = None;
        self.peers[idx].hold_deadline = Some(now_ms + INITIAL_HOLD_MS);
        let addr = self.peers[idx].addr;
        self.log(
            now_ms,
            addr,
            format!(
                "TCP established -> OPEN sent (AS {}, capabilities: {}) (OpenSent)",
                self.local_as, caps
            ),
        );
    }

    /// The capability set this speaker puts in every OPEN.
    ///
    /// The Four-Octet AS capability is unconditional: a speaker that supports
    /// 32-bit ASNs advertises so even when its own ASN happens to be small, which
    /// is what lets the *session* use the wide AS_PATH encoding for a path that
    /// transited a 32-bit AS elsewhere.
    pub fn local_capabilities(&self) -> BgpCapabilitySet {
        let mut caps = BgpCapabilitySet::new();
        for family in &self.families {
            caps.advertise(*family);
        }
        caps.push(BgpCapability::FourOctetAs(self.local_as));
        caps.push(BgpCapability::RouteRefresh);
        if self.graceful_restart_enabled {
            caps.push(BgpCapability::GracefulRestart(
                BgpGracefulRestartCapability::new(
                    self.graceful_restart_time,
                    false,
                    self.families
                        .iter()
                        .copied()
                        .map(|family| BgpGracefulRestartFamily::new(family, false))
                        .collect(),
                ),
            ));
        }
        caps
    }

    /// Address families this speaker will advertise in OPEN. IPv4 Unicast is
    /// always present; EVPN is added by [`BgpRouter::enable_family`].
    pub fn families(&self) -> Vec<AfiSafi> {
        self.families.iter().copied().collect()
    }

    /// Adds an address family to what this speaker offers in OPEN.
    ///
    /// This only changes what is *offered*. Whether a given session actually
    /// carries the family still depends on the neighbour offering it too.
    pub fn enable_family(&mut self, family: AfiSafi) {
        self.families.insert(family);
    }

    /// OpenSent / OpenConfirm / Established: read the stream, decode complete
    /// messages, then run the hold and keepalive timers.
    fn run_session(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        // 1. Drain whatever TCP has delivered into the reassembly buffer. A stream
        //    that has already ended still hands back everything delivered before the
        //    FIN, so end-of-stream is remembered rather than acted on straight away.
        let eof = match self.read_stream(idx, sockets) {
            Ok(open) => !open,
            Err(e) => {
                let note = BgpNotificationMessage::new(e.code, e.subcode);
                self.teardown(
                    idx,
                    now_ms,
                    sockets,
                    Teardown::Protocol(note, format!("framing error: {}", e)),
                );
                return;
            }
        };

        // 2. Decode and handle every complete message currently buffered. This runs
        //    even once the stream has ended: a peer that sends a final NOTIFICATION
        //    and closes in the same breath delivers both in a single read, and the
        //    NOTIFICATION is the real reason the session is going down. Reporting
        //    "peer closed the TCP connection" instead would throw that away.
        loop {
            let frame = match self.peers[idx].framer.next_frame() {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(e) => {
                    let note = BgpNotificationMessage::new(e.code, e.subcode);
                    self.teardown(
                        idx,
                        now_ms,
                        sockets,
                        Teardown::Protocol(note, format!("framing error: {}", e)),
                    );
                    return;
                }
            };

            // The AS_PATH ASN width is not visible in the message; it is whatever
            // the two OPENs agreed to, so the session state has to supply it.
            let four_octet = self.peers[idx].negotiated.four_octet_as;
            let pdu = match BgpPdu::parse_width(&frame, four_octet) {
                Ok(p) => p,
                Err(e) => {
                    let note = BgpNotificationMessage::new(e.code, e.subcode);
                    self.teardown(
                        idx,
                        now_ms,
                        sockets,
                        Teardown::Protocol(note, format!("decode error: {}", e)),
                    );
                    return;
                }
            };

            if let Some(t) = self.handle_pdu(idx, now_ms, sockets, pdu) {
                self.teardown(idx, now_ms, sockets, t);
                return;
            }
        }

        // 3. The peer closed, and everything it said beforehand has now been acted on.
        if eof {
            self.teardown(
                idx,
                now_ms,
                sockets,
                Teardown::Transport("peer closed the TCP connection".to_string()),
            );
            return;
        }

        // 4. Timers.
        self.run_timers(idx, now_ms, sockets);
    }

    /// Reads everything available. Returns `Ok(false)` at end of stream.
    fn read_stream(
        &mut self,
        idx: usize,
        sockets: &mut SocketRuntime,
    ) -> Result<bool, BgpParseError> {
        let Some(stream) = self.peers[idx].stream else {
            return Ok(false);
        };
        let mut buf = [0u8; READ_CHUNK];
        loop {
            match sockets.tcp_read(stream, &mut buf) {
                Ok(0) => return Ok(false),
                Ok(n) => self.peers[idx].framer.push(&buf[..n])?,
                Err(SocketError::WouldBlock) => return Ok(true),
                Err(_) => return Ok(false),
            }
        }
    }

    /// Dispatches one decoded message according to the current FSM state.
    /// Returns `Some(Teardown)` when the session must end.
    fn handle_pdu(
        &mut self,
        idx: usize,
        now_ms: u64,
        sockets: &mut SocketRuntime,
        pdu: BgpPdu,
    ) -> Option<Teardown> {
        let state = self.peers[idx].state;
        let addr = self.peers[idx].addr;

        // Any message from the peer proves the session is alive.
        if state == BgpState::Established || state == BgpState::OpenConfirm {
            self.arm_hold_timer(idx, now_ms);
        }

        match (state, pdu) {
            (BgpState::OpenSent, BgpPdu::Open(open)) => {
                self.peers[idx].counters.opens_received += 1;
                let peer_caps = match open.capabilities() {
                    Ok(c) => c,
                    Err(e) => {
                        return Some(Teardown::Protocol(
                            BgpNotificationMessage::new(
                                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                                e.subcode,
                            ),
                            format!("malformed OPEN capabilities: {}", e),
                        ));
                    }
                };
                if let Err(note) = self.validate_open(idx, &open, &peer_caps) {
                    let reason = format!(
                        "rejected OPEN: code {}/{}",
                        note.error_code, note.error_subcode
                    );
                    return Some(Teardown::Protocol(note, reason));
                }
                let capabilities = negotiate(&self.local_capabilities(), &peer_caps);
                let families: Vec<String> =
                    capabilities.families.iter().map(|f| f.name()).collect();
                self.log(
                    now_ms,
                    addr,
                    format!(
                        "capability negotiation: families [{}], 4-octet ASN {}, route refresh {}, graceful restart {}",
                        families.join(", "),
                        if capabilities.four_octet_as {
                            "yes"
                        } else {
                            "no"
                        },
                        if capabilities.route_refresh { "yes" } else { "no" },
                        if peer_caps.supports_graceful_restart() && self.graceful_restart_enabled {
                            "yes"
                        } else {
                            "no"
                        }
                    ),
                );
                self.reconcile_graceful_restart_open(idx, now_ms, &capabilities, &peer_caps);
                self.peers[idx].negotiated = capabilities;
                let negotiated = self.hold_time.min(open.hold_time);
                self.peers[idx].remote_router_id = Some(open.bgp_id);
                self.peers[idx].negotiated_hold_ms = negotiated as u64 * 1_000;
                self.peers[idx].keepalive_interval_ms = if negotiated == 0 {
                    0
                } else {
                    (negotiated as u64 * 1_000) / 3
                };
                if !self.send_pdu(idx, sockets, &BgpPdu::Keepalive) {
                    return Some(Teardown::Transport(
                        "could not send KEEPALIVE after OPEN".to_string(),
                    ));
                }
                self.peers[idx].counters.keepalives_sent += 1;
                self.peers[idx].state = BgpState::OpenConfirm;
                self.arm_hold_timer(idx, now_ms);
                self.arm_keepalive_timer(idx, now_ms);
                self.log(
                    now_ms,
                    addr,
                    format!(
                        "OPEN received (AS {}, id {}, hold {}s) -> negotiated hold {}s, OpenConfirm",
                        open.my_as, open.bgp_id, open.hold_time, negotiated
                    ),
                );
                None
            }

            (BgpState::OpenConfirm, BgpPdu::Keepalive) => {
                self.peers[idx].counters.keepalives_received += 1;
                self.peers[idx].state = BgpState::Established;
                self.peers[idx].established_since_ms = Some(now_ms);
                self.peers[idx].establishment_count += 1;
                self.peers[idx].last_error = None;
                self.dirty = true;
                self.log(now_ms, addr, "KEEPALIVE received -> ESTABLISHED");
                None
            }

            (BgpState::Established, BgpPdu::Keepalive) => {
                self.peers[idx].counters.keepalives_received += 1;
                None
            }

            (BgpState::Established, BgpPdu::Update(update)) => {
                self.peers[idx].counters.updates_received += 1;
                let ipv4_eor = update.is_end_of_rib();
                let evpn_eor = update
                    .mp_unreach()
                    .is_some_and(|m| m.family() == AfiSafi::L2VPN_EVPN && m.nlri.is_empty());
                if let Err(t) = self.import_mp_update(idx, now_ms, &update) {
                    return Some(t);
                }
                match self.import_update(idx, now_ms, update) {
                    Ok(()) => {
                        if ipv4_eor {
                            self.complete_graceful_restart_family(
                                idx,
                                AfiSafi::IPV4_UNICAST,
                                now_ms,
                            );
                        }
                        if evpn_eor {
                            self.complete_graceful_restart_family(
                                idx,
                                AfiSafi::L2VPN_EVPN,
                                now_ms,
                            );
                        }
                        None
                    }
                    Err(note) => {
                        let reason = format!(
                            "rejected UPDATE: code {}/{}",
                            note.error_code, note.error_subcode
                        );
                        Some(Teardown::Protocol(note, reason))
                    }
                }
            }

            (BgpState::Established, BgpPdu::RouteRefresh(refresh)) => {
                if !self.peers[idx].negotiated.supports_route_refresh() {
                    self.log(
                        now_ms,
                        addr,
                        format!(
                            "ignored ROUTE-REFRESH for {}: capability was not negotiated",
                            refresh.family
                        ),
                    );
                    return None;
                }
                if !self.peers[idx].negotiated.supports(refresh.family) {
                    self.log(
                        now_ms,
                        addr,
                        format!(
                            "ignored ROUTE-REFRESH for {}: family was not negotiated",
                            refresh.family
                        ),
                    );
                    return None;
                }
                self.peers[idx].counters.route_refreshes_received += 1;
                self.peers[idx].refresh_pending.insert(refresh.family);
                self.log(
                    now_ms,
                    addr,
                    format!("received ROUTE-REFRESH for {}; scheduling replay", refresh.family),
                );
                None
            }

            (_, BgpPdu::Notification(note)) => {
                self.peers[idx].counters.notifications_received += 1;
                Some(Teardown::PeerNotification(format!(
                    "peer sent NOTIFICATION: {}",
                    note.describe()
                )))
            }

            // Anything else is a finite state machine error (RFC 4271 section 6.5).
            (state, pdu) => {
                let reason = format!("{} is not valid in state {}", pdu.type_name(), state);
                Some(Teardown::Protocol(
                    BgpNotificationMessage::new(BGP_ERR_FSM, 0),
                    reason,
                ))
            }
        }
    }

    /// Validates a peer's OPEN against RFC 4271 section 6.2 and RFC 6793.
    fn validate_open(
        &self,
        idx: usize,
        open: &BgpOpenMessage,
        peer_caps: &BgpCapabilitySet,
    ) -> Result<(), BgpNotificationMessage> {
        if open.version != BGP_VERSION {
            let mut note = BgpNotificationMessage::new(
                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                BGP_SUB_UNSUPPORTED_VERSION,
            );
            note.data = (BGP_VERSION as u16).to_be_bytes().to_vec();
            return Err(note);
        }
        // The configured neighbour ASN is compared against what the peer really
        // claims, which for a 32-bit AS is the capability rather than the
        // two-octet field. Comparing the field alone would accept any 32-bit
        // neighbour at all, because every one of them writes AS_TRANS there.
        if open.effective_as(peer_caps) != self.peers[idx].remote_as {
            return Err(BgpNotificationMessage::new(
                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                BGP_SUB_BAD_PEER_AS,
            ));
        }
        // A peer whose ASN does not fit two octets must have said so in the
        // capability; otherwise the two fields contradict each other and there is
        // no honest way to read the AS_PATH that follows.
        if self.peers[idx].remote_as > u16::MAX as u32 && !peer_caps.supports_four_octet_as() {
            return Err(BgpNotificationMessage::new(
                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                BGP_SUB_UNSUPPORTED_CAPABILITY,
            ));
        }
        // A BGP identifier must be a valid unicast host address and must differ from ours.
        if open.bgp_id.is_unspecified()
            || open.bgp_id.is_multicast()
            || open.bgp_id.is_broadcast()
            || open.bgp_id == self.router_id
        {
            return Err(BgpNotificationMessage::new(
                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                BGP_SUB_BAD_BGP_IDENTIFIER,
            ));
        }
        if open.hold_time != 0 && open.hold_time < BGP_MIN_HOLD_TIME {
            return Err(BgpNotificationMessage::new(
                crate::bgp::BGP_ERR_OPEN_MESSAGE,
                BGP_SUB_UNACCEPTABLE_HOLD_TIME,
            ));
        }
        Ok(())
    }

    fn arm_hold_timer(&mut self, idx: usize, now_ms: u64) {
        let hold = self.peers[idx].negotiated_hold_ms;
        self.peers[idx].hold_deadline = if hold == 0 { None } else { Some(now_ms + hold) };
    }

    fn arm_keepalive_timer(&mut self, idx: usize, now_ms: u64) {
        let interval = self.peers[idx].keepalive_interval_ms;
        self.peers[idx].keepalive_deadline = if interval == 0 {
            None
        } else {
            Some(now_ms + interval)
        };
    }

    fn run_timers(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        // HoldTimer: no message from the peer within the negotiated hold time.
        if self.peers[idx].hold_deadline.is_some_and(|d| now_ms >= d) {
            let note = BgpNotificationMessage::new(BGP_ERR_HOLD_TIMER_EXPIRED, 0);
            self.teardown(
                idx,
                now_ms,
                sockets,
                Teardown::Protocol(note, "HoldTimer expired".to_string()),
            );
            return;
        }

        // KeepaliveTimer: only meaningful once the session carries traffic.
        if matches!(
            self.peers[idx].state,
            BgpState::OpenConfirm | BgpState::Established
        ) && self.peers[idx]
            .keepalive_deadline
            .is_some_and(|d| now_ms >= d)
        {
            if self.send_pdu(idx, sockets, &BgpPdu::Keepalive) {
                self.peers[idx].counters.keepalives_sent += 1;
            }
            self.arm_keepalive_timer(idx, now_ms);
        }
    }

    fn route_is_graceful_restart_stale(
        &self,
        peer_addr: Ipv4Address,
        family: AfiSafi,
        received_at_ms: u64,
    ) -> bool {
        let Some(peer) = self.peer(peer_addr) else {
            return false;
        };
        if !peer.graceful_restart_stale.contains(&family) {
            return false;
        }
        peer.graceful_restart_refresh_started_ms
            .is_none_or(|cutoff| received_at_ms < cutoff)
    }

    fn purge_graceful_restart_stale_family(&mut self, idx: usize, family: AfiSafi) -> usize {
        let addr = self.peers[idx].addr;
        let cutoff = self.peers[idx].graceful_restart_refresh_started_ms;
        match family {
            AfiSafi::IPV4_UNICAST => {
                let stale: Vec<Ipv4Prefix> = self
                    .adj_rib_in
                    .peer_table(addr)
                    .into_iter()
                    .flat_map(|table| table.iter())
                    .filter(|(_, path)| cutoff.is_none_or(|t| path.received_at_ms < t))
                    .map(|(prefix, _)| *prefix)
                    .collect();
                for prefix in &stale {
                    self.adj_rib_in.remove(addr, *prefix);
                }
                if !stale.is_empty() {
                    self.dirty = true;
                }
                stale.len()
            }
            AfiSafi::L2VPN_EVPN => {
                let stale: Vec<EvpnRouteKey> = self
                    .evpn_adj_rib_in
                    .peer_table(addr)
                    .into_iter()
                    .flat_map(|table| table.iter())
                    .filter(|(_, path)| cutoff.is_none_or(|t| path.received_at_ms < t))
                    .map(|(key, _)| key.clone())
                    .collect();
                for key in &stale {
                    self.evpn_adj_rib_in.remove(addr, key);
                }
                if !stale.is_empty() {
                    self.evpn_dirty = true;
                }
                stale.len()
            }
            _ => 0,
        }
    }

    fn complete_graceful_restart_family(
        &mut self,
        idx: usize,
        family: AfiSafi,
        now_ms: u64,
    ) {
        if !self.peers[idx].graceful_restart_stale.contains(&family) {
            return;
        }
        let addr = self.peers[idx].addr;
        let purged = self.purge_graceful_restart_stale_family(idx, family);
        self.peers[idx].graceful_restart_stale.remove(&family);
        self.peers[idx].counters.graceful_restart_eors += 1;
        if self.peers[idx].graceful_restart_stale.is_empty() {
            self.peers[idx].graceful_restart_deadline = None;
            self.peers[idx].graceful_restart_refresh_started_ms = None;
        }
        self.log(
            now_ms,
            addr,
            format!(
                "Graceful Restart EOR for {}; removed {} stale route(s)",
                family, purged
            ),
        );
    }

    fn flush_graceful_restart(&mut self, idx: usize, now_ms: u64, reason: &str) {
        let addr = self.peers[idx].addr;
        let families: Vec<AfiSafi> = self.peers[idx]
            .graceful_restart_stale
            .iter()
            .copied()
            .collect();
        let mut purged = 0usize;
        for family in families {
            purged += self.purge_graceful_restart_stale_family(idx, family);
        }
        self.peers[idx].graceful_restart_stale.clear();
        self.peers[idx].graceful_restart_deadline = None;
        self.peers[idx].graceful_restart_refresh_started_ms = None;
        self.log(
            now_ms,
            addr,
            format!("Graceful Restart ended: {}; purged {} stale route(s)", reason, purged),
        );
    }

    fn reconcile_graceful_restart_open(
        &mut self,
        idx: usize,
        now_ms: u64,
        negotiated: &NegotiatedCapabilities,
        peer_caps: &BgpCapabilitySet,
    ) {
        if !self.peers[idx].graceful_restart_active() {
            return;
        }
        let Some(gr) = peer_caps.graceful_restart() else {
            self.flush_graceful_restart(idx, now_ms, "peer reconnected without RFC 4724");
            return;
        };
        if !gr.restarting {
            self.flush_graceful_restart(idx, now_ms, "peer did not set Restart State");
            return;
        }

        let supported: BTreeSet<AfiSafi> = gr
            .families
            .iter()
            .map(|f| f.family)
            .filter(|family| negotiated.supports(*family))
            .collect();
        let dropped: Vec<AfiSafi> = self.peers[idx]
            .graceful_restart_stale
            .difference(&supported)
            .copied()
            .collect();
        for family in dropped {
            self.purge_graceful_restart_stale_family(idx, family);
            self.peers[idx].graceful_restart_stale.remove(&family);
        }
        self.peers[idx].graceful_restart_refresh_started_ms = Some(now_ms);
        if self.peers[idx].graceful_restart_stale.is_empty() {
            self.peers[idx].graceful_restart_deadline = None;
            self.peers[idx].graceful_restart_refresh_started_ms = None;
        } else {
            self.log(now_ms, self.peers[idx].addr, "peer signalled RFC 4724 Restart State; waiting for End-of-RIB");
        }
    }

    fn expire_graceful_restarts(&mut self, now_ms: u64) {
        let expired: Vec<usize> = self
            .peers
            .iter()
            .enumerate()
            .filter(|(_, peer)| peer.graceful_restart_deadline.is_some_and(|d| now_ms >= d))
            .map(|(idx, _)| idx)
            .collect();
        for idx in expired {
            self.peers[idx].counters.graceful_restart_expirations += 1;
            self.flush_graceful_restart(idx, now_ms, "Restart Time expired");
        }
    }

    /// Writes a message, but only if the send buffer can take all of it: a BGP
    /// message must never be split across a partial write.
    fn send_pdu(&mut self, idx: usize, sockets: &mut SocketRuntime, pdu: &BgpPdu) -> bool {
        let Some(stream) = self.peers[idx].stream else {
            return false;
        };
        let bytes = pdu.serialize();
        // Checking capacity first lets the caller retry the whole message later. The
        // alternative - writing a prefix now and the whole message again next time -
        // would put one header on the wire twice and desynchronise the peer.
        if sockets.tcp_writable(stream) < bytes.len() {
            return false;
        }
        match sockets.tcp_write(stream, &bytes) {
            Ok(n) if n == bytes.len() => true,
            Ok(_) => {
                // Unreachable while the capacity check above holds, but if it ever did
                // happen the stream would already carry half a message, and no retry
                // could repair it. Flag it so the session is reset instead.
                self.peers[idx].tx_desynced = true;
                false
            }
            Err(_) => false,
        }
    }

    /// Ends a session. RFC 4724 changes one important part of the ordinary
    /// teardown: an unexpected transport loss from a GR-capable established peer
    /// retains negotiated-family routes until its Restart Time expires. Protocol
    /// errors, NOTIFICATIONs, and administrative shutdowns still purge immediately.
    fn teardown(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime, why: Teardown) {
        let addr = self.peers[idx].addr;
        let transport_failure = matches!(&why, Teardown::Transport(_));
        let was_established = self.peers[idx].state == BgpState::Established;
        let already_restarting = self.peers[idx].graceful_restart_active();
        let reason = match &why {
            Teardown::Transport(r) => r.clone(),
            Teardown::Protocol(_, r) => r.clone(),
            Teardown::PeerNotification(r) => r.clone(),
        };

        if let Teardown::Protocol(note, _) = &why
            && self.peers[idx].stream.is_some()
            && self.send_pdu(idx, sockets, &BgpPdu::Notification(note.clone()))
        {
            self.peers[idx].counters.notifications_sent += 1;
        }

        if let Some(stream) = self.peers[idx].stream.take() {
            sockets.tcp_abort(stream, now_ms);
        }
        if let Some(collision) = self.peers[idx].collision.take() {
            sockets.tcp_abort(collision.stream, now_ms);
        }

        let mut preserve = BTreeSet::new();
        let mut deadline = None;
        let mut refresh_started = None;
        if transport_failure && already_restarting {
            preserve = self.peers[idx].graceful_restart_stale.clone();
            deadline = self.peers[idx].graceful_restart_deadline;
            refresh_started = self.peers[idx].graceful_restart_refresh_started_ms;
        } else if transport_failure && was_established && self.graceful_restart_enabled {
            if let Some(gr) = self.peers[idx].negotiated.peer.graceful_restart()
                && gr.restart_time > 0
            {
                preserve = gr
                    .families
                    .iter()
                    .map(|f| f.family)
                    .filter(|family| self.peers[idx].negotiated.supports(*family))
                    .filter(|family| {
                        *family == AfiSafi::IPV4_UNICAST || *family == AfiSafi::L2VPN_EVPN
                    })
                    .collect();
                if !preserve.is_empty() {
                    deadline = Some(now_ms + gr.restart_time as u64 * 1_000);
                }
            }
        }

        let preserve_ipv4 = preserve.contains(&AfiSafi::IPV4_UNICAST);
        let preserve_evpn = preserve.contains(&AfiSafi::L2VPN_EVPN);
        let purged = if preserve_ipv4 {
            0
        } else {
            self.adj_rib_in.clear_peer(addr)
        };
        self.adj_rib_out.clear_peer(addr);
        let evpn_purged = if preserve_evpn {
            0
        } else {
            self.evpn_adj_rib_in.clear_peer(addr)
        };
        self.evpn_adj_rib_out.clear_peer(addr);
        if evpn_purged > 0 {
            self.evpn_dirty = true;
        }

        let started_new_gr = !already_restarting && !preserve.is_empty();
        let peer = &mut self.peers[idx];
        peer.framer.reset();
        peer.state = BgpState::Idle;
        peer.stream_inbound = false;
        peer.hold_deadline = None;
        peer.keepalive_deadline = None;
        peer.negotiated_hold_ms = 0;
        peer.keepalive_interval_ms = 0;
        peer.negotiated = NegotiatedCapabilities::default();
        peer.refresh_pending.clear();
        peer.remote_router_id = None;
        peer.established_since_ms = None;
        peer.tx_desynced = false;
        peer.last_error = Some(reason.clone());
        peer.connect_retry_deadline = Some(now_ms + self.connect_retry_ms);
        peer.graceful_restart_stale = preserve.clone();
        peer.graceful_restart_deadline = deadline;
        peer.graceful_restart_refresh_started_ms = refresh_started;
        if started_new_gr {
            peer.counters.graceful_restarts_started += 1;
        }

        self.dirty = true;
        if preserve.is_empty() {
            self.log(
                now_ms,
                addr,
                format!(
                    "session down ({}); purged {} learned path(s) and {} EVPN route(s)",
                    reason, purged, evpn_purged
                ),
            );
        } else {
            self.log(
                now_ms,
                addr,
                format!(
                    "session down ({}); Graceful Restart retaining {} family/families until {}ms",
                    reason,
                    preserve.len(),
                    deadline.unwrap_or(now_ms)
                ),
            );
        }
    }

    // ========================================================================
    // Import
    // ========================================================================

    /// The RFC 4456 section 7 loop checks, applied to any received path.
    ///
    /// Returns the reason a reflected route must be discarded, or `None` when it
    /// is acceptable. Two independent tests, because they catch different things:
    ///
    /// * ORIGINATOR_ID equal to our own identifier means this speaker originated
    ///   the route and a reflector has handed it back. That is a loop even in a
    ///   cluster this speaker does not belong to.
    /// * Our own cluster ID in CLUSTER_LIST means the route has already been
    ///   reflected by this cluster, which is the case the attribute exists for
    ///   and the one that stops a route circling between two reflectors.
    ///
    /// Neither is a protocol violation - the sender did nothing wrong, the
    /// topology simply brought the route back - so the route is dropped and the
    /// session is left alone.
    fn reflection_loop(
        &self,
        originator_id: Option<Ipv4Address>,
        cluster_list: &[Ipv4Address],
    ) -> Option<ReflectionLoop> {
        if originator_id == Some(self.router_id) {
            return Some(ReflectionLoop::Originator);
        }
        if cluster_list.contains(&self.cluster_id()) {
            return Some(ReflectionLoop::Cluster);
        }
        None
    }

    /// Applies one received UPDATE to the Adj-RIB-In for this peer.
    ///
    /// Structural problems already caused a decode error before we got here. What is
    /// checked now is semantics: AS loops, usable NEXT_HOPs, and import policy. A route
    /// that fails those is discarded (it is not a protocol violation), whereas a NEXT_HOP
    /// that cannot be a host address is an UPDATE error and resets the session.
    fn import_update(
        &mut self,
        idx: usize,
        now_ms: u64,
        update: BgpUpdateMessage,
    ) -> Result<(), BgpNotificationMessage> {
        let addr = self.peers[idx].addr;

        for prefix in &update.withdrawn {
            if self.adj_rib_in.remove(addr, *prefix).is_some() {
                self.dirty = true;
                self.log(now_ms, addr, format!("withdrew {} from Adj-RIB-In", prefix));
            }
        }

        let Some(attrs) = update.attributes else {
            return Ok(());
        };
        if update.nlri.is_empty() {
            return Ok(());
        }

        // A NEXT_HOP that cannot be a unicast host address is an UPDATE error.
        if attrs.next_hop.is_unspecified()
            || attrs.next_hop.is_loopback()
            || attrs.next_hop.is_multicast()
            || attrs.next_hop.is_broadcast()
        {
            return Err(BgpNotificationMessage::new(
                BGP_ERR_UPDATE_MESSAGE,
                BGP_SUB_INVALID_NEXT_HOP,
            ));
        }

        let is_ebgp = self.peers[idx].remote_as != self.local_as;
        let peer_as = self.peers[idx].remote_as;

        // An UPDATE from an external peer has to say something truthful about where it
        // came from (RFC 4271 sections 6.3 and 9.1.2). Two separate rules:
        //
        //  * The AS_PATH must not be empty. This one is unconditional. A zero-length
        //    path wins step 2 of the decision process against every legitimate route,
        //    so a neighbour able to send one could take over any prefix it liked.
        //  * The path must lead with the neighbour's own ASN. This is the check
        //    vendors call "enforce-first-as"; it stops a peer disowning a path it is
        //    in fact carrying. It can be turned off per peer, the empty test cannot.
        //
        // Neither rule applies to an internal peer: an iBGP neighbour legitimately
        // passes on a path it did not originate, and a route originated inside this AS
        // carries an empty AS_PATH until it leaves.
        if is_ebgp {
            let refusal = if attrs.as_path.is_empty() {
                Some("AS_PATH is empty".to_string())
            } else if !self.peers[idx].enforce_first_as {
                None
            } else {
                match attrs.as_path.leading_as() {
                    Some(a) if a == peer_as => None,
                    Some(a) => Some(format!(
                        "AS_PATH [{}] leads with AS {}, not the neighbour's AS {}",
                        attrs.as_path, a, peer_as
                    )),
                    None => Some(format!(
                        "AS_PATH [{}] does not begin with an AS_SEQUENCE",
                        attrs.as_path
                    )),
                }
            };
            if let Some(reason) = refusal {
                self.peers[idx].counters.as_path_rejected += 1;
                self.log(now_ms, addr, format!("UPDATE refused: {}", reason));
                return Err(BgpNotificationMessage::new(
                    BGP_ERR_UPDATE_MESSAGE,
                    BGP_SUB_MALFORMED_AS_PATH,
                ));
            }
        }

        // Reflection loop: the route has been through this speaker, or through
        // this cluster, and has come back. The AS_PATH cannot catch this, because
        // reflection happens entirely inside one AS and never touches it.
        if let Some(loop_kind) = self.reflection_loop(attrs.originator_id, &attrs.cluster_list) {
            let n = update.nlri.len() as u64;
            let detail = match loop_kind {
                ReflectionLoop::Originator => {
                    self.peers[idx].counters.originator_loops_rejected += n;
                    format!("ORIGINATOR_ID is our own BGP identifier {}", self.router_id)
                }
                ReflectionLoop::Cluster => {
                    self.peers[idx].counters.cluster_loops_rejected += n;
                    format!(
                        "CLUSTER_LIST already contains cluster {}",
                        self.cluster_id()
                    )
                }
            };
            self.log(
                now_ms,
                addr,
                format!("rejected {} reflected prefix(es): {}", n, detail),
            );
            return Ok(());
        }

        // AS loop: our own ASN already appears in the path, so the route has been
        // through this AS and must not be re-accepted (RFC 4271 section 9.1.2).
        if attrs.as_path.contains(self.local_as) {
            self.peers[idx].counters.as_loops_rejected += update.nlri.len() as u64;
            self.log(
                now_ms,
                addr,
                format!(
                    "rejected {} prefix(es): AS_PATH [{}] already contains AS {}",
                    update.nlri.len(),
                    attrs.as_path,
                    self.local_as
                ),
            );
            return Ok(());
        }

        let source = if is_ebgp {
            PathSource::Ebgp
        } else {
            PathSource::Ibgp
        };
        // A route learned over eBGP whose NEXT_HOP is our own session address would
        // point straight back at us; refuse it rather than build a forwarding loop.
        let own_addr = self.peers[idx].local_addr;
        let peer_router_id = self.peers[idx].remote_router_id.unwrap_or(addr);
        let from_client = self.peers[idx].is_client();

        for prefix in update.nlri {
            if attrs.next_hop == own_addr {
                self.peers[idx].counters.next_hop_rejected += 1;
                continue;
            }

            let outcome = self.peers[idx].import_policy.apply(prefix);
            let (policy_lp, policy_med) = match outcome {
                PolicyOutcome::Denied => {
                    self.peers[idx].counters.policy_rejected += 1;
                    // A previously accepted path that policy now rejects must go.
                    if self.adj_rib_in.remove(addr, prefix).is_some() {
                        self.dirty = true;
                    }
                    continue;
                }
                PolicyOutcome::Permitted {
                    set_local_pref,
                    set_med,
                } => (set_local_pref, set_med),
            };

            let path = BgpPath {
                prefix,
                source,
                peer_addr: addr,
                peer_as,
                peer_router_id,
                origin: attrs.origin,
                as_path: attrs.as_path.clone(),
                next_hop: attrs.next_hop,
                med: policy_med.or(attrs.med),
                local_pref: policy_lp
                    .or(attrs.local_pref)
                    .unwrap_or(BGP_DEFAULT_LOCAL_PREF),
                atomic_aggregate: attrs.atomic_aggregate,
                originator_id: attrs.originator_id,
                cluster_list: attrs.cluster_list.clone(),
                from_client,
                received_at_ms: now_ms,
            };

            // Only a genuine change to the route reruns the decision process. An
            // identical re-advertisement still refreshes the stored path, so the
            // Adj-RIB-In timestamp tracks when this peer last spoke about it.
            let previous = self.adj_rib_in.insert(addr, path.clone());
            if previous.is_none_or(|prev| !prev.same_route_as(&path)) {
                self.dirty = true;
            }

            // A neighbour must not be able to exhaust memory by advertising forever.
            if self.adj_rib_in.prefix_count(addr) > self.peers[idx].max_prefixes {
                return Err(BgpNotificationMessage::new(
                    BGP_ERR_CEASE,
                    BGP_SUB_MAX_PREFIXES,
                ));
            }
        }

        self.log(
            now_ms,
            addr,
            format!(
                "Adj-RIB-In now holds {} prefix(es) from this peer",
                self.adj_rib_in.prefix_count(addr)
            ),
        );
        Ok(())
    }

    // ========================================================================
    // MP-BGP EVPN
    // ========================================================================

    /// Route Targets this speaker imports EVPN routes on.
    pub fn import_route_targets(&self) -> Vec<RouteTarget> {
        self.import_rts.iter().copied().collect()
    }

    /// Adds an import Route Target. A received EVPN route is accepted into the
    /// Loc-RIB only if one of its RTs is in this set.
    pub fn add_import_route_target(&mut self, rt: RouteTarget) {
        if self.import_rts.insert(rt) {
            // A newly imported RT can make routes already sitting in the
            // Adj-RIB-In acceptable, so the decision process has to run again.
            self.evpn_dirty = true;
        }
    }

    /// Stops importing a Route Target.
    ///
    /// Routes already in the Adj-RIB-In that no longer match any import target
    /// are dropped at the same time. Leaving them would keep a table populated
    /// with routes nothing can ever use, and a neighbour could grow that table
    /// against a limit the operator thought they had removed.
    pub fn remove_import_route_target(&mut self, rt: &RouteTarget) -> bool {
        if !self.import_rts.remove(rt) {
            return false;
        }
        self.evpn_dirty = true;

        let stale: Vec<(Ipv4Address, EvpnRouteKey)> = self
            .evpn_adj_rib_in
            .iter_paths()
            .filter(|p| !p.route.matches_import(&self.import_rts))
            .map(|p| (p.peer_addr, p.key()))
            .collect();
        for (peer, key) in stale {
            self.evpn_adj_rib_in.remove(peer, &key);
        }
        true
    }

    /// Originates an EVPN route for a host attached to this speaker.
    ///
    /// Returns true if anything changed. An identical re-origination is a no-op,
    /// so a VTEP can call this every poll for every local MAC without producing a
    /// duplicate advertisement.
    pub fn originate_evpn(&mut self, route: EvpnRoute) -> bool {
        let key = route.key();
        if self.evpn_originated.get(&key) == Some(&route) {
            return false;
        }
        self.evpn_originated.insert(key, route);
        self.evpn_dirty = true;
        true
    }

    /// Stops originating an EVPN route, which propagates as an MP_UNREACH.
    pub fn withdraw_evpn(&mut self, key: &EvpnRouteKey) -> bool {
        let removed = self.evpn_originated.remove(key).is_some();
        if removed {
            self.evpn_dirty = true;
        }
        removed
    }

    pub fn evpn_originated_routes(&self) -> Vec<&EvpnRoute> {
        self.evpn_originated.values().collect()
    }

    /// Applies the multiprotocol part of a received UPDATE.
    ///
    /// An UPDATE that carries EVPN NLRI on a session that never negotiated the
    /// family is a protocol violation, not something to quietly ignore: the peer
    /// is sending routes it was told this speaker cannot read.
    fn import_mp_update(
        &mut self,
        idx: usize,
        now_ms: u64,
        update: &BgpUpdateMessage,
    ) -> Result<(), Teardown> {
        let addr = self.peers[idx].addr;

        for family in [
            update.mp_reach().map(|m| m.family()),
            update.mp_unreach().map(|m| m.family()),
        ]
        .into_iter()
        .flatten()
        {
            if family != AfiSafi::L2VPN_EVPN {
                // A family that was never negotiated has no business here either,
                // but an unnegotiated *unknown* family is best ignored rather than
                // treated as fatal: RFC 4760 leaves the NLRI meaningless to us.
                self.log(
                    now_ms,
                    addr,
                    format!("ignored MP NLRI for unsupported family {}", family),
                );
                continue;
            }
            if !self.peers[idx].negotiated.supports_evpn() {
                return Err(Teardown::Protocol(
                    BgpNotificationMessage::new(
                        BGP_ERR_UPDATE_MESSAGE,
                        BGP_SUB_OPTIONAL_ATTRIBUTE_ERROR,
                    ),
                    "peer sent EVPN NLRI without negotiating AFI 25 / SAFI 70".to_string(),
                ));
            }
        }

        if let Some(mp) = update.mp_unreach()
            && mp.family() == AfiSafi::L2VPN_EVPN
        {
            let nlri = decode_evpn_nlri_list(&mp.nlri).map_err(|e| {
                Teardown::Protocol(
                    BgpNotificationMessage::new(e.code, e.subcode),
                    format!("malformed EVPN MP_UNREACH: {}", e),
                )
            })?;
            let mut removed = 0usize;
            for n in &nlri {
                if self
                    .evpn_adj_rib_in
                    .remove(addr, &EvpnRouteKey::from_nlri(n))
                    .is_some()
                {
                    removed += 1;
                    self.evpn_dirty = true;
                }
            }
            if removed > 0 {
                self.log(
                    now_ms,
                    addr,
                    format!("withdrew {} EVPN route(s) from Adj-RIB-In", removed),
                );
            }
        }

        let Some(mp) = update.mp_reach() else {
            return Ok(());
        };
        if mp.family() != AfiSafi::L2VPN_EVPN {
            return Ok(());
        }

        let Some(next_hop) = mp.ipv4_next_hop() else {
            return Err(Teardown::Protocol(
                BgpNotificationMessage::new(BGP_ERR_UPDATE_MESSAGE, BGP_SUB_INVALID_NEXT_HOP),
                format!(
                    "EVPN MP_REACH next hop is {} bytes, which is no IPv4 VTEP address",
                    mp.next_hop.len()
                ),
            ));
        };
        // The VTEP address has to be something a packet could actually be sent
        // to, or the overlay would program a tunnel that can never come up.
        if next_hop.is_unspecified()
            || next_hop.is_loopback()
            || next_hop.is_multicast()
            || next_hop.is_broadcast()
        {
            return Err(Teardown::Protocol(
                BgpNotificationMessage::new(BGP_ERR_UPDATE_MESSAGE, BGP_SUB_INVALID_NEXT_HOP),
                format!(
                    "EVPN MP_REACH next hop {} is not a unicast address",
                    next_hop
                ),
            ));
        }

        let nlri = decode_evpn_nlri_list(&mp.nlri).map_err(|e| {
            Teardown::Protocol(
                BgpNotificationMessage::new(e.code, e.subcode),
                format!("malformed EVPN MP_REACH: {}", e),
            )
        })?;

        // The decoder only produces MP_REACH alongside an attribute set, but an
        // UPDATE from a hostile peer is not the place to rely on that.
        let Some(attrs) = update.attributes.as_ref() else {
            return Ok(());
        };
        let route_targets = route_targets_from_communities(&attrs.ext_communities);
        let mobility_seq = mac_mobility_from_communities(&attrs.ext_communities);
        // Everything else the peer attached travels with the route unchanged, so
        // re-advertising it - and above all reflecting it - does not quietly strip
        // communities a downstream speaker depends on.
        let other_communities = other_ext_communities(&attrs.ext_communities);

        // The same AS_PATH policing an IPv4 UPDATE gets. It has to be repeated
        // here rather than inherited: `import_update` returns as soon as it sees
        // no IPv4 NLRI, so an EVPN-only UPDATE never reaches those checks. An
        // empty AS_PATH from an external peer is the dangerous one - AS_PATH
        // length is a tie-break in the EVPN decision process too, so a
        // zero-length path would win against every legitimate advertisement of
        // the same MAC and quietly steal the host.
        let is_ebgp = self.peers[idx].remote_as != self.local_as;
        if is_ebgp {
            let peer_as = self.peers[idx].remote_as;
            let refusal = if attrs.as_path.is_empty() {
                Some("AS_PATH is empty".to_string())
            } else if !self.peers[idx].enforce_first_as {
                None
            } else {
                match attrs.as_path.leading_as() {
                    Some(a) if a == peer_as => None,
                    Some(a) => Some(format!(
                        "AS_PATH [{}] leads with AS {}, not the neighbour's AS {}",
                        attrs.as_path, a, peer_as
                    )),
                    None => Some(format!(
                        "AS_PATH [{}] does not begin with an AS_SEQUENCE",
                        attrs.as_path
                    )),
                }
            };
            if let Some(reason) = refusal {
                self.peers[idx].counters.as_path_rejected += 1;
                return Err(Teardown::Protocol(
                    BgpNotificationMessage::new(BGP_ERR_UPDATE_MESSAGE, BGP_SUB_MALFORMED_AS_PATH),
                    format!("EVPN UPDATE refused: {}", reason),
                ));
            }
        }

        // The RFC 4456 loop checks apply to EVPN exactly as they do to IPv4. They
        // have to: a fabric with two route reflectors carries EVPN routes between
        // them, and inside one AS the AS_PATH never changes, so it can say nothing
        // at all about whether a route has been round already.
        if let Some(loop_kind) = self.reflection_loop(attrs.originator_id, &attrs.cluster_list) {
            let n = nlri.len() as u64;
            let detail = match loop_kind {
                ReflectionLoop::Originator => {
                    self.peers[idx].counters.originator_loops_rejected += n;
                    format!("ORIGINATOR_ID is our own BGP identifier {}", self.router_id)
                }
                ReflectionLoop::Cluster => {
                    self.peers[idx].counters.cluster_loops_rejected += n;
                    format!(
                        "CLUSTER_LIST already contains cluster {}",
                        self.cluster_id()
                    )
                }
            };
            self.log(
                now_ms,
                addr,
                format!("rejected {} reflected EVPN route(s): {}", n, detail),
            );
            return Ok(());
        }

        // The AS loop check applies to EVPN exactly as it does to IPv4: a route
        // that has already been through this AS must not come back in.
        if attrs.as_path.contains(self.local_as) {
            self.peers[idx].counters.as_loops_rejected += nlri.len() as u64;
            self.log(
                now_ms,
                addr,
                format!(
                    "rejected {} EVPN route(s): AS_PATH [{}] already contains AS {}",
                    nlri.len(),
                    attrs.as_path,
                    self.local_as
                ),
            );
            return Ok(());
        }

        let peer_as = self.peers[idx].remote_as;
        let peer_router_id = self.peers[idx].remote_router_id.unwrap_or(addr);
        let from_client = self.peers[idx].is_client();
        // A route reflector has no tenant of its own and so imports no tenant
        // Route Target. Filtering on import would leave it with nothing to
        // reflect, which is the whole reason it is in the topology. It therefore
        // retains every route it hears - still under the per-peer ceiling - and
        // records separately whether each one is usable *here*.
        let retain_all = self.retains_all_route_targets();
        let mut accepted = 0usize;

        for n in nlri {
            let route = EvpnRoute {
                nlri: n,
                next_hop,
                route_targets: route_targets.clone(),
                mobility_seq,
                other_communities: other_communities.clone(),
            };

            let importable = route.matches_import(&self.import_rts);

            // Route Target import on an ordinary speaker. A route nobody here
            // asked for is dropped at the edge of the Adj-RIB-In, so it can never
            // reach the Loc-RIB and never program a tunnel for another tenant.
            if !importable && !retain_all {
                self.peers[idx].counters.evpn_rt_rejected += 1;
                // A route that used to match and no longer does must also go.
                if self.evpn_adj_rib_in.remove(addr, &route.key()).is_some() {
                    self.evpn_dirty = true;
                }
                continue;
            }
            if !importable {
                // Retained for reflection, but counted: the operator can still
                // see that this speaker is carrying routes it does not use.
                self.peers[idx].counters.evpn_rt_rejected += 1;
            }

            let path = EvpnPath {
                route,
                peer_addr: addr,
                peer_as,
                peer_router_id,
                origin: attrs.origin,
                as_path: attrs.as_path.clone(),
                local_pref: attrs.local_pref.unwrap_or(BGP_DEFAULT_LOCAL_PREF),
                originator_id: attrs.originator_id,
                cluster_list: attrs.cluster_list.clone(),
                from_client,
                importable,
                received_at_ms: now_ms,
                local: false,
            };

            let previous = self.evpn_adj_rib_in.insert(addr, path.clone());
            if previous.is_none_or(|prev| !prev.same_route_as(&path)) {
                self.evpn_dirty = true;
            }
            accepted += 1;

            if self.evpn_adj_rib_in.route_count(addr) > MAX_EVPN_ROUTES {
                return Err(Teardown::Protocol(
                    BgpNotificationMessage::new(BGP_ERR_CEASE, BGP_SUB_MAX_PREFIXES),
                    format!("peer advertised more than {} EVPN routes", MAX_EVPN_ROUTES),
                ));
            }
        }

        if accepted > 0 {
            self.peers[idx].counters.evpn_received += accepted as u64;
            self.log(
                now_ms,
                addr,
                format!(
                    "imported {} EVPN route(s) via next-hop {}; Adj-RIB-In holds {}",
                    accepted,
                    next_hop,
                    self.evpn_adj_rib_in.route_count(addr)
                ),
            );
        }
        Ok(())
    }

    /// Recomputes the EVPN Loc-RIB from the Adj-RIB-In tables plus what this
    /// speaker originates itself.
    ///
    /// Rebuilding rather than patching is what guarantees the overlay has no
    /// stale state: a peer that went down, a route that was withdrawn, and a host
    /// that moved all reduce to "the input set is different", and the output
    /// follows from the input alone.
    fn run_evpn_decision_process(&mut self, now_ms: u64) {
        self.evpn_decision_runs += 1;
        // Two outputs from one pass over the same candidate sets.
        //
        //  * the advertisement RIB, the best path per route over everything
        //    received, which is what this speaker may pass on or reflect;
        //  * the Loc-RIB, the best path per route among the ones this speaker
        //    actually imports, which is the only thing the VTEP is programmed
        //    from.
        //
        // On a leaf they come out identical, because a route no local instance
        // asked for was never stored in the first place. On a route reflector the
        // Loc-RIB is empty and the advertisement RIB holds the whole fabric,
        // which is exactly the asymmetry that lets a reflector carry a tenant it
        // is not part of.
        let mut new_advertise = EvpnLocRib::new();
        let mut new_rib = EvpnLocRib::new();
        let mut keys = self.evpn_adj_rib_in.keys();
        keys.extend(self.evpn_originated.keys().cloned());

        for key in keys {
            let learned = self.evpn_adj_rib_in.candidates(&key);
            let fresh: Vec<&EvpnPath> = learned
                .iter()
                .copied()
                .filter(|path| {
                    !self.route_is_graceful_restart_stale(
                        path.peer_addr,
                        AfiSafi::L2VPN_EVPN,
                        path.received_at_ms,
                    )
                })
                .collect();
            let local = self
                .evpn_originated
                .get(&key)
                .map(|r| EvpnPath::local(r.clone(), self.router_id, now_ms));

            let mut candidates: Vec<&EvpnPath> = if fresh.is_empty() { learned } else { fresh };
            if let Some(ref l) = local {
                candidates.push(l);
            }
            if let Some(best) = select_best_evpn(&candidates) {
                new_advertise.insert(best.clone());
            }

            // The best *importable* path is selected among the importable
            // candidates rather than by testing the overall winner, so a tenant
            // this speaker does own is not deprived of its route merely because
            // some other path it cannot use happened to score higher.
            let importable: Vec<&EvpnPath> = candidates
                .into_iter()
                .filter(|p| p.local || p.importable)
                .collect();
            if let Some(best) = select_best_evpn(&importable) {
                new_rib.insert(best.clone());
            }
        }

        if new_rib.len() != self.evpn_loc_rib.len() {
            self.log(
                now_ms,
                Ipv4Address::UNSPECIFIED,
                format!(
                    "EVPN decision process: Loc-RIB {} -> {} route(s)",
                    self.evpn_loc_rib.len(),
                    new_rib.len()
                ),
            );
        }
        self.evpn_loc_rib = new_rib;
        self.evpn_advertise_rib = new_advertise;
    }

    /// Sends `idx` the EVPN routes it should be hearing, and withdraws the ones
    /// it should not.
    fn advertise_evpn_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        if !self.peers[idx].carries_evpn() {
            return;
        }
        let addr = self.peers[idx].addr;
        let force_refresh = self.peers[idx]
            .refresh_pending
            .contains(&AfiSafi::L2VPN_EVPN);
        let mut refresh_complete = true;
        let desired = self.compute_evpn_adj_rib_out(idx);

        let withdrawn: Vec<EvpnRouteKey> = self
            .evpn_adj_rib_out
            .keys(addr)
            .into_iter()
            .filter(|k| !desired.contains_key(k))
            .collect();

        if !withdrawn.is_empty() {
            let nlri: Vec<crate::evpn::EvpnNlri> = withdrawn
                .iter()
                .filter_map(|k| {
                    self.evpn_adj_rib_out
                        .get(addr, k)
                        .map(|a| a.route.nlri.clone())
                })
                .collect();
            let mp = MpUnreachNlri::new(AfiSafi::L2VPN_EVPN, encode_evpn_nlri_list(&nlri));
            let pdu = BgpPdu::Update(BgpUpdateMessage::mp_withdraw(mp));
            if self.send_pdu(idx, sockets, &pdu) {
                self.peers[idx].counters.updates_sent += 1;
                for k in &withdrawn {
                    self.evpn_adj_rib_out.remove(addr, k);
                }
                self.log(
                    now_ms,
                    addr,
                    format!("withdrew {} EVPN route(s) via MP_UNREACH", withdrawn.len()),
                );
            } else if force_refresh {
                refresh_complete = false;
            }
        }

        let four_octet = self.peers[idx].negotiated.four_octet_as;
        let mut groups: BTreeMap<(Ipv4Address, Vec<u8>), (BgpPathAttributes, Vec<EvpnRouteKey>)> =
            BTreeMap::new();
        for (key, advert) in &desired {
            if !force_refresh && self.evpn_adj_rib_out.get(addr, key) == Some(advert) {
                continue;
            }
            let mut attrs = Self::evpn_attributes_for(advert, four_octet);
            attrs.mp_reach = None;
            groups
                .entry((advert.route.next_hop, attrs.encode_for(false)))
                .or_insert_with(|| (attrs, Vec::new()))
                .1
                .push(key.clone());
        }

        for ((next_hop, _), (mut attrs, keys)) in groups {
            let nlri: Vec<crate::evpn::EvpnNlri> = keys
                .iter()
                .filter_map(|k| desired.get(k).map(|a| a.route.nlri.clone()))
                .collect();
            let reflected = keys
                .iter()
                .filter(|k| desired.get(*k).is_some_and(|a| a.is_reflected()))
                .count();
            attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
                AfiSafi::L2VPN_EVPN,
                next_hop,
                encode_evpn_nlri_list(&nlri),
            ));
            let pdu = BgpPdu::Update(BgpUpdateMessage::mp_announce(attrs));
            if self.send_pdu(idx, sockets, &pdu) {
                self.peers[idx].counters.updates_sent += 1;
                self.peers[idx].counters.evpn_advertised += keys.len() as u64;
                self.peers[idx].counters.routes_reflected += reflected as u64;
                for k in &keys {
                    if let Some(advert) = desired.get(k) {
                        self.evpn_adj_rib_out.insert(addr, advert.clone());
                    }
                }
                self.log(
                    now_ms,
                    addr,
                    format!(
                        "advertised {} EVPN route(s) in one UPDATE ({} reflected){}",
                        keys.len(),
                        reflected,
                        if force_refresh { " (refresh)" } else { "" }
                    ),
                );
            } else if force_refresh {
                refresh_complete = false;
            }
        }

        if force_refresh && refresh_complete {
            self.peers[idx]
                .refresh_pending
                .remove(&AfiSafi::L2VPN_EVPN);
            self.log(now_ms, addr, "completed L2VPN EVPN route refresh");
        }
    }

    /// The attribute set for one EVPN advertisement.
    ///
    /// Everything the wire needs was decided when the advertisement was computed,
    /// so this does no policy of its own. In particular ORIGIN and AS_PATH come
    /// from the path that was selected rather than being invented here: RFC 4456
    /// section 10 requires a reflector to pass the attributes through unchanged,
    /// and a route that entered the fabric as INCOMPLETE has to leave it that way.
    fn evpn_attributes_for(advert: &EvpnAdvertisedRoute, four_octet: bool) -> BgpPathAttributes {
        let mut attrs = BgpPathAttributes::new(
            advert.origin,
            advert.as_path.clone(),
            Ipv4Address::UNSPECIFIED,
        );
        attrs.four_octet_as = four_octet;
        attrs.ext_communities = advert.route.ext_communities();
        attrs.local_pref = advert.local_pref;
        attrs.originator_id = advert.originator_id;
        attrs.cluster_list = advert.cluster_list.clone();
        // The NLRI list is filled in by the caller once it knows which routes
        // share this attribute set; the next hop is what identifies the group.
        attrs.mp_reach = Some(MpReachNlri::with_ipv4_next_hop(
            AfiSafi::L2VPN_EVPN,
            advert.route.next_hop,
            Vec::new(),
        ));
        attrs
    }

    /// What `idx` should be hearing about EVPN.
    ///
    /// The next hop is *not* rewritten to this speaker's session address the way
    /// an eBGP IPv4 next hop is. In an EVPN fabric the next hop names the VTEP
    /// that owns the MAC, and rewriting it at every hop would make every leaf
    /// claim every host.
    fn compute_evpn_adj_rib_out(&self, idx: usize) -> BTreeMap<EvpnRouteKey, EvpnAdvertisedRoute> {
        let peer = &self.peers[idx];
        let is_ebgp_session = peer.remote_as != self.local_as;
        let mut out = BTreeMap::new();

        // Computed from the advertisement RIB, not the Loc-RIB. A route reflector
        // imports no tenant Route Target, so its Loc-RIB is empty; reading it here
        // is what would make an EVPN reflector need a VNI it has no business owning.
        for (key, best) in self.evpn_advertise_rib.iter() {
            // Never advertise a route back to the peer it came from.
            if !best.local && best.peer_addr == peer.addr {
                continue;
            }
            let learned_over_ibgp = !best.local && best.peer_as == self.local_as;
            let propagation =
                self.propagation(idx, is_ebgp_session, learned_over_ibgp, best.from_client);
            if propagation == Propagation::Deny {
                continue;
            }
            let mut as_path = best.as_path.clone();
            if is_ebgp_session {
                as_path.prepend(self.local_as);
            }
            if as_path.contains(peer.remote_as) {
                continue;
            }

            let (originator_id, cluster_list) = if propagation == Propagation::Reflect {
                self.reflection_metadata(
                    best.originator_id,
                    &best.cluster_list,
                    best.peer_router_id,
                )
            } else {
                (None, Vec::new())
            };

            out.insert(
                key.clone(),
                EvpnAdvertisedRoute {
                    route: best.route.clone(),
                    origin: best.origin,
                    as_path,
                    // LOCAL_PREF is internal-only, exactly as for IPv4 unicast.
                    local_pref: if is_ebgp_session {
                        None
                    } else {
                        Some(best.local_pref)
                    },
                    originator_id,
                    cluster_list,
                },
            );
        }
        out
    }

    /// How many EVPN routes this speaker is currently withholding from `peer`
    /// because the RFC 4456 rules do not allow sending them.
    ///
    /// Recomputed on demand rather than tracked incrementally: it is a
    /// diagnostic, and one derived from live state cannot drift away from what
    /// the speaker is actually doing.
    pub fn evpn_rr_suppressed(&self, peer: Ipv4Address) -> usize {
        let Some(idx) = self.peers.iter().position(|p| p.addr == peer) else {
            return 0;
        };
        let is_ebgp_session = self.peers[idx].remote_as != self.local_as;
        self.evpn_advertise_rib
            .iter()
            .filter(|(_, best)| !best.local && best.peer_addr != self.peers[idx].addr)
            .filter(|(_, best)| {
                let learned_over_ibgp = !best.local && best.peer_as == self.local_as;
                self.propagation(idx, is_ebgp_session, learned_over_ibgp, best.from_client)
                    == Propagation::Deny
            })
            .count()
    }

    /// `show bgp evpn summary`: routes received, locally imported, originated.
    pub fn evpn_route_counts(&self) -> (usize, usize, usize) {
        (
            self.evpn_adj_rib_in.total_routes(),
            self.evpn_loc_rib.len(),
            self.evpn_originated.len(),
        )
    }

    /// EVPN routes this speaker holds but does not import, which is what a route
    /// reflector carries for tenants it is not part of.
    pub fn evpn_retained_not_imported(&self) -> usize {
        self.evpn_adj_rib_in
            .iter_paths()
            .filter(|p| !p.importable)
            .count()
    }

    /// The number of routes eligible for advertisement, whether imported or not.
    pub fn evpn_advertisable_count(&self) -> usize {
        self.evpn_advertise_rib.len()
    }

    // ========================================================================
    // Decision process and FIB
    // ========================================================================

    /// Recomputes the Loc-RIB from the Adj-RIB-In tables plus the originated set.
    fn run_decision_process(&mut self, now_ms: u64) {
        self.decision_runs += 1;
        let mut new_rib = LocRib::new();

        let mut prefixes = self.adj_rib_in.prefixes();
        prefixes.extend(self.originated.keys().copied());

        for prefix in prefixes {
            let learned = self.adj_rib_in.candidates(prefix);
            let fresh: Vec<&BgpPath> = learned
                .iter()
                .copied()
                .filter(|path| {
                    !self.route_is_graceful_restart_stale(
                        path.peer_addr,
                        AfiSafi::IPV4_UNICAST,
                        path.received_at_ms,
                    )
                })
                .collect();
            let local = self
                .originated
                .get(&prefix)
                .map(|nh| BgpPath::local(prefix, *nh, self.router_id));

            let mut candidates: Vec<&BgpPath> = if fresh.is_empty() { learned } else { fresh };
            if let Some(ref l) = local {
                candidates.push(l);
            }
            if let Some(best) = select_best(&candidates) {
                new_rib.insert(best.clone());
            }
        }

        let before: Vec<Ipv4Prefix> = self.loc_rib.prefixes();
        let after: Vec<Ipv4Prefix> = new_rib.prefixes();
        if before != after {
            self.log(
                now_ms,
                Ipv4Address::UNSPECIFIED,
                format!(
                    "decision process: Loc-RIB {} -> {} prefix(es)",
                    before.len(),
                    after.len()
                ),
            );
        }
        self.loc_rib = new_rib;
    }

    /// Pushes the Loc-RIB into the real forwarding table, and removes whatever it no
    /// longer contains. Only BGP-sourced entries are touched, so connected and static
    /// routes are never disturbed.
    fn sync_fib(&mut self, now_ms: u64, fib: &mut RoutingTable) {
        let mut desired: BTreeMap<Ipv4Prefix, (Ipv4Address, String)> = BTreeMap::new();
        let mut unresolved = BTreeSet::new();

        for (prefix, path) in self.loc_rib.iter() {
            // A locally originated prefix is already reachable through a connected or
            // static route; installing a BGP copy of it would add nothing.
            if path.is_local() {
                continue;
            }
            match Self::resolve_next_hop(fib, path.next_hop) {
                Some((next_hop, iface)) => {
                    desired.insert(*prefix, (next_hop, iface));
                }
                None => {
                    unresolved.insert(*prefix);
                }
            }
        }

        let stale: Vec<Ipv4Prefix> = self
            .installed
            .iter()
            .filter(|p| !desired.contains_key(p))
            .copied()
            .collect();
        for prefix in stale {
            if fib.remove_route(prefix.address, prefix.length, RouteSource::Bgp) {
                self.log(
                    now_ms,
                    Ipv4Address::UNSPECIFIED,
                    format!("FIB: removed {}", prefix),
                );
            }
            self.installed.remove(&prefix);
        }

        for (prefix, (next_hop, iface)) in &desired {
            let already = fib
                .routes_from(RouteSource::Bgp)
                .into_iter()
                .find(|r| r.destination == prefix.address && r.prefix_len == prefix.length)
                .is_some_and(|r| r.gateway == Some(*next_hop) && r.interface == *iface);
            if !already {
                fib.add_route_from(
                    prefix.address,
                    prefix.length,
                    Some(*next_hop),
                    iface,
                    RouteSource::Bgp,
                );
                self.log(
                    now_ms,
                    Ipv4Address::UNSPECIFIED,
                    format!("FIB: installed {} via {} dev {}", prefix, next_hop, iface),
                );
            }
            self.installed.insert(*prefix);
        }

        for prefix in &unresolved {
            if !self.unresolved.contains(prefix) {
                self.log(
                    now_ms,
                    Ipv4Address::UNSPECIFIED,
                    format!("best path for {} has an unresolvable NEXT_HOP", prefix),
                );
            }
        }
        self.unresolved = unresolved;
    }

    /// Resolves a BGP NEXT_HOP to `(forwarding next hop, egress interface)` using only
    /// non-BGP routes, so resolution can never recurse through another BGP route.
    fn resolve_next_hop(
        fib: &RoutingTable,
        next_hop: Ipv4Address,
    ) -> Option<(Ipv4Address, String)> {
        let route = fib
            .all_routes()
            .iter()
            .find(|r| r.source != RouteSource::Bgp && r.matches(next_hop))?;
        Some((route.gateway.unwrap_or(next_hop), route.interface.clone()))
    }

    /// Prefixes whose best path could not be resolved to an egress interface.
    pub fn unresolved_prefixes(&self) -> Vec<Ipv4Prefix> {
        self.unresolved.iter().copied().collect()
    }

    /// Prefixes this speaker currently has installed in the FIB.
    pub fn installed_prefixes(&self) -> Vec<Ipv4Prefix> {
        self.installed.iter().copied().collect()
    }

    // ========================================================================
    // Export
    // ========================================================================

    /// Computes what `idx` should be hearing and sends only the differences.
    fn advertise_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
        if !self.peers[idx].is_established() {
            return;
        }
        let addr = self.peers[idx].addr;
        let force_refresh = self.peers[idx]
            .refresh_pending
            .contains(&AfiSafi::IPV4_UNICAST);
        let mut refresh_complete = true;
        let desired = self.compute_adj_rib_out(idx);

        // Withdrawals still compare against the real Adj-RIB-Out, even during a
        // refresh. Clearing it to force a replay would forget stale routes and
        // make it impossible to withdraw them.
        let withdrawn: Vec<Ipv4Prefix> = self
            .adj_rib_out
            .prefixes(addr)
            .into_iter()
            .filter(|p| !desired.contains_key(p))
            .collect();

        if !withdrawn.is_empty() {
            let pdu = BgpPdu::Update(BgpUpdateMessage::withdraw(withdrawn.clone()));
            if self.send_pdu(idx, sockets, &pdu) {
                self.peers[idx].counters.updates_sent += 1;
                for p in &withdrawn {
                    self.adj_rib_out.remove(addr, p);
                }
                self.log(
                    now_ms,
                    addr,
                    format!("advertised withdrawal of {} prefix(es)", withdrawn.len()),
                );
            } else if force_refresh {
                refresh_complete = false;
            }
        }

        // During a route refresh, unchanged routes are deliberately included: the
        // peer asked for a replay of the current outbound view. Outside a refresh,
        // the Adj-RIB-Out continues to suppress duplicate advertisements.
        let four_octet = self.peers[idx].negotiated.four_octet_as;
        let mut groups: BTreeMap<Vec<u8>, (AdvertisedRoute, Vec<Ipv4Prefix>)> = BTreeMap::new();
        for (prefix, route) in &desired {
            if !force_refresh && self.adj_rib_out.get(addr, prefix) == Some(route) {
                continue;
            }
            let attrs = Self::attributes_for(route, four_octet);
            let key = attrs.encode();
            groups
                .entry(key)
                .or_insert_with(|| (route.clone(), Vec::new()))
                .1
                .push(*prefix);
        }

        for (_, (route, prefixes)) in groups {
            let attrs = Self::attributes_for(&route, four_octet);
            let reflected = route.originator_id.is_some() || !route.cluster_list.is_empty();
            let pdu = BgpPdu::Update(BgpUpdateMessage::announce(attrs, prefixes.clone()));
            if self.send_pdu(idx, sockets, &pdu) {
                self.peers[idx].counters.updates_sent += 1;
                if reflected {
                    self.peers[idx].counters.routes_reflected += prefixes.len() as u64;
                }
                for p in &prefixes {
                    self.adj_rib_out.insert(addr, *p, route.clone());
                }
                self.log(
                    now_ms,
                    addr,
                    format!(
                        "advertised {} prefix(es) with AS_PATH [{}] next-hop {}{}{}",
                        prefixes.len(),
                        route.as_path,
                        route.next_hop,
                        if reflected { " (reflected)" } else { "" },
                        if force_refresh { " (refresh)" } else { "" }
                    ),
                );
            } else if force_refresh {
                refresh_complete = false;
            }
        }

        self.peers[idx].counters.rr_suppressed = self.rr_suppressed_count(idx) as u64;

        if force_refresh && refresh_complete {
            self.peers[idx]
                .refresh_pending
                .remove(&AfiSafi::IPV4_UNICAST);
            self.log(now_ms, addr, "completed IPv4 Unicast route refresh");
        }
    }

    /// How many IPv4 prefixes the RFC 4456 rules are currently withholding from
    /// peer `idx`.
    fn rr_suppressed_count(&self, idx: usize) -> usize {
        let is_ebgp_session = self.peers[idx].remote_as != self.local_as;
        self.loc_rib
            .iter()
            .filter(|(_, best)| best.peer_addr != self.peers[idx].addr)
            .filter(|(_, best)| {
                self.propagation(
                    idx,
                    is_ebgp_session,
                    best.source == PathSource::Ibgp,
                    best.from_client,
                ) == Propagation::Deny
            })
            .count()
    }

    fn attributes_for(route: &AdvertisedRoute, four_octet_as: bool) -> BgpPathAttributes {
        BgpPathAttributes {
            origin: route.origin,
            as_path: route.as_path.clone(),
            next_hop: route.next_hop,
            med: route.med,
            local_pref: route.local_pref,
            atomic_aggregate: false,
            ext_communities: Vec::new(),
            mp_reach: None,
            mp_unreach: None,
            originator_id: route.originator_id,
            cluster_list: route.cluster_list.clone(),
            four_octet_as,
        }
    }

    /// Builds the outbound view of the Loc-RIB for one peer, applying split horizon,
    /// the iBGP re-advertisement rule and its RFC 4456 exception, export policy,
    /// AS_PATH prepending, next-hop selection, and outbound loop prevention.
    fn compute_adj_rib_out(&self, idx: usize) -> BTreeMap<Ipv4Prefix, AdvertisedRoute> {
        let peer = &self.peers[idx];
        let is_ebgp_session = peer.remote_as != self.local_as;
        let mut out = BTreeMap::new();

        for (prefix, best) in self.loc_rib.iter() {
            // Never advertise a route back to the peer it came from.
            if best.peer_addr == peer.addr {
                continue;
            }
            let propagation = self.propagation(
                idx,
                is_ebgp_session,
                best.source == PathSource::Ibgp,
                best.from_client,
            );
            if propagation == Propagation::Deny {
                continue;
            }

            let (policy_lp, policy_med) = match peer.export_policy.apply(*prefix) {
                PolicyOutcome::Denied => continue,
                PolicyOutcome::Permitted {
                    set_local_pref,
                    set_med,
                } => (set_local_pref, set_med),
            };

            let mut as_path = best.as_path.clone();
            if is_ebgp_session {
                as_path.prepend(self.local_as);
            }
            // Do not send a route into an AS that is already on its path; the peer
            // would only reject it as a loop.
            if as_path.contains(peer.remote_as) {
                continue;
            }

            let reflecting = propagation == Propagation::Reflect;
            // An eBGP peer must forward through our own address on the shared subnet,
            // never through whatever we were told. An iBGP peer keeps the original
            // NEXT_HOP unless next-hop-self is configured - except when this speaker
            // is reflecting, where RFC 4456 section 10 forbids touching the NEXT_HOP
            // at all. A reflector that rewrote it would insert itself into a
            // forwarding path it has no business being in, and the client would send
            // traffic to a router that is only there to carry the control plane.
            let next_hop =
                if is_ebgp_session || best.is_local() || (peer.next_hop_self && !reflecting) {
                    peer.local_addr
                } else {
                    best.next_hop
                };

            let local_pref = if is_ebgp_session {
                // LOCAL_PREF is not sent to external peers (RFC 4271 section 5.1.5).
                None
            } else {
                Some(policy_lp.unwrap_or(best.local_pref))
            };

            let med = if is_ebgp_session {
                policy_med
            } else {
                policy_med.or(best.med)
            };

            let (originator_id, cluster_list) = if reflecting {
                self.reflection_metadata(
                    best.originator_id,
                    &best.cluster_list,
                    best.peer_router_id,
                )
            } else {
                (None, Vec::new())
            };

            out.insert(
                *prefix,
                AdvertisedRoute {
                    origin: best.origin,
                    as_path,
                    next_hop,
                    med,
                    local_pref,
                    originator_id,
                    cluster_list,
                },
            );
        }

        out
    }

    /// Whether a path may be sent to peer `idx`, and whether doing so is route
    /// reflection (RFC 4456 section 5).
    ///
    /// The plain RFC 4271 rule - a route learned from an internal peer is not
    /// passed to another internal peer - stays the default. Reflection is an
    /// exception carved out of it, and only for the pairings the RFC names:
    ///
    /// * from a client:     to clients, to non-clients, to external peers
    /// * from a non-client: to clients and to external peers only
    /// * locally originated or externally learned: to everyone
    fn propagation(
        &self,
        idx: usize,
        is_ebgp_session: bool,
        learned_over_ibgp: bool,
        from_client: bool,
    ) -> Propagation {
        // Reflection metadata is non-transitive and describes this AS only, so an
        // external session never reflects; it just advertises.
        if is_ebgp_session || !learned_over_ibgp {
            return Propagation::Plain;
        }
        if from_client || self.peers[idx].is_client() {
            Propagation::Reflect
        } else {
            Propagation::Deny
        }
    }

    /// The ORIGINATOR_ID and CLUSTER_LIST to put on a reflected advertisement.
    ///
    /// ORIGINATOR_ID is set once, by the first reflector to handle the route, to
    /// the identifier of the speaker that advertised it. Every later reflector
    /// passes it through untouched: the attribute names where the route entered
    /// this AS, not the last router to move it.
    ///
    /// The local cluster ID goes on the front of CLUSTER_LIST, so the list reads
    /// most-recent-reflector first and a receiver only has to find its own cluster
    /// anywhere in it to know the route has been round already.
    fn reflection_metadata(
        &self,
        received_originator: Option<Ipv4Address>,
        received_clusters: &[Ipv4Address],
        advertising_router_id: Ipv4Address,
    ) -> (Option<Ipv4Address>, Vec<Ipv4Address>) {
        let originator = Some(received_originator.unwrap_or(advertising_router_id));
        let mut clusters = Vec::with_capacity(received_clusters.len() + 1);
        clusters.push(self.cluster_id());
        clusters.extend_from_slice(received_clusters);
        // A list already at the accepted ceiling is truncated rather than grown
        // past it, so this speaker can never emit an attribute its own parser
        // would refuse. In practice the loop check on receipt stops a route long
        // before it gets anywhere near here.
        clusters.truncate(MAX_CLUSTER_LIST_LEN);
        (originator, clusters)
    }

    // ========================================================================
    // Diagnostics
    // ========================================================================

    pub fn summaries(&self, now_ms: u64) -> Vec<BgpPeerSummary> {
        self.peers
            .iter()
            .map(|p| BgpPeerSummary {
                addr: p.addr,
                remote_as: p.remote_as,
                local_addr: p.local_addr,
                state: p.state,
                router_id: p.remote_router_id,
                uptime_ms: p.uptime_ms(now_ms),
                hold_ms: p.negotiated_hold_ms,
                hold_remaining_ms: p.hold_remaining_ms(now_ms),
                keepalive_interval_ms: p.keepalive_interval_ms,
                keepalive_remaining_ms: p.keepalive_remaining_ms(now_ms),
                prefixes_received: self.adj_rib_in.prefix_count(p.addr),
                prefixes_advertised: self.adj_rib_out.prefix_count(p.addr),
                counters: p.counters.clone(),
                last_error: p.last_error.clone(),
                establishment_count: p.establishment_count,
            })
            .collect()
    }

    /// `show bgp summary`
    pub fn format_summary(&self, now_ms: u64) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "BGP router identifier {}, local AS number {}\n",
            self.router_id, self.local_as
        ));
        s.push_str(&format!(
            "Loc-RIB {} prefix(es), Adj-RIB-In {} path(s), {} in FIB, {} decision run(s)\n",
            self.loc_rib.len(),
            self.adj_rib_in.path_count(),
            self.installed.len(),
            self.decision_runs
        ));
        s.push_str(
            "Neighbor          AS  State        Up(ms)  Hold  PfxRcd  PfxAdv  MsgRcd  MsgSent\n",
        );
        for p in self.summaries(now_ms) {
            let msg_rcd = p.counters.opens_received
                + p.counters.updates_received
                + p.counters.keepalives_received
                + p.counters.route_refreshes_received
                + p.counters.notifications_received;
            let msg_sent = p.counters.opens_sent
                + p.counters.updates_sent
                + p.counters.keepalives_sent
                + p.counters.route_refreshes_sent
                + p.counters.notifications_sent;
            s.push_str(&format!(
                "{:<15} {:>5}  {:<11} {:>7} {:>5} {:>7} {:>7} {:>7} {:>8}\n",
                p.addr.to_string(),
                p.remote_as,
                p.state.as_str(),
                p.uptime_ms.map(|u| u.to_string()).unwrap_or("-".into()),
                p.hold_ms / 1_000,
                p.prefixes_received,
                p.prefixes_advertised,
                msg_rcd,
                msg_sent
            ));
        }
        s
    }

    /// `show bgp peers`
    pub fn format_peers(&self, now_ms: u64) -> String {
        let mut s = String::new();
        for p in self.summaries(now_ms) {
            s.push_str(&format!(
                "neighbor {} remote-as {} local-address {}\n",
                p.addr, p.remote_as, p.local_addr
            ));
            s.push_str(&format!(
                "  state {}  router-id {}  established {} time(s)\n",
                p.state,
                p.router_id.map(|r| r.to_string()).unwrap_or("-".into()),
                p.establishment_count
            ));
            s.push_str(&format!(
                "  uptime {}  hold {}ms (remaining {})  keepalive {}ms (remaining {})\n",
                p.uptime_ms
                    .map(|u| format!("{}ms", u))
                    .unwrap_or("down".into()),
                p.hold_ms,
                p.hold_remaining_ms
                    .map(|v| format!("{}ms", v))
                    .unwrap_or("n/a".into()),
                p.keepalive_interval_ms,
                p.keepalive_remaining_ms
                    .map(|v| format!("{}ms", v))
                    .unwrap_or("n/a".into()),
            ));
            s.push_str(&format!(
                "  prefixes received {}  advertised {}\n",
                p.prefixes_received, p.prefixes_advertised
            ));
            if let Some(peer) = self.peer(p.addr)
                && peer.graceful_restart_active()
            {
                s.push_str(&format!(
                    "  graceful-restart stale {:?} remaining {}ms\n",
                    peer.graceful_restart_stale_families(),
                    peer.graceful_restart_remaining_ms(now_ms).unwrap_or(0)
                ));
            }
            s.push_str(&format!(
                "  messages open {}/{} update {}/{} keepalive {}/{} route-refresh {}/{} notification {}/{} (rcvd/sent)\n",
                p.counters.opens_received,
                p.counters.opens_sent,
                p.counters.updates_received,
                p.counters.updates_sent,
                p.counters.keepalives_received,
                p.counters.keepalives_sent,
                p.counters.route_refreshes_received,
                p.counters.route_refreshes_sent,
                p.counters.notifications_received,
                p.counters.notifications_sent
            ));
            s.push_str(&format!(
                "  discarded: as-loop {}  policy {}  next-hop {}  as-path {}\n",
                p.counters.as_loops_rejected,
                p.counters.policy_rejected,
                p.counters.next_hop_rejected,
                p.counters.as_path_rejected
            ));
            s.push_str(&format!(
                "  last error: {}\n",
                p.last_error.unwrap_or("none".into())
            ));
        }
        if s.is_empty() {
            s.push_str("no BGP neighbors configured\n");
        }
        s
    }

    /// `show bgp routes` - the Loc-RIB, i.e. the best path per prefix.
    pub fn format_routes(&self) -> String {
        let mut s = String::from(
            "Prefix              Next Hop         LocPrf  AS Path        Origin  Source  FIB\n",
        );
        for (prefix, path) in self.loc_rib.iter() {
            s.push_str(&format!(
                "{:<19} {:<16} {:>6}  {:<14} {:<6}  {:<6}  {}\n",
                prefix.to_string(),
                path.next_hop.to_string(),
                path.local_pref,
                path.as_path.to_string(),
                path.origin.to_string(),
                path.source.as_str(),
                if self.installed.contains(prefix) {
                    "yes"
                } else if path.is_local() {
                    "local"
                } else {
                    "no"
                }
            ));
        }
        s
    }

    /// `show bgp rib` - every path in the Adj-RIB-In, best paths marked.
    pub fn format_rib(&self) -> String {
        let mut s = String::from(
            "   Prefix              Peer             AS Path        LocPrf  MED   Origin\n",
        );
        for path in self.adj_rib_in.iter_paths() {
            let best = self
                .loc_rib
                .get(&path.prefix)
                .is_some_and(|b| b.peer_addr == path.peer_addr);
            s.push_str(&format!(
                "{}  {:<19} {:<16} {:<14} {:>6}  {:<5} {}\n",
                if best { ">" } else { " " },
                path.prefix.to_string(),
                path.peer_addr.to_string(),
                path.as_path.to_string(),
                path.local_pref,
                path.med.map(|m| m.to_string()).unwrap_or("-".into()),
                path.origin
            ));
        }
        for (prefix, next_hop) in &self.originated {
            s.push_str(&format!(
                ">  {:<19} {:<16} {:<14} {:>6}  {:<5} i (originated)\n",
                prefix.to_string(),
                next_hop.to_string(),
                "-",
                BGP_DEFAULT_LOCAL_PREF,
                "-"
            ));
        }
        s
    }
}
