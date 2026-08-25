from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement, found {count}\n--- old ---\n{old[:600]}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


# ---------------------------------------------------------------------------
# RFC 4724 capability codec
# ---------------------------------------------------------------------------
replace_once(
    "src/bgp_caps.rs",
    """/// Route Refresh (RFC 2918).\npub const BGP_CAP_ROUTE_REFRESH: u8 = 2;\n/// Support for 4-octet AS numbers (RFC 6793).\npub const BGP_CAP_FOUR_OCTET_AS: u8 = 65;\n""",
    """/// Route Refresh (RFC 2918).\npub const BGP_CAP_ROUTE_REFRESH: u8 = 2;\n/// Graceful Restart (RFC 4724).\npub const BGP_CAP_GRACEFUL_RESTART: u8 = 64;\n/// Support for 4-octet AS numbers (RFC 6793).\npub const BGP_CAP_FOUR_OCTET_AS: u8 = 65;\n\n/// Restart State bit in the Graceful Restart flags/time word.\npub const BGP_GR_RESTART_STATE: u16 = 0x8000;\n/// Largest restart time representable by RFC 4724's 12-bit field.\npub const BGP_GR_MAX_RESTART_TIME: u16 = 0x0fff;\n/// Forwarding State bit in one AFI/SAFI tuple.\npub const BGP_GR_FORWARDING_STATE: u8 = 0x80;\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """impl fmt::Display for AfiSafi {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        write!(f, \"{} (AFI {}/SAFI {})\", self.name(), self.afi, self.safi)\n    }\n}\n\n/// One decoded capability.\n""",
    """impl fmt::Display for AfiSafi {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        write!(f, \"{} (AFI {}/SAFI {})\", self.name(), self.afi, self.safi)\n    }\n}\n\n/// Per-address-family state carried inside RFC 4724 Graceful Restart.\n#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\npub struct BgpGracefulRestartFamily {\n    pub family: AfiSafi,\n    pub forwarding_state: bool,\n}\n\nimpl BgpGracefulRestartFamily {\n    pub const fn new(family: AfiSafi, forwarding_state: bool) -> Self {\n        BgpGracefulRestartFamily {\n            family,\n            forwarding_state,\n        }\n    }\n}\n\n/// RFC 4724 Graceful Restart capability.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct BgpGracefulRestartCapability {\n    /// True when the sender is reconnecting after a control-plane restart.\n    pub restarting: bool,\n    /// Time a helper may retain stale routes, in seconds.\n    pub restart_time: u16,\n    /// Families for which graceful-restart state is advertised.\n    pub families: Vec<BgpGracefulRestartFamily>,\n}\n\nimpl BgpGracefulRestartCapability {\n    pub fn new(\n        restart_time: u16,\n        restarting: bool,\n        families: Vec<BgpGracefulRestartFamily>,\n    ) -> Self {\n        BgpGracefulRestartCapability {\n            restarting,\n            restart_time: restart_time.min(BGP_GR_MAX_RESTART_TIME),\n            families,\n        }\n    }\n\n    pub fn supports(&self, family: AfiSafi) -> bool {\n        self.families.iter().any(|f| f.family == family)\n    }\n\n    fn encode_value(&self) -> Vec<u8> {\n        let mut out = Vec::with_capacity(2 + self.families.len() * 4);\n        let word = (self.restart_time & BGP_GR_MAX_RESTART_TIME)\n            | if self.restarting { BGP_GR_RESTART_STATE } else { 0 };\n        out.extend_from_slice(&word.to_be_bytes());\n        for family in &self.families {\n            out.extend_from_slice(&family.family.afi.to_be_bytes());\n            out.push(family.family.safi);\n            out.push(if family.forwarding_state {\n                BGP_GR_FORWARDING_STATE\n            } else {\n                0\n            });\n        }\n        out\n    }\n\n    fn decode_value(value: &[u8]) -> Result<Self, BgpParseError> {\n        if value.len() < 2 || (value.len() - 2) % 4 != 0 {\n            return Err(BgpParseError::open(\n                BGP_SUB_UNSUPPORTED_OPT_PARAM,\n                format!(\n                    \"Graceful Restart capability is {} bytes; expected 2 + 4*N\",\n                    value.len()\n                ),\n            ));\n        }\n        let word = u16::from_be_bytes([value[0], value[1]]);\n        let mut families = Vec::new();\n        for chunk in value[2..].chunks_exact(4) {\n            let family = BgpGracefulRestartFamily::new(\n                AfiSafi::new(u16::from_be_bytes([chunk[0], chunk[1]]), chunk[2]),\n                chunk[3] & BGP_GR_FORWARDING_STATE != 0,\n            );\n            if !families.contains(&family) {\n                families.push(family);\n            }\n        }\n        Ok(BgpGracefulRestartCapability {\n            restarting: word & BGP_GR_RESTART_STATE != 0,\n            restart_time: word & BGP_GR_MAX_RESTART_TIME,\n            families,\n        })\n    }\n}\n\n/// One decoded capability.\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """pub enum BgpCapability {\n    MultiProtocol(AfiSafi),\n    FourOctetAs(u32),\n    RouteRefresh,\n    Unknown { code: u8, value: Vec<u8> },\n}\n""",
    """pub enum BgpCapability {\n    MultiProtocol(AfiSafi),\n    FourOctetAs(u32),\n    RouteRefresh,\n    GracefulRestart(BgpGracefulRestartCapability),\n    Unknown { code: u8, value: Vec<u8> },\n}\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """            BgpCapability::FourOctetAs(_) => BGP_CAP_FOUR_OCTET_AS,\n            BgpCapability::RouteRefresh => BGP_CAP_ROUTE_REFRESH,\n            BgpCapability::Unknown { code, .. } => *code,\n""",
    """            BgpCapability::FourOctetAs(_) => BGP_CAP_FOUR_OCTET_AS,\n            BgpCapability::RouteRefresh => BGP_CAP_ROUTE_REFRESH,\n            BgpCapability::GracefulRestart(_) => BGP_CAP_GRACEFUL_RESTART,\n            BgpCapability::Unknown { code, .. } => *code,\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """            BgpCapability::FourOctetAs(asn) => asn.to_be_bytes().to_vec(),\n            BgpCapability::RouteRefresh => Vec::new(),\n            BgpCapability::Unknown { value, .. } => value.clone(),\n""",
    """            BgpCapability::FourOctetAs(asn) => asn.to_be_bytes().to_vec(),\n            BgpCapability::RouteRefresh => Vec::new(),\n            BgpCapability::GracefulRestart(gr) => gr.encode_value(),\n            BgpCapability::Unknown { value, .. } => value.clone(),\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """            BGP_CAP_ROUTE_REFRESH => {\n                if !value.is_empty() {\n                    return Err(BgpParseError::open(\n                        BGP_SUB_UNSUPPORTED_OPT_PARAM,\n                        \"Route Refresh capability must carry no value\",\n                    ));\n                }\n                Ok(BgpCapability::RouteRefresh)\n            }\n            other => Ok(BgpCapability::Unknown {\n""",
    """            BGP_CAP_ROUTE_REFRESH => {\n                if !value.is_empty() {\n                    return Err(BgpParseError::open(\n                        BGP_SUB_UNSUPPORTED_OPT_PARAM,\n                        \"Route Refresh capability must carry no value\",\n                    ));\n                }\n                Ok(BgpCapability::RouteRefresh)\n            }\n            BGP_CAP_GRACEFUL_RESTART => Ok(BgpCapability::GracefulRestart(\n                BgpGracefulRestartCapability::decode_value(value)?,\n            )),\n            other => Ok(BgpCapability::Unknown {\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """            BgpCapability::FourOctetAs(asn) => write!(f, \"Four-Octet AS {}\", asn),\n            BgpCapability::RouteRefresh => write!(f, \"Route Refresh\"),\n            BgpCapability::Unknown { code, value } => {\n""",
    """            BgpCapability::FourOctetAs(asn) => write!(f, \"Four-Octet AS {}\", asn),\n            BgpCapability::RouteRefresh => write!(f, \"Route Refresh\"),\n            BgpCapability::GracefulRestart(gr) => write!(\n                f,\n                \"Graceful Restart {}s{} ({} families)\",\n                gr.restart_time,\n                if gr.restarting { \" restarting\" } else { \"\" },\n                gr.families.len()\n            ),\n            BgpCapability::Unknown { code, value } => {\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """    /// True when the speaker advertised RFC 2918 Route Refresh.\n    pub fn supports_route_refresh(&self) -> bool {\n        self.capabilities\n            .iter()\n            .any(|c| matches!(c, BgpCapability::RouteRefresh))\n    }\n\n    /// Encodes the whole set as an OPEN optional parameter block.\n""",
    """    /// True when the speaker advertised RFC 2918 Route Refresh.\n    pub fn supports_route_refresh(&self) -> bool {\n        self.capabilities\n            .iter()\n            .any(|c| matches!(c, BgpCapability::RouteRefresh))\n    }\n\n    /// The RFC 4724 capability advertised by the speaker, if any.\n    pub fn graceful_restart(&self) -> Option<&BgpGracefulRestartCapability> {\n        self.capabilities.iter().find_map(|c| match c {\n            BgpCapability::GracefulRestart(gr) => Some(gr),\n            _ => None,\n        })\n    }\n\n    pub fn supports_graceful_restart(&self) -> bool {\n        self.graceful_restart().is_some()\n    }\n\n    /// Encodes the whole set as an OPEN optional parameter block.\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """        set.push(BgpCapability::FourOctetAs(4_200_000_001));\n        set.push(BgpCapability::RouteRefresh);\n        set\n""",
    """        set.push(BgpCapability::FourOctetAs(4_200_000_001));\n        set.push(BgpCapability::RouteRefresh);\n        set.push(BgpCapability::GracefulRestart(\n            BgpGracefulRestartCapability::new(120, false, vec![\n                BgpGracefulRestartFamily::new(AfiSafi::IPV4_UNICAST, true),\n                BgpGracefulRestartFamily::new(AfiSafi::L2VPN_EVPN, false),\n            ]),\n        ));\n        set\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """    #[test]\n    fn test_an_unknown_capability_is_kept_but_ignored() {\n""",
    """    #[test]\n    fn test_graceful_restart_round_trips_restart_and_forwarding_state() {\n        let gr = BgpGracefulRestartCapability::new(300, true, vec![\n            BgpGracefulRestartFamily::new(AfiSafi::IPV4_UNICAST, true),\n            BgpGracefulRestartFamily::new(AfiSafi::L2VPN_EVPN, false),\n        ]);\n        let mut set = BgpCapabilitySet::new();\n        set.push(BgpCapability::GracefulRestart(gr.clone()));\n        let decoded = BgpCapabilitySet::parse_opt_params(&set.encode_opt_params()).unwrap();\n        assert_eq!(decoded.graceful_restart(), Some(&gr));\n        assert!(decoded.supports_graceful_restart());\n        assert!(decoded.graceful_restart().unwrap().supports(AfiSafi::IPV4_UNICAST));\n    }\n\n    #[test]\n    fn test_malformed_graceful_restart_lengths_are_rejected() {\n        assert!(BgpCapability::decode(BGP_CAP_GRACEFUL_RESTART, &[]).is_err());\n        assert!(BgpCapability::decode(BGP_CAP_GRACEFUL_RESTART, &[0, 10, 0]).is_err());\n    }\n\n    #[test]\n    fn test_an_unknown_capability_is_kept_but_ignored() {\n""",
)

# ---------------------------------------------------------------------------
# RFC 4724 helper mode in the live BGP speaker
# ---------------------------------------------------------------------------
replace_once(
    "src/bgp_router.rs",
    """use crate::bgp_caps::{\n    AfiSafi, BGP_SUB_UNSUPPORTED_CAPABILITY, BgpCapability, BgpCapabilitySet,\n    NegotiatedCapabilities, negotiate,\n};\n""",
    """use crate::bgp_caps::{\n    AfiSafi, BGP_SUB_UNSUPPORTED_CAPABILITY, BgpCapability, BgpCapabilitySet,\n    BgpGracefulRestartCapability, BgpGracefulRestartFamily, NegotiatedCapabilities, negotiate,\n};\n""",
)

replace_once(
    "src/bgp_router.rs",
    """pub const BGP_SUB_MAX_PREFIXES: u8 = 1;\n\n/// BGP finite state machine states (RFC 4271 section 8).\n""",
    """pub const BGP_SUB_MAX_PREFIXES: u8 = 1;\n/// Default RFC 4724 helper retention time advertised in OPEN, in seconds.\npub const DEFAULT_GRACEFUL_RESTART_TIME: u16 = 120;\n\n/// BGP finite state machine states (RFC 4271 section 8).\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    /// Inbound connections refused or resolved away by collision handling.\n    pub collisions_resolved: u64,\n}\n""",
    """    /// Inbound connections refused or resolved away by collision handling.\n    pub collisions_resolved: u64,\n    /// Unexpected transport losses for which RFC 4724 stale-route retention began.\n    pub graceful_restarts_started: u64,\n    /// Address-family End-of-RIB markers that completed graceful restart early.\n    pub graceful_restart_eors: u64,\n    /// Graceful-restart procedures that reached the Restart Time deadline.\n    pub graceful_restart_expirations: u64,\n}\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    /// Families the peer asked us to replay. Keeping this separate from the\n    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.\n    refresh_pending: BTreeSet<AfiSafi>,\n    pub remote_router_id: Option<Ipv4Address>,\n""",
    """    /// Families the peer asked us to replay. Keeping this separate from the\n    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.\n    refresh_pending: BTreeSet<AfiSafi>,\n    /// Families whose routes are retained as RFC 4724 stale state after an\n    /// unexpected transport failure.\n    graceful_restart_stale: BTreeSet<AfiSafi>,\n    /// Absolute simulated deadline for stale-route retention.\n    graceful_restart_deadline: Option<u64>,\n    /// Time the restarting peer's replacement OPEN was accepted. Routes received\n    /// at or after this point are fresh; older ones remain stale until EOR.\n    graceful_restart_refresh_started_ms: Option<u64>,\n    pub remote_router_id: Option<Ipv4Address>,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            negotiated: NegotiatedCapabilities::default(),\n            refresh_pending: BTreeSet::new(),\n            remote_router_id: None,\n""",
    """            negotiated: NegotiatedCapabilities::default(),\n            refresh_pending: BTreeSet::new(),\n            graceful_restart_stale: BTreeSet::new(),\n            graceful_restart_deadline: None,\n            graceful_restart_refresh_started_ms: None,\n            remote_router_id: None,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    /// True while a second connection to this neighbour is being held pending\n    /// collision resolution.\n    pub fn has_collision(&self) -> bool {\n        self.collision.is_some()\n    }\n}\n""",
    """    /// True while a second connection to this neighbour is being held pending\n    /// collision resolution.\n    pub fn has_collision(&self) -> bool {\n        self.collision.is_some()\n    }\n\n    /// True while routes from this peer are being retained by RFC 4724 helper mode.\n    pub fn graceful_restart_active(&self) -> bool {\n        self.graceful_restart_deadline.is_some() && !self.graceful_restart_stale.is_empty()\n    }\n\n    pub fn graceful_restart_remaining_ms(&self, now_ms: u64) -> Option<u64> {\n        self.graceful_restart_deadline\n            .map(|d| d.saturating_sub(now_ms))\n    }\n\n    pub fn graceful_restart_stale_families(&self) -> Vec<AfiSafi> {\n        self.graceful_restart_stale.iter().copied().collect()\n    }\n}\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    /// Hold time proposed in our OPEN, in seconds.\n    pub hold_time: u16,\n    pub connect_retry_ms: u64,\n    peers: Vec<BgpPeer>,\n""",
    """    /// Hold time proposed in our OPEN, in seconds.\n    pub hold_time: u16,\n    pub connect_retry_ms: u64,\n    /// Whether this speaker advertises and acts as an RFC 4724 helper.\n    pub graceful_restart_enabled: bool,\n    /// Restart Time advertised in the Graceful Restart capability.\n    pub graceful_restart_time: u16,\n    peers: Vec<BgpPeer>,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            hold_time: DEFAULT_HOLD_TIME,\n            connect_retry_ms: DEFAULT_CONNECT_RETRY_MS,\n            peers: Vec::new(),\n""",
    """            hold_time: DEFAULT_HOLD_TIME,\n            connect_retry_ms: DEFAULT_CONNECT_RETRY_MS,\n            graceful_restart_enabled: true,\n            graceful_restart_time: DEFAULT_GRACEFUL_RESTART_TIME,\n            peers: Vec::new(),\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    pub fn set_connect_retry_ms(&mut self, ms: u64) {\n        self.connect_retry_ms = ms.max(1);\n    }\n\n    /// Configures a neighbour. Peers are kept sorted by address so every iteration\n""",
    """    pub fn set_connect_retry_ms(&mut self, ms: u64) {\n        self.connect_retry_ms = ms.max(1);\n    }\n\n    pub fn set_graceful_restart_enabled(&mut self, enabled: bool) {\n        self.graceful_restart_enabled = enabled;\n    }\n\n    pub fn set_graceful_restart_time(&mut self, seconds: u16) {\n        self.graceful_restart_time = seconds.min(crate::bgp_caps::BGP_GR_MAX_RESTART_TIME);\n    }\n\n    /// Configures a neighbour. Peers are kept sorted by address so every iteration\n""",
)

replace_once(
    "src/bgp_router.rs",
    """        for idx in 0..self.peers.len() {\n            self.service_peer(idx, now_ms, sockets);\n        }\n\n        if self.dirty {\n""",
    """        for idx in 0..self.peers.len() {\n            self.service_peer(idx, now_ms, sockets);\n        }\n\n        self.expire_graceful_restarts(now_ms);\n\n        if self.dirty {\n""",
)

replace_once(
    "src/bgp_router.rs",
    """        caps.push(BgpCapability::FourOctetAs(self.local_as));\n        caps.push(BgpCapability::RouteRefresh);\n        caps\n""",
    """        caps.push(BgpCapability::FourOctetAs(self.local_as));\n        caps.push(BgpCapability::RouteRefresh);\n        if self.graceful_restart_enabled {\n            caps.push(BgpCapability::GracefulRestart(\n                BgpGracefulRestartCapability::new(\n                    self.graceful_restart_time,\n                    false,\n                    self.families\n                        .iter()\n                        .copied()\n                        .map(|family| BgpGracefulRestartFamily::new(family, false))\n                        .collect(),\n                ),\n            ));\n        }\n        caps\n""",
)

replace_once(
    "src/bgp_router.rs",
    """                self.log(\n                    now_ms,\n                    addr,\n                    format!(\n                        \"capability negotiation: families [{}], 4-octet ASN {}, route refresh {}\",\n                        families.join(\", \"),\n                        if capabilities.four_octet_as {\n                            \"yes\"\n                        } else {\n                            \"no\"\n                        },\n                        if capabilities.route_refresh { \"yes\" } else { \"no\" }\n                    ),\n                );\n                self.peers[idx].negotiated = capabilities;\n""",
    """                self.log(\n                    now_ms,\n                    addr,\n                    format!(\n                        \"capability negotiation: families [{}], 4-octet ASN {}, route refresh {}, graceful restart {}\",\n                        families.join(\", \"),\n                        if capabilities.four_octet_as {\n                            \"yes\"\n                        } else {\n                            \"no\"\n                        },\n                        if capabilities.route_refresh { \"yes\" } else { \"no\" },\n                        if peer_caps.supports_graceful_restart() && self.graceful_restart_enabled {\n                            \"yes\"\n                        } else {\n                            \"no\"\n                        }\n                    ),\n                );\n                self.reconcile_graceful_restart_open(idx, now_ms, &capabilities, &peer_caps);\n                self.peers[idx].negotiated = capabilities;\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            (BgpState::Established, BgpPdu::Update(update)) => {\n                self.peers[idx].counters.updates_received += 1;\n                if let Err(t) = self.import_mp_update(idx, now_ms, &update) {\n                    return Some(t);\n                }\n                match self.import_update(idx, now_ms, update) {\n                    Ok(()) => None,\n                    Err(note) => {\n                        let reason = format!(\n                            \"rejected UPDATE: code {}/{}\",\n                            note.error_code, note.error_subcode\n                        );\n                        Some(Teardown::Protocol(note, reason))\n                    }\n                }\n            }\n""",
    """            (BgpState::Established, BgpPdu::Update(update)) => {\n                self.peers[idx].counters.updates_received += 1;\n                let ipv4_eor = update.is_end_of_rib();\n                let evpn_eor = update\n                    .mp_unreach()\n                    .is_some_and(|m| m.family() == AfiSafi::L2VPN_EVPN && m.nlri.is_empty());\n                if let Err(t) = self.import_mp_update(idx, now_ms, &update) {\n                    return Some(t);\n                }\n                match self.import_update(idx, now_ms, update) {\n                    Ok(()) => {\n                        if ipv4_eor {\n                            self.complete_graceful_restart_family(\n                                idx,\n                                AfiSafi::IPV4_UNICAST,\n                                now_ms,\n                            );\n                        }\n                        if evpn_eor {\n                            self.complete_graceful_restart_family(\n                                idx,\n                                AfiSafi::L2VPN_EVPN,\n                                now_ms,\n                            );\n                        }\n                        None\n                    }\n                    Err(note) => {\n                        let reason = format!(\n                            \"rejected UPDATE: code {}/{}\",\n                            note.error_code, note.error_subcode\n                        );\n                        Some(Teardown::Protocol(note, reason))\n                    }\n                }\n            }\n""",
)

# Insert helper methods immediately before send_pdu/teardown section.
replace_once(
    "src/bgp_router.rs",
    """    /// Writes a message, but only if the send buffer can take all of it: a BGP\n    /// message must never be split across a partial write.\n    fn send_pdu(&mut self, idx: usize, sockets: &mut SocketRuntime, pdu: &BgpPdu) -> bool {\n""",
    """    fn route_is_graceful_restart_stale(\n        &self,\n        peer_addr: Ipv4Address,\n        family: AfiSafi,\n        received_at_ms: u64,\n    ) -> bool {\n        let Some(peer) = self.peer(peer_addr) else {\n            return false;\n        };\n        if !peer.graceful_restart_stale.contains(&family) {\n            return false;\n        }\n        peer.graceful_restart_refresh_started_ms\n            .is_none_or(|cutoff| received_at_ms < cutoff)\n    }\n\n    fn purge_graceful_restart_stale_family(&mut self, idx: usize, family: AfiSafi) -> usize {\n        let addr = self.peers[idx].addr;\n        let cutoff = self.peers[idx].graceful_restart_refresh_started_ms;\n        match family {\n            AfiSafi::IPV4_UNICAST => {\n                let stale: Vec<Ipv4Prefix> = self\n                    .adj_rib_in\n                    .peer_table(addr)\n                    .into_iter()\n                    .flat_map(|table| table.iter())\n                    .filter(|(_, path)| cutoff.is_none_or(|t| path.received_at_ms < t))\n                    .map(|(prefix, _)| *prefix)\n                    .collect();\n                for prefix in &stale {\n                    self.adj_rib_in.remove(addr, *prefix);\n                }\n                if !stale.is_empty() {\n                    self.dirty = true;\n                }\n                stale.len()\n            }\n            AfiSafi::L2VPN_EVPN => {\n                let stale: Vec<EvpnRouteKey> = self\n                    .evpn_adj_rib_in\n                    .peer_table(addr)\n                    .into_iter()\n                    .flat_map(|table| table.iter())\n                    .filter(|(_, path)| cutoff.is_none_or(|t| path.received_at_ms < t))\n                    .map(|(key, _)| key.clone())\n                    .collect();\n                for key in &stale {\n                    self.evpn_adj_rib_in.remove(addr, key);\n                }\n                if !stale.is_empty() {\n                    self.evpn_dirty = true;\n                }\n                stale.len()\n            }\n            _ => 0,\n        }\n    }\n\n    fn complete_graceful_restart_family(\n        &mut self,\n        idx: usize,\n        family: AfiSafi,\n        now_ms: u64,\n    ) {\n        if !self.peers[idx].graceful_restart_stale.contains(&family) {\n            return;\n        }\n        let addr = self.peers[idx].addr;\n        let purged = self.purge_graceful_restart_stale_family(idx, family);\n        self.peers[idx].graceful_restart_stale.remove(&family);\n        self.peers[idx].counters.graceful_restart_eors += 1;\n        if self.peers[idx].graceful_restart_stale.is_empty() {\n            self.peers[idx].graceful_restart_deadline = None;\n            self.peers[idx].graceful_restart_refresh_started_ms = None;\n        }\n        self.log(\n            now_ms,\n            addr,\n            format!(\n                \"Graceful Restart EOR for {}; removed {} stale route(s)\",\n                family, purged\n            ),\n        );\n    }\n\n    fn flush_graceful_restart(&mut self, idx: usize, now_ms: u64, reason: &str) {\n        let addr = self.peers[idx].addr;\n        let families: Vec<AfiSafi> = self.peers[idx]\n            .graceful_restart_stale\n            .iter()\n            .copied()\n            .collect();\n        let mut purged = 0usize;\n        for family in families {\n            purged += self.purge_graceful_restart_stale_family(idx, family);\n        }\n        self.peers[idx].graceful_restart_stale.clear();\n        self.peers[idx].graceful_restart_deadline = None;\n        self.peers[idx].graceful_restart_refresh_started_ms = None;\n        self.log(\n            now_ms,\n            addr,\n            format!(\"Graceful Restart ended: {}; purged {} stale route(s)\", reason, purged),\n        );\n    }\n\n    fn reconcile_graceful_restart_open(\n        &mut self,\n        idx: usize,\n        now_ms: u64,\n        negotiated: &NegotiatedCapabilities,\n        peer_caps: &BgpCapabilitySet,\n    ) {\n        if !self.peers[idx].graceful_restart_active() {\n            return;\n        }\n        let Some(gr) = peer_caps.graceful_restart() else {\n            self.flush_graceful_restart(idx, now_ms, \"peer reconnected without RFC 4724\");\n            return;\n        };\n        if !gr.restarting {\n            self.flush_graceful_restart(idx, now_ms, \"peer did not set Restart State\");\n            return;\n        }\n\n        let supported: BTreeSet<AfiSafi> = gr\n            .families\n            .iter()\n            .map(|f| f.family)\n            .filter(|family| negotiated.supports(*family))\n            .collect();\n        let dropped: Vec<AfiSafi> = self.peers[idx]\n            .graceful_restart_stale\n            .difference(&supported)\n            .copied()\n            .collect();\n        for family in dropped {\n            self.purge_graceful_restart_stale_family(idx, family);\n            self.peers[idx].graceful_restart_stale.remove(&family);\n        }\n        self.peers[idx].graceful_restart_refresh_started_ms = Some(now_ms);\n        if self.peers[idx].graceful_restart_stale.is_empty() {\n            self.peers[idx].graceful_restart_deadline = None;\n            self.peers[idx].graceful_restart_refresh_started_ms = None;\n        } else {\n            self.log(now_ms, self.peers[idx].addr, \"peer signalled RFC 4724 Restart State; waiting for End-of-RIB\");\n        }\n    }\n\n    fn expire_graceful_restarts(&mut self, now_ms: u64) {\n        let expired: Vec<usize> = self\n            .peers\n            .iter()\n            .enumerate()\n            .filter(|(_, peer)| peer.graceful_restart_deadline.is_some_and(|d| now_ms >= d))\n            .map(|(idx, _)| idx)\n            .collect();\n        for idx in expired {\n            self.peers[idx].counters.graceful_restart_expirations += 1;\n            self.flush_graceful_restart(idx, now_ms, \"Restart Time expired\");\n        }\n    }\n\n    /// Writes a message, but only if the send buffer can take all of it: a BGP\n    /// message must never be split across a partial write.\n    fn send_pdu(&mut self, idx: usize, sockets: &mut SocketRuntime, pdu: &BgpPdu) -> bool {\n""",
)

# Replace teardown wholesale so transport failure can preserve selected families.
p = Path("src/bgp_router.rs")
text = p.read_text(encoding="utf-8")
start = text.index("    /// Ends a session: tell the peer if we still can, drop the transport, purge\n")
end = text.index("    // ========================================================================\n    // Import\n", start)
new_teardown = r'''    /// Ends a session. RFC 4724 changes one important part of the ordinary
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

'''
p.write_text(text[:start] + new_teardown + text[end:], encoding="utf-8")

# Prefer fresh paths over RFC 4724 stale paths when a replacement exists.
replace_once(
    "src/bgp_router.rs",
    """        for prefix in prefixes {\n            let learned = self.adj_rib_in.candidates(prefix);\n            let local = self\n                .originated\n                .get(&prefix)\n                .map(|nh| BgpPath::local(prefix, *nh, self.router_id));\n\n            let mut candidates: Vec<&BgpPath> = learned;\n""",
    """        for prefix in prefixes {\n            let learned = self.adj_rib_in.candidates(prefix);\n            let fresh: Vec<&BgpPath> = learned\n                .iter()\n                .copied()\n                .filter(|path| {\n                    !self.route_is_graceful_restart_stale(\n                        path.peer_addr,\n                        AfiSafi::IPV4_UNICAST,\n                        path.received_at_ms,\n                    )\n                })\n                .collect();\n            let local = self\n                .originated\n                .get(&prefix)\n                .map(|nh| BgpPath::local(prefix, *nh, self.router_id));\n\n            let mut candidates: Vec<&BgpPath> = if fresh.is_empty() { learned } else { fresh };\n""",
)

replace_once(
    "src/bgp_router.rs",
    """        for key in keys {\n            let learned = self.evpn_adj_rib_in.candidates(&key);\n            let local = self\n                .evpn_originated\n                .get(&key)\n                .map(|r| EvpnPath::local(r.clone(), self.router_id, now_ms));\n\n            let mut candidates: Vec<&EvpnPath> = learned;\n""",
    """        for key in keys {\n            let learned = self.evpn_adj_rib_in.candidates(&key);\n            let fresh: Vec<&EvpnPath> = learned\n                .iter()\n                .copied()\n                .filter(|path| {\n                    !self.route_is_graceful_restart_stale(\n                        path.peer_addr,\n                        AfiSafi::L2VPN_EVPN,\n                        path.received_at_ms,\n                    )\n                })\n                .collect();\n            let local = self\n                .evpn_originated\n                .get(&key)\n                .map(|r| EvpnPath::local(r.clone(), self.router_id, now_ms));\n\n            let mut candidates: Vec<&EvpnPath> = if fresh.is_empty() { learned } else { fresh };\n""",
)

# Add diagnostics to peer output.
replace_once(
    "src/bgp_router.rs",
    """            s.push_str(&format!(\n                \"  prefixes received {}  advertised {}\\n\",\n                p.prefixes_received, p.prefixes_advertised\n            ));\n""",
    """            s.push_str(&format!(\n                \"  prefixes received {}  advertised {}\\n\",\n                p.prefixes_received, p.prefixes_advertised\n            ));\n            if let Some(peer) = self.peer(p.addr)\n                && peer.graceful_restart_active()\n            {\n                s.push_str(&format!(\n                    \"  graceful-restart stale {:?} remaining {}ms\\n\",\n                    peer.graceful_restart_stale_families(),\n                    peer.graceful_restart_remaining_ms(now_ms).unwrap_or(0)\n                ));\n            }\n""",
)

# ---------------------------------------------------------------------------
# Integration coverage
# ---------------------------------------------------------------------------
TEST = r'''//! RFC 4724 Graceful Restart helper-mode integration tests.
//!
//! The failure path is a real TCP transport loss in the virtual lab. Nothing
//! directly edits the BGP RIBs: the helper must decide to retain or purge them.

mod common;

use common::bgp_lab::{build_linear_lab, converge_sessions, ip, prefix, run_until};
use toy_tcpip::bgp_caps::{AfiSafi, BGP_GR_MAX_RESTART_TIME};
use toy_tcpip::bgp_router::{BgpState, DEFAULT_GRACEFUL_RESTART_TIME};

#[test]
fn test_open_advertises_rfc4724_for_negotiated_families() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));

    let peer = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap();
    let gr = peer
        .negotiated
        .peer
        .graceful_restart()
        .expect("peer did not advertise RFC 4724");
    assert_eq!(gr.restart_time, DEFAULT_GRACEFUL_RESTART_TIME);
    assert!(!gr.restarting);
    assert!(gr.supports(AfiSafi::IPV4_UNICAST));
}

#[test]
fn test_transport_failure_retains_routes_until_restart_time_expires() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned)
    }));

    let now = lab.current_time_ms;
    let stream = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap()
        .stream
        .expect("session has no TCP stream");

    // Prevent an immediate reconnect, then kill the live transport from underneath
    // BGP. This exercises Teardown::Transport rather than an administrative Cease.
    lab.link_mut("r1r2").unwrap().set_blackhole(true);
    lab.router_mut("r1")
        .unwrap()
        .sockets
        .as_mut()
        .unwrap()
        .tcp_abort(stream, now);
    lab.run_pumped(50);

    let peer = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap();
    assert_ne!(peer.state, BgpState::Established);
    assert!(peer.graceful_restart_active());
    assert_eq!(peer.counters.graceful_restarts_started, 1);
    assert!(peer.graceful_restart_stale_families().contains(&AfiSafi::IPV4_UNICAST));
    assert!(
        lab.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned),
        "helper dropped a route immediately instead of retaining it"
    );

    // It remains usable well inside the peer-advertised Restart Time.
    lab.advance_time((DEFAULT_GRACEFUL_RESTART_TIME as u64 * 1_000) / 2);
    lab.run_pumped(50);
    assert!(lab.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned));

    // Once the deadline passes, stale state is purged and the decision process
    // removes the route normally.
    lab.advance_time((DEFAULT_GRACEFUL_RESTART_TIME as u64 * 1_000) / 2 + 1_000);
    lab.run_pumped(100);
    let bgp = lab.router("r1").unwrap().bgp().unwrap();
    assert!(!bgp.loc_rib.contains(&learned));
    let peer = bgp.peer(ip(10, 12, 0, 2)).unwrap();
    assert!(!peer.graceful_restart_active());
    assert_eq!(peer.counters.graceful_restart_expirations, 1);
}

#[test]
fn test_peer_without_graceful_restart_is_purged_immediately() {
    let mut lab = build_linear_lab();
    lab.router_mut("r2")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_graceful_restart_enabled(false);
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r1").unwrap().bgp().unwrap().loc_rib.contains(&learned)
    }));

    let now = lab.current_time_ms;
    let stream = lab
        .router("r1")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 12, 0, 2))
        .unwrap()
        .stream
        .unwrap();
    lab.link_mut("r1r2").unwrap().set_blackhole(true);
    lab.router_mut("r1")
        .unwrap()
        .sockets
        .as_mut()
        .unwrap()
        .tcp_abort(stream, now);
    lab.run_pumped(100);

    let bgp = lab.router("r1").unwrap().bgp().unwrap();
    assert!(!bgp.peer(ip(10, 12, 0, 2)).unwrap().graceful_restart_active());
    assert!(!bgp.loc_rib.contains(&learned));
}

#[test]
fn test_restart_time_is_bounded_to_the_rfc_field_width() {
    let mut lab = build_linear_lab();
    lab.router_mut("r1")
        .unwrap()
        .bgp_mut()
        .unwrap()
        .set_graceful_restart_time(u16::MAX);
    assert_eq!(
        lab.router("r1").unwrap().bgp().unwrap().graceful_restart_time,
        BGP_GR_MAX_RESTART_TIME
    );
}
'''
Path("tests/test_bgp_graceful_restart.rs").write_text(TEST, encoding="utf-8")

print("RFC 4724 Graceful Restart helper-mode patches applied")
