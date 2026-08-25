from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement, found {count}\n--- old ---\n{old[:500]}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def replace_section(path: str, start_marker: str, end_marker: str, new_section: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new_section in text:
        return
    start = text.find(start_marker)
    if start < 0:
        raise RuntimeError(f"{path}: start marker not found: {start_marker}")
    end = text.find(end_marker, start)
    if end < 0:
        raise RuntimeError(f"{path}: end marker not found: {end_marker}")
    p.write_text(text[:start] + new_section + text[end:], encoding="utf-8")


# ---------------------------------------------------------------------------
# RFC 2918 capability negotiation
# ---------------------------------------------------------------------------
replace_once(
    "src/bgp_caps.rs",
    """    pub fn supports_four_octet_as(&self) -> bool {\n        self.four_octet_as().is_some()\n    }\n\n    /// Encodes the whole set as an OPEN optional parameter block.\n""",
    """    pub fn supports_four_octet_as(&self) -> bool {\n        self.four_octet_as().is_some()\n    }\n\n    /// True when the speaker advertised RFC 2918 Route Refresh.\n    pub fn supports_route_refresh(&self) -> bool {\n        self.capabilities\n            .iter()\n            .any(|c| matches!(c, BgpCapability::RouteRefresh))\n    }\n\n    /// Encodes the whole set as an OPEN optional parameter block.\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """    /// True when both ends sent the Four-Octet AS capability, which is what\n    /// decides whether AS_PATH on this session carries 2- or 4-octet ASNs.\n    pub four_octet_as: bool,\n    /// Everything the peer offered, kept verbatim for diagnostics.\n""",
    """    /// True when both ends sent the Four-Octet AS capability, which is what\n    /// decides whether AS_PATH on this session carries 2- or 4-octet ASNs.\n    pub four_octet_as: bool,\n    /// True when both ends advertised RFC 2918 Route Refresh.\n    pub route_refresh: bool,\n    /// Everything the peer offered, kept verbatim for diagnostics.\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """    pub fn supports_evpn(&self) -> bool {\n        self.supports(AfiSafi::L2VPN_EVPN)\n    }\n}\n""",
    """    pub fn supports_evpn(&self) -> bool {\n        self.supports(AfiSafi::L2VPN_EVPN)\n    }\n\n    pub fn supports_route_refresh(&self) -> bool {\n        self.route_refresh\n    }\n}\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """        four_octet_as: local.supports_four_octet_as() && peer.supports_four_octet_as(),\n        peer: peer.clone(),\n""",
    """        four_octet_as: local.supports_four_octet_as() && peer.supports_four_octet_as(),\n        route_refresh: local.supports_route_refresh() && peer.supports_route_refresh(),\n        peer: peer.clone(),\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """        set.push(BgpCapability::FourOctetAs(4_200_000_001));\n        set\n""",
    """        set.push(BgpCapability::FourOctetAs(4_200_000_001));\n        set.push(BgpCapability::RouteRefresh);\n        set\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """        assert!(!n.supports_evpn());\n        assert!(!n.four_octet_as);\n    }\n\n    #[test]\n    fn test_evpn_is_negotiated_only_when_both_ends_offer_it() {\n""",
    """        assert!(!n.supports_evpn());\n        assert!(!n.four_octet_as);\n        assert!(!n.route_refresh);\n    }\n\n    #[test]\n    fn test_evpn_is_negotiated_only_when_both_ends_offer_it() {\n""",
)

replace_once(
    "src/bgp_caps.rs",
    """    #[test]\n    fn test_an_unknown_capability_is_kept_but_ignored() {\n""",
    """    #[test]\n    fn test_route_refresh_is_negotiated_only_when_both_ends_offer_it() {\n        let full = full_set();\n        let mut without_refresh = full_set();\n        without_refresh\n            .capabilities\n            .retain(|c| !matches!(c, BgpCapability::RouteRefresh));\n\n        assert!(negotiate(&full, &full).supports_route_refresh());\n        assert!(!negotiate(&full, &without_refresh).supports_route_refresh());\n        assert!(!negotiate(&without_refresh, &full).supports_route_refresh());\n    }\n\n    #[test]\n    fn test_an_unknown_capability_is_kept_but_ignored() {\n""",
)

# ---------------------------------------------------------------------------
# RFC 2918 wire message (BGP message type 5)
# ---------------------------------------------------------------------------
replace_once(
    "src/bgp.rs",
    "use crate::bgp_caps::BgpCapabilitySet;\n",
    "use crate::bgp_caps::{AfiSafi, BgpCapabilitySet};\n",
)

replace_once(
    "src/bgp.rs",
    """pub const BGP_MSG_NOTIFICATION: u8 = 3;\npub const BGP_MSG_KEEPALIVE: u8 = 4;\n""",
    """pub const BGP_MSG_NOTIFICATION: u8 = 3;\npub const BGP_MSG_KEEPALIVE: u8 = 4;\n/// ROUTE-REFRESH (RFC 2918).\npub const BGP_MSG_ROUTE_REFRESH: u8 = 5;\n""",
)

replace_once(
    "src/bgp.rs",
    """/// A fully decoded BGP protocol data unit.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub enum BgpPdu {\n""",
    """/// RFC 2918 ROUTE-REFRESH request. The four-byte body names exactly one\n/// address family whose routes the peer asks us to advertise again.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct BgpRouteRefreshMessage {\n    pub family: AfiSafi,\n}\n\nimpl BgpRouteRefreshMessage {\n    pub const fn new(family: AfiSafi) -> Self {\n        BgpRouteRefreshMessage { family }\n    }\n\n    fn encode_body(&self) -> Vec<u8> {\n        let mut body = Vec::with_capacity(4);\n        body.extend_from_slice(&self.family.afi.to_be_bytes());\n        body.push(0); // Reserved, sent as zero and ignored by receivers.\n        body.push(self.family.safi);\n        body\n    }\n\n    fn parse_body(body: &[u8]) -> Result<Self, BgpParseError> {\n        if body.len() != 4 {\n            return Err(BgpParseError::header(\n                BGP_SUB_BAD_MESSAGE_LENGTH,\n                format!(\n                    \"ROUTE-REFRESH body is {} bytes, must be exactly 4\",\n                    body.len()\n                ),\n            ));\n        }\n        Ok(BgpRouteRefreshMessage {\n            family: AfiSafi::new(u16::from_be_bytes([body[0], body[1]]), body[3]),\n        })\n    }\n}\n\n/// A fully decoded BGP protocol data unit.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub enum BgpPdu {\n""",
)

replace_once(
    "src/bgp.rs",
    """    Notification(BgpNotificationMessage),\n    Keepalive,\n}\n""",
    """    Notification(BgpNotificationMessage),\n    Keepalive,\n    RouteRefresh(BgpRouteRefreshMessage),\n}\n""",
)

replace_once(
    "src/bgp.rs",
    """            BgpPdu::Notification(_) => BGP_MSG_NOTIFICATION,\n            BgpPdu::Keepalive => BGP_MSG_KEEPALIVE,\n""",
    """            BgpPdu::Notification(_) => BGP_MSG_NOTIFICATION,\n            BgpPdu::Keepalive => BGP_MSG_KEEPALIVE,\n            BgpPdu::RouteRefresh(_) => BGP_MSG_ROUTE_REFRESH,\n""",
)

replace_once(
    "src/bgp.rs",
    """            BgpPdu::Notification(_) => \"NOTIFICATION\",\n            BgpPdu::Keepalive => \"KEEPALIVE\",\n""",
    """            BgpPdu::Notification(_) => \"NOTIFICATION\",\n            BgpPdu::Keepalive => \"KEEPALIVE\",\n            BgpPdu::RouteRefresh(_) => \"ROUTE-REFRESH\",\n""",
)

replace_once(
    "src/bgp.rs",
    """            BgpPdu::Keepalive => Vec::new(),\n        };\n""",
    """            BgpPdu::Keepalive => Vec::new(),\n            BgpPdu::RouteRefresh(r) => r.encode_body(),\n        };\n""",
)

replace_once(
    "src/bgp.rs",
    """            BGP_MSG_KEEPALIVE => {\n                if !body.is_empty() {\n                    return Err(BgpParseError::header(\n                        BGP_SUB_BAD_MESSAGE_LENGTH,\n                        \"KEEPALIVE must be exactly 19 bytes\",\n                    ));\n                }\n                Ok(BgpPdu::Keepalive)\n            }\n            other => Err(BgpParseError::header(\n""",
    """            BGP_MSG_KEEPALIVE => {\n                if !body.is_empty() {\n                    return Err(BgpParseError::header(\n                        BGP_SUB_BAD_MESSAGE_LENGTH,\n                        \"KEEPALIVE must be exactly 19 bytes\",\n                    ));\n                }\n                Ok(BgpPdu::Keepalive)\n            }\n            BGP_MSG_ROUTE_REFRESH => Ok(BgpPdu::RouteRefresh(\n                BgpRouteRefreshMessage::parse_body(body)?,\n            )),\n            other => Err(BgpParseError::header(\n""",
)

replace_once(
    "src/bgp.rs",
    """        BGP_MSG_NOTIFICATION => BGP_HEADER_LEN + 2,\n        BGP_MSG_KEEPALIVE => BGP_HEADER_LEN,\n        other => {\n""",
    """        BGP_MSG_NOTIFICATION => BGP_HEADER_LEN + 2,\n        BGP_MSG_KEEPALIVE => BGP_HEADER_LEN,\n        BGP_MSG_ROUTE_REFRESH => BGP_HEADER_LEN + 4,\n        other => {\n""",
)

replace_once(
    "src/bgp.rs",
    """    #[test]\n    fn test_as_path_length_counts_a_set_as_one_hop() {\n""",
    """    #[test]\n    fn test_route_refresh_round_trips_and_has_an_exact_four_byte_body() {\n        let sent = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(AfiSafi::L2VPN_EVPN));\n        let mut raw = sent.serialize();\n        assert_eq!(raw.len(), BGP_HEADER_LEN + 4);\n        assert_eq!(raw[18], BGP_MSG_ROUTE_REFRESH);\n        assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);\n\n        // The reserved octet is ignored on receipt as RFC 2918 requires.\n        raw[21] = 0x7f;\n        assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);\n\n        // A fifth body byte is not padding: the message has exactly one shape.\n        raw.push(0);\n        raw[16..18].copy_from_slice(&((BGP_HEADER_LEN + 5) as u16).to_be_bytes());\n        assert!(BgpPdu::parse(&raw).is_err());\n    }\n\n    #[test]\n    fn test_as_path_length_counts_a_set_as_one_hop() {\n""",
)

# ---------------------------------------------------------------------------
# Packet-driven speaker: negotiate, request, receive, and replay Adj-RIB-Out
# ---------------------------------------------------------------------------
replace_once(
    "src/bgp_router.rs",
    """    BGP_VERSION, BgpFramer, BgpNotificationMessage, BgpOpenMessage, BgpParseError,\n    BgpPathAttributes, BgpPdu, BgpUpdateMessage, Ipv4Prefix, MAX_CLUSTER_LIST_LEN,\n""",
    """    BGP_VERSION, BgpFramer, BgpNotificationMessage, BgpOpenMessage, BgpParseError,\n    BgpPathAttributes, BgpPdu, BgpRouteRefreshMessage, BgpUpdateMessage, Ipv4Prefix,\n    MAX_CLUSTER_LIST_LEN,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    pub keepalives_sent: u64,\n    pub keepalives_received: u64,\n    pub notifications_sent: u64,\n""",
    """    pub keepalives_sent: u64,\n    pub keepalives_received: u64,\n    /// RFC 2918 requests sent to this peer.\n    pub route_refreshes_sent: u64,\n    /// RFC 2918 requests received from this peer.\n    pub route_refreshes_received: u64,\n    pub notifications_sent: u64,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    pub negotiated: NegotiatedCapabilities,\n    pub remote_router_id: Option<Ipv4Address>,\n""",
    """    pub negotiated: NegotiatedCapabilities,\n    /// Families the peer asked us to replay. Keeping this separate from the\n    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.\n    refresh_pending: BTreeSet<AfiSafi>,\n    pub remote_router_id: Option<Ipv4Address>,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            negotiated: NegotiatedCapabilities::default(),\n            remote_router_id: None,\n""",
    """            negotiated: NegotiatedCapabilities::default(),\n            refresh_pending: BTreeSet::new(),\n            remote_router_id: None,\n""",
)

replace_once(
    "src/bgp_router.rs",
    """    /// Re-enables a peer that was administratively shut down.\n    pub fn enable_peer(&mut self, addr: Ipv4Address) {\n        if let Some(p) = self.peer_mut(addr) {\n            p.admin_up = true;\n            p.connect_retry_deadline = None;\n        }\n    }\n\n    pub fn events(&self) -> &[BgpEvent] {\n""",
    """    /// Re-enables a peer that was administratively shut down.\n    pub fn enable_peer(&mut self, addr: Ipv4Address) {\n        if let Some(p) = self.peer_mut(addr) {\n            p.admin_up = true;\n            p.connect_retry_deadline = None;\n        }\n    }\n\n    /// Requests a soft outbound replay from a peer without resetting the TCP/BGP\n    /// session. The request is sent only for a negotiated family and only when\n    /// both ends advertised the RFC 2918 capability.\n    pub fn request_route_refresh(\n        &mut self,\n        addr: Ipv4Address,\n        family: AfiSafi,\n        now_ms: u64,\n        sockets: &mut SocketRuntime,\n    ) -> bool {\n        let Some(idx) = self.peers.iter().position(|p| p.addr == addr) else {\n            return false;\n        };\n        let allowed = {\n            let peer = &self.peers[idx];\n            peer.is_established()\n                && peer.negotiated.supports_route_refresh()\n                && peer.negotiated.supports(family)\n        };\n        if !allowed {\n            return false;\n        }\n\n        let pdu = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(family));\n        if !self.send_pdu(idx, sockets, &pdu) {\n            return false;\n        }\n        self.peers[idx].counters.route_refreshes_sent += 1;\n        self.log(now_ms, addr, format!(\"sent ROUTE-REFRESH for {}\", family));\n        true\n    }\n\n    pub fn events(&self) -> &[BgpEvent] {\n""",
)

replace_once(
    "src/bgp_router.rs",
    """        caps.push(BgpCapability::FourOctetAs(self.local_as));\n        caps\n""",
    """        caps.push(BgpCapability::FourOctetAs(self.local_as));\n        caps.push(BgpCapability::RouteRefresh);\n        caps\n""",
)

replace_once(
    "src/bgp_router.rs",
    """                        \"capability negotiation: families [{}], 4-octet ASN {}\",\n                        families.join(\", \"),\n                        if capabilities.four_octet_as {\n                            \"yes\"\n                        } else {\n                            \"no\"\n                        }\n""",
    """                        \"capability negotiation: families [{}], 4-octet ASN {}, route refresh {}\",\n                        families.join(\", \"),\n                        if capabilities.four_octet_as {\n                            \"yes\"\n                        } else {\n                            \"no\"\n                        },\n                        if capabilities.route_refresh { \"yes\" } else { \"no\" }\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            (_, BgpPdu::Notification(note)) => {\n""",
    """            (BgpState::Established, BgpPdu::RouteRefresh(refresh)) => {\n                if !self.peers[idx].negotiated.supports_route_refresh() {\n                    self.log(\n                        now_ms,\n                        addr,\n                        format!(\n                            \"ignored ROUTE-REFRESH for {}: capability was not negotiated\",\n                            refresh.family\n                        ),\n                    );\n                    return None;\n                }\n                if !self.peers[idx].negotiated.supports(refresh.family) {\n                    self.log(\n                        now_ms,\n                        addr,\n                        format!(\n                            \"ignored ROUTE-REFRESH for {}: family was not negotiated\",\n                            refresh.family\n                        ),\n                    );\n                    return None;\n                }\n                self.peers[idx].counters.route_refreshes_received += 1;\n                self.peers[idx].refresh_pending.insert(refresh.family);\n                self.log(\n                    now_ms,\n                    addr,\n                    format!(\"received ROUTE-REFRESH for {}; scheduling replay\", refresh.family),\n                );\n                None\n            }\n\n            (_, BgpPdu::Notification(note)) => {\n""",
)

replace_once(
    "src/bgp_router.rs",
    """        peer.negotiated = NegotiatedCapabilities::default();\n        peer.remote_router_id = None;\n""",
    """        peer.negotiated = NegotiatedCapabilities::default();\n        peer.refresh_pending.clear();\n        peer.remote_router_id = None;\n""",
)

new_ipv4_advertise = r'''    fn advertise_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
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

'''
replace_section(
    "src/bgp_router.rs",
    "    fn advertise_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {",
    "    /// How many IPv4 prefixes the RFC 4456 rules are currently withholding from",
    new_ipv4_advertise,
)

new_evpn_advertise = r'''    fn advertise_evpn_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {
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

'''
replace_section(
    "src/bgp_router.rs",
    "    fn advertise_evpn_to_peer(&mut self, idx: usize, now_ms: u64, sockets: &mut SocketRuntime) {",
    "    /// The attribute set for one EVPN advertisement.",
    new_evpn_advertise,
)

replace_once(
    "src/bgp_router.rs",
    """                + p.counters.keepalives_received\n                + p.counters.notifications_received;\n            let msg_sent = p.counters.opens_sent\n                + p.counters.updates_sent\n                + p.counters.keepalives_sent\n                + p.counters.notifications_sent;\n""",
    """                + p.counters.keepalives_received\n                + p.counters.route_refreshes_received\n                + p.counters.notifications_received;\n            let msg_sent = p.counters.opens_sent\n                + p.counters.updates_sent\n                + p.counters.keepalives_sent\n                + p.counters.route_refreshes_sent\n                + p.counters.notifications_sent;\n""",
)

replace_once(
    "src/bgp_router.rs",
    """            s.push_str(&format!(\n                \"  messages open {}/{} update {}/{} keepalive {}/{} notification {}/{} (rcvd/sent)\\n\",\n                p.counters.opens_received,\n                p.counters.opens_sent,\n                p.counters.updates_received,\n                p.counters.updates_sent,\n                p.counters.keepalives_received,\n                p.counters.keepalives_sent,\n                p.counters.notifications_received,\n                p.counters.notifications_sent\n            ));\n""",
    """            s.push_str(&format!(\n                \"  messages open {}/{} update {}/{} keepalive {}/{} route-refresh {}/{} notification {}/{} (rcvd/sent)\\n\",\n                p.counters.opens_received,\n                p.counters.opens_sent,\n                p.counters.updates_received,\n                p.counters.updates_sent,\n                p.counters.keepalives_received,\n                p.counters.keepalives_sent,\n                p.counters.route_refreshes_received,\n                p.counters.route_refreshes_sent,\n                p.counters.notifications_received,\n                p.counters.notifications_sent\n            ));\n""",
)

# ---------------------------------------------------------------------------
# Integration coverage: real TCP session, IPv4 and EVPN family replay
# ---------------------------------------------------------------------------
TEST = r'''//! RFC 2918 BGP Route Refresh over the stack's real TCP control plane.
//!
//! A refresh must replay the current outbound view without resetting the BGP
//! session and without discarding Adj-RIB-Out state needed for withdrawals.

mod common;

use common::bgp_lab::{
    AS1, AS2, AS3, best_as_path, build_linear_lab, converge_sessions, ip, prefix, run_until,
};
use toy_tcpip::bgp::{BGP_HEADER_LEN, BGP_MSG_ROUTE_REFRESH, BgpPdu, BgpRouteRefreshMessage};
use toy_tcpip::bgp_caps::AfiSafi;
use toy_tcpip::lab::build_evpn_fabric;

#[test]
fn test_route_refresh_wire_message_is_type_five() {
    let sent = BgpPdu::RouteRefresh(BgpRouteRefreshMessage::new(AfiSafi::IPV4_UNICAST));
    let raw = sent.serialize();
    assert_eq!(raw.len(), BGP_HEADER_LEN + 4);
    assert_eq!(raw[18], BGP_MSG_ROUTE_REFRESH);
    assert_eq!(BgpPdu::parse(&raw).unwrap(), sent);
}

#[test]
fn test_route_refresh_capability_is_negotiated_on_live_sessions() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));

    for router in ["r1", "r2", "r3"] {
        for peer in lab.router(router).unwrap().bgp().unwrap().peers() {
            assert!(
                peer.negotiated.supports_route_refresh(),
                "{} did not negotiate Route Refresh with {}",
                router,
                peer.addr
            );
        }
    }
}

#[test]
fn test_ipv4_refresh_replays_routes_without_reset_or_decision_churn() {
    let mut lab = build_linear_lab();
    let remote_prefix = prefix(10, 3, 0, 0, 24);
    let r2_addr = ip(10, 12, 0, 2);
    let r1_addr = ip(10, 12, 0, 1);

    assert!(converge_sessions(&mut lab, 60_000));
    assert!(run_until(&mut lab, 60_000, |l| {
        best_as_path(l, "r1", remote_prefix) == Some(vec![AS2, AS3])
    }));
    // Let any convergence tail finish before taking no-churn snapshots.
    lab.run_until(250, 2_000, |_| false);

    let (before_updates, before_received_at, before_decisions, before_establishments) = {
        let bgp = lab.router("r1").unwrap().bgp().unwrap();
        let peer = bgp.peer(r2_addr).unwrap();
        let path = bgp
            .adj_rib_in
            .peer_table(r2_addr)
            .unwrap()
            .get(&remote_prefix)
            .unwrap();
        (
            peer.counters.updates_received,
            path.received_at_ms,
            bgp.decision_runs,
            peer.establishment_count,
        )
    };

    let sent = {
        let r1 = lab.router_mut("r1").unwrap();
        let now = r1.current_time_ms;
        let (bgp, sockets) = (&mut r1.bgp, &mut r1.sockets);
        bgp.as_mut().unwrap().request_route_refresh(
            r2_addr,
            AfiSafi::IPV4_UNICAST,
            now,
            sockets.as_mut().unwrap(),
        )
    };
    assert!(sent, "R1 could not send a negotiated Route Refresh");

    assert!(lab.run_until(250, 10_000, |l| {
        let r1 = l.router("r1").unwrap().bgp().unwrap();
        let r2 = l.router("r2").unwrap().bgp().unwrap();
        r1.peer(r2_addr).unwrap().counters.updates_received > before_updates
            && r2.peer(r1_addr).unwrap().counters.route_refreshes_received == 1
    }));

    let r1 = lab.router("r1").unwrap().bgp().unwrap();
    let peer = r1.peer(r2_addr).unwrap();
    let refreshed = r1
        .adj_rib_in
        .peer_table(r2_addr)
        .unwrap()
        .get(&remote_prefix)
        .unwrap();
    assert!(refreshed.received_at_ms > before_received_at);
    assert_eq!(best_as_path(&lab, "r1", remote_prefix), Some(vec![AS2, AS3]));
    assert_eq!(peer.establishment_count, before_establishments);
    assert_eq!(r1.decision_runs, before_decisions, "identical replay caused churn");
    assert_eq!(peer.counters.route_refreshes_sent, 1);
}

#[test]
fn test_evpn_refresh_replays_mp_bgp_routes_without_reset() {
    let mut lab = build_evpn_fabric(AS1, AS2);
    let leaf2 = ip(10, 0, 0, 2);
    let leaf1 = ip(10, 0, 0, 1);

    assert!(lab.run_until(250, 60_000, |l| {
        l.router("leaf1")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(leaf2)
            .is_some_and(|p| p.carries_evpn() && p.negotiated.supports_route_refresh())
            && l.router("leaf2")
                .unwrap()
                .bgp()
                .unwrap()
                .peer(leaf1)
                .is_some_and(|p| p.carries_evpn() && p.negotiated.supports_route_refresh())
    }));
    assert!(lab.run_until(250, 30_000, |l| {
        l.router("leaf1")
            .unwrap()
            .bgp()
            .unwrap()
            .evpn_adj_rib_in
            .total_routes()
            > 0
    }), "leaf1 never received the baseline EVPN routes");
    lab.run_until(250, 2_000, |_| false);

    let (before_updates, before_routes, before_decisions, before_establishments) = {
        let bgp = lab.router("leaf1").unwrap().bgp().unwrap();
        let peer = bgp.peer(leaf2).unwrap();
        (
            peer.counters.updates_received,
            bgp.evpn_adj_rib_in.total_routes(),
            bgp.evpn_decision_runs,
            peer.establishment_count,
        )
    };

    let sent = {
        let r = lab.router_mut("leaf1").unwrap();
        let now = r.current_time_ms;
        let (bgp, sockets) = (&mut r.bgp, &mut r.sockets);
        bgp.as_mut().unwrap().request_route_refresh(
            leaf2,
            AfiSafi::L2VPN_EVPN,
            now,
            sockets.as_mut().unwrap(),
        )
    };
    assert!(sent);

    assert!(lab.run_until(250, 10_000, |l| {
        let l1 = l.router("leaf1").unwrap().bgp().unwrap();
        let l2 = l.router("leaf2").unwrap().bgp().unwrap();
        l1.peer(leaf2).unwrap().counters.updates_received > before_updates
            && l2.peer(leaf1).unwrap().counters.route_refreshes_received == 1
    }));

    let l1 = lab.router("leaf1").unwrap().bgp().unwrap();
    let peer = l1.peer(leaf2).unwrap();
    assert_eq!(l1.evpn_adj_rib_in.total_routes(), before_routes);
    assert_eq!(peer.establishment_count, before_establishments);
    assert_eq!(
        l1.evpn_decision_runs, before_decisions,
        "identical EVPN replay reran the decision process"
    );
    assert_eq!(peer.counters.route_refreshes_sent, 1);
}
'''
Path("tests/test_bgp_route_refresh.rs").write_text(TEST, encoding="utf-8")

print("RFC 2918 Route Refresh patches applied")
