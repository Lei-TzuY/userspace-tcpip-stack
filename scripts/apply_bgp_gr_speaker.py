from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if new in text:
        return
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{path}: expected one replacement, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


path = "src/bgp_router.rs"

replace_once(
    path,
    """    /// Address-family End-of-RIB markers that completed graceful restart early.\n    pub graceful_restart_eors: u64,\n    /// Graceful-restart procedures that reached the Restart Time deadline.\n    pub graceful_restart_expirations: u64,\n""",
    """    /// Address-family End-of-RIB markers that completed graceful restart early.\n    pub graceful_restart_eors: u64,\n    /// Address-family End-of-RIB markers sent after local RIB recovery.\n    pub graceful_restart_eors_sent: u64,\n    /// Graceful-restart procedures that reached the Restart Time deadline.\n    pub graceful_restart_expirations: u64,\n""",
)

replace_once(
    path,
    """    /// Families the peer asked us to replay. Keeping this separate from the\n    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.\n    refresh_pending: BTreeSet<AfiSafi>,\n    /// Families whose routes are retained as RFC 4724 stale state after an\n""",
    """    /// Families the peer asked us to replay. Keeping this separate from the\n    /// Adj-RIB-Out preserves the previous advertisement set for withdrawals.\n    refresh_pending: BTreeSet<AfiSafi>,\n    /// Families for which this restarting speaker owes the peer an End-of-RIB.\n    /// The set survives transport retries so an EOR cannot be lost just because\n    /// the replacement session flapped once more.\n    local_restart_eor_pending: BTreeSet<AfiSafi>,\n    /// Families whose routes are retained as RFC 4724 stale state after an\n""",
)

replace_once(
    path,
    """            negotiated: NegotiatedCapabilities::default(),\n            refresh_pending: BTreeSet::new(),\n            graceful_restart_stale: BTreeSet::new(),\n""",
    """            negotiated: NegotiatedCapabilities::default(),\n            refresh_pending: BTreeSet::new(),\n            local_restart_eor_pending: BTreeSet::new(),\n            graceful_restart_stale: BTreeSet::new(),\n""",
)

replace_once(
    path,
    """    /// Whether this speaker advertises and acts as an RFC 4724 helper.\n    pub graceful_restart_enabled: bool,\n    /// Restart Time advertised in the Graceful Restart capability.\n    pub graceful_restart_time: u16,\n    peers: Vec<BgpPeer>,\n""",
    """    /// Whether this speaker advertises and acts as an RFC 4724 helper.\n    pub graceful_restart_enabled: bool,\n    /// Restart Time advertised in the Graceful Restart capability.\n    pub graceful_restart_time: u16,\n    /// True while this speaker is reconnecting after a local control-plane restart.\n    /// While set, OPEN carries RFC 4724's Restart State bit.\n    graceful_restart_restarting: bool,\n    /// Families whose local RIB recovery has not yet been declared complete.\n    graceful_restart_recovery_pending: BTreeSet<AfiSafi>,\n    /// Safety deadline after which Restart State is cleared even if a peer never\n    /// comes back to receive its EOR. Helpers have the same bounded retention.\n    graceful_restart_local_deadline: Option<u64>,\n    peers: Vec<BgpPeer>,\n""",
)

replace_once(
    path,
    """            graceful_restart_enabled: true,\n            graceful_restart_time: DEFAULT_GRACEFUL_RESTART_TIME,\n            peers: Vec::new(),\n""",
    """            graceful_restart_enabled: true,\n            graceful_restart_time: DEFAULT_GRACEFUL_RESTART_TIME,\n            graceful_restart_restarting: false,\n            graceful_restart_recovery_pending: BTreeSet::new(),\n            graceful_restart_local_deadline: None,\n            peers: Vec::new(),\n""",
)

replace_once(
    path,
    """    pub fn set_graceful_restart_time(&mut self, seconds: u16) {\n        self.graceful_restart_time = seconds.min(crate::bgp_caps::BGP_GR_MAX_RESTART_TIME);\n    }\n\n    /// Configures a neighbour. Peers are kept sorted by address so every iteration\n""",
    """    pub fn set_graceful_restart_time(&mut self, seconds: u16) {\n        self.graceful_restart_time = seconds.min(crate::bgp_caps::BGP_GR_MAX_RESTART_TIME);\n    }\n\n    /// True while local RFC 4724 restarting-speaker mode is active.\n    pub fn graceful_restart_restarting(&self) -> bool {\n        self.graceful_restart_restarting\n    }\n\n    /// Families still waiting for the local control plane to declare RIB recovery.\n    pub fn graceful_restart_recovery_pending(&self) -> Vec<AfiSafi> {\n        self.graceful_restart_recovery_pending\n            .iter()\n            .copied()\n            .collect()\n    }\n\n    /// Simulates a local BGP control-plane restart without an administrative Cease.\n    ///\n    /// Existing transports are dropped as transport failures, so RFC 4724-capable\n    /// neighbours may retain our routes. Replacement OPENs advertise Restart State\n    /// until every configured family has recovered and every returning helper has\n    /// received its End-of-RIB, or until Restart Time expires.\n    pub fn begin_graceful_restart(\n        &mut self,\n        now_ms: u64,\n        sockets: &mut SocketRuntime,\n    ) -> bool {\n        if !self.graceful_restart_enabled || self.graceful_restart_restarting {\n            return false;\n        }\n\n        self.graceful_restart_restarting = true;\n        self.graceful_restart_recovery_pending = self.families.clone();\n        self.graceful_restart_local_deadline = Some(\n            now_ms.saturating_add(self.graceful_restart_time as u64 * 1_000),\n        );\n        for peer in &mut self.peers {\n            peer.local_restart_eor_pending.clear();\n        }\n\n        let live: Vec<usize> = self\n            .peers\n            .iter()\n            .enumerate()\n            .filter(|(_, peer)| peer.stream.is_some() || peer.state != BgpState::Idle)\n            .map(|(idx, _)| idx)\n            .collect();\n        for idx in live {\n            self.teardown(\n                idx,\n                now_ms,\n                sockets,\n                Teardown::Transport(\"local RFC 4724 graceful restart\".to_string()),\n            );\n        }\n        true\n    }\n\n    /// Declares one address family recovered after a local graceful restart.\n    /// The EOR is queued per peer and is emitted only after that peer's normal\n    /// advertisement pass, so all refreshed routes precede the marker on the wire.\n    pub fn mark_graceful_restart_family_recovered(\n        &mut self,\n        family: AfiSafi,\n        now_ms: u64,\n    ) -> bool {\n        if !self.graceful_restart_restarting\n            || !self.graceful_restart_recovery_pending.remove(&family)\n        {\n            return false;\n        }\n        for peer in &mut self.peers {\n            if peer.admin_up {\n                peer.local_restart_eor_pending.insert(family);\n            }\n        }\n        self.maybe_finish_local_graceful_restart(now_ms);\n        true\n    }\n\n    /// Configures a neighbour. Peers are kept sorted by address so every iteration\n""",
)

replace_once(
    path,
    """                BgpGracefulRestartCapability::new(\n                    self.graceful_restart_time,\n                    false,\n                    self.families\n""",
    """                BgpGracefulRestartCapability::new(\n                    self.graceful_restart_time,\n                    self.graceful_restart_restarting,\n                    self.families\n""",
)

replace_once(
    path,
    """    pub fn poll(&mut self, now_ms: u64, sockets: &mut SocketRuntime, fib: &mut RoutingTable) {\n        self.ensure_listener(now_ms, sockets);\n""",
    """    pub fn poll(&mut self, now_ms: u64, sockets: &mut SocketRuntime, fib: &mut RoutingTable) {\n        self.expire_local_graceful_restart(now_ms);\n        self.ensure_listener(now_ms, sockets);\n""",
)

replace_once(
    path,
    """        for idx in 0..self.peers.len() {\n            self.advertise_to_peer(idx, now_ms, sockets);\n            self.advertise_evpn_to_peer(idx, now_ms, sockets);\n        }\n    }\n\n    fn ensure_listener(&mut self, now_ms: u64, sockets: &mut SocketRuntime) {\n""",
    """        for idx in 0..self.peers.len() {\n            self.advertise_to_peer(idx, now_ms, sockets);\n            self.advertise_evpn_to_peer(idx, now_ms, sockets);\n            self.send_local_restart_eors(idx, now_ms, sockets);\n        }\n        self.maybe_finish_local_graceful_restart(now_ms);\n    }\n\n    fn ensure_listener(&mut self, now_ms: u64, sockets: &mut SocketRuntime) {\n""",
)

replace_once(
    path,
    """    fn route_is_graceful_restart_stale(\n        &self,\n        peer_addr: Ipv4Address,\n""",
    """    fn send_local_restart_eors(\n        &mut self,\n        idx: usize,\n        now_ms: u64,\n        sockets: &mut SocketRuntime,\n    ) {\n        if !self.peers[idx].is_established() {\n            return;\n        }\n\n        let pending: Vec<AfiSafi> = self.peers[idx]\n            .local_restart_eor_pending\n            .iter()\n            .copied()\n            .collect();\n        for family in pending {\n            let supports_gr = self.peers[idx]\n                .negotiated\n                .peer\n                .supports_graceful_restart();\n            if !supports_gr || !self.peers[idx].negotiated.supports(family) {\n                self.peers[idx].local_restart_eor_pending.remove(&family);\n                continue;\n            }\n\n            let pdu = match family {\n                AfiSafi::IPV4_UNICAST => BgpPdu::Update(BgpUpdateMessage::end_of_rib()),\n                AfiSafi::L2VPN_EVPN => BgpPdu::Update(BgpUpdateMessage::mp_withdraw(\n                    MpUnreachNlri::new(AfiSafi::L2VPN_EVPN, Vec::new()),\n                )),\n                _ => {\n                    self.peers[idx].local_restart_eor_pending.remove(&family);\n                    continue;\n                }\n            };\n\n            if self.send_pdu(idx, sockets, &pdu) {\n                let addr = self.peers[idx].addr;\n                self.peers[idx].counters.updates_sent += 1;\n                self.peers[idx].counters.graceful_restart_eors_sent += 1;\n                self.peers[idx].local_restart_eor_pending.remove(&family);\n                self.log(now_ms, addr, format!(\"sent Graceful Restart EOR for {}\", family));\n            }\n        }\n    }\n\n    fn maybe_finish_local_graceful_restart(&mut self, now_ms: u64) {\n        if !self.graceful_restart_restarting\n            || !self.graceful_restart_recovery_pending.is_empty()\n        {\n            return;\n        }\n        let waiting_for_peer = self\n            .peers\n            .iter()\n            .filter(|peer| peer.admin_up)\n            .any(|peer| !peer.local_restart_eor_pending.is_empty());\n        if waiting_for_peer {\n            return;\n        }\n\n        self.graceful_restart_restarting = false;\n        self.graceful_restart_local_deadline = None;\n        for peer in &mut self.peers {\n            peer.local_restart_eor_pending.clear();\n        }\n        let addrs: Vec<Ipv4Address> = self.peers.iter().map(|peer| peer.addr).collect();\n        for addr in addrs {\n            self.log(now_ms, addr, \"local Graceful Restart completed\");\n        }\n    }\n\n    fn expire_local_graceful_restart(&mut self, now_ms: u64) {\n        if !self.graceful_restart_restarting\n            || !self\n                .graceful_restart_local_deadline\n                .is_some_and(|deadline| now_ms >= deadline)\n        {\n            return;\n        }\n        self.graceful_restart_restarting = false;\n        self.graceful_restart_recovery_pending.clear();\n        self.graceful_restart_local_deadline = None;\n        for peer in &mut self.peers {\n            peer.local_restart_eor_pending.clear();\n        }\n        let addrs: Vec<Ipv4Address> = self.peers.iter().map(|peer| peer.addr).collect();\n        for addr in addrs {\n            self.log(now_ms, addr, \"local Graceful Restart expired before recovery completed\");\n        }\n    }\n\n    fn route_is_graceful_restart_stale(\n        &self,\n        peer_addr: Ipv4Address,\n""",
)

# Add an end-to-end restarting-speaker test. The helper must retain the old route,
# accept the replacement OPEN with Restart State, and leave helper mode only after
# the restarting speaker declares RIB recovery and sends EOR.
test_path = Path("tests/test_bgp_graceful_restart.rs")
test_text = test_path.read_text(encoding="utf-8")
marker = "fn test_restarting_speaker_sets_restart_state_and_finishes_with_eor()"
if marker not in test_text:
    test_text += r'''

#[test]
fn test_restarting_speaker_sets_restart_state_and_finishes_with_eor() {
    let mut lab = build_linear_lab();
    assert!(converge_sessions(&mut lab, 60_000));
    let learned = prefix(10, 3, 0, 0, 24);
    assert!(run_until(&mut lab, 60_000, |l| {
        l.router("r2").unwrap().bgp().unwrap().loc_rib.contains(&learned)
    }));

    let now = lab.current_time_ms;
    {
        let r3 = lab.router_mut("r3").unwrap();
        let (bgp, sockets) = (&mut r3.bgp, &mut r3.sockets);
        let bgp = bgp.as_mut().unwrap();
        assert!(bgp.begin_graceful_restart(now, sockets.as_mut().unwrap()));
        assert!(bgp.graceful_restart_restarting());
        assert_eq!(
            bgp.graceful_restart_recovery_pending(),
            vec![AfiSafi::IPV4_UNICAST]
        );
    }

    // Let the TCP close reach r2. Its helper must keep r3's route while the
    // restarting speaker is away.
    lab.run_pumped(100);
    let helper_peer = lab
        .router("r2")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 23, 0, 3))
        .unwrap();
    assert!(helper_peer.graceful_restart_active());
    assert!(lab.router("r2").unwrap().bgp().unwrap().loc_rib.contains(&learned));

    // Hold the link down briefly so the helper state is observable, then allow the
    // active r2 side to reconnect. The replacement OPEN from r3 must carry R=1.
    lab.link_mut("r2r3").unwrap().set_blackhole(true);
    lab.advance_time(1_000);
    lab.run_pumped(50);
    lab.link_mut("r2r3").unwrap().set_blackhole(false);
    assert!(converge_sessions(&mut lab, 60_000));

    let helper_peer = lab
        .router("r2")
        .unwrap()
        .bgp()
        .unwrap()
        .peer(ip(10, 23, 0, 3))
        .unwrap();
    let restart_cap = helper_peer
        .negotiated
        .peer
        .graceful_restart()
        .expect("replacement OPEN omitted RFC 4724");
    assert!(restart_cap.restarting, "replacement OPEN did not set Restart State");
    assert!(helper_peer.graceful_restart_active());

    let now = lab.current_time_ms;
    {
        let r3 = lab.router_mut("r3").unwrap();
        let bgp = r3.bgp.as_mut().unwrap();
        assert!(bgp.mark_graceful_restart_family_recovered(AfiSafi::IPV4_UNICAST, now));
        assert!(bgp.graceful_restart_restarting());
    }

    assert!(run_until(&mut lab, 20_000, |l| {
        let helper_done = !l
            .router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 3))
            .unwrap()
            .graceful_restart_active();
        let speaker_done = !l
            .router("r3")
            .unwrap()
            .bgp()
            .unwrap()
            .graceful_restart_restarting();
        helper_done && speaker_done
    }));

    assert!(lab.router("r2").unwrap().bgp().unwrap().loc_rib.contains(&learned));
    assert!(
        lab.router("r2")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 3))
            .unwrap()
            .counters
            .graceful_restart_eors
            >= 1
    );
    assert!(
        lab.router("r3")
            .unwrap()
            .bgp()
            .unwrap()
            .peer(ip(10, 23, 0, 2))
            .unwrap()
            .counters
            .graceful_restart_eors_sent
            >= 1
    );
}
'''
    test_path.write_text(test_text, encoding="utf-8")

print("BGP restarting-speaker patch applied")
