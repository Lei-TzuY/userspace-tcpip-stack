from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "src/icmpv6.rs",
    """#[derive(Debug, Clone, Default)]
pub struct NdpTable {
    entries: HashMap<Ipv6Address, MacAddress>,
    nud: HashMap<Ipv6Address, NudMetadata>,
}

impl NdpTable {
    pub fn new() -> Self {
        NdpTable {
            entries: HashMap::new(),
            nud: HashMap::new(),
        }
    }
""",
    """#[derive(Debug, Clone)]
pub struct NdpTable {
    entries: HashMap<Ipv6Address, MacAddress>,
    nud: HashMap<Ipv6Address, NudMetadata>,
    // RFC 4861 interface variables. ReachableTime normally includes a random
    // factor; this deterministic simulator deliberately uses factor 1.0.
    reachable_time_ms: u64,
    retrans_timer_ms: u64,
}

impl Default for NdpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl NdpTable {
    pub fn new() -> Self {
        NdpTable {
            entries: HashMap::new(),
            nud: HashMap::new(),
            reachable_time_ms: NDP_REACHABLE_TIME_MS,
            retrans_timer_ms: NDP_RETRANS_TIMER_MS,
        }
    }

    /// Applies the RFC 4861 fixed-header NUD parameters from a valid Router
    /// Advertisement. Zero means unspecified and therefore preserves the
    /// currently active value instead of restoring a protocol default.
    pub fn apply_router_advertisement_timers(
        &mut self,
        reachable_time_ms: u32,
        retrans_timer_ms: u32,
    ) {
        if reachable_time_ms != 0 {
            self.reachable_time_ms = u64::from(reachable_time_ms);
        }
        if retrans_timer_ms != 0 {
            self.retrans_timer_ms = u64::from(retrans_timer_ms);
        }
    }
""",
)

replace_once(
    "src/icmpv6.rs",
    """    /// Records positive reachability confirmation, such as a solicited NA.
    pub fn confirm_reachable(&mut self, ip: Ipv6Address, mac: MacAddress, now_ms: u64) {
        self.entries.insert(ip, mac);
        self.nud.insert(
            ip,
            NudMetadata {
                state: NeighborState::Reachable,
                deadline_ms: Some(now_ms.saturating_add(NDP_REACHABLE_TIME_MS)),
                probes_sent: 0,
            },
        );
    }
""",
    """    /// Records positive reachability confirmation, such as a solicited NA.
    pub fn confirm_reachable(&mut self, ip: Ipv6Address, mac: MacAddress, now_ms: u64) {
        self.entries.insert(ip, mac);
        self.nud.insert(
            ip,
            NudMetadata {
                state: NeighborState::Reachable,
                deadline_ms: Some(now_ms.saturating_add(self.reachable_time_ms)),
                probes_sent: 0,
            },
        );
    }
""",
)

replace_once(
    "src/icmpv6.rs",
    """    pub fn step_nud(&mut self, now_ms: u64) -> Vec<(Ipv6Address, MacAddress)> {
        let keys: Vec<Ipv6Address> = self.nud.keys().copied().collect();
        let mut probes = Vec::new();
        let mut remove = Vec::new();
""",
    """    pub fn step_nud(&mut self, now_ms: u64) -> Vec<(Ipv6Address, MacAddress)> {
        let retrans_timer_ms = self.retrans_timer_ms;
        let keys: Vec<Ipv6Address> = self.nud.keys().copied().collect();
        let mut probes = Vec::new();
        let mut remove = Vec::new();
""",
)

p = Path("src/icmpv6.rs")
text = p.read_text()
old = "meta.deadline_ms = Some(now_ms.saturating_add(NDP_RETRANS_TIMER_MS));"
count = text.count(old)
if count != 2:
    raise SystemExit(f"src/icmpv6.rs: expected two RetransTimer scheduling sites, found {count}")
p.write_text(text.replace(old, "meta.deadline_ms = Some(now_ms.saturating_add(retrans_timer_ms));"))

replace_once(
    "src/stack.rs",
    """                                ) {
                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may
                                    // update the Neighbor Cache only when it actually carries
                                    // SLLA. The enclosing Ethernet source is not a substitute.
""",
    """                                ) {
                                    // RFC 4861 section 6.3.4: non-zero Reachable Time and
                                    // Retrans Timer replace the host's current NUD variables;
                                    // zero means unspecified and must leave prior values intact.
                                    self.ndp_table.apply_router_advertisement_timers(
                                        ra.reachable_time,
                                        ra.retrans_timer,
                                    );

                                    // RFC 4861 sections 6.3.4 and 7.2: a valid RA may
                                    // update the Neighbor Cache only when it actually carries
                                    // SLLA. The enclosing Ethernet source is not a substitute.
""",
)

replace_once(
    "tests/test_ipv6_nud.rs",
    """fn na_frame_with_tlla(
""",
    """fn ra_frame_with_nud_timers(
    router_ip: Ipv6Address,
    router_mac: MacAddress,
    reachable_time_ms: u32,
    retrans_timer_ms: u32,
    hop_limit: u8,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let mut ra = Icmpv6Packet::build_router_advertisement(
        router_ip,
        dst,
        64,
        1800,
        &[],
        Some(router_mac),
    );
    ra[8..12].copy_from_slice(&reachable_time_ms.to_be_bytes());
    ra[12..16].copy_from_slice(&retrans_timer_ms.to_be_bytes());
    ra[2..4].copy_from_slice(&[0, 0]);
    let checksum = compute_ipv6_transport_checksum(router_ip, dst, NEXT_HEADER_ICMPV6, &ra);
    ra[2..4].copy_from_slice(&checksum.to_be_bytes());
    let packet = Ipv6Packet::serialize(router_ip, dst, NEXT_HEADER_ICMPV6, hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &packet,
    )
}

fn na_frame_with_tlla(
""",
)

marker = """#[test]
fn reachable_ages_to_stale_and_first_use_enters_delay() {
"""
additions = r"""#[test]
fn valid_ra_updates_reachable_and_retrans_timer_for_future_nud_transitions() {
    let host_ip = ip6("2001:db8:100::1");
    let router_ip = ip6("fe80::100");
    let peer_ip = ip6("2001:db8:100::2");
    let host_mac = mac(0x10);
    let router_mac = mac(0x11);
    let peer_mac = mac(0x12);
    let mut stack = host(host_ip, host_mac);

    let ra = ra_frame_with_nud_timers(router_ip, router_mac, 2_000, 250, 255);
    assert!(stack.process_frame(&ra).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 100);
    assert!(stack.ndp_table.step_nud(2_099).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack.ndp_table.step_nud(2_100).is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 2_100),
        Some(peer_mac)
    );
    let first_probe_at = 2_100 + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 249).is_empty());
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at + 250),
        vec![(peer_ip, peer_mac)]
    );
}

#[test]
fn zero_ra_nud_timers_preserve_previously_advertised_values() {
    let host_ip = ip6("2001:db8:101::1");
    let router_ip = ip6("fe80::101");
    let peer_ip = ip6("2001:db8:101::2");
    let host_mac = mac(0x20);
    let router_mac = mac(0x21);
    let peer_mac = mac(0x22);
    let mut stack = host(host_ip, host_mac);

    let learned = ra_frame_with_nud_timers(router_ip, router_mac, 1_500, 300, 255);
    assert!(stack.process_frame(&learned).is_empty());
    let unspecified = ra_frame_with_nud_timers(router_ip, router_mac, 0, 0, 255);
    assert!(stack.process_frame(&unspecified).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 0);
    assert!(stack.ndp_table.step_nud(1_499).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack.ndp_table.step_nud(1_500).is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack.ndp_table.lookup_for_transmit(&peer_ip, 1_500),
        Some(peer_mac)
    );
    let first_probe_at = 1_500 + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 299).is_empty());
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at + 300),
        vec![(peer_ip, peer_mac)]
    );
}

#[test]
fn invalid_ra_cannot_change_nud_timers() {
    let host_ip = ip6("2001:db8:102::1");
    let router_ip = ip6("fe80::102");
    let peer_ip = ip6("2001:db8:102::2");
    let host_mac = mac(0x30);
    let router_mac = mac(0x31);
    let peer_mac = mac(0x32);
    let mut stack = host(host_ip, host_mac);

    let invalid = ra_frame_with_nud_timers(router_ip, router_mac, 100, 100, 64);
    assert!(stack.process_frame(&invalid).is_empty());

    stack.ndp_table.confirm_reachable(peer_ip, peer_mac, 0);
    assert!(stack.ndp_table.step_nud(100).is_empty());
    assert_eq!(
        stack.ndp_table.state(&peer_ip),
        Some(NeighborState::Reachable)
    );
    assert!(stack
        .ndp_table
        .step_nud(NDP_REACHABLE_TIME_MS)
        .is_empty());
    assert_eq!(stack.ndp_table.state(&peer_ip), Some(NeighborState::Stale));

    assert_eq!(
        stack
            .ndp_table
            .lookup_for_transmit(&peer_ip, NDP_REACHABLE_TIME_MS),
        Some(peer_mac)
    );
    let first_probe_at = NDP_REACHABLE_TIME_MS + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(
        stack.ndp_table.step_nud(first_probe_at),
        vec![(peer_ip, peer_mac)]
    );
    assert!(stack.ndp_table.step_nud(first_probe_at + 100).is_empty());
    assert_eq!(
        stack
            .ndp_table
            .step_nud(first_probe_at + NDP_RETRANS_TIMER_MS),
        vec![(peer_ip, peer_mac)]
    );
}

"""
p = Path("tests/test_ipv6_nud.rs")
text = p.read_text()
if text.count(marker) != 1:
    raise SystemExit("tests/test_ipv6_nud.rs: insertion marker missing or ambiguous")
p.write_text(text.replace(marker, additions + marker, 1))
