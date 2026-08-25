from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"anchor not found in {path}: {old[:120]!r}")
    if text.count(old) != 1:
        raise SystemExit(f"anchor not unique in {path}: {text.count(old)} matches")
    p.write_text(text.replace(old, new, 1))

# ---------------------------------------------------------------------------
# ICMPv6: central RFC 4861 Router Solicitation / Advertisement validation.
# ---------------------------------------------------------------------------
icmp_path = "src/icmpv6.rs"
anchor = r'''    /// Builds an ICMPv6 Echo Request (Ping6)
    pub fn build_echo_request(
'''
methods = r'''    /// Validates an RFC 4861 Router Solicitation before a router uses
    /// the packet as a Neighbor Cache hint or generates a Router Advertisement.
    pub fn is_valid_router_solicitation(
        &self,
        src_ip: Ipv6Address,
        hop_limit: u8,
    ) -> bool {
        if self.msg_type != ICMPV6_TYPE_ROUTER_SOLICIT
            || self.code != 0
            || hop_limit != 255
            || self.payload.len() < 4
            || !ndp_options_well_formed(&self.payload[4..])
        {
            return false;
        }

        // RFC 4861 section 6.1.1: initial RS packets sourced from :: MUST NOT
        // include the Source Link-Layer Address option.
        !(src_ip.is_unspecified()
            && ndp_options_contain(&self.payload[4..], NDP_OPT_SRC_LINK_LAYER_ADDR))
    }

    /// Validates an RFC 4861 Router Advertisement and returns the parsed body.
    /// Callers use this before passive Neighbor Cache learning so an off-link or
    /// malformed RA cannot leave a cache entry behind even though its SLAAC data
    /// is subsequently rejected.
    pub fn validated_router_advertisement(
        &self,
        src_ip: Ipv6Address,
        hop_limit: u8,
    ) -> Option<RouterAdvertisement> {
        if self.msg_type != ICMPV6_TYPE_ROUTER_ADVERT
            || self.code != 0
            || hop_limit != 255
            || !src_ip.is_link_local()
            || self.payload.len() < 12
            || !ndp_options_well_formed(&self.payload[12..])
        {
            return None;
        }
        RouterAdvertisement::parse(self)
    }

    /// Builds an ICMPv6 Echo Request (Ping6)
    pub fn build_echo_request(
'''
replace_once(icmp_path, anchor, methods)

# RFC 4862 5.5.3(c): a PIO whose Preferred Lifetime exceeds Valid Lifetime is
# ignored. Do not silently clamp it into a different, acceptable PIO.
pio_old = r'''                let preferred_lifetime = u32::from_be_bytes(option[8..12].try_into().ok()?);
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&option[16..32]);
                prefixes.push(PrefixInformationOption::new(
'''
pio_new = r'''                let preferred_lifetime = u32::from_be_bytes(option[8..12].try_into().ok()?);
                if preferred_lifetime > valid_lifetime {
                    offset += option_len;
                    continue;
                }
                let mut prefix_bytes = [0u8; 16];
                prefix_bytes.copy_from_slice(&option[16..32]);
                prefixes.push(PrefixInformationOption::new(
'''
replace_once(icmp_path, pio_old, pio_new)

# ---------------------------------------------------------------------------
# NetStack: include Router Discovery messages in the pre-cache validation gate.
# Hosts discard RS outright; only valid RA may proceed to source-MAC learning.
# ---------------------------------------------------------------------------
stack_path = "src/stack.rs"
stack_import_old = r'''    ICMPV6_TYPE_ECHO_REPLY, ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT,
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_ROUTER_ADVERT, Icmpv6Packet, NdpTable,
    RouterAdvertisement, ipv6_multicast_mac, slaac_address,
'''
stack_import_new = r'''    ICMPV6_TYPE_ECHO_REPLY, ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT,
    ICMPV6_TYPE_NEIGHBOR_SOLICIT, ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT,
    Icmpv6Packet, NdpTable, ipv6_multicast_mac, slaac_address,
'''
replace_once(stack_path, stack_import_old, stack_import_new)

stack_match_old = r'''                                    ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6
                                        .validated_neighbor_advertisement_target(
                                            ip6_pkt.header.dst_ip,
                                            ip6_pkt.header.hop_limit,
                                        )
                                        .is_some(),
                                    _ => true,
'''
stack_match_new = r'''                                    ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6
                                        .validated_neighbor_advertisement_target(
                                            ip6_pkt.header.dst_ip,
                                            ip6_pkt.header.hop_limit,
                                        )
                                        .is_some(),
                                    // RFC 4861: hosts silently discard Router
                                    // Solicitations; do so before passive NDP learning.
                                    ICMPV6_TYPE_ROUTER_SOLICIT => false,
                                    ICMPV6_TYPE_ROUTER_ADVERT => icmp6
                                        .validated_router_advertisement(
                                            ip6_pkt.header.src_ip,
                                            ip6_pkt.header.hop_limit,
                                        )
                                        .is_some(),
                                    _ => true,
'''
replace_once(stack_path, stack_match_old, stack_match_new)

stack_err_old = r'''                                    Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                        | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
'''
stack_err_new = r'''                                    Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                        | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
                                        | Some(ICMPV6_TYPE_ROUTER_SOLICIT)
                                        | Some(ICMPV6_TYPE_ROUTER_ADVERT)
'''
replace_once(stack_path, stack_err_old, stack_err_new)

stack_ra_old = r'''                            ICMPV6_TYPE_ROUTER_ADVERT => {
                                if ip6_pkt.header.hop_limit == 255
                                    && ip6_pkt.header.src_ip.is_link_local()
                                    && let Some(ra) = RouterAdvertisement::parse(&icmp6)
                                {
'''
stack_ra_new = r'''                            ICMPV6_TYPE_ROUTER_ADVERT => {
                                if let Some(ra) = icmp6.validated_router_advertisement(
                                    ip6_pkt.header.src_ip,
                                    ip6_pkt.header.hop_limit,
                                ) {
'''
replace_once(stack_path, stack_ra_old, stack_ra_new)

# ---------------------------------------------------------------------------
# LabRouter: validate RS/RA before passive cache learning / queued release.
# ---------------------------------------------------------------------------
lab_path = "src/lab.rs"
lab_import_old = r'''    ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,
    ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable, PrefixInformationOption,
'''
lab_import_new = r'''    ICMPV6_TYPE_ECHO_REQUEST, ICMPV6_TYPE_NEIGHBOR_ADVERT, ICMPV6_TYPE_NEIGHBOR_SOLICIT,
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet, NdpTable,
    PrefixInformationOption,
'''
replace_once(lab_path, lab_import_old, lab_import_new)

lab_match_old = r'''                                ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6
                                    .validated_neighbor_advertisement_target(
                                        ip6_pkt.header.dst_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                    .is_some(),
                                _ => true,
'''
lab_match_new = r'''                                ICMPV6_TYPE_NEIGHBOR_ADVERT => icmp6
                                    .validated_neighbor_advertisement_target(
                                        ip6_pkt.header.dst_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                    .is_some(),
                                ICMPV6_TYPE_ROUTER_SOLICIT => icmp6
                                    .is_valid_router_solicitation(
                                        ip6_pkt.header.src_ip,
                                        ip6_pkt.header.hop_limit,
                                    ),
                                ICMPV6_TYPE_ROUTER_ADVERT => icmp6
                                    .validated_router_advertisement(
                                        ip6_pkt.header.src_ip,
                                        ip6_pkt.header.hop_limit,
                                    )
                                    .is_some(),
                                _ => true,
'''
replace_once(lab_path, lab_match_old, lab_match_new)

lab_err_old = r'''                                Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                    | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
'''
lab_err_new = r'''                                Some(ICMPV6_TYPE_NEIGHBOR_SOLICIT)
                                    | Some(ICMPV6_TYPE_NEIGHBOR_ADVERT)
                                    | Some(ICMPV6_TYPE_ROUTER_SOLICIT)
                                    | Some(ICMPV6_TYPE_ROUTER_ADVERT)
'''
replace_once(lab_path, lab_err_old, lab_err_new)

lab_rs_old = r'''                    if icmp6.msg_type == ICMPV6_TYPE_ROUTER_SOLICIT
                        && ip6_pkt.header.hop_limit == 255
                        && ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS
                        && let Some((router_address, prefix_len)) = ingress_iface.ipv6
'''
lab_rs_new = r'''                    if icmp6.msg_type == ICMPV6_TYPE_ROUTER_SOLICIT
                        && icmp6.is_valid_router_solicitation(
                            ip6_pkt.header.src_ip,
                            ip6_pkt.header.hop_limit,
                        )
                        && ip6_pkt.header.dst_ip == Ipv6Address::LINK_LOCAL_ALL_ROUTERS
                        && let Some((router_address, prefix_len)) = ingress_iface.ipv6
'''
replace_once(lab_path, lab_rs_old, lab_rs_new)

# ---------------------------------------------------------------------------
# Integration tests.
# ---------------------------------------------------------------------------
test = r'''use std::str::FromStr;

use toy_tcpip::ethernet::{ETHERTYPE_IPV6, EthernetFrame, MacAddress};
use toy_tcpip::icmpv6::{
    ICMPV6_TYPE_ROUTER_ADVERT, ICMPV6_TYPE_ROUTER_SOLICIT, Icmpv6Packet,
    PrefixInformationOption, RouterAdvertisement, ipv6_multicast_mac, link_local_address,
};
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::{Ipv6Address, Ipv6Packet, NEXT_HEADER_ICMPV6};
use toy_tcpip::lab::LabRouter;
use toy_tcpip::stack::{Ipv6RouterDiscoveryStatus, NetStack, NetStackConfig};

fn ip6(text: &str) -> Ipv6Address {
    Ipv6Address::from_str(text).unwrap()
}

fn mac(a: u8, b: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, a, b])
}

fn host() -> NetStack {
    NetStack::new(NetStackConfig {
        mac: mac(1, 2),
        ip: Ipv4Address::new(192, 0, 2, 2),
        ipv6: None,
        subnet_mask: 24,
        gateway: None,
    })
}

fn ra_frame(
    router_mac: MacAddress,
    source: Ipv6Address,
    hop_limit: u8,
    prefix: PrefixInformationOption,
) -> Vec<u8> {
    let dst = Ipv6Address::LINK_LOCAL_ALL_NODES;
    let ra = Icmpv6Packet::build_router_advertisement(
        source,
        dst,
        64,
        1800,
        &[prefix],
        Some(router_mac),
    );
    let ip = Ipv6Packet::serialize(source, dst, NEXT_HEADER_ICMPV6, hop_limit, &ra);
    EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        router_mac,
        ETHERTYPE_IPV6,
        &ip,
    )
}

#[test]
fn invalid_ra_is_rejected_before_host_neighbor_cache_learning() {
    let router_mac = mac(9, 1);
    let router = link_local_address(router_mac);
    let prefix = PrefixInformationOption::new(ip6("2001:db8:44::"), 64, true, true, 3600, 1800);
    let mut stack = host();
    let _ = stack.start_router_discovery();

    let offlink = ra_frame(router_mac, router, 64, prefix);
    assert!(stack.process_frame(&offlink).is_empty());
    assert_eq!(stack.ndp_table.lookup(&router), None);
    assert!(matches!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting { .. }
    ));
    assert_eq!(stack.config.ipv6, None);

    let global_source = ip6("2001:db8::1");
    let wrong_source = ra_frame(router_mac, global_source, 255, prefix);
    assert!(stack.process_frame(&wrong_source).is_empty());
    assert_eq!(stack.ndp_table.lookup(&global_source), None);
    assert!(matches!(
        stack.ipv6_router_discovery_status(),
        Ipv6RouterDiscoveryStatus::Soliciting { .. }
    ));
}

#[test]
fn valid_ra_still_learns_router_and_enters_slaac_dad() {
    let router_mac = mac(9, 2);
    let router = link_local_address(router_mac);
    let prefix = PrefixInformationOption::new(ip6("2001:db8:45::"), 64, true, true, 3600, 1800);
    let mut stack = host();
    let _ = stack.start_router_discovery();

    let valid = ra_frame(router_mac, router, 255, prefix);
    let out = stack.process_frame(&valid);
    assert_eq!(out.len(), 1, "a valid autonomous PIO should start DAD");
    assert_eq!(stack.ndp_table.lookup(&router), Some(router_mac));
    assert_eq!(stack.ipv6_router_discovery_status(), Ipv6RouterDiscoveryStatus::Idle);
}

#[test]
fn lab_router_rejects_invalid_rs_before_cache_learning_and_reply() {
    let router_mac = mac(1, 1);
    let host_mac = mac(2, 2);
    let router_ip = ip6("2001:db8:1::1");
    let host_ll = link_local_address(host_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let mut router = LabRouter::new("r1");
    router.add_interface(
        "eth0",
        router_mac,
        Ipv4Address::new(10, 0, 0, 1),
        24,
        "lan",
    );
    assert!(router.set_interface_ipv6("eth0", router_ip, 64));

    let rs = Icmpv6Packet::build_router_solicitation(host_ll, dst, Some(host_mac));
    let bad_ip = Ipv6Packet::serialize(host_ll, dst, NEXT_HEADER_ICMPV6, 64, &rs);
    let bad_frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &bad_ip,
    );
    assert!(router.process_incoming_frame("lan", &bad_frame).is_empty());
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&host_ll),
        None
    );

    let good_ip = Ipv6Packet::serialize(host_ll, dst, NEXT_HEADER_ICMPV6, 255, &rs);
    let good_frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        host_mac,
        ETHERTYPE_IPV6,
        &good_ip,
    );
    assert_eq!(router.process_incoming_frame("lan", &good_frame).len(), 1);
    assert_eq!(
        router.ndp_tables.get("eth0").unwrap().lookup(&host_ll),
        Some(host_mac)
    );
}

#[test]
fn unspecified_source_rs_with_slla_is_invalid() {
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    // Semantic validator tests can construct an already checksum-validated packet
    // directly. The fixed RS body is four reserved bytes, followed by SLLA.
    let payload = [0, 0, 0, 0, 1, 1, 0x02, 0, 0, 0, 1, 2];
    let rs = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_SOLICIT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };
    assert!(!rs.is_valid_router_solicitation(Ipv6Address::UNSPECIFIED, 255));
    assert!(rs.is_valid_router_solicitation(ip6("fe80::2"), 255));
    assert!(!rs.is_valid_router_solicitation(ip6("fe80::2"), 64));
    let _ = dst;
}

#[test]
fn pio_with_preferred_lifetime_above_valid_is_ignored_not_clamped() {
    let mut payload = vec![0u8; 12]; // RA body after ICMPv6 header
    payload.extend_from_slice(&[
        3, 4, 64, 0xc0, // PIO type, length, prefix length, L+A
        0, 0, 0, 10,   // Valid Lifetime = 10
        0, 0, 0, 20,   // Preferred Lifetime = 20 (invalid)
        0, 0, 0, 0,    // Reserved2
    ]);
    payload.extend_from_slice(&ip6("2001:db8:46::").0);
    let ra = Icmpv6Packet {
        msg_type: ICMPV6_TYPE_ROUTER_ADVERT,
        code: 0,
        checksum: 0,
        payload: &payload,
    };
    let parsed = RouterAdvertisement::parse(&ra).expect("RA framing itself remains valid");
    assert!(parsed.prefixes.is_empty(), "RFC 4862 requires ignoring this PIO");
}

#[test]
fn host_silently_discards_router_solicitations_before_cache_learning() {
    let mut stack = host();
    let peer_mac = mac(7, 7);
    let peer = link_local_address(peer_mac);
    let dst = Ipv6Address::LINK_LOCAL_ALL_ROUTERS;
    let rs = Icmpv6Packet::build_router_solicitation(peer, dst, Some(peer_mac));
    let ip = Ipv6Packet::serialize(peer, dst, NEXT_HEADER_ICMPV6, 255, &rs);
    let frame = EthernetFrame::serialize(
        ipv6_multicast_mac(dst).unwrap(),
        peer_mac,
        ETHERTYPE_IPV6,
        &ip,
    );
    assert!(stack.process_frame(&frame).is_empty());
    assert_eq!(stack.ndp_table.lookup(&peer), None);
}
'''
Path("tests/test_ipv6_router_discovery_ingress_validation.rs").write_text(test)
