use toy_tcpip::flowspec_redirect_vrf::{
    FlowspecVrfAction, FlowspecVrfRule, FlowspecVrfScrubbingEngine,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_flowspec_redirect_to_vrf_and_dscp_remarking() {
    let mut engine = FlowspecVrfScrubbingEngine::new();
    let victim_ip = Ipv4Address::new(198, 51, 100, 10);

    // Rule 1: Divert DNS Flood (UDP port 53) to Scrubbing VRF
    engine.add_rule(FlowspecVrfRule {
        rule_id: 1,
        match_dst_ip: Some(victim_ip),
        match_protocol: Some(17), // UDP
        match_dst_port: Some(53),
        action: FlowspecVrfAction::RedirectVrf("VRF_DDoS_Cleaner".to_string()),
    });

    // Rule 2: Remark DSCP to 46 (EF) for HTTP traffic
    engine.add_rule(FlowspecVrfRule {
        rule_id: 2,
        match_dst_ip: Some(victim_ip),
        match_protocol: Some(6), // TCP
        match_dst_port: Some(80),
        action: FlowspecVrfAction::RemarkDscp(46),
    });

    // 1. Test DNS attack packet diversion
    let act1 = engine.evaluate_packet(victim_ip, 17, 53);
    assert_eq!(
        act1,
        FlowspecVrfAction::RedirectVrf("VRF_DDoS_Cleaner".to_string())
    );
    assert_eq!(engine.redirected_packets_count, 1);

    // 2. Test HTTP remarking
    let act2 = engine.evaluate_packet(victim_ip, 6, 80);
    assert_eq!(act2, FlowspecVrfAction::RemarkDscp(46));
    assert_eq!(engine.remarked_packets_count, 1);

    // 3. Test clean unmatched traffic
    let act3 = engine.evaluate_packet(victim_ip, 6, 443);
    assert_eq!(act3, FlowspecVrfAction::Pass);
    assert_eq!(engine.passed_packets_count, 1);
}

#[test]
fn test_flowspec_advanced_port_range_and_tcp_flags_syn_flood() {
    use toy_tcpip::flowspec_redirect_vrf::{
        FlowspecVrfAction, FlowspecVrfAdvancedRule, FlowspecVrfScrubbingEngine, PacketLengthMatch,
        PortRangeMatch, TCP_FLAG_ACK, TCP_FLAG_SYN, TcpFlagsMatch,
    };

    let mut engine = FlowspecVrfScrubbingEngine::new();
    let victim_ip = Ipv4Address::new(203, 0, 113, 50);

    // Rule 1: Detect TCP SYN Flood (SYN=1, ACK=0) on ports 8000..8080 with small packets (40..100 bytes)
    let mut syn_rule = FlowspecVrfAdvancedRule::new(
        101,
        FlowspecVrfAction::RedirectAndRemark {
            vrf: "VRF_SYN_PROXY".to_string(),
            dscp: 10,
        },
    );
    syn_rule.match_dst_ip = Some(victim_ip);
    syn_rule.match_protocol = Some(6); // TCP
    syn_rule.match_dst_port = Some(PortRangeMatch::Range(8000, 8080));
    // Match SYN=1, ACK=0
    syn_rule.match_tcp_flags = Some(TcpFlagsMatch::new(
        TCP_FLAG_SYN | TCP_FLAG_ACK,
        TCP_FLAG_SYN,
    ));
    syn_rule.match_packet_len = Some(PacketLengthMatch::new(40, 100));

    engine.add_advanced_rule(syn_rule);

    // Packet 1: True SYN packet to port 8005, len 60 -> matches SYN proxy redirection
    let attacker_ip = Ipv4Address::new(198, 51, 100, 99);
    let act1 =
        engine.evaluate_packet_advanced(attacker_ip, victim_ip, 6, 45678, 8005, TCP_FLAG_SYN, 60);
    assert_eq!(
        act1,
        FlowspecVrfAction::RedirectAndRemark {
            vrf: "VRF_SYN_PROXY".to_string(),
            dscp: 10,
        }
    );
    assert_eq!(engine.redirected_packets_count, 1);
    assert_eq!(engine.remarked_packets_count, 1);
    assert_eq!(engine.total_bytes_diverted, 60);

    // Packet 2: Established ACK packet to port 8005 -> flags don't match, passes through
    let act2 =
        engine.evaluate_packet_advanced(attacker_ip, victim_ip, 6, 45678, 8005, TCP_FLAG_ACK, 60);
    assert_eq!(act2, FlowspecVrfAction::Pass);

    // Packet 3: SYN packet to port 9000 -> outside port range, passes through
    let act3 =
        engine.evaluate_packet_advanced(attacker_ip, victim_ip, 6, 45678, 9000, TCP_FLAG_SYN, 60);
    assert_eq!(act3, FlowspecVrfAction::Pass);
}

#[test]
fn test_flowspec_rate_limiting_and_packet_length_scrubbing() {
    use toy_tcpip::flowspec_redirect_vrf::{
        FlowspecVrfAction, FlowspecVrfAdvancedRule, FlowspecVrfScrubbingEngine, PacketLengthMatch,
        PortRangeMatch,
    };

    let mut engine = FlowspecVrfScrubbingEngine::new();
    let victim_ip = Ipv4Address::new(192, 0, 2, 1);

    // NTP Amplification mitigation: UDP source port 123 with huge response length (> 400 bytes)
    let mut ntp_rule = FlowspecVrfAdvancedRule::new(
        201,
        FlowspecVrfAction::RateLimitBytesPerSec(10_000_000), // 10 MB/s rate limit
    );
    ntp_rule.match_dst_ip = Some(victim_ip);
    ntp_rule.match_protocol = Some(17); // UDP
    ntp_rule.match_src_port = Some(PortRangeMatch::Exact(123));
    ntp_rule.match_packet_len = Some(PacketLengthMatch::new(400, 1500));

    engine.add_advanced_rule(ntp_rule);

    let ntp_reflector = Ipv4Address::new(198, 51, 100, 123);

    // Amplified response packet: 1200 bytes
    let act = engine.evaluate_packet_advanced(ntp_reflector, victim_ip, 17, 123, 54321, 0, 1200);
    assert_eq!(act, FlowspecVrfAction::RateLimitBytesPerSec(10_000_000));
    assert_eq!(engine.rate_limited_packets_count, 1);

    // Small NTP response: 48 bytes -> passes through normally
    let small_act =
        engine.evaluate_packet_advanced(ntp_reflector, victim_ip, 17, 123, 54321, 0, 48);
    assert_eq!(small_act, FlowspecVrfAction::Pass);
}

#[test]
fn test_flowspec_fragment_matching_mitigation() {
    use toy_tcpip::flowspec_redirect_vrf::{
        FlowspecVrfAction, FlowspecVrfAdvancedRule, FlowspecVrfScrubbingEngine, FragmentMatch,
    };

    let mut engine = FlowspecVrfScrubbingEngine::new();
    let victim_ip = Ipv4Address::new(198, 51, 100, 20);

    // Drop all IP fragments targeting victim (Fragment Flood / Teardrop attack mitigation)
    let mut frag_rule = FlowspecVrfAdvancedRule::new(301, FlowspecVrfAction::Drop);
    frag_rule.match_dst_ip = Some(victim_ip);
    frag_rule.match_fragment = Some(FragmentMatch::IsFragment);

    engine.add_advanced_rule(frag_rule);

    let attacker = Ipv4Address::new(203, 0, 113, 99);

    // 1. First fragment (offset = 0, more_frags = true) -> dropped
    let act1 = engine.evaluate_packet_full(
        attacker, victim_ip, 17, 4000, 5000, 0, 1400, true, 0, true, None,
    );
    assert_eq!(act1, FlowspecVrfAction::Drop);
    assert_eq!(engine.dropped_packets_count, 1);

    // 2. Middle/Last fragment (offset = 185, more_frags = false) -> dropped
    let act2 = engine.evaluate_packet_full(
        attacker, victim_ip, 17, 4000, 5000, 0, 800, true, 185, false, None,
    );
    assert_eq!(act2, FlowspecVrfAction::Drop);
    assert_eq!(engine.dropped_packets_count, 2);

    // 3. Normal unfragmented packet (offset = 0, more_frags = false, is_fragment = false) -> Pass
    let act3 = engine.evaluate_packet_full(
        attacker, victim_ip, 17, 4000, 5000, 0, 500, false, 0, false, None,
    );
    assert_eq!(act3, FlowspecVrfAction::Pass);
}

#[test]
fn test_flowspec_icmp_echo_flood_mitigation() {
    use toy_tcpip::flowspec_redirect_vrf::{
        FlowspecVrfAction, FlowspecVrfAdvancedRule, FlowspecVrfScrubbingEngine, IcmpMatch,
    };

    let mut engine = FlowspecVrfScrubbingEngine::new();
    let victim_ip = Ipv4Address::new(203, 0, 113, 88);

    // Scrub ICMP Echo Requests (Ping Flood: Type 8, Code 0) to Scrubbing VRF
    let mut icmp_rule = FlowspecVrfAdvancedRule::new(
        401,
        FlowspecVrfAction::RedirectVrf("VRF_ICMP_SCRUBBER".to_string()),
    );
    icmp_rule.match_dst_ip = Some(victim_ip);
    icmp_rule.match_protocol = Some(1); // ICMP
    icmp_rule.match_icmp = Some(IcmpMatch::new(8, Some(0)));

    engine.add_advanced_rule(icmp_rule);

    let sender = Ipv4Address::new(192, 0, 2, 55);

    // Ping request (Type 8, Code 0) -> redirected
    let act1 = engine.evaluate_packet_full(
        sender,
        victim_ip,
        1,
        0,
        0,
        0,
        64,
        false,
        0,
        false,
        Some((8, 0)),
    );
    assert_eq!(
        act1,
        FlowspecVrfAction::RedirectVrf("VRF_ICMP_SCRUBBER".to_string())
    );

    // ICMP Destination Unreachable (Type 3, Code 1) -> passes through
    let act2 = engine.evaluate_packet_full(
        sender,
        victim_ip,
        1,
        0,
        0,
        0,
        56,
        false,
        0,
        false,
        Some((3, 1)),
    );
    assert_eq!(act2, FlowspecVrfAction::Pass);
}
