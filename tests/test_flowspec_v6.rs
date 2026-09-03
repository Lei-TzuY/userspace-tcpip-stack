use toy_tcpip::flowspec_v6::{
    BGP_AFI_IPV6, BGP_SAFI_FLOWSPEC_IPV6, FlowspecV6Action, FlowspecV6Decision, FlowspecV6Engine,
    FlowspecV6Match, FlowspecV6Rule, matches_ipv6_cidr, parse_flowspec_v6_nlri,
    serialize_flowspec_v6_nlri,
};
use toy_tcpip::ipv6::Ipv6Address;

#[test]
fn test_flowspec_v6_constants_and_cidr() {
    assert_eq!(BGP_AFI_IPV6, 2);
    assert_eq!(BGP_SAFI_FLOWSPEC_IPV6, 133);

    let prefix = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let target1 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
    let target2 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x99, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    assert!(matches_ipv6_cidr(target1, prefix, 48));
    assert!(!matches_ipv6_cidr(target2, prefix, 48));
}

#[test]
fn test_flowspec_v6_engine_ddos_mitigation_and_redirect() {
    let mut engine = FlowspecV6Engine::new();

    let victim_ip = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe,
    ]);
    let redirect_scrubber = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x99, 0x99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    // Rule 1: High Priority DDoS UDP Flood to port 53 with specific Flow Label -> Drop
    engine.add_rule(FlowspecV6Rule {
        id: 1,
        priority: 100,
        match_fields: FlowspecV6Match {
            dst_prefix: Some((victim_ip, 128)),
            next_header: Some(17), // UDP
            dst_port: Some(53),
            flow_label: Some(0x000E_EEEE),
            ..Default::default()
        },
        action: FlowspecV6Action::Drop,
    });

    // Rule 2: Lower Priority Rate-limit / Redirect HTTP traffic on port 80 to scrubbing center
    engine.add_rule(FlowspecV6Rule {
        id: 2,
        priority: 50,
        match_fields: FlowspecV6Match {
            dst_prefix: Some((victim_ip, 128)),
            next_header: Some(6), // TCP
            dst_port: Some(80),
            ..Default::default()
        },
        action: FlowspecV6Action::RedirectIpv6(redirect_scrubber),
    });

    let attacker = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0x66, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);

    // 1. Evaluate UDP Attack datagram
    let dec_attack = engine.evaluate(
        attacker,
        victim_ip,
        17,
        Some(40000),
        Some(53),
        None,
        None,
        None,
        None,
        Some(0x000E_EEEE),
    );
    assert_eq!(dec_attack, FlowspecV6Decision::Drop);

    // 2. Evaluate Legitimate HTTP request -> Redirect to Scrubber
    let dec_http = engine.evaluate(
        attacker,
        victim_ip,
        6,
        Some(50000),
        Some(80),
        None,
        None,
        Some(0x02), // SYN
        None,
        None,
    );
    assert_eq!(dec_http, FlowspecV6Decision::Redirect(redirect_scrubber));

    // 3. Evaluate Unrelated traffic -> Pass
    let dec_ssh = engine.evaluate(
        attacker,
        victim_ip,
        6,
        Some(50000),
        Some(22),
        None,
        None,
        Some(0x02),
        None,
        None,
    );
    assert_eq!(dec_ssh, FlowspecV6Decision::Pass);
}

#[test]
fn test_flowspec_v6_wire_nlri_encoding_decoding() {
    let match_rule = FlowspecV6Match {
        dst_prefix: Some((
            Ipv6Address([
                0x20, 0x01, 0x0d, 0xb8, 0x11, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            64,
        )),
        src_prefix: Some((
            Ipv6Address([
                0x20, 0x01, 0x0d, 0xb8, 0x22, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            64,
        )),
        next_header: Some(17),
        dst_port: Some(8080),
        src_port: Some(3000),
        flow_label: Some(0x54321),
        ..Default::default()
    };

    let wire_bytes = serialize_flowspec_v6_nlri(&match_rule);
    let parsed_match = parse_flowspec_v6_nlri(&wire_bytes).expect("NLRI parse should succeed");

    assert_eq!(parsed_match.dst_prefix, match_rule.dst_prefix);
    assert_eq!(parsed_match.src_prefix, match_rule.src_prefix);
    assert_eq!(parsed_match.next_header, match_rule.next_header);
    assert_eq!(parsed_match.dst_port, match_rule.dst_port);
    assert_eq!(parsed_match.src_port, match_rule.src_port);
    assert_eq!(parsed_match.flow_label, match_rule.flow_label);
}
