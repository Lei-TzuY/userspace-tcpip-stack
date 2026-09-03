use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::icmpv6::*;
use toy_tcpip::ipv6::Ipv6Address;

#[test]
fn test_ndp_rdnss_dnssl_mtu_ra_codec() {
    let src = Ipv6Address::new([0xfe80, 0, 0, 0, 0, 0, 0, 1]);
    let dst = Ipv6Address::new([0xff02, 0, 0, 0, 0, 0, 0, 1]);
    let mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    let prefix = PrefixInformationOption::new(
        Ipv6Address::new([0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 0]),
        64,
        true,
        true,
        86400,
        14400,
    );

    let dns1 = Ipv6Address::new([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888]);
    let dns2 = Ipv6Address::new([0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844]);
    let rdnss = RdnssOption::new(3600, vec![dns1, dns2]);

    let dnssl = DnsslOption::new(
        3600,
        vec!["corp.example.com".to_string(), "lab.local".to_string()],
    );

    let packet_raw = Icmpv6Packet::build_router_advertisement_full(
        src,
        dst,
        64,
        1800,
        RouterPreference::High,
        &[prefix],
        &[],
        Some(1500),
        &[rdnss],
        &[dnssl],
        Some(mac),
    );

    let parsed_icmp = Icmpv6Packet::parse(src, dst, &packet_raw, true).unwrap();
    let ra = parsed_icmp
        .validated_router_advertisement(src, 255)
        .unwrap();

    assert_eq!(ra.current_hop_limit, 64);
    assert_eq!(ra.router_lifetime, 1800);
    assert_eq!(ra.preference, RouterPreference::High);
    assert_eq!(ra.mtu, Some(1500));

    assert_eq!(ra.prefixes.len(), 1);
    assert_eq!(ra.prefixes[0].prefix_length, 64);

    assert_eq!(ra.rdnss.len(), 1);
    assert_eq!(ra.rdnss[0].lifetime, 3600);
    assert_eq!(ra.rdnss[0].servers, vec![dns1, dns2]);

    assert_eq!(ra.dnssl.len(), 1);
    assert_eq!(ra.dnssl[0].lifetime, 3600);
    assert_eq!(
        ra.dnssl[0].search_list,
        vec!["corp.example.com".to_string(), "lab.local".to_string()]
    );
}

#[test]
fn test_ndp_table_rdnss_dnssl_lifecycle() {
    let mut table = NdpTable::new();
    assert_eq!(table.learned_dns_servers(1000).len(), 0);
    assert_eq!(table.learned_search_domains(1000).len(), 0);
    assert_eq!(table.learned_mtu(), None);

    let dns1 = Ipv6Address::new([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53]);
    let rdnss = RdnssOption::new(300, vec![dns1]);
    let dnssl = DnsslOption::new(300, vec!["example.org".to_string()]);

    let ra = RouterAdvertisement {
        current_hop_limit: 64,
        managed: false,
        other_config: false,
        preference: RouterPreference::Medium,
        router_lifetime: 600,
        reachable_time: 30000,
        retrans_timer: 1000,
        prefixes: vec![],
        routes: vec![],
        mtu: Some(1400),
        rdnss: vec![rdnss],
        dnssl: vec![dnssl],
    };

    // Apply RA at t = 1,000 ms (valid for 300 s -> expires at t = 301,000 ms)
    table.apply_router_advertisement(&ra, 1000);

    assert_eq!(table.learned_mtu(), Some(1400));
    assert_eq!(table.learned_dns_servers(2000), vec![dns1]);
    assert_eq!(
        table.learned_search_domains(2000),
        vec!["example.org".to_string()]
    );

    // Check after expiry (t = 302,000 ms)
    assert_eq!(table.learned_dns_servers(302000).len(), 0);
    assert_eq!(table.learned_search_domains(302000).len(), 0);

    // Apply RA with lifetime 0 to explicitly revoke
    let revoke_rdnss = RdnssOption::new(0, vec![dns1]);
    let revoke_ra = RouterAdvertisement {
        current_hop_limit: 64,
        managed: false,
        other_config: false,
        preference: RouterPreference::Medium,
        router_lifetime: 600,
        reachable_time: 30000,
        retrans_timer: 1000,
        prefixes: vec![],
        routes: vec![],
        mtu: None,
        rdnss: vec![revoke_rdnss],
        dnssl: vec![],
    };

    table.apply_router_advertisement(&revoke_ra, 5000);
    assert_eq!(table.learned_dns_servers(6000).len(), 0);
}
