use toy_tcpip::dns::*;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::ipv6::Ipv6Address;

#[test]
fn test_dns_aaaa_ipv6_resolution() {
    let hostname = "ipv6.example.org";
    let ipv6 = Ipv6Address([
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88,
        0x88,
    ]);
    let id = 0xbeef;

    // 1. Build Query
    let query_wire = DnsMessage::build_aaaa_query(id, hostname);
    let query = DnsMessage::parse(&query_wire).unwrap();
    assert_eq!(query.id, id);
    assert_eq!(query.questions.len(), 1);
    assert_eq!(query.questions[0].name, hostname);
    assert_eq!(query.questions[0].qtype, DNS_TYPE_AAAA);
    assert_eq!(query.questions[0].qclass, DNS_CLASS_IN);

    // 2. Build Response
    let resp_wire = DnsMessage::build_aaaa_response(id, hostname, ipv6, 3600);
    let resp = DnsMessage::parse(&resp_wire).unwrap();
    assert_eq!(resp.id, id);
    assert!(resp.is_response);
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(resp.answers[0].name, hostname);
    assert_eq!(resp.answers[0].rtype, DNS_TYPE_AAAA);
    assert_eq!(resp.answers[0].ttl, 3600);
    assert_eq!(resp.answers[0].data, DnsRecordData::Aaaa(ipv6));
}

#[test]
fn test_dns_reverse_ptr_queries_v4_and_v6() {
    // IPv4 reverse pointer
    let ip4 = Ipv4Address::new(192, 0, 2, 1);
    let query_v4 = DnsMessage::build_ptr_query_v4(0x1111, ip4);
    let parsed_v4 = DnsMessage::parse(&query_v4).unwrap();
    assert_eq!(parsed_v4.questions[0].name, "1.2.0.192.in-addr.arpa");
    assert_eq!(parsed_v4.questions[0].qtype, DNS_TYPE_PTR);

    let resp_v4 =
        DnsMessage::build_ptr_response(0x1111, "1.2.0.192.in-addr.arpa", "host1.example.org", 300);
    let parsed_resp_v4 = DnsMessage::parse(&resp_v4).unwrap();
    assert_eq!(
        parsed_resp_v4.answers[0].data,
        DnsRecordData::Ptr("host1.example.org".to_string())
    );

    // IPv6 reverse pointer
    let ip6 = Ipv6Address([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
    ]);
    let query_v6 = DnsMessage::build_ptr_query_v6(0x2222, ip6);
    let parsed_v6 = DnsMessage::parse(&query_v6).unwrap();
    assert!(parsed_v6.questions[0].name.ends_with(".ip6.arpa"));
    assert_eq!(parsed_v6.questions[0].qtype, DNS_TYPE_PTR);
}

#[test]
fn test_dns_cname_mx_txt_srv_records() {
    let id = 0x3333;

    // CNAME
    let cname_wire = DnsMessage::build_cname_response(id, "www.example.com", "example.com", 600);
    let cname_msg = DnsMessage::parse(&cname_wire).unwrap();
    assert_eq!(
        cname_msg.answers[0].data,
        DnsRecordData::Cname("example.com".to_string())
    );

    // MX
    let mx_wire = DnsMessage::build_mx_response(id, "example.com", 10, "mail.example.com", 1800);
    let mx_msg = DnsMessage::parse(&mx_wire).unwrap();
    assert_eq!(
        mx_msg.answers[0].data,
        DnsRecordData::Mx {
            preference: 10,
            exchange: "mail.example.com".to_string()
        }
    );

    // TXT
    let txt_wire = DnsMessage::build_txt_response(
        id,
        "example.com",
        &["v=spf1 -all", "google-site-verification=abc123xyz"],
        3600,
    );
    let txt_msg = DnsMessage::parse(&txt_wire).unwrap();
    assert_eq!(
        txt_msg.answers[0].data,
        DnsRecordData::Txt(vec![
            "v=spf1 -all".to_string(),
            "google-site-verification=abc123xyz".to_string()
        ])
    );

    // SRV
    let srv_wire = DnsMessage::build_srv_response(
        id,
        "_http._tcp.example.com",
        0,
        5,
        8080,
        "web1.example.com",
        300,
    );
    let srv_msg = DnsMessage::parse(&srv_wire).unwrap();
    assert_eq!(
        srv_msg.answers[0].data,
        DnsRecordData::Srv {
            priority: 0,
            weight: 5,
            port: 8080,
            target: "web1.example.com".to_string()
        }
    );
}

#[test]
fn test_dns_nxdomain_and_caching_resolver() {
    let id = 0x4444;
    let nx_wire = DnsMessage::build_nxdomain_response(id, "nonexistent.example.com", DNS_TYPE_A);
    let nx_msg = DnsMessage::parse(&nx_wire).unwrap();
    assert_eq!(nx_msg.rcode, DNS_RCODE_NXDOMAIN);
    assert_eq!(nx_msg.questions[0].name, "nonexistent.example.com");

    // Cache testing
    let mut cache = DnsCache::new();
    let now = 10_000u64;

    // Positive Cache
    let ip4 = Ipv4Address::new(93, 184, 216, 34);
    let ip6 = Ipv6Address([
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19,
        0x46,
    ]);
    let ans_a = DnsAnswer {
        name: "example.com".to_string(),
        rtype: DNS_TYPE_A,
        rclass: DNS_CLASS_IN,
        ttl: 300,
        ip: ip4,
        data: DnsRecordData::A(ip4),
    };
    let ans_aaaa = DnsAnswer {
        name: "example.com".to_string(),
        rtype: DNS_TYPE_AAAA,
        rclass: DNS_CLASS_IN,
        ttl: 600,
        ip: Ipv4Address::new(0, 0, 0, 0),
        data: DnsRecordData::Aaaa(ip6),
    };

    cache.insert("example.com", DNS_TYPE_A, vec![ans_a], now);
    cache.insert("example.com", DNS_TYPE_AAAA, vec![ans_aaaa], now);

    assert_eq!(cache.lookup_a("example.com", now + 100), Some(vec![ip4]));
    assert_eq!(cache.lookup_aaaa("example.com", now + 100), Some(vec![ip6]));

    // Check TTL decrement
    let lookup_res = cache
        .lookup("example.com", DNS_TYPE_A, now + 100)
        .unwrap()
        .unwrap();
    assert_eq!(lookup_res[0].ttl, 200);

    // Negative Cache
    cache.insert_negative("invalid.domain", DNS_TYPE_A, 60, now);
    assert_eq!(
        cache.lookup("invalid.domain", DNS_TYPE_A, now + 30),
        Some(Err(()))
    );

    // Purge expired
    cache.purge_expired(now + 350);
    assert_eq!(cache.lookup_a("example.com", now + 350), None);
    assert_eq!(cache.lookup_aaaa("example.com", now + 350), Some(vec![ip6]));
}
