//! Integration tests for 3GPP TS 29.544 / TS 23.548 5G Edge Application Server Discovery Function (EASDF) Engine.

use toy_tcpip::easdf_5g::*;
use toy_tcpip::ipv4::Ipv4Address;

// ---------------------------------------------------------------------------
// 1. Report and Forward Rule with SMF Notification
// ---------------------------------------------------------------------------

#[test]
fn test_easdf_report_and_forward_rule_happy_path() {
    let default_dns = Ipv4Address::new(8, 8, 8, 8);
    let mut easdf = EasdfEngine::new("easdf-mec-01", default_dns);

    let local_ldns = Ipv4Address::new(10, 20, 0, 1);
    let edge_ip = Ipv4Address::new(10, 20, 10, 5);
    easdf.add_dns_record(local_ldns, "server-a.edge.gamestream.com", edge_ip);

    let ue_ip = Ipv4Address::new(10, 45, 0, 10);
    let rule = DnsRule {
        rule_id: 101,
        precedence: 10,
        fqdn_patterns: vec!["*.edge.gamestream.com".to_string()],
        action: DnsAction::ReportAndForward,
        target_ldns_ip: Some(local_ldns),
        target_dnai: Some("edge-tokyo-01".to_string()),
        ecs_client_subnet: None,
    };

    let ctx_id = easdf.create_dns_context("imsi-208950000000001", 1, ue_ip, "internet", vec![rule]);
    assert!(!ctx_id.is_empty());

    // UE issues DNS lookup
    let res = easdf
        .process_dns_query(ue_ip, "server-a.edge.gamestream.com", 1000)
        .expect("DNS processing failed");

    assert_eq!(res.resolved_ip, edge_ip);
    assert_eq!(res.matched_rule_id, Some(101));
    assert_eq!(res.forwarded_ldns, Some(local_ldns));

    // Verify event report queued for SMF
    assert_eq!(easdf.smf_notification_queue.len(), 1);
    let notif = &easdf.smf_notification_queue[0];
    assert_eq!(notif.supi, "imsi-208950000000001");
    assert_eq!(notif.matched_rule_id, 101);
    assert_eq!(notif.target_dnai, Some("edge-tokyo-01".to_string()));
}

// ---------------------------------------------------------------------------
// 2. Wildcard Matching & Precedence Ordering
// ---------------------------------------------------------------------------

#[test]
fn test_easdf_wildcard_fqdn_matching_and_precedence() {
    let mut easdf = EasdfEngine::new("easdf-mec-02", Ipv4Address::new(8, 8, 8, 8));

    let ldns_vip = Ipv4Address::new(10, 20, 0, 2);
    let ldns_general = Ipv4Address::new(10, 20, 0, 1);

    let ip_vip = Ipv4Address::new(10, 20, 20, 1);
    let ip_general = Ipv4Address::new(10, 20, 10, 1);

    easdf.add_dns_record(ldns_vip, "vip.edge.gamestream.com", ip_vip);
    easdf.add_dns_record(ldns_general, "normal.edge.gamestream.com", ip_general);

    let ue_ip = Ipv4Address::new(10, 45, 0, 11);

    // Rule 1: Exact match on VIP (precedence 5 - higher priority)
    let r1 = DnsRule {
        rule_id: 1,
        precedence: 5,
        fqdn_patterns: vec!["vip.edge.gamestream.com".to_string()],
        action: DnsAction::ForwardToLdns,
        target_ldns_ip: Some(ldns_vip),
        target_dnai: Some("dnai-vip".to_string()),
        ecs_client_subnet: None,
    };

    // Rule 2: Wildcard match (precedence 50 - lower priority)
    let r2 = DnsRule {
        rule_id: 2,
        precedence: 50,
        fqdn_patterns: vec!["*.edge.gamestream.com".to_string()],
        action: DnsAction::ForwardToLdns,
        target_ldns_ip: Some(ldns_general),
        target_dnai: Some("dnai-general".to_string()),
        ecs_client_subnet: None,
    };

    easdf.create_dns_context("imsi-208950000000002", 1, ue_ip, "internet", vec![r2, r1]);

    // Query 1: VIP FQDN -> should match Rule 1
    let res1 = easdf
        .process_dns_query(ue_ip, "vip.edge.gamestream.com", 1000)
        .unwrap();
    assert_eq!(res1.resolved_ip, ip_vip);
    assert_eq!(res1.matched_rule_id, Some(1));

    // Query 2: Normal FQDN -> should match Rule 2
    let res2 = easdf
        .process_dns_query(ue_ip, "normal.edge.gamestream.com", 1000)
        .unwrap();
    assert_eq!(res2.resolved_ip, ip_general);
    assert_eq!(res2.matched_rule_id, Some(2));
}

// ---------------------------------------------------------------------------
// 3. EDNS0 Client Subnet (ECS) Injection
// ---------------------------------------------------------------------------

#[test]
fn test_easdf_ecs_injection_for_geo_dns() {
    let mut easdf = EasdfEngine::new("easdf-mec-03", Ipv4Address::new(8, 8, 8, 8));

    let ldns = Ipv4Address::new(10, 30, 0, 1);
    let edge_app_ip = Ipv4Address::new(10, 30, 0, 99);
    easdf.add_dns_record(ldns, "cloud-ar.metaverse.io", edge_app_ip);

    let ue_ip = Ipv4Address::new(10, 45, 0, 12);
    let rule = DnsRule {
        rule_id: 201,
        precedence: 10,
        fqdn_patterns: vec!["cloud-ar.metaverse.io".to_string()],
        action: DnsAction::InjectEcsAndForward,
        target_ldns_ip: Some(ldns),
        target_dnai: Some("dnai-ar-zone".to_string()),
        ecs_client_subnet: Some((Ipv4Address::new(10, 45, 0, 0), 24)),
    };

    easdf.create_dns_context("imsi-208950000000003", 1, ue_ip, "ims", vec![rule]);

    let res = easdf
        .process_dns_query(ue_ip, "cloud-ar.metaverse.io", 1000)
        .unwrap();

    assert_eq!(res.resolved_ip, edge_app_ip);
    assert!(res.ecs_injected);
}

// ---------------------------------------------------------------------------
// 4. Default DNS Fallback
// ---------------------------------------------------------------------------

#[test]
fn test_easdf_fallback_to_default_dns() {
    let default_dns = Ipv4Address::new(8, 8, 8, 8);
    let mut easdf = EasdfEngine::new("easdf-mec-04", default_dns);

    let wiki_ip = Ipv4Address::new(208, 80, 154, 224);
    easdf.add_dns_record(default_dns, "www.wikipedia.org", wiki_ip);

    let ue_ip = Ipv4Address::new(10, 45, 0, 13);
    // Context with no matching rules for wikipedia
    easdf.create_dns_context("imsi-208950000000004", 1, ue_ip, "internet", vec![]);

    let res = easdf
        .process_dns_query(ue_ip, "www.wikipedia.org", 1000)
        .unwrap();

    assert_eq!(res.resolved_ip, wiki_ip);
    assert_eq!(res.matched_rule_id, None);
    assert_eq!(res.forwarded_ldns, Some(default_dns));
    assert!(!res.ecs_injected);
}

// ---------------------------------------------------------------------------
// 5. Context Lifecycle (Create, Update, Delete)
// ---------------------------------------------------------------------------

#[test]
fn test_easdf_context_lifecycle_crud() {
    let mut easdf = EasdfEngine::new("easdf-mec-05", Ipv4Address::new(8, 8, 8, 8));
    let ue_ip = Ipv4Address::new(10, 45, 0, 14);

    let ctx_id = easdf.create_dns_context("imsi-208950000000005", 1, ue_ip, "internet", vec![]);
    assert!(easdf.contexts.contains_key(&ctx_id));

    // Update rules upon mobility
    let new_rule = DnsRule {
        rule_id: 301,
        precedence: 1,
        fqdn_patterns: vec!["mobility.mec.com".to_string()],
        action: DnsAction::ForwardDefault,
        target_ldns_ip: None,
        target_dnai: None,
        ecs_client_subnet: None,
    };
    easdf
        .update_dns_context_rules(&ctx_id, vec![new_rule])
        .unwrap();
    assert_eq!(easdf.contexts.get(&ctx_id).unwrap().dns_rules.len(), 1);

    // Delete context
    easdf.delete_dns_context(&ctx_id).unwrap();
    assert!(!easdf.contexts.contains_key(&ctx_id));

    // Query after deletion should fail with ContextNotFound
    let err = easdf.process_dns_query(ue_ip, "mobility.mec.com", 1000);
    assert_eq!(err, Err(EasdfError::ContextNotFound));
}
