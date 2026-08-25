use toy_tcpip::arp::{
    ARP_DEFAULT_DYNAMIC_TTL_MS, ArpEntryKind, ArpLearnOutcome, ArpPacket, ArpTable,
};
use toy_tcpip::ethernet::MacAddress;

fn mac(last: u8) -> MacAddress {
    MacAddress([0x02, 0, 0, 0, 0, last])
}

#[test]
fn timed_dynamic_learning_ages_out_without_touching_static_entries() {
    let mut table = ArpTable::new();
    let dynamic_ip = [192, 0, 2, 10];
    let static_ip = [192, 0, 2, 1];

    table.insert_dynamic_default(dynamic_ip, mac(10), 1_000);
    table.insert_static(static_ip, mac(1));

    assert_eq!(
        table.entry_meta(&dynamic_ip).unwrap().kind,
        ArpEntryKind::Dynamic
    );
    assert_eq!(
        table.entry_meta(&static_ip).unwrap().kind,
        ArpEntryKind::Static
    );
    assert_eq!(
        table.lookup_at(&dynamic_ip, 1_000 + ARP_DEFAULT_DYNAMIC_TTL_MS - 1),
        Some(mac(10))
    );
    assert_eq!(
        table.lookup_at(&dynamic_ip, 1_000 + ARP_DEFAULT_DYNAMIC_TTL_MS),
        None
    );
    assert_eq!(table.purge_expired(1_000 + ARP_DEFAULT_DYNAMIC_TTL_MS), 1);
    assert_eq!(table.lookup(&static_ip), Some(mac(1)));
}

#[test]
fn rfc5227_probe_does_not_poison_zero_address_cache_entry() {
    let mut table = ArpTable::new();
    let probe = ArpPacket::build_probe(mac(7), [198, 51, 100, 25]);

    assert!(probe.is_probe());
    assert_eq!(
        table.learn_from_packet(&probe, 10, 30_000),
        ArpLearnOutcome::IgnoredProbe
    );
    assert_eq!(table.lookup(&[0, 0, 0, 0]), None);
    assert!(table.is_empty());
}

#[test]
fn gratuitous_arp_can_refresh_a_dynamic_mapping() {
    let mut table = ArpTable::new();
    let ip = [203, 0, 113, 9];
    let announcement = ArpPacket::build_announcement(mac(9), ip);

    assert!(announcement.is_gratuitous());
    assert_eq!(
        table.learn_from_packet(&announcement, 100, 50),
        ArpLearnOutcome::Learned
    );
    assert_eq!(
        table.learn_from_packet(&announcement, 125, 50),
        ArpLearnOutcome::Refreshed
    );
    assert_eq!(table.lookup_at(&ip, 174), Some(mac(9)));
    assert_eq!(table.lookup_at(&ip, 175), None);
}

#[test]
fn static_mapping_wins_over_conflicting_wire_advertisement() {
    let mut table = ArpTable::new();
    let gateway_ip = [10, 10, 0, 1];
    table.insert_static(gateway_ip, mac(1));

    let conflicting = ArpPacket::build_reply(mac(99), gateway_ip, mac(5), [10, 10, 0, 5]);
    assert_eq!(
        table.learn_from_packet(&conflicting, 500, 60_000),
        ArpLearnOutcome::StaticConflict {
            configured: mac(1),
            advertised: mac(99),
        }
    );
    assert_eq!(table.lookup(&gateway_ip), Some(mac(1)));
}
