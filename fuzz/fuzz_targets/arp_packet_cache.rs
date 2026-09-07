#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::arp::{ArpLearnOutcome, ArpPacket, ArpTable, ARP_PACKET_LEN};
use toy_tcpip::ethernet::MacAddress;

fuzz_target!(|data: &[u8]| {
    // First exercise the raw parser directly. Successful parses must round-trip
    // to the canonical 28-byte Ethernet/IPv4 ARP encoding even when the input
    // carried trailing bytes.
    if let Ok(packet) = ArpPacket::parse(data) {
        let encoded = packet.serialize();
        assert_eq!(encoded.len(), ARP_PACKET_LEN);
        assert_eq!(ArpPacket::parse(&encoded).unwrap(), packet);
    }

    if data.len() < 24 {
        return;
    }

    let sender_mac = MacAddress([
        data[0], data[1], data[2], data[3], data[4], data[5],
    ]);
    let sender_ip = [data[6], data[7], data[8], data[9]];
    let target_mac = MacAddress([
        data[10], data[11], data[12], data[13], data[14], data[15],
    ]);
    let target_ip = [data[16], data[17], data[18], data[19]];
    let now_ms = u16::from_be_bytes([data[20], data[21]]) as u64;
    let ttl_ms = 1 + u16::from_be_bytes([data[22], data[23]]) as u64;

    let packet = if data.get(24).copied().unwrap_or_default() & 1 == 0 {
        ArpPacket::build_request(sender_mac, sender_ip, target_ip)
    } else {
        ArpPacket::build_reply(sender_mac, sender_ip, target_mac, target_ip)
    };

    let mut table = ArpTable::new();
    let outcome = table.learn_from_packet(&packet, now_ms, ttl_ms);

    match outcome {
        ArpLearnOutcome::IgnoredProbe | ArpLearnOutcome::IgnoredInvalidSender => {
            assert_eq!(table.lookup(&sender_ip), None);
        }
        ArpLearnOutcome::Learned => {
            assert_eq!(table.lookup_at(&sender_ip, now_ms), Some(sender_mac));
            assert_eq!(table.lookup_at(&sender_ip, now_ms.saturating_add(ttl_ms)), None);
            assert_eq!(table.purge_expired(now_ms.saturating_add(ttl_ms)), 1);
            assert_eq!(table.lookup(&sender_ip), None);
        }
        other => panic!("fresh table produced unexpected ARP learning outcome: {other:?}"),
    }

    // A static entry must never be replaced by a contradictory advertisement.
    if sender_ip != [0, 0, 0, 0] {
        let configured = MacAddress([0x02, 0, 0, 0, 0, data[0]]);
        let mut static_table = ArpTable::new();
        static_table.insert_static(sender_ip, configured);
        let _ = static_table.learn_from_packet(&packet, now_ms, ttl_ms);
        assert_eq!(static_table.lookup(&sender_ip), Some(configured));
    }
});
