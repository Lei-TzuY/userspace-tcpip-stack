#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::icmpv6::{
    NDP_DELAY_FIRST_PROBE_TIME_MS, NDP_REACHABLE_TIME_MS, NDP_RETRANS_TIMER_MS, NdpTable,
    NeighborState,
};
use toy_tcpip::ipv6::Ipv6Address;

fn ip(bytes: &[u8]) -> Ipv6Address {
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&bytes[..16]);
    Ipv6Address(addr)
}

fn mac(bytes: &[u8]) -> MacAddress {
    let mut addr = [0u8; 6];
    addr.copy_from_slice(&bytes[..6]);
    MacAddress(addr)
}

fuzz_target!(|data: &[u8]| {
    let mut table = NdpTable::new();

    for chunk in data.chunks_exact(32).take(256) {
        let neighbor = ip(&chunk[1..17]);
        let link = mac(&chunk[17..23]);
        let now_ms = u64::from_be_bytes(chunk[24..32].try_into().expect("fixed chunk"));

        match chunk[0] % 7 {
            0 => {
                table.insert(neighbor, link);
                assert_eq!(table.lookup(&neighbor), Some(link));
                assert_eq!(table.state(&neighbor), Some(NeighborState::Reachable));
            }
            1 => {
                table.learn_stale(neighbor, link);
                assert_eq!(table.lookup(&neighbor), Some(link));
            }
            2 => {
                table.mark_stale(neighbor, link);
                assert_eq!(table.lookup(&neighbor), Some(link));
                assert_eq!(table.state(&neighbor), Some(NeighborState::Stale));
            }
            3 => {
                table.confirm_reachable(neighbor, link, now_ms);
                assert_eq!(table.lookup(&neighbor), Some(link));
                assert_eq!(table.state(&neighbor), Some(NeighborState::Reachable));
            }
            4 => {
                let before = table.lookup(&neighbor);
                let after = table.lookup_for_transmit(&neighbor, now_ms);
                assert_eq!(after, before);
            }
            5 => {
                table.demote_reachable_preserving_mac(neighbor);
            }
            _ => {
                let probes = table.step_nud(now_ms);
                for (target, target_mac) in probes {
                    assert_eq!(table.lookup(&target), Some(target_mac));
                    assert_eq!(table.state(&target), Some(NeighborState::Probe));
                }
            }
        }
    }

    // A static/external mapping must not be aged out by NUD timer pumps.
    let static_ip = Ipv6Address([0xfd, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let static_mac = MacAddress([0x02, 0xff, 0, 0, 0, 1]);
    table.insert(static_ip, static_mac);
    table.step_nud(u64::MAX);
    assert_eq!(table.lookup(&static_ip), Some(static_mac));
    assert_eq!(table.state(&static_ip), Some(NeighborState::Reachable));

    // Drive one dynamic neighbor through the full RFC 4861 NUD lifecycle.
    let dynamic_ip = Ipv6Address([0xfd, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    let dynamic_mac = MacAddress([0x02, 0xfe, 0, 0, 0, 2]);
    let base = 1_000_000u64;
    table.confirm_reachable(dynamic_ip, dynamic_mac, base);
    assert_eq!(table.state(&dynamic_ip), Some(NeighborState::Reachable));

    table.step_nud(base + NDP_REACHABLE_TIME_MS);
    assert_eq!(table.state(&dynamic_ip), Some(NeighborState::Stale));

    assert_eq!(
        table.lookup_for_transmit(&dynamic_ip, base + NDP_REACHABLE_TIME_MS),
        Some(dynamic_mac)
    );
    assert_eq!(table.state(&dynamic_ip), Some(NeighborState::Delay));

    let first_probe = base + NDP_REACHABLE_TIME_MS + NDP_DELAY_FIRST_PROBE_TIME_MS;
    assert_eq!(table.step_nud(first_probe), vec![(dynamic_ip, dynamic_mac)]);
    assert_eq!(table.state(&dynamic_ip), Some(NeighborState::Probe));

    assert_eq!(
        table.step_nud(first_probe + NDP_RETRANS_TIMER_MS),
        vec![(dynamic_ip, dynamic_mac)]
    );
    assert_eq!(
        table.step_nud(first_probe + 2 * NDP_RETRANS_TIMER_MS),
        vec![(dynamic_ip, dynamic_mac)]
    );
    assert!(
        table
            .step_nud(first_probe + 3 * NDP_RETRANS_TIMER_MS)
            .is_empty()
    );
    assert_eq!(table.lookup(&dynamic_ip), None);

    // Exhausting one dynamic neighbor must not disturb the independent static entry.
    assert_eq!(table.lookup(&static_ip), Some(static_mac));
});
