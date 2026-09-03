// tests/test_evpn_ssm_dr_election.rs

use toy_tcpip::evpn_ssm_dr_election::{DrElectionVerdict, EvpnSsmDrElectionEngine};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_ssm_dr_election_lifecycle() {
    let local_pe = Ipv4Address::new(192, 168, 10, 1);
    let mut engine = EvpnSsmDrElectionEngine::new(local_pe, 150, 45);

    let esi = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];
    let vni = 200;

    // 1. Local PE registers -> Elected as DR
    engine.register_segment(esi, vni, 500);
    let v1 = engine.run_election(esi, vni);
    assert_eq!(
        v1,
        Some(DrElectionVerdict::ElectedAsDr {
            esi,
            vni,
            dr_ip: local_pe,
            priority: 150,
        })
    );

    // 2. Add remote PE 192.168.10.2 with equal priority 150 -> higher IP wins tie-break
    let remote_pe2 = Ipv4Address::new(192, 168, 10, 2);
    engine.add_or_update_remote_pe(esi, vni, remote_pe2, 150, 500);
    let v2 = engine.run_election(esi, vni);
    assert_eq!(
        v2,
        Some(DrElectionVerdict::StandbyNonDr {
            esi,
            vni,
            active_dr_ip: remote_pe2,
            active_dr_priority: 150,
        })
    );

    // 3. Add remote PE 192.168.10.3 with highest priority 250 -> wins election
    let remote_pe3 = Ipv4Address::new(192, 168, 10, 3);
    engine.add_or_update_remote_pe(esi, vni, remote_pe3, 250, 500);
    let v3 = engine.run_election(esi, vni);
    assert_eq!(
        v3,
        Some(DrElectionVerdict::StandbyNonDr {
            esi,
            vni,
            active_dr_ip: remote_pe3,
            active_dr_priority: 250,
        })
    );

    // 4. Remote PE 3 sends keepalive query at t = 520, Remote PE 2 at t = 560
    engine.record_dr_query(esi, vni, remote_pe3, 520);
    engine.record_dr_query(esi, vni, remote_pe2, 560);

    // 5. At t = 550, no timeout yet (550 - 520 = 30s <= 45s)
    let timeouts = engine.check_timeouts(550);
    assert!(timeouts.is_empty());

    // 6. At t = 580 (60s since last query > 45s timeout), Remote PE 3 fails -> PE 2 is next highest
    let failovers = engine.check_timeouts(580);
    assert_eq!(failovers.len(), 1);
    assert_eq!(
        failovers[0],
        DrElectionVerdict::DrFailoverTriggered {
            esi,
            vni,
            new_dr_ip: remote_pe2,
            new_dr_priority: 150,
            is_local_elected: false,
        }
    );
}
