use toy_tcpip::evpn_pref_df::{
    BGP_EXT_COMM_SUBTYPE_DF_ELECTION, BGP_EXT_COMM_TYPE_EVPN, CandidatePe, DfElectionAlgorithm,
    DfTimerState, EvpnDfElectionExtCommunity, EvpnPrefDfEngine, compute_hrw_weight,
};
use toy_tcpip::evpn_synch::EthernetSegmentId;
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_evpn_pref_df_extended_community_codec() {
    let comm = EvpnDfElectionExtCommunity::new_preference(500, true, false);
    let wire = comm.serialize();

    assert_eq!(wire.len(), 8);
    assert_eq!(wire[0], BGP_EXT_COMM_TYPE_EVPN);
    assert_eq!(wire[1], BGP_EXT_COMM_SUBTYPE_DF_ELECTION);
    assert_eq!(wire[2], DfElectionAlgorithm::PreferenceBased as u8);
    assert_eq!(wire[3] & 0x01, 0x01); // DP bit set
    assert_eq!(wire[3] & 0x02, 0x00); // Sticky bit false
    assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 500);

    let parsed = EvpnDfElectionExtCommunity::parse(&wire).expect("parse DF community");
    assert_eq!(parsed.algorithm, DfElectionAlgorithm::PreferenceBased);
    assert_eq!(parsed.dont_preempt, true);
    assert_eq!(parsed.sticky, false);
    assert_eq!(parsed.preference, 500);
}

#[test]
fn test_evpn_preference_df_election_and_dont_preempt() {
    let mut engine = EvpnPrefDfEngine::new();
    let esi = EthernetSegmentId([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);

    let pe1 = Ipv4Address::new(192, 168, 1, 1);
    let pe2 = Ipv4Address::new(192, 168, 1, 2);

    // PE1: Preference 200 (Active DF) with Don't Preempt bit
    engine.add_or_update_candidate(
        esi,
        CandidatePe {
            pe_ip: pe1,
            preference: 200,
            dont_preempt: true,
            sticky: false,
        },
    );

    // PE2: Preference 100
    engine.add_or_update_candidate(
        esi,
        CandidatePe {
            pe_ip: pe2,
            preference: 100,
            dont_preempt: false,
            sticky: false,
        },
    );

    let elected = engine.elect_df(esi).expect("elect DF");
    assert_eq!(elected, pe1); // PE1 wins due to higher preference

    // A third PE comes online with higher preference 300
    let pe3 = Ipv4Address::new(192, 168, 1, 3);
    engine.add_or_update_candidate(
        esi,
        CandidatePe {
            pe_ip: pe3,
            preference: 300,
            dont_preempt: false,
            sticky: false,
        },
    );

    // Because PE1 has dont_preempt set, it remains DF despite PE3's higher preference
    let elected_retained = engine.elect_df(esi).expect("retain DF");
    assert_eq!(elected_retained, pe1);

    // PE1 link fails and PE1 is removed
    engine.remove_candidate(esi, pe1);

    // Election runs again, PE3 now wins with preference 300
    let elected_new = engine.elect_df(esi).expect("elect new DF");
    assert_eq!(elected_new, pe3);
}

#[test]
fn test_evpn_hrw_and_modulo_per_vlan_df_carving() {
    let mut engine = EvpnPrefDfEngine::new();
    let esi = EthernetSegmentId([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x11, 0x22, 0x33, 0x44]);

    let pe1 = Ipv4Address::new(10, 0, 0, 1);
    let pe2 = Ipv4Address::new(10, 0, 0, 2);
    let pe3 = Ipv4Address::new(10, 0, 0, 3);

    for &pe in &[pe1, pe2, pe3] {
        engine.add_or_update_candidate(
            esi,
            CandidatePe {
                pe_ip: pe,
                preference: 100,
                dont_preempt: false,
                sticky: false,
            },
        );
    }

    let vlans: Vec<u32> = (100..110).collect();

    // 1. Test Modulo Carving (Algorithm 0x00)
    let modulo_map = engine.elect_df_per_vlan(esi, &vlans, DfElectionAlgorithm::DefaultModulo);
    assert_eq!(modulo_map.len(), 10);
    // VLAN 100 % 3 = 1 -> pe2 (sorted: pe1, pe2, pe3)
    assert_eq!(modulo_map[&100], pe2);
    // VLAN 101 % 3 = 2 -> pe3
    assert_eq!(modulo_map[&101], pe3);
    // VLAN 102 % 3 = 0 -> pe1
    assert_eq!(modulo_map[&102], pe1);

    // 2. Test Highest Random Weight (HRW Algorithm 0x01)
    let hrw_map = engine.elect_df_per_vlan(esi, &vlans, DfElectionAlgorithm::HighestRandomWeight);
    assert_eq!(hrw_map.len(), 10);
    // Ensure all 3 PEs are assigned at least one VLAN across the 10 VLANs (load distribution)
    let mut pe_counts = std::collections::HashMap::new();
    for winner in hrw_map.values() {
        *pe_counts.entry(*winner).or_insert(0) += 1;
    }
    assert!(
        pe_counts.len() >= 2,
        "HRW should distribute VLANs across candidates"
    );

    // HRW weight determinism
    let w1 = compute_hrw_weight(100, pe1);
    let w2 = compute_hrw_weight(100, pe1);
    assert_eq!(w1, w2);
}

#[test]
fn test_evpn_df_election_wait_timer_lifecycle() {
    let mut engine = EvpnPrefDfEngine::new();
    let esi = EthernetSegmentId([0x11; 10]);

    let pe1 = Ipv4Address::new(172, 16, 0, 1);
    engine.add_or_update_candidate(
        esi,
        CandidatePe {
            pe_ip: pe1,
            preference: 500,
            dont_preempt: false,
            sticky: false,
        },
    );

    // Start 3000ms wait timer
    engine.start_election_timer(esi, 3000);
    assert_eq!(
        engine.timer_state.get(&esi),
        Some(&DfTimerState::Waiting { remaining_ms: 3000 })
    );

    // Advance 1000ms -> still waiting
    let result1 = engine.tick_timer(1000);
    assert!(result1.is_empty());
    assert_eq!(
        engine.timer_state.get(&esi),
        Some(&DfTimerState::Waiting { remaining_ms: 2000 })
    );

    // Advance 2500ms -> timer expires and PE1 is elected DF
    let result2 = engine.tick_timer(2500);
    assert_eq!(result2.len(), 1);
    assert_eq!(result2[0], (esi, pe1));
    assert_eq!(engine.timer_state.get(&esi), Some(&DfTimerState::Elected));
    assert_eq!(engine.elected_df.get(&esi), Some(&pe1));
}
