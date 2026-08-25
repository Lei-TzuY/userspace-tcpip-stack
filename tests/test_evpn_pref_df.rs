use toy_tcpip::evpn_pref_df::{
    CandidatePe, DfElectionAlgorithm, EvpnDfElectionExtCommunity, EvpnPrefDfEngine,
    BGP_EXT_COMM_SUBTYPE_DF_ELECTION, BGP_EXT_COMM_TYPE_EVPN,
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
