use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::pim_bsr::{
    CandidateRpRecord, EncodedGroupAddress, GroupRpMapping, PimBootstrapMessage, PimBsrEngine,
    PimCandidateRpAdv,
};

#[test]
fn test_encoded_group_and_candidate_rp_codec() {
    let grp = EncodedGroupAddress::new(Ipv4Address::new(239, 255, 0, 0), 16);
    let bytes = grp.encode();
    assert_eq!(bytes.len(), 8);

    let (decoded_grp, consumed) = EncodedGroupAddress::decode(&bytes).expect("decode group");
    assert_eq!(consumed, 8);
    assert_eq!(decoded_grp, grp);

    let crp = CandidateRpRecord::new(Ipv4Address::new(10, 0, 0, 1), 10, 180);
    let crp_bytes = crp.encode();
    assert_eq!(crp_bytes.len(), 8);
}

#[test]
fn test_pim_bootstrap_message_codec() {
    let bsr_ip = Ipv4Address::new(192, 168, 1, 1);
    let mut bsm = PimBootstrapMessage::new(bsr_ip, 128, 30);

    let grp = EncodedGroupAddress::new(Ipv4Address::new(239, 0, 0, 0), 8);
    let mapping = GroupRpMapping {
        group: grp,
        rp_count: 2,
        frag_tag: 0x1234,
        candidates: vec![
            CandidateRpRecord::new(Ipv4Address::new(10, 1, 1, 1), 10, 150),
            CandidateRpRecord::new(Ipv4Address::new(10, 1, 1, 2), 10, 150),
        ],
    };
    bsm.group_mappings.push(mapping);

    let wire = bsm.serialize();
    let parsed = PimBootstrapMessage::parse(&wire).expect("parse BSM");
    assert_eq!(parsed.bsr_ip, bsr_ip);
    assert_eq!(parsed.bsr_priority, 128);
    assert_eq!(parsed.hash_mask_len, 30);
    assert_eq!(parsed.group_mappings.len(), 1);
    assert_eq!(parsed.group_mappings[0].candidates.len(), 2);
}

#[test]
fn test_pim_bsr_election_and_ssm_bypass() {
    let mut engine = PimBsrEngine::new(Ipv4Address::new(192, 168, 1, 10), true, 64);
    assert_eq!(engine.elected_bsr, Some(Ipv4Address::new(192, 168, 1, 10)));

    // Incoming BSM with higher priority (128 > 64)
    let higher_bsr = Ipv4Address::new(192, 168, 1, 1);
    let mut higher_bsm = PimBootstrapMessage::new(higher_bsr, 128, 30);
    let grp = EncodedGroupAddress::new(Ipv4Address::new(239, 0, 0, 0), 8);
    higher_bsm.group_mappings.push(GroupRpMapping {
        group: grp,
        rp_count: 1,
        frag_tag: 0,
        candidates: vec![CandidateRpRecord::new(Ipv4Address::new(10, 0, 0, 5), 10, 120)],
    });

    assert!(engine.process_bootstrap_message(higher_bsm));
    assert_eq!(engine.elected_bsr, Some(higher_bsr));

    // Resolve RP for ASM group
    let asm_group = Ipv4Address::new(239, 10, 20, 30);
    let resolved_rp = engine.get_rp_for_group(asm_group);
    assert_eq!(resolved_rp, Some(Ipv4Address::new(10, 0, 0, 5)));

    // Resolve RP for SSM group (232.0.0.0/8) -> Must return None (RP Bypassed!)
    let ssm_group = Ipv4Address::new(232, 1, 2, 3);
    assert!(PimBsrEngine::is_ssm_group(ssm_group));
    assert_eq!(engine.get_rp_for_group(ssm_group), None);
}

#[test]
fn test_candidate_rp_adv_codec() {
    let mut adv = PimCandidateRpAdv::new(Ipv4Address::new(10, 0, 0, 1), 5, 120);
    adv.group_prefixes.push(EncodedGroupAddress::new(Ipv4Address::new(239, 0, 0, 0), 8));
    let wire = adv.serialize();
    assert_eq!(wire.len(), 10 + 8);

    let parsed = PimCandidateRpAdv::parse(&wire).expect("parse C-RP-Adv");
    assert_eq!(parsed.rp_ip, Ipv4Address::new(10, 0, 0, 1));
    assert_eq!(parsed.priority, 5);
    assert_eq!(parsed.holdtime, 120);
    assert_eq!(parsed.group_prefixes.len(), 1);
}
