use toy_tcpip::diameter_zh::{
    BsfZhEngine, DIAMETER_APPLICATION_ZH, DIAMETER_CMD_MULTIMEDIA_AUTH, GbaAuthVector, GbaType,
    ZhAvp, ZhMessage,
};

#[test]
fn test_diameter_zh_bootstrapping_and_naf_key_derivation() {
    let mut bsf = BsfZhEngine::new("hss.node.ims.net");
    let vec = GbaAuthVector {
        rand: [0xAA; 16],
        autn: [0xBB; 16],
        ck: [0xCC; 16],
        ik: [0xDD; 16],
    };
    bsf.register_subscriber(
        "460019998887771",
        "<guss-profile>active</guss-profile>",
        vec,
    );

    let mar = ZhMessage::new_mar("sess-zh-999", "460019998887771", GbaType::Gba3G);
    assert_eq!(mar.application_id, DIAMETER_APPLICATION_ZH);
    assert_eq!(mar.command_code, DIAMETER_CMD_MULTIMEDIA_AUTH);

    let maa = bsf.handle_mar(&mar);
    assert!(!maa.is_request);

    let rc = maa.avps.iter().find_map(|a| {
        if let ZhAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));

    let ks_naf = bsf
        .derive_ks_naf("460019998887771", "secure.banking.naf")
        .unwrap();
    assert_eq!(ks_naf.len(), 32);
    assert_eq!(bsf.successful_bootstraps, 1);
}
