use toy_tcpip::diameter_np::{
    DIAMETER_APPLICATION_NP, DIAMETER_CMD_NON_AGGREGATED_RUCI_REPORT, NpAvp, NpMessage,
    RanCongestionInfo, RanCongestionLevel, RcafNpEngine,
};

#[test]
fn test_diameter_np_rcaf_congestion_report() {
    let mut pcrf = RcafNpEngine::new("pcrf01.core.5g");
    let info = RanCongestionInfo {
        enodeb_id: 5002,
        cell_id: 3,
        level: RanCongestionLevel::Medium,
    };
    let ncr = NpMessage::new_ncr("sess-np-01", "460019998881234", info);
    assert_eq!(ncr.application_id, DIAMETER_APPLICATION_NP);
    assert_eq!(ncr.command_code, DIAMETER_CMD_NON_AGGREGATED_RUCI_REPORT);

    let nca = pcrf.handle_ncr(&ncr);
    let rc = nca.avps.iter().find_map(|a| {
        if let NpAvp::ResultCode(c) = a {
            Some(*c)
        } else {
            None
        }
    });
    assert_eq!(rc, Some(2001));

    assert_eq!(
        pcrf.get_cell_congestion(5002, 3),
        RanCongestionLevel::Medium
    );
    assert_eq!(pcrf.total_ncr_reports, 1);
}
