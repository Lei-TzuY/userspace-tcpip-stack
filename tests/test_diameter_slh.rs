use toy_tcpip::diameter::DIAMETER_SUCCESS;
use toy_tcpip::diameter_slh::{
    HssSlhEngine, ServingNodeInfo, AVP_SERVING_NODE, DIAMETER_APPLICATION_SLH,
    DIAMETER_CMD_LCS_ROUTING_INFO,
};

#[test]
fn test_diameter_slh_location_query() {
    let mut hss = HssSlhEngine::new();
    let imsi = "001010123456789";
    let mme_name = "mme01.epc.mnc001.mcc001.3gppnetwork.org";
    let mme_realm = "epc.mnc001.mcc001.3gppnetwork.org";

    hss.register_location(imsi, mme_name, mme_realm);

    // LCS-Routing-Info-Request (RIR)
    let ria = hss.handle_rir(imsi);
    assert_eq!(ria.header.application_id, DIAMETER_APPLICATION_SLH);
    assert_eq!(ria.header.command_code, DIAMETER_CMD_LCS_ROUTING_INFO);
    assert_eq!(ria.get_avp(268).unwrap().as_u32().unwrap(), DIAMETER_SUCCESS);

    let serving_avp = ria.get_avp(AVP_SERVING_NODE).expect("Serving-Node AVP");
    let parsed_node = ServingNodeInfo::from_grouped_avp(&serving_avp).expect("parse grouped node");
    assert_eq!(parsed_node.mme_name, mme_name);
    assert_eq!(parsed_node.mme_realm, mme_realm);

    // Unknown subscriber returns 5001
    let unk_ria = hss.handle_rir("999999999999999");
    assert_eq!(unk_ria.get_avp(268).unwrap().as_u32().unwrap(), 5001);
}
