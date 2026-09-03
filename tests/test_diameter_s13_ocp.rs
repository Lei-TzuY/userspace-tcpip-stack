use toy_tcpip::diameter_s13_ocp::{
    DIAMETER_APPLICATION_S13, OcReportType, OcThrottleVerdict, S13OverloadControlEngine,
};

#[test]
fn test_diameter_s13_ocp_lifecycle() {
    let mut engine = S13OverloadControlEngine::new("eir-central.epc.mnc001.mcc208.3gppnetwork.org");
    assert_eq!(DIAMETER_APPLICATION_S13, 16777252);

    // 1. Initial State: 100% admission
    assert_eq!(
        engine.evaluate_request(false, 500),
        OcThrottleVerdict::AdmitRequest
    );

    // 2. Overload signal received: 30% reduction for 120s
    engine.update_overload_report(10, OcReportType::Realm, 30, 120, 500);
    assert!(engine.current_olr.is_some());

    // 3. Emergency bypass works
    assert_eq!(
        engine.evaluate_request(true, 510),
        OcThrottleVerdict::EmergencyBypass
    );

    // 4. Over 100 requests, 30 are throttled and 70 admitted
    let mut throttled = 0;
    let mut admitted = 0;
    for _ in 0..100 {
        match engine.evaluate_request(false, 520) {
            OcThrottleVerdict::ThrottleDrop {
                reduction_percentage,
                ..
            } => {
                assert_eq!(reduction_percentage, 30);
                throttled += 1;
            }
            OcThrottleVerdict::AdmitRequest => admitted += 1,
            _ => {}
        }
    }
    assert_eq!(throttled, 30);
    assert_eq!(admitted, 70);
}
