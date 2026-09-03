use toy_tcpip::diameter_s13_imeidb::{
    DIAMETER_APPLICATION_S13, DIAMETER_CMD_IMEI_DB_QUERY, DIAMETER_ERROR_EQUIPMENT_BLOCKED,
    GsmaDeviceStatus, S13ImeiDbEngine, S13ImeiDbMessage,
};

#[test]
fn test_diameter_s13_imeidb_lifecycle() {
    let mut engine = S13ImeiDbEngine::new("imeidb.gsma.org", "gsma.org");

    assert_eq!(DIAMETER_APPLICATION_S13, 16777252);
    assert_eq!(DIAMETER_CMD_IMEI_DB_QUERY, 327);

    // Register blacklisted devices
    engine.register_device(
        "860011112222333",
        "Galaxy S24 Ultra",
        "Samsung",
        GsmaDeviceStatus::Stolen,
        "20801",
    );
    engine.register_device(
        "860044445555666",
        "iPhone 16 Pro",
        "Apple",
        GsmaDeviceStatus::ClonedFraud,
        "20802",
    );

    // 1. Query Stolen device
    let req1 = S13ImeiDbMessage::new_request(
        "sess-imei-01",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "gsma.org",
        "860011112222333",
    );
    let ans1 = engine.process_idr(&req1);
    assert_eq!(ans1.result_code, DIAMETER_ERROR_EQUIPMENT_BLOCKED);
    assert_eq!(ans1.status, Some(GsmaDeviceStatus::Stolen));
    assert_eq!(
        ans1.model_info,
        Some("Samsung Galaxy S24 Ultra".to_string())
    );

    // 2. Query Clean device
    let req2 = S13ImeiDbMessage::new_request(
        "sess-imei-02",
        "mme01.epc.mnc001.mcc208.3gppnetwork.org",
        "epc.mnc001.mcc208.3gppnetwork.org",
        "gsma.org",
        "869900001111222",
    );
    let ans2 = engine.process_idr(&req2);
    assert_eq!(ans2.result_code, 2001); // DIAMETER_SUCCESS
    assert_eq!(ans2.status, Some(GsmaDeviceStatus::Clean));
}
