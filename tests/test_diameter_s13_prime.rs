use toy_tcpip::diameter_s13_prime::{
    DIAMETER_APPLICATION_S13_PRIME, DIAMETER_CMD_ME_IDENTITY_CHECK, EirS13PrimeEngine,
    EquipmentStatus, S13PrimeAvp, S13PrimeMessage, TerminalInformation,
};

#[test]
fn test_diameter_s13_prime_blacklisted_stolen_device() {
    let mut eir = EirS13PrimeEngine::new("eir.telco.com");
    eir.register_equipment("351756051523999", EquipmentStatus::Blacklisted);

    let term_info = TerminalInformation {
        imei: "351756051523999".to_string(),
        software_version: Some("12".to_string()),
    };

    let ecr = S13PrimeMessage::new_ecr("s13p-session-100", "460001234567890", term_info);
    assert_eq!(ecr.application_id, DIAMETER_APPLICATION_S13_PRIME);
    assert_eq!(ecr.command_code, DIAMETER_CMD_ME_IDENTITY_CHECK);

    let eca = eir.process_ecr(&ecr);
    assert!(!eca.is_request);

    let status = eca.avps.iter().find_map(|a| {
        if let S13PrimeAvp::EquipmentStatus(s) = a {
            Some(*s)
        } else {
            None
        }
    });
    assert_eq!(status, Some(EquipmentStatus::Blacklisted));
    assert_eq!(eir.blacklisted_hits, 1);
}

#[test]
fn test_diameter_s13_prime_terminal_info_tlv_codec() {
    let original = TerminalInformation {
        imei: "867890123456789".to_string(),
        software_version: Some("03".to_string()),
    };

    let serialized = original.serialize();
    let parsed = TerminalInformation::parse(&serialized).expect("Must parse TLV");

    assert_eq!(parsed.imei, "867890123456789");
    assert_eq!(parsed.software_version, Some("03".to_string()));
}
