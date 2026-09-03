use toy_tcpip::geneve_evc_mux::{
    EvcServiceProfile, EvcServiceType, EvcVlanDeliveryAction, GENEVE_OPT_CLASS_CARRIER_ETHERNET,
    GENEVE_OPT_TYPE_EVC_METADATA, GeneveEvcEngine,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_geneve_evc_service_multiplexing_and_vlan_strip() {
    let mut engine = GeneveEvcEngine::new();

    // E-Line 1 (VLAN 10 -> VNI 10010, Deliver Untagged / Strip)
    engine.add_service_mapping(
        "ge-0/0/0",
        10,
        EvcServiceProfile {
            evc_id: 10,
            service_type: EvcServiceType::PointToPointELine,
            geneve_vni: 10010,
            remote_vtep: Ipv4Address::new(172, 16, 0, 1),
            egress_delivery: EvcVlanDeliveryAction::Strip,
        },
        "ge-0/0/1",
    );

    // E-LAN 2 (VLAN 20 -> VNI 20020, Preserve Tag)
    engine.add_service_mapping(
        "ge-0/0/0",
        20,
        EvcServiceProfile {
            evc_id: 20,
            service_type: EvcServiceType::MultipointELan,
            geneve_vni: 20020,
            remote_vtep: Ipv4Address::new(172, 16, 0, 2),
            egress_delivery: EvcVlanDeliveryAction::Preserve,
        },
        "ge-0/0/2",
    );

    let customer_frame_vlan10 = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x81, 0x00, 0x00,
        0x0A, // VLAN 10
        0x08, 0x00, 0xde, 0xad, 0xbe, 0xef,
    ];

    let encap10 = engine
        .encapsulate_evc_frame("ge-0/0/0", &customer_frame_vlan10)
        .unwrap();
    assert_eq!(encap10.remote_vtep, Ipv4Address::new(172, 16, 0, 1));
    assert_eq!(encap10.geneve_packet.vni, 10010);
    assert_eq!(
        encap10.geneve_packet.options[0].class,
        GENEVE_OPT_CLASS_CARRIER_ETHERNET
    );
    assert_eq!(
        encap10.geneve_packet.options[0].opt_type,
        GENEVE_OPT_TYPE_EVC_METADATA
    );

    // Egress delivery on ge-0/0/1 strips the VLAN tag
    let decap10 = engine
        .decapsulate_evc_packet(&encap10.geneve_packet)
        .unwrap();
    assert_eq!(decap10.out_if, "ge-0/0/1");
    assert_eq!(decap10.evc_id, 10);
    assert_eq!(
        decap10.customer_frame.len(),
        customer_frame_vlan10.len() - 4
    );
    assert_eq!(&decap10.customer_frame[12..14], &[0x08, 0x00]);

    // Test unmapped VLAN rejection
    let unmapped_frame = vec![
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0x81, 0x00, 0x00,
        0x63, // VLAN 99 (Unmapped)
        0x08, 0x00,
    ];
    let err = engine.encapsulate_evc_frame("ge-0/0/0", &unmapped_frame);
    assert!(err.is_err());
}
