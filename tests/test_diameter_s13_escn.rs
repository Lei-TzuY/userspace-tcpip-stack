//! Integration tests for 3GPP TS 29.272 Diameter S13 ESCN and Batch Audit Engine.

use toy_tcpip::diameter_s13_escn::{EscnVerdict, S13EquipmentStatus, S13EscnEngine};

#[test]
fn test_diameter_s13_escn_integration() {
    let mut engine = S13EscnEngine::new("eir-central.epc.mnc001.mcc208.3gppnetwork.org");
    engine.subscribe_mme("mme-edge-paris.epc.mnc001.mcc208.3gppnetwork.org");

    // Change status from WhiteListed to GrayListed (Cloned IMEI alert)
    let v = engine.update_equipment_status(
        "860011112222333",
        S13EquipmentStatus::GrayListed,
        "GSMA Clone Suspect",
        2000,
    );
    match v {
        EscnVerdict::StatusChangedNotificationsQueued {
            imei,
            new_status,
            notified_mme_count,
            ..
        } => {
            assert_eq!(imei, "860011112222333");
            assert_eq!(new_status, S13EquipmentStatus::GrayListed);
            assert_eq!(notified_mme_count, 1);
        }
        _ => panic!("Expected StatusChangedNotificationsQueued"),
    }

    // Edge cache audit
    let audit_batch = vec![(
        "860011112222333".to_string(),
        S13EquipmentStatus::WhiteListed,
    )];
    let res = engine.audit_edge_cache(
        "mme-edge-paris.epc.mnc001.mcc208.3gppnetwork.org",
        &audit_batch,
    );
    assert_eq!(res.len(), 1);
    assert_eq!(
        res[0].eir_authoritative_status,
        S13EquipmentStatus::GrayListed
    );
    assert!(!res[0].synchronized);
}
