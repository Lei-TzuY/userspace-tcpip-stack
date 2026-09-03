//! Integration tests for Geneve PMTUD & Active Flow Probe Option (RFC 8926 §4.4 / RFC 1191).

use toy_tcpip::geneve_pmtud::{
    GENEVE_CLASS_PMTUD_OAM, GENEVE_TYPE_PMTUD_PROBE, GenevePmtudEngine, GenevePmtudResult,
};
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_geneve_pmtud_constants() {
    assert_eq!(GENEVE_CLASS_PMTUD_OAM, 0x0109);
    assert_eq!(GENEVE_TYPE_PMTUD_PROBE, 0x10);
}

#[test]
fn test_geneve_pmtud_probe_and_bottleneck_detection() {
    let mut vtep_east = GenevePmtudEngine::new(9216); // Jumbo frame capable
    let mut vtep_west = GenevePmtudEngine::new(1400); // Standard MTU bottleneck

    let ip_east = Ipv4Address::new(198, 51, 100, 1);
    let ip_west = Ipv4Address::new(198, 51, 100, 2);

    // 1. East probes West with 9000 bytes
    let req = vtep_east.start_probe(ip_west, 9000);
    let req_tlv = match req {
        GenevePmtudResult::SendProbeRequest { probe, tlv, .. } => {
            assert_eq!(probe.probed_mtu_size, 9000);
            tlv
        }
        other => panic!("Expected SendProbeRequest, got {:?}", other),
    };

    // 2. West processes request -> clips to local MTU 1400
    let resp = vtep_west.process_incoming_tlv(ip_east, &req_tlv);
    let resp_tlv = match resp {
        GenevePmtudResult::SendProbeReply { reply, tlv, .. } => {
            assert_eq!(reply.min_supported_mtu, 1400);
            tlv
        }
        other => panic!("Expected SendProbeReply, got {:?}", other),
    };

    // 3. East receives reply -> clamps Path MTU to 1400
    let confirmed = vtep_east.process_incoming_tlv(ip_west, &resp_tlv);
    match confirmed {
        GenevePmtudResult::PmtuConfirmed { path_mtu, .. } => {
            assert_eq!(path_mtu, 1400);
        }
        other => panic!("Expected PmtuConfirmed, got {:?}", other),
    }

    assert_eq!(vtep_east.pmtu_cache.get(&ip_west), Some(&1400));
}
