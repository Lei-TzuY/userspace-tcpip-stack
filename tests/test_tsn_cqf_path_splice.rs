//! Integration tests for IEEE 802.1Qch CQF Dynamic Path Splicing & Rerouting Engine.

use toy_tcpip::tsn_cqf_path_splice::{PathSpliceVerdict, TsnCqfHop, TsnCqfPathSpliceEngine};

#[test]
fn test_tsn_cqf_path_splice_integration() {
    let mut engine = TsnCqfPathSpliceEngine::new(125_000);

    let prim_hops = vec![
        TsnCqfHop {
            node_id: 101,
            egress_port: 1,
            propagation_delay_ns: 5000,
            cycle_offset: 0,
        },
        TsnCqfHop {
            node_id: 102,
            egress_port: 2,
            propagation_delay_ns: 5000,
            cycle_offset: 1,
        },
    ];
    engine.register_stream(1, prim_hops);

    // Initial 5 frames on primary
    for c in 0..5 {
        let v = engine.route_frame(1, c);
        match v {
            PathSpliceVerdict::FrameRoutedPrimary {
                stream_id,
                cycle_idx,
                hop_count,
            } => {
                assert_eq!(stream_id, 1);
                assert_eq!(cycle_idx, c);
                assert_eq!(hop_count, 2);
            }
            _ => panic!("Expected FrameRoutedPrimary"),
        }
    }

    // Request path splice with 3 cycles lead time
    let alt_hops = vec![
        TsnCqfHop {
            node_id: 101,
            egress_port: 3,
            propagation_delay_ns: 2500,
            cycle_offset: 0,
        },
        TsnCqfHop {
            node_id: 103,
            egress_port: 1,
            propagation_delay_ns: 2500,
            cycle_offset: 1,
        },
        TsnCqfHop {
            node_id: 104,
            egress_port: 2,
            propagation_delay_ns: 3000,
            cycle_offset: 2,
        },
    ];
    let v_req = engine.request_splice(1, alt_hops, 5, 3);
    match v_req {
        PathSpliceVerdict::SpliceScheduled {
            stream_id,
            switchover_cycle,
            phase_delta_ns,
        } => {
            assert_eq!(stream_id, 1);
            assert_eq!(switchover_cycle, 8);
            assert_eq!(phase_delta_ns, -2000); // 8000 - 10000 = -2000 ns
        }
        _ => panic!("Expected SpliceScheduled"),
    }

    // Frames 5, 6, 7 are still routed along primary
    for c in 5..8 {
        let v = engine.route_frame(1, c);
        match v {
            PathSpliceVerdict::FrameRoutedPrimary { cycle_idx, .. } => {
                assert_eq!(cycle_idx, c);
            }
            _ => panic!("Expected FrameRoutedPrimary during lead time"),
        }
    }

    // Frames 8..12 are routed along alternate path
    for c in 8..12 {
        let v = engine.route_frame(1, c);
        match v {
            PathSpliceVerdict::FrameRoutedAlternate {
                cycle_idx,
                hop_count,
                phase_adjusted_ns,
                ..
            } => {
                assert_eq!(cycle_idx, c);
                assert_eq!(hop_count, 3);
                assert_eq!(phase_adjusted_ns, -2000);
            }
            _ => panic!("Expected FrameRoutedAlternate after switchover"),
        }
    }

    // Finalize splice
    let v_fin = engine.complete_splice(1);
    match v_fin {
        PathSpliceVerdict::SpliceCompleted {
            stream_id,
            total_primary,
            total_alternate,
        } => {
            assert_eq!(stream_id, 1);
            assert_eq!(total_primary, 8);
            assert_eq!(total_alternate, 4);
        }
        _ => panic!("Expected SpliceCompleted"),
    }
}
