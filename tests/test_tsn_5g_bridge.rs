//! Integration tests for 3GPP TS 23.501 / TS 24.519 / TS 29.574 / IEEE 802.1AS
//! 5G-TSN Time-Sensitive Communication (TSC) Virtual Bridge & NW-TT / DS-TT Engine.

use toy_tcpip::ethernet::MacAddress;
use toy_tcpip::ptp::{PTP_MSG_SYNC, PtpHeader};
use toy_tcpip::tsn_5g_bridge::{
    DsTtEngine, NwTtEngine, TscTrafficDirection, Tsn5gBridgeEngine, TsnBridgeId, TsnPortConfig,
    TsnPortState, TsnPortType,
};
use toy_tcpip::tsn_cnc::{StreamId, TrafficSpecification, UserToNetworkRequirements};

#[test]
fn test_tsn_5g_bridge_port_registration_and_delay_config() {
    let bridge_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x00]);
    let bridge_id = TsnBridgeId::new(0x8000, bridge_mac);
    let mut bridge = Tsn5gBridgeEngine::new("tsctf.edge01.5gc.operator.net", bridge_id);

    assert_eq!(bridge_id.to_string(), "8000:00:11:22:33:44:00");

    // Setup NW-TT at UPF edge (Ports 1 and 2)
    let mut nw_tt = NwTtEngine::new("upf-edge-tokyo-01");
    let port1 = TsnPortConfig::new(
        1,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]),
        10_000, // 10 Gbps
        25,     // 25 ns propagation delay
        8,      // 8 ns sync granularity
    );
    let port2 = TsnPortConfig::new(
        2,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x02]),
        10_000,
        25,
        8,
    );
    nw_tt.add_port(port1);
    nw_tt.add_port(port2);
    bridge.register_nw_tt(nw_tt);

    // Setup DS-TT at UE industrial robot (Port 3)
    let port3 = TsnPortConfig::new(
        3,
        TsnPortType::DsTt,
        MacAddress([0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x03]),
        1_000, // 1 Gbps
        40,    // 40 ns propagation delay
        10,    // 10 ns sync granularity
    );
    let ds_tt = DsTtEngine::new("imsi-208950000000001", port3);
    bridge.register_ds_tt(ds_tt);

    // Configure Port-Pair Delays (TS 23.501 §5.27.1.4)
    // Port 1 -> Port 3 (Downlink): min 2ms (2_000_000 ns), max 4ms (4_000_000 ns)
    bridge.configure_port_pair_delay(1, 3, 6, 2_000_000, 4_000_000);
    // Port 3 -> Port 1 (Uplink): min 2.5ms (2_500_000 ns), max 5ms (5_000_000 ns)
    bridge.configure_port_pair_delay(3, 1, 6, 2_500_000, 5_000_000);

    // Verify port lookups
    let p1 = bridge.get_port_config(1).expect("Port 1 should exist");
    assert_eq!(p1.port_type, TsnPortType::NwTt);
    assert_eq!(p1.link_speed_mbps, 10_000);
    assert_eq!(p1.state, TsnPortState::Forwarding);

    let p3 = bridge.get_port_config(3).expect("Port 3 should exist");
    assert_eq!(p3.port_type, TsnPortType::DsTt);
    assert_eq!(p3.link_speed_mbps, 1_000);

    let delay_dl = bridge
        .port_pair_delays
        .get(&(1, 3))
        .expect("Port pair (1, 3) must exist");
    assert_eq!(delay_dl.min_bridge_delay_ns, 2_000_000);
    assert_eq!(delay_dl.max_bridge_delay_ns, 4_000_000);
}

#[test]
fn test_tsn_5g_cnc_stream_reservation_and_tscai_generation() {
    let bridge_mac = MacAddress([0x00, 0x22, 0x44, 0x66, 0x88, 0x00]);
    let bridge_id = TsnBridgeId::new(0x8000, bridge_mac);
    let mut bridge = Tsn5gBridgeEngine::new("tsctf.factory.5gc.net", bridge_id);

    let mut nw_tt = NwTtEngine::new("upf-tsn-gw");
    nw_tt.add_port(TsnPortConfig::new(
        1,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x22, 0x44, 0x66, 0x88, 0x01]),
        10_000,
        20,
        10,
    ));
    bridge.register_nw_tt(nw_tt);

    let ds_tt = DsTtEngine::new(
        "imsi-robot-controller-10",
        TsnPortConfig::new(
            2,
            TsnPortType::DsTt,
            MacAddress([0x02, 0x22, 0x44, 0x66, 0x88, 0x02]),
            1_000,
            30,
            10,
        ),
    );
    bridge.register_ds_tt(ds_tt);

    // Port pair delay: min 1.5ms, max 3.5ms (3_500_000 ns)
    bridge.configure_port_pair_delay(1, 2, 7, 1_500_000, 3_500_000);

    // CNC Stream profile (IEEE 802.1Qcc)
    let talker_mac = MacAddress([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0x01]);
    let stream_id = StreamId::new(talker_mac, 100);
    let tspec = TrafficSpecification {
        max_frame_size: 400,    // 400 bytes per frame
        max_interval_frames: 2, // 2 frames per interval
        interval_us: 1000,      // 1000 us = 1ms cycle
    };
    let user_reqs = UserToNetworkRequirements {
        max_latency_us: 5000, // 5ms maximum latency tolerance
        num_seamless_trees: 1,
    };

    let base_arrival_time_ns = 1_700_000_000_000_000_000; // 5GS clock reference

    let binding = bridge
        .process_cnc_stream_reservation(
            stream_id,
            200, // VLAN 200
            7,   // PCP 7
            1,   // Ingress Port (NW-TT)
            2,   // Egress Port (DS-TT)
            5,   // PDU Session ID 5
            TscTrafficDirection::Downlink,
            &tspec,
            &user_reqs,
            base_arrival_time_ns,
        )
        .expect("Reservation should succeed");

    // Bandwidth check: (400 bytes * 2 frames * 8 bits) / 0.001s = 6,400,000 bps
    assert_eq!(binding.qos_profile.gfbr_bps, 6_400_000);
    assert_eq!(binding.qos_profile.mfbr_bps, 7_680_000);

    // 5QI check: max bridge delay 3.5ms <= 5ms -> Delay-Critical GBR 5QI 85
    assert_eq!(binding.qos_profile.five_qi, 85);
    assert_eq!(binding.qos_profile.pdb_ms, 5);

    // TSCAI check for gNodeB radio scheduling
    let tscai = binding.qos_profile.tscai.expect("TSCAI must be present");
    assert_eq!(tscai.direction, TscTrafficDirection::Downlink);
    assert_eq!(tscai.periodicity_ns, 1_000_000); // 1ms
    assert_eq!(tscai.burst_size_bytes, 800); // 400 * 2
    assert_eq!(tscai.burst_arrival_time_ns, base_arrival_time_ns);
    assert_eq!(tscai.survival_time_us, 2000); // 2 * interval
}

#[test]
fn test_tsn_5g_ptp_residence_time_and_correction_field_update() {
    let bridge_mac = MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let bridge_id = TsnBridgeId::new(0x8000, bridge_mac);
    let mut bridge = Tsn5gBridgeEngine::new("tsctf.ptp.5gc.net", bridge_id);

    let mut nw_tt = NwTtEngine::new("upf-ptp-edge");
    nw_tt.add_port(TsnPortConfig::new(
        1,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]),
        10_000,
        25, // 25 ns ingress port delay
        8,
    ));
    bridge.register_nw_tt(nw_tt);

    let ds_tt = DsTtEngine::new(
        "imsi-cnc-ptp-slave",
        TsnPortConfig::new(
            2,
            TsnPortType::DsTt,
            MacAddress([0x02, 0x11, 0x22, 0x33, 0x44, 0x02]),
            1_000,
            40, // 40 ns egress port delay
            10,
        ),
    );
    bridge.register_ds_tt(ds_tt);

    bridge.configure_port_pair_delay(1, 2, 7, 2_000_000, 4_000_000);

    // Construct IEEE 802.1AS PTP Sync header with initial correctionField of 100 ns
    let initial_cf = 100i64 << 16;
    let mut ptp_header = PtpHeader {
        message_type: PTP_MSG_SYNC,
        version: 2,
        message_length: 44,
        domain_number: 0,
        flags: 0x0200, // Two-step flag
        correction_field: initial_cf,
        clock_identity: [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55],
        source_port_id: 1,
        sequence_id: 42,
        control_field: 0,
        log_message_interval: -3,
    };

    let frame_id = 9001;
    let t_in_ns = 10_000_000_000; // 10.000000000 s
    let t_out_ns = 10_003_200_000; // 10.003200000 s (3.2 ms residence time)

    // Ingress TT captures T_in
    bridge
        .process_ptp_ingress(1, frame_id, t_in_ns)
        .expect("PTP ingress timestamping must succeed");

    // Egress TT captures T_out and updates correction field
    let report = bridge
        .process_ptp_egress(1, 2, frame_id, t_out_ns, &mut ptp_header)
        .expect("PTP egress correction must succeed");

    assert_eq!(report.ptp_msg_type, PTP_MSG_SYNC);
    assert_eq!(report.residence_time_ns, 3_200_000); // 3.2 ms
    assert_eq!(report.ingress_port_delay_ns, 25);
    assert_eq!(report.egress_port_delay_ns, 40);
    assert_eq!(report.total_correction_ns, 3_200_065); // 3_200_000 + 25 + 40

    // Updated correctionField should be: initial + (3_200_065 << 16)
    let expected_cf = initial_cf + (3_200_065i64 << 16);
    assert_eq!(report.updated_correction_field, expected_cf);
    assert_eq!(ptp_header.correction_field, expected_cf);
}

#[test]
fn test_tsn_5g_de_jitter_buffer_hold_and_forward() {
    let bridge_mac = MacAddress([0x00, 0x55, 0x44, 0x33, 0x22, 0x11]);
    let bridge_id = TsnBridgeId::new(0x8000, bridge_mac);
    let mut bridge = Tsn5gBridgeEngine::new("tsctf.dejitter.net", bridge_id);

    let mut nw_tt = NwTtEngine::new("upf-01");
    nw_tt.add_port(TsnPortConfig::new(
        1,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x55, 0x44, 0x33, 0x22, 0x01]),
        10_000,
        20,
        10,
    ));
    bridge.register_nw_tt(nw_tt);

    let ds_tt = DsTtEngine::new(
        "imsi-actuator-99",
        TsnPortConfig::new(
            2,
            TsnPortType::DsTt,
            MacAddress([0x02, 0x55, 0x44, 0x33, 0x22, 0x02]),
            1_000,
            20,
            10,
        ),
    );
    bridge.register_ds_tt(ds_tt);

    // Max bridge delay: 4,000,000 ns (4ms)
    bridge.configure_port_pair_delay(1, 2, 6, 2_000_000, 4_000_000);

    let stream_id = StreamId::new(MacAddress([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]), 1);
    let tspec = TrafficSpecification {
        max_frame_size: 500,
        max_interval_frames: 1,
        interval_us: 1000,
    };
    let user_reqs = UserToNetworkRequirements {
        max_latency_us: 5000,
        num_seamless_trees: 1,
    };

    bridge
        .process_cnc_stream_reservation(
            stream_id,
            100,
            6,
            1,
            2,
            1,
            TscTrafficDirection::Downlink,
            &tspec,
            &user_reqs,
            1_000_000_000,
        )
        .expect("Reservation must succeed");

    let t_in_ns = 5_000_000_000; // Ingress timestamp
    let scheduled_release_ns = t_in_ns + 4_000_000; // 5_004_000_000 ns

    let payload = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03];

    // Frame arrives early at egress TT after only 2.5ms transit (5_002_500_000 ns)
    let frame_id = bridge
        .queue_de_jitter_frame(stream_id, 2, t_in_ns, payload.clone())
        .expect("Queueing in de-jitter buffer must succeed");

    assert_eq!(frame_id, 1);

    // At t = 5_003_000_000 ns (before scheduled epoch of 5_004_000_000 ns):
    let released_early = bridge.flush_de_jitter_buffer(2, 5_003_000_000);
    assert!(
        released_early.is_empty(),
        "Frame must NOT be released before scheduled release epoch"
    );

    // At t = 5_004_000_000 ns (exact scheduled epoch reached):
    let released_on_time = bridge.flush_de_jitter_buffer(2, scheduled_release_ns);
    assert_eq!(released_on_time.len(), 1);
    assert_eq!(released_on_time[0].frame_id, 1);
    assert_eq!(released_on_time[0].payload, payload);

    // Buffer is now drained
    let released_empty = bridge.flush_de_jitter_buffer(2, scheduled_release_ns + 1000);
    assert!(released_empty.is_empty());
}

#[test]
fn test_tsn_5g_latency_budget_violation_and_error_handling() {
    let bridge_mac = MacAddress([0x00, 0x99, 0x88, 0x77, 0x66, 0x55]);
    let bridge_id = TsnBridgeId::new(0x8000, bridge_mac);
    let mut bridge = Tsn5gBridgeEngine::new("tsctf.error.test", bridge_id);

    let mut nw_tt = NwTtEngine::new("upf-err");
    let mut disabled_port = TsnPortConfig::new(
        1,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x99, 0x88, 0x77, 0x66, 0x01]),
        10_000,
        20,
        10,
    );
    disabled_port.state = TsnPortState::Disabled;
    nw_tt.add_port(disabled_port);

    let active_port = TsnPortConfig::new(
        2,
        TsnPortType::NwTt,
        MacAddress([0x00, 0x99, 0x88, 0x77, 0x66, 0x02]),
        10_000,
        20,
        10,
    );
    nw_tt.add_port(active_port);
    bridge.register_nw_tt(nw_tt);

    let ds_tt = DsTtEngine::new(
        "imsi-err-ue",
        TsnPortConfig::new(
            3,
            TsnPortType::DsTt,
            MacAddress([0x02, 0x99, 0x88, 0x77, 0x66, 0x03]),
            1_000,
            20,
            10,
        ),
    );
    bridge.register_ds_tt(ds_tt);

    // Port 2 -> Port 3 delay: min 3ms, max 8ms (8_000_000 ns = 8000 us)
    bridge.configure_port_pair_delay(2, 3, 5, 3_000_000, 8_000_000);

    let stream_id = StreamId::new(MacAddress([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]), 1);
    let tspec = TrafficSpecification {
        max_frame_size: 200,
        max_interval_frames: 1,
        interval_us: 1000,
    };

    // Case 1: Listener demands max 4ms latency, but bridge delay is 8ms
    let user_reqs_tight = UserToNetworkRequirements {
        max_latency_us: 4000, // 4ms
        num_seamless_trees: 1,
    };
    let res_tight = bridge.process_cnc_stream_reservation(
        stream_id,
        50,
        5,
        2,
        3,
        1,
        TscTrafficDirection::Downlink,
        &tspec,
        &user_reqs_tight,
        0,
    );
    assert!(res_tight.is_err());
    assert_eq!(
        res_tight.err().unwrap(),
        "5GS virtual bridge delay exceeds listener maximum latency budget"
    );

    // Case 2: Attempting reservation through a Disabled port
    let user_reqs_ok = UserToNetworkRequirements {
        max_latency_us: 10000,
        num_seamless_trees: 1,
    };
    let res_disabled = bridge.process_cnc_stream_reservation(
        stream_id,
        50,
        5,
        1, // Disabled port
        3,
        1,
        TscTrafficDirection::Downlink,
        &tspec,
        &user_reqs_ok,
        0,
    );
    assert!(res_disabled.is_err());
    assert_eq!(
        res_disabled.err().unwrap(),
        "Bridge ports must be in Forwarding state for TSN reservation"
    );

    // Case 3: Invalid/non-existent port
    let res_invalid_port = bridge.process_cnc_stream_reservation(
        stream_id,
        50,
        5,
        99, // Non-existent port
        3,
        1,
        TscTrafficDirection::Downlink,
        &tspec,
        &user_reqs_ok,
        0,
    );
    assert!(res_invalid_port.is_err());
}
