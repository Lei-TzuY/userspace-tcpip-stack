//! Integration tests for O-RAN WG4 CUS-Plane Packet Processor & eCPRI Multiplexer Engine.

use toy_tcpip::ecpri::{ECPRI_MSG_RT_CONTROL, EcpriCommonHeader};
use toy_tcpip::oran_cplane_ext::{
    BfwBundle, BfwCompressionMethod, BfwWeight, CPlaneSectionType3, ORAN_SECTION_TYPE_3,
    SectionExtension1, SectionExtension2,
};
use toy_tcpip::oran_fh_cus::{DataDirection, EaxcIdFormat, OranRadioHeader};
use toy_tcpip::oran_fh_delay_mgmt::WindowVerdict;
use toy_tcpip::oran_iq_compression::IqSample;
use toy_tcpip::oran_packet_proc::{OranDemuxEvent, OranFronthaulProcessor, OranStreamConfig};
use toy_tcpip::tsn_8021cm_fronthaul::Ieee8021CmProfile;

fn make_test_stream_config(eaxc_id: u16) -> OranStreamConfig {
    let format = EaxcIdFormat::new(4, 4, 4, 4).unwrap();
    OranStreamConfig::new(eaxc_id, format, 64, 10_000, 40_000).unwrap()
}

#[test]
fn test_oran_uplane_ingress_decompression_and_timing_window() {
    let mut processor = OranFronthaulProcessor::new(Ieee8021CmProfile::ProfileA);
    let eaxc_id = 0x1001;
    processor.register_stream(make_test_stream_config(eaxc_id));

    // Generate 48 IQ samples (4 PRBs x 12 subcarriers)
    let mut samples = Vec::with_capacity(48);
    for i in 0..48 {
        samples.push(IqSample::new((i as i16) * 15 - 300, 300 - (i as i16) * 12));
    }

    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 1, 0, 0, 2);

    // Build U-Plane frame with 9-bit BFP compression
    let uplane_frame = processor.build_uplane_frame(eaxc_id, &radio_header, 10, 4, &samples, 9);

    // On-time arrival: air time = 0 * 1,000,000 + 2 * 71,428 = 142,856 ns
    // Supported arrival window: [air_time - T2a_max, air_time - T2a_min] = [102,856, 132,856]
    let on_time_arrival = 120_000;
    let events = processor.process_ingress_packet(&uplane_frame, on_time_arrival);

    assert_eq!(events.len(), 1);
    match &events[0] {
        OranDemuxEvent::UPlaneReceived {
            eaxc_id: id,
            frame_id,
            subframe_id,
            slot_id,
            symbol_id,
            prb_count,
            samples_count,
            verdict,
        } => {
            assert_eq!(*id, eaxc_id);
            assert_eq!(*frame_id, 1);
            assert_eq!(*subframe_id, 0);
            assert_eq!(*slot_id, 0);
            assert_eq!(*symbol_id, 2);
            assert_eq!(*prb_count, 4);
            assert_eq!(*samples_count, 48);
            assert!(matches!(verdict, WindowVerdict::OnTime { .. }));
        }
        other => panic!("Unexpected event: {:?}", other),
    }

    let stats = processor.get_stream_stats(eaxc_id).unwrap();
    assert_eq!(stats.total_uplane_packets, 1);
    assert_eq!(stats.on_time_uplane_packets, 1);
    assert_eq!(stats.early_dropped_packets, 0);
    assert_eq!(stats.late_dropped_packets, 0);
    assert_eq!(stats.total_decompressed_samples, 48);
}

#[test]
fn test_oran_cplane_ingress_with_bfw_and_beam_attributes() {
    let mut processor = OranFronthaulProcessor::new(Ieee8021CmProfile::ProfileA);
    let eaxc_id = 0x2002;
    processor.register_stream(make_test_stream_config(eaxc_id));

    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 2, 1, 0, 0);

    // 64-element massive MIMO beamforming weights
    let weights = vec![BfwWeight::new(120, -85); 64];
    let bundle = BfwBundle::new(3, weights);
    let ext1 = SectionExtension1::new(BfwCompressionMethod::BlockFloatingPoint, 16, vec![bundle]);
    let ext2 = SectionExtension2::new(205, 30.0, -10.0);

    let cplane_frame = processor.build_cplane_section1_frame(
        eaxc_id,
        &radio_header,
        15,  // section_id
        0,   // start_prbc
        100, // num_prbc
        Some(&ext1),
        Some(&ext2),
    );

    let events = processor.process_ingress_packet(&cplane_frame, 0);

    assert_eq!(events.len(), 1);
    match &events[0] {
        OranDemuxEvent::CPlaneSection1Received {
            eaxc_id: id,
            section_id,
            start_prbc,
            num_prbc,
            beam_id,
            bfw_antennas,
        } => {
            assert_eq!(*id, eaxc_id);
            assert_eq!(*section_id, 15);
            assert_eq!(*start_prbc, 0);
            assert_eq!(*num_prbc, 100);
            assert_eq!(*beam_id, Some(205));
            assert_eq!(*bfw_antennas, Some(64));
        }
        other => panic!("Unexpected event: {:?}", other),
    }

    let stats = processor.get_stream_stats(eaxc_id).unwrap();
    assert_eq!(stats.total_cplane_packets, 1);
    assert_eq!(stats.last_beam_id, Some(205));
    assert_eq!(stats.last_bfw_weights_count, Some(64));
}

#[test]
fn test_oran_cplane_section3_prach_ingress() {
    let mut processor = OranFronthaulProcessor::new(Ieee8021CmProfile::ProfileA);
    let eaxc_id = 0x3003;
    processor.register_stream(make_test_stream_config(eaxc_id));

    let radio_header = OranRadioHeader::new(DataDirection::Uplink, 3, 0, 0, 0);
    let prach_sec = CPlaneSectionType3::new(501, 12, 48, 1250, 0x81, 3168, -300);

    // Build eCPRI message with Section Type 3
    let mut msg_payload = Vec::new();
    msg_payload.extend_from_slice(&eaxc_id.to_be_bytes());
    msg_payload.extend_from_slice(&[0x00, 0x80]); // seq_id
    msg_payload.extend_from_slice(&radio_header.serialize());
    msg_payload.extend_from_slice(&[ORAN_SECTION_TYPE_3, 1, 0, 0]); // Section Type 3, 1 section
    msg_payload.extend_from_slice(&prach_sec.serialize());

    let ecpri_hdr = EcpriCommonHeader::new(ECPRI_MSG_RT_CONTROL, msg_payload.len() as u16);
    let mut frame = Vec::new();
    frame.extend_from_slice(&ecpri_hdr.serialize());
    frame.extend_from_slice(&msg_payload);

    let events = processor.process_ingress_packet(&frame, 0);
    assert_eq!(events.len(), 1);
    match &events[0] {
        OranDemuxEvent::CPlaneSection3Received {
            eaxc_id: id,
            section_id,
            time_offset,
            frame_structure,
            frequency_offset_hz,
        } => {
            assert_eq!(*id, eaxc_id);
            assert_eq!(*section_id, 501);
            assert_eq!(*time_offset, 1250);
            assert_eq!(*frame_structure, 0x81);
            assert_eq!(*frequency_offset_hz, -375_000.0);
        }
        other => panic!("Unexpected event: {:?}", other),
    }
}

#[test]
fn test_oran_packet_dropped_on_late_arrival() {
    let mut processor = OranFronthaulProcessor::new(Ieee8021CmProfile::ProfileA);
    let eaxc_id = 0x4004;
    processor.register_stream(make_test_stream_config(eaxc_id));

    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 1, 0, 0, 1);
    let samples = vec![IqSample::new(10, 20); 12];

    let uplane_frame = processor.build_uplane_frame(eaxc_id, &radio_header, 0, 1, &samples, 9);

    // Expired late arrival: arrival_time = 1,000,000 ns (far past air time of symbol 1 = 71,428 ns)
    let events = processor.process_ingress_packet(&uplane_frame, 1_000_000);

    assert_eq!(events.len(), 1);
    match &events[0] {
        OranDemuxEvent::UPlaneReceived { verdict, .. } => {
            assert!(matches!(verdict, WindowVerdict::TooLate { .. }));
        }
        other => panic!("Unexpected event: {:?}", other),
    }

    let stats = processor.get_stream_stats(eaxc_id).unwrap();
    assert_eq!(stats.late_dropped_packets, 1);
    assert_eq!(stats.on_time_uplane_packets, 0);
}

#[test]
fn test_oran_concatenated_ecpri_messages() {
    let mut processor = OranFronthaulProcessor::new(Ieee8021CmProfile::ProfileA);
    let eaxc_id = 0x5005;
    processor.register_stream(make_test_stream_config(eaxc_id));

    let radio_header = OranRadioHeader::new(DataDirection::Downlink, 1, 0, 0, 0);

    // Message 1: C-Plane Section 1
    let mut cplane_frame =
        processor.build_cplane_section1_frame(eaxc_id, &radio_header, 100, 0, 20, None, None);
    // Set concatenation bit (c = 1, bit 0 of byte 0) on Message 1
    cplane_frame[0] |= 0x01;

    // Pad Message 1 to 4-byte boundary
    let unpadded_len = cplane_frame.len();
    let pad_len = (4 - (unpadded_len % 4)) % 4;
    cplane_frame.resize(unpadded_len + pad_len, 0);

    // Message 2: U-Plane IQ data (c = 0)
    let samples = vec![IqSample::new(50, -50); 24];
    let uplane_frame = processor.build_uplane_frame(eaxc_id, &radio_header, 0, 2, &samples, 9);

    // Concatenate Message 1 and Message 2 into a single raw packet
    let mut combined_packet = cplane_frame;
    combined_packet.extend_from_slice(&uplane_frame);

    // Process concatenated frame: air time for symbol 0 is 0 ns, advance is 20,000 ns -> on time!
    let events = processor.process_ingress_packet(&combined_packet, -20_000);

    // Both messages should be demultiplexed in order!
    assert_eq!(events.len(), 2);
    assert!(matches!(
        &events[0],
        OranDemuxEvent::CPlaneSection1Received {
            section_id: 100,
            ..
        }
    ));
    assert!(matches!(
        &events[1],
        OranDemuxEvent::UPlaneReceived {
            prb_count: 2,
            samples_count: 24,
            ..
        }
    ));
}
