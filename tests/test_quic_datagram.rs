use toy_tcpip::quic_datagram::{
    DatagramDropPolicy, DatagramQueueError, QUIC_FRAME_DATAGRAM, QUIC_FRAME_DATAGRAM_LEN,
    QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, QuicDatagramEngine, QuicDatagramFrame, QuicDatagramQueue,
    WebTransportDatagram,
};

#[test]
fn test_quic_datagram_frame_constants_and_types() {
    assert_eq!(QUIC_FRAME_DATAGRAM, 0x30);
    assert_eq!(QUIC_FRAME_DATAGRAM_LEN, 0x31);
    assert_eq!(QUIC_TP_MAX_DATAGRAM_FRAME_SIZE, 0x20);

    let frame_with_len = QuicDatagramFrame::new(b"hello world".to_vec(), true);
    let bytes = frame_with_len.serialize();
    let (decoded, consumed) = QuicDatagramFrame::parse(&bytes).expect("Valid parse");

    assert_eq!(consumed, bytes.len());
    assert!(decoded.has_length);
    assert_eq!(decoded.payload, b"hello world");
}

#[test]
fn test_webtransport_quarter_stream_multiplexing() {
    let session_1_datagram = WebTransportDatagram::new(100, b"video frame 1".to_vec());
    let session_2_datagram = WebTransportDatagram::new(200, b"audio packet 1".to_vec());

    let ser_1 = session_1_datagram.serialize();
    let ser_2 = session_2_datagram.serialize();

    let parsed_1 = WebTransportDatagram::parse(&ser_1).expect("Parse session 1");
    let parsed_2 = WebTransportDatagram::parse(&ser_2).expect("Parse session 2");

    assert_eq!(parsed_1.session_id, 100);
    assert_eq!(parsed_1.payload, b"video frame 1");

    assert_eq!(parsed_2.session_id, 200);
    assert_eq!(parsed_2.payload, b"audio packet 1");
}

#[test]
fn test_quic_datagram_engine_negotiation_and_flow() {
    let mut client_engine = QuicDatagramEngine::new(1200, 10);
    let mut server_engine = QuicDatagramEngine::new(1200, 10);

    // Peer transport parameter exchange
    client_engine.on_peer_transport_parameters(1200);
    server_engine.on_peer_transport_parameters(1200);

    // Client queues a media datagram
    client_engine
        .send_datagram(b"H.264 NAL Unit keyframe".to_vec())
        .expect("Send should succeed");

    // Client packages it into a QUIC DATAGRAM frame (0x31)
    let outgoing_frame = client_engine
        .create_outgoing_frame(true)
        .expect("Frame should be available");

    // Server receives the frame
    server_engine
        .receive_frame(&outgoing_frame)
        .expect("Receive should succeed");

    // Server pops the datagram
    let received_payload = server_engine.rx_queue.pop().expect("Should have payload");
    assert_eq!(received_payload, b"H.264 NAL Unit keyframe");
}

#[test]
fn test_quic_datagram_queue_policies_and_errors() {
    let mut q = QuicDatagramQueue::new(2, 100, DatagramDropPolicy::DropOldest);
    q.push(b"pkt1".to_vec()).unwrap();
    q.push(b"pkt2".to_vec()).unwrap();
    q.push(b"pkt3".to_vec()).unwrap(); // drops pkt1

    assert_eq!(q.stats.dropped, 1);
    assert_eq!(q.pop().unwrap(), b"pkt2");
    assert_eq!(q.pop().unwrap(), b"pkt3");

    // Size limit check
    let err = q.push(vec![0u8; 150]).unwrap_err();
    assert_eq!(err, DatagramQueueError::ExceedsMaxDatagramSize(150, 100));
}

#[test]
fn test_webtransport_datagram_engine_session_multiplexing_and_demux() {
    use toy_tcpip::quic_datagram::WebTransportDatagramEngine;

    let mut client_wt = WebTransportDatagramEngine::new(1200, 5, DatagramDropPolicy::DropOldest);
    let mut server_wt = WebTransportDatagramEngine::new(1200, 5, DatagramDropPolicy::DropOldest);

    // Client sends datagrams on two distinct WebTransport sessions:
    // Session 10: Video track
    // Session 20: Audio track
    client_wt
        .send_session_datagram(10, b"video-frame-key".to_vec())
        .unwrap();
    client_wt
        .send_session_datagram(20, b"audio-sample-01".to_vec())
        .unwrap();
    client_wt
        .send_session_datagram(10, b"video-frame-delta".to_vec())
        .unwrap();

    // Pull outgoing QUIC DATAGRAM frames (with explicit length)
    let f1 = client_wt.create_outgoing_frame(true).expect("frame 1");
    let f2 = client_wt.create_outgoing_frame(true).expect("frame 2");
    let f3 = client_wt.create_outgoing_frame(true).expect("frame 3");
    assert!(client_wt.create_outgoing_frame(true).is_none());

    // Server receives and demultiplexes incoming frames
    let d1 = server_wt.receive_and_demux(&f1).expect("demux f1");
    assert_eq!(d1.session_id, 10);
    let d2 = server_wt.receive_and_demux(&f2).expect("demux f2");
    assert_eq!(d2.session_id, 20);
    let d3 = server_wt.receive_and_demux(&f3).expect("demux f3");
    assert_eq!(d3.session_id, 10);

    // Check demultiplexed session queue lengths
    assert_eq!(server_wt.session_queue_len(10), 2);
    assert_eq!(server_wt.session_queue_len(20), 1);
    assert_eq!(server_wt.session_queue_len(999), 0);

    // Pop from Session 10
    assert_eq!(
        server_wt.pop_session_datagram(10).unwrap(),
        b"video-frame-key"
    );
    assert_eq!(
        server_wt.pop_session_datagram(10).unwrap(),
        b"video-frame-delta"
    );
    assert_eq!(server_wt.pop_session_datagram(10), None);

    // Pop from Session 20
    assert_eq!(
        server_wt.pop_session_datagram(20).unwrap(),
        b"audio-sample-01"
    );
    assert_eq!(server_wt.pop_session_datagram(20), None);
}
