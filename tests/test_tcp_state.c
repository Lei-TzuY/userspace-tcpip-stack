#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tcp_state.h"

static const uint8_t CLIENT_IP[4] = { 192, 168, 1, 10 };
static const uint8_t SERVER_IP[4] = { 192, 168, 1, 20 };
static const uint8_t DEFAULT_PAYLOAD[32] = { 0 };

static TcpHeader make_segment(uint16_t src_port, uint16_t dst_port,
                              uint32_t seq, uint32_t ack, uint8_t flags,
                              size_t payload_len) {
    TcpHeader segment;
    memset(&segment, 0, sizeof(segment));
    segment.src_port = src_port;
    segment.dst_port = dst_port;
    segment.seq_num = seq;
    segment.ack_num = ack;
    segment.flags = flags;
    segment.payload = payload_len > 0 ? DEFAULT_PAYLOAD : NULL;
    segment.payload_len = payload_len;
    return segment;
}

static TcpObservation observe(TcpTracker* tracker,
                              const uint8_t* src_ip, const uint8_t* dst_ip,
                              TcpHeader segment) {
    TcpObservation observation;
    assert(tcp_tracker_observe(
        tracker, src_ip, dst_ip, &segment, &observation) == 1);
    return observation;
}

static TcpObservation observe_at(TcpTracker* tracker,
                                 const uint8_t* src_ip, const uint8_t* dst_ip,
                                 TcpHeader segment, uint64_t now_usec) {
    TcpObservation observation;
    assert(tcp_tracker_observe_at(
        tracker, src_ip, dst_ip, &segment, now_usec, &observation) == 1);
    return observation;
}

static size_t active_connections(const TcpTracker* tracker) {
    size_t count = 0;
    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        if (tracker->connections[i].in_use)
            count++;
    }
    return count;
}

static void assert_states(const TcpConnection* connection,
                          TcpState client, TcpState server) {
    assert(connection->client.state == client);
    assert(connection->server.state == server);
}

static TcpConnection* establish(TcpTracker* tracker,
                                uint16_t client_port, uint16_t server_port) {
    TcpObservation observation = observe(
        tracker, CLIENT_IP, SERVER_IP,
        make_segment(client_port, server_port, 100, 0, TCP_SYN, 0));
    observation = observe(
        tracker, SERVER_IP, CLIENT_IP,
        make_segment(server_port, client_port, 500, 101, TCP_SYN | TCP_ACK, 0));
    observation = observe(
        tracker, CLIENT_IP, SERVER_IP,
        make_segment(client_port, server_port, 101, 501, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);
    return observation.connection;
}

static void test_handshake_data_and_close(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    TcpObservation observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 100, 0, TCP_SYN, 0));
    assert(observation.created);
    assert_states(observation.connection, TCP_STATE_SYN_SENT, TCP_STATE_SYN_RCVD);

    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(80, 54321, 500, 101, TCP_SYN | TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_SYN_SENT, TCP_STATE_SYN_RCVD);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 101, 501, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 101, 501, TCP_ACK | TCP_PSH, 5));
    assert(observation.seq_status == TCP_SEQ_IN_ORDER);
    assert(observation.connection->client.next_seq == 106);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 106, 501, TCP_ACK | TCP_FIN, 0));
    assert_states(observation.connection, TCP_STATE_FIN_WAIT_1, TCP_STATE_CLOSE_WAIT);

    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(80, 54321, 501, 107, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_FIN_WAIT_2, TCP_STATE_CLOSE_WAIT);

    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(80, 54321, 501, 107, TCP_ACK | TCP_FIN, 0));
    assert_states(observation.connection, TCP_STATE_TIME_WAIT, TCP_STATE_LAST_ACK);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 107, 502, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_TIME_WAIT, TCP_STATE_CLOSED);
}

static void test_sequence_gap_and_reset(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    TcpObservation observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(12345, 8080, 10, 0, TCP_SYN, 0));
    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(8080, 12345, 20, 11, TCP_SYN | TCP_ACK, 0));
    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(12345, 8080, 11, 21, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(12345, 8080, 14, 21, TCP_ACK | TCP_PSH, 2));
    assert(observation.seq_status == TCP_SEQ_GAP);
    assert(observation.expected_seq == 11);
    assert(observation.connection->client.next_seq == 11);

    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(8080, 12345, 21, 11, TCP_RST, 0));
    assert_states(observation.connection, TCP_STATE_CLOSED, TCP_STATE_CLOSED);
}

static void test_bad_syn_ack_does_not_establish(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    TcpObservation observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(23456, 443, 10, 0, TCP_SYN, 0));
    observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(443, 23456, 20, 10, TCP_SYN | TCP_ACK, 0));
    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(23456, 443, 11, 21, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_SYN_SENT, TCP_STATE_SYN_RCVD);
}

static void test_infers_midstream_ack(void) {
    TcpTracker tracker;
    TcpObservation observation;
    TcpHeader segment = make_segment(54321, 80, 1, 1, TCP_ACK, 0);
    tcp_tracker_init(&tracker);
    observation = observe(&tracker, CLIENT_IP, SERVER_IP, segment);
    assert(observation.created);
    assert(observation.connection->inferred);
    assert(observation.src_is_client);
    assert_states(observation.connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);
    assert(observation.connection->server.next_seq == 1);
}

static void test_infers_midstream_server_payload(void) {
    static const uint8_t PAYLOAD[] = "HTTP";
    TcpTracker tracker;
    tcp_tracker_init(&tracker);
    TcpHeader segment = make_segment(443, 60000, 7000, 9000, TCP_ACK | TCP_PSH, 4);
    segment.payload = PAYLOAD;

    TcpObservation observation = observe(
        &tracker, SERVER_IP, CLIENT_IP, segment);
    assert(observation.created);
    assert(observation.connection->inferred);
    assert(!observation.src_is_client);
    assert(observation.stream_emitted == 4);
    assert(memcmp(observation.stream_preview, "HTTP", 4) == 0);
    assert(observation.connection->server.stream.delivered_bytes == 4);
    assert(observation.connection->client.next_seq == 9000);
}

static void test_recovers_handshake_from_syn_ack(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    TcpObservation observation = observe(
        &tracker, SERVER_IP, CLIENT_IP,
        make_segment(80, 54321, 500, 101, TCP_SYN | TCP_ACK, 0));
    assert(observation.created);
    assert(observation.connection->inferred);
    assert(!observation.src_is_client);
    assert_states(observation.connection, TCP_STATE_SYN_SENT, TCP_STATE_SYN_RCVD);

    observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(54321, 80, 101, 501, TCP_ACK, 0));
    assert_states(observation.connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);
}

static void test_stream_reassembles_gap(void) {
    static const uint8_t HEAD[] = "abc";
    static const uint8_t TAIL[] = "def";
    TcpTracker tracker;
    tcp_tracker_init(&tracker);
    TcpConnection* connection = establish(&tracker, 34567, 80);

    TcpHeader tail = make_segment(34567, 80, 104, 501, TCP_ACK | TCP_PSH, 3);
    tail.payload = TAIL;
    TcpObservation observation = observe(&tracker, CLIENT_IP, SERVER_IP, tail);
    assert(observation.seq_status == TCP_SEQ_GAP);
    assert(observation.stream_emitted == 0);
    assert(observation.stream_buffered == 3);
    assert(connection->client.next_seq == 101);

    TcpHeader head = make_segment(34567, 80, 101, 501, TCP_ACK | TCP_PSH, 3);
    head.payload = HEAD;
    observation = observe(&tracker, CLIENT_IP, SERVER_IP, head);
    assert(observation.seq_status == TCP_SEQ_IN_ORDER);
    assert(observation.stream_status == TCP_STREAM_OK);
    assert(observation.stream_emitted == 6);
    assert(observation.stream_buffered == 0);
    assert(observation.stream_preview_len == 6);
    assert(memcmp(observation.stream_preview, "abcdef", 6) == 0);
    assert(connection->client.next_seq == 107);
    assert(connection->client.stream.delivered_bytes == 6);
}

static void test_out_of_order_fin_waits_for_gap(void) {
    static const uint8_t DATA[] = "abc";
    TcpTracker tracker;
    tcp_tracker_init(&tracker);
    TcpConnection* connection = establish(&tracker, 45678, 80);

    TcpObservation observation = observe(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(45678, 80, 104, 501, TCP_ACK | TCP_FIN, 0));
    assert(observation.seq_status == TCP_SEQ_GAP);
    assert_states(connection, TCP_STATE_ESTABLISHED, TCP_STATE_ESTABLISHED);
    assert(connection->client.pending_fin_valid);

    TcpHeader data = make_segment(45678, 80, 101, 501, TCP_ACK | TCP_PSH, 3);
    data.payload = DATA;
    observation = observe(&tracker, CLIENT_IP, SERVER_IP, data);
    assert(observation.stream_emitted == 3);
    assert_states(connection, TCP_STATE_FIN_WAIT_1, TCP_STATE_CLOSE_WAIT);
    assert(connection->client.next_seq == 105);
    assert(!connection->client.pending_fin_valid);
}

static void test_reuses_reset_connection_slots(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS + 1; i++) {
        uint16_t client_port = (uint16_t)(10000 + i);
        TcpObservation observation = observe(
            &tracker, CLIENT_IP, SERVER_IP,
            make_segment(client_port, 80, 100, 0, TCP_SYN, 0));
        assert(observation.created);
        observation = observe(
            &tracker, SERVER_IP, CLIENT_IP,
            make_segment(80, client_port, 500, 0, TCP_RST, 0));
        assert_states(observation.connection, TCP_STATE_CLOSED, TCP_STATE_CLOSED);
    }
}

static void test_expires_idle_connections(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    TcpObservation observation = observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(20000, 80, 100, 0, TCP_SYN, 0), 10);
    assert(observation.connection->id == 1);
    tcp_tracker_expire_idle(&tracker, 11 + TCP_TRACKER_IDLE_TIMEOUT_USEC);
    assert(tracker.expired_connections == 1);
    assert(active_connections(&tracker) == 0);

    observation = observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(20001, 80, 100, 0, TCP_SYN, 0),
        11 + TCP_TRACKER_IDLE_TIMEOUT_USEC);
    assert(observation.connection->id == 2);
    assert(tracker.expired_connections == 1);
    assert(tracker.evicted_connections == 0);
    assert(active_connections(&tracker) == 1);
}

static void test_activity_refreshes_idle_timeout(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(21000, 80, 100, 0, TCP_SYN, 0), 10);
    observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(21000, 80, 101, 0, TCP_ACK, 0),
        10 + TCP_TRACKER_IDLE_TIMEOUT_USEC);
    observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(21001, 80, 100, 0, TCP_SYN, 0),
        11 + TCP_TRACKER_IDLE_TIMEOUT_USEC);

    assert(tracker.expired_connections == 0);
    assert(active_connections(&tracker) == 2);
}

static void test_evicts_oldest_connection_when_full(void) {
    TcpTracker tracker;
    tcp_tracker_init(&tracker);

    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        TcpObservation observation = observe_at(
            &tracker, CLIENT_IP, SERVER_IP,
            make_segment((uint16_t)(22000 + i), 80, 100, 0, TCP_SYN, 0),
            i + 1);
        assert(observation.created);
    }
    assert(active_connections(&tracker) == TCP_TRACKER_MAX_CONNECTIONS);

    TcpObservation observation = observe_at(
        &tracker, CLIENT_IP, SERVER_IP,
        make_segment(23000, 80, 100, 0, TCP_SYN, 0),
        TCP_TRACKER_MAX_CONNECTIONS + 1);
    assert(observation.created);
    assert(observation.connection->id == TCP_TRACKER_MAX_CONNECTIONS + 1);
    assert(observation.connection->client.port == 23000);
    assert(tracker.connections[0].client.port == 23000);
    assert(tracker.expired_connections == 0);
    assert(tracker.evicted_connections == 1);
    assert(active_connections(&tracker) == TCP_TRACKER_MAX_CONNECTIONS);
}

int main(void) {
    test_handshake_data_and_close();
    test_sequence_gap_and_reset();
    test_bad_syn_ack_does_not_establish();
    test_infers_midstream_ack();
    test_infers_midstream_server_payload();
    test_recovers_handshake_from_syn_ack();
    test_stream_reassembles_gap();
    test_out_of_order_fin_waits_for_gap();
    test_reuses_reset_connection_slots();
    test_expires_idle_connections();
    test_activity_refreshes_idle_timeout();
    test_evicts_oldest_connection_when_full();
    printf("tcp_state tests passed\n");
    return 0;
}
