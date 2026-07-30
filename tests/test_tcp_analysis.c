#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tcp_analysis.h"

/* ── segment construction helpers ────────────────────────────────────────── */

static void segment_init(TcpHeader* segment, uint8_t flags,
                         uint32_t seq, uint32_t ack, uint16_t window) {
    memset(segment, 0, sizeof(*segment));
    segment->src_port    = 1234;
    segment->dst_port    = 80;
    segment->seq_num     = seq;
    segment->ack_num     = ack;
    segment->flags       = flags;
    segment->window      = window;
    segment->data_offset = 5;
    segment->hdr_len     = 20;
}

static void segment_set_payload(TcpHeader* segment,
                                const uint8_t* data, size_t len) {
    segment->payload     = data;
    segment->payload_len = len;
}

static void segment_add_option(TcpHeader* segment, uint8_t kind,
                               const uint8_t* data, uint8_t data_len) {
    TcpOption* opt = &segment->options[segment->opt_count++];
    opt->kind     = kind;
    opt->data_len = data_len;
    if (data_len > 0)
        memcpy(opt->data, data, data_len);
}

static void put32(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/* ── window scaling (RFC 7323) ───────────────────────────────────────────── */

static void test_window_scale_needs_both_sides(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    uint8_t shift = 7;

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    /* Only the client offers scaling, so nothing may be scaled. */
    segment_init(&segment, TCP_SYN, 1000, 0, 8192);
    segment_add_option(&segment, TCP_OPT_WSCALE, &shift, 1);
    tcp_analysis_note_syn_options(&client, &segment);
    tcp_analysis_settle_options(&client, &server);
    assert(client.wscale_active == 0);
    assert(server.wscale_active == 0);

    segment_init(&segment, TCP_ACK, 1001, 5001, 8192);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);
    assert(out.window_was_scaled == 0);
    assert(out.window_scaled == 8192);

    /* Now the server offers it too, and the client's window scales. */
    segment_init(&segment, TCP_SYN | TCP_ACK, 5000, 1001, 8192);
    segment_add_option(&segment, TCP_OPT_WSCALE, &shift, 1);
    tcp_analysis_note_syn_options(&server, &segment);
    tcp_analysis_settle_options(&client, &server);
    assert(client.wscale_active == 1);
    assert(server.wscale_active == 1);

    segment_init(&segment, TCP_ACK, 1001, 5001, 8192);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);
    assert(out.window_was_scaled == 1);
    assert(out.window_scaled == 8192u << 7);
}

static void test_syn_window_is_never_scaled(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    uint8_t shift = 7;

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    segment_init(&segment, TCP_SYN, 1000, 0, 8192);
    segment_add_option(&segment, TCP_OPT_WSCALE, &shift, 1);
    tcp_analysis_note_syn_options(&client, &segment);
    tcp_analysis_note_syn_options(&server, &segment);
    tcp_analysis_settle_options(&client, &server);
    assert(client.wscale_active == 1);

    /* The option announcing the shift travels in this same segment, so there
       is no agreed factor to apply to its own window yet. */
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_FIRST,
                         1000, &out);
    assert(out.window_was_scaled == 0);
    assert(out.window_scaled == 8192);
}

static void test_window_scale_shift_is_capped(void) {
    TcpEndpointAnalysis endpoint;
    TcpHeader segment;
    uint8_t shift = 200;

    tcp_analysis_init(&endpoint);
    segment_init(&segment, TCP_SYN, 0, 0, 8192);
    segment_add_option(&segment, TCP_OPT_WSCALE, &shift, 1);
    tcp_analysis_note_syn_options(&endpoint, &segment);

    /* RFC 7323 §2.3 caps the shift at 14. Honouring 200 would shift a 16-bit
       field past the width of the type holding the result. */
    assert(endpoint.wscale_shift == 14);
}

static void test_scaling_inferred_from_syn_ack(void) {
    TcpEndpointAnalysis client, server;
    uint8_t shift = 8;
    TcpHeader synack;

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    /* Capture began at the SYN-ACK. The server would not have echoed the
       option unless the client had offered it, so scaling is in use — but the
       client's own shift was never seen, so its windows stay unscaled. */
    segment_init(&synack, TCP_SYN | TCP_ACK, 5000, 1001, 8192);
    segment_add_option(&synack, TCP_OPT_WSCALE, &shift, 1);
    tcp_analysis_note_syn_options(&server, &synack);
    client.wscale_offer_inferred = 1;
    tcp_analysis_settle_options(&client, &server);

    assert(server.wscale_active == 1);
    assert(client.wscale_active == 0);
}

/* ── duplicate ACKs and fast retransmit ──────────────────────────────────── */

static void test_duplicate_acks_then_fast_retransmit(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };
    uint64_t now = 1000000;

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    /* The sender pushes three segments so there is data outstanding. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         now, &out);
    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         now + 1000, &out);
    segment_init(&segment, TCP_ACK, 1200, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         now + 2000, &out);

    /* The receiver acknowledges 1100 once, then repeats it three times. */
    segment_init(&segment, TCP_ACK, 1, 1100, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         now + 3000, &out);
    assert(!(out.findings & TCP_FINDING_DUP_ACK));

    for (unsigned i = 1; i <= 3; i++) {
        segment_init(&segment, TCP_ACK, 1, 1100, 8192);
        tcp_analysis_observe(&receiver, &sender, &segment,
                             TCP_ARRIVAL_IN_ORDER, now + 3000 + i * 100, &out);
        assert(out.findings & TCP_FINDING_DUP_ACK);
        assert(out.dup_ack_run == i);
    }
    assert(receiver.dup_acks == 3);

    /* The sender resends the missing segment. Three duplicate ACKs is the
       protocol-defined trigger, so this is a fast retransmission — and the
       delay puts it outside the reordering window. */
    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, now + 10000, &out);
    assert(out.retrans == TCP_RETRANS_FAST);
    assert(sender.retrans_fast == 1);
    assert(sender.retrans_bytes == 100);
}

static void test_window_update_is_not_a_duplicate_ack(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    segment_init(&segment, TCP_ACK, 1, 1050, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);

    /* Same ACK number, larger window: this conveys new information, so it is
       a window update rather than a duplicate. Counting it as a duplicate
       would inflate the fast-retransmit signal. */
    segment_init(&segment, TCP_ACK, 1, 1050, 16384);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         3000, &out);
    assert(!(out.findings & TCP_FINDING_DUP_ACK));
    assert(receiver.dup_acks == 0);
}

static void test_repeat_ack_with_nothing_outstanding_is_not_duplicate(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    /* Everything the sender sent is acknowledged, so a repeat cannot be
       signalling a hole. */
    for (int i = 0; i < 3; i++) {
        segment_init(&segment, TCP_ACK, 1, 1100, 8192);
        tcp_analysis_observe(&receiver, &sender, &segment,
                             TCP_ARRIVAL_IN_ORDER, 2000 + i * 100u, &out);
    }
    assert(receiver.dup_acks == 0);
}

/* ── retransmission classification ───────────────────────────────────────── */

static void test_spurious_retransmission(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    /* The receiver acknowledges all of it. */
    segment_init(&segment, TCP_ACK, 1, 1100, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);

    /* Resending acknowledged data is spurious, and that verdict outranks the
       timing guesses because the receiver stated it outright. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, 3000000, &out);
    assert(out.retrans == TCP_RETRANS_SPURIOUS);
    assert(sender.retrans_spurious == 1);
}

static void test_timeout_retransmission(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000000, &out);

    /* No duplicate ACKs and nothing acknowledged, after a silence longer than
       the RTO floor: an expired timer is the remaining explanation. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED,
                         1000000 + TCP_RTO_FLOOR_USEC + 1000, &out);
    assert(out.retrans == TCP_RETRANS_TIMEOUT);
    assert(sender.retrans_timeout == 1);
}

static void test_fast_reorder_is_not_a_retransmission(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000000, &out);

    /* The gap-filling segment turns up a few hundred microseconds later with
       no duplicate ACK to have prompted it. No sender reacts that fast, so
       this is the network reordering, not a resend. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, 1000500, &out);
    assert(out.findings & TCP_FINDING_OUT_OF_ORDER);
    assert(out.retrans == TCP_RETRANS_NONE);
    assert(sender.out_of_order == 1);
    assert(sender.retrans_bytes == 0);
}

static void test_dup_acks_rule_out_reordering(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000000, &out);
    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000100, &out);

    segment_init(&segment, TCP_ACK, 1, 1000, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000200, &out);
    segment_init(&segment, TCP_ACK, 1, 1000, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000300, &out);
    assert(out.findings & TCP_FINDING_DUP_ACK);

    /* Even arriving inside the reordering window, a duplicate ACK gave the
       sender a reason to resend, so reordering is no longer the simpler
       explanation. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, 1000400, &out);
    assert(!(out.findings & TCP_FINDING_OUT_OF_ORDER));
    assert(out.retrans != TCP_RETRANS_NONE);
}

/* ── window pressure ─────────────────────────────────────────────────────── */

static void test_zero_window_then_update(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    segment_init(&segment, TCP_ACK, 1, 1000, 0);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);
    assert(out.findings & TCP_FINDING_ZERO_WINDOW);
    assert(client.zero_window == 1);
    assert(client.zero_window_events == 1);

    /* A second zero-window advertisement is the same condition, not a new
       event. */
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);
    assert(client.zero_window_events == 1);

    segment_init(&segment, TCP_ACK, 1, 1000, 4096);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         3000, &out);
    assert(out.findings & TCP_FINDING_WINDOW_UPDATE);
    assert(client.zero_window == 0);
}

static void test_zero_window_probe(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t byte = 'x';

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    /* The client advertises no room. */
    segment_init(&segment, TCP_ACK, 1, 1000, 0);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    /* The server offers a single byte to prompt an update. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, &byte, 1);
    tcp_analysis_observe(&server, &client, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);
    assert(out.findings & TCP_FINDING_ZERO_WINDOW_PROBE);
}

static void test_window_full_and_bytes_in_flight(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[200] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    /* The receiver advertises a 200-byte window and acknowledges 1000. */
    segment_init(&segment, TCP_ACK, 1, 1000, 200);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    /* The sender fills it exactly. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 200);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);
    assert(out.bytes_in_flight_valid);
    assert(out.bytes_in_flight == 200);
    assert(out.findings & TCP_FINDING_WINDOW_FULL);
    assert(sender.window_full_events == 1);
}

static void test_keep_alive(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);
    assert(client.highest_seq_sent == 1100);

    /* A keep-alive sits one below the next byte owed. */
    segment_init(&segment, TCP_ACK, 1099, 1, 8192);
    tcp_analysis_observe(&client, &server, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, 60000000, &out);
    assert(out.findings & TCP_FINDING_KEEP_ALIVE);
    assert(client.keep_alives == 1);

    /* The peer's bare ACK in response is the keep-alive ACK. */
    segment_init(&segment, TCP_ACK, 1, 1100, 8192);
    tcp_analysis_observe(&server, &client, &segment, TCP_ARRIVAL_IN_ORDER,
                         60001000, &out);
    assert(out.findings & TCP_FINDING_KEEP_ALIVE_ACK);
}

/* ── SACK ────────────────────────────────────────────────────────────────── */

static void test_sack_reveals_one_hole(void) {
    TcpEndpointAnalysis receiver, sender;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    uint8_t blocks[8];

    tcp_analysis_init(&receiver);
    tcp_analysis_init(&sender);

    /* Acknowledges through 1000 but holds 1100..1200: the 100 bytes between
       are what went missing. */
    put32(blocks + 0, 1100);
    put32(blocks + 4, 1200);
    segment_init(&segment, TCP_ACK, 1, 1000, 8192);
    segment_add_option(&segment, TCP_OPT_SACK, blocks, 8);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    assert(out.sack_block_count == 1);
    assert(out.sacked_bytes == 100);
    assert(out.findings & TCP_FINDING_SACK_HOLE);
    assert(out.hole_count == 1);
    assert(out.hole_left[0] == 1000);
    assert(out.hole_right[0] == 1100);
    assert(out.hole_bytes == 100);
}

static void test_sack_blocks_out_of_order(void) {
    TcpEndpointAnalysis receiver, sender;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    uint8_t blocks[16];

    tcp_analysis_init(&receiver);
    tcp_analysis_init(&sender);

    /* RFC 2018 does not require the blocks after the first to be sorted, so
       the hole walk has to sort them before trusting the edges. */
    put32(blocks + 0, 1300);
    put32(blocks + 4, 1400);
    put32(blocks + 8, 1100);
    put32(blocks + 12, 1200);
    segment_init(&segment, TCP_ACK, 1, 1000, 8192);
    segment_add_option(&segment, TCP_OPT_SACK, blocks, 16);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    assert(out.sack_block_count == 2);
    assert(out.sack_left[0] == 1100);
    assert(out.sack_left[1] == 1300);
    assert(out.hole_count == 2);
    assert(out.hole_left[0] == 1000 && out.hole_right[0] == 1100);
    assert(out.hole_left[1] == 1200 && out.hole_right[1] == 1300);
    assert(out.hole_bytes == 200);
}

static void test_sack_rejects_reversed_block(void) {
    TcpEndpointAnalysis receiver, sender;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    uint8_t blocks[8];

    tcp_analysis_init(&receiver);
    tcp_analysis_init(&sender);

    /* Right edge below left: malformed, and counting it would produce a
       nonsense byte total. */
    put32(blocks + 0, 1200);
    put32(blocks + 4, 1100);
    segment_init(&segment, TCP_ACK, 1, 1000, 8192);
    segment_add_option(&segment, TCP_OPT_SACK, blocks, 8);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    assert(out.sack_block_count == 0);
    assert(out.sacked_bytes == 0);
    assert(out.hole_count == 0);
}

/* ── gaps and unseen data ────────────────────────────────────────────────── */

static void test_gap_reports_missing_segment(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 2000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_ABOVE_EXPECTED, 1000, &out);
    assert(out.findings & TCP_FINDING_PREVIOUS_MISSING);
    assert(sender.missing_segments == 1);
}

static void test_quick_gap_fill_is_reordering(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    /* The later segment arrives first, leaving a gap. */
    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_ABOVE_EXPECTED, 1000000, &out);
    assert(out.findings & TCP_FINDING_PREVIOUS_MISSING);
    assert(sender.missing_segments == 1);

    /* Its predecessor turns up half a millisecond later: the two were swapped
       in flight, so nothing was lost and the gap is withdrawn. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000500, &out);
    assert(out.findings & TCP_FINDING_OUT_OF_ORDER);
    assert(sender.out_of_order == 1);
    assert(sender.missing_segments == 0);
}

static void test_slow_gap_fill_keeps_the_gap(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    segment_init(&segment, TCP_ACK, 1100, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_ABOVE_EXPECTED, 1000000, &out);
    assert(sender.missing_segments == 1);

    /* Filled a quarter of a second later, which is long enough that it had to
       be retransmitted. The data really was missing, so the gap stands. */
    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1250000, &out);
    assert(!(out.findings & TCP_FINDING_OUT_OF_ORDER));
    assert(sender.out_of_order == 0);
    assert(sender.missing_segments == 1);
}

static void test_ack_beyond_observed_data(void) {
    TcpEndpointAnalysis client, server;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&client);
    tcp_analysis_init(&server);

    segment_init(&segment, TCP_ACK, 1000, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&client, &server, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);

    /* The server acknowledges past anything the client was seen to send, so
       the capture missed a segment that certainly existed. */
    segment_init(&segment, TCP_ACK, 1, 1500, 8192);
    tcp_analysis_observe(&server, &client, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);
    assert(out.findings & TCP_FINDING_ACK_UNSEEN_SEGMENT);
}

/* ── sequence-space wraparound ───────────────────────────────────────────── */

static void test_wraparound_retransmission(void) {
    TcpEndpointAnalysis sender, receiver;
    TcpSegmentAnalysis out;
    TcpHeader segment;
    const uint8_t payload[100] = { 0 };

    tcp_analysis_init(&sender);
    tcp_analysis_init(&receiver);

    /* Data straddling the 32-bit boundary. */
    segment_init(&segment, TCP_ACK, UINT32_MAX - 49u, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment, TCP_ARRIVAL_IN_ORDER,
                         1000, &out);
    assert(sender.highest_seq_sent == 50u);

    /* Acknowledged past the wrap, so resending it is spurious — the
       comparison has to be modular for this to come out right. */
    segment_init(&segment, TCP_ACK, 1, 50, 8192);
    tcp_analysis_observe(&receiver, &sender, &segment, TCP_ARRIVAL_IN_ORDER,
                         2000, &out);

    segment_init(&segment, TCP_ACK, UINT32_MAX - 49u, 1, 8192);
    segment_set_payload(&segment, payload, 100);
    tcp_analysis_observe(&sender, &receiver, &segment,
                         TCP_ARRIVAL_BELOW_EXPECTED, 3000000, &out);
    assert(out.retrans == TCP_RETRANS_SPURIOUS);
}

/* ── RTT smoothing ───────────────────────────────────────────────────────── */

static void test_rtt_statistics(void) {
    TcpEndpointAnalysis endpoint;

    tcp_analysis_init(&endpoint);
    assert(tcp_analysis_rto_estimate(&endpoint) == TCP_RTO_FLOOR_USEC);

    /* RFC 6298 §2.2: the first sample seeds SRTT outright. */
    tcp_analysis_add_rtt_sample(&endpoint, 100000);
    assert(endpoint.srtt == 100000);
    assert(endpoint.rttvar == 50000);
    assert(endpoint.rtt_min == 100000);
    assert(endpoint.rtt_max == 100000);

    tcp_analysis_add_rtt_sample(&endpoint, 200000);
    assert(endpoint.rtt_min == 100000);
    assert(endpoint.rtt_max == 200000);
    /* SRTT moves an eighth of the way toward the new sample. */
    assert(endpoint.srtt == (100000u * 7u + 200000u) / 8u);
    assert(endpoint.rtt_samples == 3 - 1);

    /* The estimate must never fall below the floor. */
    tcp_analysis_init(&endpoint);
    tcp_analysis_add_rtt_sample(&endpoint, 100);
    assert(tcp_analysis_rto_estimate(&endpoint) == TCP_RTO_FLOOR_USEC);
}

static void test_throughput_and_goodput(void) {
    TcpEndpointAnalysis endpoint;

    tcp_analysis_init(&endpoint);
    assert(tcp_analysis_throughput_bps(&endpoint) == 0.0);

    endpoint.seen = 1;
    endpoint.first_seen_usec = 1000000;
    endpoint.last_seen_usec  = 3000000;
    endpoint.payload_bytes   = 2000;
    endpoint.retrans_bytes   = 500;

    /* 2000 bytes over two seconds. */
    assert(tcp_analysis_throughput_bps(&endpoint) == 1000.0);
    assert(tcp_analysis_goodput_bytes(&endpoint) == 1500);

    /* Retransmitted more than sent should clamp rather than wrap. */
    endpoint.retrans_bytes = 5000;
    assert(tcp_analysis_goodput_bytes(&endpoint) == 0);
}

/* ── findings string ─────────────────────────────────────────────────────── */

static void test_findings_string(void) {
    char buf[256];
    char tiny[8];

    tcp_findings_str(0, buf, sizeof(buf));
    assert(buf[0] == '\0');

    tcp_findings_str(TCP_FINDING_DUP_ACK | TCP_FINDING_WINDOW_FULL,
                     buf, sizeof(buf));
    assert(strcmp(buf, "duplicate ACK, window full") == 0);

    /* A buffer too small to hold the first name must still be terminated. */
    tcp_findings_str(TCP_FINDING_DUP_ACK, tiny, sizeof(tiny));
    assert(tiny[0] == '\0');

    /* And a zero-length buffer must not be written to at all. */
    tcp_findings_str(TCP_FINDING_DUP_ACK, buf, 0);
}

int main(void) {
    test_window_scale_needs_both_sides();
    test_syn_window_is_never_scaled();
    test_window_scale_shift_is_capped();
    test_scaling_inferred_from_syn_ack();

    test_duplicate_acks_then_fast_retransmit();
    test_window_update_is_not_a_duplicate_ack();
    test_repeat_ack_with_nothing_outstanding_is_not_duplicate();

    test_spurious_retransmission();
    test_timeout_retransmission();
    test_fast_reorder_is_not_a_retransmission();
    test_dup_acks_rule_out_reordering();

    test_zero_window_then_update();
    test_zero_window_probe();
    test_window_full_and_bytes_in_flight();
    test_keep_alive();

    test_sack_reveals_one_hole();
    test_sack_blocks_out_of_order();
    test_sack_rejects_reversed_block();

    test_gap_reports_missing_segment();
    test_quick_gap_fill_is_reordering();
    test_slow_gap_fill_keeps_the_gap();
    test_ack_beyond_observed_data();
    test_wraparound_retransmission();

    test_rtt_statistics();
    test_throughput_and_goodput();
    test_findings_string();

    printf("tcp_analysis tests passed\n");
    return 0;
}
