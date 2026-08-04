#include "tcp_state.h"

static void sync_endpoint_sequence(TcpEndpoint* endpoint);

static int endpoint_matches(const TcpEndpoint* endpoint,
                            const uint8_t* ip, uint8_t ip_len, uint16_t port) {
    return endpoint->ip_len == ip_len
        && endpoint->port == port
        && memcmp(endpoint->ip, ip, ip_len) == 0;
}

static int connection_is_closed(const TcpConnection* connection) {
    return connection->client.state == TCP_STATE_CLOSED
        && connection->server.state == TCP_STATE_CLOSED;
}

static int idle_timeout_elapsed(uint64_t now_usec, uint64_t last_seen_usec) {
    return now_usec > last_seen_usec
        && now_usec - last_seen_usec > TCP_TRACKER_IDLE_TIMEOUT_USEC;
}

void tcp_tracker_expire_idle(TcpTracker* tracker, uint64_t now_usec) {
    if (!tracker)
        return;
    if (now_usec > tracker->logical_now_usec)
        tracker->logical_now_usec = now_usec;

    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use
                || !idle_timeout_elapsed(now_usec, connection->last_seen_usec))
            continue;

        memset(connection, 0, sizeof(*connection));
        tracker->expired_connections++;
    }
}

static TcpConnection* find_connection(TcpTracker* tracker,
                                      const uint8_t* src_ip, uint8_t ip_len,
                                      uint16_t src_port,
                                      const uint8_t* dst_ip, uint16_t dst_port,
                                      int* src_is_client) {
    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use || connection_is_closed(connection))
            continue;

        if (endpoint_matches(&connection->client, src_ip, ip_len, src_port)
                && endpoint_matches(&connection->server, dst_ip, ip_len, dst_port)) {
            *src_is_client = 1;
            return connection;
        }
        if (endpoint_matches(&connection->server, src_ip, ip_len, src_port)
                && endpoint_matches(&connection->client, dst_ip, ip_len, dst_port)) {
            *src_is_client = 0;
            return connection;
        }
    }
    return NULL;
}

static TcpConnection* reset_connection_slot(TcpTracker* tracker,
                                            TcpConnection* connection) {
    memset(connection, 0, sizeof(*connection));
    connection->in_use = 1;
    connection->id = tracker->next_id++;
    return connection;
}

static TcpConnection* allocate_connection(TcpTracker* tracker) {
    TcpConnection* oldest = NULL;

    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use)
            return reset_connection_slot(tracker, connection);
    }

    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        TcpConnection* connection = &tracker->connections[i];
        if (connection_is_closed(connection))
            return reset_connection_slot(tracker, connection);

        if (!oldest || connection->last_seen_usec < oldest->last_seen_usec)
            oldest = connection;
    }

    if (!oldest)
        return NULL;
    tracker->evicted_connections++;
    return reset_connection_slot(tracker, oldest);
}

static void init_endpoint(TcpEndpoint* endpoint,
                          const uint8_t* ip, uint8_t ip_len,
                          uint16_t port, TcpState state) {
    memcpy(endpoint->ip, ip, ip_len);
    endpoint->ip_len = ip_len;
    endpoint->port = port;
    endpoint->state = state;
}

static TcpConnection* create_syn_connection(
    TcpTracker* tracker,
    const uint8_t* src_ip, uint16_t src_port,
    const uint8_t* dst_ip, uint16_t dst_port,
    uint8_t ip_len) {
    TcpConnection* connection = allocate_connection(tracker);
    if (!connection)
        return NULL;

    init_endpoint(&connection->client, src_ip, ip_len, src_port, TCP_STATE_CLOSED);
    init_endpoint(&connection->server, dst_ip, ip_len, dst_port, TCP_STATE_LISTEN);
    return connection;
}

static TcpConnection* create_syn_ack_connection(
    TcpTracker* tracker,
    const uint8_t* src_ip, uint16_t src_port,
    const uint8_t* dst_ip, uint16_t dst_port,
    uint32_t client_next_seq,
    uint8_t ip_len) {
    TcpConnection* connection = allocate_connection(tracker);
    if (!connection)
        return NULL;

    connection->inferred = 1;
    connection->syn_ack_seen = 1;
    init_endpoint(&connection->client, dst_ip, ip_len, dst_port, TCP_STATE_SYN_SENT);
    init_endpoint(&connection->server, src_ip, ip_len, src_port, TCP_STATE_SYN_RCVD);
    tcp_stream_reset(&connection->client.stream, client_next_seq);
    sync_endpoint_sequence(&connection->client);
    return connection;
}

static int source_is_likely_server(uint16_t src_port, uint16_t dst_port) {
    /* Without a handshake, the lower port is usually the listening service. */
    if (src_port == dst_port)
        return 0;
    return src_port < dst_port;
}

static TcpConnection* create_midstream_connection(
    TcpTracker* tracker,
    const uint8_t* src_ip, uint16_t src_port,
    const uint8_t* dst_ip, uint16_t dst_port,
    const TcpHeader* segment,
    uint8_t ip_len,
    int* src_is_client) {
    TcpConnection* connection = allocate_connection(tracker);
    int src_is_server;
    if (!connection)
        return NULL;

    connection->inferred = 1;
    src_is_server = source_is_likely_server(src_port, dst_port);
    *src_is_client = !src_is_server;

    if (*src_is_client) {
        init_endpoint(&connection->client, src_ip, ip_len, src_port, TCP_STATE_ESTABLISHED);
        init_endpoint(&connection->server, dst_ip, ip_len, dst_port, TCP_STATE_ESTABLISHED);
    } else {
        init_endpoint(&connection->client, dst_ip, ip_len, dst_port, TCP_STATE_ESTABLISHED);
        init_endpoint(&connection->server, src_ip, ip_len, src_port, TCP_STATE_ESTABLISHED);
    }

    if (segment->flags & TCP_ACK) {
        TcpEndpoint* dst = *src_is_client
                         ? &connection->server : &connection->client;
        tcp_stream_reset(&dst->stream, segment->ack_num);
        sync_endpoint_sequence(dst);
    }
    return connection;
}

static int seq_at_or_after(uint32_t value, uint32_t expected) {
    return (int32_t)(value - expected) >= 0;
}

static int ack_covers(const TcpHeader* segment, const TcpEndpoint* endpoint) {
    return endpoint->next_seq_valid
        && seq_at_or_after(segment->ack_num, endpoint->next_seq);
}

static void sync_endpoint_sequence(TcpEndpoint* endpoint) {
    endpoint->next_seq = endpoint->stream.next_seq;
    endpoint->next_seq_valid = endpoint->stream.next_seq_valid;
}

static void collect_stream_bytes(const uint8_t* data, size_t len, void* context) {
    TcpObservation* observation = (TcpObservation*)context;
    size_t available = TCP_STREAM_PREVIEW_LEN - observation->stream_preview_len;
    size_t copy = len < available ? len : available;

    memcpy(observation->stream_preview + observation->stream_preview_len,
           data, copy);
    observation->stream_preview_len += copy;
}

static int consume_pending_fin(TcpEndpoint* endpoint) {
    if (!endpoint->pending_fin_valid
            || endpoint->pending_fin_seq != endpoint->stream.next_seq)
        return 0;

    if (tcp_stream_advance(&endpoint->stream, 1) != 0)
        return 0;

    endpoint->pending_fin_valid = 0;
    sync_endpoint_sequence(endpoint);
    return 1;
}

static TcpSeqStatus track_sequence(TcpEndpoint* endpoint,
                                   const TcpHeader* segment,
                                   TcpObservation* observation,
                                   int* fin_consumed) {
    uint32_t payload_seq = segment->seq_num;
    TcpSeqStatus status = TCP_SEQ_UNTRACKED;
    size_t emitted = 0;

    observation->expected_seq = endpoint->next_seq;
    observation->stream_status = TCP_STREAM_OK;
    *fin_consumed = 0;

    if (!endpoint->next_seq_valid) {
        tcp_stream_reset(&endpoint->stream, segment->seq_num);
        sync_endpoint_sequence(endpoint);
    } else if (segment->seq_num == endpoint->next_seq) {
        status = TCP_SEQ_IN_ORDER;
    } else if (seq_at_or_after(endpoint->next_seq, segment->seq_num)) {
        status = TCP_SEQ_RETRANSMISSION;
    } else {
        status = TCP_SEQ_GAP;
    }

    if ((segment->flags & TCP_SYN)
            && segment->seq_num == endpoint->stream.next_seq) {
        if (tcp_stream_advance(&endpoint->stream, 1) != 0)
            observation->stream_status = TCP_STREAM_CONFLICT;
        sync_endpoint_sequence(endpoint);
        payload_seq++;
    } else if (segment->flags & TCP_SYN) {
        payload_seq++;
    }

    if (observation->stream_status == TCP_STREAM_OK
            && segment->payload_len > 0) {
        observation->stream_status = tcp_stream_add(
            &endpoint->stream, payload_seq, segment->payload,
            segment->payload_len, collect_stream_bytes, observation, &emitted);
        observation->stream_emitted += emitted;
        sync_endpoint_sequence(endpoint);
    }

    if (observation->stream_status == TCP_STREAM_OK
            && (segment->flags & TCP_FIN)) {
        uint32_t fin_seq = payload_seq + (uint32_t)segment->payload_len;
        if (seq_at_or_after(fin_seq, endpoint->stream.next_seq)
                && (!endpoint->pending_fin_valid
                    || seq_at_or_after(endpoint->pending_fin_seq, fin_seq))) {
            endpoint->pending_fin_valid = 1;
            endpoint->pending_fin_seq = fin_seq;
        }
    }

    if (observation->stream_status == TCP_STREAM_OK)
        *fin_consumed = consume_pending_fin(endpoint);

    observation->stream_buffered = endpoint->stream.buffered_bytes;
    return status;
}

static void process_ack(TcpConnection* connection,
                        TcpEndpoint* src, TcpEndpoint* dst,
                        const TcpHeader* segment) {
    if (!(segment->flags & TCP_ACK) || !ack_covers(segment, dst))
        return;

    if (!(segment->flags & TCP_SYN)
            && src->state == TCP_STATE_SYN_SENT
            && dst->state == TCP_STATE_SYN_RCVD
            && connection->syn_ack_seen) {
        src->state = TCP_STATE_ESTABLISHED;
        dst->state = TCP_STATE_ESTABLISHED;
        return;
    }

    switch (dst->state) {
        case TCP_STATE_FIN_WAIT_1:
            dst->state = TCP_STATE_FIN_WAIT_2;
            break;
        case TCP_STATE_CLOSING:
            dst->state = TCP_STATE_TIME_WAIT;
            break;
        case TCP_STATE_LAST_ACK:
            dst->state = TCP_STATE_CLOSED;
            break;
        default:
            break;
    }
}

static void process_fin(TcpEndpoint* src, TcpEndpoint* dst) {
    switch (src->state) {
        case TCP_STATE_ESTABLISHED:
            src->state = TCP_STATE_FIN_WAIT_1;
            if (dst->state == TCP_STATE_ESTABLISHED)
                dst->state = TCP_STATE_CLOSE_WAIT;
            else if (dst->state == TCP_STATE_FIN_WAIT_1)
                dst->state = TCP_STATE_CLOSING;
            break;
        case TCP_STATE_CLOSE_WAIT:
            src->state = TCP_STATE_LAST_ACK;
            if (dst->state == TCP_STATE_FIN_WAIT_1)
                dst->state = TCP_STATE_CLOSING;
            else if (dst->state == TCP_STATE_FIN_WAIT_2)
                dst->state = TCP_STATE_TIME_WAIT;
            break;
        default:
            break;
    }
}

static void process_segment(TcpConnection* connection,
                            TcpEndpoint* src, TcpEndpoint* dst,
                            const TcpHeader* segment,
                            int fin_consumed) {
    if (segment->flags & TCP_RST) {
        src->state = TCP_STATE_CLOSED;
        dst->state = TCP_STATE_CLOSED;
        return;
    }

    if ((segment->flags & TCP_SYN) && !(segment->flags & TCP_ACK)
            && src->state == TCP_STATE_CLOSED
            && dst->state == TCP_STATE_LISTEN) {
        src->state = TCP_STATE_SYN_SENT;
        dst->state = TCP_STATE_SYN_RCVD;
        return;
    }

    if ((segment->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)
            && src->state == TCP_STATE_SYN_RCVD
            && dst->state == TCP_STATE_SYN_SENT
            && ack_covers(segment, dst))
        connection->syn_ack_seen = 1;

    process_ack(connection, src, dst, segment);

    if (fin_consumed)
        process_fin(src, dst);
}

/*
 * Translate the tracker's sequence verdict into the raw placement the analysis
 * module works from. The tracker already calls a segment below the expected
 * point a retransmission; the analysis is what decides whether it really is
 * one or is merely reordered, so it is handed the placement instead.
 */
static TcpArrival arrival_of(TcpSeqStatus status) {
    switch (status) {
        case TCP_SEQ_IN_ORDER:       return TCP_ARRIVAL_IN_ORDER;
        case TCP_SEQ_RETRANSMISSION: return TCP_ARRIVAL_BELOW_EXPECTED;
        case TCP_SEQ_GAP:            return TCP_ARRIVAL_ABOVE_EXPECTED;
        default:                     return TCP_ARRIVAL_FIRST;
    }
}

void tcp_tracker_init(TcpTracker* tracker) {
    memset(tracker, 0, sizeof(*tracker));
    tracker->next_id = 1;
}

static int tcp_tracker_observe_impl(TcpTracker* tracker,
                                    const uint8_t* src_ip, const uint8_t* dst_ip,
                                    uint8_t ip_len,
                                    const TcpHeader* segment, uint64_t now_usec,
                                    TcpObservation* out) {
    int src_is_client = 0;
    int created = 0;
    if (!tracker || !src_ip || !dst_ip || !segment || !out)
        return 0;

    tcp_tracker_expire_idle(tracker, now_usec);

    TcpConnection* connection = find_connection(
        tracker, src_ip, ip_len, segment->src_port, dst_ip, segment->dst_port,
        &src_is_client);

    if (!connection) {
        if ((segment->flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
            connection = create_syn_ack_connection(
                tracker, src_ip, segment->src_port,
                dst_ip, segment->dst_port, segment->ack_num, ip_len);
            src_is_client = 0;
        } else if (segment->flags & TCP_SYN) {
            connection = create_syn_connection(
                tracker, src_ip, segment->src_port,
                dst_ip, segment->dst_port, ip_len);
            src_is_client = 1;
        } else {
            connection = create_midstream_connection(
                tracker, src_ip, segment->src_port, dst_ip, segment->dst_port,
                segment, ip_len, &src_is_client);
        }
        if (!connection)
            return -1;
        created = 1;
    }
    if (now_usec > connection->last_seen_usec)
        connection->last_seen_usec = now_usec;

    TcpEndpoint* src = src_is_client ? &connection->client : &connection->server;
    TcpEndpoint* dst = src_is_client ? &connection->server : &connection->client;

    memset(out, 0, sizeof(*out));
    out->connection = connection;
    out->created = created;
    out->src_is_client = src_is_client;
    out->src_before = src->state;
    out->dst_before = dst->state;
    int fin_consumed = 0;
    out->seq_status = track_sequence(src, segment, out, &fin_consumed);

    process_segment(connection, src, dst, segment, fin_consumed);

    out->src_after = src->state;
    out->dst_after = dst->state;

    /* Handshake options decide how every later window is read, so they have to
       be recorded before the first non-SYN segment is analysed. */
    if (segment->flags & TCP_SYN) {
        tcp_analysis_note_syn_options(&src->analysis, segment);
        /* A SYN-ACK carrying window scale or SACK-permitted proves the peer's
           SYN offered the same, even when that SYN was never captured. */
        if (segment->flags & TCP_ACK) {
            for (int i = 0; i < segment->opt_count; i++) {
                if (segment->options[i].kind == TCP_OPT_WSCALE)
                    dst->analysis.wscale_offer_inferred = 1;
                else if (segment->options[i].kind == TCP_OPT_SACKP)
                    dst->analysis.sack_permitted = 1;
            }
        }
        tcp_analysis_settle_options(&connection->client.analysis,
                                    &connection->server.analysis);
    }

    tcp_analysis_observe(&src->analysis, &dst->analysis, segment,
                         arrival_of(out->seq_status), now_usec, &out->analysis);

    /* Passive RTT from TCP Timestamps option (RFC 7323).
     * When segment carries TSval, record it on src endpoint.
     * When TSecr matches dst's last recorded TSval, RTT = now - that time. */
    for (int i = 0; i < segment->opt_count; i++) {
        const TcpOption* opt = &segment->options[i];
        if (opt->kind == TCP_OPT_TS && opt->data_len == 8) {
            uint32_t tsval = ((uint32_t)opt->data[0] << 24)
                           | ((uint32_t)opt->data[1] << 16)
                           | ((uint32_t)opt->data[2] <<  8)
                           |  (uint32_t)opt->data[3];
            uint32_t tsecr = ((uint32_t)opt->data[4] << 24)
                           | ((uint32_t)opt->data[5] << 16)
                           | ((uint32_t)opt->data[6] <<  8)
                           |  (uint32_t)opt->data[7];
            if (tsval) {
                src->last_tsval      = tsval;
                src->last_tsval_usec = now_usec;
                src->last_tsval_valid = 1;
            }
            if (tsecr && dst->last_tsval_valid && dst->last_tsval == tsecr
                    && now_usec >= dst->last_tsval_usec) {
                out->has_rtt  = 1;
                out->rtt_usec = now_usec - dst->last_tsval_usec;
                /* The sample belongs to dst: it is dst's timestamp coming
                   back, so the interval measures the round trip dst sees. */
                tcp_analysis_add_rtt_sample(&dst->analysis, out->rtt_usec);
            }
            break;
        }
    }

    return 1;
}

int tcp_tracker_observe_at(TcpTracker* tracker,
                           const uint8_t* src_ip, const uint8_t* dst_ip,
                           const TcpHeader* segment, uint64_t now_usec,
                           TcpObservation* out) {
    return tcp_tracker_observe_impl(
        tracker, src_ip, dst_ip, 4, segment, now_usec, out);
}

int tcp_tracker_observe_v6_at(TcpTracker* tracker,
                               const uint8_t* src_ip6, const uint8_t* dst_ip6,
                               const TcpHeader* segment, uint64_t now_usec,
                               TcpObservation* out) {
    return tcp_tracker_observe_impl(
        tracker, src_ip6, dst_ip6, 16, segment, now_usec, out);
}

int tcp_tracker_observe(TcpTracker* tracker,
                        const uint8_t* src_ip, const uint8_t* dst_ip,
                        const TcpHeader* segment, TcpObservation* out) {
    uint64_t now_usec = tracker && tracker->logical_now_usec < UINT64_MAX
                      ? tracker->logical_now_usec + 1u
                      : (tracker ? tracker->logical_now_usec : 0);
    return tcp_tracker_observe_at(
        tracker, src_ip, dst_ip, segment, now_usec, out);
}

const char* tcp_state_name(TcpState state) {
    switch (state) {
        case TCP_STATE_CLOSED:      return "CLOSED";
        case TCP_STATE_LISTEN:      return "LISTEN";
        case TCP_STATE_SYN_SENT:    return "SYN_SENT";
        case TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
        case TCP_STATE_ESTABLISHED: return "ESTABLISHED";
        case TCP_STATE_FIN_WAIT_1:  return "FIN_WAIT_1";
        case TCP_STATE_FIN_WAIT_2:  return "FIN_WAIT_2";
        case TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
        case TCP_STATE_CLOSING:     return "CLOSING";
        case TCP_STATE_LAST_ACK:    return "LAST_ACK";
        case TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
        default:                    return "UNKNOWN";
    }
}

const char* tcp_seq_status_name(TcpSeqStatus status) {
    switch (status) {
        case TCP_SEQ_UNTRACKED:      return "initial";
        case TCP_SEQ_IN_ORDER:       return "in-order";
        case TCP_SEQ_RETRANSMISSION: return "retransmission";
        case TCP_SEQ_GAP:            return "gap";
        default:                     return "unknown";
    }
}

void tcp_endpoint_address_str(const TcpEndpoint* endpoint,
                              char* buf, size_t buf_len) {
    if (!buf || buf_len == 0)
        return;
    buf[0] = '\0';
    if (!endpoint)
        return;

    if (endpoint->ip_len == 16) {
        snprintf(buf, buf_len, "%x:%x:%x:%x:%x:%x:%x:%x",
                 (unsigned)((endpoint->ip[0]  << 8) | endpoint->ip[1]),
                 (unsigned)((endpoint->ip[2]  << 8) | endpoint->ip[3]),
                 (unsigned)((endpoint->ip[4]  << 8) | endpoint->ip[5]),
                 (unsigned)((endpoint->ip[6]  << 8) | endpoint->ip[7]),
                 (unsigned)((endpoint->ip[8]  << 8) | endpoint->ip[9]),
                 (unsigned)((endpoint->ip[10] << 8) | endpoint->ip[11]),
                 (unsigned)((endpoint->ip[12] << 8) | endpoint->ip[13]),
                 (unsigned)((endpoint->ip[14] << 8) | endpoint->ip[15]));
    } else {
        snprintf(buf, buf_len, "%u.%u.%u.%u",
                 endpoint->ip[0], endpoint->ip[1],
                 endpoint->ip[2], endpoint->ip[3]);
    }
}

static void print_endpoint(const TcpEndpoint* endpoint) {
    char address[TCP_ADDRESS_STR_MAX];

    tcp_endpoint_address_str(endpoint, address, sizeof(address));
    if (endpoint->ip_len == 16)
        printf("[%s]:%u", address, endpoint->port);
    else
        printf("%s:%u", address, endpoint->port);
}

void tcp_observation_print(const TcpObservation* observation) {
    const TcpConnection* connection = observation->connection;
    const TcpEndpoint* src = observation->src_is_client
                           ? &connection->client : &connection->server;
    const TcpEndpoint* dst = observation->src_is_client
                           ? &connection->server : &connection->client;

    printf("  TCP state  : connection #%zu%s%s\n",
           connection->id,
           observation->created ? " (new" : "",
           observation->created
               ? (connection->inferred ? ", inferred mid-stream)" : ")")
               : "");
    printf("    ");
    print_endpoint(src);
    printf("  %s => %s\n",
           tcp_state_name(observation->src_before),
           tcp_state_name(observation->src_after));
    printf("    ");
    print_endpoint(dst);
    printf("  %s => %s\n",
           tcp_state_name(observation->dst_before),
           tcp_state_name(observation->dst_after));
    printf("    sequence  : %s", tcp_seq_status_name(observation->seq_status));
    if (observation->seq_status == TCP_SEQ_RETRANSMISSION
            || observation->seq_status == TCP_SEQ_GAP)
        printf(" (expected %u)", observation->expected_seq);
    printf("\n");
    if (observation->stream_status != TCP_STREAM_OK)
        printf("    stream    : %s\n",
               tcp_stream_status_name(observation->stream_status));
    else if (observation->stream_emitted > 0) {
        printf("    stream    : emitted %zu byte(s)", observation->stream_emitted);
        if (observation->stream_preview_len > 0) {
            printf("  \"");
            for (size_t i = 0; i < observation->stream_preview_len; i++) {
                uint8_t ch = observation->stream_preview[i];
                putchar(ch >= 32 && ch <= 126 ? ch : '.');
            }
            if (observation->stream_preview_len < observation->stream_emitted)
                printf("...");
            printf("\"");
        }
        printf("\n");
    }
    if (observation->stream_buffered > 0)
        printf("    buffered  : %zu byte(s) waiting for a gap\n",
               observation->stream_buffered);
    if (observation->has_rtt)
        printf("    rtt       : %.3f ms  (TCP timestamp echo)\n",
               (double)observation->rtt_usec / 1000.0);
    tcp_segment_analysis_print(&observation->analysis);
}

/* ── conversation table ──────────────────────────────────────────────────── */

/*
 * Print a byte rate in whichever unit keeps it readable. A capture of a
 * handful of bytes has a real rate that rounds to "0.0 KiB/s", which reads
 * like a bug rather than like a small transfer.
 */
static void print_rate(double bytes_per_second) {
    if (bytes_per_second >= 1048576.0)
        printf("%.1f MiB/s", bytes_per_second / 1048576.0);
    else if (bytes_per_second >= 1024.0)
        printf("%.1f KiB/s", bytes_per_second / 1024.0);
    else
        printf("%.0f B/s", bytes_per_second);
}

static void print_direction_stats(const char* label,
                                  const TcpEndpointAnalysis* analysis) {
    double throughput;

    if (!analysis->seen) {
        printf("      %-8s no segments observed\n", label);
        return;
    }

    printf("      %-8s %llu segment(s), %llu payload byte(s)",
           label,
           (unsigned long long)analysis->segments,
           (unsigned long long)analysis->payload_bytes);
    if (analysis->retrans_bytes > 0)
        printf(", %llu resent",
               (unsigned long long)analysis->retrans_bytes);
    printf("\n");

    throughput = tcp_analysis_throughput_bps(analysis);
    if (throughput > 0.0) {
        printf("               goodput %llu byte(s), ",
               (unsigned long long)tcp_analysis_goodput_bytes(analysis));
        print_rate(throughput);
        printf("\n");
    }

    if (analysis->retrans_fast || analysis->retrans_timeout
            || analysis->retrans_spurious || analysis->retrans_plain) {
        printf("               retrans:");
        if (analysis->retrans_fast)
            printf(" fast=%llu", (unsigned long long)analysis->retrans_fast);
        if (analysis->retrans_timeout)
            printf(" rto=%llu", (unsigned long long)analysis->retrans_timeout);
        if (analysis->retrans_spurious)
            printf(" spurious=%llu",
                   (unsigned long long)analysis->retrans_spurious);
        if (analysis->retrans_plain)
            printf(" unclassified=%llu",
                   (unsigned long long)analysis->retrans_plain);
        printf("\n");
    }

    /* out-of-order belongs here rather than on the retransmission line: the
       whole point of the verdict is that the segment was not a resend. */
    if (analysis->dup_acks || analysis->zero_window_events
            || analysis->window_full_events || analysis->keep_alives
            || analysis->missing_segments || analysis->sack_holes
            || analysis->out_of_order) {
        printf("               events :");
        if (analysis->out_of_order)
            printf(" out-of-order=%llu",
                   (unsigned long long)analysis->out_of_order);
        if (analysis->dup_acks)
            printf(" dup-ack=%llu", (unsigned long long)analysis->dup_acks);
        if (analysis->zero_window_events)
            printf(" zero-window=%llu",
                   (unsigned long long)analysis->zero_window_events);
        if (analysis->window_full_events)
            printf(" window-full=%llu",
                   (unsigned long long)analysis->window_full_events);
        if (analysis->keep_alives)
            printf(" keep-alive=%llu",
                   (unsigned long long)analysis->keep_alives);
        if (analysis->missing_segments)
            printf(" missing=%llu",
                   (unsigned long long)analysis->missing_segments);
        if (analysis->sack_holes)
            printf(" sack-hole=%llu",
                   (unsigned long long)analysis->sack_holes);
        printf("\n");
    }

    if (analysis->rtt_samples > 0)
        printf("               rtt    : min %.3f / srtt %.3f / max %.3f ms"
               "  (%llu sample(s), rto %.3f ms)\n",
               (double)analysis->rtt_min / 1000.0,
               (double)analysis->srtt / 1000.0,
               (double)analysis->rtt_max / 1000.0,
               (unsigned long long)analysis->rtt_samples,
               (double)tcp_analysis_rto_estimate(analysis) / 1000.0);

    printf("               window : max %u byte(s)", analysis->max_window_seen);
    if (analysis->wscale_active)
        printf("  scale 2^%u", analysis->wscale_shift);
    else
        printf("  unscaled");
    if (analysis->mss)
        printf("  mss %u", analysis->mss);
    if (analysis->sack_permitted)
        printf("  sack-permitted");
    printf("\n");
}

void tcp_tracker_print_summary(const TcpTracker* tracker) {
    size_t count = 0;

    printf("\n-- TCP tracker summary --\n");
    for (size_t i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        const TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use)
            continue;
        count++;
        printf("  #%zu ", connection->id);
        print_endpoint(&connection->client);
        printf(" -> ");
        print_endpoint(&connection->server);
        printf("  client=%s server=%s%s\n",
               tcp_state_name(connection->client.state),
               tcp_state_name(connection->server.state),
               connection->inferred ? " (inferred mid-stream)" : "");
        printf("      stream bytes: client=%llu server=%llu\n",
               (unsigned long long)connection->client.stream.delivered_bytes,
               (unsigned long long)connection->server.stream.delivered_bytes);
        print_direction_stats("c->s", &connection->client.analysis);
        print_direction_stats("s->c", &connection->server.analysis);
    }
    printf("  tracked connections: %zu\n", count);
    printf("  expired connections: %zu\n", tracker->expired_connections);
    printf("  evicted connections: %zu\n", tracker->evicted_connections);
}
