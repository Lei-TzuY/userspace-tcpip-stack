/*
 * report.c — machine-readable export of the conversation table
 */

#include "report.h"

/* ── output plumbing ─────────────────────────────────────────────────────── */

/*
 * Open the destination. "-" and NULL both mean stdout, which must not be
 * closed afterwards, so the caller is told whether it owns the stream.
 */
static FILE* open_destination(const char* path, int* owns_stream) {
    if (!path || path[0] == '\0' || (path[0] == '-' && path[1] == '\0')) {
        *owns_stream = 0;
        return stdout;
    }
    *owns_stream = 1;
    return fopen(path, "wb");
}

static int close_destination(FILE* fp, int owns_stream) {
    if (owns_stream)
        return fclose(fp) == 0 ? 0 : -1;
    return fflush(fp) == 0 ? 0 : -1;
}

/*
 * Write a string as a JSON string literal.
 *
 * Only control characters and the two mandatory escapes can occur in what this
 * program produces — addresses, state names, and fixed labels — but escaping is
 * done properly anyway rather than relying on that staying true.
 */
static void write_json_string(FILE* fp, const char* text) {
    const unsigned char* p = (const unsigned char*)text;

    fputc('"', fp);
    for (; *p; p++) {
        switch (*p) {
            case '"':  fputs("\\\"", fp); break;
            case '\\': fputs("\\\\", fp); break;
            case '\b': fputs("\\b", fp);  break;
            case '\f': fputs("\\f", fp);  break;
            case '\n': fputs("\\n", fp);  break;
            case '\r': fputs("\\r", fp);  break;
            case '\t': fputs("\\t", fp);  break;
            default:
                if (*p < 0x20)
                    fprintf(fp, "\\u%04x", *p);
                else
                    fputc((int)*p, fp);
                break;
        }
    }
    fputc('"', fp);
}

/* ── JSON ────────────────────────────────────────────────────────────────── */

static void write_json_direction(FILE* fp, const char* indent,
                                 const TcpEndpoint* endpoint) {
    const TcpEndpointAnalysis* a = &endpoint->analysis;

    fprintf(fp, "%s\"observed\": %s,\n", indent, a->seen ? "true" : "false");
    fprintf(fp, "%s\"segments\": %llu,\n", indent,
            (unsigned long long)a->segments);
    fprintf(fp, "%s\"data_segments\": %llu,\n", indent,
            (unsigned long long)a->data_segments);
    fprintf(fp, "%s\"payload_bytes\": %llu,\n", indent,
            (unsigned long long)a->payload_bytes);
    fprintf(fp, "%s\"retransmitted_bytes\": %llu,\n", indent,
            (unsigned long long)a->retrans_bytes);
    fprintf(fp, "%s\"goodput_bytes\": %llu,\n", indent,
            (unsigned long long)tcp_analysis_goodput_bytes(a));
    fprintf(fp, "%s\"throughput_bytes_per_second\": %.3f,\n", indent,
            tcp_analysis_throughput_bps(a));
    fprintf(fp, "%s\"stream_bytes_delivered\": %llu,\n", indent,
            (unsigned long long)endpoint->stream.delivered_bytes);

    fprintf(fp, "%s\"retransmissions\": {"
                " \"fast\": %llu,"
                " \"timeout\": %llu,"
                " \"spurious\": %llu,"
                " \"unclassified\": %llu },\n",
            indent,
            (unsigned long long)a->retrans_fast,
            (unsigned long long)a->retrans_timeout,
            (unsigned long long)a->retrans_spurious,
            (unsigned long long)a->retrans_plain);

    fprintf(fp, "%s\"events\": {"
                " \"out_of_order\": %llu,"
                " \"duplicate_acks\": %llu,"
                " \"zero_window\": %llu,"
                " \"window_full\": %llu,"
                " \"keep_alive\": %llu,"
                " \"missing_segments\": %llu,"
                " \"sack_holes\": %llu },\n",
            indent,
            (unsigned long long)a->out_of_order,
            (unsigned long long)a->dup_acks,
            (unsigned long long)a->zero_window_events,
            (unsigned long long)a->window_full_events,
            (unsigned long long)a->keep_alives,
            (unsigned long long)a->missing_segments,
            (unsigned long long)a->sack_holes);

    fprintf(fp, "%s\"rtt_usec\": {"
                " \"samples\": %llu,"
                " \"min\": %llu,"
                " \"smoothed\": %llu,"
                " \"max\": %llu,"
                " \"rto_estimate\": %llu },\n",
            indent,
            (unsigned long long)a->rtt_samples,
            (unsigned long long)a->rtt_min,
            (unsigned long long)a->srtt,
            (unsigned long long)a->rtt_max,
            (unsigned long long)tcp_analysis_rto_estimate(a));

    /* window_scale is reported as null when this endpoint's own SYN was never
       captured: the negotiation may well have happened, but the shift it asked
       for is unknown, and emitting 0 would assert that it asked for none. */
    fprintf(fp, "%s\"window\": {"
                " \"max_advertised\": %u,"
                " \"scaling_active\": %s,",
            indent, a->max_window_seen, a->wscale_active ? "true" : "false");
    if (a->wscale_active)
        fprintf(fp, " \"scale_shift\": %u,", a->wscale_shift);
    else
        fprintf(fp, " \"scale_shift\": null,");
    fprintf(fp, " \"mss\": ");
    if (a->mss)
        fprintf(fp, "%u", a->mss);
    else
        fprintf(fp, "null");
    fprintf(fp, ", \"sack_permitted\": %s }\n",
            a->sack_permitted ? "true" : "false");
}

static void write_json_endpoint_identity(FILE* fp, const char* indent,
                                         const TcpEndpoint* endpoint) {
    char address[TCP_ADDRESS_STR_MAX];

    tcp_endpoint_address_str(endpoint, address, sizeof(address));
    fprintf(fp, "%s\"address\": ", indent);
    write_json_string(fp, address);
    fprintf(fp, ",\n%s\"port\": %u,\n", indent, endpoint->port);
    fprintf(fp, "%s\"family\": ", indent);
    write_json_string(fp, endpoint->ip_len == 16 ? "ipv6" : "ipv4");
    fprintf(fp, ",\n%s\"state\": ", indent);
    write_json_string(fp, tcp_state_name(endpoint->state));
    fprintf(fp, ",\n");
}

int report_write_json(const StackContext* ctx, const char* path,
                      size_t packet_count) {
    FILE* fp;
    int owns_stream;
    const TcpTracker* tracker;
    size_t tracked = 0;
    size_t emitted = 0;
    size_t i;

    if (!ctx)
        return -1;

    fp = open_destination(path, &owns_stream);
    if (!fp)
        return -1;

    tracker = &ctx->tcp_tracker;
    for (i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        if (tracker->connections[i].in_use)
            tracked++;
    }

    fprintf(fp, "{\n");
    fprintf(fp, "  \"packets\": %llu,\n", (unsigned long long)packet_count);
    fprintf(fp, "  \"tcp\": {\n");
    fprintf(fp, "    \"tracked_connections\": %llu,\n",
            (unsigned long long)tracked);
    fprintf(fp, "    \"expired_connections\": %llu,\n",
            (unsigned long long)tracker->expired_connections);
    fprintf(fp, "    \"evicted_connections\": %llu,\n",
            (unsigned long long)tracker->evicted_connections);
    fprintf(fp, "    \"connections\": [\n");

    for (i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        const TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use)
            continue;

        fprintf(fp, "%s      {\n", emitted > 0 ? ",\n" : "");
        emitted++;
        fprintf(fp, "        \"id\": %llu,\n",
                (unsigned long long)connection->id);
        fprintf(fp, "        \"inferred_midstream\": %s,\n",
                connection->inferred ? "true" : "false");
        fprintf(fp, "        \"handshake_observed\": %s,\n",
                connection->syn_ack_seen ? "true" : "false");

        fprintf(fp, "        \"client\": {\n");
        write_json_endpoint_identity(fp, "          ", &connection->client);
        write_json_direction(fp, "          ", &connection->client);
        fprintf(fp, "        },\n");

        fprintf(fp, "        \"server\": {\n");
        write_json_endpoint_identity(fp, "          ", &connection->server);
        write_json_direction(fp, "          ", &connection->server);
        fprintf(fp, "        }\n");

        fprintf(fp, "      }");
    }

    fprintf(fp, "%s    ]\n", emitted > 0 ? "\n" : "");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    return close_destination(fp, owns_stream);
}

/* ── CSV ─────────────────────────────────────────────────────────────────── */

static const char* CSV_HEADER =
    "connection_id,direction,inferred_midstream,handshake_observed,"
    "src_address,src_port,src_state,dst_address,dst_port,dst_state,"
    "segments,data_segments,payload_bytes,retransmitted_bytes,goodput_bytes,"
    "throughput_bytes_per_second,stream_bytes_delivered,"
    "retrans_fast,retrans_timeout,retrans_spurious,retrans_unclassified,"
    "out_of_order,duplicate_acks,zero_window,window_full,keep_alive,"
    "missing_segments,sack_holes,"
    "rtt_samples,rtt_min_usec,rtt_smoothed_usec,rtt_max_usec,rto_estimate_usec,"
    "max_window,scaling_active,scale_shift,mss,sack_permitted\n";

static void write_csv_row(FILE* fp, const TcpConnection* connection,
                          const char* direction,
                          const TcpEndpoint* src, const TcpEndpoint* dst) {
    const TcpEndpointAnalysis* a = &src->analysis;
    char src_address[TCP_ADDRESS_STR_MAX];
    char dst_address[TCP_ADDRESS_STR_MAX];

    tcp_endpoint_address_str(src, src_address, sizeof(src_address));
    tcp_endpoint_address_str(dst, dst_address, sizeof(dst_address));

    /* Every field is a number, a fixed label, or an address, so none of them
       can contain a comma or a quote; plain concatenation is safe here. */
    fprintf(fp, "%llu,%s,%d,%d,", (unsigned long long)connection->id, direction,
            connection->inferred ? 1 : 0, connection->syn_ack_seen ? 1 : 0);
    fprintf(fp, "%s,%u,%s,%s,%u,%s,",
            src_address, src->port, tcp_state_name(src->state),
            dst_address, dst->port, tcp_state_name(dst->state));
    fprintf(fp, "%llu,%llu,%llu,%llu,%llu,%.3f,%llu,",
            (unsigned long long)a->segments,
            (unsigned long long)a->data_segments,
            (unsigned long long)a->payload_bytes,
            (unsigned long long)a->retrans_bytes,
            (unsigned long long)tcp_analysis_goodput_bytes(a),
            tcp_analysis_throughput_bps(a),
            (unsigned long long)src->stream.delivered_bytes);
    fprintf(fp, "%llu,%llu,%llu,%llu,",
            (unsigned long long)a->retrans_fast,
            (unsigned long long)a->retrans_timeout,
            (unsigned long long)a->retrans_spurious,
            (unsigned long long)a->retrans_plain);
    fprintf(fp, "%llu,%llu,%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)a->out_of_order,
            (unsigned long long)a->dup_acks,
            (unsigned long long)a->zero_window_events,
            (unsigned long long)a->window_full_events,
            (unsigned long long)a->keep_alives,
            (unsigned long long)a->missing_segments,
            (unsigned long long)a->sack_holes);
    fprintf(fp, "%llu,%llu,%llu,%llu,%llu,",
            (unsigned long long)a->rtt_samples,
            (unsigned long long)a->rtt_min,
            (unsigned long long)a->srtt,
            (unsigned long long)a->rtt_max,
            (unsigned long long)tcp_analysis_rto_estimate(a));

    /* An unknown scale shift is left empty rather than written as 0, which
       would claim the endpoint asked for no scaling. */
    fprintf(fp, "%u,%d,", a->max_window_seen, a->wscale_active ? 1 : 0);
    if (a->wscale_active)
        fprintf(fp, "%u,", a->wscale_shift);
    else
        fprintf(fp, ",");
    if (a->mss)
        fprintf(fp, "%u,", a->mss);
    else
        fprintf(fp, ",");
    fprintf(fp, "%d\n", a->sack_permitted ? 1 : 0);
}

int report_write_csv(const StackContext* ctx, const char* path,
                     size_t packet_count) {
    FILE* fp;
    int owns_stream;
    const TcpTracker* tracker;
    size_t i;

    UNUSED(packet_count);

    if (!ctx)
        return -1;

    fp = open_destination(path, &owns_stream);
    if (!fp)
        return -1;

    fputs(CSV_HEADER, fp);

    tracker = &ctx->tcp_tracker;
    for (i = 0; i < TCP_TRACKER_MAX_CONNECTIONS; i++) {
        const TcpConnection* connection = &tracker->connections[i];
        if (!connection->in_use)
            continue;
        write_csv_row(fp, connection, "c->s",
                      &connection->client, &connection->server);
        write_csv_row(fp, connection, "s->c",
                      &connection->server, &connection->client);
    }

    return close_destination(fp, owns_stream);
}
