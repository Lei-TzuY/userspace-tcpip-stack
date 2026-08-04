/*
 * tcp_analysis.c — expert analysis of an observed TCP conversation
 *
 * See tcp_analysis.h for what each finding means and where the timing
 * thresholds come from.
 */

#include "tcp_analysis.h"

/* ── sequence-space helpers (RFC 1982) ───────────────────────────────────── */

static int seq_at_or_after(uint32_t value, uint32_t reference) {
    return (int32_t)(value - reference) >= 0;
}

static int seq_after(uint32_t value, uint32_t reference) {
    return (int32_t)(value - reference) > 0;
}

/* Distance from earlier to later, or 0 if they are out of order. */
static uint32_t seq_distance(uint32_t later, uint32_t earlier) {
    int32_t delta = (int32_t)(later - earlier);
    return delta > 0 ? (uint32_t)delta : 0u;
}

static uint32_t read32(const uint8_t* data) {
    return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] <<  8)
         |  (uint32_t)data[3];
}

/* ── option extraction ───────────────────────────────────────────────────── */

static const TcpOption* find_option(const TcpHeader* segment, uint8_t kind) {
    for (int i = 0; i < segment->opt_count; i++) {
        if (segment->options[i].kind == kind)
            return &segment->options[i];
    }
    return NULL;
}

void tcp_analysis_init(TcpEndpointAnalysis* analysis) {
    memset(analysis, 0, sizeof(*analysis));
}

void tcp_analysis_note_syn_options(TcpEndpointAnalysis* analysis,
                                   const TcpHeader* segment) {
    const TcpOption* opt;

    if (!analysis || !segment || !(segment->flags & TCP_SYN))
        return;

    opt = find_option(segment, TCP_OPT_WSCALE);
    if (opt && opt->data_len >= 1) {
        analysis->wscale_offered = 1;
        /* RFC 7323 §2.3 caps the shift at 14; a larger value is a bug at the
           sender, and honouring it would let a 16-bit field claim gigabytes. */
        analysis->wscale_shift = opt->data[0] > 14 ? 14u : opt->data[0];
    }

    if (find_option(segment, TCP_OPT_SACKP))
        analysis->sack_permitted = 1;

    opt = find_option(segment, TCP_OPT_MSS);
    if (opt && opt->data_len >= 2)
        analysis->mss = (uint16_t)((opt->data[0] << 8) | opt->data[1]);
}

void tcp_analysis_settle_options(TcpEndpointAnalysis* a, TcpEndpointAnalysis* b) {
    int a_offers;
    int b_offers;

    if (!a || !b)
        return;

    /* RFC 7323 §2.2: scaling is used only if both sides sent the option. One
       side offering it alone changes nothing, and applying a shift anyway
       would misreport every window by a factor of 2^shift — which looks
       exactly like a receiver with a very large buffer.
     *
     * The two conditions are deliberately not symmetric. Whether scaling is
     * negotiated at all depends on both sides offering, which may be inferred.
     * Whether *this* endpoint's window can be scaled additionally requires its
     * own shift, which only its own SYN carries. */
    a_offers = a->wscale_offered || a->wscale_offer_inferred;
    b_offers = b->wscale_offered || b->wscale_offer_inferred;

    a->wscale_active = a->wscale_offered && b_offers;
    b->wscale_active = b->wscale_offered && a_offers;
}

/* ── RTT statistics ──────────────────────────────────────────────────────── */

void tcp_analysis_add_rtt_sample(TcpEndpointAnalysis* analysis,
                                 uint64_t rtt_usec) {
    if (!analysis)
        return;

    if (analysis->rtt_samples == 0) {
        /* RFC 6298 §2.2: the first sample seeds SRTT directly and RTTVAR at
           half the sample. */
        analysis->srtt   = rtt_usec;
        analysis->rttvar = rtt_usec / 2u;
        analysis->rtt_min = rtt_usec;
        analysis->rtt_max = rtt_usec;
    } else {
        /* RFC 6298 §2.3 with alpha = 1/8 and beta = 1/4, in integer
           arithmetic: RTTVAR is updated before SRTT because it depends on the
           previous SRTT. */
        uint64_t srtt = analysis->srtt;
        uint64_t delta = rtt_usec > srtt ? rtt_usec - srtt : srtt - rtt_usec;

        analysis->rttvar = (analysis->rttvar * 3u + delta) / 4u;
        analysis->srtt   = (srtt * 7u + rtt_usec) / 8u;

        if (rtt_usec < analysis->rtt_min) analysis->rtt_min = rtt_usec;
        if (rtt_usec > analysis->rtt_max) analysis->rtt_max = rtt_usec;
    }
    analysis->rtt_samples++;
}

uint64_t tcp_analysis_rto_estimate(const TcpEndpointAnalysis* analysis) {
    uint64_t rto;

    if (!analysis || analysis->rtt_samples == 0)
        return TCP_RTO_FLOOR_USEC;

    rto = analysis->srtt + 4u * analysis->rttvar;
    return rto < TCP_RTO_FLOOR_USEC ? TCP_RTO_FLOOR_USEC : rto;
}

double tcp_analysis_throughput_bps(const TcpEndpointAnalysis* analysis) {
    uint64_t span;

    if (!analysis || !analysis->seen || analysis->payload_bytes == 0)
        return 0.0;

    span = analysis->last_seen_usec > analysis->first_seen_usec
         ? analysis->last_seen_usec - analysis->first_seen_usec
         : 0u;
    if (span == 0)
        return 0.0;

    return (double)analysis->payload_bytes * 1000000.0 / (double)span;
}

uint64_t tcp_analysis_goodput_bytes(const TcpEndpointAnalysis* analysis) {
    if (!analysis)
        return 0;
    return analysis->payload_bytes > analysis->retrans_bytes
         ? analysis->payload_bytes - analysis->retrans_bytes
         : 0u;
}

/* ── SACK ────────────────────────────────────────────────────────────────── */

/*
 * Pull the SACK blocks out of the segment and work out which ranges they
 * imply are missing.
 *
 * A SACK block names bytes the receiver already holds. The cumulative ACK
 * names the last byte it holds contiguously. So the gap between the ACK and
 * the first block, and every gap between consecutive blocks, is data the
 * receiver has not got — which is as close to a direct statement of what was
 * lost as TCP ever gives.
 */
static void analyse_sack(const TcpHeader* segment, uint32_t ack_num,
                         TcpSegmentAnalysis* out) {
    const TcpOption* opt = find_option(segment, TCP_OPT_SACK);
    int blocks;
    int i;
    uint32_t hole_from;

    if (!opt)
        return;

    blocks = opt->data_len / 8;
    if (blocks > TCP_SACK_MAX_BLOCKS)
        blocks = TCP_SACK_MAX_BLOCKS;

    for (i = 0; i < blocks; i++) {
        uint32_t left  = read32(opt->data + (i * 8));
        uint32_t right = read32(opt->data + (i * 8) + 4);

        /* A block whose edges are reversed is malformed; skip it rather than
           letting it contribute a nonsense byte count. */
        if (!seq_after(right, left))
            continue;

        out->sack_left[out->sack_block_count]  = left;
        out->sack_right[out->sack_block_count] = right;
        out->sack_block_count++;
        out->sacked_bytes += seq_distance(right, left);
    }

    /* Blocks after the first are not required to be in order (RFC 2018 §4),
       but the hole walk below only makes sense on sorted edges. With at most
       four blocks an insertion sort is the clearest thing to write. */
    for (i = 1; i < out->sack_block_count; i++) {
        uint32_t left = out->sack_left[i];
        uint32_t right = out->sack_right[i];
        int j = i - 1;
        while (j >= 0 && seq_after(out->sack_left[j], left)) {
            out->sack_left[j + 1]  = out->sack_left[j];
            out->sack_right[j + 1] = out->sack_right[j];
            j--;
        }
        out->sack_left[j + 1]  = left;
        out->sack_right[j + 1] = right;
    }

    hole_from = ack_num;
    for (i = 0; i < out->sack_block_count && out->hole_count < TCP_ANALYSIS_MAX_HOLES; i++) {
        if (seq_after(out->sack_left[i], hole_from)) {
            out->hole_left[out->hole_count]  = hole_from;
            out->hole_right[out->hole_count] = out->sack_left[i];
            out->hole_bytes += seq_distance(out->sack_left[i], hole_from);
            out->hole_count++;
        }
        if (seq_at_or_after(out->sack_right[i], hole_from))
            hole_from = out->sack_right[i];
    }

    if (out->hole_count > 0)
        out->findings |= TCP_FINDING_SACK_HOLE;
}

/* ── the per-segment walk ────────────────────────────────────────────────── */

/*
 * How many sequence numbers this segment consumes. SYN and FIN each occupy one
 * beyond the payload (RFC 793 §3.3), which is why a bare SYN still advances the
 * sequence space.
 */
static uint32_t sequence_span(const TcpHeader* segment) {
    uint32_t span = (uint32_t)segment->payload_len;
    if (segment->flags & TCP_SYN) span++;
    if (segment->flags & TCP_FIN) span++;
    return span;
}

/*
 * Scale the advertised window.
 *
 * The window in a SYN is never scaled: the option that announces the shift is
 * carried by the same segment, so there is no agreed factor yet (RFC 7323
 * §2.2). Applying the shift to a SYN is a classic off-by-one-segment error
 * that inflates the initial window by up to 2^14.
 */
static uint32_t scaled_window(const TcpEndpointAnalysis* src,
                              const TcpHeader* segment, int* was_scaled) {
    *was_scaled = 0;
    if ((segment->flags & TCP_SYN) || !src->wscale_active)
        return segment->window;
    if (src->wscale_shift == 0)
        return segment->window;
    *was_scaled = 1;
    return (uint32_t)segment->window << src->wscale_shift;
}

/*
 * Decide whether a bare ACK repeats the previous one.
 *
 * A duplicate ACK carries no data, acknowledges nothing new, and advertises
 * the same window. If the window changed, the segment is a window update: it
 * conveys new information even though the ACK number did not move, and
 * counting it as a duplicate would inflate the fast-retransmit signal.
 */
static int is_duplicate_ack(const TcpEndpointAnalysis* src,
                            const TcpEndpointAnalysis* dst,
                            const TcpHeader* segment, uint32_t window) {
    if (!(segment->flags & TCP_ACK))
        return 0;
    if (segment->payload_len > 0)
        return 0;
    if (segment->flags & (TCP_SYN | TCP_FIN | TCP_RST))
        return 0;
    if (!src->last_ack_valid || segment->ack_num != src->last_ack)
        return 0;
    if (window != src->last_ack_window)
        return 0;
    /* A repeated ACK only signals loss while the peer still has data
       outstanding. Once everything is acknowledged, a repeat is just a
       keep-alive or a window probe response. */
    return dst->highest_seq_valid && seq_after(dst->highest_seq_sent,
                                               segment->ack_num);
}

/*
 * Keep-alives are recognised by shape: a segment carrying nothing, or one
 * garbage byte, positioned one below the next byte the sender owes
 * (RFC 1122 §4.2.3.6).
 */
static int is_keep_alive(const TcpEndpointAnalysis* src,
                         const TcpHeader* segment) {
    if (!(segment->flags & TCP_ACK))
        return 0;
    if (segment->flags & (TCP_SYN | TCP_FIN | TCP_RST))
        return 0;
    if (segment->payload_len > 1)
        return 0;
    if (!src->highest_seq_valid)
        return 0;
    return segment->seq_num == src->highest_seq_sent - 1u;
}

/*
 * Attribute a retransmission to a cause.
 *
 * Order matters. Spurious is checked first because it is the one verdict that
 * rests on something the peer stated outright — it already acknowledged these
 * bytes — rather than on a timing threshold. Fast retransmit comes next
 * because three duplicate ACKs are a protocol-defined trigger (RFC 5681 §3.2).
 * Only then does the RTO guess apply.
 */
static TcpRetransKind classify_retransmission(const TcpEndpointAnalysis* src,
                                              const TcpEndpointAnalysis* dst,
                                              const TcpHeader* segment,
                                              uint64_t now_usec) {
    uint32_t span_end = segment->seq_num + sequence_span(segment);

    if (dst->highest_ack_valid && seq_at_or_after(dst->highest_ack, span_end))
        return TCP_RETRANS_SPURIOUS;

    if (dst->dup_ack_run >= TCP_FAST_RETRANSMIT_DUP_ACKS)
        return TCP_RETRANS_FAST;

    /* Time since this sender last put data on the wire. That is not the same
       as the age of the segment being resent — tracking that would need a
       send time per sequence range — so a sender that keeps transmitting new
       data while resending old data will not show up as RTO here. */
    if (src->last_data_usec != 0 && now_usec > src->last_data_usec
            && now_usec - src->last_data_usec >= tcp_analysis_rto_estimate(src))
        return TCP_RETRANS_TIMEOUT;

    return TCP_RETRANS_PLAIN;
}

/*
 * Reordering and retransmission are indistinguishable in sequence space: both
 * put data below the expected point. The separation is timing. A segment that
 * follows the sender's previous data almost immediately, with no duplicate ACK
 * to have prompted a resend, is far more likely to have taken a different path
 * than to be a deliberate retransmission — no sender reacts that fast.
 */
static int looks_reordered(const TcpEndpointAnalysis* src,
                           const TcpEndpointAnalysis* dst,
                           uint64_t now_usec) {
    uint64_t elapsed;
    uint64_t threshold = TCP_REORDER_WINDOW_USEC;

    if (dst->dup_ack_run > 0)
        return 0;
    if (src->last_data_usec == 0 || now_usec < src->last_data_usec)
        return 0;

    /* On a fast path the smoothed RTT can be below the fixed window, and
       nothing should be called reordering if a retransmission could plausibly
       have been triggered and delivered in that time. */
    if (src->rtt_samples > 0 && src->srtt < threshold)
        threshold = src->srtt;

    elapsed = now_usec - src->last_data_usec;
    return elapsed < threshold;
}

void tcp_analysis_observe(TcpEndpointAnalysis* src, TcpEndpointAnalysis* dst,
                          const TcpHeader* segment, TcpArrival arrival,
                          uint64_t now_usec, TcpSegmentAnalysis* out) {
    uint32_t window;
    int      window_was_scaled;
    uint32_t span;
    uint32_t span_end;
    int      keep_alive;
    int      dup_ack;

    if (!src || !dst || !segment || !out)
        return;

    memset(out, 0, sizeof(*out));

    /* ── timing ──────────────────────────────────────────────────────────── */
    if (!src->seen) {
        src->seen = 1;
        src->first_seen_usec = now_usec;
    }
    if (now_usec > src->last_seen_usec)
        src->last_seen_usec = now_usec;
    src->segments++;

    /* ── window ──────────────────────────────────────────────────────────── */
    window = scaled_window(src, segment, &window_was_scaled);
    out->window_scaled     = window;
    out->window_was_scaled = window_was_scaled;
    src->window_scaled = window;
    src->window_valid  = 1;
    if (window > src->max_window_seen)
        src->max_window_seen = window;

    if (segment->flags & TCP_RST)
        out->findings |= TCP_FINDING_RESET;

    if (window == 0 && !(segment->flags & (TCP_RST | TCP_FIN | TCP_SYN))) {
        out->findings |= TCP_FINDING_ZERO_WINDOW;
        if (!src->zero_window) {
            src->zero_window = 1;
            src->zero_window_events++;
        }
    } else if (src->zero_window && window > 0) {
        src->zero_window = 0;
        out->findings |= TCP_FINDING_WINDOW_UPDATE;
    }

    /* ── keep-alive and zero-window probe ────────────────────────────────── */
    keep_alive = is_keep_alive(src, segment);
    if (keep_alive) {
        out->findings |= TCP_FINDING_KEEP_ALIVE;
        src->keep_alives++;
    } else if (dst->last_was_keep_alive
               && (segment->flags & TCP_ACK)
               && segment->payload_len == 0
               && !(segment->flags & (TCP_SYN | TCP_FIN | TCP_RST))) {
        out->findings |= TCP_FINDING_KEEP_ALIVE_ACK;
    }

    /* A single byte offered to a peer advertising no room is a probe for a
       window update, not an attempt to make progress (RFC 1122 §4.2.2.17). */
    if (segment->payload_len == 1 && dst->zero_window && !keep_alive)
        out->findings |= TCP_FINDING_ZERO_WINDOW_PROBE;

    /* ── duplicate ACK accounting ────────────────────────────────────────── */
    dup_ack = is_duplicate_ack(src, dst, segment, window);
    if (dup_ack) {
        src->dup_ack_run++;
        src->dup_acks++;
        out->findings   |= TCP_FINDING_DUP_ACK;
        out->dup_ack_run = src->dup_ack_run;
    } else if ((segment->flags & TCP_ACK)
               && (!src->last_ack_valid || segment->ack_num != src->last_ack)) {
        /* The ACK moved, so whatever the peer resent has arrived. */
        src->dup_ack_run = 0;
    }

    if (segment->flags & TCP_ACK) {
        /* An ACK beyond anything the peer was seen to send means the capture
           missed that data — the segment exists, we just never saw it. */
        if (dst->highest_seq_valid
                && seq_after(segment->ack_num, dst->highest_seq_sent))
            out->findings |= TCP_FINDING_ACK_UNSEEN_SEGMENT;

        if (!src->highest_ack_valid
                || seq_after(segment->ack_num, src->highest_ack)) {
            src->highest_ack = segment->ack_num;
            src->highest_ack_valid = 1;
        }
        src->last_ack        = segment->ack_num;
        src->last_ack_valid  = 1;
        src->last_ack_window = window;

        analyse_sack(segment, segment->ack_num, out);
        if (out->hole_count > 0)
            src->sack_holes += (uint64_t)out->hole_count;
    }

    /* ── placement: retransmission, reordering, or a gap ─────────────────── */
    span     = sequence_span(segment);
    span_end = segment->seq_num + span;

    if (arrival == TCP_ARRIVAL_IN_ORDER && src->gap_outstanding) {
        /* The data that was missing has turned up. If it did so immediately,
           the two segments were merely swapped in flight, so the gap reported
           a moment ago is withdrawn — nothing was lost. Arriving later than
           that means it really had to be resent, and the gap stands. */
        if (now_usec >= src->gap_seen_usec
                && now_usec - src->gap_seen_usec < TCP_REORDER_WINDOW_USEC) {
            out->findings |= TCP_FINDING_OUT_OF_ORDER;
            src->out_of_order++;
            if (src->missing_segments > 0)
                src->missing_segments--;
        }
        src->gap_outstanding = 0;
    }

    if (arrival == TCP_ARRIVAL_BELOW_EXPECTED && span > 0) {
        if (looks_reordered(src, dst, now_usec)) {
            out->findings |= TCP_FINDING_OUT_OF_ORDER;
            src->out_of_order++;
        } else {
            out->retrans = classify_retransmission(src, dst, segment, now_usec);
            src->retrans_bytes += segment->payload_len;
            switch (out->retrans) {
                case TCP_RETRANS_FAST:     src->retrans_fast++;     break;
                case TCP_RETRANS_TIMEOUT:  src->retrans_timeout++;  break;
                case TCP_RETRANS_SPURIOUS: src->retrans_spurious++; break;
                default:                   src->retrans_plain++;    break;
            }
        }
    } else if (arrival == TCP_ARRIVAL_ABOVE_EXPECTED) {
        /* Data beyond the expected point. Whatever fills the gap was lost,
           never captured, or is simply still in flight behind this segment —
           which is why the count is revisited if it shows up immediately. */
        out->findings |= TCP_FINDING_PREVIOUS_MISSING;
        src->missing_segments++;
        src->gap_outstanding = 1;
        src->gap_seen_usec   = now_usec;
    }

    /* ── send-side accounting ────────────────────────────────────────────── */
    if (segment->payload_len > 0) {
        src->payload_bytes += segment->payload_len;
        src->data_segments++;
        src->last_data_usec = now_usec;
    }

    if (!src->highest_seq_valid || seq_after(span_end, src->highest_seq_sent)) {
        src->highest_seq_sent  = span_end;
        src->highest_seq_valid = 1;
    }

    /* ── bytes in flight and window pressure ─────────────────────────────── */
    if (src->highest_seq_valid && dst->highest_ack_valid) {
        out->bytes_in_flight = seq_distance(src->highest_seq_sent,
                                            dst->highest_ack);
        out->bytes_in_flight_valid = 1;

        /* The sender has used up everything the receiver offered, so the next
           segment cannot leave until the window opens. This is a property of
           the receiver's advertised window, so it is read from dst. */
        if (dst->window_valid && dst->window_scaled > 0
                && out->bytes_in_flight >= dst->window_scaled) {
            out->findings |= TCP_FINDING_WINDOW_FULL;
            src->window_full_events++;
        }
    }

    src->last_was_keep_alive = keep_alive;
}

/* ── naming and printing ─────────────────────────────────────────────────── */

const char* tcp_retrans_kind_name(TcpRetransKind kind) {
    switch (kind) {
        case TCP_RETRANS_NONE:     return "none";
        case TCP_RETRANS_PLAIN:    return "retransmission";
        case TCP_RETRANS_FAST:     return "fast retransmission";
        case TCP_RETRANS_TIMEOUT:  return "RTO retransmission";
        case TCP_RETRANS_SPURIOUS: return "spurious retransmission";
        default:                   return "unknown";
    }
}

void tcp_findings_str(unsigned findings, char* buf, size_t buf_len) {
    static const struct { unsigned bit; const char* name; } names[] = {
        { TCP_FINDING_DUP_ACK,            "duplicate ACK" },
        { TCP_FINDING_OUT_OF_ORDER,       "out-of-order" },
        { TCP_FINDING_ZERO_WINDOW,        "zero window" },
        { TCP_FINDING_ZERO_WINDOW_PROBE,  "zero-window probe" },
        { TCP_FINDING_WINDOW_FULL,        "window full" },
        { TCP_FINDING_WINDOW_UPDATE,      "window update" },
        { TCP_FINDING_KEEP_ALIVE,         "keep-alive" },
        { TCP_FINDING_KEEP_ALIVE_ACK,     "keep-alive ACK" },
        { TCP_FINDING_ACK_UNSEEN_SEGMENT, "ACK for unseen segment" },
        { TCP_FINDING_SACK_HOLE,          "SACK hole" },
        { TCP_FINDING_PREVIOUS_MISSING,   "previous segment missing" },
        { TCP_FINDING_RESET,              "reset" }
    };
    size_t used = 0;
    size_t i;

    if (!buf || buf_len == 0)
        return;
    buf[0] = '\0';

    for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        size_t need;
        if (!(findings & names[i].bit))
            continue;

        need = strlen(names[i].name) + (used > 0 ? 2u : 0u);
        if (used + need + 1u > buf_len)
            break;

        if (used > 0) {
            buf[used++] = ',';
            buf[used++] = ' ';
        }
        memcpy(buf + used, names[i].name, strlen(names[i].name));
        used += strlen(names[i].name);
        buf[used] = '\0';
    }
}

void tcp_segment_analysis_print(const TcpSegmentAnalysis* analysis) {
    char findings[256];
    int i;

    if (!analysis)
        return;

    if (analysis->retrans != TCP_RETRANS_NONE)
        printf("    analysis  : %s\n",
               tcp_retrans_kind_name(analysis->retrans));

    tcp_findings_str(analysis->findings, findings, sizeof(findings));
    if (findings[0] != '\0') {
        printf("    findings  : %s", findings);
        if (analysis->findings & TCP_FINDING_DUP_ACK)
            printf(" (#%u)", analysis->dup_ack_run);
        printf("\n");
    }

    if (analysis->window_was_scaled)
        printf("    window    : %u bytes (scaled)\n", analysis->window_scaled);

    if (analysis->bytes_in_flight_valid && analysis->bytes_in_flight > 0)
        printf("    in flight : %u byte(s)\n", analysis->bytes_in_flight);

    if (analysis->sack_block_count > 0) {
        printf("    sack      : %d block(s), %u byte(s) held",
               analysis->sack_block_count, analysis->sacked_bytes);
        for (i = 0; i < analysis->sack_block_count; i++)
            printf("  [%u,%u)", analysis->sack_left[i], analysis->sack_right[i]);
        printf("\n");
    }

    if (analysis->hole_count > 0) {
        printf("    lost      : %u byte(s) in %d hole(s) inferred from SACK",
               analysis->hole_bytes, analysis->hole_count);
        for (i = 0; i < analysis->hole_count; i++)
            printf("  [%u,%u)", analysis->hole_left[i], analysis->hole_right[i]);
        printf("\n");
    }
}
