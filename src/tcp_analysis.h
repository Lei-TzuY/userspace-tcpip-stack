#ifndef TCP_ANALYSIS_H
#define TCP_ANALYSIS_H

/*
 * tcp_analysis.h — expert analysis of an observed TCP conversation
 *
 * tcp_state.c decides *where* a segment sits in sequence space. This module
 * decides what that placement means: whether a segment below the expected
 * sequence number is a retransmission or merely reordering, what triggered the
 * retransmission, whether a sender is blocked on the receiver's window, and
 * what a SACK block implies about which bytes went missing.
 *
 * Everything here is inferred from one direction of capture, which sets a hard
 * limit on how much can be known. A capture taken at the sender sees loss that
 * a capture at the receiver cannot, and vice versa. Where a verdict rests on a
 * timing threshold rather than on something the protocol states outright, the
 * comment at the decision says so.
 *
 * Sequence-space arithmetic is done with the wraparound-safe comparison
 * described in RFC 1982: subtract, then read the result as signed.
 *
 * References:
 *   RFC 5681  congestion control, duplicate-ACK semantics
 *   RFC 6298  retransmission timer, SRTT and RTTVAR
 *   RFC 2018  SACK
 *   RFC 7323  window scale and timestamps
 */

#include "tcp.h"

#define TCP_SACK_MAX_BLOCKS   4   /* what fits in the 40-byte option space */
#define TCP_ANALYSIS_MAX_HOLES 4

/*
 * Where a segment landed relative to the sequence number the tracker expected.
 * This is the raw observation; deciding what it means is this module's job, so
 * the caller passes the placement rather than its own interpretation of it.
 */
typedef enum {
    TCP_ARRIVAL_FIRST = 0,        /* nothing tracked for this endpoint yet */
    TCP_ARRIVAL_IN_ORDER,         /* exactly the expected sequence number */
    TCP_ARRIVAL_BELOW_EXPECTED,   /* data at or before the expected point */
    TCP_ARRIVAL_ABOVE_EXPECTED    /* data beyond it: something is missing */
} TcpArrival;

typedef enum {
    TCP_RETRANS_NONE = 0,
    TCP_RETRANS_PLAIN,      /* a retransmission with no distinguishing signal */
    TCP_RETRANS_FAST,       /* the peer had sent three or more duplicate ACKs */
    TCP_RETRANS_TIMEOUT,    /* sent after a silence long enough to be an RTO */
    TCP_RETRANS_SPURIOUS    /* data the peer had already acknowledged */
} TcpRetransKind;

/* Per-segment findings, reported as a bitmask. */
#define TCP_FINDING_DUP_ACK            0x00000001u
#define TCP_FINDING_OUT_OF_ORDER       0x00000002u
#define TCP_FINDING_ZERO_WINDOW        0x00000004u
#define TCP_FINDING_ZERO_WINDOW_PROBE  0x00000008u
#define TCP_FINDING_WINDOW_FULL        0x00000010u
#define TCP_FINDING_WINDOW_UPDATE      0x00000020u
#define TCP_FINDING_KEEP_ALIVE         0x00000040u
#define TCP_FINDING_KEEP_ALIVE_ACK     0x00000080u
#define TCP_FINDING_ACK_UNSEEN_SEGMENT 0x00000100u
#define TCP_FINDING_SACK_HOLE          0x00000200u
#define TCP_FINDING_PREVIOUS_MISSING   0x00000400u
#define TCP_FINDING_RESET              0x00000800u

/*
 * A retransmission is called an RTO when the sender had been silent for longer
 * than a plausible retransmission timeout. RFC 6298 puts the floor for a real
 * stack at one second, but stacks in the field routinely use 200 ms, so that
 * is the floor used here: preferring the smaller value labels a borderline
 * case RTO rather than leaving it unexplained.
 */
#define TCP_RTO_FLOOR_USEC   200000ULL

/*
 * Reordering shows up two ways, and both are recognised by timing.
 *
 * The direct one is a gap followed almost immediately by the data that fills
 * it: the segments took different paths and arrived swapped. Nothing was lost,
 * so the gap that was reported a moment earlier gets withdrawn.
 *
 * The other is a segment below the expected point arriving right behind the
 * sender's previous data with no duplicate ACK to have prompted a resend. No
 * sender reacts that fast, so a retransmission is the less likely explanation.
 *
 * Either way the window is what separates reordering from a real resend.
 */
#define TCP_REORDER_WINDOW_USEC 3000ULL

/* Duplicate ACKs needed before a retransmission is attributed to fast retransmit. */
#define TCP_FAST_RETRANSMIT_DUP_ACKS 3

/*
 * Analysis state for one direction of one connection.
 *
 * Fields are named from the point of view of the endpoint that owns them: the
 * window this endpoint advertises, the ACKs it sends, the data it sends. What
 * the peer does lives in the peer's own instance.
 */
typedef struct {
    /* Options offered in this endpoint's SYN (RFC 7323, RFC 2018). */
    int      wscale_offered;
    uint8_t  wscale_shift;
    int      wscale_active;     /* both directions offered it, so it is in use */
    int      sack_permitted;
    uint16_t mss;

    /*
     * Set when the peer's SYN-ACK carried the window-scale option. A server
     * only echoes that option if the client's SYN offered it (RFC 7323 §2.2),
     * so this endpoint must have offered it even though its SYN was not
     * captured. That is enough to enable scaling for the peer's windows, but
     * not for this endpoint's own: the shift it asked for is unknown, and
     * guessing one would silently misreport every window it advertises.
     */
    int      wscale_offer_inferred;

    /* Data this endpoint has sent. */
    uint32_t highest_seq_sent;  /* one past the highest sequence number sent */
    int      highest_seq_valid;
    uint64_t payload_bytes;     /* every payload byte, retransmissions included */
    uint64_t retrans_bytes;
    uint64_t segments;
    uint64_t data_segments;

    /* ACKs this endpoint has sent, which describe the peer's data. */
    uint32_t last_ack;
    int      last_ack_valid;
    uint32_t highest_ack;
    int      highest_ack_valid;
    uint32_t last_ack_window;   /* scaled, for telling a dup ACK from an update */
    unsigned dup_ack_run;       /* consecutive duplicate ACKs just sent */

    /* The receive window this endpoint advertises. */
    uint32_t window_scaled;
    int      window_valid;
    int      zero_window;       /* currently advertising zero */
    uint32_t max_window_seen;

    /* Round-trip time, microseconds (RFC 6298 smoothing). */
    uint64_t rtt_min;
    uint64_t rtt_max;
    uint64_t srtt;
    uint64_t rttvar;
    uint64_t rtt_samples;

    /* Timing. */
    uint64_t first_seen_usec;
    uint64_t last_seen_usec;
    uint64_t last_data_usec;    /* when this endpoint last sent payload */
    int      seen;

    /* Set when the last segment sent was a keep-alive, so the peer's next bare
       ACK can be recognised as the keep-alive response. */
    int      last_was_keep_alive;

    /* When a segment arrived beyond the expected point, leaving a gap that has
       not yet been filled. If the missing data turns up almost immediately the
       gap was reordering rather than loss. */
    int      gap_outstanding;
    uint64_t gap_seen_usec;

    /* Totals for the summary. */
    uint64_t retrans_fast;
    uint64_t retrans_timeout;
    uint64_t retrans_spurious;
    uint64_t retrans_plain;
    uint64_t out_of_order;
    uint64_t dup_acks;
    /*
     * Counted once per entry into the zero-window condition, not once per
     * advertisement: a receiver repeating "still full" is the same stall, and
     * counting each repeat would make one stall look like many.
     */
    uint64_t zero_window_events;
    /*
     * Counted once per segment that filled the peer's window, so a sender held
     * at the limit for a long stretch registers repeatedly. That is the useful
     * reading — it measures how often the window was the binding constraint,
     * not how many distinct times it filled.
     */
    uint64_t window_full_events;
    uint64_t keep_alives;
    /*
     * Gaps that still look like genuinely absent data. A gap filled by a
     * reordered segment moments later is withdrawn from this count, so it
     * reports what appears lost rather than every gap ever seen.
     */
    uint64_t missing_segments;
    /*
     * Holes reported by SACK blocks, summed over every ACK that carried them.
     * A receiver repeating the same SACK while it waits contributes each time,
     * so this counts hole reports rather than distinct lost ranges.
     */
    uint64_t sack_holes;
} TcpEndpointAnalysis;

/* What this one segment showed. */
typedef struct {
    unsigned       findings;    /* TCP_FINDING_* bitmask */
    TcpRetransKind retrans;
    unsigned       dup_ack_run;

    uint32_t window_scaled;
    int      window_was_scaled; /* a scale factor was actually applied */

    uint32_t bytes_in_flight;
    int      bytes_in_flight_valid;

    /* SACK blocks carried by this segment, and the holes they imply. */
    int      sack_block_count;
    uint32_t sack_left[TCP_SACK_MAX_BLOCKS];
    uint32_t sack_right[TCP_SACK_MAX_BLOCKS];
    uint32_t sacked_bytes;
    int      hole_count;
    uint32_t hole_left[TCP_ANALYSIS_MAX_HOLES];
    uint32_t hole_right[TCP_ANALYSIS_MAX_HOLES];
    uint32_t hole_bytes;
} TcpSegmentAnalysis;

void tcp_analysis_init(TcpEndpointAnalysis* analysis);

/*
 * Record the options carried by a SYN or SYN-ACK. Call this for handshake
 * segments before tcp_analysis_observe().
 */
void tcp_analysis_note_syn_options(TcpEndpointAnalysis* analysis,
                                   const TcpHeader* segment);

/*
 * Window scaling takes effect only if both directions offered it (RFC 7323
 * §2.2). Call this once the SYN-ACK has been seen, with both endpoints.
 */
void tcp_analysis_settle_options(TcpEndpointAnalysis* a, TcpEndpointAnalysis* b);

/*
 * Analyse one segment.
 *
 *   src      analysis state of the endpoint that sent this segment
 *   dst      analysis state of its peer
 *   arrival  where the segment landed relative to the expected sequence number
 *   out      zeroed and filled in with what this segment showed
 *
 * Both endpoint states are updated. Call once per segment, in capture order.
 */
void tcp_analysis_observe(TcpEndpointAnalysis* src, TcpEndpointAnalysis* dst,
                          const TcpHeader* segment, TcpArrival arrival,
                          uint64_t now_usec, TcpSegmentAnalysis* out);

/*
 * Fold a round-trip sample into this endpoint's statistics, using the
 * smoothing from RFC 6298 §2. Samples come from the timestamp option echo, so
 * an endpoint that does not use timestamps will have none.
 */
void tcp_analysis_add_rtt_sample(TcpEndpointAnalysis* analysis,
                                 uint64_t rtt_usec);

/*
 * The retransmission timeout implied by the current RTT estimate:
 * SRTT + 4·RTTVAR, floored at TCP_RTO_FLOOR_USEC. With no samples yet, the
 * floor is returned.
 */
uint64_t tcp_analysis_rto_estimate(const TcpEndpointAnalysis* analysis);

/* Throughput of this endpoint's payload, bytes per second. 0 if unknown. */
double tcp_analysis_throughput_bps(const TcpEndpointAnalysis* analysis);

/* Payload bytes excluding retransmissions, i.e. bytes that carried progress. */
uint64_t tcp_analysis_goodput_bytes(const TcpEndpointAnalysis* analysis);

const char* tcp_retrans_kind_name(TcpRetransKind kind);

/*
 * Append the names of the set findings to buf, comma-separated. Always
 * NUL-terminates. Writes an empty string when nothing was found.
 */
void tcp_findings_str(unsigned findings, char* buf, size_t buf_len);

/* Print the per-segment findings, indented to match the tracker's output. */
void tcp_segment_analysis_print(const TcpSegmentAnalysis* analysis);

#endif /* TCP_ANALYSIS_H */
