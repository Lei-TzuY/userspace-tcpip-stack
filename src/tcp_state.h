#ifndef TCP_STATE_H
#define TCP_STATE_H

/*
 * Passive TCP connection tracker.
 *
 * The current stack reads offline captures, so it cannot actively open sockets
 * or transmit replies yet. This module still models the TCP endpoint state
 * machine from observed segments. A newly observed SYN is treated as an active
 * opener in CLOSED sending to a passive endpoint in LISTEN. If a capture starts
 * after the initial SYN, the tracker creates an inferred connection so stream
 * inspection can continue without pretending the handshake was observed.
 */

#include "tcp.h"
#include "tcp_stream.h"

#define TCP_TRACKER_MAX_CONNECTIONS 64
#define TCP_STREAM_PREVIEW_LEN      32
#define TCP_TRACKER_IDLE_TIMEOUT_USEC (5ULL * 60ULL * 1000000ULL)

typedef enum {
    TCP_STATE_CLOSED = 0,
    TCP_STATE_LISTEN,
    TCP_STATE_SYN_SENT,
    TCP_STATE_SYN_RCVD,
    TCP_STATE_ESTABLISHED,
    TCP_STATE_FIN_WAIT_1,
    TCP_STATE_FIN_WAIT_2,
    TCP_STATE_CLOSE_WAIT,
    TCP_STATE_CLOSING,
    TCP_STATE_LAST_ACK,
    TCP_STATE_TIME_WAIT
} TcpState;

typedef enum {
    TCP_SEQ_UNTRACKED = 0,
    TCP_SEQ_IN_ORDER,
    TCP_SEQ_RETRANSMISSION,
    TCP_SEQ_GAP
} TcpSeqStatus;

typedef struct {
    uint8_t  ip[16];   /* first 4 bytes used for IPv4; all 16 for IPv6 */
    uint8_t  ip_len;   /* 4 = IPv4, 16 = IPv6 */
    uint16_t port;
    TcpState state;
    uint32_t next_seq;
    int      next_seq_valid;
    int      pending_fin_valid;
    uint32_t pending_fin_seq;
    TcpStream stream;
    /* Timestamp option tracking for passive RTT measurement (RFC 7323) */
    uint32_t last_tsval;
    uint64_t last_tsval_usec;
    int      last_tsval_valid;
} TcpEndpoint;

typedef struct {
    int         in_use;
    size_t      id;
    int         syn_ack_seen;
    int         inferred;
    uint64_t    last_seen_usec;
    TcpEndpoint client;
    TcpEndpoint server;
} TcpConnection;

typedef struct {
    TcpConnection connections[TCP_TRACKER_MAX_CONNECTIONS];
    size_t        next_id;
    uint64_t      logical_now_usec;
    size_t        expired_connections;
    size_t        evicted_connections;
} TcpTracker;

typedef struct {
    TcpConnection* connection;
    int            created;
    int            src_is_client;
    TcpState       src_before;
    TcpState       src_after;
    TcpState       dst_before;
    TcpState       dst_after;
    TcpSeqStatus   seq_status;
    uint32_t       expected_seq;
    TcpStreamStatus stream_status;
    size_t          stream_emitted;
    size_t          stream_buffered;
    uint8_t         stream_preview[TCP_STREAM_PREVIEW_LEN];
    size_t          stream_preview_len;
    /* Passive RTT from TCP Timestamp echo (RFC 7323) */
    int      has_rtt;
    uint64_t rtt_usec;
} TcpObservation;

void tcp_tracker_init(TcpTracker* tracker);

/*
 * Advance capture time and discard idle connections. Call this for every
 * captured packet so non-TCP traffic also advances tracker lifecycle.
 */
void tcp_tracker_expire_idle(TcpTracker* tracker, uint64_t now_usec);

/*
 * Observe one parsed TCP segment.
 *
 * Returns 1 when a connection was tracked, 0 for invalid input, and -1 if a
 * connection slot cannot be allocated.
 */
int tcp_tracker_observe(TcpTracker* tracker,
                        const uint8_t* src_ip, const uint8_t* dst_ip,
                        const TcpHeader* segment, TcpObservation* out);

/*
 * Timestamp-aware variant for offline captures. Idle connections expire after
 * TCP_TRACKER_IDLE_TIMEOUT_USEC. If the table remains full, the least recently
 * seen connection is evicted deterministically.
 */
int tcp_tracker_observe_at(TcpTracker* tracker,
                           const uint8_t* src_ip, const uint8_t* dst_ip,
                           const TcpHeader* segment, uint64_t now_usec,
                           TcpObservation* out);

/*
 * IPv6 variant of tcp_tracker_observe_at. src_ip6 and dst_ip6 must point to
 * 16-byte IPv6 addresses. IPv4 and IPv6 connections are tracked in the same
 * table but never collide because ip_len differs.
 */
int tcp_tracker_observe_v6_at(TcpTracker* tracker,
                              const uint8_t* src_ip6, const uint8_t* dst_ip6,
                              const TcpHeader* segment, uint64_t now_usec,
                              TcpObservation* out);

const char* tcp_state_name(TcpState state);
const char* tcp_seq_status_name(TcpSeqStatus status);
void tcp_observation_print(const TcpObservation* observation);
void tcp_tracker_print_summary(const TcpTracker* tracker);

#endif /* TCP_STATE_H */
