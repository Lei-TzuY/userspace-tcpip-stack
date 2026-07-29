#ifndef UDP_TRACKER_H
#define UDP_TRACKER_H

/*
 * udp_tracker.h — UDP flow table with DNS RTT measurement
 *
 * Tracks UDP flows keyed by (src_ip, src_port, dst_ip, dst_port) and
 * measures DNS query-response RTT by matching transaction IDs.
 *
 * DNS RTT: when a query (QR=0) is seen, store (xid, timestamp).
 * When the matching response (QR=1, same xid, swapped addresses) arrives,
 * compute rtt = response_time - query_time.
 */

#include "common.h"

#define UDP_TRACKER_MAX_FLOWS   64
#define UDP_TRACKER_DNS_SLOTS   32   /* pending query slots */
#define UDP_TRACKER_IDLE_USEC   (30 * 1000000ull)  /* 30 s idle timeout */

typedef struct {
    uint8_t  src_ip[16];
    uint8_t  dst_ip[16];
    uint8_t  ip_len;         /* 4 for IPv4, 16 for IPv6 */
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t first_seen_usec;
    uint64_t last_seen_usec;
    uint64_t packet_count;
    int      active;
} UdpFlow;

typedef struct {
    uint16_t xid;
    uint64_t query_usec;
    uint8_t  client_ip[16];
    uint8_t  server_ip[16];
    uint8_t  ip_len;
    uint16_t client_port;
    int      active;
} DnsQuerySlot;

typedef struct {
    UdpFlow     flows[UDP_TRACKER_MAX_FLOWS];
    int         flow_count;
    DnsQuerySlot dns_pending[UDP_TRACKER_DNS_SLOTS];
    uint64_t    total_flows;
    uint64_t    dns_queries;
    uint64_t    dns_responses;
    uint64_t    dns_rtt_sum_usec;
    uint64_t    dns_rtt_count;
} UdpTracker;

void udp_tracker_init(UdpTracker* t);
void udp_tracker_expire_idle(UdpTracker* t, uint64_t now_usec);

/*
 * udp_tracker_observe — record a UDP datagram and return the flow index.
 * Returns ≥0 on success, -1 on overflow.
 */
int  udp_tracker_observe(UdpTracker* t,
                         const uint8_t* src_ip, const uint8_t* dst_ip,
                         uint8_t ip_len,
                         uint16_t src_port, uint16_t dst_port,
                         uint64_t now_usec);

/*
 * udp_tracker_dns_query — record a pending DNS query (QR=0).
 */
void udp_tracker_dns_query(UdpTracker* t,
                           uint16_t xid,
                           const uint8_t* client_ip, const uint8_t* server_ip,
                           uint8_t ip_len, uint16_t client_port,
                           uint64_t now_usec);

/*
 * udp_tracker_dns_response — match DNS response (QR=1) to pending query.
 * Returns RTT in microseconds if matched, 0 if no match.
 */
uint64_t udp_tracker_dns_response(UdpTracker* t,
                                  uint16_t xid,
                                  const uint8_t* server_ip,
                                  const uint8_t* client_ip,
                                  uint8_t ip_len, uint16_t client_port,
                                  uint64_t now_usec);

void udp_tracker_print_summary(const UdpTracker* t);

#endif /* UDP_TRACKER_H */
