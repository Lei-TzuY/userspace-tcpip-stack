/*
 * udp_tracker.c — UDP flow table with DNS RTT measurement
 */

#include "udp_tracker.h"

void udp_tracker_init(UdpTracker* t) {
    memset(t, 0, sizeof(*t));
}

void udp_tracker_expire_idle(UdpTracker* t, uint64_t now_usec) {
    for (int i = 0; i < UDP_TRACKER_MAX_FLOWS; i++) {
        UdpFlow* f = &t->flows[i];
        if (f->active && now_usec > f->last_seen_usec
                && now_usec - f->last_seen_usec > UDP_TRACKER_IDLE_USEC)
            f->active = 0;
    }
    for (int i = 0; i < UDP_TRACKER_DNS_SLOTS; i++) {
        DnsQuerySlot* s = &t->dns_pending[i];
        if (s->active && now_usec > s->query_usec
                && now_usec - s->query_usec > UDP_TRACKER_IDLE_USEC)
            s->active = 0;
    }
}

static int flow_matches(const UdpFlow* f,
                        const uint8_t* src_ip, const uint8_t* dst_ip,
                        uint8_t ip_len,
                        uint16_t src_port, uint16_t dst_port) {
    return f->active && f->ip_len == ip_len
        && f->src_port == src_port && f->dst_port == dst_port
        && memcmp(f->src_ip, src_ip, ip_len) == 0
        && memcmp(f->dst_ip, dst_ip, ip_len) == 0;
}

int udp_tracker_observe(UdpTracker* t,
                        const uint8_t* src_ip, const uint8_t* dst_ip,
                        uint8_t ip_len,
                        uint16_t src_port, uint16_t dst_port,
                        uint64_t now_usec) {
    /* Find existing flow */
    for (int i = 0; i < UDP_TRACKER_MAX_FLOWS; i++) {
        if (flow_matches(&t->flows[i], src_ip, dst_ip, ip_len, src_port, dst_port)) {
            if (now_usec > t->flows[i].last_seen_usec)
                t->flows[i].last_seen_usec = now_usec;
            t->flows[i].packet_count++;
            return i;
        }
    }
    /* Allocate new flow in first empty slot */
    for (int i = 0; i < UDP_TRACKER_MAX_FLOWS; i++) {
        if (!t->flows[i].active) {
            UdpFlow* f = &t->flows[i];
            memset(f, 0, sizeof(*f));
            f->active = 1;
            f->ip_len = ip_len;
            memcpy(f->src_ip, src_ip, ip_len);
            memcpy(f->dst_ip, dst_ip, ip_len);
            f->src_port        = src_port;
            f->dst_port        = dst_port;
            f->first_seen_usec = now_usec;
            f->last_seen_usec  = now_usec;
            f->packet_count    = 1;
            t->total_flows++;
            return i;
        }
    }
    return -1;
}

void udp_tracker_dns_query(UdpTracker* t,
                           uint16_t xid,
                           const uint8_t* client_ip, const uint8_t* server_ip,
                           uint8_t ip_len, uint16_t client_port,
                           uint64_t now_usec) {
    /* Overwrite oldest slot if all busy */
    int oldest = 0;
    uint64_t oldest_t = UINT64_MAX;
    for (int i = 0; i < UDP_TRACKER_DNS_SLOTS; i++) {
        if (!t->dns_pending[i].active) { oldest = i; break; }
        if (t->dns_pending[i].query_usec < oldest_t) {
            oldest_t = t->dns_pending[i].query_usec;
            oldest = i;
        }
    }
    DnsQuerySlot* s = &t->dns_pending[oldest];
    s->active      = 1;
    s->xid         = xid;
    s->query_usec  = now_usec;
    s->ip_len      = ip_len;
    s->client_port = client_port;
    memcpy(s->client_ip, client_ip, ip_len);
    memcpy(s->server_ip, server_ip, ip_len);
    t->dns_queries++;
}

uint64_t udp_tracker_dns_response(UdpTracker* t,
                                  uint16_t xid,
                                  const uint8_t* server_ip,
                                  const uint8_t* client_ip,
                                  uint8_t ip_len, uint16_t client_port,
                                  uint64_t now_usec) {
    for (int i = 0; i < UDP_TRACKER_DNS_SLOTS; i++) {
        DnsQuerySlot* s = &t->dns_pending[i];
        if (!s->active || s->xid != xid || s->ip_len != ip_len) continue;
        if (s->client_port != client_port) continue;
        if (memcmp(s->client_ip, client_ip, ip_len) != 0) continue;
        if (memcmp(s->server_ip, server_ip, ip_len) != 0) continue;
        if (now_usec < s->query_usec) continue;
        uint64_t rtt = now_usec - s->query_usec;
        s->active = 0;
        t->dns_responses++;
        t->dns_rtt_sum_usec += rtt;
        t->dns_rtt_count++;
        return rtt;
    }
    return 0;
}

void udp_tracker_print_summary(const UdpTracker* t) {
    printf("── UDP tracker: %llu total flows seen ──\n",
           (unsigned long long)t->total_flows);
    if (t->dns_rtt_count > 0) {
        uint64_t avg = t->dns_rtt_sum_usec / t->dns_rtt_count;
        printf("── DNS RTT: %llu queries  %llu matched  avg=%.2f ms ──\n",
               (unsigned long long)t->dns_queries,
               (unsigned long long)t->dns_rtt_count,
               (double)avg / 1000.0);
    } else if (t->dns_queries > 0) {
        printf("── DNS: %llu queries (no matched responses) ──\n",
               (unsigned long long)t->dns_queries);
    }
}
