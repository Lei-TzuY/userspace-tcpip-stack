/*
 * dispatch.c — Layer-2-upward packet dispatch
 *
 * See dispatch.h for the dispatch chain this file implements.
 */

#include "dispatch.h"

#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmpv6.h"
#include "udp.h"
#include "tcp.h"
#include "dns.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "ntp.h"
#include "http.h"
#include "tls.h"
#include "gre.h"
#include "igmp.h"

/* ── lifecycle ───────────────────────────────────────────────────────────── */

void stack_init(StackContext* ctx) {
    arp_cache_init(&ctx->arp_cache);
    tcp_tracker_init(&ctx->tcp_tracker);
    udp_tracker_init(&ctx->udp_tracker);
    ipv4_reassembly_init(&ctx->ipv4_reassembler);
    ipv6_reassembly_init(&ctx->ipv6_reassembler);
}

StackContext* stack_create(void) {
    StackContext* ctx = (StackContext*)malloc(sizeof(*ctx));
    if (!ctx) return NULL;
    stack_init(ctx);
    return ctx;
}

void stack_destroy(StackContext* ctx) {
    free(ctx);
}

void stack_expire_idle(StackContext* ctx, uint64_t now_usec) {
    tcp_tracker_expire_idle(&ctx->tcp_tracker, now_usec);
    ipv4_reassembly_expire_idle(&ctx->ipv4_reassembler, now_usec);
    ipv6_reassembly_expire_idle(&ctx->ipv6_reassembler, now_usec);
    udp_tracker_expire_idle(&ctx->udp_tracker, now_usec);
}

void stack_print_summary(const StackContext* ctx) {
    tcp_tracker_print_summary(&ctx->tcp_tracker);
    ipv4_reassembly_print_summary(&ctx->ipv4_reassembler);
    ipv6_reassembly_print_summary(&ctx->ipv6_reassembler);
    arp_cache_print_summary(&ctx->arp_cache);
    udp_tracker_print_summary(&ctx->udp_tracker);
}

/* ── shared application-layer sniffing ───────────────────────────────────── */

/*
 * Inspect a TCP payload for an application protocol we recognise. TLS is
 * tested first because its record header is far more specific than HTTP's
 * text prefix.
 */
static void handle_tcp_payload(const uint8_t* payload, size_t payload_len) {
    if (payload_len == 0) return;

    if (tls_sniff(payload, payload_len)) {
        TlsMessage tls;
        if (tls_parse(payload, payload_len, &tls) == 0)
            tls_print(&tls);
    } else if (http_sniff(payload, payload_len)) {
        HttpMessage http;
        if (http_parse(payload, payload_len, &http) == 0)
            http_print(&http);
    }
}

/*
 * UDP payload dispatch shared by the IPv4 and IPv6 paths. dhcp_ports selects
 * the DHCP flavour to try: 0 for IPv4 (BOOTP 67/68), 1 for IPv6 (546/547).
 */
static void handle_udp_payload(UdpTracker* udp_tracker, const UdpHeader* udp,
                               const uint8_t* src_ip, const uint8_t* dst_ip,
                               uint8_t ip_len, int is_ipv6,
                               uint64_t timestamp_usec) {
    if (udp->payload_len == 0) return;

    if (!is_ipv6) {
        /* DHCP: server=67, client=68 */
        if (udp->dst_port == 67 || udp->dst_port == 68
            || udp->src_port == 67 || udp->src_port == 68) {
            DhcpMessage dhcp;
            if (dhcp_parse(udp->payload, udp->payload_len, &dhcp) == 0)
                dhcp_print(&dhcp);
        }
    } else {
        /* DHCPv6: server=547, client=546 */
        if (udp->dst_port == 546 || udp->dst_port == 547
            || udp->src_port == 546 || udp->src_port == 547) {
            Dhcpv6Message dhcpv6;
            if (dhcpv6_parse(udp->payload, udp->payload_len, &dhcpv6) == 0)
                dhcpv6_print(&dhcpv6);
        }
    }

    /* DNS and mDNS (port 53 and 5353) */
    if (udp->src_port == 53 || udp->dst_port == 53
        || udp->src_port == 5353 || udp->dst_port == 5353) {
        DnsMessage dns;
        if (dns_parse(udp->payload, udp->payload_len, &dns) == 0) {
            dns_print(&dns);
            /* DNS RTT tracking (port 53 only; mDNS is multicast) */
            if (udp->src_port == 53 || udp->dst_port == 53) {
                int is_response = (dns.flags & 0x8000u) != 0;
                if (!is_response) {
                    udp_tracker_dns_query(udp_tracker, dns.id,
                                          src_ip, dst_ip, ip_len,
                                          udp->src_port, timestamp_usec);
                } else {
                    uint64_t rtt = udp_tracker_dns_response(udp_tracker, dns.id,
                                                            src_ip, dst_ip, ip_len,
                                                            udp->dst_port,
                                                            timestamp_usec);
                    if (rtt)
                        printf("  [dns-rtt] %.3f ms\n", (double)rtt / 1000.0);
                }
            }
        }
    }

    /* NTP */
    if (udp->src_port == 123 || udp->dst_port == 123) {
        NtpMessage ntp;
        if (ntp_parse(udp->payload, udp->payload_len, &ntp) == 0)
            ntp_print(&ntp);
    }
}

/* ── ARP ─────────────────────────────────────────────────────────────────── */

static void handle_arp(ArpCache* cache,
                       const uint8_t* payload, size_t payload_len) {
    ArpHeader arp;
    if (arp_parse(payload, payload_len, &arp) != 0)
        return;

    arp_print(&arp);
    ArpCacheStatus status = arp_cache_learn(cache, arp.sender_ip, arp.sender_mac);
    if (status != ARP_CACHE_UNCHANGED)
        printf("  [arp-cache] %s\n", arp_cache_status_name(status));
}

/* ── IPv4 ────────────────────────────────────────────────────────────────── */

static void handle_icmp(const Ipv4Header* ip,
                        const uint8_t* payload, size_t payload_len) {
    IcmpHeader icmp;
    if (icmp_parse(payload, payload_len, &icmp) == 0)
        icmp_print(&icmp);
    UNUSED(ip);
}

static void handle_udp(StackContext* ctx, const Ipv4Header* ip,
                       const uint8_t* payload, size_t payload_len,
                       uint64_t timestamp_usec) {
    UdpHeader udp;
    if (udp_parse(payload, payload_len, &udp) != 0) return;

    int ck = udp_checksum_ok(ip->src, ip->dst, payload, udp.length);
    udp_print(&udp, ck);

    udp_tracker_observe(&ctx->udp_tracker, ip->src, ip->dst, 4,
                        udp.src_port, udp.dst_port, timestamp_usec);

    handle_udp_payload(&ctx->udp_tracker, &udp, ip->src, ip->dst, 4,
                       0 /* IPv4 */, timestamp_usec);
}

static void handle_tcp(StackContext* ctx, const Ipv4Header* ip,
                       const uint8_t* payload, size_t payload_len,
                       uint64_t timestamp_usec) {
    TcpHeader tcp;
    if (tcp_parse(payload, payload_len, &tcp) != 0) return;

    int ck = tcp_checksum_ok(ip->src, ip->dst, payload, (uint16_t)payload_len);
    tcp_print(&tcp, ck);

    if (!ck) {
        printf("  [tcp-state] ignored segment with bad checksum\n");
        return;
    }

    TcpObservation observation;
    int tracked = tcp_tracker_observe_at(
        &ctx->tcp_tracker, ip->src, ip->dst, &tcp, timestamp_usec, &observation);
    if (tracked > 0)
        tcp_observation_print(&observation);
    else if (tracked == 0)
        printf("  [tcp-state] invalid segment metadata\n");
    else
        printf("  [tcp-state] unable to allocate connection slot\n");

    handle_tcp_payload(tcp.payload, tcp.payload_len);
}

/* Forward declarations for recursive GRE dispatch */
static void handle_ipv4(StackContext* ctx,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec);
static void handle_ipv6(StackContext* ctx,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec);

static void handle_gre(StackContext* ctx,
                       const uint8_t* payload, size_t payload_len,
                       uint64_t timestamp_usec) {
    GreHeader gre;
    if (gre_parse(payload, payload_len, &gre) != 0) return;
    gre_print(&gre);
    if (gre.payload_len == 0) return;
    switch (gre.proto) {
        case ETHERTYPE_IPV4:
            handle_ipv4(ctx, gre.payload, gre.payload_len, timestamp_usec);
            break;
        case ETHERTYPE_IPV6:
            handle_ipv6(ctx, gre.payload, gre.payload_len, timestamp_usec);
            break;
        default:
            printf("  [gre] inner protocol 0x%04x — not yet supported\n",
                   gre.proto);
            break;
    }
}

static void handle_ipv4_transport(StackContext* ctx, const Ipv4Header* ip,
                                  const uint8_t* payload, size_t payload_len,
                                  uint64_t timestamp_usec) {
    switch (ip->protocol) {
        case IPPROTO_ICMP: handle_icmp(ip, payload, payload_len); break;
        case 2: { /* IGMP */
            IgmpMessage igmp;
            if (igmp_parse(payload, payload_len, &igmp) == 0)
                igmp_print(&igmp);
            break;
        }
        case IPPROTO_UDP:
            handle_udp(ctx, ip, payload, payload_len, timestamp_usec);
            break;
        case IPPROTO_TCP:
            handle_tcp(ctx, ip, payload, payload_len, timestamp_usec);
            break;
        case 47: /* GRE */
            handle_gre(ctx, payload, payload_len, timestamp_usec);
            break;
        default:
            printf("  [IPv4 protocol %u (%s) — not yet supported]\n",
                   ip->protocol, ipv4_proto_name(ip->protocol));
            break;
    }
}

static void handle_ipv4(StackContext* ctx,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec) {
    Ipv4Header ip;
    if (ipv4_parse(payload, payload_len, &ip) != 0) return;
    ipv4_print(&ip);
    if (!ip.checksum_valid) {
        printf("  [ipv4] skipped payload with bad header checksum\n");
        return;
    }

    /* Compute actual inner-payload bounds, accounting for Ethernet padding.
       Ethernet pads frames to 60 bytes min, so payload_len may exceed
       ip.total_len.  Use ip.total_len as the authoritative length. */
    size_t inner_len = payload_len - ip.hdr_len;
    if (ip.total_len >= ip.hdr_len) {
        size_t ip_inner = (size_t)(ip.total_len - ip.hdr_len);
        if (ip_inner < inner_len) inner_len = ip_inner;
    }
    const uint8_t* inner = payload + ip.hdr_len;

    /* Transport checksum verification requires the complete datagram. */
    if (ip.frag_offset != 0 || (ip.flags & IPV4_FLAG_MF)) {
        Ipv4ReassemblyResult result;
        Ipv4ReassemblyStatus status = ipv4_reassembly_add_at(
            &ctx->ipv4_reassembler, &ip, inner, inner_len, timestamp_usec,
            &result);
        if (status == IPV4_REASSEMBLY_COMPLETE) {
            printf("  [ipv4-reassembly] complete: %zu bytes from %zu fragments\n",
                   result.payload_len, result.fragment_count);
            handle_ipv4_transport(ctx, &ip, result.payload, result.payload_len,
                                  timestamp_usec);
        } else if (status == IPV4_REASSEMBLY_INCOMPLETE) {
            printf("  [ipv4-reassembly] stored fragment: offset=%u bytes len=%zu MF=%u\n",
                   ip.frag_offset * 8u, inner_len,
                   (ip.flags & IPV4_FLAG_MF) ? 1u : 0u);
        } else {
            printf("  [ipv4-reassembly] rejected malformed fragment\n");
        }
        return;
    }

    handle_ipv4_transport(ctx, &ip, inner, inner_len, timestamp_usec);
}

/* ── IPv6 ────────────────────────────────────────────────────────────────── */

static void handle_icmpv6(const Ipv6Header* ip,
                          const uint8_t* payload, size_t payload_len) {
    Icmpv6Header icmp;
    if (icmpv6_parse(payload, payload_len, &icmp) != 0)
        return;

    icmpv6_print(&icmp, icmpv6_checksum_ok(ip, payload, payload_len));
}

static void handle_ipv6_udp(StackContext* ctx, const Ipv6Header* ip6,
                            const uint8_t* payload, size_t payload_len,
                            uint64_t timestamp_usec) {
    UdpHeader udp;
    if (udp_parse(payload, payload_len, &udp) != 0) return;

    int ck = udp_checksum_ok_v6(ip6->src, ip6->dst,
                                payload, (uint16_t)payload_len);
    udp_print(&udp, ck);

    udp_tracker_observe(&ctx->udp_tracker, ip6->src, ip6->dst, 16,
                        udp.src_port, udp.dst_port, timestamp_usec);

    handle_udp_payload(&ctx->udp_tracker, &udp, ip6->src, ip6->dst, 16,
                       1 /* IPv6 */, timestamp_usec);
}

static void handle_ipv6_tcp(StackContext* ctx, const Ipv6Header* ip6,
                            const uint8_t* payload, size_t payload_len,
                            uint64_t timestamp_usec) {
    TcpHeader tcp;
    if (tcp_parse(payload, payload_len, &tcp) != 0) return;

    int ck = tcp_checksum_ok_v6(ip6->src, ip6->dst,
                                payload, (uint16_t)payload_len);
    tcp_print(&tcp, ck);

    if (!ck) {
        printf("  [tcp-state] ignored segment with bad checksum\n");
        return;
    }

    TcpObservation observation;
    int tracked = tcp_tracker_observe_v6_at(
        &ctx->tcp_tracker, ip6->src, ip6->dst, &tcp, timestamp_usec,
        &observation);
    if (tracked > 0)
        tcp_observation_print(&observation);
    else if (tracked == 0)
        printf("  [tcp-state] invalid segment metadata\n");
    else
        printf("  [tcp-state] unable to allocate connection slot\n");

    handle_tcp_payload(tcp.payload, tcp.payload_len);
}

/* Forward declaration so ipv6 dispatch can recurse after reassembly. */
static void handle_ipv6_transport(StackContext* ctx, const Ipv6Header* ip,
                                   uint8_t next_header,
                                   const uint8_t* payload, size_t payload_len,
                                   uint64_t timestamp_usec);

static void handle_ipv6(StackContext* ctx,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec) {
    Ipv6Header ip;
    Ipv6Payload inner;
    if (ipv6_parse(payload, payload_len, &ip) != 0)
        return;

    ipv6_print(&ip);
    if (ipv6_locate_payload(&ip, payload, payload_len, &inner) != 0)
        return;

    if (inner.extension_len > 0)
        printf("  [ipv6] extension headers: %zu byte(s)\n",
               inner.extension_len);

    if (inner.has_routing)
        ipv6_routing_print(&inner);

    if (inner.fragment_seen) {
        printf("  [ipv6] fragment: id=0x%08x offset=%u bytes MF=%u\n",
               inner.fragment_id, inner.fragment_offset * 8u,
               inner.more_fragments ? 1u : 0u);

        if (inner.fragment_offset != 0 || inner.more_fragments) {
            Ipv6ReassemblyResult result;
            Ipv6ReassemblyStatus status = ipv6_reassembly_add_at(
                &ctx->ipv6_reassembler, &ip, &inner, timestamp_usec, &result);
            if (status == IPV6_REASSEMBLY_COMPLETE) {
                printf("  [ipv6-reassembly] complete: %zu bytes from %zu fragments"
                       "  next=%u\n",
                       result.payload_len, result.fragment_count,
                       result.final_next_header);
                handle_ipv6_transport(ctx, &ip, result.final_next_header,
                                      result.payload, result.payload_len,
                                      timestamp_usec);
            } else if (status == IPV6_REASSEMBLY_INCOMPLETE) {
                printf("  [ipv6-reassembly] stored fragment: offset=%u bytes"
                       " len=%zu MF=%u\n",
                       inner.fragment_offset * 8u, inner.payload_len,
                       inner.more_fragments ? 1u : 0u);
            } else {
                printf("  [ipv6-reassembly] rejected malformed fragment\n");
            }
            return;
        }
        /* Fragment at offset 0 with MF=0 is a single-fragment datagram;
           fall through to normal dispatch. */
    }

    handle_ipv6_transport(ctx, &ip, inner.final_next_header,
                          inner.payload, inner.payload_len, timestamp_usec);
}

static void handle_ipv6_transport(StackContext* ctx, const Ipv6Header* ip,
                                   uint8_t next_header,
                                   const uint8_t* payload, size_t payload_len,
                                   uint64_t timestamp_usec) {
    switch (next_header) {
        case 59:
            printf("  [ipv6] no payload\n");
            break;
        case IPPROTO_ICMPV6:
            handle_icmpv6(ip, payload, payload_len);
            break;
        case IPPROTO_UDP:
            handle_ipv6_udp(ctx, ip, payload, payload_len, timestamp_usec);
            break;
        case IPPROTO_TCP:
            handle_ipv6_tcp(ctx, ip, payload, payload_len, timestamp_usec);
            break;
        default:
            printf("  [ipv6] next-header dispatch not yet supported: %u (%s)\n",
                   next_header, ipv6_next_header_name(next_header));
            break;
    }
}

/* ── Layer 2 entry point ─────────────────────────────────────────────────── */

void stack_dispatch_frame(StackContext* ctx,
                          const uint8_t* frame, size_t frame_len,
                          uint64_t timestamp_usec) {
    EtherHeader eth;
    if (eth_parse(frame, frame_len, &eth) != 0)
        return;
    eth_print(&eth);

    if (frame_len <= eth.hdr_len)
        return;

    const uint8_t* payload     = frame + eth.hdr_len;
    size_t         payload_len = frame_len - eth.hdr_len;

    switch (eth.ethertype) {
        case ETHERTYPE_ARP:
            handle_arp(&ctx->arp_cache, payload, payload_len);
            break;
        case ETHERTYPE_IPV4:
            handle_ipv4(ctx, payload, payload_len, timestamp_usec);
            break;
        case ETHERTYPE_IPV6:
            handle_ipv6(ctx, payload, payload_len, timestamp_usec);
            break;
        default:
            if (eth.ethertype <= 1500)
                printf("  [802.3 frame, length=%u — not yet supported]\n",
                       eth.ethertype);
            else
                printf("  [EtherType 0x%04x — unknown]\n", eth.ethertype);
            break;
    }
}
