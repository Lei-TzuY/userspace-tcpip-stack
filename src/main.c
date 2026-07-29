/*
 * main.c — Toy TCP/IP Stack
 *
 * Usage:
 *   tcpip <file.pcap|file.pcapng>
 *
 * Protocol stack layers implemented:
 *
 *   ┌──────────────────────────────────────────────────────────┐
 *   │  Layer 7 — DNS  (query/answer, A/AAAA/CNAME/MX/TXT/NS) │
 *   │  Layer 4 — TCP  (segments, options, checksum)            │
 *   │  Layer 4 — UDP  (datagrams, pseudo-header checksum)      │
 *   │  Layer 3 — ICMPv6 (echo, NDP RS/RA/NS/NA, options)      │
 *   │  Layer 3 — ICMP (echo, unreachable, time-exceeded)       │
 *   │  Layer 3 — IPv6 (fixed header + reassembly)              │
 *   │  Layer 3 — IPv4 (header, reassembly, checksum)           │
 *   │  Layer 2 — ARP  (request / reply)                        │
 *   │  Layer 2 — Ethernet II / VLAN (MAC, dispatch)            │
 *   │  pcap file reader (offline mode, endian-aware)           │
 *   └──────────────────────────────────────────────────────────┘
 *
 * Dispatch logic:
 *   Ethernet EtherType → ARP   : arp_parse / arp_print
 *   Ethernet EtherType → IPv4  : ipv4_parse / ipv4_print
 *   Ethernet EtherType → IPv6  : ipv6_parse / ipv6_print
 *     IPv4 Protocol → ICMP     : icmp_parse / icmp_print
 *     IPv4 Protocol → UDP      : udp_parse / udp_print  (+ IPv4 checksum)
 *       UDP port 53            : dns_parse / dns_print
 *     IPv4 Protocol → TCP      : tcp_parse / tcp_print  (+ IPv4 checksum)
 *     IPv6 Next Hdr → ICMPv6   : icmpv6_parse / icmpv6_print (+ checksum)
 *     IPv6 Next Hdr → UDP      : udp_parse / udp_print  (+ IPv6 checksum)
 *       UDP port 53            : dns_parse / dns_print
 *     IPv6 Next Hdr → TCP      : tcp_parse / tcp_print  (+ IPv6 checksum)
 *     IPv6 fragment → reassembled then dispatch as above
 */

#include "common.h"
#include "pcap.h"
#include "ethernet.h"
#include "arp.h"
#include "arp_cache.h"
#include "ipv4.h"
#include "ipv4_reassembly.h"
#include "ipv6.h"
#include "ipv6_reassembly.h"
#include "icmp.h"
#include "icmpv6.h"
#include "udp.h"
#include "tcp.h"
#include "tcp_state.h"
#include "dns.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "ntp.h"
#include "http.h"
#include "tls.h"
#include "gre.h"
#include "igmp.h"
#include "udp_tracker.h"

#define PKT_BUF_SIZE (64 * 1024)

/* ── dispatch helpers ────────────────────────────────────────────────────── */

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

static void handle_icmp(const Ipv4Header* ip,
                         const uint8_t* payload, size_t payload_len) {
    IcmpHeader icmp;
    if (icmp_parse(payload, payload_len, &icmp) == 0)
        icmp_print(&icmp);
    UNUSED(ip);
}

static void handle_udp(UdpTracker* udp_tracker, const Ipv4Header* ip,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec) {
    UdpHeader udp;
    if (udp_parse(payload, payload_len, &udp) != 0) return;

    int ck = udp_checksum_ok(ip->src, ip->dst, payload, udp.length);
    udp_print(&udp, ck);

    udp_tracker_observe(udp_tracker, ip->src, ip->dst, 4,
                        udp.src_port, udp.dst_port, timestamp_usec);

    /* DHCP: server=67, client=68 */
    if ((udp.dst_port == 67 || udp.dst_port == 68
         || udp.src_port == 67 || udp.src_port == 68) && udp.payload_len > 0) {
        DhcpMessage dhcp;
        if (dhcp_parse(udp.payload, udp.payload_len, &dhcp) == 0)
            dhcp_print(&dhcp);
    }

    /* DNS and mDNS (port 53 and 5353) */
    if ((udp.src_port == 53 || udp.dst_port == 53
         || udp.src_port == 5353 || udp.dst_port == 5353)
            && udp.payload_len > 0) {
        DnsMessage dns;
        if (dns_parse(udp.payload, udp.payload_len, &dns) == 0) {
            dns_print(&dns);
            /* DNS RTT tracking (port 53 only; mDNS is multicast) */
            if (udp.src_port == 53 || udp.dst_port == 53) {
                int is_response = (dns.flags & 0x8000u) != 0;
                if (!is_response) {
                    udp_tracker_dns_query(udp_tracker, dns.id,
                                          ip->src, ip->dst, 4,
                                          udp.src_port, timestamp_usec);
                } else {
                    uint64_t rtt = udp_tracker_dns_response(udp_tracker, dns.id,
                                                            ip->src, ip->dst, 4,
                                                            udp.dst_port,
                                                            timestamp_usec);
                    if (rtt)
                        printf("  [dns-rtt] %.3f ms\n", (double)rtt / 1000.0);
                }
            }
        }
    }

    /* NTP */
    if ((udp.src_port == 123 || udp.dst_port == 123) && udp.payload_len > 0) {
        NtpMessage ntp;
        if (ntp_parse(udp.payload, udp.payload_len, &ntp) == 0)
            ntp_print(&ntp);
    }
}

static void handle_tcp(TcpTracker* tracker, const Ipv4Header* ip,
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
        tracker, ip->src, ip->dst, &tcp, timestamp_usec, &observation);
    if (tracked > 0)
        tcp_observation_print(&observation);
    else if (tracked == 0)
        printf("  [tcp-state] invalid segment metadata\n");
    else
        printf("  [tcp-state] unable to allocate connection slot\n");

    /* Application-layer sniffing on payload */
    if (tcp.payload_len > 0) {
        if (tls_sniff(tcp.payload, tcp.payload_len)) {
            TlsMessage tls;
            if (tls_parse(tcp.payload, tcp.payload_len, &tls) == 0)
                tls_print(&tls);
        } else if (http_sniff(tcp.payload, tcp.payload_len)) {
            HttpMessage http;
            if (http_parse(tcp.payload, tcp.payload_len, &http) == 0)
                http_print(&http);
        }
    }
}

/* Forward declarations for recursive GRE dispatch */
static void handle_ipv4(TcpTracker* tracker, UdpTracker* udp_tracker,
                        Ipv4Reassembler* ipv4_reassembler,
                        Ipv6Reassembler* ipv6_reassembler,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec);
static void handle_ipv6(TcpTracker* tracker, UdpTracker* udp_tracker,
                        Ipv6Reassembler* reassembler,
                        const uint8_t* payload, size_t payload_len,
                        uint64_t timestamp_usec);

static void handle_gre(TcpTracker* tracker, UdpTracker* udp_tracker,
                       Ipv4Reassembler* ipv4_reassembler,
                       Ipv6Reassembler* ipv6_reassembler,
                       const uint8_t* payload, size_t payload_len,
                       uint64_t timestamp_usec) {
    GreHeader gre;
    if (gre_parse(payload, payload_len, &gre) != 0) return;
    gre_print(&gre);
    if (gre.payload_len == 0) return;
    switch (gre.proto) {
        case ETHERTYPE_IPV4:
            handle_ipv4(tracker, udp_tracker, ipv4_reassembler, ipv6_reassembler,
                        gre.payload, gre.payload_len, timestamp_usec);
            break;
        case ETHERTYPE_IPV6:
            handle_ipv6(tracker, udp_tracker, ipv6_reassembler,
                        gre.payload, gre.payload_len, timestamp_usec);
            break;
        default:
            printf("  [gre] inner protocol 0x%04x — not yet supported\n",
                   gre.proto);
            break;
    }
}

static void handle_ipv4_transport(TcpTracker* tracker, UdpTracker* udp_tracker,
                                  Ipv4Reassembler* ipv4_reassembler,
                                  Ipv6Reassembler* ipv6_reassembler,
                                  const Ipv4Header* ip,
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
            handle_udp(udp_tracker, ip, payload, payload_len, timestamp_usec);
            break;
        case IPPROTO_TCP:
            handle_tcp(tracker, ip, payload, payload_len, timestamp_usec);
            break;
        case 47: /* GRE */
            handle_gre(tracker, udp_tracker, ipv4_reassembler,
                       ipv6_reassembler, payload, payload_len, timestamp_usec);
            break;
        default:
            printf("  [IPv4 protocol %u (%s) — not yet supported]\n",
                   ip->protocol, ipv4_proto_name(ip->protocol));
            break;
    }
}

static void handle_ipv4(TcpTracker* tracker, UdpTracker* udp_tracker,
                        Ipv4Reassembler* ipv4_reassembler,
                        Ipv6Reassembler* ipv6_reassembler,
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
            ipv4_reassembler, &ip, inner, inner_len, timestamp_usec, &result);
        if (status == IPV4_REASSEMBLY_COMPLETE) {
            printf("  [ipv4-reassembly] complete: %zu bytes from %zu fragments\n",
                   result.payload_len, result.fragment_count);
            handle_ipv4_transport(
                tracker, udp_tracker, ipv4_reassembler, ipv6_reassembler,
                &ip, result.payload, result.payload_len, timestamp_usec);
        } else if (status == IPV4_REASSEMBLY_INCOMPLETE) {
            printf("  [ipv4-reassembly] stored fragment: offset=%u bytes len=%zu MF=%u\n",
                   ip.frag_offset * 8u, inner_len,
                   (ip.flags & IPV4_FLAG_MF) ? 1u : 0u);
        } else {
            printf("  [ipv4-reassembly] rejected malformed fragment\n");
        }
        return;
    }

    handle_ipv4_transport(tracker, udp_tracker, ipv4_reassembler, ipv6_reassembler,
                          &ip, inner, inner_len, timestamp_usec);
}

/* ── IPv6 helpers ────────────────────────────────────────────────────────── */

static void handle_icmpv6(const Ipv6Header* ip,
                          const uint8_t* payload, size_t payload_len) {
    Icmpv6Header icmp;
    if (icmpv6_parse(payload, payload_len, &icmp) != 0)
        return;

    icmpv6_print(&icmp, icmpv6_checksum_ok(ip, payload, payload_len));
}

static void handle_ipv6_udp(UdpTracker* udp_tracker, const Ipv6Header* ip6,
                             const uint8_t* payload, size_t payload_len,
                             uint64_t timestamp_usec) {
    UdpHeader udp;
    if (udp_parse(payload, payload_len, &udp) != 0) return;

    int ck = udp_checksum_ok_v6(ip6->src, ip6->dst,
                                 payload, (uint16_t)payload_len);
    udp_print(&udp, ck);

    udp_tracker_observe(udp_tracker, ip6->src, ip6->dst, 16,
                        udp.src_port, udp.dst_port, timestamp_usec);

    /* DHCPv6: server=547, client=546 */
    if ((udp.dst_port == 546 || udp.dst_port == 547
         || udp.src_port == 546 || udp.src_port == 547) && udp.payload_len > 0) {
        Dhcpv6Message dhcpv6;
        if (dhcpv6_parse(udp.payload, udp.payload_len, &dhcpv6) == 0)
            dhcpv6_print(&dhcpv6);
    }

    /* DNS and mDNS (port 53 and 5353) */
    if ((udp.src_port == 53 || udp.dst_port == 53
         || udp.src_port == 5353 || udp.dst_port == 5353)
            && udp.payload_len > 0) {
        DnsMessage dns;
        if (dns_parse(udp.payload, udp.payload_len, &dns) == 0) {
            dns_print(&dns);
            if (udp.src_port == 53 || udp.dst_port == 53) {
                int is_response = (dns.flags & 0x8000u) != 0;
                if (!is_response) {
                    udp_tracker_dns_query(udp_tracker, dns.id,
                                          ip6->src, ip6->dst, 16,
                                          udp.src_port, timestamp_usec);
                } else {
                    uint64_t rtt = udp_tracker_dns_response(udp_tracker, dns.id,
                                                            ip6->src, ip6->dst, 16,
                                                            udp.dst_port,
                                                            timestamp_usec);
                    if (rtt)
                        printf("  [dns-rtt] %.3f ms\n", (double)rtt / 1000.0);
                }
            }
        }
    }

    /* NTP */
    if ((udp.src_port == 123 || udp.dst_port == 123) && udp.payload_len > 0) {
        NtpMessage ntp;
        if (ntp_parse(udp.payload, udp.payload_len, &ntp) == 0)
            ntp_print(&ntp);
    }
}

static void handle_ipv6_tcp(TcpTracker* tracker, const Ipv6Header* ip6,
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
        tracker, ip6->src, ip6->dst, &tcp, timestamp_usec, &observation);
    if (tracked > 0)
        tcp_observation_print(&observation);
    else if (tracked == 0)
        printf("  [tcp-state] invalid segment metadata\n");
    else
        printf("  [tcp-state] unable to allocate connection slot\n");

    if (tcp.payload_len > 0) {
        if (tls_sniff(tcp.payload, tcp.payload_len)) {
            TlsMessage tls;
            if (tls_parse(tcp.payload, tcp.payload_len, &tls) == 0)
                tls_print(&tls);
        } else if (http_sniff(tcp.payload, tcp.payload_len)) {
            HttpMessage http;
            if (http_parse(tcp.payload, tcp.payload_len, &http) == 0)
                http_print(&http);
        }
    }
}

/* Forward declaration so ipv6 dispatch can recurse after reassembly. */
static void handle_ipv6_transport(TcpTracker* tracker, UdpTracker* udp_tracker,
                                   const Ipv6Header* ip,
                                   uint8_t next_header,
                                   const uint8_t* payload, size_t payload_len,
                                   uint64_t timestamp_usec);

static void handle_ipv6(TcpTracker* tracker, UdpTracker* udp_tracker,
                        Ipv6Reassembler* reassembler,
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
                reassembler, &ip, &inner, timestamp_usec, &result);
            if (status == IPV6_REASSEMBLY_COMPLETE) {
                printf("  [ipv6-reassembly] complete: %zu bytes from %zu fragments"
                       "  next=%u\n",
                       result.payload_len, result.fragment_count,
                       result.final_next_header);
                handle_ipv6_transport(
                    tracker, udp_tracker, &ip, result.final_next_header,
                    result.payload, result.payload_len, timestamp_usec);
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

    handle_ipv6_transport(tracker, udp_tracker, &ip, inner.final_next_header,
                          inner.payload, inner.payload_len, timestamp_usec);
}

static void handle_ipv6_transport(TcpTracker* tracker, UdpTracker* udp_tracker,
                                   const Ipv6Header* ip,
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
            handle_ipv6_udp(udp_tracker, ip, payload, payload_len, timestamp_usec);
            break;
        case IPPROTO_TCP:
            handle_ipv6_tcp(tracker, ip, payload, payload_len, timestamp_usec);
            break;
        default:
            printf("  [ipv6] next-header dispatch not yet supported: %u (%s)\n",
                   next_header, ipv6_next_header_name(next_header));
            break;
    }
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <file.pcap|file.pcapng>\n", argv[0]);
        return EXIT_FAILURE;
    }

    PcapReader* reader = pcap_open(argv[1]);
    if (!reader) return EXIT_FAILURE;

    uint8_t* buf = (uint8_t*)malloc(PKT_BUF_SIZE);
    if (!buf) {
        fprintf(stderr, "Out of memory\n");
        pcap_close(reader);
        return EXIT_FAILURE;
    }

    PcapPacketHeader pkt_hdr;
    size_t pkt_count = 0;
    ArpCache arp_cache;
    TcpTracker* tcp_tracker = (TcpTracker*)malloc(sizeof(*tcp_tracker));
    if (!tcp_tracker) {
        fprintf(stderr, "Out of memory\n");
        free(buf);
        pcap_close(reader);
        return EXIT_FAILURE;
    }
    Ipv4Reassembler* ipv4_reassembler =
        (Ipv4Reassembler*)malloc(sizeof(*ipv4_reassembler));
    if (!ipv4_reassembler) {
        fprintf(stderr, "Out of memory\n");
        free(tcp_tracker);
        free(buf);
        pcap_close(reader);
        return EXIT_FAILURE;
    }
    Ipv6Reassembler* ipv6_reassembler =
        (Ipv6Reassembler*)malloc(sizeof(*ipv6_reassembler));
    if (!ipv6_reassembler) {
        fprintf(stderr, "Out of memory\n");
        free(ipv4_reassembler);
        free(tcp_tracker);
        free(buf);
        pcap_close(reader);
        return EXIT_FAILURE;
    }
    UdpTracker* udp_tracker = (UdpTracker*)malloc(sizeof(*udp_tracker));
    if (!udp_tracker) {
        fprintf(stderr, "Out of memory\n");
        free(ipv6_reassembler);
        free(ipv4_reassembler);
        free(tcp_tracker);
        free(buf);
        pcap_close(reader);
        return EXIT_FAILURE;
    }
    tcp_tracker_init(tcp_tracker);
    ipv4_reassembly_init(ipv4_reassembler);
    ipv6_reassembly_init(ipv6_reassembler);
    udp_tracker_init(udp_tracker);
    arp_cache_init(&arp_cache);

    printf("\n");

    while (1) {
        size_t pkt_len = pcap_next(reader, &pkt_hdr, buf, PKT_BUF_SIZE);
        if (pkt_len == 0) break;

        pkt_count++;
        uint64_t timestamp_usec =
            ((uint64_t)pkt_hdr.ts_sec * 1000000u) + pkt_hdr.ts_usec;
        tcp_tracker_expire_idle(tcp_tracker, timestamp_usec);
        ipv4_reassembly_expire_idle(ipv4_reassembler, timestamp_usec);
        ipv6_reassembly_expire_idle(ipv6_reassembler, timestamp_usec);
        udp_tracker_expire_idle(udp_tracker, timestamp_usec);
        printf("══ Packet #%zu  (%u bytes on-wire  @  %u.%06u s) ══\n",
               pkt_count,
               pkt_hdr.orig_len,
               pkt_hdr.ts_sec,
               pkt_hdr.ts_usec);

        if (reader->global.network != LINKTYPE_ETHERNET) {
            printf("  [skip] Non-Ethernet link type %u\n",
                   reader->global.network);
            printf("\n");
            continue;
        }

        /* ── Layer 2: Ethernet ────────────────────────────────────────── */
        EtherHeader eth;
        if (eth_parse(buf, pkt_len, &eth) != 0) {
            printf("\n");
            continue;
        }
        eth_print(&eth);

        if (pkt_len <= eth.hdr_len) {
            printf("\n");
            continue;
        }

        const uint8_t* eth_payload     = buf + eth.hdr_len;
        size_t         eth_payload_len = pkt_len - eth.hdr_len;

        /* ── Layer 3 dispatch by EtherType ────────────────────────────── */
        switch (eth.ethertype) {
            case ETHERTYPE_ARP:
                handle_arp(&arp_cache, eth_payload, eth_payload_len);
                break;
            case ETHERTYPE_IPV4:
                handle_ipv4(tcp_tracker, udp_tracker,
                            ipv4_reassembler, ipv6_reassembler,
                            eth_payload, eth_payload_len, timestamp_usec);
                break;
            case ETHERTYPE_IPV6:
                handle_ipv6(tcp_tracker, udp_tracker, ipv6_reassembler,
                            eth_payload, eth_payload_len, timestamp_usec);
                break;
            default:
                if (eth.ethertype <= 1500)
                    printf("  [802.3 frame, length=%u — not yet supported]\n",
                           eth.ethertype);
                else
                    printf("  [EtherType 0x%04x — unknown]\n", eth.ethertype);
                break;
        }

        printf("\n");
    }

    printf("── Done. Parsed %zu packet(s). ──\n", pkt_count);

    tcp_tracker_print_summary(tcp_tracker);
    ipv4_reassembly_print_summary(ipv4_reassembler);
    ipv6_reassembly_print_summary(ipv6_reassembler);
    arp_cache_print_summary(&arp_cache);
    udp_tracker_print_summary(udp_tracker);

    free(udp_tracker);
    free(ipv6_reassembler);
    free(ipv4_reassembler);
    free(tcp_tracker);
    free(buf);
    pcap_close(reader);
    return EXIT_SUCCESS;
}
