/*
 * fuzz_parsers.c — drive one parser at a time
 *
 * fuzz_frame.c reaches the parsers only through the dispatch chain, so a
 * mutation has to keep the outer headers plausible before the inner parser
 * sees anything interesting. This target skips that: the first input byte
 * selects a parser and the rest is handed to it directly.
 *
 *   byte 0    parser selector (low 5 bits)
 *   byte 1..  the buffer passed to that parser
 *
 * Each case runs the print function too. The print functions walk the parsed
 * structure — option lists, DNS records, TLS records — so they are part of
 * what needs testing, not just decoration.
 */

#include "fuzz_target.h"

#include "ethernet.h"
#include "arp.h"
#include "ipv4.h"
#include "ipv6.h"
#include "icmp.h"
#include "icmpv6.h"
#include "tcp.h"
#include "udp.h"
#include "dns.h"
#include "dhcp.h"
#include "dhcpv6.h"
#include "ntp.h"
#include "http.h"
#include "tls.h"
#include "gre.h"
#include "igmp.h"
#include "linktype.h"
#include "pppoe.h"
#include "vxlan.h"
#include "pcap.h"

/* Fixed addresses for the pseudo-header checksum paths. The checksum result
   is irrelevant here; what matters is that the summing loops stay in bounds. */
static const uint8_t k_ipv4_a[4]  = { 192, 168, 0, 1 };
static const uint8_t k_ipv4_b[4]  = { 192, 168, 0, 2 };
static const uint8_t k_ipv6_a[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0x01 };
static const uint8_t k_ipv6_b[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0, 0x02 };

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const uint8_t* buf;
    size_t   len;
    uint16_t seg_len;

    fuzz_silence_stdout();

    if (size < 1) return 0;

    buf = data + 1;
    len = size - 1;
    seg_len = (len > 0xFFFFu) ? 0xFFFFu : (uint16_t)len;

    /* Five bits, not four. The first sixteen selectors keep the values they
       had, so corpus inputs written against the earlier mask still reach the
       same parser. */
    switch (data[0] & 0x1Fu) {
        case 0: {
            EtherHeader eth;
            if (eth_parse(buf, len, &eth) == 0)
                eth_print(&eth);
            break;
        }
        case 1: {
            ArpHeader arp;
            if (arp_parse(buf, len, &arp) == 0)
                arp_print(&arp);
            break;
        }
        case 2: {
            Ipv4Header ip;
            if (ipv4_parse(buf, len, &ip) == 0)
                ipv4_print(&ip);
            break;
        }
        case 3: {
            Ipv6Header ip6;
            Ipv6Payload inner;
            if (ipv6_parse(buf, len, &ip6) == 0) {
                ipv6_print(&ip6);
                /* The extension-header walk is the interesting part: it
                   chases a linked list of attacker-controlled lengths. */
                if (ipv6_locate_payload(&ip6, buf, len, &inner) == 0
                        && inner.has_routing)
                    ipv6_routing_print(&inner);
            }
            break;
        }
        case 4: {
            IcmpHeader icmp;
            if (icmp_parse(buf, len, &icmp) == 0)
                icmp_print(&icmp);
            break;
        }
        case 5: {
            Icmpv6Header icmp6;
            if (icmpv6_parse(buf, len, &icmp6) == 0)
                icmpv6_print(&icmp6, 1);
            break;
        }
        case 6: {
            TcpHeader tcp;
            if (tcp_parse(buf, len, &tcp) == 0) {
                char flags[64];
                tcp_print(&tcp, tcp_checksum_ok(k_ipv4_a, k_ipv4_b,
                                                buf, seg_len));
                tcp_print(&tcp, tcp_checksum_ok_v6(k_ipv6_a, k_ipv6_b,
                                                   buf, seg_len));
                tcp_flags_str(tcp.flags, flags, sizeof(flags));
            }
            break;
        }
        case 7: {
            UdpHeader udp;
            if (udp_parse(buf, len, &udp) == 0) {
                udp_print(&udp, udp_checksum_ok(k_ipv4_a, k_ipv4_b,
                                                buf, udp.length));
                udp_print(&udp, udp_checksum_ok_v6(k_ipv6_a, k_ipv6_b,
                                                   buf, udp.length));
            }
            break;
        }
        case 8: {
            DnsMessage dns;
            if (dns_parse(buf, len, &dns) == 0)
                dns_print(&dns);
            break;
        }
        case 9: {
            DhcpMessage dhcp;
            if (dhcp_parse(buf, len, &dhcp) == 0)
                dhcp_print(&dhcp);
            break;
        }
        case 10: {
            Dhcpv6Message dhcpv6;
            if (dhcpv6_parse(buf, len, &dhcpv6) == 0)
                dhcpv6_print(&dhcpv6);
            break;
        }
        case 11: {
            NtpMessage ntp;
            if (ntp_parse(buf, len, &ntp) == 0)
                ntp_print(&ntp);
            break;
        }
        case 12: {
            HttpMessage http;
            (void)http_sniff(buf, len);
            if (http_parse(buf, len, &http) == 0)
                http_print(&http);
            break;
        }
        case 13: {
            TlsMessage tls;
            (void)tls_sniff(buf, len);
            if (tls_parse(buf, len, &tls) == 0)
                tls_print(&tls);
            break;
        }
        case 14: {
            GreHeader gre;
            if (gre_parse(buf, len, &gre) == 0)
                gre_print(&gre);
            break;
        }
        case 15: {
            IgmpMessage igmp;
            if (igmp_parse(buf, len, &igmp) == 0)
                igmp_print(&igmp);
            break;
        }
        case 16: {
            PppoeHeader pppoe;
            if (pppoe_parse(ETHERTYPE_PPPOE_SESSION, buf, len, &pppoe) == 0)
                pppoe_print(&pppoe);
            if (pppoe_parse(ETHERTYPE_PPPOE_DISCOVERY, buf, len, &pppoe) == 0)
                pppoe_print(&pppoe);
            break;
        }
        case 17: {
            VxlanHeader vxlan;
            (void)vxlan_sniff(buf, len);
            if (vxlan_parse(buf, len, &vxlan) == 0)
                vxlan_print(&vxlan);
            break;
        }
        case 18: case 19: case 20: case 21: {
            /* The four link headers, one per selector, so a mutation stays on
               whichever one it started from instead of drifting between
               layouts with completely different field offsets. */
            static const uint16_t link_types[] = {
                LINKTYPE_NULL, LINKTYPE_RAW,
                LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2
            };
            uint16_t link_type = link_types[(data[0] & 0x1Fu) - 18u];
            LinkFrame frame;
            if (link_decode(link_type, buf, len, &frame) == 0)
                link_print(link_type, &frame);
            break;
        }
        default: {
            IgmpMessage igmp;
            if (igmp_parse(buf, len, &igmp) == 0)
                igmp_print(&igmp);
            break;
        }
    }

    return 0;
}
