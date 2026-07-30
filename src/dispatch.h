#ifndef DISPATCH_H
#define DISPATCH_H

/*
 * dispatch.h — Layer-2-upward packet dispatch and the stack's mutable state
 *
 * The CLI reads packets from a capture file and hands each Ethernet frame to
 * stack_dispatch_frame(), which walks the frame down through the protocol
 * layers, printing what it finds and updating the trackers.
 *
 * Dispatch chain:
 *   Ethernet EtherType → ARP   : arp_parse / arp_print
 *   Ethernet EtherType → IPv4  : ipv4_parse / ipv4_print
 *   Ethernet EtherType → IPv6  : ipv6_parse / ipv6_print
 *     IPv4 Protocol → ICMP     : icmp_parse / icmp_print
 *     IPv4 Protocol → IGMP     : igmp_parse / igmp_print
 *     IPv4 Protocol → UDP      : udp_parse / udp_print  (+ IPv4 checksum)
 *       UDP port 53 / 5353     : dns_parse / dns_print
 *       UDP port 67 / 68       : dhcp_parse / dhcp_print
 *       UDP port 123           : ntp_parse / ntp_print
 *     IPv4 Protocol → TCP      : tcp_parse / tcp_print  (+ IPv4 checksum)
 *       payload sniff          : tls_parse or http_parse
 *     IPv4 Protocol → GRE      : gre_parse, then recurse on the inner packet
 *     IPv6 Next Hdr → ICMPv6   : icmpv6_parse / icmpv6_print (+ checksum)
 *     IPv6 Next Hdr → UDP/TCP  : as above, with the IPv6 pseudo-header
 *     IPv4/IPv6 fragments      : reassembled first, then dispatched
 *
 * The state carried across packets lives in StackContext. It is a large
 * object — the TCP tracker alone holds a reassembly window per endpoint — so
 * it is allocated on the heap by stack_create() rather than declared on the
 * stack.
 */

#include "common.h"
#include "arp_cache.h"
#include "ipv4_reassembly.h"
#include "ipv6_reassembly.h"
#include "tcp_state.h"
#include "udp_tracker.h"

typedef struct {
    ArpCache        arp_cache;
    TcpTracker      tcp_tracker;
    UdpTracker      udp_tracker;
    Ipv4Reassembler ipv4_reassembler;
    Ipv6Reassembler ipv6_reassembler;
} StackContext;

/*
 * stack_create — allocate and initialise a dispatch context.
 * Returns NULL when out of memory. Release it with stack_destroy().
 */
StackContext* stack_create(void);

/* stack_destroy — release a context obtained from stack_create(). */
void stack_destroy(StackContext* ctx);

/* stack_init — initialise a caller-provided context in place. */
void stack_init(StackContext* ctx);

/*
 * stack_expire_idle — advance capture time and drop idle tracker entries.
 * Call this once per captured packet, including non-IP packets, so that
 * tracker lifetimes follow the capture clock rather than packet counts.
 */
void stack_expire_idle(StackContext* ctx, uint64_t now_usec);

/*
 * stack_dispatch_frame — parse and dispatch one Ethernet frame.
 *
 *   frame           — raw bytes starting at the Ethernet destination MAC
 *   frame_len       — number of bytes available in frame
 *   timestamp_usec  — capture timestamp, microseconds
 *
 * Malformed input is reported and skipped; there is no failure return because
 * a capture is expected to contain frames this stack does not understand.
 */
void stack_dispatch_frame(StackContext* ctx,
                          const uint8_t* frame, size_t frame_len,
                          uint64_t timestamp_usec);

/* stack_print_summary — print the end-of-capture tracker summaries. */
void stack_print_summary(const StackContext* ctx);

#endif /* DISPATCH_H */
