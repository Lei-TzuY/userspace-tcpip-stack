/*
 * pppoe.c — PPP over Ethernet (RFC 2516)
 */

#include "pppoe.h"
#include "ethernet.h"

int pppoe_parse(uint16_t ethertype, const uint8_t* data, size_t len,
                PppoeHeader* out) {
    size_t available;

    if (!data || !out) {
        fprintf(stderr, "[pppoe] Missing packet data or output header\n");
        return -1;
    }
    if (len < PPPOE_HDR_LEN) {
        fprintf(stderr, "[pppoe] Too short: %zu bytes (need %d)\n",
                len, PPPOE_HDR_LEN);
        return -1;
    }

    memset(out, 0, sizeof(*out));
    out->version    = (uint8_t)(data[0] >> 4);
    out->type       = (uint8_t)(data[0] & 0x0Fu);
    out->code       = data[1];
    out->session_id = (uint16_t)((data[2] << 8) | data[3]);
    out->length     = (uint16_t)((data[4] << 8) | data[5]);
    out->is_session = (ethertype == ETHERTYPE_PPPOE_SESSION && out->code == 0);

    /* The declared length is the sender's claim about the rest of the packet.
       Trust the smaller of it and what is actually present, so a header
       claiming more than arrived cannot widen the payload. */
    available = len - PPPOE_HDR_LEN;
    if (out->length < available)
        available = out->length;

    if (!out->is_session) {
        /* Discovery packets carry TLV tags rather than a PPP frame. They are
           reported but not walked: a session's traffic is what matters here. */
        out->payload     = available > 0 ? data + PPPOE_HDR_LEN : NULL;
        out->payload_len = available;
        return 0;
    }

    if (available < 2) {
        /* A session packet with no room for the PPP protocol field. */
        out->payload     = NULL;
        out->payload_len = 0;
        return 0;
    }

    out->ppp_protocol     = (uint16_t)((data[PPPOE_HDR_LEN] << 8)
                                       | data[PPPOE_HDR_LEN + 1]);
    out->has_ppp_protocol = 1;
    out->payload_len      = available - 2;
    out->payload          = out->payload_len > 0
                          ? data + PPPOE_HDR_LEN + 2 : NULL;
    return 0;
}

const char* ppp_protocol_name(uint16_t protocol) {
    switch (protocol) {
        case PPP_PROTO_IPV4: return "IPv4";
        case PPP_PROTO_IPV6: return "IPv6";
        case PPP_PROTO_LCP:  return "LCP";
        case PPP_PROTO_IPCP: return "IPCP";
        case PPP_PROTO_CHAP: return "CHAP";
        case PPP_PROTO_PAP:  return "PAP";
        default:             return "UNKNOWN";
    }
}

static const char* pppoe_code_name(uint8_t code) {
    switch (code) {
        case 0x00: return "session data";
        case 0x09: return "PADI";
        case 0x07: return "PADO/PADS";
        case 0x19: return "PADR";
        case 0xa7: return "PADT";
        default:   return "unknown";
    }
}

void pppoe_print(const PppoeHeader* hdr) {
    printf("┌─ PPPoE ────────────────────────────────────────────┐\n");
    printf("│  Version   : %u  type=%u\n", hdr->version, hdr->type);
    printf("│  Code      : 0x%02x  (%s)\n", hdr->code,
           pppoe_code_name(hdr->code));
    printf("│  Session   : 0x%04x\n", hdr->session_id);
    printf("│  Length    : %u bytes\n", hdr->length);
    if (hdr->has_ppp_protocol)
        printf("│  PPP proto : 0x%04x  (%s)\n", hdr->ppp_protocol,
               ppp_protocol_name(hdr->ppp_protocol));
    printf("└────────────────────────────────────────────────────┘\n");
}
