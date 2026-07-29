/*
 * igmp.c — IGMPv1/v2 message parser
 */

#include "igmp.h"

int igmp_parse(const uint8_t* data, size_t len, IgmpMessage* out) {
    if (!data || !out || len < IGMP_MIN_LEN) return -1;
    out->type          = data[0];
    out->max_resp_time = data[1];
    out->checksum      = (uint16_t)((data[2] << 8) | data[3]);
    memcpy(out->group_addr, data + 4, 4);
    return 0;
}

const char* igmp_type_name(uint8_t type) {
    switch (type) {
        case IGMP_QUERY:     return "Membership Query";
        case IGMP_V1_REPORT: return "v1 Membership Report";
        case IGMP_V2_REPORT: return "v2 Membership Report";
        case IGMP_LEAVE:     return "Leave Group";
        default:             return "UNKNOWN";
    }
}

void igmp_print(const IgmpMessage* msg) {
    printf("+-- IGMP ----------------------------------------------------+\n");
    printf("|  Type      : 0x%02x  (%s)\n", msg->type, igmp_type_name(msg->type));
    if (msg->max_resp_time)
        printf("|  Max Resp  : %.1f s\n", msg->max_resp_time / 10.0);
    printf("|  Group     : %u.%u.%u.%u\n",
           msg->group_addr[0], msg->group_addr[1],
           msg->group_addr[2], msg->group_addr[3]);
    printf("+------------------------------------------------------------+\n");
}
