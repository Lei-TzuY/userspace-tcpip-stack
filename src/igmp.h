#ifndef IGMP_H
#define IGMP_H

/*
 * igmp.h — IGMPv1/v2 message parser (RFC 2236)
 *
 * Wire format (8 bytes):
 *   Type (1)  Max Resp Time (1)  Checksum (2)  Group Address (4)
 *
 * Types:
 *   0x11  Membership Query    (v1 and v2)
 *   0x12  v1 Membership Report
 *   0x16  v2 Membership Report
 *   0x17  Leave Group
 */

#include "common.h"

#define IGMP_MIN_LEN 8

#define IGMP_QUERY        0x11u
#define IGMP_V1_REPORT    0x12u
#define IGMP_V2_REPORT    0x16u
#define IGMP_LEAVE        0x17u

typedef struct {
    uint8_t  type;
    uint8_t  max_resp_time;  /* 0.1 s units (v2); 0 for v1 */
    uint16_t checksum;
    uint8_t  group_addr[4];
} IgmpMessage;

int         igmp_parse(const uint8_t* data, size_t len, IgmpMessage* out);
void        igmp_print(const IgmpMessage* msg);
const char* igmp_type_name(uint8_t type);

#endif /* IGMP_H */
