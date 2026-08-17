#include "ipv6_reassembly.h"

static int byte_received(const Ipv6ReassemblyEntry* entry, size_t index) {
    return (entry->received[index / 8u] & (uint8_t)(1u << (index % 8u))) != 0;
}

static void mark_byte_received(Ipv6ReassemblyEntry* entry, size_t index) {
    entry->received[index / 8u] |= (uint8_t)(1u << (index % 8u));
}

static int entry_matches(const Ipv6ReassemblyEntry* entry,
                         const Ipv6Header* header, uint32_t id) {
    return entry->in_use
        && entry->id == id
        && memcmp(entry->src, header->src, 16) == 0
        && memcmp(entry->dst, header->dst, 16) == 0;
}

static Ipv6ReassemblyEntry* find_entry(Ipv6Reassembler* reassembler,
                                       const Ipv6Header* header, uint32_t id) {
    for (size_t i = 0; i < IPV6_REASSEMBLY_MAX_ENTRIES; i++) {
        if (entry_matches(&reassembler->entries[i], header, id))
            return &reassembler->entries[i];
    }
    return NULL;
}

static Ipv6ReassemblyEntry* allocate_entry(Ipv6Reassembler* reassembler,
                                           const Ipv6Header* header,
                                           uint32_t id) {
    Ipv6ReassemblyEntry* oldest = NULL;

    for (size_t i = 0; i < IPV6_REASSEMBLY_MAX_ENTRIES; i++) {
        Ipv6ReassemblyEntry* entry = &reassembler->entries[i];
        if (!entry->in_use) {
            oldest = entry;
            break;
        }
        if (!oldest || entry->last_seen_sequence < oldest->last_seen_sequence)
            oldest = entry;
    }

    if (oldest->in_use)
        reassembler->evicted_datagrams++;
    memset(oldest, 0, sizeof(*oldest));
    oldest->in_use = 1;
    memcpy(oldest->src, header->src, 16);
    memcpy(oldest->dst, header->dst, 16);
    oldest->id = id;
    return oldest;
}

static Ipv6ReassemblyStatus reject_entry(Ipv6Reassembler* reassembler,
                                         Ipv6ReassemblyEntry* entry) {
    if (reassembler)
        reassembler->rejected_datagrams++;
    if (entry)
        memset(entry, 0, sizeof(*entry));
    return IPV6_REASSEMBLY_ERROR;
}

void ipv6_reassembly_init(Ipv6Reassembler* reassembler) {
    memset(reassembler, 0, sizeof(*reassembler));
    reassembler->next_sequence = 1;
}

void ipv6_reassembly_expire_idle(Ipv6Reassembler* reassembler,
                                 uint64_t now_usec) {
    if (!reassembler)
        return;
    if (now_usec > reassembler->logical_now_usec)
        reassembler->logical_now_usec = now_usec;

    for (size_t i = 0; i < IPV6_REASSEMBLY_MAX_ENTRIES; i++) {
        Ipv6ReassemblyEntry* entry = &reassembler->entries[i];
        if (!entry->in_use
                || reassembler->logical_now_usec <= entry->last_seen_usec
                || reassembler->logical_now_usec - entry->last_seen_usec
                    <= IPV6_REASSEMBLY_TIMEOUT_USEC)
            continue;

        memset(entry, 0, sizeof(*entry));
        reassembler->expired_datagrams++;
    }
}

Ipv6ReassemblyStatus ipv6_reassembly_add_at(
    Ipv6Reassembler* reassembler,
    const Ipv6Header* header,
    const Ipv6Payload* inner,
    uint64_t now_usec,
    Ipv6ReassemblyResult* result) {

    if (!reassembler || !header || !inner || !result)
        return IPV6_REASSEMBLY_ERROR;
    if (!inner->fragment_seen || !inner->payload || inner->payload_len == 0)
        return IPV6_REASSEMBLY_ERROR;

    ipv6_reassembly_expire_idle(reassembler, now_usec);
    memset(result, 0, sizeof(*result));

    uint32_t id = inner->fragment_id;
    Ipv6ReassemblyEntry* entry = find_entry(reassembler, header, id);

    size_t offset = (size_t)inner->fragment_offset * 8u;
    size_t frag_len = inner->payload_len;

    if (offset > IPV6_REASSEMBLY_MAX_PAYLOAD
            || frag_len > IPV6_REASSEMBLY_MAX_PAYLOAD - offset)
        return reject_entry(reassembler, entry);

    size_t end = offset + frag_len;

    /* Non-final fragments must be a multiple of 8 bytes (RFC 8200 §4.5). */
    if (inner->more_fragments && (frag_len % 8u) != 0)
        return reject_entry(reassembler, entry);

    if (!entry)
        entry = allocate_entry(reassembler, header, id);

    entry->last_seen_sequence = reassembler->next_sequence++;
    entry->last_seen_usec = reassembler->logical_now_usec;
    entry->fragment_count++;

    /* The first fragment (offset 0) carries the final next header. */
    if (offset == 0) {
        entry->first_seen = 1;
        entry->final_next_header = inner->final_next_header;
    }

    if (entry->final_seen && end > entry->total_len)
        return reject_entry(reassembler, entry);

    if (!inner->more_fragments) {
        if (entry->final_seen && entry->total_len != end)
            return reject_entry(reassembler, entry);
        if (entry->highest_end > end)
            return reject_entry(reassembler, entry);
        entry->final_seen = 1;
        entry->total_len  = end;
    }

    /* Check for conflicting overlaps. */
    for (size_t i = 0; i < frag_len; i++) {
        size_t index = offset + i;
        if (byte_received(entry, index)
                && entry->payload[index] != inner->payload[i])
            return reject_entry(reassembler, entry);
    }

    for (size_t i = 0; i < frag_len; i++) {
        size_t index = offset + i;
        if (!byte_received(entry, index)) {
            entry->payload[index] = inner->payload[i];
            mark_byte_received(entry, index);
            entry->received_count++;
        }
    }

    if (end > entry->highest_end)
        entry->highest_end = end;

    if (entry->first_seen && entry->final_seen
            && entry->received_count == entry->total_len) {
        result->payload           = entry->payload;
        result->payload_len       = entry->total_len;
        result->fragment_count    = entry->fragment_count;
        result->final_next_header = entry->final_next_header;
        entry->in_use = 0;
        reassembler->completed_datagrams++;
        return IPV6_REASSEMBLY_COMPLETE;
    }

    return IPV6_REASSEMBLY_INCOMPLETE;
}

void ipv6_reassembly_print_summary(const Ipv6Reassembler* reassembler) {
    size_t pending = 0;

    for (size_t i = 0; i < IPV6_REASSEMBLY_MAX_ENTRIES; i++) {
        if (reassembler->entries[i].in_use)
            pending++;
    }

    printf("\n-- IPv6 reassembly summary --\n");
    printf("  completed datagrams: %zu\n", reassembler->completed_datagrams);
    printf("  pending datagrams: %zu\n", pending);
    printf("  expired datagrams: %zu\n", reassembler->expired_datagrams);
    printf("  rejected datagrams: %zu\n", reassembler->rejected_datagrams);
    printf("  evicted datagrams: %zu\n", reassembler->evicted_datagrams);
}
