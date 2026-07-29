#include "ipv4_reassembly.h"

static int byte_received(const Ipv4ReassemblyEntry* entry, size_t index) {
    return (entry->received[index / 8u] & (uint8_t)(1u << (index % 8u))) != 0;
}

static void mark_byte_received(Ipv4ReassemblyEntry* entry, size_t index) {
    entry->received[index / 8u] |= (uint8_t)(1u << (index % 8u));
}

static int entry_matches(const Ipv4ReassemblyEntry* entry,
                         const Ipv4Header* header) {
    return entry->in_use
        && entry->id == header->id
        && entry->protocol == header->protocol
        && memcmp(entry->src, header->src, 4) == 0
        && memcmp(entry->dst, header->dst, 4) == 0;
}

static Ipv4ReassemblyEntry* find_entry(Ipv4Reassembler* reassembler,
                                       const Ipv4Header* header) {
    for (size_t i = 0; i < IPV4_REASSEMBLY_MAX_ENTRIES; i++) {
        if (entry_matches(&reassembler->entries[i], header))
            return &reassembler->entries[i];
    }
    return NULL;
}

static Ipv4ReassemblyEntry* allocate_entry(Ipv4Reassembler* reassembler,
                                           const Ipv4Header* header) {
    Ipv4ReassemblyEntry* oldest = NULL;

    for (size_t i = 0; i < IPV4_REASSEMBLY_MAX_ENTRIES; i++) {
        Ipv4ReassemblyEntry* entry = &reassembler->entries[i];
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
    memcpy(oldest->src, header->src, 4);
    memcpy(oldest->dst, header->dst, 4);
    oldest->protocol = header->protocol;
    oldest->id = header->id;
    return oldest;
}

static Ipv4ReassemblyStatus reject_entry(Ipv4Reassembler* reassembler,
                                         Ipv4ReassemblyEntry* entry) {
    if (reassembler)
        reassembler->rejected_datagrams++;
    if (entry)
        memset(entry, 0, sizeof(*entry));
    return IPV4_REASSEMBLY_ERROR;
}

void ipv4_reassembly_init(Ipv4Reassembler* reassembler) {
    memset(reassembler, 0, sizeof(*reassembler));
    reassembler->next_sequence = 1;
}

void ipv4_reassembly_expire_idle(Ipv4Reassembler* reassembler,
                                 uint64_t now_usec) {
    if (!reassembler)
        return;
    if (now_usec > reassembler->logical_now_usec)
        reassembler->logical_now_usec = now_usec;

    for (size_t i = 0; i < IPV4_REASSEMBLY_MAX_ENTRIES; i++) {
        Ipv4ReassemblyEntry* entry = &reassembler->entries[i];
        if (!entry->in_use
                || reassembler->logical_now_usec <= entry->last_seen_usec
                || reassembler->logical_now_usec - entry->last_seen_usec
                    <= IPV4_REASSEMBLY_TIMEOUT_USEC)
            continue;

        memset(entry, 0, sizeof(*entry));
        reassembler->expired_datagrams++;
    }
}

Ipv4ReassemblyStatus ipv4_reassembly_add_at(
    Ipv4Reassembler* reassembler,
    const Ipv4Header* header,
    const uint8_t* fragment_payload,
    size_t fragment_len,
    uint64_t now_usec,
    Ipv4ReassemblyResult* result) {
    Ipv4ReassemblyEntry* entry;
    size_t offset;
    size_t end;

    if (!reassembler || !header || !fragment_payload || !result)
        return IPV4_REASSEMBLY_ERROR;

    ipv4_reassembly_expire_idle(reassembler, now_usec);
    memset(result, 0, sizeof(*result));
    entry = find_entry(reassembler, header);

    if (header->hdr_len < IPV4_MIN_HDR_LEN
            || header->hdr_len > IPV4_MAX_HDR_LEN
            || header->hdr_len > header->total_len
            || fragment_len != (size_t)(header->total_len - header->hdr_len)
            || fragment_len == 0
            || (header->flags & IPV4_FLAG_DF)
            || (header->frag_offset == 0 && !(header->flags & IPV4_FLAG_MF)))
        return reject_entry(reassembler, entry);

    offset = (size_t)header->frag_offset * 8u;
    if (offset > IPV4_REASSEMBLY_MAX_PAYLOAD
            || fragment_len > IPV4_REASSEMBLY_MAX_PAYLOAD - offset)
        return reject_entry(reassembler, entry);
    end = offset + fragment_len;

    if ((header->flags & IPV4_FLAG_MF) && (fragment_len % 8u) != 0)
        return reject_entry(reassembler, entry);

    if (!entry)
        entry = allocate_entry(reassembler, header);

    entry->last_seen_sequence = reassembler->next_sequence++;
    entry->last_seen_usec = reassembler->logical_now_usec;

    if (offset == 0) {
        if ((entry->first_seen && entry->first_hdr_len != header->hdr_len)
                || entry->highest_end > 65535u - header->hdr_len)
            return reject_entry(reassembler, entry);
        entry->first_seen = 1;
        entry->first_hdr_len = header->hdr_len;
    }

    if (entry->first_seen && end > 65535u - entry->first_hdr_len)
        return reject_entry(reassembler, entry);

    if (entry->final_seen && end > entry->total_len)
        return reject_entry(reassembler, entry);

    if (!(header->flags & IPV4_FLAG_MF)) {
        if ((entry->final_seen && entry->total_len != end)
                || entry->highest_end > end)
            return reject_entry(reassembler, entry);
        entry->final_seen = 1;
        entry->total_len = end;
    }

    for (size_t i = 0; i < fragment_len; i++) {
        size_t index = offset + i;
        if (byte_received(entry, index)
                && entry->payload[index] != fragment_payload[i])
            return reject_entry(reassembler, entry);
    }

    for (size_t i = 0; i < fragment_len; i++) {
        size_t index = offset + i;
        if (!byte_received(entry, index)) {
            entry->payload[index] = fragment_payload[i];
            mark_byte_received(entry, index);
            entry->received_count++;
        }
    }

    if (end > entry->highest_end)
        entry->highest_end = end;
    entry->fragment_count++;

    if (entry->final_seen && entry->received_count == entry->total_len) {
        result->payload = entry->payload;
        result->payload_len = entry->total_len;
        result->fragment_count = entry->fragment_count;
        entry->in_use = 0;
        reassembler->completed_datagrams++;
        return IPV4_REASSEMBLY_COMPLETE;
    }

    return IPV4_REASSEMBLY_INCOMPLETE;
}

Ipv4ReassemblyStatus ipv4_reassembly_add(
    Ipv4Reassembler* reassembler,
    const Ipv4Header* header,
    const uint8_t* fragment_payload,
    size_t fragment_len,
    Ipv4ReassemblyResult* result) {
    uint64_t now_usec =
        reassembler && reassembler->logical_now_usec < UINT64_MAX
            ? reassembler->logical_now_usec + 1u
            : (reassembler ? reassembler->logical_now_usec : 0);
    return ipv4_reassembly_add_at(
        reassembler, header, fragment_payload, fragment_len, now_usec, result);
}

void ipv4_reassembly_print_summary(const Ipv4Reassembler* reassembler) {
    size_t pending = 0;

    for (size_t i = 0; i < IPV4_REASSEMBLY_MAX_ENTRIES; i++) {
        if (reassembler->entries[i].in_use)
            pending++;
    }

    printf("\n-- IPv4 reassembly summary --\n");
    printf("  completed datagrams: %zu\n", reassembler->completed_datagrams);
    printf("  pending datagrams: %zu\n", pending);
    printf("  expired datagrams: %zu\n", reassembler->expired_datagrams);
    printf("  rejected datagrams: %zu\n", reassembler->rejected_datagrams);
    printf("  evicted datagrams: %zu\n", reassembler->evicted_datagrams);
}
