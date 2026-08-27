//! IPv4 Packet Fragmentation and Reassembly (RFC 791).
//!
//! Handles splitting oversized IPv4 packets into $\le \text{MTU}$ fragments
//! (aligned to 8-byte boundaries) and reassembling out-of-order IP fragments.

use crate::ipv4::{IPV4_MIN_HEADER_LEN, Ipv4Address};
use std::collections::HashMap;

const IPV4_MAX_PAYLOAD_LEN: usize = u16::MAX as usize - IPV4_MIN_HEADER_LEN;
const MAX_REASSEMBLY_DATAGRAMS: usize = 1024;
const MAX_REASSEMBLY_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub protocol: u8,
    pub identification: u16,
}

#[derive(Debug, Clone)]
struct FragmentEntry {
    offset: usize, // in bytes
    data: Vec<u8>,
    more_fragments: bool,
}

#[derive(Debug, Default)]
struct FragmentSet {
    entries: Vec<FragmentEntry>,
    last_used: u64,
}

#[derive(Debug, Default)]
pub struct IpReassemblyBuffer {
    buffers: HashMap<FragmentKey, FragmentSet>,
    buffered_bytes: usize,
    sequence: u64,
}

impl IpReassemblyBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence = self.sequence.saturating_add(1);
        self.sequence
    }

    fn remove_buffer(&mut self, key: &FragmentKey) {
        if let Some(set) = self.buffers.remove(key) {
            let removed_bytes = set
                .entries
                .iter()
                .map(|entry| entry.data.len())
                .sum::<usize>();
            self.buffered_bytes = self.buffered_bytes.saturating_sub(removed_bytes);
        }
    }

    fn evict_oldest_except(&mut self, protected: Option<&FragmentKey>) -> bool {
        let oldest = self
            .buffers
            .iter()
            .filter(|(key, _)| protected != Some(*key))
            .min_by_key(|(_, set)| set.last_used)
            .map(|(key, _)| key.clone());

        if let Some(key) = oldest {
            self.remove_buffer(&key);
            true
        } else {
            false
        }
    }

    fn make_room_for(&mut self, key: &FragmentKey, additional_bytes: usize) -> bool {
        if additional_bytes > MAX_REASSEMBLY_BYTES {
            self.remove_buffer(key);
            return false;
        }

        if !self.buffers.contains_key(key) {
            while self.buffers.len() >= MAX_REASSEMBLY_DATAGRAMS {
                if !self.evict_oldest_except(None) {
                    return false;
                }
            }
        }

        while self.buffered_bytes.saturating_add(additional_bytes) > MAX_REASSEMBLY_BYTES {
            if !self.evict_oldest_except(Some(key)) {
                self.remove_buffer(key);
                return false;
            }
        }

        true
    }

    /// Ingests an incoming IPv4 fragment. If all fragments have been received,
    /// returns the reconstructed complete unfragmented payload.
    pub fn add_fragment(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        protocol: u8,
        identification: u16,
        fragment_offset_blocks: u16,
        more_fragments: bool,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let offset_bytes = (fragment_offset_blocks as usize) * 8;
        let fragment_end = offset_bytes.checked_add(payload.len())?;
        if fragment_end > IPV4_MAX_PAYLOAD_LEN {
            // Even with the minimum IPv4 header, this fragment would make the
            // reassembled datagram exceed the 65,535-byte Total Length limit.
            return None;
        }

        let key = FragmentKey {
            src_ip,
            dst_ip,
            protocol,
            identification,
        };

        // Reject inconsistent terminal lengths and conflicting overlaps. Once a
        // datagram has a final fragment, no fragment may extend beyond that end;
        // likewise, a newly arrived final fragment cannot truncate data already
        // accepted for the same reassembly key.
        let invalid = self.buffers.get(&key).is_some_and(|set| {
            let entries = &set.entries;
            let existing_terminal_end = entries
                .iter()
                .filter(|entry| !entry.more_fragments)
                .map(|entry| entry.offset + entry.data.len())
                .next();

            let mut invalid = existing_terminal_end.is_some_and(|terminal_end| {
                fragment_end > terminal_end || (!more_fragments && fragment_end != terminal_end)
            });

            if !more_fragments
                && entries
                    .iter()
                    .any(|entry| entry.offset + entry.data.len() > fragment_end)
            {
                invalid = true;
            }

            for entry in entries {
                let entry_end = entry.offset + entry.data.len();
                let overlap_start = offset_bytes.max(entry.offset);
                let overlap_end = fragment_end.min(entry_end);
                if overlap_start < overlap_end {
                    let incoming_start = overlap_start - offset_bytes;
                    let existing_start = overlap_start - entry.offset;
                    let overlap_len = overlap_end - overlap_start;
                    if payload[incoming_start..incoming_start + overlap_len]
                        != entry.data[existing_start..existing_start + overlap_len]
                    {
                        invalid = true;
                        break;
                    }
                }
            }

            invalid
        });

        if invalid {
            self.remove_buffer(&key);
            return None;
        }

        if !self.make_room_for(&key, payload.len()) {
            return None;
        }

        let last_used = self.next_sequence();
        let entries = &mut self
            .buffers
            .entry(key.clone())
            .or_insert_with(|| FragmentSet {
                entries: Vec::new(),
                last_used,
            })
            .entries;

        entries.push(FragmentEntry {
            offset: offset_bytes,
            data: payload.to_vec(),
            more_fragments,
        });
        self.buffered_bytes += payload.len();

        let set = self
            .buffers
            .get_mut(&key)
            .expect("reassembly set just inserted");
        set.last_used = last_used;
        set.entries.sort_by_key(|entry| entry.offset);

        // Check if contiguous and complete.
        let assembled = if !set.entries.is_empty() && set.entries[0].offset == 0 {
            let mut current_end = 0;
            let mut has_last = false;
            let mut total_len = 0;

            for entry in &set.entries {
                if entry.offset > current_end {
                    // Gap detected -> still incomplete.
                    return None;
                }
                let end = entry.offset + entry.data.len();
                if end > current_end {
                    current_end = end;
                }
                if !entry.more_fragments {
                    has_last = true;
                    total_len = end;
                }
            }

            if has_last && current_end == total_len {
                let mut full_payload = vec![0u8; total_len];
                for entry in &set.entries {
                    let end = entry.offset + entry.data.len();
                    full_payload[entry.offset..end].copy_from_slice(&entry.data);
                }
                Some(full_payload)
            } else {
                None
            }
        } else {
            None
        };

        if assembled.is_some() {
            self.remove_buffer(&key);
        }

        assembled
    }
}

/// Splits a large payload into valid IPv4 fragment packet byte buffers matching MTU.
pub fn fragment_payload(
    src_ip: Ipv4Address,
    dst_ip: Ipv4Address,
    protocol: u8,
    identification: u16,
    ttl: u8,
    mtu: usize,
    payload: &[u8],
) -> Vec<Vec<u8>> {
    let mut fragments = Vec::new();
    let max_header = IPV4_MIN_HEADER_LEN;
    if mtu <= max_header {
        return fragments;
    }

    // Maximum payload per fragment must be multiple of 8 bytes (RFC 791)
    let max_payload = ((mtu - max_header) / 8) * 8;
    if max_payload == 0 {
        return fragments;
    }

    let mut offset = 0;
    while offset < payload.len() {
        let remaining = payload.len() - offset;
        let chunk_len = remaining.min(max_payload);
        let more_fragments = (offset + chunk_len) < payload.len();
        let frag_offset_blocks = (offset / 8) as u16;

        let total_length = (IPV4_MIN_HEADER_LEN + chunk_len) as u16;
        let mut buf = Vec::with_capacity(total_length as usize);

        buf.push(0x45); // Version 4, IHL 5
        buf.push(0x00); // DSCP
        buf.extend_from_slice(&total_length.to_be_bytes());
        buf.extend_from_slice(&identification.to_be_bytes());

        // Flags + Fragment Offset
        let mut flags_offset: u16 = frag_offset_blocks & 0x1FFF;
        if more_fragments {
            flags_offset |= 0x2000; // MF flag
        }
        buf.extend_from_slice(&flags_offset.to_be_bytes());

        buf.push(ttl);
        buf.push(protocol);
        buf.extend_from_slice(&[0x00, 0x00]); // Checksum placeholder
        buf.extend_from_slice(&src_ip.0);
        buf.extend_from_slice(&dst_ip.0);

        let csum = crate::checksum::compute_checksum(&buf[0..IPV4_MIN_HEADER_LEN]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        buf.extend_from_slice(&payload[offset..offset + chunk_len]);
        fragments.push(buf);

        offset += chunk_len;
    }

    fragments
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> Ipv4Address {
        Ipv4Address::new(192, 0, 2, 1)
    }

    fn dst() -> Ipv4Address {
        Ipv4Address::new(198, 51, 100, 1)
    }

    #[test]
    fn reassembly_rejects_fragment_beyond_ipv4_datagram_limit_without_poisoning_key() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0x1234;

        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 8191, false, &[0u8; 8]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[1u8; 8]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, false, &[2u8; 8]),
            Some([&[1u8; 8][..], &[2u8; 8][..]].concat())
        );
    }

    #[test]
    fn reassembly_accepts_maximum_ipv4_payload_boundary() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0x5678;
        let prefix_len = 8189 * 8;
        let prefix = vec![0xa5; prefix_len];
        let tail = [0xde, 0xad, 0xbe];

        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &prefix),
            None
        );
        let assembled = reassembly
            .add_fragment(src(), dst(), 17, id, 8189, false, &tail)
            .expect("maximum legal IPv4 payload should reassemble");

        assert_eq!(assembled.len(), IPV4_MAX_PAYLOAD_LEN);
        assert_eq!(&assembled[..prefix_len], prefix.as_slice());
        assert_eq!(&assembled[prefix_len..], &tail);
    }

    #[test]
    fn reassembly_rejects_final_fragment_that_truncates_existing_data_without_panicking() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0x9abc;

        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[1u8; 16]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, false, &[2u8; 4]),
            None
        );

        // The malformed datagram is discarded, so the same key remains reusable.
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[3u8; 8]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, false, &[4u8; 8]),
            Some([&[3u8; 8][..], &[4u8; 8][..]].concat())
        );
    }

    #[test]
    fn reassembly_rejects_conflicting_overlap_and_discards_datagram() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0xdef0;

        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[1u8; 16]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, true, &[2u8; 8]),
            None
        );

        // Conflicting overlap clears the poisoned key; a clean datagram can follow.
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[5u8; 8]),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, false, &[6u8; 8]),
            Some([&[5u8; 8][..], &[6u8; 8][..]].concat())
        );
    }

    #[test]
    fn reassembly_accepts_identical_overlap() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0x1357;
        let first = [1u8; 16];
        let overlap = [1u8; 8];
        let tail = [2u8; 8];

        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &first),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 1, true, &overlap),
            None
        );
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 2, false, &tail),
            Some([&first[..], &tail[..]].concat())
        );
    }

    #[test]
    fn reassembly_evicts_oldest_datagram_when_key_limit_is_reached() {
        let mut reassembly = IpReassemblyBuffer::new();

        for id in 0..=MAX_REASSEMBLY_DATAGRAMS as u16 {
            assert_eq!(
                reassembly.add_fragment(src(), dst(), 17, id, 0, true, &[id as u8; 8]),
                None
            );
        }

        // A newer incomplete datagram is retained and can complete.
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, 1, 1, false, &[0xaa; 8]),
            Some([&[1u8; 8][..], &[0xaa; 8][..]].concat())
        );

        // The oldest key was evicted, so its tail alone cannot complete it.
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, 0, 1, false, &[0xbb; 8]),
            None
        );
    }

    #[test]
    fn reassembly_bounds_identical_overlap_memory() {
        let mut reassembly = IpReassemblyBuffer::new();
        let id = 0x2468;
        let fragment = vec![0x5a; 65_512];

        for _ in 0..64 {
            assert_eq!(
                reassembly.add_fragment(src(), dst(), 17, id, 0, true, &fragment),
                None
            );
        }
        assert!(reassembly.buffered_bytes <= MAX_REASSEMBLY_BYTES);

        // One more identical fragment cannot make the buffer grow past the cap.
        assert_eq!(
            reassembly.add_fragment(src(), dst(), 17, id, 0, true, &fragment),
            None
        );
        assert!(reassembly.buffered_bytes <= MAX_REASSEMBLY_BYTES);
        assert!(reassembly.buffers.len() <= MAX_REASSEMBLY_DATAGRAMS);
    }
}
