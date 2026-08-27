//! IPv4 Packet Fragmentation and Reassembly (RFC 791).
//!
//! Handles splitting oversized IPv4 packets into $\le \text{MTU}$ fragments
//! (aligned to 8-byte boundaries) and reassembling out-of-order IP fragments.

use crate::ipv4::{IPV4_MIN_HEADER_LEN, Ipv4Address};
use std::collections::HashMap;

const IPV4_MAX_PAYLOAD_LEN: usize = u16::MAX as usize - IPV4_MIN_HEADER_LEN;

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
pub struct IpReassemblyBuffer {
    buffers: HashMap<FragmentKey, Vec<FragmentEntry>>,
}

impl IpReassemblyBuffer {
    pub fn new() -> Self {
        IpReassemblyBuffer {
            buffers: HashMap::new(),
        }
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

        let entries = self.buffers.entry(key.clone()).or_default();
        entries.push(FragmentEntry {
            offset: offset_bytes,
            data: payload.to_vec(),
            more_fragments,
        });

        // Sort by offset
        entries.sort_by_key(|e| e.offset);

        // Check if contiguous and complete
        if !entries.is_empty() && entries[0].offset == 0 {
            let mut current_end = 0;
            let mut has_last = false;
            let mut total_len = 0;

            for entry in entries.iter() {
                if entry.offset > current_end {
                    // Gap detected -> still incomplete
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

            if has_last && current_end >= total_len {
                // Fully reassembled! Assemble bytes.
                let mut full_payload = vec![0u8; total_len];
                for entry in entries.iter() {
                    let end = entry.offset + entry.data.len();
                    full_payload[entry.offset..end].copy_from_slice(&entry.data);
                }
                self.buffers.remove(&key);
                return Some(full_payload);
            }
        }

        None
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
}
