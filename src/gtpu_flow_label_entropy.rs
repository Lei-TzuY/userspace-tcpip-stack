//! 3GPP TS 29.281 / RFC 6437 5G GTP-U Outer IPv6 Flow Label Entropy & ECMP Hashing Engine
//!
//! Computes pseudo-random, uniform 20-bit IPv6 Flow Labels from inner packet 5-tuples,
//! TEID, and QFI to maximize Equal-Cost Multi-Path (ECMP) and Link Aggregation (LAG)
//! distribution across datacenter IP underlays without deep packet inspection.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowLabelAlgorithm {
    Fnv1aEntropy,
    Crc32Entropy,
    JenkinsEntropy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InnerPacketTuple {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub teid: u32,
    pub qfi: u8,
}

impl InnerPacketTuple {
    pub fn new(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        teid: u32,
        qfi: u8,
    ) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            teid,
            qfi,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowLabelVerdict {
    pub flow_label_20bit: u32,
    pub inner_hash: u32,
    pub ecmp_bin: u16,
    pub algorithm: FlowLabelAlgorithm,
}

#[derive(Debug, Clone)]
pub struct GtpuFlowLabelEntropyEngine {
    pub algorithm: FlowLabelAlgorithm,
    pub ecmp_buckets: u16,
    pub total_computations: usize,
    pub bucket_counts: Vec<usize>,
}

impl GtpuFlowLabelEntropyEngine {
    pub fn new(algorithm: FlowLabelAlgorithm, ecmp_buckets: u16) -> Self {
        let buckets = ecmp_buckets.max(1);
        Self {
            algorithm,
            ecmp_buckets: buckets,
            total_computations: 0,
            bucket_counts: vec![0; buckets as usize],
        }
    }

    /// Computes the 20-bit Flow Label (0x00000..0xFFFFF) and ECMP bin assignment.
    pub fn compute_flow_label(&mut self, tuple: &InnerPacketTuple) -> FlowLabelVerdict {
        self.total_computations += 1;

        let hash = match self.algorithm {
            FlowLabelAlgorithm::Fnv1aEntropy => Self::hash_fnv1a(tuple),
            FlowLabelAlgorithm::Crc32Entropy => Self::hash_crc32(tuple),
            FlowLabelAlgorithm::JenkinsEntropy => Self::hash_jenkins(tuple),
        };

        // Mask to 20 bits (RFC 6437 / RFC 8200 Flow Label field)
        // Ensure non-zero according to RFC 6437 if hash produces 0
        let flow_label_20bit = (hash & 0x000F_FFFF).max(1);
        let ecmp_bin = (hash % self.ecmp_buckets as u32) as u16;

        self.bucket_counts[ecmp_bin as usize] += 1;

        FlowLabelVerdict {
            flow_label_20bit,
            inner_hash: hash,
            ecmp_bin,
            algorithm: self.algorithm,
        }
    }

    fn hash_fnv1a(t: &InnerPacketTuple) -> u32 {
        let mut h: u32 = 0x811C9DC5;
        let bytes: [u8; 19] = [
            t.src_ip[0],
            t.src_ip[1],
            t.src_ip[2],
            t.src_ip[3],
            t.dst_ip[0],
            t.dst_ip[1],
            t.dst_ip[2],
            t.dst_ip[3],
            (t.src_port >> 8) as u8,
            (t.src_port & 0xFF) as u8,
            (t.dst_port >> 8) as u8,
            (t.dst_port & 0xFF) as u8,
            t.protocol,
            (t.teid >> 24) as u8,
            (t.teid >> 16) as u8,
            (t.teid >> 8) as u8,
            (t.teid & 0xFF) as u8,
            t.qfi,
            0xA5,
        ];
        for &b in &bytes {
            h ^= b as u32;
            h = h.wrapping_mul(0x01000193);
        }
        h
    }

    fn hash_crc32(t: &InnerPacketTuple) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        let bytes: [u8; 18] = [
            t.src_ip[0],
            t.src_ip[1],
            t.src_ip[2],
            t.src_ip[3],
            t.dst_ip[0],
            t.dst_ip[1],
            t.dst_ip[2],
            t.dst_ip[3],
            (t.src_port >> 8) as u8,
            (t.src_port & 0xFF) as u8,
            (t.dst_port >> 8) as u8,
            (t.dst_port & 0xFF) as u8,
            t.protocol,
            (t.teid >> 24) as u8,
            (t.teid >> 16) as u8,
            (t.teid >> 8) as u8,
            (t.teid & 0xFF) as u8,
            t.qfi,
        ];
        for &b in &bytes {
            crc ^= b as u32;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xEDB88320;
                } else {
                    crc >>= 1;
                }
            }
        }
        !crc
    }

    fn hash_jenkins(t: &InnerPacketTuple) -> u32 {
        let mut a: u32 = u32::from_be_bytes(t.src_ip);
        let mut b: u32 = u32::from_be_bytes(t.dst_ip);
        let mut c: u32 = ((t.src_port as u32) << 16) | (t.dst_port as u32);

        a = a.wrapping_add(t.teid);
        b = b.wrapping_add(((t.protocol as u32) << 8) | (t.qfi as u32));
        c = c.wrapping_add(0xdeadbeef);

        // Mix 3 words
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(4);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(6);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(8);
        b = b.wrapping_add(a);
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(16);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(19);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(4);
        c = c.wrapping_add(a);

        c
    }

    /// Resets all statistics and bucket assignments.
    pub fn reset(&mut self) {
        self.total_computations = 0;
        self.bucket_counts.fill(0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtpu_flow_label_entropy_lifecycle() {
        let mut engine = GtpuFlowLabelEntropyEngine::new(FlowLabelAlgorithm::Fnv1aEntropy, 8);

        // Stream 1: User 1 web traffic
        let t1 = InnerPacketTuple::new([10, 0, 0, 1], [192, 168, 1, 1], 54321, 443, 6, 0x10001, 9);

        let v1 = engine.compute_flow_label(&t1);
        assert!(v1.flow_label_20bit <= 0x000F_FFFF);
        assert!(v1.ecmp_bin < 8);

        // Deterministic repeat
        let v1_dup = engine.compute_flow_label(&t1);
        assert_eq!(v1.flow_label_20bit, v1_dup.flow_label_20bit);
        assert_eq!(v1.ecmp_bin, v1_dup.ecmp_bin);

        // Stream 2: User 2 video traffic with different TEID/QFI
        let t2 = InnerPacketTuple::new([10, 0, 0, 2], [192, 168, 1, 2], 54322, 443, 6, 0x20002, 5);
        let v2 = engine.compute_flow_label(&t2);
        assert!(v2.flow_label_20bit <= 0x000F_FFFF);

        // Switch to Jenkins
        engine.algorithm = FlowLabelAlgorithm::JenkinsEntropy;
        let v3 = engine.compute_flow_label(&t1);
        assert!(v3.flow_label_20bit <= 0x000F_FFFF);

        // Switch to CRC32
        engine.algorithm = FlowLabelAlgorithm::Crc32Entropy;
        let v4 = engine.compute_flow_label(&t1);
        assert!(v4.flow_label_20bit <= 0x000F_FFFF);

        assert_eq!(engine.total_computations, 5);
    }
}
