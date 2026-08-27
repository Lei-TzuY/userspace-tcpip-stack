//! sFlow v5 Network Flow Telemetry & Packet Sampling (RFC 3176).
//!
//! Multi-vendor high-speed hardware packet sampling and interface counter exporter over UDP port 6343.

use crate::ipv4::Ipv4Address;
use std::fmt;

pub const SFLOW_UDP_PORT: u16 = 6343;
pub const SFLOW_VERSION_5: u32 = 5;

// Sample Format Codes
pub const SFLOW_FORMAT_FLOW_SAMPLE: u32 = 1;
pub const SFLOW_FORMAT_COUNTER_SAMPLE: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SflowFlowSample {
    pub seq_num: u32,
    pub source_id: u32,
    pub sampling_rate: u32,
    pub sample_pool: u32,
    pub drops: u32,
    pub input_if: u32,
    pub output_if: u32,
    pub orig_packet_len: u32,
    pub sampled_header: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SflowCounterSample {
    pub seq_num: u32,
    pub source_id: u32,
    pub if_index: u32,
    pub if_speed_bps: u64,
    pub in_octets: u64,
    pub in_packets: u32,
    pub out_octets: u64,
    pub out_packets: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SflowSample {
    Flow(SflowFlowSample),
    Counter(SflowCounterSample),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SflowDatagram {
    pub version: u32,
    pub agent_ip: Ipv4Address,
    pub sub_agent_id: u32,
    pub seq_num: u32,
    pub uptime_ms: u32,
    pub samples: Vec<SflowSample>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SflowError {
    PacketTooShort(usize),
    UnsupportedVersion(u32),
    InvalidLength,
}

impl fmt::Display for SflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SflowError::PacketTooShort(l) => write!(f, "sFlow datagram too short ({} bytes)", l),
            SflowError::UnsupportedVersion(v) => write!(f, "Unsupported sFlow version: {}", v),
            SflowError::InvalidLength => write!(f, "Invalid sFlow sample length"),
        }
    }
}

impl std::error::Error for SflowError {}

impl SflowDatagram {
    pub fn new(agent_ip: Ipv4Address, seq_num: u32, uptime_ms: u32) -> Self {
        SflowDatagram {
            version: SFLOW_VERSION_5,
            agent_ip,
            sub_agent_id: 0,
            seq_num,
            uptime_ms,
            samples: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.version.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes()); // Agent Address Type = 1 (IPv4)
        buf.extend_from_slice(&self.agent_ip.0);
        buf.extend_from_slice(&self.sub_agent_id.to_be_bytes());
        buf.extend_from_slice(&self.seq_num.to_be_bytes());
        buf.extend_from_slice(&self.uptime_ms.to_be_bytes());
        buf.extend_from_slice(&(self.samples.len() as u32).to_be_bytes());

        for s in &self.samples {
            match s {
                SflowSample::Flow(f) => {
                    buf.extend_from_slice(&SFLOW_FORMAT_FLOW_SAMPLE.to_be_bytes());
                    let mut s_buf = Vec::new();
                    s_buf.extend_from_slice(&f.seq_num.to_be_bytes());
                    s_buf.extend_from_slice(&f.source_id.to_be_bytes());
                    s_buf.extend_from_slice(&f.sampling_rate.to_be_bytes());
                    s_buf.extend_from_slice(&f.sample_pool.to_be_bytes());
                    s_buf.extend_from_slice(&f.drops.to_be_bytes());
                    s_buf.extend_from_slice(&f.input_if.to_be_bytes());
                    s_buf.extend_from_slice(&f.output_if.to_be_bytes());
                    s_buf.extend_from_slice(&1u32.to_be_bytes()); // 1 Flow Record (Raw Packet Header)

                    // Raw Header Record
                    s_buf.extend_from_slice(&1u32.to_be_bytes()); // Format 1 (Raw Header)
                    let mut h_buf = Vec::new();
                    h_buf.extend_from_slice(&1u32.to_be_bytes()); // Header Protocol = 1 (Ethernet)
                    h_buf.extend_from_slice(&f.orig_packet_len.to_be_bytes());
                    h_buf.extend_from_slice(&0u32.to_be_bytes()); // Stripped octets
                    h_buf.extend_from_slice(&(f.sampled_header.len() as u32).to_be_bytes());
                    h_buf.extend_from_slice(&f.sampled_header);
                    while h_buf.len() % 4 != 0 {
                        h_buf.push(0x00);
                    }

                    s_buf.extend_from_slice(&(h_buf.len() as u32).to_be_bytes());
                    s_buf.extend_from_slice(&h_buf);

                    buf.extend_from_slice(&(s_buf.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&s_buf);
                }
                SflowSample::Counter(c) => {
                    buf.extend_from_slice(&SFLOW_FORMAT_COUNTER_SAMPLE.to_be_bytes());
                    let mut s_buf = Vec::new();
                    s_buf.extend_from_slice(&c.seq_num.to_be_bytes());
                    s_buf.extend_from_slice(&c.source_id.to_be_bytes());
                    s_buf.extend_from_slice(&1u32.to_be_bytes()); // 1 Counter Record (Generic Interface)

                    // Generic Interface Counter Record (Format 1)
                    s_buf.extend_from_slice(&1u32.to_be_bytes());
                    let mut c_buf = Vec::new();
                    c_buf.extend_from_slice(&c.if_index.to_be_bytes());
                    c_buf.extend_from_slice(&6u32.to_be_bytes()); // ifType = 6 (ethernetCsmacd)
                    c_buf.extend_from_slice(&c.if_speed_bps.to_be_bytes());
                    c_buf.extend_from_slice(&1u32.to_be_bytes()); // ifDirection = 1 (full-duplex)
                    c_buf.extend_from_slice(&3u32.to_be_bytes()); // ifStatus = 3 (admin-up / oper-up)
                    c_buf.extend_from_slice(&c.in_octets.to_be_bytes());
                    c_buf.extend_from_slice(&c.in_packets.to_be_bytes());
                    c_buf.extend_from_slice(&0u32.to_be_bytes()); // in_multicast
                    c_buf.extend_from_slice(&0u32.to_be_bytes()); // in_broadcast
                    c_buf.extend_from_slice(&0u32.to_be_bytes()); // in_discards
                    c_buf.extend_from_slice(&0u32.to_be_bytes()); // in_errors
                    c_buf.extend_from_slice(&c.out_octets.to_be_bytes());
                    c_buf.extend_from_slice(&c.out_packets.to_be_bytes());

                    s_buf.extend_from_slice(&(c_buf.len() as u32).to_be_bytes());
                    s_buf.extend_from_slice(&c_buf);

                    buf.extend_from_slice(&(s_buf.len() as u32).to_be_bytes());
                    buf.extend_from_slice(&s_buf);
                }
            }
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, SflowError> {
        if data.len() < 28 {
            return Err(SflowError::PacketTooShort(data.len()));
        }

        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if version != SFLOW_VERSION_5 {
            return Err(SflowError::UnsupportedVersion(version));
        }

        let agent_ip = Ipv4Address([data[8], data[9], data[10], data[11]]);
        let sub_agent_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let seq_num = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let uptime_ms = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let samples_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]) as usize;

        let mut samples = Vec::new();
        let mut offset = 28;

        for _ in 0..samples_count {
            if data.len() - offset < 8 {
                return Err(SflowError::InvalidLength);
            }
            let sample_type = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let sample_len = u32::from_be_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;
            offset += 8;

            if sample_len > data.len() - offset {
                return Err(SflowError::InvalidLength);
            }

            let s_data = &data[offset..offset + sample_len];
            if sample_type == SFLOW_FORMAT_FLOW_SAMPLE && s_data.len() >= 32 {
                let s_seq = u32::from_be_bytes([s_data[0], s_data[1], s_data[2], s_data[3]]);
                let source_id = u32::from_be_bytes([s_data[4], s_data[5], s_data[6], s_data[7]]);
                let rate = u32::from_be_bytes([s_data[8], s_data[9], s_data[10], s_data[11]]);
                let pool = u32::from_be_bytes([s_data[12], s_data[13], s_data[14], s_data[15]]);
                let drops = u32::from_be_bytes([s_data[16], s_data[17], s_data[18], s_data[19]]);
                let in_if = u32::from_be_bytes([s_data[20], s_data[21], s_data[22], s_data[23]]);
                let out_if = u32::from_be_bytes([s_data[24], s_data[25], s_data[26], s_data[27]]);

                // Raw header record offset
                if s_data.len() >= 56 {
                    let orig_len =
                        u32::from_be_bytes([s_data[44], s_data[45], s_data[46], s_data[47]]);
                    let hdr_len =
                        u32::from_be_bytes([s_data[52], s_data[53], s_data[54], s_data[55]])
                            as usize;
                    let sampled_hdr = if 56 + hdr_len <= s_data.len() {
                        s_data[56..56 + hdr_len].to_vec()
                    } else {
                        Vec::new()
                    };

                    samples.push(SflowSample::Flow(SflowFlowSample {
                        seq_num: s_seq,
                        source_id,
                        sampling_rate: rate,
                        sample_pool: pool,
                        drops,
                        input_if: in_if,
                        output_if: out_if,
                        orig_packet_len: orig_len,
                        sampled_header: sampled_hdr,
                    }));
                }
            } else if sample_type == SFLOW_FORMAT_COUNTER_SAMPLE && s_data.len() >= 84 {
                let s_seq = u32::from_be_bytes([s_data[0], s_data[1], s_data[2], s_data[3]]);
                let source_id = u32::from_be_bytes([s_data[4], s_data[5], s_data[6], s_data[7]]);
                let if_index = u32::from_be_bytes([s_data[20], s_data[21], s_data[22], s_data[23]]);
                let if_speed_bps = u64::from_be_bytes([
                    s_data[28], s_data[29], s_data[30], s_data[31], s_data[32], s_data[33],
                    s_data[34], s_data[35],
                ]);
                let in_octets = u64::from_be_bytes([
                    s_data[44], s_data[45], s_data[46], s_data[47], s_data[48], s_data[49],
                    s_data[50], s_data[51],
                ]);
                let in_packets =
                    u32::from_be_bytes([s_data[52], s_data[53], s_data[54], s_data[55]]);
                let out_octets = u64::from_be_bytes([
                    s_data[72], s_data[73], s_data[74], s_data[75], s_data[76], s_data[77],
                    s_data[78], s_data[79],
                ]);
                let out_packets =
                    u32::from_be_bytes([s_data[80], s_data[81], s_data[82], s_data[83]]);

                samples.push(SflowSample::Counter(SflowCounterSample {
                    seq_num: s_seq,
                    source_id,
                    if_index,
                    if_speed_bps,
                    in_octets,
                    in_packets,
                    out_octets,
                    out_packets,
                }));
            }

            offset += sample_len;
        }

        Ok(SflowDatagram {
            version,
            agent_ip,
            sub_agent_id,
            seq_num,
            uptime_ms,
            samples,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sflow_flow_and_counter_roundtrip() {
        let agent_ip = Ipv4Address::new(10, 0, 0, 1);
        let mut dgram = SflowDatagram::new(agent_ip, 1, 360000);

        let flow = SflowFlowSample {
            seq_num: 101,
            source_id: 1,
            sampling_rate: 1000,
            sample_pool: 50000,
            drops: 0,
            input_if: 1,
            output_if: 2,
            orig_packet_len: 128,
            sampled_header: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        };
        dgram.samples.push(SflowSample::Flow(flow));

        let counter = SflowCounterSample {
            seq_num: 201,
            source_id: 1,
            if_index: 1,
            if_speed_bps: 10_000_000_000,
            in_octets: 1024000,
            in_packets: 1500,
            out_octets: 512000,
            out_packets: 800,
        };
        dgram.samples.push(SflowSample::Counter(counter));

        let raw = dgram.serialize();
        assert!(raw.len() >= 28);

        let parsed = SflowDatagram::parse(&raw).unwrap();
        assert_eq!(parsed.version, 5);
        assert_eq!(parsed.agent_ip, agent_ip);
        assert_eq!(parsed.samples.len(), 2);
        assert_eq!(SFLOW_UDP_PORT, 6343);
    }
}
