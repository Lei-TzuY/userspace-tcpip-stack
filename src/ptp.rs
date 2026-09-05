//! Precision Time Protocol (IEEE 1588v2 PTP).
//!
//! Sub-microsecond / nanosecond hardware and software clock synchronization across local networks.

use std::fmt;

pub const PTP_EVENT_PORT: u16 = 319;
pub const PTP_GENERAL_PORT: u16 = 320;
pub const ETHERTYPE_PTP: u16 = 0x88F7;
pub const PTP_HEADER_LEN: usize = 34;

// PTP Message Types (IEEE 1588-2008 Table 19)
pub const PTP_MSG_SYNC: u8 = 0x0;
pub const PTP_MSG_DELAY_REQ: u8 = 0x1;
pub const PTP_MSG_FOLLOW_UP: u8 = 0x8;
pub const PTP_MSG_DELAY_RESP: u8 = 0x9;
pub const PTP_MSG_ANNOUNCE: u8 = 0xB;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PtpTimestamp {
    pub seconds: u64, // 48-bit integer in PTP
    pub nanoseconds: u32,
}

impl PtpTimestamp {
    pub fn new(seconds: u64, nanoseconds: u32) -> Self {
        PtpTimestamp {
            seconds,
            nanoseconds,
        }
    }

    pub fn to_total_nanoseconds(&self) -> i128 {
        (self.seconds as i128) * 1_000_000_000 + (self.nanoseconds as i128)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtpHeader {
    pub message_type: u8,
    pub version: u8,
    pub message_length: u16,
    pub domain_number: u8,
    pub flags: u16,
    pub correction_field: i64,
    pub clock_identity: [u8; 8],
    pub source_port_id: u16,
    pub sequence_id: u16,
    pub control_field: u8,
    pub log_message_interval: i8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtpPacket {
    pub header: PtpHeader,
    pub origin_timestamp: Option<PtpTimestamp>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtpError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidMessageLength { declared: u16, available: usize },
    InvalidTimestampNanoseconds(u32),
}

impl fmt::Display for PtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PtpError::PacketTooShort(l) => write!(f, "PTP packet too short ({} bytes)", l),
            PtpError::InvalidVersion(v) => write!(f, "Invalid PTP version: {}", v),
            PtpError::InvalidMessageLength {
                declared,
                available,
            } => write!(
                f,
                "Invalid PTP message length: declared {}, available {}",
                declared, available
            ),
            PtpError::InvalidTimestampNanoseconds(ns) => {
                write!(f, "Invalid PTP timestamp nanoseconds: {}", ns)
            }
        }
    }
}

impl std::error::Error for PtpError {}

impl PtpPacket {
    pub fn build_sync(clock_id: [u8; 8], seq_id: u16, ts: PtpTimestamp) -> Self {
        let header = PtpHeader {
            message_type: PTP_MSG_SYNC,
            version: 2,
            message_length: 44, // 34-byte header + 10-byte timestamp
            domain_number: 0,
            flags: 0x0200, // Two-step flag
            correction_field: 0,
            clock_identity: clock_id,
            source_port_id: 1,
            sequence_id: seq_id,
            control_field: 0x00, // Sync
            log_message_interval: 0,
        };

        PtpPacket {
            header,
            origin_timestamp: Some(ts),
            payload: Vec::new(),
        }
    }

    pub fn build_follow_up(clock_id: [u8; 8], seq_id: u16, precise_ts: PtpTimestamp) -> Self {
        let header = PtpHeader {
            message_type: PTP_MSG_FOLLOW_UP,
            version: 2,
            message_length: 44,
            domain_number: 0,
            flags: 0,
            correction_field: 0,
            clock_identity: clock_id,
            source_port_id: 1,
            sequence_id: seq_id,
            control_field: 0x02, // Follow_Up
            log_message_interval: 0,
        };

        PtpPacket {
            header,
            origin_timestamp: Some(precise_ts),
            payload: Vec::new(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let b0 = self.header.message_type & 0x0F;
        let b1 = self.header.version & 0x0F;
        buf.push(b0);
        buf.push(b1);
        buf.extend_from_slice(&self.header.message_length.to_be_bytes());
        buf.push(self.header.domain_number);
        buf.push(0x00); // Reserved
        buf.extend_from_slice(&self.header.flags.to_be_bytes());
        buf.extend_from_slice(&self.header.correction_field.to_be_bytes());
        buf.extend_from_slice(&[0u8; 4]); // Reserved
        buf.extend_from_slice(&self.header.clock_identity);
        buf.extend_from_slice(&self.header.source_port_id.to_be_bytes());
        buf.extend_from_slice(&self.header.sequence_id.to_be_bytes());
        buf.push(self.header.control_field);
        buf.push(self.header.log_message_interval as u8);

        if let Some(ts) = self.origin_timestamp {
            // 48-bit (6 bytes) seconds + 32-bit (4 bytes) nanoseconds
            let sec_bytes = ts.seconds.to_be_bytes();
            buf.extend_from_slice(&sec_bytes[2..8]); // Lower 6 bytes
            buf.extend_from_slice(&ts.nanoseconds.to_be_bytes());
        }

        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, PtpError> {
        if data.len() < PTP_HEADER_LEN {
            return Err(PtpError::PacketTooShort(data.len()));
        }

        let message_type = data[0] & 0x0F;
        let version = data[1] & 0x0F;
        if version != 2 {
            return Err(PtpError::InvalidVersion(version));
        }

        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let declared_len = message_length as usize;
        if declared_len < PTP_HEADER_LEN || declared_len > data.len() {
            return Err(PtpError::InvalidMessageLength {
                declared: message_length,
                available: data.len(),
            });
        }
        let frame = &data[..declared_len];

        let domain_number = frame[4];
        let flags = u16::from_be_bytes([frame[6], frame[7]]);
        let correction_field = i64::from_be_bytes([
            frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
        ]);

        let mut clock_identity = [0u8; 8];
        clock_identity.copy_from_slice(&frame[20..28]);
        let source_port_id = u16::from_be_bytes([frame[28], frame[29]]);
        let sequence_id = u16::from_be_bytes([frame[30], frame[31]]);
        let control_field = frame[32];
        let log_message_interval = frame[33] as i8;

        let header = PtpHeader {
            message_type,
            version,
            message_length,
            domain_number,
            flags,
            correction_field,
            clock_identity,
            source_port_id,
            sequence_id,
            control_field,
            log_message_interval,
        };

        let mut origin_timestamp = None;
        let mut offset = PTP_HEADER_LEN;

        if frame.len() >= offset + 10 {
            let mut sec_buf = [0u8; 8];
            sec_buf[2..8].copy_from_slice(&frame[offset..offset + 6]);
            let seconds = u64::from_be_bytes(sec_buf);
            let nanoseconds = u32::from_be_bytes([
                frame[offset + 6],
                frame[offset + 7],
                frame[offset + 8],
                frame[offset + 9],
            ]);
            if nanoseconds >= 1_000_000_000 {
                return Err(PtpError::InvalidTimestampNanoseconds(nanoseconds));
            }
            origin_timestamp = Some(PtpTimestamp {
                seconds,
                nanoseconds,
            });
            offset += 10;
        }

        let payload = if offset < frame.len() {
            frame[offset..].to_vec()
        } else {
            Vec::new()
        };

        Ok(PtpPacket {
            header,
            origin_timestamp,
            payload,
        })
    }
}

/// Calculate PTP Offset and Mean Path Delay in nanoseconds:
/// Offset: ((t2 - t1) - (t4 - t3)) / 2
/// Mean Path Delay: ((t2 - t1) + (t4 - t3)) / 2
pub fn calculate_ptp_offset_and_delay(
    t1: PtpTimestamp,
    t2: PtpTimestamp,
    t3: PtpTimestamp,
    t4: PtpTimestamp,
) -> (i64, i64) {
    let t1_ns = t1.to_total_nanoseconds();
    let t2_ns = t2.to_total_nanoseconds();
    let t3_ns = t3.to_total_nanoseconds();
    let t4_ns = t4.to_total_nanoseconds();

    let m_to_s = t2_ns - t1_ns;
    let s_to_m = t4_ns - t3_ns;

    let offset_ns = (m_to_s - s_to_m) / 2;
    let delay_ns = (m_to_s + s_to_m) / 2;

    (offset_ns as i64, delay_ns as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ptp_sync_packet_roundtrip() {
        let clock_id = [0x00, 0x11, 0x22, 0xFF, 0xFE, 0x33, 0x44, 0x55];
        let ts = PtpTimestamp::new(1700000000, 500_000_000);
        let sync = PtpPacket::build_sync(clock_id, 42, ts);
        let raw = sync.serialize();

        assert_eq!(raw.len(), 44);
        let parsed = PtpPacket::parse(&raw).unwrap();

        assert_eq!(parsed.header.message_type, PTP_MSG_SYNC);
        assert_eq!(parsed.header.sequence_id, 42);
        assert_eq!(parsed.header.clock_identity, clock_id);
        let parsed_ts = parsed.origin_timestamp.unwrap();
        assert_eq!(parsed_ts.seconds, 1700000000);
        assert_eq!(parsed_ts.nanoseconds, 500_000_000);
    }

    #[test]
    fn test_ptp_clock_offset_calculation() {
        let t1 = PtpTimestamp::new(100, 0);
        let t2 = PtpTimestamp::new(100, 100); // 100ns master-to-slave delay
        let t3 = PtpTimestamp::new(100, 200);
        let t4 = PtpTimestamp::new(100, 300); // 100ns slave-to-master delay

        let (offset, delay) = calculate_ptp_offset_and_delay(t1, t2, t3, t4);
        assert_eq!(offset, 0); // Synchronized
        assert_eq!(delay, 100); // 100ns path delay
    }

    #[test]
    fn test_ptp_rejects_declared_length_below_header() {
        let sync = PtpPacket::build_sync([0; 8], 1, PtpTimestamp::new(1, 0));
        let mut raw = sync.serialize();
        raw[2..4].copy_from_slice(&(PTP_HEADER_LEN as u16 - 1).to_be_bytes());

        assert_eq!(
            PtpPacket::parse(&raw),
            Err(PtpError::InvalidMessageLength {
                declared: PTP_HEADER_LEN as u16 - 1,
                available: raw.len(),
            })
        );
    }

    #[test]
    fn test_ptp_rejects_truncated_declared_frame() {
        let sync = PtpPacket::build_sync([0; 8], 2, PtpTimestamp::new(1, 0));
        let mut raw = sync.serialize();
        let declared = raw.len() as u16 + 1;
        raw[2..4].copy_from_slice(&declared.to_be_bytes());

        assert_eq!(
            PtpPacket::parse(&raw),
            Err(PtpError::InvalidMessageLength {
                declared,
                available: raw.len(),
            })
        );
    }

    #[test]
    fn test_ptp_ignores_transport_bytes_beyond_declared_message() {
        let sync = PtpPacket::build_sync([0; 8], 3, PtpTimestamp::new(1, 123));
        let mut raw = sync.serialize();
        raw.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

        let parsed = PtpPacket::parse(&raw).unwrap();
        assert_eq!(parsed.header.message_length, 44);
        assert_eq!(parsed.origin_timestamp.unwrap().nanoseconds, 123);
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_ptp_rejects_invalid_timestamp_nanoseconds() {
        let sync = PtpPacket::build_sync([0; 8], 4, PtpTimestamp::new(1, 0));
        let mut raw = sync.serialize();
        raw[40..44].copy_from_slice(&1_000_000_000u32.to_be_bytes());

        assert_eq!(
            PtpPacket::parse(&raw),
            Err(PtpError::InvalidTimestampNanoseconds(1_000_000_000))
        );
    }
}
