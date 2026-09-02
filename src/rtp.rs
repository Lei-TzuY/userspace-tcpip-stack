//! Real-time Transport Protocol (RTP) & RTCP (RFC 3550).
//!
//! Real-time audio and video streaming transport over UDP.

use std::fmt;

pub const RTP_FIXED_HEADER_LEN: usize = 12;

// Standard RTP Payload Types
pub const RTP_PT_PCMU: u8 = 0; // G.711 mu-law audio, 8000 Hz
pub const RTP_PT_PCMA: u8 = 8; // G.711 A-law audio, 8000 Hz
pub const RTP_PT_DYNAMIC: u8 = 96; // Dynamic payload type (e.g., Opus / H.264)

// RTCP Packet Types
pub const RTCP_PT_SR: u8 = 200; // Sender Report
pub const RTCP_PT_RR: u8 = 201; // Receiver Report
pub const RTCP_PT_SDES: u8 = 202; // Source Description
pub const RTCP_PT_BYE: u8 = 203; // Goodbye

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrc_list: Vec<u32>,
    /// RFC 3550 section 5.3.1 profile identifier when the X bit is set.
    pub extension_profile: Option<u16>,
    /// Raw header-extension body, excluding the 4-byte extension preamble.
    /// The serialized form is padded with zero octets to a 32-bit boundary.
    pub extension_data: Vec<u8>,
    /// Number of RTP padding octets, including the terminal count octet.
    /// A value of zero means no padding.
    pub padding_len: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtcpSenderReport {
    pub ssrc: u32,
    pub ntp_timestamp: u64,
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtpError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    TruncatedExtension,
    InvalidPadding(u8),
}

impl fmt::Display for RtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RtpError::PacketTooShort(l) => write!(f, "RTP packet too short ({} bytes)", l),
            RtpError::InvalidVersion(v) => {
                write!(f, "Invalid RTP version: expected 2, found {}", v)
            }
            RtpError::TruncatedExtension => write!(f, "RTP header extension is truncated"),
            RtpError::InvalidPadding(count) => {
                write!(f, "Invalid RTP padding count: {}", count)
            }
        }
    }
}

impl std::error::Error for RtpError {}

impl RtpPacket {
    pub fn build_audio(
        pt: u8,
        seq: u16,
        timestamp: u32,
        ssrc: u32,
        marker: bool,
        audio_data: &[u8],
    ) -> Self {
        RtpPacket {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker,
            payload_type: pt & 0x7F,
            sequence_number: seq,
            timestamp,
            ssrc,
            csrc_list: Vec::new(),
            extension_profile: None,
            extension_data: Vec::new(),
            padding_len: 0,
            payload: audio_data.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let cc = (self.csrc_list.len() as u8) & 0x0F;
        let extension =
            self.extension || self.extension_profile.is_some() || !self.extension_data.is_empty();
        let padding_len = if self.padding || self.padding_len != 0 {
            self.padding_len.max(1)
        } else {
            0
        };

        let mut b0 = (self.version << 6) | cc;
        if padding_len != 0 {
            b0 |= 0x20;
        }
        if extension {
            b0 |= 0x10;
        }
        buf.push(b0);

        let mut b1 = self.payload_type & 0x7F;
        if self.marker {
            b1 |= 0x80;
        }
        buf.push(b1);

        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());

        for csrc in &self.csrc_list {
            buf.extend_from_slice(&csrc.to_be_bytes());
        }

        if extension {
            let profile = self.extension_profile.unwrap_or(0);
            let extension_words = self.extension_data.len().div_ceil(4);
            buf.extend_from_slice(&profile.to_be_bytes());
            buf.extend_from_slice(&(extension_words as u16).to_be_bytes());
            buf.extend_from_slice(&self.extension_data);
            buf.resize(
                buf.len() + (extension_words * 4 - self.extension_data.len()),
                0,
            );
        }

        buf.extend_from_slice(&self.payload);

        if padding_len != 0 {
            buf.resize(buf.len() + padding_len as usize, 0);
            let last = buf.len() - 1;
            buf[last] = padding_len;
        }

        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, RtpError> {
        if data.len() < RTP_FIXED_HEADER_LEN {
            return Err(RtpError::PacketTooShort(data.len()));
        }

        let version = data[0] >> 6;
        if version != 2 {
            return Err(RtpError::InvalidVersion(version));
        }

        let padding = (data[0] & 0x20) != 0;
        let extension = (data[0] & 0x10) != 0;
        let csrc_count = data[0] & 0x0F;

        let marker = (data[1] & 0x80) != 0;
        let payload_type = data[1] & 0x7F;

        let sequence_number = u16::from_be_bytes([data[2], data[3]]);
        let timestamp = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ssrc = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

        let mut offset = RTP_FIXED_HEADER_LEN;
        let csrc_bytes = (csrc_count as usize) * 4;
        if data.len() < offset + csrc_bytes {
            return Err(RtpError::PacketTooShort(data.len()));
        }

        let mut csrc_list = Vec::new();
        for _ in 0..csrc_count {
            let csrc = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            csrc_list.push(csrc);
            offset += 4;
        }

        let mut extension_profile = None;
        let mut extension_data = Vec::new();
        if extension {
            if data.len().saturating_sub(offset) < 4 {
                return Err(RtpError::TruncatedExtension);
            }

            let profile = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let extension_words = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let extension_bytes = extension_words
                .checked_mul(4)
                .ok_or(RtpError::TruncatedExtension)?;
            let extension_start = offset + 4;
            let extension_end = extension_start
                .checked_add(extension_bytes)
                .ok_or(RtpError::TruncatedExtension)?;
            if extension_end > data.len() {
                return Err(RtpError::TruncatedExtension);
            }

            extension_profile = Some(profile);
            extension_data.extend_from_slice(&data[extension_start..extension_end]);
            offset = extension_end;
        }

        let padding_len = if padding {
            let Some(&count) = data.last() else {
                return Err(RtpError::InvalidPadding(0));
            };
            let count_usize = count as usize;
            if count == 0 || count_usize > data.len().saturating_sub(offset) {
                return Err(RtpError::InvalidPadding(count));
            }
            count
        } else {
            0
        };

        let payload_end = data.len() - padding_len as usize;
        if payload_end < offset {
            return Err(RtpError::InvalidPadding(padding_len));
        }
        let payload = data[offset..payload_end].to_vec();

        Ok(RtpPacket {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc_list,
            extension_profile,
            extension_data,
            padding_len,
            payload,
        })
    }
}

impl RtcpSenderReport {
    pub fn build(ssrc: u32, ntp: u64, rtp_ts: u32, pkts: u32, octets: u32) -> Self {
        RtcpSenderReport {
            ssrc,
            ntp_timestamp: ntp,
            rtp_timestamp: rtp_ts,
            packet_count: pkts,
            octet_count: octets,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Byte 0: V=2, P=0, RC=0 (2 << 6 = 0x80)
        buf.push(0x80);
        buf.push(RTCP_PT_SR);
        let length_words: u16 = 6; // (28 bytes total - 4) / 4 = 6 words
        buf.extend_from_slice(&length_words.to_be_bytes());
        buf.extend_from_slice(&self.ssrc.to_be_bytes());
        buf.extend_from_slice(&self.ntp_timestamp.to_be_bytes());
        buf.extend_from_slice(&self.rtp_timestamp.to_be_bytes());
        buf.extend_from_slice(&self.packet_count.to_be_bytes());
        buf.extend_from_slice(&self.octet_count.to_be_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 28 || data[1] != RTCP_PT_SR || u16::from_be_bytes([data[2], data[3]]) != 6 {
            return None;
        }

        let ssrc = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ntp_timestamp = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let rtp_timestamp = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let packet_count = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
        let octet_count = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        Some(RtcpSenderReport {
            ssrc,
            ntp_timestamp,
            rtp_timestamp,
            packet_count,
            octet_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_audio_packet_roundtrip() {
        let audio_samples = [0xD5u8; 160]; // 20ms of G.711 audio (160 bytes @ 8kHz)
        let rtp =
            RtpPacket::build_audio(RTP_PT_PCMU, 1001, 160000, 0x11223344, false, &audio_samples);
        let raw = rtp.serialize();

        assert_eq!(raw.len(), RTP_FIXED_HEADER_LEN + 160);
        let parsed = RtpPacket::parse(&raw).unwrap();

        assert_eq!(parsed.version, 2);
        assert_eq!(parsed.payload_type, RTP_PT_PCMU);
        assert_eq!(parsed.sequence_number, 1001);
        assert_eq!(parsed.timestamp, 160000);
        assert_eq!(parsed.ssrc, 0x11223344);
        assert_eq!(parsed.payload.len(), 160);
    }

    #[test]
    fn test_rtp_extension_and_padding_roundtrip() {
        let payload = b"audio";
        let mut rtp = RtpPacket::build_audio(RTP_PT_DYNAMIC, 42, 90_000, 0x01020304, true, payload);
        rtp.extension = true;
        rtp.extension_profile = Some(0xBEDE);
        rtp.extension_data = vec![0x10, 0xAA, 0xBB, 0x00, 0x20];
        rtp.padding = true;
        rtp.padding_len = 4;

        let raw = rtp.serialize();
        let parsed = RtpPacket::parse(&raw).unwrap();

        assert!(parsed.extension);
        assert_eq!(parsed.extension_profile, Some(0xBEDE));
        assert_eq!(
            parsed.extension_data,
            vec![0x10, 0xAA, 0xBB, 0x00, 0x20, 0, 0, 0]
        );
        assert!(parsed.padding);
        assert_eq!(parsed.padding_len, 4);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn test_rtp_parser_rejects_truncated_header_extension() {
        let mut raw = RtpPacket::build_audio(RTP_PT_DYNAMIC, 1, 1, 1, false, b"x").serialize();
        raw[0] |= 0x10;
        raw.truncate(RTP_FIXED_HEADER_LEN + 3);

        assert_eq!(RtpPacket::parse(&raw), Err(RtpError::TruncatedExtension));
    }

    #[test]
    fn test_rtp_parser_rejects_extension_length_beyond_packet() {
        let mut raw = RtpPacket::build_audio(RTP_PT_DYNAMIC, 1, 1, 1, false, b"").serialize();
        raw[0] |= 0x10;
        raw.extend_from_slice(&[0xBE, 0xDE, 0x00, 0x02, 1, 2, 3, 4]);

        assert_eq!(RtpPacket::parse(&raw), Err(RtpError::TruncatedExtension));
    }

    #[test]
    fn test_rtp_parser_strips_valid_padding() {
        let mut raw =
            RtpPacket::build_audio(RTP_PT_PCMU, 7, 160, 0xAABBCCDD, false, b"abc").serialize();
        raw[0] |= 0x20;
        raw.extend_from_slice(&[0, 0, 0, 4]);

        let parsed = RtpPacket::parse(&raw).unwrap();
        assert_eq!(parsed.padding_len, 4);
        assert_eq!(parsed.payload, b"abc");
    }

    #[test]
    fn test_rtp_parser_rejects_zero_padding_count() {
        let mut raw =
            RtpPacket::build_audio(RTP_PT_PCMU, 7, 160, 0xAABBCCDD, false, b"abc").serialize();
        raw[0] |= 0x20;
        raw.push(0);

        assert_eq!(RtpPacket::parse(&raw), Err(RtpError::InvalidPadding(0)));
    }

    #[test]
    fn test_rtp_parser_rejects_padding_larger_than_remaining_payload() {
        let mut raw =
            RtpPacket::build_audio(RTP_PT_PCMU, 7, 160, 0xAABBCCDD, false, b"abc").serialize();
        raw[0] |= 0x20;
        raw.push(20);

        assert_eq!(RtpPacket::parse(&raw), Err(RtpError::InvalidPadding(20)));
    }

    #[test]
    fn test_rtcp_sender_report_roundtrip() {
        let sr = RtcpSenderReport::build(0x11223344, 0xE584123400000000, 160000, 50, 8000);
        let raw = sr.serialize();
        let parsed = RtcpSenderReport::parse(&raw).unwrap();

        assert_eq!(parsed.ssrc, 0x11223344);
        assert_eq!(parsed.packet_count, 50);
        assert_eq!(parsed.octet_count, 8000);
    }

    #[test]
    fn test_rtcp_sender_report_rejects_invalid_length_field() {
        let sr = RtcpSenderReport::build(0x11223344, 0xE584123400000000, 160000, 50, 8000);
        let mut raw = sr.serialize();
        raw[2..4].copy_from_slice(&5u16.to_be_bytes());

        assert_eq!(RtcpSenderReport::parse(&raw), None);
    }
}
