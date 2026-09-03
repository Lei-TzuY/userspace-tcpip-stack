//! Bidirectional Forwarding Detection (BFD - RFC 5880 / RFC 5881).
//!
//! Sub-second link and path liveness detection operating over UDP port 3784 (Control)
//! and UDP port 3785 (Echo). Supports authentication (Simple Password, Keyed MD5/SHA1).

use std::fmt;

pub const BFD_CONTROL_PORT: u16 = 3784;
pub const BFD_ECHO_PORT: u16 = 3785;
pub const BFD_MIN_PACKET_LEN: usize = 24;

// BFD Authentication Types (RFC 5880 Section 4.1)
pub const BFD_AUTH_SIMPLE_PASSWORD: u8 = 1;
pub const BFD_AUTH_KEYED_MD5: u8 = 2;
pub const BFD_AUTH_METICULOUS_KEYED_MD5: u8 = 3;
pub const BFD_AUTH_KEYED_SHA1: u8 = 4;
pub const BFD_AUTH_METICULOUS_KEYED_SHA1: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfdState {
    AdminDown = 0,
    Down = 1,
    Init = 2,
    Up = 3,
}

impl BfdState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            3 => BfdState::Up,
            _ => BfdState::Down,
        }
    }
}

impl fmt::Display for BfdState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BfdState::AdminDown => write!(f, "ADMIN_DOWN"),
            BfdState::Down => write!(f, "DOWN"),
            BfdState::Init => write!(f, "INIT"),
            BfdState::Up => write!(f, "UP"),
        }
    }
}

/// BFD Authentication Header (RFC 5880 Section 6.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfdAuthHeader {
    SimplePassword {
        key_id: u8,
        password: Vec<u8>,
    },
    KeyedMd5 {
        meticulous: bool,
        key_id: u8,
        sequence_number: u32,
        auth_key_hash: [u8; 16],
    },
    KeyedSha1 {
        meticulous: bool,
        key_id: u8,
        sequence_number: u32,
        auth_key_hash: [u8; 20],
    },
    Raw {
        auth_type: u8,
        key_id: u8,
        data: Vec<u8>,
    },
}

impl BfdAuthHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            BfdAuthHeader::SimplePassword { key_id, password } => {
                buf.push(BFD_AUTH_SIMPLE_PASSWORD);
                let auth_len = 3 + password.len().min(16);
                buf.push(auth_len as u8);
                buf.push(*key_id);
                buf.extend_from_slice(&password[..password.len().min(16)]);
            }
            BfdAuthHeader::KeyedMd5 {
                meticulous,
                key_id,
                sequence_number,
                auth_key_hash,
            } => {
                buf.push(if *meticulous {
                    BFD_AUTH_METICULOUS_KEYED_MD5
                } else {
                    BFD_AUTH_KEYED_MD5
                });
                buf.push(24); // Length: 1 auth_type + 1 auth_len + 1 key_id + 1 reserved + 4 seq + 16 digest
                buf.push(*key_id);
                buf.push(0); // Reserved
                buf.extend_from_slice(&sequence_number.to_be_bytes());
                buf.extend_from_slice(auth_key_hash);
            }
            BfdAuthHeader::KeyedSha1 {
                meticulous,
                key_id,
                sequence_number,
                auth_key_hash,
            } => {
                buf.push(if *meticulous {
                    BFD_AUTH_METICULOUS_KEYED_SHA1
                } else {
                    BFD_AUTH_KEYED_SHA1
                });
                buf.push(28); // Length: 1 auth_type + 1 auth_len + 1 key_id + 1 reserved + 4 seq + 20 digest
                buf.push(*key_id);
                buf.push(0); // Reserved
                buf.extend_from_slice(&sequence_number.to_be_bytes());
                buf.extend_from_slice(auth_key_hash);
            }
            BfdAuthHeader::Raw {
                auth_type,
                key_id,
                data,
            } => {
                buf.push(*auth_type);
                buf.push((3 + data.len()) as u8);
                buf.push(*key_id);
                buf.extend_from_slice(data);
            }
        }
        buf
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let auth_type = data[0];
        let auth_len = data[1] as usize;
        if auth_len < 3 || auth_len > data.len() {
            return None;
        }
        let key_id = data[2];

        match auth_type {
            BFD_AUTH_SIMPLE_PASSWORD if (4..=19).contains(&auth_len) => {
                let password = data[3..auth_len].to_vec();
                Some(BfdAuthHeader::SimplePassword { key_id, password })
            }
            BFD_AUTH_SIMPLE_PASSWORD => None,
            BFD_AUTH_KEYED_MD5 | BFD_AUTH_METICULOUS_KEYED_MD5 if auth_len == 24 => {
                let sequence_number = u32::from_be_bytes(data[4..8].try_into().ok()?);
                let mut auth_key_hash = [0u8; 16];
                auth_key_hash.copy_from_slice(&data[8..24]);
                Some(BfdAuthHeader::KeyedMd5 {
                    meticulous: auth_type == BFD_AUTH_METICULOUS_KEYED_MD5,
                    key_id,
                    sequence_number,
                    auth_key_hash,
                })
            }
            BFD_AUTH_KEYED_MD5 | BFD_AUTH_METICULOUS_KEYED_MD5 => None,
            BFD_AUTH_KEYED_SHA1 | BFD_AUTH_METICULOUS_KEYED_SHA1 if auth_len == 28 => {
                let sequence_number = u32::from_be_bytes(data[4..8].try_into().ok()?);
                let mut auth_key_hash = [0u8; 20];
                auth_key_hash.copy_from_slice(&data[8..28]);
                Some(BfdAuthHeader::KeyedSha1 {
                    meticulous: auth_type == BFD_AUTH_METICULOUS_KEYED_SHA1,
                    key_id,
                    sequence_number,
                    auth_key_hash,
                })
            }
            BFD_AUTH_KEYED_SHA1 | BFD_AUTH_METICULOUS_KEYED_SHA1 => None,
            _ => {
                let raw_data = data[3..auth_len].to_vec();
                Some(BfdAuthHeader::Raw {
                    auth_type,
                    key_id,
                    data: raw_data,
                })
            }
        }
    }
}

/// BFD Echo Packet (RFC 5880 Section 6.8.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdEchoPacket {
    pub my_discriminator: u32,
    pub sender_timestamp_us: u64,
    pub sequence_number: u32,
    pub payload: Vec<u8>,
}

impl BfdEchoPacket {
    pub fn new(my_disc: u32, timestamp_us: u64, seq: u32, payload: &[u8]) -> Self {
        BfdEchoPacket {
            my_discriminator: my_disc,
            sender_timestamp_us: timestamp_us,
            sequence_number: seq,
            payload: payload.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(16 + self.payload.len());
        buf.extend_from_slice(&self.my_discriminator.to_be_bytes());
        buf.extend_from_slice(&self.sender_timestamp_us.to_be_bytes());
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, BfdError> {
        if data.len() < 16 {
            return Err(BfdError::PacketTooShort(data.len()));
        }
        let my_discriminator = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let sender_timestamp_us = u64::from_be_bytes([
            data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
        ]);
        let sequence_number = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let payload = data[16..].to_vec();
        Ok(BfdEchoPacket {
            my_discriminator,
            sender_timestamp_us,
            sequence_number,
            payload,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdControlPacket {
    pub version: u8,
    pub diagnostic: u8,
    pub state: BfdState,
    pub poll: bool,
    pub r#final: bool,
    pub cpi: bool,
    pub auth: bool,
    pub demand: bool,
    pub multipoint: bool,
    pub detect_mult: u8,
    pub length: u8,
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub desired_min_tx_interval_us: u32,
    pub required_min_rx_interval_us: u32,
    pub required_min_echo_rx_interval_us: u32,
    pub auth_header: Option<BfdAuthHeader>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BfdError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidLength(u8),
    PollFinalBothSet,
    UnsupportedAuthentication,
    UnsupportedMultipoint,
    ZeroDetectMultiplier,
    ZeroMyDiscriminator,
    InvalidAuthHeader,
}

impl fmt::Display for BfdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BfdError::PacketTooShort(l) => write!(f, "BFD packet too short ({} bytes, min 24)", l),
            BfdError::InvalidVersion(v) => {
                write!(f, "Invalid BFD version: expected 1, found {}", v)
            }
            BfdError::InvalidLength(l) => write!(f, "Invalid BFD length field: {}", l),
            BfdError::PollFinalBothSet => {
                write!(f, "BFD Poll and Final bits must not both be set")
            }
            BfdError::UnsupportedAuthentication => {
                write!(f, "Authenticated BFD packets are not supported")
            }
            BfdError::UnsupportedMultipoint => {
                write!(f, "Multipoint BFD packets are not supported")
            }
            BfdError::ZeroDetectMultiplier => write!(f, "BFD Detect Mult must not be zero"),
            BfdError::ZeroMyDiscriminator => write!(f, "BFD My Discriminator must not be zero"),
            BfdError::InvalidAuthHeader => write!(f, "Invalid BFD authentication header"),
        }
    }
}

impl std::error::Error for BfdError {}

impl BfdControlPacket {
    pub fn parse(data: &[u8]) -> Result<Self, BfdError> {
        if data.len() < BFD_MIN_PACKET_LEN {
            return Err(BfdError::PacketTooShort(data.len()));
        }

        let b0 = data[0];
        let version = b0 >> 5;
        let diagnostic = b0 & 0x1F;

        if version != 1 {
            return Err(BfdError::InvalidVersion(version));
        }

        let b1 = data[1];
        let state_val = (b1 >> 6) & 0x03;
        let poll = (b1 & 0x20) != 0;
        let r#final = (b1 & 0x10) != 0;
        let cpi = (b1 & 0x08) != 0;
        let auth = (b1 & 0x04) != 0;
        let demand = (b1 & 0x02) != 0;
        let multipoint = (b1 & 0x01) != 0;
        let length = data[3];
        let min_length = if auth { 26 } else { BFD_MIN_PACKET_LEN };

        if (length as usize) < min_length || (length as usize) > data.len() {
            return Err(BfdError::InvalidLength(length));
        }
        if poll && r#final {
            return Err(BfdError::PollFinalBothSet);
        }
        if multipoint {
            return Err(BfdError::UnsupportedMultipoint);
        }

        let detect_mult = data[2];
        if detect_mult == 0 {
            return Err(BfdError::ZeroDetectMultiplier);
        }

        let my_discriminator = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if my_discriminator == 0 {
            return Err(BfdError::ZeroMyDiscriminator);
        }

        let your_discriminator = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let desired_min_tx_interval_us =
            u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let required_min_rx_interval_us =
            u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let required_min_echo_rx_interval_us =
            u32::from_be_bytes([data[20], data[21], data[22], data[23]]);

        // A packet that claims authentication is only acceptable when its
        // authentication section is genuinely present and well formed. A truncated or
        // malformed section cannot be verified, so it is refused rather than silently
        // treated as unauthenticated.
        let auth_header = if auth {
            match BfdAuthHeader::parse(data.get(BFD_MIN_PACKET_LEN..).unwrap_or(&[])) {
                Some(header) => Some(header),
                None => return Err(BfdError::UnsupportedAuthentication),
            }
        } else {
            None
        };

        Ok(BfdControlPacket {
            version,
            diagnostic,
            state: BfdState::from_u8(state_val),
            poll,
            r#final,
            cpi,
            auth,
            demand,
            multipoint,
            detect_mult,
            length,
            my_discriminator,
            your_discriminator,
            desired_min_tx_interval_us,
            required_min_rx_interval_us,
            required_min_echo_rx_interval_us,
            auth_header,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let auth_bytes = self
            .auth_header
            .as_ref()
            .map(|a| a.serialize())
            .unwrap_or_default();
        let total_len = BFD_MIN_PACKET_LEN + auth_bytes.len();

        let mut buf = vec![0u8; total_len];
        buf[0] = ((self.version & 0x07) << 5) | (self.diagnostic & 0x1F);

        let state_val = self.state as u8;
        let mut b1 = (state_val & 0x03) << 6;
        if self.poll {
            b1 |= 0x20;
        }
        if self.r#final {
            b1 |= 0x10;
        }
        if self.cpi {
            b1 |= 0x08;
        }
        if self.auth || self.auth_header.is_some() {
            b1 |= 0x04;
        }
        if self.demand {
            b1 |= 0x02;
        }
        if self.multipoint {
            b1 |= 0x01;
        }
        buf[1] = b1;

        buf[2] = self.detect_mult;
        // RFC 5880 section 4.1 Length: the actual octet count of this packet. The
        // authentication section, when present, is part of it.
        buf[3] = (total_len as u8).max(BFD_MIN_PACKET_LEN as u8);
        buf[4..8].copy_from_slice(&self.my_discriminator.to_be_bytes());
        buf[8..12].copy_from_slice(&self.your_discriminator.to_be_bytes());
        buf[12..16].copy_from_slice(&self.desired_min_tx_interval_us.to_be_bytes());
        buf[16..20].copy_from_slice(&self.required_min_rx_interval_us.to_be_bytes());
        buf[20..24].copy_from_slice(&self.required_min_echo_rx_interval_us.to_be_bytes());

        if !auth_bytes.is_empty() {
            buf[24..total_len].copy_from_slice(&auth_bytes);
        }

        buf
    }

    pub fn build_control(state: BfdState, my_disc: u32, your_disc: u32, interval_us: u32) -> Self {
        BfdControlPacket {
            version: 1,
            diagnostic: 0,
            state,
            poll: false,
            r#final: false,
            cpi: false,
            auth: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            length: 24,
            my_discriminator: my_disc,
            your_discriminator: your_disc,
            desired_min_tx_interval_us: interval_us,
            required_min_rx_interval_us: interval_us,
            required_min_echo_rx_interval_us: 0,
            auth_header: None,
        }
    }

    pub fn build_authenticated(
        state: BfdState,
        my_disc: u32,
        your_disc: u32,
        interval_us: u32,
        auth_header: BfdAuthHeader,
    ) -> Self {
        let mut pkt = Self::build_control(state, my_disc, your_disc, interval_us);
        pkt.auth = true;
        pkt.auth_header = Some(auth_header);
        pkt
    }
}

/// BFD Session State Machine with Echo & Authentication support.
#[derive(Debug, Clone)]
pub struct BfdSession {
    pub local_discriminator: u32,
    pub remote_discriminator: u32,
    pub state: BfdState,
    pub tx_interval_us: u32,
    pub rx_interval_us: u32,
    pub required_min_echo_rx_interval_us: u32,
    pub detect_mult: u8,
    pub auth_key: Option<BfdAuthHeader>,
    pub echo_sequence: u32,
    pub last_echo_rtt_us: Option<u64>,
}

impl BfdSession {
    pub fn new(local_disc: u32, interval_us: u32) -> Self {
        BfdSession {
            local_discriminator: local_disc,
            remote_discriminator: 0,
            state: BfdState::Down,
            tx_interval_us: interval_us,
            rx_interval_us: interval_us,
            required_min_echo_rx_interval_us: 50_000,
            detect_mult: 3,
            auth_key: None,
            echo_sequence: 1,
            last_echo_rtt_us: None,
        }
    }

    /// Generates an outbound BFD Echo packet.
    pub fn generate_echo_packet(&mut self, now_us: u64) -> Vec<u8> {
        let echo = BfdEchoPacket::new(
            self.local_discriminator,
            now_us,
            self.echo_sequence,
            b"BFD-ECHO-PROBE",
        );
        self.echo_sequence = self.echo_sequence.wrapping_add(1);
        echo.serialize()
    }

    /// Validates an incoming looped-back BFD Echo packet and records RTT.
    pub fn process_echo_packet(&mut self, data: &[u8], now_us: u64) -> bool {
        let echo = match BfdEchoPacket::parse(data) {
            Ok(e) => e,
            Err(_) => return false,
        };
        if echo.my_discriminator != self.local_discriminator {
            return false;
        }
        let rtt = now_us.saturating_sub(echo.sender_timestamp_us);
        self.last_echo_rtt_us = Some(rtt);
        true
    }

    /// Advances the BFD FSM upon receiving a remote BFD control packet.
    pub fn process_packet(&mut self, pkt: &BfdControlPacket) -> Option<BfdControlPacket> {
        if pkt.version != 1
            || (pkt.length as usize) < BFD_MIN_PACKET_LEN
            || pkt.my_discriminator == 0
            || pkt.detect_mult == 0
            || (pkt.poll && pkt.r#final)
            || pkt.auth
            || pkt.multipoint
        {
            return None;
        }
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.local_discriminator {
            return None;
        }
        if pkt.your_discriminator == 0 && !matches!(pkt.state, BfdState::Down | BfdState::AdminDown)
        {
            return None;
        }
        if self.state == BfdState::AdminDown {
            return None;
        }

        self.remote_discriminator = pkt.my_discriminator;

        let state_changed = match (self.state, pkt.state) {
            (BfdState::Down, BfdState::Down) => {
                self.state = BfdState::Init;
                true
            }
            (BfdState::Down, BfdState::Init)
            | (BfdState::Init, BfdState::Init)
            | (BfdState::Init, BfdState::Up) => {
                self.state = BfdState::Up;
                true
            }
            (BfdState::Init | BfdState::Up, BfdState::AdminDown)
            | (BfdState::Up, BfdState::Down) => {
                self.state = BfdState::Down;
                false
            }
            _ => false,
        };

        if state_changed || pkt.poll {
            let mut response = BfdControlPacket::build_control(
                self.state,
                self.local_discriminator,
                self.remote_discriminator,
                self.tx_interval_us,
            );
            response.r#final = pkt.poll;
            // Carry this session's configured authentication onto the reply, so an
            // authenticated session does not answer with an unauthenticated packet.
            response.auth_header = self.auth_key.clone();
            response.auth = self.auth_key.is_some();
            Some(response)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bfd_packet_roundtrip() {
        let pkt = BfdControlPacket::build_control(BfdState::Up, 0x12345678, 0x87654321, 50_000);
        let raw = pkt.serialize();

        assert_eq!(raw.len(), BFD_MIN_PACKET_LEN);
        let parsed = BfdControlPacket::parse(&raw).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.state, BfdState::Up);
        assert_eq!(parsed.my_discriminator, 0x12345678);
        assert_eq!(parsed.your_discriminator, 0x87654321);
        assert_eq!(parsed.desired_min_tx_interval_us, 50_000);
    }

    #[test]
    fn test_bfd_simple_password_rejects_zero_length_password() {
        assert_eq!(
            BfdAuthHeader::parse(&[BFD_AUTH_SIMPLE_PASSWORD, 3, 7]),
            None
        );
    }

    #[test]
    fn test_bfd_keyed_md5_rejects_noncanonical_auth_length() {
        let mut auth = vec![BFD_AUTH_KEYED_MD5, 25, 7, 0];
        auth.extend_from_slice(&0x01020304u32.to_be_bytes());
        auth.extend_from_slice(&[0xAA; 16]);
        auth.push(0);

        assert_eq!(BfdAuthHeader::parse(&auth), None);
    }

    #[test]
    fn test_bfd_keyed_sha1_rejects_noncanonical_auth_length() {
        let mut auth = vec![BFD_AUTH_KEYED_SHA1, 29, 7, 0];
        auth.extend_from_slice(&0x01020304u32.to_be_bytes());
        auth.extend_from_slice(&[0xAA; 20]);
        auth.push(0);

        assert_eq!(BfdAuthHeader::parse(&auth), None);
    }

    #[test]
    fn test_bfd_serializer_uses_actual_encoded_length() {
        let mut pkt = BfdControlPacket::build_control(BfdState::Up, 0x12345678, 0x87654321, 50_000);
        pkt.length = u8::MAX;

        let raw = pkt.serialize();

        assert_eq!(raw.len(), BFD_MIN_PACKET_LEN);
        assert_eq!(raw[3] as usize, raw.len());
        let parsed =
            BfdControlPacket::parse(&raw).expect("serialized packet must remain parseable");
        assert_eq!(parsed.length as usize, raw.len());
    }

    #[test]
    fn test_bfd_parser_rejects_unverified_authenticated_packet() {
        let mut raw =
            BfdControlPacket::build_control(BfdState::Down, 0x12345678, 0, 50_000).serialize();
        raw[1] |= 0x04;
        raw[3] = 26;
        raw.extend_from_slice(&[0, 0]);

        assert_eq!(
            BfdControlPacket::parse(&raw),
            Err(BfdError::UnsupportedAuthentication)
        );
    }

    #[test]
    fn test_bfd_parser_validates_authenticated_minimum_length_first() {
        let mut raw =
            BfdControlPacket::build_control(BfdState::Down, 0x12345678, 0, 50_000).serialize();
        raw[1] |= 0x04;

        assert_eq!(
            BfdControlPacket::parse(&raw),
            Err(BfdError::InvalidLength(24))
        );
    }

    #[test]
    fn test_bfd_parser_rejects_poll_and_final_together() {
        let mut raw =
            BfdControlPacket::build_control(BfdState::Down, 0x12345678, 0, 50_000).serialize();
        raw[1] |= 0x30;

        assert_eq!(
            BfdControlPacket::parse(&raw),
            Err(BfdError::PollFinalBothSet)
        );
    }

    #[test]
    fn test_bfd_parser_rejects_multipoint_packet() {
        let mut raw =
            BfdControlPacket::build_control(BfdState::Down, 0x12345678, 0, 50_000).serialize();
        raw[1] |= 0x01;

        assert_eq!(
            BfdControlPacket::parse(&raw),
            Err(BfdError::UnsupportedMultipoint)
        );
    }

    #[test]
    fn test_bfd_session_state_transition() {
        let mut session = BfdSession::new(0x1001, 100_000);
        assert_eq!(session.state, BfdState::Down);

        let incoming_down = BfdControlPacket::build_control(BfdState::Down, 0x2002, 0, 100_000);
        let resp = session.process_packet(&incoming_down).unwrap();
        assert_eq!(session.state, BfdState::Init);
        assert_eq!(resp.state, BfdState::Init);

        let incoming_init =
            BfdControlPacket::build_control(BfdState::Init, 0x2002, 0x1001, 100_000);
        let resp2 = session.process_packet(&incoming_init).unwrap();
        assert_eq!(session.state, BfdState::Up);
        assert_eq!(resp2.state, BfdState::Up);
    }

    #[test]
    fn test_bfd_poll_request_gets_final_response_without_state_change() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.state = BfdState::Up;
        session.remote_discriminator = 0x2002;

        let mut incoming = BfdControlPacket::build_control(
            BfdState::Up,
            session.remote_discriminator,
            session.local_discriminator,
            100_000,
        );
        incoming.poll = true;

        let response = session
            .process_packet(&incoming)
            .expect("Poll request must receive a Final response");
        assert_eq!(session.state, BfdState::Up);
        assert_eq!(response.state, BfdState::Up);
        assert!(!response.poll);
        assert!(response.r#final);
        assert_eq!(response.my_discriminator, session.local_discriminator);
        assert_eq!(response.your_discriminator, incoming.my_discriminator);
    }

    #[test]
    fn test_bfd_session_rejects_mismatched_your_discriminator() {
        let mut session = BfdSession::new(0x1001, 100_000);
        let incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0x9999, 100_000);

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0);
    }

    #[test]
    fn test_bfd_session_rejects_invalid_version_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.version = 0;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_short_length_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.length = (BFD_MIN_PACKET_LEN - 1) as u8;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_zero_my_discriminator_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let incoming = BfdControlPacket::build_control(BfdState::Down, 0, 0, 100_000);

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_zero_detect_multiplier_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.detect_mult = 0;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_unverified_auth_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.auth = true;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_multipoint_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.multipoint = true;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }

    #[test]
    fn test_bfd_session_rejects_poll_and_final_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(BfdState::Down, 0x3003, 0, 100_000);
        incoming.poll = true;
        incoming.r#final = true;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x2002);
    }
    #[test]
    fn test_bfd_session_rejects_zero_your_discriminator_for_init_packet() {
        let mut session = BfdSession::new(0x1001, 100_000);
        let incoming = BfdControlPacket::build_control(BfdState::Init, 0x3003, 0, 100_000);

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0);
    }

    #[test]
    fn test_bfd_session_accepts_zero_your_discriminator_for_admin_down_packet() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.state = BfdState::Up;
        session.remote_discriminator = 0x2002;
        let incoming = BfdControlPacket::build_control(BfdState::AdminDown, 0x3003, 0, 100_000);

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x3003);
    }

    #[test]
    fn test_bfd_up_transitions_down_when_remote_signals_down() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.state = BfdState::Up;
        session.remote_discriminator = 0x2002;
        let incoming = BfdControlPacket::build_control(
            BfdState::Down,
            0x3003,
            session.local_discriminator,
            100_000,
        );

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x3003);
    }

    #[test]
    fn test_bfd_init_transitions_down_when_remote_signals_admin_down() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.state = BfdState::Init;
        session.remote_discriminator = 0x2002;
        let incoming = BfdControlPacket::build_control(
            BfdState::AdminDown,
            0x3003,
            session.local_discriminator,
            100_000,
        );

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0x3003);
    }

    #[test]
    fn test_bfd_admin_down_session_discards_control_packet_without_mutation() {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.state = BfdState::AdminDown;
        session.remote_discriminator = 0x2002;
        let mut incoming = BfdControlPacket::build_control(
            BfdState::Down,
            0x3003,
            session.local_discriminator,
            100_000,
        );
        incoming.poll = true;

        assert!(session.process_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::AdminDown);
        assert_eq!(session.remote_discriminator, 0x2002);
    }
}
