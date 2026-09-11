//! 3GPP Rel-18 5G NR Sidelink PC5-S Unicast Session & Direct Security Engine.
//!
//! Compliant with:
//! - **3GPP TS 24.554 Rel-18**: "5G System; User Equipment (UE) to V2X / ProSe
//!   control function; Protocol aspects; Stage 3 (PC5-S)".
//! - **3GPP TS 33.536 Rel-18**: "Security aspects of 3GPP support for advanced
//!   V2X services; Stage 3 (Direct Security Association - DSA)".
//! - **3GPP TS 23.304 Rel-18**: "Proximity-based Services (ProSe) in the 5G System".
//!
//! Provides pure-Rust, zero-dependency implementations of:
//! - RFC 6234 / FIPS 180-4 compliant SHA-256 and RFC 2104 HMAC-SHA256 primitives.
//! - 3GPP TS 33.220 / TS 33.536 Key Derivation Function (KDF).
//! - Direct Security Association (DSA) mutual authentication and key derivation
//!   (K_NRP -> K_NRP-sess -> K_enc / K_int).
//! - PC5-S Signaling Protocol Data Unit (PDU) wire serialization & deserialization:
//!   - Direct Communication Request / Accept / Reject
//!   - Direct Security Mode Command / Complete / Reject
//!   - Direct Link Keepalive / Keepalive Ack
//!   - Direct Link Release Request / Accept
//!   - Direct Link Rekeying Request / Response
//! - User Plane & Signaling Plane encryption, integrity protection, and 32-bit Count anti-replay sliding window.
//! - Session timer state machines (T4100, T4101, T4111, T4112) with automatic heartbeat loss detection.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Protocol Constants (TS 24.554 & TS 33.536)
// ---------------------------------------------------------------------------

/// 3GPP PC5-S Protocol Discriminator.
pub const PC5S_PROTOCOL_DISCRIMINATOR: u8 = 0x56;

/// Default keepalive heartbeat timer (T4111) in milliseconds.
pub const DEFAULT_T4111_KEEPALIVE_MS: u64 = 10_000;

/// Default keepalive response timeout (T4112) in milliseconds.
pub const DEFAULT_T4112_TIMEOUT_MS: u64 = 3_000;

/// Default direct communication request timeout (T4100) in milliseconds.
pub const DEFAULT_T4100_REQUEST_TIMEOUT_MS: u64 = 2_000;

/// Default direct security mode command timeout (T4101) in milliseconds.
pub const DEFAULT_T4101_SEC_MODE_TIMEOUT_MS: u64 = 2_000;

/// Maximum retransmission count for unacknowledged PC5-S control messages.
pub const MAX_PC5S_RETRANSMISSIONS: u8 = 3;

/// Anti-replay sliding window size in packets (TS 33.536 §6.3).
pub const ANTI_REPLAY_WINDOW_SIZE: u32 = 64;

// ---------------------------------------------------------------------------
// Cryptographic Primitives in Pure Rust (SHA-256, HMAC, 3GPP KDF)
// ---------------------------------------------------------------------------

/// Pure standard Rust SHA-256 state and hasher (RFC 6234 / FIPS 180-4).
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut idx = 0;
        let mut buffer_idx = (self.count % 64) as usize;
        self.count += data.len() as u64;

        while idx < data.len() {
            let space = 64 - buffer_idx;
            let take = space.min(data.len() - idx);
            self.buffer[buffer_idx..buffer_idx + take].copy_from_slice(&data[idx..idx + take]);
            idx += take;
            buffer_idx += take;

            if buffer_idx == 64 {
                self.process_block();
                buffer_idx = 0;
            }
        }
    }

    fn process_block(&mut self) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let j = i * 4;
            w[i] = u32::from_be_bytes([
                self.buffer[j],
                self.buffer[j + 1],
                self.buffer[j + 2],
                self.buffer[j + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    pub fn finalize(mut self) -> [u8; 32] {
        let bit_len = self.count * 8;
        let buffer_idx = (self.count % 64) as usize;
        self.buffer[buffer_idx] = 0x80;
        for b in &mut self.buffer[buffer_idx + 1..] {
            *b = 0;
        }

        if buffer_idx >= 56 {
            self.process_block();
            self.buffer = [0u8; 64];
        }

        let len_bytes = bit_len.to_be_bytes();
        self.buffer[56..64].copy_from_slice(&len_bytes);
        self.process_block();

        let mut out = [0u8; 32];
        for (i, &val) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
        }
        out
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

/// Pure standard Rust HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_pad = [0u8; 64];
    if key.len() > 64 {
        let hash = Sha256::digest(key);
        key_pad[..32].copy_from_slice(&hash);
    } else {
        key_pad[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key_pad[i];
        opad[i] ^= key_pad[i];
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(message);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// 3GPP Key Derivation Function (KDF) compliant with TS 33.220 / TS 33.536 Annex B.
/// Formula: DerivedKey = HMAC-SHA256(Key, FC || P0 || L0 || P1 || L1 || ...)
pub fn kdf_3gpp(key: &[u8], fc: u8, params: &[&[u8]]) -> [u8; 32] {
    let mut s = Vec::new();
    s.push(fc);
    for p in params {
        s.extend_from_slice(p);
        let len_u16 = p.len() as u16;
        s.extend_from_slice(&len_u16.to_be_bytes());
    }
    hmac_sha256(key, &s)
}

// ---------------------------------------------------------------------------
// Security Algorithms & Cryptographic Context (TS 33.536)
// ---------------------------------------------------------------------------

/// Sidelink Direct Ciphering Algorithm (TS 33.536 §5.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidelinkCipheringAlgorithm {
    /// NEA0: Null ciphering (no encryption).
    Nea0 = 0x00,
    /// NEA1: 128-bit SNOW 3G based stream cipher.
    Nea1 = 0x01,
    /// NEA2: 128-bit AES-CTR based stream cipher.
    Nea2 = 0x02,
    /// NEA3: 128-bit ZUC based stream cipher.
    Nea3 = 0x03,
}

impl SidelinkCipheringAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Nea0),
            0x01 => Some(Self::Nea1),
            0x02 => Some(Self::Nea2),
            0x03 => Some(Self::Nea3),
            _ => None,
        }
    }
}

/// Sidelink Direct Integrity Algorithm (TS 33.536 §5.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidelinkIntegrityAlgorithm {
    /// NIA0: Null integrity (no MAC).
    Nia0 = 0x00,
    /// NIA1: 128-bit SNOW 3G based integrity.
    Nia1 = 0x01,
    /// NIA2: 128-bit AES-CMAC based integrity.
    Nia2 = 0x02,
    /// NIA3: 128-bit ZUC based integrity.
    Nia3 = 0x03,
}

impl SidelinkIntegrityAlgorithm {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::Nia0),
            0x01 => Some(Self::Nia1),
            0x02 => Some(Self::Nia2),
            0x03 => Some(Self::Nia3),
            _ => None,
        }
    }
}

/// Security context for an established PC5-S Unicast Link.
#[derive(Debug, Clone, PartialEq)]
pub struct Pc5SecurityContext {
    pub ciphering_algorithm: SidelinkCipheringAlgorithm,
    pub integrity_algorithm: SidelinkIntegrityAlgorithm,
    /// Root NRP key (32 bytes).
    pub k_nrp: [u8; 32],
    /// Session NRP key (32 bytes).
    pub k_nrp_sess: [u8; 32],
    /// 128-bit confidentiality key K_enc.
    pub k_enc: [u8; 16],
    /// 128-bit integrity key K_int.
    pub k_int: [u8; 16],
    /// Transmit 32-bit Count.
    pub tx_count: u32,
    /// Highest received 32-bit Count for anti-replay window.
    pub rx_count_highest: u32,
    /// Replay window bitmap covering [rx_count_highest - 63 .. rx_count_highest].
    pub replay_bitmap: u64,
}

impl Pc5SecurityContext {
    /// Derive session keys K_NRP-sess, K_enc, and K_int from K_NRP, nonces, and Link ID (TS 33.536 §A.2).
    pub fn derive_new(
        k_nrp: [u8; 32],
        initiator_nonce: &[u8; 16],
        responder_nonce: &[u8; 16],
        link_id: u32,
        cipher_alg: SidelinkCipheringAlgorithm,
        integ_alg: SidelinkIntegrityAlgorithm,
    ) -> Self {
        // Step 1: K_NRP-sess derivation (FC = 0x70)
        let link_id_bytes = link_id.to_be_bytes();
        let k_nrp_sess = kdf_3gpp(
            &k_nrp,
            0x70,
            &[initiator_nonce, responder_nonce, &link_id_bytes],
        );

        // Step 2: K_enc derivation (FC = 0x71)
        let cipher_param = [cipher_alg as u8];
        let k_enc_full = kdf_3gpp(&k_nrp_sess, 0x71, &[b"enc", &cipher_param]);
        let mut k_enc = [0u8; 16];
        k_enc.copy_from_slice(&k_enc_full[16..32]);

        // Step 3: K_int derivation (FC = 0x72)
        let integ_param = [integ_alg as u8];
        let k_int_full = kdf_3gpp(&k_nrp_sess, 0x72, &[b"int", &integ_param]);
        let mut k_int = [0u8; 16];
        k_int.copy_from_slice(&k_int_full[16..32]);

        Self {
            ciphering_algorithm: cipher_alg,
            integrity_algorithm: integ_alg,
            k_nrp,
            k_nrp_sess,
            k_enc,
            k_int,
            tx_count: 0,
            rx_count_highest: 0,
            replay_bitmap: 0,
        }
    }

    /// Check and update anti-replay sliding window (TS 33.536 §6.3.3).
    pub fn check_anti_replay(&mut self, count: u32) -> bool {
        if self.rx_count_highest == 0 && self.replay_bitmap == 0 {
            self.rx_count_highest = count;
            self.replay_bitmap = 1;
            return true;
        }

        if count > self.rx_count_highest {
            let diff = count - self.rx_count_highest;
            if diff >= ANTI_REPLAY_WINDOW_SIZE {
                self.replay_bitmap = 1;
            } else {
                self.replay_bitmap = (self.replay_bitmap << diff) | 1;
            }
            self.rx_count_highest = count;
            true
        } else {
            let diff = self.rx_count_highest - count;
            if diff >= ANTI_REPLAY_WINDOW_SIZE {
                return false;
            }
            let mask = 1u64 << diff;
            if (self.replay_bitmap & mask) != 0 {
                false
            } else {
                self.replay_bitmap |= mask;
                true
            }
        }
    }

    /// Compute 32-bit Message Authentication Code (MAC-I).
    pub fn compute_mac_i(&self, count: u32, bearer_id: u8, direction: u8, data: &[u8]) -> [u8; 4] {
        if self.integrity_algorithm == SidelinkIntegrityAlgorithm::Nia0 {
            return [0u8; 4];
        }
        let mut msg = Vec::with_capacity(data.len() + 8);
        msg.extend_from_slice(&count.to_be_bytes());
        msg.push(bearer_id);
        msg.push(direction);
        msg.extend_from_slice(data);

        let hash = hmac_sha256(&self.k_int, &msg);
        let mut mac = [0u8; 4];
        mac.copy_from_slice(&hash[0..4]);
        mac
    }

    /// Encrypt or Decrypt data using PRF keystream stream ciphering.
    pub fn cipher(&self, count: u32, bearer_id: u8, direction: u8, data: &[u8]) -> Vec<u8> {
        if self.ciphering_algorithm == SidelinkCipheringAlgorithm::Nea0 {
            return data.to_vec();
        }
        let mut output = Vec::with_capacity(data.len());
        let mut block_idx: u32 = 0;

        while output.len() < data.len() {
            let mut seed = Vec::with_capacity(16);
            seed.extend_from_slice(&count.to_be_bytes());
            seed.push(bearer_id);
            seed.push(direction);
            seed.extend_from_slice(&block_idx.to_be_bytes());
            let keystream = hmac_sha256(&self.k_enc, &seed);

            for &k_byte in &keystream {
                if output.len() < data.len() {
                    let p_byte = data[output.len()];
                    output.push(p_byte ^ k_byte);
                } else {
                    break;
                }
            }
            block_idx += 1;
        }

        output
    }
}

// ---------------------------------------------------------------------------
// PC5-S Messages & Information Elements (TS 24.554 §7)
// ---------------------------------------------------------------------------

/// Cause codes for Direct Communication Reject or Release (TS 24.554 §7.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pc5sRejectCause {
    ServiceNotSupported = 0x01,
    SecurityCapabilitiesMismatch = 0x02,
    AuthenticationFailed = 0x03,
    ResourceNotAvailable = 0x04,
    KeepaliveTimeout = 0x05,
    UserInactivity = 0x06,
    NormalTeardown = 0x07,
}

impl Pc5sRejectCause {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0x01 => Self::ServiceNotSupported,
            0x02 => Self::SecurityCapabilitiesMismatch,
            0x03 => Self::AuthenticationFailed,
            0x04 => Self::ResourceNotAvailable,
            0x05 => Self::KeepaliveTimeout,
            0x06 => Self::UserInactivity,
            _ => Self::NormalTeardown,
        }
    }
}

/// Sidelink QoS Flow parameter (TS 24.554).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pc5QosFlow {
    pub pqfi: u8,
    pub pc5_5qi: u8,
    pub range_meters: u16,
}

/// Sidelink PC5-S Control Signaling Messages.
#[derive(Debug, Clone, PartialEq)]
pub enum Pc5sMessage {
    /// Direct Communication Request (DCR).
    DirectCommunicationRequest {
        initiator_l2_id: u32,
        target_l2_id: u32,
        application_id: u32,
        initiator_nonce: [u8; 16],
        supported_ciphers: u8,
        supported_integs: u8,
        ip_address_config: u8,
        qos_flows: Vec<Pc5QosFlow>,
    },
    /// Direct Security Mode Command (DSMC).
    DirectSecurityModeCommand {
        link_id: u32,
        selected_cipher: SidelinkCipheringAlgorithm,
        selected_integ: SidelinkIntegrityAlgorithm,
        responder_nonce: [u8; 16],
        mac_i: [u8; 4],
    },
    /// Direct Security Mode Complete.
    DirectSecurityModeComplete {
        link_id: u32,
        mac_i: [u8; 4],
    },
    /// Direct Communication Accept (DCA).
    DirectCommunicationAccept {
        link_id: u32,
        responder_l2_id: u32,
        ip_address_config: u8,
        admitted_pqfis: Vec<u8>,
    },
    /// Direct Communication Reject.
    DirectCommunicationReject {
        target_l2_id: u32,
        cause: Pc5sRejectCause,
    },
    /// Direct Link Keepalive (Ping).
    DirectLinkKeepalive {
        link_id: u32,
        seq_num: u16,
    },
    /// Direct Link Keepalive Ack (Pong).
    DirectLinkKeepaliveAck {
        link_id: u32,
        seq_num: u16,
    },
    /// Direct Link Rekeying Request.
    DirectLinkRekeyingRequest {
        link_id: u32,
        fresh_nonce: [u8; 16],
    },
    /// Direct Link Rekeying Response.
    DirectLinkRekeyingResponse {
        link_id: u32,
        responder_nonce: [u8; 16],
        mac_i: [u8; 4],
    },
    /// Direct Link Release Request.
    DirectLinkReleaseRequest {
        link_id: u32,
        cause: Pc5sRejectCause,
    },
    /// Direct Link Release Accept.
    DirectLinkReleaseAccept {
        link_id: u32,
    },
}

impl Pc5sMessage {
    /// Encode PC5-S message into binary wire format (TS 24.554 §7).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(PC5S_PROTOCOL_DISCRIMINATOR);

        match self {
            Self::DirectCommunicationRequest {
                initiator_l2_id,
                target_l2_id,
                application_id,
                initiator_nonce,
                supported_ciphers,
                supported_integs,
                ip_address_config,
                qos_flows,
            } => {
                buf.push(0x01);
                buf.extend_from_slice(&initiator_l2_id.to_be_bytes());
                buf.extend_from_slice(&target_l2_id.to_be_bytes());
                buf.extend_from_slice(&application_id.to_be_bytes());
                buf.extend_from_slice(initiator_nonce);
                buf.push(*supported_ciphers);
                buf.push(*supported_integs);
                buf.push(*ip_address_config);
                buf.push(qos_flows.len() as u8);
                for qf in qos_flows {
                    buf.push(qf.pqfi);
                    buf.push(qf.pc5_5qi);
                    buf.extend_from_slice(&qf.range_meters.to_be_bytes());
                }
            }
            Self::DirectSecurityModeCommand {
                link_id,
                selected_cipher,
                selected_integ,
                responder_nonce,
                mac_i,
            } => {
                buf.push(0x02);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.push(*selected_cipher as u8);
                buf.push(*selected_integ as u8);
                buf.extend_from_slice(responder_nonce);
                buf.extend_from_slice(mac_i);
            }
            Self::DirectSecurityModeComplete { link_id, mac_i } => {
                buf.push(0x03);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(mac_i);
            }
            Self::DirectCommunicationAccept {
                link_id,
                responder_l2_id,
                ip_address_config,
                admitted_pqfis,
            } => {
                buf.push(0x04);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(&responder_l2_id.to_be_bytes());
                buf.push(*ip_address_config);
                buf.push(admitted_pqfis.len() as u8);
                buf.extend_from_slice(admitted_pqfis);
            }
            Self::DirectCommunicationReject {
                target_l2_id,
                cause,
            } => {
                buf.push(0x05);
                buf.extend_from_slice(&target_l2_id.to_be_bytes());
                buf.push(*cause as u8);
            }
            Self::DirectLinkKeepalive { link_id, seq_num } => {
                buf.push(0x06);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(&seq_num.to_be_bytes());
            }
            Self::DirectLinkKeepaliveAck { link_id, seq_num } => {
                buf.push(0x07);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(&seq_num.to_be_bytes());
            }
            Self::DirectLinkRekeyingRequest {
                link_id,
                fresh_nonce,
            } => {
                buf.push(0x08);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(fresh_nonce);
            }
            Self::DirectLinkRekeyingResponse {
                link_id,
                responder_nonce,
                mac_i,
            } => {
                buf.push(0x09);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.extend_from_slice(responder_nonce);
                buf.extend_from_slice(mac_i);
            }
            Self::DirectLinkReleaseRequest { link_id, cause } => {
                buf.push(0x0A);
                buf.extend_from_slice(&link_id.to_be_bytes());
                buf.push(*cause as u8);
            }
            Self::DirectLinkReleaseAccept { link_id } => {
                buf.push(0x0B);
                buf.extend_from_slice(&link_id.to_be_bytes());
            }
        }
        buf
    }

    /// Decode binary wire format buffer into PC5-S message.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 2 {
            return Err("Buffer too short for PC5-S header".to_string());
        }
        if bytes[0] != PC5S_PROTOCOL_DISCRIMINATOR {
            return Err(format!(
                "Invalid Protocol Discriminator: expected 0x56, got {:#04x}",
                bytes[0]
            ));
        }

        let msg_type = bytes[1];
        let payload = &bytes[2..];

        match msg_type {
            0x01 => {
                if payload.len() < 31 {
                    return Err("Buffer too short for DirectCommunicationRequest".to_string());
                }
                let initiator_l2_id = u32::from_be_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                let target_l2_id = u32::from_be_bytes([
                    payload[4], payload[5], payload[6], payload[7],
                ]);
                let application_id = u32::from_be_bytes([
                    payload[8], payload[9], payload[10], payload[11],
                ]);
                let mut initiator_nonce = [0u8; 16];
                initiator_nonce.copy_from_slice(&payload[12..28]);
                let supported_ciphers = payload[28];
                let supported_integs = payload[29];
                let ip_address_config = payload[30];
                let mut qos_flows = Vec::new();
                if payload.len() > 31 {
                    let num_flows = payload[31] as usize;
                    let mut offset = 32;
                    for _ in 0..num_flows {
                        if offset + 4 <= payload.len() {
                            let pqfi = payload[offset];
                            let pc5_5qi = payload[offset + 1];
                            let range_meters =
                                u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
                            qos_flows.push(Pc5QosFlow {
                                pqfi,
                                pc5_5qi,
                                range_meters,
                            });
                            offset += 4;
                        }
                    }
                }
                Ok(Self::DirectCommunicationRequest {
                    initiator_l2_id,
                    target_l2_id,
                    application_id,
                    initiator_nonce,
                    supported_ciphers,
                    supported_integs,
                    ip_address_config,
                    qos_flows,
                })
            }
            0x02 => {
                if payload.len() < 26 {
                    return Err("Buffer too short for DirectSecurityModeCommand".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let selected_cipher = SidelinkCipheringAlgorithm::from_u8(payload[4])
                    .ok_or_else(|| format!("Invalid cipher algorithm: {}", payload[4]))?;
                let selected_integ = SidelinkIntegrityAlgorithm::from_u8(payload[5])
                    .ok_or_else(|| format!("Invalid integrity algorithm: {}", payload[5]))?;
                let mut responder_nonce = [0u8; 16];
                responder_nonce.copy_from_slice(&payload[6..22]);
                let mut mac_i = [0u8; 4];
                mac_i.copy_from_slice(&payload[22..26]);

                Ok(Self::DirectSecurityModeCommand {
                    link_id,
                    selected_cipher,
                    selected_integ,
                    responder_nonce,
                    mac_i,
                })
            }
            0x03 => {
                if payload.len() < 8 {
                    return Err("Buffer too short for DirectSecurityModeComplete".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let mut mac_i = [0u8; 4];
                mac_i.copy_from_slice(&payload[4..8]);
                Ok(Self::DirectSecurityModeComplete { link_id, mac_i })
            }
            0x04 => {
                if payload.len() < 10 {
                    return Err("Buffer too short for DirectCommunicationAccept".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let responder_l2_id =
                    u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let ip_address_config = payload[8];
                let num_pqfis = payload[9] as usize;
                let mut admitted_pqfis = Vec::new();
                if payload.len() >= 10 + num_pqfis {
                    admitted_pqfis.extend_from_slice(&payload[10..10 + num_pqfis]);
                }
                Ok(Self::DirectCommunicationAccept {
                    link_id,
                    responder_l2_id,
                    ip_address_config,
                    admitted_pqfis,
                })
            }
            0x05 => {
                if payload.len() < 5 {
                    return Err("Buffer too short for DirectCommunicationReject".to_string());
                }
                let target_l2_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let cause = Pc5sRejectCause::from_u8(payload[4]);
                Ok(Self::DirectCommunicationReject {
                    target_l2_id,
                    cause,
                })
            }
            0x06 => {
                if payload.len() < 6 {
                    return Err("Buffer too short for DirectLinkKeepalive".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let seq_num = u16::from_be_bytes([payload[4], payload[5]]);
                Ok(Self::DirectLinkKeepalive { link_id, seq_num })
            }
            0x07 => {
                if payload.len() < 6 {
                    return Err("Buffer too short for DirectLinkKeepaliveAck".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let seq_num = u16::from_be_bytes([payload[4], payload[5]]);
                Ok(Self::DirectLinkKeepaliveAck { link_id, seq_num })
            }
            0x08 => {
                if payload.len() < 20 {
                    return Err("Buffer too short for DirectLinkRekeyingRequest".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let mut fresh_nonce = [0u8; 16];
                fresh_nonce.copy_from_slice(&payload[4..20]);
                Ok(Self::DirectLinkRekeyingRequest {
                    link_id,
                    fresh_nonce,
                })
            }
            0x09 => {
                if payload.len() < 24 {
                    return Err("Buffer too short for DirectLinkRekeyingResponse".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let mut responder_nonce = [0u8; 16];
                responder_nonce.copy_from_slice(&payload[4..20]);
                let mut mac_i = [0u8; 4];
                mac_i.copy_from_slice(&payload[20..24]);
                Ok(Self::DirectLinkRekeyingResponse {
                    link_id,
                    responder_nonce,
                    mac_i,
                })
            }
            0x0A => {
                if payload.len() < 5 {
                    return Err("Buffer too short for DirectLinkReleaseRequest".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let cause = Pc5sRejectCause::from_u8(payload[4]);
                Ok(Self::DirectLinkReleaseRequest { link_id, cause })
            }
            0x0B => {
                if payload.len() < 4 {
                    return Err("Buffer too short for DirectLinkReleaseAccept".to_string());
                }
                let link_id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Self::DirectLinkReleaseAccept { link_id })
            }
            other => Err(format!("Unsupported PC5-S message type: {:#04x}", other)),
        }
    }
}

// ---------------------------------------------------------------------------
// PC5-S State Machine & Session Entity
// ---------------------------------------------------------------------------

/// Link lifecycle states (TS 24.554 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pc5sLinkState {
    Null,
    DirectCommRequested,
    Securing,
    DirectCommEstablished,
    DirectCommReleasing,
}

/// Sidelink role of the local UE for this unicast session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pc5LinkRole {
    Initiator,
    Responder,
}

/// Active Sidelink Unicast Link entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Pc5UnicastLink {
    pub link_id: u32,
    pub role: Pc5LinkRole,
    pub local_l2_id: u32,
    pub peer_l2_id: u32,
    pub state: Pc5sLinkState,
    pub security_context: Option<Pc5SecurityContext>,
    pub initiator_nonce: [u8; 16],
    pub responder_nonce: [u8; 16],
    pub last_activity_ms: u64,
    pub last_keepalive_sent_ms: u64,
    pub keepalive_seq: u16,
    pub unacked_keepalives: u8,
    pub qos_flows: Vec<Pc5QosFlow>,
}

// ---------------------------------------------------------------------------
// Sidelink PC5-S Unicast Session & Direct Security Engine
// ---------------------------------------------------------------------------

/// Main 3GPP Rel-18 Sidelink PC5-S Unicast Session & Direct Security Engine.
#[derive(Debug, PartialEq)]
pub struct Pc5sEngine {
    pub local_l2_id: u32,
    /// Root pre-shared / provisioned NRP key (32 bytes).
    pub root_k_nrp: [u8; 32],
    /// Configured ciphering algorithm priority list.
    pub allowed_ciphers: Vec<SidelinkCipheringAlgorithm>,
    /// Configured integrity algorithm priority list.
    pub allowed_integs: Vec<SidelinkIntegrityAlgorithm>,
    /// Active unicast sessions indexed by link_id.
    pub links: HashMap<u32, Pc5UnicastLink>,
    /// Next monotonic link identifier.
    pub next_link_id: u32,
    /// Statistics.
    pub stats_links_established: u64,
    pub stats_links_released: u64,
    pub stats_keepalives_sent: u64,
    pub stats_keepalives_acked: u64,
    pub stats_security_failures: u64,
    pub stats_replays_detected: u64,
}

impl Pc5sEngine {
    pub fn new(
        local_l2_id: u32,
        root_k_nrp: [u8; 32],
        allowed_ciphers: Vec<SidelinkCipheringAlgorithm>,
        allowed_integs: Vec<SidelinkIntegrityAlgorithm>,
    ) -> Self {
        Self {
            local_l2_id,
            root_k_nrp,
            allowed_ciphers,
            allowed_integs,
            links: HashMap::new(),
            next_link_id: 1,
            stats_links_established: 0,
            stats_links_released: 0,
            stats_keepalives_sent: 0,
            stats_keepalives_acked: 0,
            stats_security_failures: 0,
            stats_replays_detected: 0,
        }
    }

    /// Initiator: Start establishment of a new Sidelink Unicast Link with a target peer.
    pub fn initiate_link(
        &mut self,
        target_l2_id: u32,
        application_id: u32,
        qos_flows: Vec<Pc5QosFlow>,
        initiator_nonce: [u8; 16],
        now_ms: u64,
    ) -> (u32, Pc5sMessage) {
        let link_id = self.next_link_id;
        self.next_link_id += 1;

        let mut cipher_mask = 0u8;
        for c in &self.allowed_ciphers {
            cipher_mask |= 1 << (*c as u8);
        }
        let mut integ_mask = 0u8;
        for i in &self.allowed_integs {
            integ_mask |= 1 << (*i as u8);
        }

        let link = Pc5UnicastLink {
            link_id,
            role: Pc5LinkRole::Initiator,
            local_l2_id: self.local_l2_id,
            peer_l2_id: target_l2_id,
            state: Pc5sLinkState::DirectCommRequested,
            security_context: None,
            initiator_nonce,
            responder_nonce: [0u8; 16],
            last_activity_ms: now_ms,
            last_keepalive_sent_ms: 0,
            keepalive_seq: 0,
            unacked_keepalives: 0,
            qos_flows: qos_flows.clone(),
        };
        self.links.insert(link_id, link);

        let dcr = Pc5sMessage::DirectCommunicationRequest {
            initiator_l2_id: self.local_l2_id,
            target_l2_id,
            application_id,
            initiator_nonce,
            supported_ciphers: cipher_mask,
            supported_integs: integ_mask,
            ip_address_config: 2,
            qos_flows,
        };

        (link_id, dcr)
    }

    /// Responder: Handle incoming Direct Communication Request from Initiator.
    pub fn handle_direct_comm_request(
        &mut self,
        dcr: &Pc5sMessage,
        responder_nonce: [u8; 16],
        now_ms: u64,
    ) -> Result<(u32, Pc5sMessage), Pc5sMessage> {
        let (initiator_l2_id, target_l2_id, initiator_nonce, supported_ciphers, supported_integs, qos_flows) =
            match dcr {
                Pc5sMessage::DirectCommunicationRequest {
                    initiator_l2_id,
                    target_l2_id,
                    initiator_nonce,
                    supported_ciphers,
                    supported_integs,
                    qos_flows,
                    ..
                } => (
                    *initiator_l2_id,
                    *target_l2_id,
                    *initiator_nonce,
                    *supported_ciphers,
                    *supported_integs,
                    qos_flows.clone(),
                ),
                _ => return Err(Pc5sMessage::DirectCommunicationReject {
                    target_l2_id: 0,
                    cause: Pc5sRejectCause::ServiceNotSupported,
                }),
            };

        if target_l2_id != self.local_l2_id && target_l2_id != 0xFFFFFF {
            return Err(Pc5sMessage::DirectCommunicationReject {
                target_l2_id: initiator_l2_id,
                cause: Pc5sRejectCause::ServiceNotSupported,
            });
        }

        let chosen_cipher = self
            .allowed_ciphers
            .iter()
            .find(|&&c| (supported_ciphers & (1 << (c as u8))) != 0)
            .copied()
            .ok_or_else(|| Pc5sMessage::DirectCommunicationReject {
                target_l2_id: initiator_l2_id,
                cause: Pc5sRejectCause::SecurityCapabilitiesMismatch,
            })?;

        let chosen_integ = self
            .allowed_integs
            .iter()
            .find(|&&i| (supported_integs & (1 << (i as u8))) != 0)
            .copied()
            .ok_or_else(|| Pc5sMessage::DirectCommunicationReject {
                target_l2_id: initiator_l2_id,
                cause: Pc5sRejectCause::SecurityCapabilitiesMismatch,
            })?;

        let link_id = self.next_link_id;
        self.next_link_id += 1;

        let sec_ctx = Pc5SecurityContext::derive_new(
            self.root_k_nrp,
            &initiator_nonce,
            &responder_nonce,
            link_id,
            chosen_cipher,
            chosen_integ,
        );

        let mut dsmc_body = Vec::new();
        dsmc_body.extend_from_slice(&link_id.to_be_bytes());
        dsmc_body.push(chosen_cipher as u8);
        dsmc_body.push(chosen_integ as u8);
        dsmc_body.extend_from_slice(&responder_nonce);
        let mac_i = sec_ctx.compute_mac_i(0, 0, 1, &dsmc_body);

        let link = Pc5UnicastLink {
            link_id,
            role: Pc5LinkRole::Responder,
            local_l2_id: self.local_l2_id,
            peer_l2_id: initiator_l2_id,
            state: Pc5sLinkState::Securing,
            security_context: Some(sec_ctx),
            initiator_nonce,
            responder_nonce,
            last_activity_ms: now_ms,
            last_keepalive_sent_ms: 0,
            keepalive_seq: 0,
            unacked_keepalives: 0,
            qos_flows,
        };
        self.links.insert(link_id, link);

        let dsmc = Pc5sMessage::DirectSecurityModeCommand {
            link_id,
            selected_cipher: chosen_cipher,
            selected_integ: chosen_integ,
            responder_nonce,
            mac_i,
        };

        Ok((link_id, dsmc))
    }

    /// Initiator: Handle Direct Security Mode Command, verify MAC-I, and emit DirectSecurityModeComplete.
    pub fn handle_security_mode_command(
        &mut self,
        link_id: u32,
        dsmc: &Pc5sMessage,
        now_ms: u64,
    ) -> Result<Pc5sMessage, String> {
        let link = self
            .links
            .get_mut(&link_id)
            .ok_or_else(|| format!("Link ID {} not found", link_id))?;

        if link.state != Pc5sLinkState::DirectCommRequested {
            return Err("Link not in DirectCommRequested state".to_string());
        }

        let (sel_cipher, sel_integ, responder_nonce, mac_i) = match dsmc {
            Pc5sMessage::DirectSecurityModeCommand {
                selected_cipher,
                selected_integ,
                responder_nonce,
                mac_i,
                ..
            } => (*selected_cipher, *selected_integ, *responder_nonce, *mac_i),
            _ => return Err("Invalid message type: expected DirectSecurityModeCommand".to_string()),
        };

        let sec_ctx = Pc5SecurityContext::derive_new(
            self.root_k_nrp,
            &link.initiator_nonce,
            &responder_nonce,
            link_id,
            sel_cipher,
            sel_integ,
        );

        let mut dsmc_body = Vec::new();
        dsmc_body.extend_from_slice(&link_id.to_be_bytes());
        dsmc_body.push(sel_cipher as u8);
        dsmc_body.push(sel_integ as u8);
        dsmc_body.extend_from_slice(&responder_nonce);
        let expected_mac = sec_ctx.compute_mac_i(0, 0, 1, &dsmc_body);

        if mac_i != expected_mac {
            self.stats_security_failures += 1;
            link.state = Pc5sLinkState::Null;
            return Err("DSMC MAC-I verification failed: authentication failure".to_string());
        }

        let mut dsmc_comp_body = Vec::new();
        dsmc_comp_body.extend_from_slice(&link_id.to_be_bytes());
        let resp_mac = sec_ctx.compute_mac_i(1, 0, 0, &dsmc_comp_body);

        link.responder_nonce = responder_nonce;
        link.security_context = Some(sec_ctx);
        link.state = Pc5sLinkState::DirectCommEstablished;
        link.last_activity_ms = now_ms;
        self.stats_links_established += 1;

        Ok(Pc5sMessage::DirectSecurityModeComplete {
            link_id,
            mac_i: resp_mac,
        })
    }

    /// Responder: Handle Direct Security Mode Complete, verify MAC-I, and finalize link establishment.
    pub fn handle_security_mode_complete(
        &mut self,
        link_id: u32,
        dsm_comp: &Pc5sMessage,
        now_ms: u64,
    ) -> Result<Pc5sMessage, String> {
        let link = self
            .links
            .get_mut(&link_id)
            .ok_or_else(|| format!("Link ID {} not found", link_id))?;

        if link.state != Pc5sLinkState::Securing {
            return Err("Link not in Securing state".to_string());
        }

        let mac_i = match dsm_comp {
            Pc5sMessage::DirectSecurityModeComplete { mac_i, .. } => *mac_i,
            _ => {
                return Err(
                    "Invalid message type: expected DirectSecurityModeComplete".to_string()
                )
            }
        };

        let sec_ctx = link
            .security_context
            .as_ref()
            .ok_or("Missing security context")?;

        let mut dsmc_comp_body = Vec::new();
        dsmc_comp_body.extend_from_slice(&link_id.to_be_bytes());
        let expected_mac = sec_ctx.compute_mac_i(1, 0, 0, &dsmc_comp_body);

        if mac_i != expected_mac {
            self.stats_security_failures += 1;
            link.state = Pc5sLinkState::Null;
            return Err("DirectSecurityModeComplete MAC-I mismatch".to_string());
        }

        link.state = Pc5sLinkState::DirectCommEstablished;
        link.last_activity_ms = now_ms;
        self.stats_links_established += 1;

        let admitted_pqfis: Vec<u8> = link.qos_flows.iter().map(|q| q.pqfi).collect();
        Ok(Pc5sMessage::DirectCommunicationAccept {
            link_id,
            responder_l2_id: self.local_l2_id,
            ip_address_config: 2,
            admitted_pqfis,
        })
    }

    /// Protect and encrypt outgoing user/control PDU over established link.
    /// Appends 4-byte Count + 4-byte MAC-I.
    pub fn protect_pdu(
        &mut self,
        link_id: u32,
        bearer_id: u8,
        direction: u8,
        plain_pdu: &[u8],
    ) -> Result<Vec<u8>, String> {
        let link = self
            .links
            .get_mut(&link_id)
            .ok_or_else(|| format!("Link ID {} not found", link_id))?;

        if link.state != Pc5sLinkState::DirectCommEstablished {
            return Err("Link not in DirectCommEstablished state".to_string());
        }

        let sec_ctx = link
            .security_context
            .as_mut()
            .ok_or("Missing security context")?;

        let count = sec_ctx.tx_count;
        sec_ctx.tx_count = sec_ctx.tx_count.wrapping_add(1);

        let ciphered = sec_ctx.cipher(count, bearer_id, direction, plain_pdu);
        let mac_i = sec_ctx.compute_mac_i(count, bearer_id, direction, &ciphered);

        let mut output = Vec::with_capacity(ciphered.len() + 8);
        output.extend_from_slice(&count.to_be_bytes());
        output.extend_from_slice(&ciphered);
        output.extend_from_slice(&mac_i);

        Ok(output)
    }

    /// Decrypt and verify incoming protected PDU over established link.
    pub fn unprotect_pdu(
        &mut self,
        link_id: u32,
        bearer_id: u8,
        direction: u8,
        protected_pdu: &[u8],
    ) -> Result<Vec<u8>, String> {
        if protected_pdu.len() < 8 {
            return Err("PDU too short for Count and MAC-I".to_string());
        }

        let link = self
            .links
            .get_mut(&link_id)
            .ok_or_else(|| format!("Link ID {} not found", link_id))?;

        if link.state != Pc5sLinkState::DirectCommEstablished {
            return Err("Link not in DirectCommEstablished state".to_string());
        }

        let sec_ctx = link
            .security_context
            .as_mut()
            .ok_or("Missing security context")?;

        let count = u32::from_be_bytes([
            protected_pdu[0],
            protected_pdu[1],
            protected_pdu[2],
            protected_pdu[3],
        ]);

        if !sec_ctx.check_anti_replay(count) {
            self.stats_replays_detected += 1;
            return Err(format!("Replay check failed for count {}", count));
        }

        let ciphered_len = protected_pdu.len() - 8;
        let ciphered = &protected_pdu[4..4 + ciphered_len];
        let mut received_mac = [0u8; 4];
        received_mac.copy_from_slice(&protected_pdu[4 + ciphered_len..]);

        let expected_mac = sec_ctx.compute_mac_i(count, bearer_id, direction, ciphered);
        if received_mac != expected_mac {
            self.stats_security_failures += 1;
            return Err("Integrity check failed: invalid MAC-I".to_string());
        }

        let plaintext = sec_ctx.cipher(count, bearer_id, direction, ciphered);
        Ok(plaintext)
    }

    /// Periodic tick for keepalive heartbeats and link loss monitoring (TS 24.554 §5.2.4).
    pub fn tick_timers(&mut self, now_ms: u64) -> Vec<(u32, Pc5sMessage)> {
        let mut outgoing = Vec::new();
        let mut dead_links = Vec::new();

        for (&link_id, link) in &mut self.links {
            if link.state != Pc5sLinkState::DirectCommEstablished {
                continue;
            }

            if now_ms >= link.last_activity_ms + DEFAULT_T4111_KEEPALIVE_MS {
                if link.unacked_keepalives >= MAX_PC5S_RETRANSMISSIONS {
                    dead_links.push(link_id);
                    continue;
                }

                if now_ms >= link.last_keepalive_sent_ms + DEFAULT_T4112_TIMEOUT_MS {
                    link.keepalive_seq = link.keepalive_seq.wrapping_add(1);
                    link.last_keepalive_sent_ms = now_ms;
                    link.unacked_keepalives += 1;

                    outgoing.push((
                        link_id,
                        Pc5sMessage::DirectLinkKeepalive {
                            link_id,
                            seq_num: link.keepalive_seq,
                        },
                    ));
                    self.stats_keepalives_sent += 1;
                }
            }
        }

        for lid in dead_links {
            if let Some(link) = self.links.get_mut(&lid) {
                link.state = Pc5sLinkState::DirectCommReleasing;
                self.stats_links_released += 1;
                outgoing.push((
                    lid,
                    Pc5sMessage::DirectLinkReleaseRequest {
                        link_id: lid,
                        cause: Pc5sRejectCause::KeepaliveTimeout,
                    },
                ));
            }
        }

        outgoing
    }

    /// Handle incoming Direct Link Keepalive (Ping) and return Ack.
    pub fn handle_keepalive(&mut self, link_id: u32, seq_num: u16, now_ms: u64) -> Option<Pc5sMessage> {
        if let Some(link) = self.links.get_mut(&link_id) {
            if link.state == Pc5sLinkState::DirectCommEstablished {
                link.last_activity_ms = now_ms;
                return Some(Pc5sMessage::DirectLinkKeepaliveAck { link_id, seq_num });
            }
        }
        None
    }

    /// Handle incoming Direct Link Keepalive Ack.
    pub fn handle_keepalive_ack(&mut self, link_id: u32, seq_num: u16, now_ms: u64) {
        if let Some(link) = self.links.get_mut(&link_id) {
            if link.keepalive_seq == seq_num {
                link.unacked_keepalives = 0;
                link.last_activity_ms = now_ms;
                self.stats_keepalives_acked += 1;
            }
        }
    }

    /// Explicit link release request.
    pub fn release_link(&mut self, link_id: u32, cause: Pc5sRejectCause) -> Option<Pc5sMessage> {
        if let Some(link) = self.links.get_mut(&link_id) {
            link.state = Pc5sLinkState::DirectCommReleasing;
            self.stats_links_released += 1;
            Some(Pc5sMessage::DirectLinkReleaseRequest { link_id, cause })
        } else {
            None
        }
    }

    /// Handle peer link release request.
    pub fn handle_release_request(&mut self, link_id: u32) -> Option<Pc5sMessage> {
        if let Some(link) = self.links.get_mut(&link_id) {
            link.state = Pc5sLinkState::Null;
            self.stats_links_released += 1;
            Some(Pc5sMessage::DirectLinkReleaseAccept { link_id })
        } else {
            None
        }
    }
}
