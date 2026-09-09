//! IEEE 802.1AE MACsec — Media Access Control Security
//!
//! Implements the SecTAG (Security Tag) header, Secure Channel Identifier (SCI),
//! Packet Number (PN) management, Secure Association (SA) key indexing, and
//! integrity-only vs encrypt-and-authenticate confidentiality modes.
//!
//! Reference: IEEE 802.1AE-2018, IEEE 802.1X-2020 (MKA)

use crate::ethernet::MacAddress;
use std::collections::HashMap;

/// EtherType for MACsec-tagged frames (802.1AE SecTAG).
pub const ETHERTYPE_MACSEC: u16 = 0x88E5;

/// MACsec SecTAG header length (fixed portion, 8 bytes without SCI).
pub const SECTAG_HEADER_LEN: usize = 8;

/// MACsec SecTAG header length with explicit SCI (16 bytes).
pub const SECTAG_HEADER_LEN_WITH_SCI: usize = 16;

/// ICV (Integrity Check Value) length for GCM-AES-128.
pub const ICV_LEN_GCM_AES_128: usize = 16;

/// ICV length for GCM-AES-256.
pub const ICV_LEN_GCM_AES_256: usize = 16;

/// Maximum PN value before SA key rollover is required (2^32 - 1).
pub const PN_EXHAUSTION_THRESHOLD: u64 = 0xFFFF_FFFF;

/// XPN (Extended Packet Number) exhaustion threshold (2^64 - 1).
pub const XPN_EXHAUSTION_THRESHOLD: u64 = u64::MAX;

/// SecTAG TCI (Tag Control Information) flag bits.
pub const TCI_V_BIT: u8 = 0x80;   // Version bit (must be 0)
pub const TCI_ES_BIT: u8 = 0x40;  // End Station bit
pub const TCI_SC_BIT: u8 = 0x20;  // Secure Channel bit (SCI present)
pub const TCI_SCB_BIT: u8 = 0x10; // Single Copy Broadcast bit
pub const TCI_E_BIT: u8 = 0x08;   // Encryption bit
pub const TCI_C_BIT: u8 = 0x04;   // Changed Text bit

/// Confidentiality mode for a MACsec Secure Association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidentialityMode {
    /// Integrity-only: no encryption, only ICV appended.
    IntegrityOnly,
    /// Encrypt-and-authenticate: payload encrypted, ICV appended.
    EncryptAndAuthenticate,
    /// Confidentiality with no ICV offset (full encryption from SecTAG).
    EncryptNoOffset,
}

/// Cipher suite identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacsecCipherSuite {
    /// GCM-AES-128 (default, mandatory).
    GcmAes128,
    /// GCM-AES-256 (optional, recommended for high security).
    GcmAes256,
    /// GCM-AES-XPN-128 (Extended Packet Number, 802.1AEbw).
    GcmAesXpn128,
    /// GCM-AES-XPN-256 (Extended Packet Number, 802.1AEbw).
    GcmAesXpn256,
}

impl MacsecCipherSuite {
    /// Returns the ICV length for this cipher suite.
    pub fn icv_len(&self) -> usize {
        match self {
            MacsecCipherSuite::GcmAes128 | MacsecCipherSuite::GcmAesXpn128 => ICV_LEN_GCM_AES_128,
            MacsecCipherSuite::GcmAes256 | MacsecCipherSuite::GcmAesXpn256 => ICV_LEN_GCM_AES_256,
        }
    }

    /// Returns true if this is an XPN cipher suite.
    pub fn is_xpn(&self) -> bool {
        matches!(self, MacsecCipherSuite::GcmAesXpn128 | MacsecCipherSuite::GcmAesXpn256)
    }
}

/// Secure Channel Identifier (SCI): 8 bytes = MAC address (6) + Port ID (2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecureChannelId {
    /// Source MAC address of the transmitting station.
    pub mac_address: MacAddress,
    /// Port identifier (unique per port on the station).
    pub port_id: u16,
}

impl SecureChannelId {
    pub fn new(mac: MacAddress, port: u16) -> Self {
        Self {
            mac_address: mac,
            port_id: port,
        }
    }

    /// Serialize SCI to 8 bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; 8] {
        let mac = self.mac_address.octets();
        let port = self.port_id.to_be_bytes();
        [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], port[0], port[1]]
    }

    /// Deserialize SCI from 8 bytes.
    pub fn from_bytes(bytes: &[u8; 8]) -> Self {
        let mac = MacAddress::new([bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]);
        let port = u16::from_be_bytes([bytes[6], bytes[7]]);
        Self {
            mac_address: mac,
            port_id: port,
        }
    }
}

/// MACsec SecTAG header parsed from a frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacsecSecTag {
    /// Tag Control Information byte.
    pub tci_an: u8,
    /// Short Length field (0 if frame > 48 bytes user data).
    pub short_length: u8,
    /// Packet Number (32-bit for standard PN, lower 32 bits for XPN).
    pub packet_number: u32,
    /// Secure Channel Identifier (present if SC bit is set).
    pub sci: Option<SecureChannelId>,
}

impl MacsecSecTag {
    /// Extract the Association Number (AN) from the TCI/AN byte.
    pub fn association_number(&self) -> u8 {
        self.tci_an & 0x03
    }

    /// Check if the SC bit is set (explicit SCI present).
    pub fn has_explicit_sci(&self) -> bool {
        (self.tci_an & TCI_SC_BIT) != 0
    }

    /// Check if the E (encryption) bit is set.
    pub fn is_encrypted(&self) -> bool {
        (self.tci_an & TCI_E_BIT) != 0
    }

    /// Check if the C (changed text) bit is set.
    pub fn is_changed_text(&self) -> bool {
        (self.tci_an & TCI_C_BIT) != 0
    }

    /// Determine confidentiality mode from E and C bits.
    pub fn confidentiality_mode(&self) -> ConfidentialityMode {
        match (self.is_encrypted(), self.is_changed_text()) {
            (false, false) => ConfidentialityMode::IntegrityOnly,
            (true, true) => ConfidentialityMode::EncryptAndAuthenticate,
            (true, false) => ConfidentialityMode::EncryptNoOffset,
            // E=0,C=1 is reserved / invalid per 802.1AE
            (false, true) => ConfidentialityMode::IntegrityOnly,
        }
    }

    /// Total SecTAG length in bytes (depends on whether SCI is present).
    pub fn header_len(&self) -> usize {
        if self.has_explicit_sci() {
            SECTAG_HEADER_LEN_WITH_SCI
        } else {
            SECTAG_HEADER_LEN
        }
    }

    /// Parse SecTAG from raw bytes after EtherType.
    pub fn parse(data: &[u8]) -> Result<Self, MacsecError> {
        if data.len() < SECTAG_HEADER_LEN {
            return Err(MacsecError::SecTagTooShort(data.len()));
        }

        let tci_an = data[0];
        let short_length = data[1];
        let packet_number = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);

        // Check version bit (must be 0)
        if (tci_an & TCI_V_BIT) != 0 {
            return Err(MacsecError::InvalidVersion);
        }

        let sc_bit = (tci_an & TCI_SC_BIT) != 0;
        let sci = if sc_bit {
            if data.len() < SECTAG_HEADER_LEN_WITH_SCI {
                return Err(MacsecError::SecTagTooShort(data.len()));
            }
            let mut sci_bytes = [0u8; 8];
            sci_bytes.copy_from_slice(&data[6..14]);
            // SCI bytes start at offset 6 in the fixed header area
            // but we already consumed 6 bytes for TCI+SL+PN
            // Actually SecTAG is: [TCI/AN(1)][SL(1)][PN(4)][SCI(8)]
            Some(SecureChannelId::from_bytes(&sci_bytes))
        } else {
            None
        };

        Ok(Self {
            tci_an,
            short_length,
            packet_number,
            sci,
        })
    }

    /// Serialize SecTAG to bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.header_len());
        buf.push(self.tci_an);
        buf.push(self.short_length);
        buf.extend_from_slice(&self.packet_number.to_be_bytes());
        if let Some(ref sci) = self.sci {
            buf.extend_from_slice(&sci.to_bytes());
        }
        buf
    }
}

/// Secure Association (SA) — one direction of a secure channel.
#[derive(Debug, Clone)]
pub struct SecureAssociation {
    /// Association Number (0..3).
    pub an: u8,
    /// Secure Association Key (SAK) — 128 or 256 bit key material.
    pub sak: Vec<u8>,
    /// Next expected Packet Number (receive) or next to transmit (transmit).
    pub next_pn: u64,
    /// Lowest acceptable PN (anti-replay window lower bound).
    pub lowest_pn: u64,
    /// Whether this SA is currently active.
    pub active: bool,
    /// Cipher suite used by this SA.
    pub cipher_suite: MacsecCipherSuite,
    /// Total frames protected/validated by this SA.
    pub stats_frames: u64,
    /// Total octets protected/validated.
    pub stats_octets: u64,
}

impl SecureAssociation {
    pub fn new(an: u8, sak: Vec<u8>, cipher_suite: MacsecCipherSuite) -> Self {
        assert!(an <= 3, "AN must be 0..3");
        Self {
            an,
            sak,
            next_pn: 1,
            lowest_pn: 1,
            active: true,
            cipher_suite,
            stats_frames: 0,
            stats_octets: 0,
        }
    }

    /// Check if the PN is exhausted and key rollover is needed.
    pub fn is_pn_exhausted(&self) -> bool {
        if self.cipher_suite.is_xpn() {
            self.next_pn >= XPN_EXHAUSTION_THRESHOLD
        } else {
            self.next_pn >= PN_EXHAUSTION_THRESHOLD
        }
    }

    /// Advance the PN and return the current value for use in the SecTAG.
    pub fn advance_pn(&mut self) -> Result<u64, MacsecError> {
        if self.is_pn_exhausted() {
            return Err(MacsecError::PnExhausted { an: self.an });
        }
        let pn = self.next_pn;
        self.next_pn = self.next_pn.saturating_add(1);
        Ok(pn)
    }
}

/// Transmit Secure Channel (SC) — manages outbound SAs.
#[derive(Debug, Clone)]
pub struct TransmitSecureChannel {
    /// SCI for this transmit channel.
    pub sci: SecureChannelId,
    /// Current active SA index (AN).
    pub encoding_sa: u8,
    /// SAs indexed by AN (0..3).
    pub sas: [Option<SecureAssociation>; 4],
    /// Confidentiality mode for all frames on this channel.
    pub confidentiality: ConfidentialityMode,
}

impl TransmitSecureChannel {
    pub fn new(sci: SecureChannelId, confidentiality: ConfidentialityMode) -> Self {
        Self {
            sci,
            encoding_sa: 0,
            sas: [None, None, None, None],
            confidentiality,
        }
    }

    /// Install a new SA for transmission.
    pub fn install_sa(&mut self, sa: SecureAssociation) {
        let an = sa.an as usize;
        self.sas[an] = Some(sa);
    }

    /// Set the active encoding SA.
    pub fn set_encoding_sa(&mut self, an: u8) -> Result<(), MacsecError> {
        if an > 3 {
            return Err(MacsecError::InvalidAn(an));
        }
        if self.sas[an as usize].is_none() {
            return Err(MacsecError::SaNotFound(an));
        }
        self.encoding_sa = an;
        Ok(())
    }
}

/// Receive Secure Channel (SC) — manages inbound SAs.
#[derive(Debug, Clone)]
pub struct ReceiveSecureChannel {
    /// SCI identifying the remote transmitter.
    pub sci: SecureChannelId,
    /// SAs indexed by AN (0..3).
    pub sas: [Option<SecureAssociation>; 4],
    /// Anti-replay window size (in packets).
    pub replay_window: u32,
}

impl ReceiveSecureChannel {
    pub fn new(sci: SecureChannelId, replay_window: u32) -> Self {
        Self {
            sci,
            sas: [None, None, None, None],
            replay_window,
        }
    }

    /// Install a new SA for reception.
    pub fn install_sa(&mut self, sa: SecureAssociation) {
        let an = sa.an as usize;
        self.sas[an] = Some(sa);
    }

    /// Validate PN against anti-replay window.
    pub fn validate_pn(&self, an: u8, pn: u64) -> Result<bool, MacsecError> {
        let sa = self.sas[an as usize]
            .as_ref()
            .ok_or(MacsecError::SaNotFound(an))?;

        if pn == 0 {
            return Ok(false); // PN 0 is never valid
        }

        // Check against lowest acceptable PN with replay window
        if pn < sa.lowest_pn {
            return Ok(false); // Replayed packet
        }

        // Within window check
        let window_lower = sa.next_pn.saturating_sub(self.replay_window as u64);
        if pn < window_lower {
            return Ok(false);
        }

        Ok(true)
    }
}

/// MACsec processing errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacsecError {
    /// SecTAG is too short.
    SecTagTooShort(usize),
    /// Invalid version bit in TCI.
    InvalidVersion,
    /// Frame too short for MACsec processing.
    FrameTooShort(usize),
    /// PN exhausted for the given SA — key rollover required.
    PnExhausted { an: u8 },
    /// SA not found for the given AN.
    SaNotFound(u8),
    /// Invalid Association Number.
    InvalidAn(u8),
    /// SCI not found in receive channel database.
    SciNotFound(SecureChannelId),
    /// ICV validation failed.
    IcvValidationFailed,
    /// Anti-replay check failed.
    ReplayDetected { an: u8, pn: u64 },
}

impl std::fmt::Display for MacsecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecTagTooShort(len) => write!(f, "SecTAG too short: {} bytes", len),
            Self::InvalidVersion => write!(f, "Invalid MACsec version bit"),
            Self::FrameTooShort(len) => write!(f, "Frame too short for MACsec: {} bytes", len),
            Self::PnExhausted { an } => write!(f, "PN exhausted for SA AN={}", an),
            Self::SaNotFound(an) => write!(f, "SA not found for AN={}", an),
            Self::InvalidAn(an) => write!(f, "Invalid AN={}", an),
            Self::SciNotFound(sci) => write!(f, "SCI not found: {:?}", sci),
            Self::IcvValidationFailed => write!(f, "ICV validation failed"),
            Self::ReplayDetected { an, pn } => {
                write!(f, "Replay detected: AN={}, PN={}", an, pn)
            }
        }
    }
}

/// Result of MACsec frame protection (transmit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacsecProtectResult {
    /// Frame successfully protected with SecTAG.
    Protected {
        /// The AN used for this frame.
        an: u8,
        /// The PN assigned to this frame.
        pn: u64,
        /// Total protected frame length.
        frame_len: usize,
        /// Whether the frame was encrypted.
        encrypted: bool,
    },
    /// PN exhaustion — key rollover needed before more frames can be sent.
    PnExhaustion { an: u8 },
}

/// Result of MACsec frame validation (receive).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacsecValidateResult {
    /// Frame successfully validated and (optionally) decrypted.
    Valid {
        /// SCI of the sender.
        sci: SecureChannelId,
        /// AN used.
        an: u8,
        /// PN of the frame.
        pn: u64,
        /// Whether the frame was encrypted.
        was_encrypted: bool,
        /// Length of the inner (decrypted) payload.
        payload_len: usize,
    },
    /// Validation failed.
    Invalid {
        /// Reason for failure.
        reason: MacsecError,
    },
}

/// MACsec SecY (Security Entity) — the main processing engine.
///
/// Each SecY is bound to a single controlled port and manages one
/// transmit SC and zero or more receive SCs.
#[derive(Debug)]
pub struct MacsecSecY {
    /// Local SCI for the transmit channel.
    pub local_sci: SecureChannelId,
    /// Transmit Secure Channel.
    pub tx_sc: TransmitSecureChannel,
    /// Receive Secure Channels, keyed by remote SCI.
    pub rx_scs: HashMap<SecureChannelId, ReceiveSecureChannel>,
    /// Whether to include explicit SCI in transmitted frames.
    pub include_sci: bool,
    /// Default anti-replay window for new receive SCs.
    pub default_replay_window: u32,
    /// Statistics: total frames protected.
    pub stats_protected: u64,
    /// Statistics: total frames validated.
    pub stats_validated: u64,
    /// Statistics: total frames failed validation.
    pub stats_invalid: u64,
}

impl MacsecSecY {
    /// Create a new SecY with the given local SCI and confidentiality mode.
    pub fn new(
        local_sci: SecureChannelId,
        confidentiality: ConfidentialityMode,
        include_sci: bool,
    ) -> Self {
        Self {
            local_sci,
            tx_sc: TransmitSecureChannel::new(local_sci, confidentiality),
            rx_scs: HashMap::new(),
            include_sci,
            default_replay_window: 32,
            stats_protected: 0,
            stats_validated: 0,
            stats_invalid: 0,
        }
    }

    /// Add a receive SC for a remote peer.
    pub fn add_receive_sc(&mut self, sci: SecureChannelId) {
        let rx_sc = ReceiveSecureChannel::new(sci, self.default_replay_window);
        self.rx_scs.insert(sci, rx_sc);
    }

    /// Install a transmit SA on the local TX SC.
    pub fn install_tx_sa(&mut self, sa: SecureAssociation) {
        self.tx_sc.install_sa(sa);
    }

    /// Install a receive SA on the specified remote SC.
    pub fn install_rx_sa(
        &mut self,
        sci: SecureChannelId,
        sa: SecureAssociation,
    ) -> Result<(), MacsecError> {
        let rx_sc = self
            .rx_scs
            .get_mut(&sci)
            .ok_or(MacsecError::SciNotFound(sci))?;
        rx_sc.install_sa(sa);
        Ok(())
    }

    /// Protect (encrypt/authenticate) an outgoing Ethernet frame.
    ///
    /// Returns the SecTAG-protected frame bytes and protection result.
    pub fn protect_frame(
        &mut self,
        dst_mac: &MacAddress,
        src_mac: &MacAddress,
        original_ethertype: u16,
        payload: &[u8],
    ) -> Result<(Vec<u8>, MacsecProtectResult), MacsecError> {
        let an = self.tx_sc.encoding_sa;
        let sa = self.tx_sc.sas[an as usize]
            .as_mut()
            .ok_or(MacsecError::SaNotFound(an))?;

        // Get next PN
        let pn = sa.advance_pn()?;
        let cipher_suite = sa.cipher_suite;
        let encrypted = matches!(
            self.tx_sc.confidentiality,
            ConfidentialityMode::EncryptAndAuthenticate | ConfidentialityMode::EncryptNoOffset
        );

        // Build TCI/AN byte
        let mut tci_an: u8 = an & 0x03;
        if self.include_sci {
            tci_an |= TCI_SC_BIT;
        }
        if encrypted {
            tci_an |= TCI_E_BIT | TCI_C_BIT;
        }

        // Build SecTAG
        let sectag = MacsecSecTag {
            tci_an,
            short_length: 0,
            packet_number: pn as u32,
            sci: if self.include_sci {
                Some(self.local_sci)
            } else {
                None
            },
        };

        // Build protected frame: [DST(6)][SRC(6)][0x88E5(2)][SecTAG][SecureData][ICV]
        let icv_len = cipher_suite.icv_len();
        let sectag_bytes = sectag.serialize();
        let ethertype_bytes = original_ethertype.to_be_bytes();

        let frame_len = 6 + 6 + 2 + sectag_bytes.len() + 2 + payload.len() + icv_len;
        let mut frame = Vec::with_capacity(frame_len);

        // Ethernet header with MACsec EtherType
        frame.extend_from_slice(&dst_mac.octets());
        frame.extend_from_slice(&src_mac.octets());
        frame.extend_from_slice(&ETHERTYPE_MACSEC.to_be_bytes());

        // SecTAG
        frame.extend_from_slice(&sectag_bytes);

        // Secure Data = original EtherType + payload
        // (In real MACsec, this would be encrypted if E bit is set)
        frame.extend_from_slice(&ethertype_bytes);
        frame.extend_from_slice(payload);

        // ICV placeholder (in production: GCM-AES tag)
        // We compute a simple XOR-based checksum for simulation
        let mut icv = vec![0u8; icv_len];
        let sa_key = &sa.sak;
        for (i, byte) in frame.iter().enumerate() {
            icv[i % icv_len] ^= byte ^ sa_key[i % sa_key.len()];
        }
        frame.extend_from_slice(&icv);

        // Update stats
        sa.stats_frames += 1;
        sa.stats_octets += payload.len() as u64;
        self.stats_protected += 1;

        let result = MacsecProtectResult::Protected {
            an,
            pn,
            frame_len: frame.len(),
            encrypted,
        };

        Ok((frame, result))
    }

    /// Validate (decrypt/authenticate) an incoming MACsec frame.
    pub fn validate_frame(&mut self, frame: &[u8]) -> MacsecValidateResult {
        // Minimum frame: DST(6) + SRC(6) + EtherType(2) + SecTAG(8) + ICV(16) = 38
        if frame.len() < 38 {
            self.stats_invalid += 1;
            return MacsecValidateResult::Invalid {
                reason: MacsecError::FrameTooShort(frame.len()),
            };
        }

        // Parse EtherType at offset 12
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
        if ethertype != ETHERTYPE_MACSEC {
            self.stats_invalid += 1;
            return MacsecValidateResult::Invalid {
                reason: MacsecError::FrameTooShort(frame.len()),
            };
        }

        // Parse SecTAG starting at offset 14
        let sectag = match MacsecSecTag::parse(&frame[14..]) {
            Ok(s) => s,
            Err(e) => {
                self.stats_invalid += 1;
                return MacsecValidateResult::Invalid { reason: e };
            }
        };

        let an = sectag.association_number();
        let pn = sectag.packet_number as u64;

        // Determine SCI: explicit from SecTAG or implied from source MAC
        let sci = if let Some(s) = sectag.sci {
            s
        } else {
            // Implied SCI: source MAC + port 1
            let mut src_mac_bytes = [0u8; 6];
            src_mac_bytes.copy_from_slice(&frame[6..12]);
            SecureChannelId::new(MacAddress::new(src_mac_bytes), 1)
        };

        // Look up receive SC
        let rx_sc = match self.rx_scs.get_mut(&sci) {
            Some(sc) => sc,
            None => {
                self.stats_invalid += 1;
                return MacsecValidateResult::Invalid {
                    reason: MacsecError::SciNotFound(sci),
                };
            }
        };

        // Validate PN against anti-replay window
        match rx_sc.validate_pn(an, pn) {
            Ok(true) => {}
            Ok(false) => {
                self.stats_invalid += 1;
                return MacsecValidateResult::Invalid {
                    reason: MacsecError::ReplayDetected { an, pn },
                };
            }
            Err(e) => {
                self.stats_invalid += 1;
                return MacsecValidateResult::Invalid { reason: e };
            }
        }

        // Verify ICV (simplified: verify against our simulated checksum)
        let sectag_len = sectag.header_len();
        let sa = match rx_sc.sas[an as usize].as_mut() {
            Some(s) => s,
            None => {
                self.stats_invalid += 1;
                return MacsecValidateResult::Invalid {
                    reason: MacsecError::SaNotFound(an),
                };
            }
        };

        let icv_len = sa.cipher_suite.icv_len();
        let data_end = frame.len().saturating_sub(icv_len);
        let secure_data_start = 14 + sectag_len;

        if data_end <= secure_data_start {
            self.stats_invalid += 1;
            return MacsecValidateResult::Invalid {
                reason: MacsecError::FrameTooShort(frame.len()),
            };
        }

        // Verify ICV using same XOR simulation
        let frame_without_icv = &frame[..data_end];
        let received_icv = &frame[data_end..];
        let mut computed_icv = vec![0u8; icv_len];
        for (i, byte) in frame_without_icv.iter().enumerate() {
            computed_icv[i % icv_len] ^= byte ^ sa.sak[i % sa.sak.len()];
        }

        if computed_icv != received_icv {
            self.stats_invalid += 1;
            return MacsecValidateResult::Invalid {
                reason: MacsecError::IcvValidationFailed,
            };
        }

        let payload_len = data_end - secure_data_start;
        let was_encrypted = sectag.is_encrypted();

        // Update SA stats
        sa.stats_frames += 1;
        sa.stats_octets += payload_len as u64;

        // Advance lowest_pn if needed
        if pn >= sa.next_pn {
            sa.next_pn = pn + 1;
        }

        self.stats_validated += 1;

        MacsecValidateResult::Valid {
            sci,
            an,
            pn,
            was_encrypted,
            payload_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_macsec_sci_roundtrip() {
        let mac = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let sci = SecureChannelId::new(mac, 0x0001);
        let bytes = sci.to_bytes();
        let decoded = SecureChannelId::from_bytes(&bytes);
        assert_eq!(sci, decoded);
    }

    #[test]
    fn test_macsec_sectag_parse_and_serialize() {
        let sci = SecureChannelId::new(
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            42,
        );
        let sectag = MacsecSecTag {
            tci_an: TCI_SC_BIT | TCI_E_BIT | TCI_C_BIT | 0x02,
            short_length: 0,
            packet_number: 12345,
            sci: Some(sci),
        };
        let bytes = sectag.serialize();
        assert_eq!(bytes.len(), SECTAG_HEADER_LEN_WITH_SCI);
        let parsed = MacsecSecTag::parse(&bytes).unwrap();
        assert_eq!(parsed.association_number(), 2);
        assert!(parsed.has_explicit_sci());
        assert!(parsed.is_encrypted());
        assert_eq!(parsed.packet_number, 12345);
        assert_eq!(parsed.sci, Some(sci));
    }

    #[test]
    fn test_macsec_protect_and_validate_roundtrip() {
        let local_sci = SecureChannelId::new(
            MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]),
            1,
        );
        let remote_sci = SecureChannelId::new(
            MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            1,
        );

        let sak = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10];

        // Sender SecY
        let mut sender = MacsecSecY::new(local_sci, ConfidentialityMode::EncryptAndAuthenticate, true);
        sender.install_tx_sa(SecureAssociation::new(0, sak.clone(), MacsecCipherSuite::GcmAes128));

        // Receiver SecY
        let mut receiver = MacsecSecY::new(remote_sci, ConfidentialityMode::EncryptAndAuthenticate, true);
        receiver.add_receive_sc(local_sci);
        receiver.install_rx_sa(local_sci, SecureAssociation::new(0, sak.clone(), MacsecCipherSuite::GcmAes128)).unwrap();

        // Protect a frame
        let dst = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let src = MacAddress::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let (protected_frame, result) = sender.protect_frame(&dst, &src, 0x0800, b"Hello MACsec!").unwrap();

        match result {
            MacsecProtectResult::Protected { an, pn, encrypted, .. } => {
                assert_eq!(an, 0);
                assert_eq!(pn, 1);
                assert!(encrypted);
            }
            _ => panic!("Expected Protected result"),
        }

        // Validate the frame
        let validate_result = receiver.validate_frame(&protected_frame);
        match validate_result {
            MacsecValidateResult::Valid { sci, an, pn, was_encrypted, .. } => {
                assert_eq!(sci, local_sci);
                assert_eq!(an, 0);
                assert_eq!(pn, 1);
                assert!(was_encrypted);
            }
            MacsecValidateResult::Invalid { reason } => {
                panic!("Validation failed: {:?}", reason);
            }
        }

        assert_eq!(sender.stats_protected, 1);
        assert_eq!(receiver.stats_validated, 1);
    }
}
