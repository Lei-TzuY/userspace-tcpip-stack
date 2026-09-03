//! O-RAN WG4 Open Fronthaul Control Plane Section Extensions & Section Type 3 PRACH Engine.
//!
//! Implements O-RAN.WG4.CUS-Plane Section Extensions for Massive MIMO beamforming weights
//! (Section Extension 1), Beam Attributes (Section Extension 2), Modulation Compression
//! (Section Extension 4), and Section Type 3 PRACH / Mixed-Numerology scheduling frames.

use std::fmt;

/// O-RAN C-Plane Section Extension Types (O-RAN.WG4.CUS-Plane Section 7.5.3).
pub const ORAN_EXT_BEAMFORMING_WEIGHTS: u8 = 1;
pub const ORAN_EXT_BEAM_ATTRIBUTES: u8 = 2;
pub const ORAN_EXT_DL_PRECODING: u32 = 3;
pub const ORAN_EXT_MODULATION_COMPRESSION: u8 = 4;
pub const ORAN_EXT_FLEXIBLE_BF_WEIGHTS: u8 = 5;

/// O-RAN Section Type 3 for PRACH and Mixed-Numerology channels (Section 7.5.2).
pub const ORAN_SECTION_TYPE_3: u8 = 3;

/// Errors raised during C-Plane extensions and Section Type 3 parsing/serialization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OranCPlaneError {
    Truncated {
        need: usize,
        got: usize,
    },
    InvalidExtensionLength {
        declared_words: u16,
        actual_len: usize,
    },
    UnsupportedExtensionType(u8),
    UnsupportedSectionType(u8),
    AntennaCountMismatch {
        expected: usize,
        got: usize,
    },
    FieldOverflow {
        field: &'static str,
        val: u32,
        max: u32,
    },
    InvalidCompressionWidth(u8),
}

impl fmt::Display for OranCPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OranCPlaneError::Truncated { need, got } => {
                write!(
                    f,
                    "O-RAN C-Plane payload truncated: need {} bytes, got {}",
                    need, got
                )
            }
            OranCPlaneError::InvalidExtensionLength {
                declared_words,
                actual_len,
            } => {
                write!(
                    f,
                    "Invalid extension length: declared {} 32-bit words, buffer has {} bytes",
                    declared_words, actual_len
                )
            }
            OranCPlaneError::UnsupportedExtensionType(t) => {
                write!(f, "Unsupported Section Extension Type {}", t)
            }
            OranCPlaneError::UnsupportedSectionType(t) => {
                write!(f, "Unsupported Section Type {}, expected Type 3", t)
            }
            OranCPlaneError::AntennaCountMismatch { expected, got } => {
                write!(
                    f,
                    "Antenna count mismatch: expected {}, parsed {}",
                    expected, got
                )
            }
            OranCPlaneError::FieldOverflow { field, val, max } => {
                write!(
                    f,
                    "Field '{}' value {} exceeds maximum allowed {}",
                    field, val, max
                )
            }
            OranCPlaneError::InvalidCompressionWidth(w) => {
                write!(f, "Invalid BFW compression bit width {}", w)
            }
        }
    }
}

impl std::error::Error for OranCPlaneError {}

/// Beamforming weight compression method (O-RAN.WG4.CUS-Plane Table 7-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BfwCompressionMethod {
    Uncompressed = 0,
    BlockFloatingPoint = 1,
    BlockScaling = 2,
    MuLaw = 3,
}

impl BfwCompressionMethod {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x07 {
            1 => BfwCompressionMethod::BlockFloatingPoint,
            2 => BfwCompressionMethod::BlockScaling,
            3 => BfwCompressionMethod::MuLaw,
            _ => BfwCompressionMethod::Uncompressed,
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}

/// Complex Beamforming weight for a single antenna element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BfwWeight {
    pub re: i16,
    pub im: i16,
}

impl BfwWeight {
    pub fn new(re: i16, im: i16) -> Self {
        Self { re, im }
    }
}

/// Beamforming Weight Bundle applied across a contiguous group of PRBs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfwBundle {
    pub exponent: u8,
    pub weights: Vec<BfwWeight>,
}

impl BfwBundle {
    pub fn new(exponent: u8, weights: Vec<BfwWeight>) -> Self {
        Self { exponent, weights }
    }
}

/// Section Extension 1: Beamforming Weights (O-RAN.WG4.CUS-Plane Section 7.5.3.1).
///
/// Carries digital beamforming weight matrices for massive MIMO antenna arrays (e.g. 32T32R, 64T64R).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionExtension1 {
    pub bfw_comp_meth: BfwCompressionMethod,
    pub bfw_iq_width: u8,
    pub bundles: Vec<BfwBundle>,
}

impl SectionExtension1 {
    pub fn new(
        bfw_comp_meth: BfwCompressionMethod,
        bfw_iq_width: u8,
        bundles: Vec<BfwBundle>,
    ) -> Self {
        Self {
            bfw_comp_meth,
            bfw_iq_width,
            bundles,
        }
    }

    /// Serializes Section Extension 1 into wire format with 32-bit word alignment padding.
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // Byte 0: bfwCompMeth (upper 4 bits) | bfwIqWidth (lower 4 bits)
        let width_nibble = if self.bfw_iq_width == 16 {
            0
        } else {
            self.bfw_iq_width & 0x0F
        };
        body.push(((self.bfw_comp_meth.to_u8() & 0x0F) << 4) | width_nibble);

        // Append weights per bundle
        for b in &self.bundles {
            if self.bfw_comp_meth == BfwCompressionMethod::BlockFloatingPoint {
                body.push(b.exponent & 0x0F);
            }
            for w in &b.weights {
                match self.bfw_iq_width {
                    16 => {
                        body.extend_from_slice(&w.re.to_be_bytes());
                        body.extend_from_slice(&w.im.to_be_bytes());
                    }
                    8 => {
                        body.push((w.re as i8) as u8);
                        body.push((w.im as i8) as u8);
                    }
                    _ => {
                        // For generic 9..14 bit widths, pack as 16-bit word
                        body.extend_from_slice(&w.re.to_be_bytes());
                        body.extend_from_slice(&w.im.to_be_bytes());
                    }
                }
            }
        }

        // Header: extType (1 byte) | extLen in 32-bit words (2 bytes)
        // Body length + 3 bytes header; pad total to multiple of 4 bytes
        let total_unpadded = 3 + body.len();
        let pad_len = (4 - (total_unpadded % 4)) % 4;
        let total_len = total_unpadded + pad_len;
        let ext_len_words = (total_len / 4) as u16;

        let mut out = Vec::with_capacity(total_len);
        out.push(ORAN_EXT_BEAMFORMING_WEIGHTS);
        out.extend_from_slice(&ext_len_words.to_be_bytes());
        out.extend_from_slice(&body);
        out.resize(total_len, 0); // 32-bit word alignment padding
        out
    }

    /// Parses Section Extension 1 from wire format.
    pub fn parse(data: &[u8], num_antennas: usize) -> Result<Self, OranCPlaneError> {
        if data.len() < 4 {
            return Err(OranCPlaneError::Truncated {
                need: 4,
                got: data.len(),
            });
        }
        let ext_type = data[0];
        if ext_type != ORAN_EXT_BEAMFORMING_WEIGHTS {
            return Err(OranCPlaneError::UnsupportedExtensionType(ext_type));
        }
        let ext_len_words = u16::from_be_bytes([data[1], data[2]]);
        let declared_bytes = (ext_len_words as usize) * 4;
        if data.len() < declared_bytes || declared_bytes < 4 {
            return Err(OranCPlaneError::InvalidExtensionLength {
                declared_words: ext_len_words,
                actual_len: data.len(),
            });
        }

        let comp_byte = data[3];
        let comp_meth = BfwCompressionMethod::from_u8(comp_byte >> 4);
        let raw_width = comp_byte & 0x0F;
        let iq_width = if raw_width == 0 { 16 } else { raw_width };

        let mut offset = 4;
        let mut bundles = Vec::new();

        while offset < declared_bytes {
            let exponent = if comp_meth == BfwCompressionMethod::BlockFloatingPoint {
                if offset >= declared_bytes {
                    break;
                }
                let exp = data[offset] & 0x0F;
                offset += 1;
                exp
            } else {
                0
            };

            let mut weights = Vec::with_capacity(num_antennas);
            let bytes_per_element = if iq_width == 8 { 2 } else { 4 };
            if offset + (num_antennas * bytes_per_element) > declared_bytes {
                let remaining_bytes = declared_bytes.saturating_sub(offset);
                let available_elements = remaining_bytes / bytes_per_element;
                if available_elements > 0 && available_elements < num_antennas {
                    return Err(OranCPlaneError::AntennaCountMismatch {
                        expected: num_antennas,
                        got: available_elements,
                    });
                }
                break; // End of valid bundles or padding reached
            }

            for _ in 0..num_antennas {
                if iq_width == 8 {
                    let re = (data[offset] as i8) as i16;
                    let im = (data[offset + 1] as i8) as i16;
                    offset += 2;
                    weights.push(BfwWeight::new(re, im));
                } else {
                    let re = i16::from_be_bytes([data[offset], data[offset + 1]]);
                    let im = i16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                    offset += 4;
                    weights.push(BfwWeight::new(re, im));
                }
            }

            if weights.len() == num_antennas {
                bundles.push(BfwBundle::new(exponent, weights));
            }
        }

        Ok(SectionExtension1 {
            bfw_comp_meth: comp_meth,
            bfw_iq_width: iq_width,
            bundles,
        })
    }
}

/// Section Extension 2: Beamforming Attributes (O-RAN.WG4.CUS-Plane Section 7.5.3.2).
#[derive(Debug, Clone, PartialEq)]
pub struct SectionExtension2 {
    pub bf_id: u16,
    pub azimuth_deg: f32,
    pub elevation_deg: f32,
}

impl SectionExtension2 {
    pub fn new(bf_id: u16, azimuth_deg: f32, elevation_deg: f32) -> Self {
        Self {
            bf_id,
            azimuth_deg,
            elevation_deg,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.push(ORAN_EXT_BEAM_ATTRIBUTES);
        out.extend_from_slice(&3u16.to_be_bytes()); // 3 * 32-bit words = 12 bytes
        out.push(0); // Alignment padding
        out.extend_from_slice(&self.bf_id.to_be_bytes());
        // Quantize angles: resolution 0.01 deg -> i16
        let az_quant = (self.azimuth_deg * 100.0).round() as i16;
        let el_quant = (self.elevation_deg * 100.0).round() as i16;
        out.extend_from_slice(&az_quant.to_be_bytes());
        out.extend_from_slice(&el_quant.to_be_bytes());
        out.resize(12, 0); // Word alignment
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, OranCPlaneError> {
        if data.len() < 10 {
            return Err(OranCPlaneError::Truncated {
                need: 10,
                got: data.len(),
            });
        }
        if data[0] != ORAN_EXT_BEAM_ATTRIBUTES {
            return Err(OranCPlaneError::UnsupportedExtensionType(data[0]));
        }
        let bf_id = u16::from_be_bytes([data[4], data[5]]);
        let az_quant = i16::from_be_bytes([data[6], data[7]]);
        let el_quant = i16::from_be_bytes([data[8], data[9]]);
        Ok(SectionExtension2 {
            bf_id,
            azimuth_deg: (az_quant as f32) / 100.0,
            elevation_deg: (el_quant as f32) / 100.0,
        })
    }
}

/// Section Extension 4: Modulation Compression Parameters (O-RAN.WG4.CUS-Plane Section 7.5.3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionExtension4 {
    pub csf: bool,
    pub mod_comp_scaler: u16,
}

impl SectionExtension4 {
    pub fn new(csf: bool, mod_comp_scaler: u16) -> Self {
        Self {
            csf,
            mod_comp_scaler,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8);
        out.push(ORAN_EXT_MODULATION_COMPRESSION);
        out.extend_from_slice(&1u16.to_be_bytes()); // 1 word = 4 bytes
        out.push(0); // padding
        let flag = if self.csf { 0x80 } else { 0x00 };
        out.push(flag | ((self.mod_comp_scaler >> 8) as u8 & 0x7F));
        out.push((self.mod_comp_scaler & 0xFF) as u8);
        out.extend_from_slice(&[0, 0]); // 32-bit alignment
        out
    }

    pub fn parse(data: &[u8]) -> Result<Self, OranCPlaneError> {
        if data.len() < 6 {
            return Err(OranCPlaneError::Truncated {
                need: 6,
                got: data.len(),
            });
        }
        if data[0] != ORAN_EXT_MODULATION_COMPRESSION {
            return Err(OranCPlaneError::UnsupportedExtensionType(data[0]));
        }
        let csf = (data[4] & 0x80) != 0;
        let scaler = (((data[4] & 0x7F) as u16) << 8) | (data[5] as u16);
        Ok(SectionExtension4 {
            csf,
            mod_comp_scaler: scaler,
        })
    }
}

/// O-RAN C-Plane Section Type 3: PRACH and Mixed-Numerology Scheduling (Section 7.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CPlaneSectionType3 {
    pub section_id: u16,
    pub rb: bool,
    pub sym_inc: bool,
    pub start_prbc: u16,
    pub num_prbc: u8,
    pub re_mask: u16,
    pub time_offset: u16,
    pub frame_structure: u8,
    pub cp_length: u16,
    pub frequency_offset: i32, // 24-bit signed subcarrier shift
}

impl CPlaneSectionType3 {
    pub fn new(
        section_id: u16,
        start_prbc: u16,
        num_prbc: u8,
        time_offset: u16,
        frame_structure: u8,
        cp_length: u16,
        frequency_offset: i32,
    ) -> Self {
        Self {
            section_id,
            rb: true,
            sym_inc: false,
            start_prbc,
            num_prbc,
            re_mask: 0x0FFF, // Default: all 12 REs in PRB active
            time_offset,
            frame_structure,
            cp_length,
            frequency_offset,
        }
    }

    /// Serializes Section Type 3 section body (14 bytes).
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14);

        // Bytes 0-1: sectionId (12 bits) | rb (1 bit) | symInc (1 bit) | startPrbc high 2 bits
        let b0 = ((self.section_id >> 4) & 0xFF) as u8;
        let b1 = (((self.section_id & 0x0F) as u8) << 4)
            | (if self.rb { 0x08 } else { 0x00 })
            | (if self.sym_inc { 0x04 } else { 0x00 })
            | (((self.start_prbc >> 8) & 0x03) as u8);
        out.push(b0);
        out.push(b1);

        // Byte 2: startPrbc low 8 bits
        out.push((self.start_prbc & 0xFF) as u8);
        // Byte 3: numPrbc
        out.push(self.num_prbc);

        // Bytes 4-5: reMask (12 bits) | reserved (4 bits)
        out.push(((self.re_mask >> 4) & 0xFF) as u8);
        out.push(((self.re_mask & 0x0F) as u8) << 4);

        // Bytes 6-7: timeOffset (14 bits) | reserved (2 bits)
        out.push(((self.time_offset >> 6) & 0xFF) as u8);
        out.push(((self.time_offset & 0x3F) as u8) << 2);

        // Byte 8: frameStructure (FFT size upper 4 bits, SCS lower 4 bits)
        out.push(self.frame_structure);

        // Bytes 9-10: cpLength (16 bits)
        out.extend_from_slice(&self.cp_length.to_be_bytes());

        // Bytes 11-13: frequencyOffset (24 bits signed 2's complement)
        let fo_unsigned = (self.frequency_offset as u32) & 0x00FF_FFFF;
        out.push(((fo_unsigned >> 16) & 0xFF) as u8);
        out.push(((fo_unsigned >> 8) & 0xFF) as u8);
        out.push((fo_unsigned & 0xFF) as u8);

        out
    }

    /// Parses Section Type 3 section body from wire format.
    pub fn parse(data: &[u8]) -> Result<Self, OranCPlaneError> {
        if data.len() < 14 {
            return Err(OranCPlaneError::Truncated {
                need: 14,
                got: data.len(),
            });
        }

        let section_id = (((data[0] as u16) << 4) | (((data[1] >> 4) & 0x0F) as u16)) & 0x0FFF;
        let rb = (data[1] & 0x08) != 0;
        let sym_inc = (data[1] & 0x04) != 0;
        let start_prbc = (((data[1] & 0x03) as u16) << 8) | (data[2] as u16);
        let num_prbc = data[3];
        let re_mask = (((data[4] as u16) << 4) | (((data[5] >> 4) & 0x0F) as u16)) & 0x0FFF;
        let time_offset = (((data[6] as u16) << 6) | (((data[7] >> 2) & 0x3F) as u16)) & 0x3FFF;
        let frame_structure = data[8];
        let cp_length = u16::from_be_bytes([data[9], data[10]]);

        // 24-bit signed two's complement frequency offset
        let raw_fo = ((data[11] as u32) << 16) | ((data[12] as u32) << 8) | (data[13] as u32);
        let frequency_offset = if (raw_fo & 0x0080_0000) != 0 {
            (raw_fo | 0xFF00_0000) as i32
        } else {
            raw_fo as i32
        };

        Ok(Self {
            section_id,
            rb,
            sym_inc,
            start_prbc,
            num_prbc,
            re_mask,
            time_offset,
            frame_structure,
            cp_length,
            frequency_offset,
        })
    }
}

/// Dispatcher and Engine for O-RAN WG4 C-Plane Extensions.
pub struct OranCPlaneExtEngine;

impl OranCPlaneExtEngine {
    /// Validates and parses digital beamforming weights against target antenna array dimensions.
    pub fn validate_and_parse_bfw(
        data: &[u8],
        expected_antennas: usize,
    ) -> Result<SectionExtension1, OranCPlaneError> {
        let ext = SectionExtension1::parse(data, expected_antennas)?;
        for bundle in &ext.bundles {
            if bundle.weights.len() != expected_antennas {
                return Err(OranCPlaneError::AntennaCountMismatch {
                    expected: expected_antennas,
                    got: bundle.weights.len(),
                });
            }
        }
        Ok(ext)
    }

    /// Helper that calculates frequency offset in Hz from Section Type 3 frequencyOffset field.
    pub fn calculate_frequency_shift_hz(fo_subcarriers: i32, scs_khz: f64) -> f64 {
        (fo_subcarriers as f64) * (scs_khz * 1000.0)
    }
}
