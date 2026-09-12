//! 3GPP Release 18/19 5G-Advanced Polar Coding & CRC-Aided List (CA-SCL) Decoding Engine.
//!
//! Standards Reference:
//! - 3GPP TS 38.212 Rel-18 §5.1: 24-bit CRC24C calculation and RNTI scrambling for control channels.
//! - 3GPP TS 38.212 Rel-18 §5.3.1: Polar coding, mother code sizing ($N = 2^n \in [32, 1024]$),
//!   and 1024-element standardized channel reliability sequence (Table 5.3.1.2-1).
//! - 3GPP TS 38.212 Rel-18 §5.4.1: Polar rate matching: Sub-block interleaving, Puncturing,
//!   Shortening, and Repetition.
//! - 3GPP TS 38.212 Rel-18 §7.3.2: DCI payload processing on PDCCH.
//!
//! Features:
//! 1. Complete 1024-element 3GPP TS 38.212 Table 5.3.1.2-1 channel reliability sequence.
//! 2. CRC24C generator with RNTI scrambling mask on the last 16 parity bits.
//! 3. Mother code length determination ($N \in [32, 1024]$) and sub-channel frozen/info bit allocation.
//! 4. Fast $O(N \log N)$ recursive Kronecker polar encoder kernel.
//! 5. Rate matching engine: 32-element sub-block interleaver with Repetition, Puncturing, and Shortening.
//! 6. CRC-Aided Successive Cancellation List (CA-SCL) decoder with Min-Sum LLR recursion,
//!    path metric tracking, list pruning ($L \in [1, 8]$), and CRC candidate validation.
//! 7. Binary wire framing (`PolarFramePdu`) with magic `0x504F4C52` ("POLR") and CRC-16 CCITT.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants & Error Definitions
// ---------------------------------------------------------------------------

/// Magic bytes for Polar PDU: "POLR" (0x504F4C52).
pub const POLAR_WIRE_MAGIC: u32 = 0x504F4C52;

/// Standard CRC-16 CCITT polynomial.
pub const CRC16_CCITT_POLY: u16 = 0x1021;

/// CRC24C generator polynomial: D^24 + D^23 + D^21 + D^20 + D^17 + D^15 + D^13 + D^12 + D^8 + D^4 + D^2 + D + 1
pub const CRC24C_POLY: u32 = 0xB2B117;

/// Minimum mother code length for 5G NR Polar Codes ($2^5 = 32$).
pub const MIN_POLAR_N: usize = 32;

/// Maximum mother code length for 5G NR Polar Codes ($2^{10} = 1024$).
pub const MAX_POLAR_N: usize = 1024;

/// Sub-block interleaver pattern $P$ of length 32 (TS 38.212 Table 5.4.1.1-1).
pub const POLAR_INTERLEAVER_PATTERN: [usize; 32] = [
    0, 1, 2, 4, 3, 5, 6, 7, 8, 16, 9, 17, 10, 18, 11, 19, 12, 20, 13, 21, 14, 22, 15, 23, 24, 25,
    26, 28, 27, 29, 30, 31,
];

/// Standard 3GPP channel reliability sequence $\mathbf{Q}_{0}^{1023}$ (TS 38.212 Table 5.3.1.2-1).
/// Ranked in ascending order from least reliable to most reliable.
#[rustfmt::skip]
pub const POLAR_RELIABILITY_SEQUENCE_1024: [u16; 1024] = [
0, 1, 2, 4, 8, 16, 32, 3, 5, 64, 9, 6, 17, 10, 18, 128, 12, 33, 65, 20,
    256, 34, 24, 36, 7, 129, 66, 512, 11, 40, 68, 130, 19, 13, 48, 14, 72, 257, 21, 132,
    35, 258, 26, 513, 80, 37, 25, 22, 136, 260, 264, 38, 514, 96, 67, 41, 144, 28, 69, 42,
    516, 49, 74, 272, 160, 520, 288, 528, 192, 544, 70, 44, 131, 81, 50, 73, 15, 320, 133, 52,
    23, 134, 384, 76, 137, 82, 56, 27, 97, 39, 259, 84, 138, 145, 261, 29, 43, 98, 515, 88,
    140, 30, 146, 71, 262, 265, 161, 576, 45, 100, 640, 51, 148, 46, 75, 266, 273, 517, 104, 162,
    53, 193, 152, 77, 164, 768, 268, 274, 518, 54, 83, 57, 521, 112, 135, 78, 289, 194, 85, 276,
    522, 58, 168, 139, 99, 86, 60, 280, 89, 290, 529, 524, 196, 141, 101, 147, 176, 142, 530, 321,
    31, 200, 90, 545, 292, 322, 532, 263, 149, 102, 105, 304, 296, 163, 92, 47, 267, 385, 546, 324,
    208, 386, 150, 153, 165, 106, 55, 328, 536, 577, 548, 113, 154, 79, 269, 108, 578, 224, 166, 519,
    552, 195, 270, 641, 523, 275, 580, 291, 59, 169, 560, 114, 277, 156, 87, 197, 116, 170, 61, 531,
    525, 642, 281, 278, 526, 177, 293, 388, 91, 584, 769, 198, 172, 120, 201, 336, 62, 282, 143, 103,
    178, 294, 93, 644, 202, 592, 323, 392, 297, 770, 107, 180, 151, 209, 284, 648, 94, 204, 298, 400,
    608, 352, 325, 533, 155, 210, 305, 547, 300, 109, 184, 534, 537, 115, 167, 225, 326, 306, 772, 157,
    656, 329, 110, 117, 212, 171, 776, 330, 226, 549, 538, 387, 308, 216, 416, 271, 279, 158, 337, 550,
    672, 118, 332, 579, 540, 389, 173, 121, 553, 199, 784, 179, 228, 338, 312, 704, 390, 174, 554, 581,
    393, 283, 122, 448, 353, 561, 203, 63, 340, 394, 527, 582, 556, 181, 295, 285, 232, 124, 205, 182,
    643, 562, 286, 585, 299, 354, 211, 401, 185, 396, 344, 586, 645, 593, 535, 240, 206, 95, 327, 564,
    800, 402, 356, 307, 301, 417, 213, 568, 832, 588, 186, 646, 404, 227, 896, 594, 418, 302, 649, 771,
    360, 539, 111, 331, 214, 309, 188, 449, 217, 408, 609, 596, 551, 650, 229, 159, 420, 310, 541, 773,
    610, 657, 333, 119, 600, 339, 218, 368, 652, 230, 391, 313, 450, 542, 334, 233, 555, 774, 175, 123,
    658, 612, 341, 777, 220, 314, 424, 395, 673, 583, 355, 287, 183, 234, 125, 557, 660, 616, 342, 316,
    241, 778, 563, 345, 452, 397, 403, 207, 674, 558, 785, 432, 357, 187, 236, 664, 624, 587, 780, 705,
    126, 242, 565, 398, 346, 456, 358, 405, 303, 569, 244, 595, 189, 566, 676, 361, 706, 589, 215, 786,
    647, 348, 419, 406, 464, 680, 801, 362, 590, 409, 570, 788, 597, 572, 219, 311, 708, 598, 601, 651,
    421, 792, 802, 611, 602, 410, 231, 688, 653, 248, 369, 190, 364, 654, 659, 335, 480, 315, 221, 370,
    613, 422, 425, 451, 614, 543, 235, 412, 343, 372, 775, 317, 222, 426, 453, 237, 559, 833, 804, 712,
    834, 661, 808, 779, 617, 604, 433, 720, 816, 836, 347, 897, 243, 662, 454, 318, 675, 618, 898, 781,
    376, 428, 665, 736, 567, 840, 625, 238, 359, 457, 399, 787, 591, 678, 434, 677, 349, 245, 458, 666,
    620, 363, 127, 191, 782, 407, 436, 626, 571, 465, 681, 246, 707, 350, 599, 668, 790, 460, 249, 682,
    573, 411, 803, 789, 709, 365, 440, 628, 689, 374, 423, 466, 793, 250, 371, 481, 574, 413, 603, 366,
    468, 655, 900, 805, 615, 684, 710, 429, 794, 252, 373, 605, 848, 690, 713, 632, 482, 806, 427, 904,
    414, 223, 663, 692, 835, 619, 472, 455, 796, 809, 714, 721, 837, 716, 864, 810, 606, 912, 722, 696,
    377, 435, 817, 319, 621, 812, 484, 430, 838, 667, 488, 239, 378, 459, 622, 627, 437, 380, 818, 461,
    496, 669, 679, 724, 841, 629, 351, 467, 438, 737, 251, 462, 442, 441, 469, 247, 683, 842, 738, 899,
    670, 783, 849, 820, 728, 928, 791, 367, 901, 630, 685, 844, 633, 711, 253, 691, 824, 902, 686, 740,
    850, 375, 444, 470, 483, 415, 485, 905, 795, 473, 634, 744, 852, 960, 865, 693, 797, 906, 715, 807,
    474, 636, 694, 254, 717, 575, 913, 798, 811, 379, 697, 431, 607, 489, 866, 723, 486, 908, 718, 813,
    476, 856, 839, 725, 698, 914, 752, 868, 819, 814, 439, 929, 490, 623, 671, 739, 916, 463, 843, 381,
    497, 930, 821, 726, 961, 872, 492, 631, 729, 700, 443, 741, 845, 920, 382, 822, 851, 730, 498, 880,
    742, 445, 471, 635, 932, 687, 903, 825, 500, 846, 745, 826, 732, 446, 962, 936, 475, 853, 867, 637,
    907, 487, 695, 746, 828, 753, 854, 857, 504, 799, 255, 964, 909, 719, 477, 915, 638, 748, 944, 869,
    491, 699, 754, 858, 478, 968, 383, 910, 815, 976, 870, 917, 727, 493, 873, 701, 931, 756, 860, 499,
    731, 823, 922, 874, 918, 502, 933, 743, 760, 881, 494, 702, 921, 501, 876, 847, 992, 447, 733, 827,
    934, 882, 937, 963, 747, 505, 855, 924, 734, 829, 965, 938, 884, 506, 749, 945, 966, 755, 859, 940,
    830, 911, 871, 639, 888, 479, 946, 750, 969, 508, 861, 757, 970, 919, 875, 862, 758, 948, 977, 923,
    972, 761, 877, 952, 495, 703, 935, 978, 883, 762, 503, 925, 878, 735, 993, 885, 939, 994, 980, 926,
    764, 941, 967, 886, 831, 947, 507, 889, 984, 751, 942, 996, 971, 890, 509, 949, 973, 1000, 892, 950,
    863, 759, 1008, 510, 979, 953, 763, 974, 954, 879, 981, 982, 927, 995, 765, 956, 887, 985, 997, 986,
    943, 891, 998, 766, 511, 988, 1001, 951, 1002, 893, 975, 894, 1009, 955, 1004, 1010, 957, 983, 958, 987,
    1012, 999, 1016, 767, 989, 1003, 990, 1005, 959, 1011, 1013, 895, 1006, 1014, 1017, 1018, 991, 1020, 1007, 1015,
    1019, 1021, 1022, 1023,
];

/// Errors encountered in Polar coding operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolarError {
    EmptyPayload,
    PayloadTooLarge { k: usize, max_k: usize },
    InvalidRateMatchedLength(usize),
    InvalidMotherCodeSize(usize),
    CrcCheckFailed,
    DecodingError(String),
    SerializationError(String),
    DeserializationError(String),
    CrcMismatch { expected: u16, actual: u16 },
    InvalidMagic(u32),
}

impl fmt::Display for PolarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => write!(f, "Payload cannot be empty"),
            Self::PayloadTooLarge { k, max_k } => {
                write!(f, "Payload {} bits exceeds maximum capacity {}", k, max_k)
            }
            Self::InvalidRateMatchedLength(e) => write!(f, "Invalid rate-matched length: {}", e),
            Self::InvalidMotherCodeSize(n) => write!(f, "Invalid mother code size: {}", n),
            Self::CrcCheckFailed => write!(f, "CRC verification failed for all candidate paths"),
            Self::DecodingError(msg) => write!(f, "Decoding error: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
            Self::CrcMismatch { expected, actual } => {
                write!(
                    f,
                    "CRC mismatch: expected 0x{:04X}, computed 0x{:04X}",
                    expected, actual
                )
            }
            Self::InvalidMagic(m) => write!(f, "Invalid magic: 0x{:08X}", m),
        }
    }
}

// ---------------------------------------------------------------------------
// CRC24C & RNTI Scrambling (TS 38.212 §5.1 / §7.3.2)
// ---------------------------------------------------------------------------

/// Computes 24-bit CRC24C over bit slice (0 and 1 values).
pub fn compute_crc24c(bits: &[u8]) -> u32 {
    let mut crc: u32 = 0;
    for &b in bits {
        let bit = (b & 1) as u32;
        let msb = (crc >> 23) & 1;
        crc = ((crc << 1) | bit) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24C_POLY;
        }
    }
    for _ in 0..24 {
        let msb = (crc >> 23) & 1;
        crc = (crc << 1) & 0x00FF_FFFF;
        if msb == 1 {
            crc ^= CRC24C_POLY;
        }
    }
    crc
}

/// Attaches 24-bit CRC24C with optional RNTI scrambling on the last 16 parity bits (TS 38.212 §7.3.2).
pub fn attach_crc24c_with_rnti(payload: &[u8], rnti: u16) -> Vec<u8> {
    let crc = compute_crc24c(payload);
    let mut output = Vec::with_capacity(payload.len() + 24);
    output.extend_from_slice(payload);

    for i in 0..24 {
        let bit_pos = 23 - i;
        let mut bit = ((crc >> bit_pos) & 1) as u8;
        // Scramble last 16 bits with RNTI
        if i >= 8 {
            let rnti_bit_pos = 15 - (i - 8);
            let rnti_bit = ((rnti >> rnti_bit_pos) & 1) as u8;
            bit ^= rnti_bit;
        }
        output.push(bit);
    }

    output
}

// ---------------------------------------------------------------------------
// Mother Code Sizing & Sub-Channel Allocation (TS 38.212 §5.3.1)
// ---------------------------------------------------------------------------

/// Determines the Polar mother code size $N = 2^n \in [32, 1024]$ from payload $K$ and rate-matched length $E$.
pub fn determine_mother_code_size(k_bits: usize, e_bits: usize) -> Result<usize, PolarError> {
    if k_bits == 0 || k_bits > 1024 {
        return Err(PolarError::PayloadTooLarge {
            k: k_bits,
            max_k: 1024,
        });
    }
    if e_bits == 0 {
        return Err(PolarError::InvalidRateMatchedLength(e_bits));
    }

    // TS 38.212 Section 5.3.1 rules:
    let n1 = (e_bits as f64).log2().ceil() as u32;
    let n_tentative = if e_bits <= ((9 * (1 << (n1 - 1))) / 8)
        && (k_bits as f64) / (e_bits as f64) <= 9.0 / 16.0
    {
        n1.saturating_sub(1)
    } else {
        n1
    };

    let mut n = n_tentative.clamp(5, 10);
    while (1 << n) < k_bits && n < 10 {
        n += 1;
    }

    Ok(1 << n)
}

/// Identifies the $K$ most reliable sub-channel indices for mother size $N$.
pub fn get_information_subchannel_set(n_mother: usize, k_bits: usize) -> Vec<usize> {
    let filtered_indices: Vec<usize> = POLAR_RELIABILITY_SEQUENCE_1024
        .iter()
        .filter_map(|&ch| {
            let ch_idx = ch as usize;
            if ch_idx < n_mother {
                Some(ch_idx)
            } else {
                None
            }
        })
        .collect();

    let total = filtered_indices.len();
    if k_bits >= total {
        return filtered_indices;
    }

    // The last K elements have the highest reliability
    filtered_indices[total - k_bits..].to_vec()
}

// ---------------------------------------------------------------------------
// Polar Encoding (TS 38.212 §5.3.1)
// ---------------------------------------------------------------------------

/// Performs Polar encoding of $K$ information/CRC bits into $N$ mother coded bits.
pub fn polar_encode(info_bits: &[u8], n_mother: usize) -> Result<Vec<u8>, PolarError> {
    let k = info_bits.len();
    if k == 0 || k > n_mother {
        return Err(PolarError::PayloadTooLarge { k, max_k: n_mother });
    }
    if !n_mother.is_power_of_two() || n_mother < MIN_POLAR_N || n_mother > MAX_POLAR_N {
        return Err(PolarError::InvalidMotherCodeSize(n_mother));
    }

    // 1. Sub-channel allocation
    let info_set = get_information_subchannel_set(n_mother, k);
    let mut u = vec![0u8; n_mother];
    for (&ch_idx, &bit) in info_set.iter().zip(info_bits.iter()) {
        u[ch_idx] = bit & 1;
    }

    // 2. Recursive Fast Walsh-Hadamard / Kronecker transformation: d = u * G_N
    let mut d = u;
    let mut step = 1;
    while step < n_mother {
        for i in (0..n_mother).step_by(step * 2) {
            for j in 0..step {
                d[i + j] ^= d[i + j + step];
            }
        }
        step *= 2;
    }

    Ok(d)
}

// ---------------------------------------------------------------------------
// Rate Matching (TS 38.212 §5.4.1)
// ---------------------------------------------------------------------------

/// Performs rate matching on $N$ Polar coded bits to produce $E$ output bits.
pub fn polar_rate_match(
    coded_bits: &[u8],
    e_bits: usize,
    k_bits: usize,
) -> Result<Vec<u8>, PolarError> {
    let n = coded_bits.len();
    if n == 0 || !n.is_power_of_two() {
        return Err(PolarError::InvalidMotherCodeSize(n));
    }
    if e_bits == 0 {
        return Err(PolarError::InvalidRateMatchedLength(e_bits));
    }

    // 1. Sub-block interleaving using 32 sub-blocks
    let subblock_size = n / 32;
    let mut interleaved = vec![0u8; n];
    for (out_sb, &in_sb) in POLAR_INTERLEAVER_PATTERN.iter().enumerate() {
        let in_start = in_sb * subblock_size;
        let out_start = out_sb * subblock_size;
        interleaved[out_start..out_start + subblock_size]
            .copy_from_slice(&coded_bits[in_start..in_start + subblock_size]);
    }

    // 2. Bit selection (Repetition, Puncturing, or Shortening)
    let mut output = Vec::with_capacity(e_bits);
    if e_bits >= n {
        // Repetition: cyclic extraction
        for i in 0..e_bits {
            output.push(interleaved[i % n]);
        }
    } else {
        // TS 38.212 Section 5.4.1.3:
        // If K / E <= 7/16: Puncturing (extract last E bits)
        // Else: Shortening (extract first E bits)
        if (k_bits as f64) / (e_bits as f64) <= 7.0 / 16.0 {
            // Puncturing: take interleaved[N - E .. N]
            output.extend_from_slice(&interleaved[n - e_bits..]);
        } else {
            // Shortening: take interleaved[0 .. E]
            output.extend_from_slice(&interleaved[..e_bits]);
        }
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// CRC-Aided Successive Cancellation List (CA-SCL) Decoder
// ---------------------------------------------------------------------------

/// Candidate path in CA-SCL decoding.
#[derive(Debug, Clone)]
struct SclPath {
    decisions: Vec<u8>,
    path_metric: f64,
}

/// Recursive Min-Sum check-node LLR update: $f(a, b) = \text{sign}(a)\text{sign}(b)\min(|a|, |b|)$.
#[inline]
fn f_min_sum(a: f64, b: f64) -> f64 {
    let sign = if (a >= 0.0) == (b >= 0.0) { 1.0 } else { -1.0 };
    sign * a.abs().min(b.abs())
}

/// Bit-node LLR update given hard partial decision $u \in \{0, 1\}$: $g(a, b, u) = b + (1 - 2u) a$.
#[inline]
fn g_update(a: f64, b: f64, u: u8) -> f64 {
    if u == 0 { b + a } else { b - a }
}

/// Decodes received channel log-likelihood ratios (LLRs) using CRC-Aided SCL decoding.
pub fn ca_scl_decode(
    llr: &[f64],
    k_info_with_crc: usize,
    list_size: usize,
    rnti: u16,
) -> Result<Vec<u8>, PolarError> {
    let n = llr.len();
    if !n.is_power_of_two() || n < MIN_POLAR_N || n > MAX_POLAR_N {
        return Err(PolarError::InvalidMotherCodeSize(n));
    }
    if k_info_with_crc == 0 || k_info_with_crc > n {
        return Err(PolarError::PayloadTooLarge {
            k: k_info_with_crc,
            max_k: n,
        });
    }

    let info_set = get_information_subchannel_set(n, k_info_with_crc);
    let mut is_info = vec![false; n];
    for &idx in &info_set {
        is_info[idx] = true;
    }

    let list_cap = list_size.clamp(1, 8);
    let mut paths = vec![SclPath {
        decisions: Vec::with_capacity(n),
        path_metric: 0.0,
    }];

    for i in 0..n {
        let mut new_paths = Vec::new();

        for path in &paths {
            let estimated_llr = get_bit_llr(llr, &path.decisions, i);

            if !is_info[i] {
                // Frozen bit: decision strictly forced to 0
                let penalty = if estimated_llr < 0.0 {
                    -estimated_llr
                } else {
                    0.0
                };
                let mut p = path.clone();
                p.decisions.push(0);
                p.path_metric += penalty;
                new_paths.push(p);
            } else {
                // Information bit: fork path into both 0 and 1
                let penalty0 = if estimated_llr < 0.0 {
                    -estimated_llr
                } else {
                    0.0
                };
                let penalty1 = if estimated_llr > 0.0 {
                    estimated_llr
                } else {
                    0.0
                };

                let mut p0 = path.clone();
                p0.decisions.push(0);
                p0.path_metric += penalty0;
                new_paths.push(p0);

                let mut p1 = path.clone();
                p1.decisions.push(1);
                p1.path_metric += penalty1;
                new_paths.push(p1);
            }
        }

        // Sort by path metric ascending (lower metric = more likely)
        new_paths.sort_by(|a, b| {
            a.path_metric
                .partial_cmp(&b.path_metric)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        new_paths.truncate(list_cap);
        paths = new_paths;
    }

    // Validate CRC on surviving paths
    for path in &paths {
        let mut extracted_info = Vec::with_capacity(k_info_with_crc);
        for &idx in &info_set {
            extracted_info.push(path.decisions[idx]);
        }

        if extracted_info.len() >= 24 {
            let payload_len = extracted_info.len() - 24;
            let payload = &extracted_info[..payload_len];
            let rx_crc_bits = &extracted_info[payload_len..];

            // Compute expected CRC with RNTI descrambling
            let calc_crc = compute_crc24c(payload);
            let mut crc_match = true;

            for i in 0..24 {
                let bit_pos = 23 - i;
                let mut exp_bit = ((calc_crc >> bit_pos) & 1) as u8;
                if i >= 8 {
                    let rnti_bit_pos = 15 - (i - 8);
                    let rnti_bit = ((rnti >> rnti_bit_pos) & 1) as u8;
                    exp_bit ^= rnti_bit;
                }
                if rx_crc_bits[i] != exp_bit {
                    crc_match = false;
                    break;
                }
            }

            if crc_match {
                return Ok(payload.to_vec());
            }
        }
    }

    // If k_info_with_crc < 24, return best path's decisions
    if k_info_with_crc < 24 {
        if let Some(best) = paths.first() {
            let mut extracted = Vec::with_capacity(k_info_with_crc);
            for &idx in &info_set {
                extracted.push(best.decisions[idx]);
            }
            return Ok(extracted);
        }
    }

    Err(PolarError::CrcCheckFailed)
}

/// Helper: Fast Kronecker polar encoding of sub-vector decisions.
fn polar_transform_internal(u: &[u8]) -> Vec<u8> {
    let n = u.len();
    if n <= 1 {
        return u.to_vec();
    }
    let half = n / 2;
    let d_a = polar_transform_internal(&u[..half]);
    let d_b = polar_transform_internal(&u[half..]);
    let mut d = vec![0u8; n];
    for j in 0..half {
        d[j] = d_a[j] ^ d_b[j];
        d[j + half] = d_b[j];
    }
    d
}

/// Recursive LLR calculation for bit $i$ given path decisions so far.
fn get_bit_llr(llrs: &[f64], decisions: &[u8], i: usize) -> f64 {
    let n = llrs.len();
    if n == 1 {
        return llrs[0];
    }
    let half = n / 2;
    if i < half {
        let mut left_llrs = Vec::with_capacity(half);
        for j in 0..half {
            left_llrs.push(f_min_sum(llrs[j], llrs[j + half]));
        }
        get_bit_llr(&left_llrs, &decisions[..i], i)
    } else {
        let d_a = polar_transform_internal(&decisions[..half]);
        let mut right_llrs = Vec::with_capacity(half);
        for j in 0..half {
            right_llrs.push(g_update(llrs[j], llrs[j + half], d_a[j]));
        }
        get_bit_llr(&right_llrs, &decisions[half..], i - half)
    }
}

// ---------------------------------------------------------------------------
// Binary Wire Framing & CRC-16
// ---------------------------------------------------------------------------

/// Computes CRC-16 CCITT over binary slice.
pub fn compute_crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ CRC16_CCITT_POLY;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Binary wire framing carrying Polar coding configuration and verification telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolarFramePdu {
    pub version: u8,
    pub k_info_bits: u16,
    pub n_mother_bits: u16,
    pub e_rate_matched_bits: u16,
    pub rnti: u16,
    pub list_size: u8,
    pub payload_bytes: Vec<u8>,
}

impl PolarFramePdu {
    pub const HEADER_SIZE: usize = 4 + 1 + 2 + 2 + 2 + 2 + 1 + 2; // 16 bytes

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::HEADER_SIZE + self.payload_bytes.len() + 2);
        buf.extend_from_slice(&POLAR_WIRE_MAGIC.to_be_bytes());
        buf.push(self.version);
        buf.extend_from_slice(&self.k_info_bits.to_be_bytes());
        buf.extend_from_slice(&self.n_mother_bits.to_be_bytes());
        buf.extend_from_slice(&self.e_rate_matched_bits.to_be_bytes());
        buf.extend_from_slice(&self.rnti.to_be_bytes());
        buf.push(self.list_size);
        buf.extend_from_slice(&(self.payload_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.payload_bytes);

        let crc = compute_crc16(&buf);
        buf.extend_from_slice(&crc.to_be_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PolarError> {
        if bytes.len() < Self::HEADER_SIZE + 2 {
            return Err(PolarError::DeserializationError(format!(
                "Buffer length {} is less than minimum {}",
                bytes.len(),
                Self::HEADER_SIZE + 2
            )));
        }

        let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != POLAR_WIRE_MAGIC {
            return Err(PolarError::InvalidMagic(magic));
        }

        let payload_len = u16::from_be_bytes([bytes[14], bytes[15]]) as usize;
        let expected_total_len = Self::HEADER_SIZE + payload_len + 2;
        if bytes.len() < expected_total_len {
            return Err(PolarError::DeserializationError(format!(
                "Total buffer length {} is less than expected {}",
                bytes.len(),
                expected_total_len
            )));
        }

        let checksum_boundary = Self::HEADER_SIZE + payload_len;
        let expected_crc = compute_crc16(&bytes[..checksum_boundary]);
        let actual_crc =
            u16::from_be_bytes([bytes[checksum_boundary], bytes[checksum_boundary + 1]]);
        if expected_crc != actual_crc {
            return Err(PolarError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let version = bytes[4];
        let k_info_bits = u16::from_be_bytes([bytes[5], bytes[6]]);
        let n_mother_bits = u16::from_be_bytes([bytes[7], bytes[8]]);
        let e_rate_matched_bits = u16::from_be_bytes([bytes[9], bytes[10]]);
        let rnti = u16::from_be_bytes([bytes[11], bytes[12]]);
        let list_size = bytes[13];
        let payload_bytes = bytes[Self::HEADER_SIZE..checksum_boundary].to_vec();

        Ok(Self {
            version,
            k_info_bits,
            n_mother_bits,
            e_rate_matched_bits,
            rnti,
            list_size,
            payload_bytes,
        })
    }
}
