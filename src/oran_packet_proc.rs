//! O-RAN WG4 Open Fronthaul CUS-Plane Packet Processor & eCPRI Multiplexer Engine.
//!
//! Unifies eCPRI message concatenation, eAxC routing, 3GPP slot/symbol timing validation,
//! U-Plane Block Floating Point (BFP) IQ decompression, C-Plane Massive MIMO beamforming
//! weights extraction, Section Type 3 PRACH scheduling, and IEEE 802.1CM QoS traffic classification.

use std::collections::HashMap;

use crate::ecpri::{
    ECPRI_COMMON_HEADER_LEN, ECPRI_CONCATENATION_ALIGNMENT, ECPRI_ETHERTYPE, ECPRI_MSG_IQ_DATA,
    ECPRI_MSG_RT_CONTROL, EcpriCommonHeader,
};
use crate::oran_cplane_ext::{
    CPlaneSectionType3, ORAN_EXT_BEAM_ATTRIBUTES, ORAN_EXT_BEAMFORMING_WEIGHTS,
    ORAN_SECTION_TYPE_3, OranCPlaneExtEngine, SectionExtension1, SectionExtension2,
};
use crate::oran_fh_cus::{EaxcIdFormat, OranRadioHeader};
use crate::oran_fh_delay_mgmt::{
    FronthaulWindowKind, OranDelayManager, OruReceptionWindow, WindowVerdict,
};
use crate::oran_iq_compression::{BfpCodec, IqSample};
use crate::tsn_8021cm_fronthaul::{Ieee8021CmEngine, Ieee8021CmProfile};

/// Configuration for an Antenna-Carrier (eAxC) stream.
#[derive(Debug, Clone)]
pub struct OranStreamConfig {
    pub eaxc_id: u16,
    pub format: EaxcIdFormat,
    pub num_antennas: usize,
    pub reception_window: OruReceptionWindow,
}

impl OranStreamConfig {
    pub fn new(
        eaxc_id: u16,
        format: EaxcIdFormat,
        num_antennas: usize,
        t2a_min_ns: i64,
        t2a_max_ns: i64,
    ) -> Result<Self, crate::oran_fh_delay_mgmt::DelayMgmtError> {
        let window =
            OruReceptionWindow::new(FronthaulWindowKind::UPlaneDownlink, t2a_min_ns, t2a_max_ns)?;
        Ok(Self {
            eaxc_id,
            format,
            num_antennas,
            reception_window: window,
        })
    }
}

/// Statistics collected per eAxC stream.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OranStreamStats {
    pub total_uplane_packets: u64,
    pub on_time_uplane_packets: u64,
    pub early_dropped_packets: u64,
    pub late_dropped_packets: u64,
    pub total_cplane_packets: u64,
    pub total_decompressed_samples: u64,
    pub last_beam_id: Option<u16>,
    pub last_bfw_weights_count: Option<usize>,
}

/// High-level events emitted during ingress demultiplexing.
#[derive(Debug, Clone, PartialEq)]
pub enum OranDemuxEvent {
    UPlaneReceived {
        eaxc_id: u16,
        frame_id: u8,
        subframe_id: u8,
        slot_id: u8,
        symbol_id: u8,
        prb_count: u8,
        samples_count: usize,
        verdict: WindowVerdict,
    },
    CPlaneSection1Received {
        eaxc_id: u16,
        section_id: u16,
        start_prbc: u16,
        num_prbc: u8,
        beam_id: Option<u16>,
        bfw_antennas: Option<usize>,
    },
    CPlaneSection3Received {
        eaxc_id: u16,
        section_id: u16,
        time_offset: u16,
        frame_structure: u8,
        frequency_offset_hz: f64,
    },
    PacketDropped {
        reason: &'static str,
    },
}

/// O-RAN WG4 Open Fronthaul Packet Stream Processor.
pub struct OranFronthaulProcessor {
    pub stream_configs: HashMap<u16, OranStreamConfig>,
    pub delay_managers: HashMap<u16, OranDelayManager>,
    pub stats: HashMap<u16, OranStreamStats>,
    pub tsn_engine: Ieee8021CmEngine,
}

impl OranFronthaulProcessor {
    pub fn new(profile: Ieee8021CmProfile) -> Self {
        Self {
            stream_configs: HashMap::new(),
            delay_managers: HashMap::new(),
            stats: HashMap::new(),
            tsn_engine: Ieee8021CmEngine::new(profile),
        }
    }

    /// Registers a new eAxC antenna-carrier stream and initializes delay management.
    pub fn register_stream(&mut self, config: OranStreamConfig) {
        let eaxc_id = config.eaxc_id;
        let dm = OranDelayManager::new(config.reception_window.clone());
        self.delay_managers.insert(eaxc_id, dm);
        self.stream_configs.insert(eaxc_id, config);
        self.stats.insert(eaxc_id, OranStreamStats::default());
    }

    /// Processes an incoming raw Ethernet or UDP packet containing concatenated eCPRI messages.
    pub fn process_ingress_packet(
        &mut self,
        packet: &[u8],
        arrival_time_ns: i64,
    ) -> Vec<OranDemuxEvent> {
        let mut events = Vec::new();
        if packet.is_empty() {
            return events;
        }

        // Check if raw Ethernet frame with eCPRI EtherType (0xAEFE)
        let mut offset = 0;
        if packet.len() >= 14 {
            let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
            if ethertype == ECPRI_ETHERTYPE {
                offset = 14;
            }
        }

        // Loop through concatenated eCPRI messages
        while offset + ECPRI_COMMON_HEADER_LEN <= packet.len() {
            let header =
                match EcpriCommonHeader::parse(&packet[offset..offset + ECPRI_COMMON_HEADER_LEN]) {
                    Ok(h) => h,
                    Err(_) => {
                        events.push(OranDemuxEvent::PacketDropped {
                            reason: "Malformed eCPRI Common Header",
                        });
                        break;
                    }
                };

            let payload_len = header.payload_size as usize;
            let msg_end = offset + ECPRI_COMMON_HEADER_LEN + payload_len;
            if msg_end > packet.len() {
                events.push(OranDemuxEvent::PacketDropped {
                    reason: "Truncated eCPRI Message Payload",
                });
                break;
            }

            let msg_payload = &packet[offset + ECPRI_COMMON_HEADER_LEN..msg_end];

            // Demultiplex message types
            if header.message_type == ECPRI_MSG_IQ_DATA {
                self.process_uplane_message(msg_payload, arrival_time_ns, &mut events);
            } else if header.message_type == ECPRI_MSG_RT_CONTROL {
                self.process_cplane_message(msg_payload, &mut events);
            }

            // Next message alignment (4-byte boundary)
            let padded_len = (msg_end + ECPRI_CONCATENATION_ALIGNMENT - 1)
                & !(ECPRI_CONCATENATION_ALIGNMENT - 1);
            if !header.concatenated {
                break;
            }
            offset = padded_len;
        }

        events
    }

    fn process_uplane_message(
        &mut self,
        payload: &[u8],
        arrival_time_ns: i64,
        events: &mut Vec<OranDemuxEvent>,
    ) {
        // Minimum U-Plane: 2 bytes PC_ID (eAxC ID) + 2 bytes seq_id + 4 bytes radio header = 8 bytes
        if payload.len() < 8 {
            events.push(OranDemuxEvent::PacketDropped {
                reason: "U-Plane payload too short",
            });
            return;
        }

        let eaxc_id = u16::from_be_bytes([payload[0], payload[1]]);
        let radio_header = match OranRadioHeader::parse(&payload[4..8]) {
            Ok(h) => h,
            Err(_) => {
                events.push(OranDemuxEvent::PacketDropped {
                    reason: "Malformed Radio Application Header",
                });
                return;
            }
        };

        let stat = self.stats.entry(eaxc_id).or_default();
        stat.total_uplane_packets += 1;

        // Check timing window
        let verdict = if let Some(dm) = self.delay_managers.get_mut(&eaxc_id) {
            let air_time_ns = (radio_header.subframe_id as i64) * 1_000_000
                + (radio_header.symbol_id as i64) * 71_428;
            dm.observe(air_time_ns, arrival_time_ns)
        } else {
            WindowVerdict::OnTime { margin_ns: 0 }
        };

        match verdict {
            WindowVerdict::TooEarly { .. } => {
                stat.early_dropped_packets += 1;
                events.push(OranDemuxEvent::UPlaneReceived {
                    eaxc_id,
                    frame_id: radio_header.frame_id,
                    subframe_id: radio_header.subframe_id,
                    slot_id: radio_header.slot_id,
                    symbol_id: radio_header.symbol_id,
                    prb_count: 0,
                    samples_count: 0,
                    verdict,
                });
                return;
            }
            WindowVerdict::TooLate { .. } => {
                stat.late_dropped_packets += 1;
                events.push(OranDemuxEvent::UPlaneReceived {
                    eaxc_id,
                    frame_id: radio_header.frame_id,
                    subframe_id: radio_header.subframe_id,
                    slot_id: radio_header.slot_id,
                    symbol_id: radio_header.symbol_id,
                    prb_count: 0,
                    samples_count: 0,
                    verdict,
                });
                return;
            }
            WindowVerdict::OnTime { .. } => {
                stat.on_time_uplane_packets += 1;
            }
        }

        // Parse U-Plane PRB sections if present
        let mut prb_count = 0;
        let mut samples_decompressed = 0;

        if payload.len() >= 12 {
            let section_header = &payload[8..12];
            let num_prbc = section_header[3];
            prb_count = num_prbc;

            // Decompress BFP IQ payload if present
            if payload.len() > 12 && num_prbc > 0 {
                let iq_bytes = &payload[12..];
                if let Ok(codec) = BfpCodec::new(9) {
                    if let Ok(samples) = codec.decompress(iq_bytes, num_prbc as usize) {
                        samples_decompressed = samples.len();
                        stat.total_decompressed_samples += samples.len() as u64;
                    }
                }
            }
        }

        events.push(OranDemuxEvent::UPlaneReceived {
            eaxc_id,
            frame_id: radio_header.frame_id,
            subframe_id: radio_header.subframe_id,
            slot_id: radio_header.slot_id,
            symbol_id: radio_header.symbol_id,
            prb_count,
            samples_count: samples_decompressed,
            verdict,
        });
    }

    fn process_cplane_message(&mut self, payload: &[u8], events: &mut Vec<OranDemuxEvent>) {
        if payload.len() < 8 {
            events.push(OranDemuxEvent::PacketDropped {
                reason: "C-Plane payload too short",
            });
            return;
        }

        let eaxc_id = u16::from_be_bytes([payload[0], payload[1]]);
        let _radio_header = match OranRadioHeader::parse(&payload[4..8]) {
            Ok(h) => h,
            Err(_) => {
                events.push(OranDemuxEvent::PacketDropped {
                    reason: "Malformed C-Plane Radio Header",
                });
                return;
            }
        };

        let stat = self.stats.entry(eaxc_id).or_default();
        stat.total_cplane_packets += 1;

        if payload.len() < 12 {
            return;
        }

        let section_type = payload[8];

        if section_type == ORAN_SECTION_TYPE_3 {
            // Section Type 3 (PRACH)
            if payload.len() >= 12 + 14 {
                if let Ok(sec3) = CPlaneSectionType3::parse(&payload[12..12 + 14]) {
                    let freq_shift_hz = OranCPlaneExtEngine::calculate_frequency_shift_hz(
                        sec3.frequency_offset,
                        1.25,
                    );
                    events.push(OranDemuxEvent::CPlaneSection3Received {
                        eaxc_id,
                        section_id: sec3.section_id,
                        time_offset: sec3.time_offset,
                        frame_structure: sec3.frame_structure,
                        frequency_offset_hz: freq_shift_hz,
                    });
                }
            }
        } else {
            // Section Type 1
            let section_body = &payload[12..];
            if section_body.len() >= 8 {
                let section_id = (((section_body[0] as u16) << 4)
                    | (((section_body[1] >> 4) & 0x0F) as u16))
                    & 0x0FFF;
                let ef = (section_body[1] & 0x08) != 0;
                let start_prbc =
                    (((section_body[1] & 0x03) as u16) << 8) | (section_body[2] as u16);
                let num_prbc = section_body[3];

                let mut beam_id = None;
                let mut bfw_antennas = None;

                // Parse section extensions if ef is set
                if ef && section_body.len() > 8 {
                    let mut ext_offset = 8;
                    while ext_offset + 4 <= section_body.len() {
                        let ext_type = section_body[ext_offset];
                        let ext_len_words = u16::from_be_bytes([
                            section_body[ext_offset + 1],
                            section_body[ext_offset + 2],
                        ]);
                        let ext_bytes = (ext_len_words as usize) * 4;
                        if ext_offset + ext_bytes > section_body.len() || ext_bytes < 4 {
                            break;
                        }

                        let ext_data = &section_body[ext_offset..ext_offset + ext_bytes];
                        if ext_type == ORAN_EXT_BEAMFORMING_WEIGHTS {
                            let ant_count = self
                                .stream_configs
                                .get(&eaxc_id)
                                .map(|c| c.num_antennas)
                                .unwrap_or(64);
                            if let Ok(ext1) = SectionExtension1::parse(ext_data, ant_count) {
                                if let Some(first_b) = ext1.bundles.first() {
                                    bfw_antennas = Some(first_b.weights.len());
                                    stat.last_bfw_weights_count = Some(first_b.weights.len());
                                }
                            }
                        } else if ext_type == ORAN_EXT_BEAM_ATTRIBUTES {
                            if let Ok(ext2) = SectionExtension2::parse(ext_data) {
                                beam_id = Some(ext2.bf_id);
                                stat.last_beam_id = Some(ext2.bf_id);
                            }
                        }

                        ext_offset += ext_bytes;
                    }
                }

                events.push(OranDemuxEvent::CPlaneSection1Received {
                    eaxc_id,
                    section_id,
                    start_prbc,
                    num_prbc,
                    beam_id,
                    bfw_antennas,
                });
            }
        }
    }

    /// Builds a serialized eCPRI User Plane frame (Type 0) with Block Floating Point compressed IQ data.
    pub fn build_uplane_frame(
        &self,
        eaxc_id: u16,
        radio_header: &OranRadioHeader,
        start_prbc: u16,
        num_prbc: u8,
        samples: &[IqSample],
        iq_width: u8,
    ) -> Vec<u8> {
        let mut msg_payload = Vec::new();

        // 2 bytes eAxC ID
        msg_payload.extend_from_slice(&eaxc_id.to_be_bytes());
        // 2 bytes Sequence ID (subsequence = 0, e_bit = 1)
        msg_payload.extend_from_slice(&[0x00, 0x80]);
        // 4 bytes Radio Application Header
        msg_payload.extend_from_slice(&radio_header.serialize());

        // 4 bytes Section Header (sectionId = 0, rb = 0, symInc = 0, startPrbc, numPrbc)
        let b0 = 0x00;
        let b1 = ((start_prbc >> 8) & 0x03) as u8;
        let b2 = (start_prbc & 0xFF) as u8;
        let b3 = num_prbc;
        msg_payload.extend_from_slice(&[b0, b1, b2, b3]);

        // Compress IQ samples using BFP
        let codec = BfpCodec::new(iq_width).unwrap_or_else(|_| BfpCodec::new(9).unwrap());
        if let Ok(compressed_iq) = codec.compress(samples) {
            msg_payload.extend_from_slice(&compressed_iq);
        }

        // eCPRI Common Header
        let ecpri_hdr = EcpriCommonHeader::new(ECPRI_MSG_IQ_DATA, msg_payload.len() as u16);
        let mut frame = Vec::with_capacity(ECPRI_COMMON_HEADER_LEN + msg_payload.len());
        frame.extend_from_slice(&ecpri_hdr.serialize());
        frame.extend_from_slice(&msg_payload);
        frame
    }

    /// Builds a serialized eCPRI Real-Time Control frame (Type 2) with Section Extension 1 and 2.
    pub fn build_cplane_section1_frame(
        &self,
        eaxc_id: u16,
        radio_header: &OranRadioHeader,
        section_id: u16,
        start_prbc: u16,
        num_prbc: u8,
        ext1: Option<&SectionExtension1>,
        ext2: Option<&SectionExtension2>,
    ) -> Vec<u8> {
        let mut msg_payload = Vec::new();

        // 2 bytes eAxC ID (RTC_ID)
        msg_payload.extend_from_slice(&eaxc_id.to_be_bytes());
        // 2 bytes Sequence ID
        msg_payload.extend_from_slice(&[0x00, 0x80]);
        // 4 bytes Radio Application Header
        msg_payload.extend_from_slice(&radio_header.serialize());

        // 4 bytes Section Type Common Header: sectionType = 1, numberOfSections = 1
        msg_payload.push(1); // Section Type 1
        msg_payload.push(1); // 1 section
        msg_payload.extend_from_slice(&[0, 0]); // reserved

        // Section body (8 bytes)
        let ef = ext1.is_some() || ext2.is_some();
        let b0 = ((section_id >> 4) & 0xFF) as u8;
        let b1 = (((section_id & 0x0F) as u8) << 4)
            | (if ef { 0x08 } else { 0x00 })
            | (((start_prbc >> 8) & 0x03) as u8);
        let b2 = (start_prbc & 0xFF) as u8;
        let b3 = num_prbc;
        let re_mask = 0x0FFF;
        let b4 = ((re_mask >> 4) & 0xFF) as u8;
        let b5 = ((re_mask & 0x0F) as u8) << 4;
        let b6 = 0;
        let b7 = 0;
        msg_payload.extend_from_slice(&[b0, b1, b2, b3, b4, b5, b6, b7]);

        // Append Section Extensions
        if let Some(e1) = ext1 {
            msg_payload.extend_from_slice(&e1.serialize());
        }
        if let Some(e2) = ext2 {
            msg_payload.extend_from_slice(&e2.serialize());
        }

        let ecpri_hdr = EcpriCommonHeader::new(ECPRI_MSG_RT_CONTROL, msg_payload.len() as u16);
        let mut frame = Vec::with_capacity(ECPRI_COMMON_HEADER_LEN + msg_payload.len());
        frame.extend_from_slice(&ecpri_hdr.serialize());
        frame.extend_from_slice(&msg_payload);
        frame
    }

    /// Returns statistics for a registered eAxC stream.
    pub fn get_stream_stats(&self, eaxc_id: u16) -> Option<&OranStreamStats> {
        self.stats.get(&eaxc_id)
    }
}
