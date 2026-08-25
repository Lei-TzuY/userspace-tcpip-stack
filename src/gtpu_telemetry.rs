//! 5G GTP-U PDU Session Container Extension Header & In-Band Delay Telemetry (3GPP TS 38.415 / TS 29.281).
//!
//! Implements 5G GTP-U user plane extensions carrying QoS Flow Identifier (QFI), Reflective QoS
//! Indication (RQI), Paging Policy Indicator (PPI), and in-band transport delay reporting
//! between 5G gNodeB / RAN and UPF user-plane functions.

/// PDU Session Container Extension Header Type (3GPP TS 29.281).
pub const GTP_EXT_HDR_PDU_SESSION_CONTAINER: u8 = 0x85;

/// PDU Session Information Types.
pub const PDU_SESSION_TYPE_DL: u8 = 0x00;
pub const PDU_SESSION_TYPE_UL: u8 = 0x01;

/// 5G PDU Session Container Telemetry Header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduSessionTelemetry {
    pub pdu_type: u8,
    pub qfi: u8,                     // 6-bit QoS Flow Identifier (0..63)
    pub rqi: bool,                   // Reflective QoS Indication
    pub ppi: Option<u8>,             // Optional Paging Policy Indicator
    pub delay_result_us: Option<u32>, // In-band delay report in microseconds
}

impl PduSessionTelemetry {
    pub fn new(pdu_type: u8, qfi: u8, rqi: bool, delay_us: Option<u32>) -> Self {
        PduSessionTelemetry {
            pdu_type,
            qfi: qfi & 0x3F,
            rqi,
            ppi: None,
            delay_result_us: delay_us,
        }
    }

    /// Serializes the PDU Session Container into raw octets.
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Byte 0: [PDU Type: 4 bits | Flags: 4 bits (e.g. RQI, Delay Flag)]
        let mut byte0 = (self.pdu_type & 0x0F) << 4;
        if self.rqi {
            byte0 |= 0x04;
        }
        if self.delay_result_us.is_some() {
            byte0 |= 0x02; // Delay Reporting Present Flag
        }
        buf.push(byte0);

        // Byte 1: [Spare: 2 bits | QFI: 6 bits]
        buf.push(self.qfi & 0x3F);

        // If delay is present, append 4 bytes of microsecond delay
        if let Some(delay) = self.delay_result_us {
            buf.extend_from_slice(&delay.to_be_bytes());
        }

        buf
    }

    /// Parses a PDU Session Container from raw octets.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 2 {
            return Err("PDU Session Container too short".to_string());
        }

        let pdu_type = (data[0] >> 4) & 0x0F;
        let rqi = (data[0] & 0x04) != 0;
        let has_delay = (data[0] & 0x02) != 0;
        let qfi = data[1] & 0x3F;

        let delay_result_us = if has_delay && data.len() >= 6 {
            Some(u32::from_be_bytes([data[2], data[3], data[4], data[5]]))
        } else {
            None
        };

        Ok(PduSessionTelemetry {
            pdu_type,
            qfi,
            rqi,
            ppi: None,
            delay_result_us,
        })
    }
}

/// 5G GTP-U Telemetry Packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GtpuTelemetryPacket {
    pub teid: u32,
    pub telemetry: PduSessionTelemetry,
    pub payload: Vec<u8>,
}

impl GtpuTelemetryPacket {
    pub fn new(teid: u32, telemetry: PduSessionTelemetry, payload: Vec<u8>) -> Self {
        GtpuTelemetryPacket {
            teid,
            telemetry,
            payload,
        }
    }

    /// Serializes full GTP-U packet with 5G PDU Session Container extension header.
    pub fn serialize(&self) -> Vec<u8> {
        let container_bytes = self.telemetry.serialize();
        // Extension header length in 4-octet units: (Length byte + Container bytes + Next Ext Header byte) / 4
        let total_ext_len = 1 + container_bytes.len() + 1;
        let ext_len_units = ((total_ext_len + 3) / 4) as u8;
        let padded_ext_len = (ext_len_units as usize) * 4;

        let total_length = 4 + padded_ext_len + self.payload.len(); // 4 for seq/npdu/ext_hdr + ext_hdr + payload

        let mut out = Vec::with_capacity(8 + 4 + padded_ext_len + self.payload.len());
        // GTP-U Header (8 bytes): Flags=0x34 (v1, PT=1, E=1), MsgType=0xFF (G-PDU), Length, TEID
        out.push(0x34);
        out.push(0xFF);
        out.extend_from_slice(&(total_length as u16).to_be_bytes());
        out.extend_from_slice(&self.teid.to_be_bytes());

        // Mandatory 4-octet trailing field when E=1: [Seq (2B) | N-PDU (1B) | Next Ext Hdr (1B)]
        out.extend_from_slice(&[0x00, 0x00, 0x00, GTP_EXT_HDR_PDU_SESSION_CONTAINER]);

        // Extension Header Content: [Length Units (1B) | Content | Next Ext Hdr (1B: 0x00)]
        out.push(ext_len_units);
        out.extend_from_slice(&container_bytes);
        // Pad with zeros to 4-octet boundary
        while (out.len() % 4) != 0 {
            out.push(0x00);
        }

        // Inner User Payload
        out.extend_from_slice(&self.payload);
        out
    }

    /// Parses a 5G GTP-U Telemetry Packet.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err("GTP-U packet too short for extension headers".to_string());
        }

        let flags = data[0];
        let has_ext = (flags & 0x04) != 0;
        if !has_ext {
            return Err("No GTP-U extension header flag present".to_string());
        }

        let teid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let next_ext = data[11];
        if next_ext != GTP_EXT_HDR_PDU_SESSION_CONTAINER {
            return Err(format!("Unsupported extension header: 0x{:02X}", next_ext));
        }

        let ext_len_units = data[12] as usize;
        let ext_total_bytes = ext_len_units * 4;
        if data.len() < 12 + ext_total_bytes {
            return Err("Truncated GTP-U extension header".to_string());
        }

        let container_data = &data[13..12 + ext_total_bytes];
        let telemetry = PduSessionTelemetry::parse(container_data)?;
        let payload = data[12 + ext_total_bytes..].to_vec();

        Ok(GtpuTelemetryPacket {
            teid,
            telemetry,
            payload,
        })
    }
}

/// 5G GTP-U Telemetry Engine.
#[derive(Debug, Clone, Default)]
pub struct GtpuTelemetryEngine {
    pub encapsulated_count: usize,
    pub decapsulated_count: usize,
    pub total_delay_us_accumulated: u64,
}

impl GtpuTelemetryEngine {
    pub fn new() -> Self {
        GtpuTelemetryEngine {
            encapsulated_count: 0,
            decapsulated_count: 0,
            total_delay_us_accumulated: 0,
        }
    }

    /// Encapsulates payload with 5G PDU session container telemetry.
    pub fn encapsulate(
        &mut self,
        teid: u32,
        qfi: u8,
        rqi: bool,
        delay_us: Option<u32>,
        payload: &[u8],
    ) -> GtpuTelemetryPacket {
        self.encapsulated_count += 1;
        if let Some(d) = delay_us {
            self.total_delay_us_accumulated += d as u64;
        }
        let tel = PduSessionTelemetry::new(PDU_SESSION_TYPE_UL, qfi, rqi, delay_us);
        GtpuTelemetryPacket::new(teid, tel, payload.to_vec())
    }

    /// Decapsulates a 5G GTP-U telemetry packet.
    pub fn decapsulate(&mut self, data: &[u8]) -> Result<GtpuTelemetryPacket, String> {
        let pkt = GtpuTelemetryPacket::parse(data)?;
        self.decapsulated_count += 1;
        if let Some(d) = pkt.telemetry.delay_result_us {
            self.total_delay_us_accumulated += d as u64;
        }
        Ok(pkt)
    }
}
