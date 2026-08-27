//! IP Flow Information Export (IPFIX / NetFlow v10 - RFC 7011 / RFC 7012).
//!
//! Provides extensible enterprise network flow measurement, performance monitoring, and telemetry export (UDP/TCP Port 4739).

use crate::ipv4::Ipv4Address;

pub const IPFIX_UDP_PORT: u16 = 4739;
pub const IPFIX_TCP_PORT: u16 = 4739;
pub const IPFIX_VERSION: u16 = 10;

pub const IPFIX_SET_ID_TEMPLATE: u16 = 2;
pub const IPFIX_SET_ID_OPTIONS_TEMPLATE: u16 = 3;
pub const IPFIX_DEFAULT_TEMPLATE_ID: u16 = 256;

// IANA Standard IPFIX Information Elements (RFC 7012)
pub const IE_OCTET_DELTA_COUNT: u16 = 1;
pub const IE_PACKET_DELTA_COUNT: u16 = 2;
pub const IE_PROTOCOL_IDENTIFIER: u16 = 4;
pub const IE_IP_CLASS_OF_SERVICE: u16 = 5;
pub const IE_TCP_CONTROL_BITS: u16 = 6;
pub const IE_SOURCE_TRANSPORT_PORT: u16 = 7;
pub const IE_SOURCE_IPV4_ADDRESS: u16 = 8;
pub const IE_DESTINATION_TRANSPORT_PORT: u16 = 11;
pub const IE_DESTINATION_IPV4_ADDRESS: u16 = 12;
pub const IE_DOT1Q_VLAN_ID: u16 = 58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfixFieldSpecifier {
    pub element_id: u16,
    pub field_length: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfixTemplateRecord {
    pub template_id: u16,
    pub fields: Vec<IpfixFieldSpecifier>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfixFlowRecord {
    pub src_ip: Ipv4Address,
    pub dst_ip: Ipv4Address,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub packets: u64,
    pub octets: u64,
    pub tcp_flags: u16,
    pub vlan_id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpfixMessage {
    pub export_time: u32,
    pub sequence_number: u32,
    pub observation_domain_id: u32,
    pub template: Option<IpfixTemplateRecord>,
    pub flow_records: Vec<IpfixFlowRecord>,
}

impl IpfixMessage {
    pub fn build_standard_flow_export(
        export_time: u32,
        seq_num: u32,
        domain_id: u32,
        flows: &[IpfixFlowRecord],
        include_template: bool,
    ) -> Self {
        let template = if include_template {
            Some(IpfixTemplateRecord {
                template_id: IPFIX_DEFAULT_TEMPLATE_ID,
                fields: vec![
                    IpfixFieldSpecifier {
                        element_id: IE_SOURCE_IPV4_ADDRESS,
                        field_length: 4,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_DESTINATION_IPV4_ADDRESS,
                        field_length: 4,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_SOURCE_TRANSPORT_PORT,
                        field_length: 2,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_DESTINATION_TRANSPORT_PORT,
                        field_length: 2,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_PROTOCOL_IDENTIFIER,
                        field_length: 1,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_PACKET_DELTA_COUNT,
                        field_length: 8,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_OCTET_DELTA_COUNT,
                        field_length: 8,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_TCP_CONTROL_BITS,
                        field_length: 2,
                    },
                    IpfixFieldSpecifier {
                        element_id: IE_DOT1Q_VLAN_ID,
                        field_length: 2,
                    },
                ],
            })
        } else {
            None
        };

        IpfixMessage {
            export_time,
            sequence_number: seq_num,
            observation_domain_id: domain_id,
            template,
            flow_records: flows.to_vec(),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();

        // 1. Template Set if present
        if let Some(ref tmpl) = self.template {
            let mut tmpl_buf = Vec::new();
            tmpl_buf.extend_from_slice(&tmpl.template_id.to_be_bytes());
            tmpl_buf.extend_from_slice(&(tmpl.fields.len() as u16).to_be_bytes());
            for f in &tmpl.fields {
                tmpl_buf.extend_from_slice(&f.element_id.to_be_bytes());
                tmpl_buf.extend_from_slice(&f.field_length.to_be_bytes());
            }

            let set_len = 4 + tmpl_buf.len() as u16;
            body.extend_from_slice(&IPFIX_SET_ID_TEMPLATE.to_be_bytes());
            body.extend_from_slice(&set_len.to_be_bytes());
            body.extend_from_slice(&tmpl_buf);
        }

        // 2. Data Set
        if !self.flow_records.is_empty() {
            let mut data_buf = Vec::new();
            for f in &self.flow_records {
                data_buf.extend_from_slice(&f.src_ip.0);
                data_buf.extend_from_slice(&f.dst_ip.0);
                data_buf.extend_from_slice(&f.src_port.to_be_bytes());
                data_buf.extend_from_slice(&f.dst_port.to_be_bytes());
                data_buf.push(f.protocol);
                data_buf.extend_from_slice(&f.packets.to_be_bytes());
                data_buf.extend_from_slice(&f.octets.to_be_bytes());
                data_buf.extend_from_slice(&f.tcp_flags.to_be_bytes());
                data_buf.extend_from_slice(&f.vlan_id.to_be_bytes());
            }

            let data_set_len = 4 + data_buf.len() as u16;
            body.extend_from_slice(&IPFIX_DEFAULT_TEMPLATE_ID.to_be_bytes());
            body.extend_from_slice(&data_set_len.to_be_bytes());
            body.extend_from_slice(&data_buf);
        }

        let total_length = 16 + body.len() as u16;
        let mut msg = Vec::with_capacity(total_length as usize);
        msg.extend_from_slice(&IPFIX_VERSION.to_be_bytes());
        msg.extend_from_slice(&total_length.to_be_bytes());
        msg.extend_from_slice(&self.export_time.to_be_bytes());
        msg.extend_from_slice(&self.sequence_number.to_be_bytes());
        msg.extend_from_slice(&self.observation_domain_id.to_be_bytes());
        msg.extend_from_slice(&body);

        msg
    }

    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }

        let version = u16::from_be_bytes([data[0], data[1]]);
        if version != IPFIX_VERSION {
            return None;
        }

        let length = u16::from_be_bytes([data[2], data[3]]) as usize;
        if length < 16 || data.len() < length {
            return None;
        }

        let export_time = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let sequence_number = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let observation_domain_id = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);

        let mut offset = 16;
        let mut template = None;
        let mut flow_records = Vec::new();

        while offset + 4 <= length {
            let set_id = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let set_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;

            if set_len < 4 || offset + set_len > length {
                return None;
            }

            let set_data = &data[offset + 4..offset + set_len];
            if set_id == IPFIX_SET_ID_TEMPLATE {
                if set_data.len() >= 4 {
                    let tid = u16::from_be_bytes([set_data[0], set_data[1]]);
                    let f_count = u16::from_be_bytes([set_data[2], set_data[3]]) as usize;
                    let mut fields = Vec::new();
                    let mut f_off = 4;
                    for _ in 0..f_count {
                        if f_off + 4 <= set_data.len() {
                            let elem = u16::from_be_bytes([set_data[f_off], set_data[f_off + 1]]);
                            let flen =
                                u16::from_be_bytes([set_data[f_off + 2], set_data[f_off + 3]]);
                            fields.push(IpfixFieldSpecifier {
                                element_id: elem,
                                field_length: flen,
                            });
                            f_off += 4;
                        }
                    }
                    template = Some(IpfixTemplateRecord {
                        template_id: tid,
                        fields,
                    });
                }
            } else if set_id >= IPFIX_DEFAULT_TEMPLATE_ID {
                // Record length for standard template = 4+4+2+2+1+8+8+2+2 = 33 bytes
                let mut d_off = 0;
                while d_off + 33 <= set_data.len() {
                    let src_ip = Ipv4Address([
                        set_data[d_off],
                        set_data[d_off + 1],
                        set_data[d_off + 2],
                        set_data[d_off + 3],
                    ]);
                    let dst_ip = Ipv4Address([
                        set_data[d_off + 4],
                        set_data[d_off + 5],
                        set_data[d_off + 6],
                        set_data[d_off + 7],
                    ]);
                    let src_port = u16::from_be_bytes([set_data[d_off + 8], set_data[d_off + 9]]);
                    let dst_port = u16::from_be_bytes([set_data[d_off + 10], set_data[d_off + 11]]);
                    let protocol = set_data[d_off + 12];
                    let packets = u64::from_be_bytes([
                        set_data[d_off + 13],
                        set_data[d_off + 14],
                        set_data[d_off + 15],
                        set_data[d_off + 16],
                        set_data[d_off + 17],
                        set_data[d_off + 18],
                        set_data[d_off + 19],
                        set_data[d_off + 20],
                    ]);
                    let octets = u64::from_be_bytes([
                        set_data[d_off + 21],
                        set_data[d_off + 22],
                        set_data[d_off + 23],
                        set_data[d_off + 24],
                        set_data[d_off + 25],
                        set_data[d_off + 26],
                        set_data[d_off + 27],
                        set_data[d_off + 28],
                    ]);
                    let tcp_flags =
                        u16::from_be_bytes([set_data[d_off + 29], set_data[d_off + 30]]);
                    let vlan_id = u16::from_be_bytes([set_data[d_off + 31], set_data[d_off + 32]]);

                    flow_records.push(IpfixFlowRecord {
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        packets,
                        octets,
                        tcp_flags,
                        vlan_id,
                    });
                    d_off += 33;
                }
            }

            offset += set_len;
        }

        if offset != length {
            return None;
        }

        Some(IpfixMessage {
            export_time,
            sequence_number,
            observation_domain_id,
            template,
            flow_records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipfix_template_and_data_export_roundtrip() {
        let flows = vec![IpfixFlowRecord {
            src_ip: Ipv4Address::new(10, 1, 1, 100),
            dst_ip: Ipv4Address::new(10, 2, 2, 200),
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            packets: 1540,
            octets: 1540000,
            tcp_flags: 0x0018,
            vlan_id: 100,
        }];

        let msg = IpfixMessage::build_standard_flow_export(1700000000, 1, 101, &flows, true);
        let raw = msg.serialize();
        assert!(raw.len() >= 16);

        let parsed = IpfixMessage::parse(&raw).unwrap();
        assert_eq!(parsed.export_time, 1700000000);
        assert_eq!(parsed.sequence_number, 1);
        assert_eq!(parsed.observation_domain_id, 101);
        assert!(parsed.template.is_some());
        assert_eq!(parsed.flow_records.len(), 1);
        assert_eq!(
            parsed.flow_records[0].src_ip,
            Ipv4Address::new(10, 1, 1, 100)
        );
        assert_eq!(parsed.flow_records[0].dst_port, 443);
        assert_eq!(parsed.flow_records[0].packets, 1540);
    }

    fn empty_message() -> Vec<u8> {
        IpfixMessage {
            export_time: 1,
            sequence_number: 2,
            observation_domain_id: 3,
            template: None,
            flow_records: Vec::new(),
        }
        .serialize()
    }

    fn stamp_message_length(raw: &mut [u8]) {
        let message_len = raw.len() as u16;
        raw[2..4].copy_from_slice(&message_len.to_be_bytes());
    }

    #[test]
    fn test_ipfix_rejects_declared_length_below_header() {
        let mut raw = empty_message();
        raw[2..4].copy_from_slice(&15u16.to_be_bytes());
        assert!(IpfixMessage::parse(&raw).is_none());
    }

    #[test]
    fn test_ipfix_rejects_set_length_below_set_header() {
        let mut raw = empty_message();
        raw.extend_from_slice(&[0, 2, 0, 3]);
        stamp_message_length(&mut raw);
        assert!(IpfixMessage::parse(&raw).is_none());
    }

    #[test]
    fn test_ipfix_rejects_set_overrun_past_message_length() {
        let mut raw = empty_message();
        raw.extend_from_slice(&[0, 2, 0, 8]);
        stamp_message_length(&mut raw);
        assert!(IpfixMessage::parse(&raw).is_none());
    }

    #[test]
    fn test_ipfix_rejects_trailing_partial_set_header() {
        let mut raw = empty_message();
        raw.push(0);
        stamp_message_length(&mut raw);
        assert!(IpfixMessage::parse(&raw).is_none());
    }

    #[test]
    fn test_ipfix_empty_message_remains_valid() {
        let raw = empty_message();
        let parsed = IpfixMessage::parse(&raw).unwrap();
        assert!(parsed.template.is_none());
        assert!(parsed.flow_records.is_empty());
    }
}
