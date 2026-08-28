//! Application Layer: Trivial File Transfer Protocol (TFTP - RFC 1350).
//!
//! Lock-step stop-and-wait reliable file transfer over UDP port 69 with 512-byte blocks.

use std::collections::HashMap;
use std::fmt;

pub const TFTP_PORT: u16 = 69;
pub const TFTP_BLOCK_SIZE: usize = 512;

// TFTP Opcodes
pub const TFTP_OPCODE_RRQ: u16 = 1;
pub const TFTP_OPCODE_WRQ: u16 = 2;
pub const TFTP_OPCODE_DATA: u16 = 3;
pub const TFTP_OPCODE_ACK: u16 = 4;
pub const TFTP_OPCODE_ERROR: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftpPacket {
    Rrq { filename: String, mode: String },
    Wrq { filename: String, mode: String },
    Data { block_num: u16, data: Vec<u8> },
    Ack { block_num: u16 },
    Error { error_code: u16, message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TftpError {
    PacketTooShort(usize),
    InvalidOpcode(u16),
    MissingNullTerminator,
    InvalidUtf8(&'static str),
    InvalidMode(String),
    EmbeddedNull(&'static str),
    TrailingData { opcode: u16, length: usize },
    InvalidPacketLength { opcode: u16, length: usize },
    DataBlockTooLarge(usize),
}

impl fmt::Display for TftpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TftpError::PacketTooShort(len) => {
                write!(f, "TFTP packet too short ({} bytes, min 4)", len)
            }
            TftpError::InvalidOpcode(op) => write!(f, "Invalid TFTP opcode: {}", op),
            TftpError::MissingNullTerminator => write!(f, "TFTP string missing null terminator"),
            TftpError::InvalidUtf8(field) => {
                write!(f, "TFTP {} is not valid UTF-8", field)
            }
            TftpError::InvalidMode(mode) => write!(f, "Invalid TFTP transfer mode: {}", mode),
            TftpError::EmbeddedNull(field) => {
                write!(f, "TFTP {} contains an embedded null byte", field)
            }
            TftpError::TrailingData { opcode, length } => write!(
                f,
                "TFTP opcode {} has {} trailing bytes after its final field",
                opcode, length
            ),
            TftpError::InvalidPacketLength { opcode, length } => write!(
                f,
                "TFTP opcode {} has invalid packet length {}",
                opcode, length
            ),
            TftpError::DataBlockTooLarge(length) => write!(
                f,
                "TFTP DATA block is {} bytes, exceeding the {}-byte maximum",
                length, TFTP_BLOCK_SIZE
            ),
        }
    }
}

impl std::error::Error for TftpError {}

fn parse_text(bytes: &[u8], field: &'static str) -> Result<String, TftpError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| TftpError::InvalidUtf8(field))
}

fn is_valid_mode(mode: &str) -> bool {
    mode.eq_ignore_ascii_case("netascii")
        || mode.eq_ignore_ascii_case("octet")
        || mode.eq_ignore_ascii_case("mail")
}

fn validate_c_string(value: &str, field: &'static str) -> Result<(), TftpError> {
    if value.as_bytes().contains(&0) {
        return Err(TftpError::EmbeddedNull(field));
    }
    Ok(())
}

impl TftpPacket {
    pub fn parse(data: &[u8]) -> Result<Self, TftpError> {
        if data.len() < 4 {
            return Err(TftpError::PacketTooShort(data.len()));
        }

        let opcode = u16::from_be_bytes([data[0], data[1]]);

        match opcode {
            TFTP_OPCODE_RRQ | TFTP_OPCODE_WRQ => {
                let rest = &data[2..];
                let null1 = rest
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(TftpError::MissingNullTerminator)?;
                let filename = parse_text(&rest[..null1], "filename")?;

                let mode_rest = &rest[null1 + 1..];
                let null2 = mode_rest
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(TftpError::MissingNullTerminator)?;
                let mode = parse_text(&mode_rest[..null2], "mode")?;
                if !is_valid_mode(&mode) {
                    return Err(TftpError::InvalidMode(mode));
                }
                let consumed = null1 + 1 + null2 + 1;
                if consumed != rest.len() {
                    return Err(TftpError::TrailingData {
                        opcode,
                        length: rest.len() - consumed,
                    });
                }

                if opcode == TFTP_OPCODE_RRQ {
                    Ok(TftpPacket::Rrq { filename, mode })
                } else {
                    Ok(TftpPacket::Wrq { filename, mode })
                }
            }
            TFTP_OPCODE_DATA => {
                let block_num = u16::from_be_bytes([data[2], data[3]]);
                let chunk = data[4..].to_vec();
                if chunk.len() > TFTP_BLOCK_SIZE {
                    return Err(TftpError::DataBlockTooLarge(chunk.len()));
                }
                Ok(TftpPacket::Data {
                    block_num,
                    data: chunk,
                })
            }
            TFTP_OPCODE_ACK => {
                if data.len() != 4 {
                    return Err(TftpError::InvalidPacketLength {
                        opcode,
                        length: data.len(),
                    });
                }
                let block_num = u16::from_be_bytes([data[2], data[3]]);
                Ok(TftpPacket::Ack { block_num })
            }
            TFTP_OPCODE_ERROR => {
                let error_code = u16::from_be_bytes([data[2], data[3]]);
                let msg_bytes = &data[4..];
                let msg_len = msg_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .ok_or(TftpError::MissingNullTerminator)?;
                if msg_len + 1 != msg_bytes.len() {
                    return Err(TftpError::TrailingData {
                        opcode,
                        length: msg_bytes.len() - msg_len - 1,
                    });
                }
                let message = parse_text(&msg_bytes[..msg_len], "error message")?;
                Ok(TftpPacket::Error {
                    error_code,
                    message,
                })
            }
            _ => Err(TftpError::InvalidOpcode(opcode)),
        }
    }

    pub fn try_serialize(&self) -> Result<Vec<u8>, TftpError> {
        let mut buf = Vec::new();

        match self {
            TftpPacket::Rrq { filename, mode } => {
                validate_c_string(filename, "filename")?;
                validate_c_string(mode, "mode")?;
                if !is_valid_mode(mode) {
                    return Err(TftpError::InvalidMode(mode.clone()));
                }
                buf.extend_from_slice(&TFTP_OPCODE_RRQ.to_be_bytes());
                buf.extend_from_slice(filename.as_bytes());
                buf.push(0);
                buf.extend_from_slice(mode.as_bytes());
                buf.push(0);
            }
            TftpPacket::Wrq { filename, mode } => {
                validate_c_string(filename, "filename")?;
                validate_c_string(mode, "mode")?;
                if !is_valid_mode(mode) {
                    return Err(TftpError::InvalidMode(mode.clone()));
                }
                buf.extend_from_slice(&TFTP_OPCODE_WRQ.to_be_bytes());
                buf.extend_from_slice(filename.as_bytes());
                buf.push(0);
                buf.extend_from_slice(mode.as_bytes());
                buf.push(0);
            }
            TftpPacket::Data { block_num, data } => {
                if data.len() > TFTP_BLOCK_SIZE {
                    return Err(TftpError::DataBlockTooLarge(data.len()));
                }
                buf.extend_from_slice(&TFTP_OPCODE_DATA.to_be_bytes());
                buf.extend_from_slice(&block_num.to_be_bytes());
                buf.extend_from_slice(data);
            }
            TftpPacket::Ack { block_num } => {
                buf.extend_from_slice(&TFTP_OPCODE_ACK.to_be_bytes());
                buf.extend_from_slice(&block_num.to_be_bytes());
            }
            TftpPacket::Error {
                error_code,
                message,
            } => {
                validate_c_string(message, "error message")?;
                buf.extend_from_slice(&TFTP_OPCODE_ERROR.to_be_bytes());
                buf.extend_from_slice(&error_code.to_be_bytes());
                buf.extend_from_slice(message.as_bytes());
                buf.push(0);
            }
        }

        Ok(buf)
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.try_serialize()
            .expect("attempted to serialize an invalid TFTP packet")
    }
}

/// Virtual in-memory TFTP File Server
pub struct TftpFileServer {
    files: HashMap<String, Vec<u8>>,
}

impl Default for TftpFileServer {
    fn default() -> Self {
        Self::new()
    }
}

impl TftpFileServer {
    pub fn new() -> Self {
        let mut server = TftpFileServer {
            files: HashMap::new(),
        };
        server.add_file(
            "pxeboot.bin",
            b"VIRTUAL PXE BOOTLOADER PAYLOAD 1234567890".to_vec(),
        );
        server.add_file("firmware.img", vec![0xaa; 1000]); // 2 blocks (512B + 488B)
        server
    }

    pub fn add_file(&mut self, filename: &str, content: Vec<u8>) {
        self.files.insert(filename.to_string(), content);
    }

    pub fn handle_read_request(&self, filename: &str, block_num: u16) -> TftpPacket {
        if let Some(content) = self.files.get(filename) {
            let offset = ((block_num.saturating_sub(1)) as usize) * TFTP_BLOCK_SIZE;
            if offset >= content.len() && !content.is_empty() {
                return TftpPacket::Data {
                    block_num,
                    data: Vec::new(), // Empty data block marks end of transfer
                };
            }

            let end = (offset + TFTP_BLOCK_SIZE).min(content.len());
            let chunk = content[offset..end].to_vec();

            TftpPacket::Data {
                block_num,
                data: chunk,
            }
        } else {
            TftpPacket::Error {
                error_code: 1, // File not found
                message: format!("File '{}' not found", filename),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tftp_rrq_ack_and_data_roundtrips() {
        // 1. RRQ
        let rrq = TftpPacket::Rrq {
            filename: "kernel.bin".to_string(),
            mode: "octet".to_string(),
        };
        let parsed_rrq = TftpPacket::parse(&rrq.serialize()).unwrap();
        assert_eq!(parsed_rrq, rrq);

        // 2. DATA
        let data = TftpPacket::Data {
            block_num: 1,
            data: vec![0x11, 0x22, 0x33, 0x44],
        };
        let parsed_data = TftpPacket::parse(&data.serialize()).unwrap();
        assert_eq!(parsed_data, data);

        // 3. ACK
        let ack = TftpPacket::Ack { block_num: 1 };
        let parsed_ack = TftpPacket::parse(&ack.serialize()).unwrap();
        assert_eq!(parsed_ack, ack);
    }

    #[test]
    fn test_tftp_try_serialize_accepts_max_data_block() {
        let packet = TftpPacket::Data {
            block_num: 1,
            data: vec![0x5a; TFTP_BLOCK_SIZE],
        };

        let serialized = packet.try_serialize().unwrap();
        assert_eq!(serialized.len(), 4 + TFTP_BLOCK_SIZE);
        assert_eq!(TftpPacket::parse(&serialized).unwrap(), packet);
    }

    #[test]
    fn test_tftp_try_serialize_rejects_oversized_data_block() {
        let packet = TftpPacket::Data {
            block_num: 1,
            data: vec![0x5a; TFTP_BLOCK_SIZE + 1],
        };

        assert_eq!(
            packet.try_serialize(),
            Err(TftpError::DataBlockTooLarge(TFTP_BLOCK_SIZE + 1))
        );
    }

    #[test]
    fn test_tftp_try_serialize_rejects_unknown_mode() {
        let packet = TftpPacket::Rrq {
            filename: "kernel.bin".to_string(),
            mode: "binary".to_string(),
        };

        assert_eq!(
            packet.try_serialize(),
            Err(TftpError::InvalidMode("binary".to_string()))
        );
    }

    #[test]
    fn test_tftp_try_serialize_rejects_embedded_nulls() {
        let rrq = TftpPacket::Rrq {
            filename: "kernel\0.bin".to_string(),
            mode: "octet".to_string(),
        };
        let error = TftpPacket::Error {
            error_code: 1,
            message: "not\0found".to_string(),
        };

        assert_eq!(
            rrq.try_serialize(),
            Err(TftpError::EmbeddedNull("filename"))
        );
        assert_eq!(
            error.try_serialize(),
            Err(TftpError::EmbeddedNull("error message"))
        );
    }

    #[test]
    fn test_tftp_rrq_rejects_invalid_utf8_filename() {
        let raw = [0x00, 0x01, 0xff, 0x00, b'o', b'c', b't', b'e', b't', 0x00];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::InvalidUtf8("filename"))
        );
    }

    #[test]
    fn test_tftp_wrq_rejects_invalid_utf8_mode() {
        let raw = [0x00, 0x02, b'f', 0x00, 0xff, 0x00];

        assert_eq!(TftpPacket::parse(&raw), Err(TftpError::InvalidUtf8("mode")));
    }

    #[test]
    fn test_tftp_rrq_rejects_unknown_mode() {
        let raw = [
            0x00, 0x01, b'f', 0x00, b'b', b'i', b'n', b'a', b'r', b'y', 0x00,
        ];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::InvalidMode("binary".to_string()))
        );
    }

    #[test]
    fn test_tftp_mode_matching_is_case_insensitive() {
        let rrq = TftpPacket::Rrq {
            filename: "kernel.bin".to_string(),
            mode: "OcTeT".to_string(),
        };

        assert_eq!(TftpPacket::parse(&rrq.serialize()).unwrap(), rrq);
    }

    #[test]
    fn test_tftp_error_rejects_invalid_utf8_message() {
        let raw = [0x00, 0x05, 0x00, 0x01, 0xff, 0x00];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::InvalidUtf8("error message"))
        );
    }

    #[test]
    fn test_tftp_rrq_rejects_trailing_bytes() {
        let mut raw = TftpPacket::Rrq {
            filename: "kernel.bin".to_string(),
            mode: "octet".to_string(),
        }
        .serialize();
        raw.extend_from_slice(&[0xaa, 0xbb]);

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::TrailingData {
                opcode: TFTP_OPCODE_RRQ,
                length: 2,
            })
        );
    }

    #[test]
    fn test_tftp_ack_rejects_trailing_bytes() {
        let raw = [0x00, 0x04, 0x00, 0x01, 0xff];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::InvalidPacketLength {
                opcode: TFTP_OPCODE_ACK,
                length: raw.len(),
            })
        );
    }

    #[test]
    fn test_tftp_data_rejects_oversized_block() {
        let mut raw = vec![0x00, 0x03, 0x00, 0x01];
        raw.extend(std::iter::repeat_n(0x5a, TFTP_BLOCK_SIZE + 1));

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::DataBlockTooLarge(TFTP_BLOCK_SIZE + 1))
        );
    }

    #[test]
    fn test_tftp_error_requires_null_terminator() {
        let raw = [0x00, 0x05, 0x00, 0x01, b'n', b'o'];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::MissingNullTerminator)
        );
    }

    #[test]
    fn test_tftp_error_rejects_trailing_bytes() {
        let raw = [0x00, 0x05, 0x00, 0x01, b'n', b'o', 0x00, 0xff];

        assert_eq!(
            TftpPacket::parse(&raw),
            Err(TftpError::TrailingData {
                opcode: TFTP_OPCODE_ERROR,
                length: 1,
            })
        );
    }

    #[test]
    fn test_tftp_virtual_server_multi_block() {
        let server = TftpFileServer::new();

        // Request block 1 of 1000-byte firmware.img
        let blk1 = server.handle_read_request("firmware.img", 1);
        if let TftpPacket::Data { block_num, data } = blk1 {
            assert_eq!(block_num, 1);
            assert_eq!(data.len(), TFTP_BLOCK_SIZE);
        } else {
            panic!("Expected Data packet");
        }

        // Request block 2 (remaining 488 bytes)
        let blk2 = server.handle_read_request("firmware.img", 2);
        if let TftpPacket::Data { block_num, data } = blk2 {
            assert_eq!(block_num, 2);
            assert_eq!(data.len(), 488); // < 512 indicates final block
        } else {
            panic!("Expected Data packet");
        }
    }
}
