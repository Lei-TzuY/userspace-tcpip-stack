from pathlib import Path

path = Path("src/diameter.rs")
text = path.read_text()

old_avp = '''        if length < 8 || length > data.len() {
            return None;
        }

        let (vendor_id, data_start) = if (flags & 0x80) != 0 && length >= 12 {
            let vid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            (Some(vid), 12)
        } else {
            (None, 8)
        };

        let avp_data = data[data_start..length].to_vec();
        let padded_len = (length + 3) & !3;

        Some((
            DiameterAvp {
                code,
                flags,
                vendor_id,
                data: avp_data,
            },
            padded_len.min(data.len()),
        ))
'''
new_avp = '''        if length < 8 || length > data.len() {
            return None;
        }

        let has_vendor_id = (flags & DIAMETER_FLAG_VENDOR_SPECIFIC) != 0;
        if has_vendor_id && length < 12 {
            return None;
        }

        let (vendor_id, data_start) = if has_vendor_id {
            let vid = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
            (Some(vid), 12)
        } else {
            (None, 8)
        };

        let padded_len = (length + 3) & !3;
        if padded_len > data.len() {
            return None;
        }

        let avp_data = data[data_start..length].to_vec();

        Some((
            DiameterAvp {
                code,
                flags,
                vendor_id,
                data: avp_data,
            },
            padded_len,
        ))
'''
if text.count(old_avp) != 1:
    raise SystemExit(f"AVP parse anchor count = {text.count(old_avp)}")
text = text.replace(old_avp, new_avp)

old_message_len = '''        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if length > data.len() {
            return Err(DiameterError::InvalidLength);
        }
'''
new_message_len = '''        let length = u32::from_be_bytes([0, data[1], data[2], data[3]]) as usize;
        if length < 20 || length > data.len() {
            return Err(DiameterError::InvalidLength);
        }
'''
if text.count(old_message_len) != 1:
    raise SystemExit(f"message length anchor count = {text.count(old_message_len)}")
text = text.replace(old_message_len, new_message_len)

old_loop = '''        while offset < length {
            if let Some((avp, consumed)) = DiameterAvp::parse(&data[offset..length]) {
                avps.push(avp);
                offset += consumed;
            } else {
                break;
            }
        }
'''
new_loop = '''        while offset < length {
            if let Some((avp, consumed)) = DiameterAvp::parse(&data[offset..length]) {
                avps.push(avp);
                offset += consumed;
            } else {
                return Err(DiameterError::InvalidLength);
            }
        }
'''
if text.count(old_loop) != 1:
    raise SystemExit(f"message AVP loop anchor count = {text.count(old_loop)}")
text = text.replace(old_loop, new_loop)

marker = '''        assert_eq!(DIAMETER_PORT, 3868);
    }
}'''
tests = '''        assert_eq!(DIAMETER_PORT, 3868);
    }

    fn empty_diameter_message() -> Vec<u8> {
        DiameterMessage::new_request(DIAMETER_CMD_DEVICE_WATCHDOG, 0, 1, 2).serialize()
    }

    fn set_message_length(raw: &mut [u8], length: usize) {
        let bytes = (length as u32).to_be_bytes();
        raw[1..4].copy_from_slice(&bytes[1..4]);
    }

    #[test]
    fn test_diameter_rejects_declared_length_below_header() {
        let mut raw = empty_diameter_message();
        set_message_length(&mut raw, 19);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_trailing_partial_avp_header() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&[0, 0, 0, 1]);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_vendor_avp_shorter_than_vendor_header() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&123u32.to_be_bytes());
        raw.push(DIAMETER_FLAG_VENDOR_SPECIFIC);
        raw.extend_from_slice(&[0, 0, 8]);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_rejects_missing_avp_padding() {
        let mut raw = empty_diameter_message();
        raw.extend_from_slice(&123u32.to_be_bytes());
        raw.push(DIAMETER_FLAG_MANDATORY);
        raw.extend_from_slice(&[0, 0, 9]);
        raw.push(0xaa);
        let length = raw.len();
        set_message_length(&mut raw, length);
        assert_eq!(
            DiameterMessage::parse(&raw),
            Err(DiameterError::InvalidLength)
        );
    }

    #[test]
    fn test_diameter_empty_message_and_padded_avp_remain_valid() {
        let raw = empty_diameter_message();
        let parsed = DiameterMessage::parse(&raw).unwrap();
        assert!(parsed.avps.is_empty());
        assert_eq!(parsed.header.length, 20);

        let mut message = DiameterMessage::new_request(DIAMETER_CMD_DEVICE_WATCHDOG, 0, 1, 2);
        message.add_avp(DiameterAvp::new(123, &[0xaa]));
        let raw = message.serialize();
        assert_eq!(raw.len(), 32);
        let parsed = DiameterMessage::parse(&raw).unwrap();
        assert_eq!(parsed.avps.len(), 1);
        assert_eq!(parsed.avps[0].data, vec![0xaa]);
    }
}'''
if text.count(marker) != 1:
    raise SystemExit(f"test insertion anchor count = {text.count(marker)}")
text = text.replace(marker, tests)

path.write_text(text)
