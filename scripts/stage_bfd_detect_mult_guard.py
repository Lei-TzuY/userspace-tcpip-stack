from pathlib import Path

src = Path('src/bfd.rs')
text = src.read_text()

old = '''pub enum BfdError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidLength(u8),
    ZeroMyDiscriminator,
}
'''
new = '''pub enum BfdError {
    PacketTooShort(usize),
    InvalidVersion(u8),
    InvalidLength(u8),
    ZeroDetectMultiplier,
    ZeroMyDiscriminator,
}
'''
assert old in text
text = text.replace(old, new, 1)

old = '''            BfdError::InvalidLength(l) => write!(f, "Invalid BFD length field: {}", l),
            BfdError::ZeroMyDiscriminator => write!(f, "BFD My Discriminator must not be zero"),
'''
new = '''            BfdError::InvalidLength(l) => write!(f, "Invalid BFD length field: {}", l),
            BfdError::ZeroDetectMultiplier => write!(f, "BFD Detect Mult must not be zero"),
            BfdError::ZeroMyDiscriminator => write!(f, "BFD My Discriminator must not be zero"),
'''
assert old in text
text = text.replace(old, new, 1)

old = '''        let detect_mult = data[2];
        let length = data[3];

        if (length as usize) < BFD_MIN_PACKET_LEN || (length as usize) > data.len() {
'''
new = '''        let detect_mult = data[2];
        if detect_mult == 0 {
            return Err(BfdError::ZeroDetectMultiplier);
        }
        let length = data[3];

        if (length as usize) < BFD_MIN_PACKET_LEN || (length as usize) > data.len() {
'''
assert old in text
text = text.replace(old, new, 1)
src.write_text(text)

Path('tests/test_bfd_validation.rs').write_text('''use toy_tcpip::bfd::{BFD_MIN_PACKET_LEN, BfdControlPacket, BfdError, BfdState};

#[test]
fn zero_detect_multiplier_is_rejected() {
    let mut packet = BfdControlPacket::build_control(BfdState::Down, 0x0102_0304, 0, 100_000)
        .serialize();
    packet[2] = 0;

    assert_eq!(
        BfdControlPacket::parse(&packet),
        Err(BfdError::ZeroDetectMultiplier)
    );
}

#[test]
fn nonzero_detect_multiplier_at_minimum_packet_length_still_parses() {
    let mut packet = BfdControlPacket::build_control(BfdState::Down, 0x0102_0304, 0, 100_000)
        .serialize();
    assert_eq!(packet.len(), BFD_MIN_PACKET_LEN);
    packet[2] = 1;

    let parsed = BfdControlPacket::parse(&packet).unwrap();
    assert_eq!(parsed.detect_mult, 1);
}
''')
