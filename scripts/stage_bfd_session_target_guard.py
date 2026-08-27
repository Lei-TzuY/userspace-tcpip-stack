from pathlib import Path

src = Path('src/bfd.rs')
text = src.read_text()
old = '''    /// Advances the BFD FSM upon receiving a remote BFD control packet
    pub fn process_packet(&mut self, pkt: &BfdControlPacket) -> Option<BfdControlPacket> {
        self.remote_discriminator = pkt.my_discriminator;

        match (self.state, pkt.state) {
'''
new = '''    /// Advances the BFD FSM upon receiving a remote BFD control packet.
    ///
    /// RFC 5880 section 6.8.6 requires session demultiplexing to succeed
    /// before any remote session state is updated. A nonzero Your
    /// Discriminator must identify this session, while a zero value is only
    /// valid during the Down/AdminDown bootstrap states.
    pub fn process_packet(&mut self, pkt: &BfdControlPacket) -> Option<BfdControlPacket> {
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.local_discriminator {
            return None;
        }
        if pkt.your_discriminator == 0
            && !matches!(pkt.state, BfdState::Down | BfdState::AdminDown)
        {
            return None;
        }

        self.remote_discriminator = pkt.my_discriminator;

        match (self.state, pkt.state) {
'''
assert old in text
src.write_text(text.replace(old, new, 1))

Path('tests/test_bfd_session_targeting.rs').write_text('''use toy_tcpip::bfd::{BfdControlPacket, BfdSession, BfdState};

#[test]
fn wrong_nonzero_your_discriminator_is_ignored_without_mutating_session() {
    let mut session = BfdSession::new(0x1001, 100_000);
    session.remote_discriminator = 0xaaaa;

    let packet = BfdControlPacket::build_control(BfdState::Down, 0x2002, 0x9999, 100_000);
    assert_eq!(session.process_packet(&packet), None);
    assert_eq!(session.state, BfdState::Down);
    assert_eq!(session.remote_discriminator, 0xaaaa);
}

#[test]
fn zero_your_discriminator_cannot_drive_init_or_up_state() {
    for remote_state in [BfdState::Init, BfdState::Up] {
        let mut session = BfdSession::new(0x1001, 100_000);
        session.remote_discriminator = 0xaaaa;

        let packet = BfdControlPacket::build_control(remote_state, 0x2002, 0, 100_000);
        assert_eq!(session.process_packet(&packet), None);
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.remote_discriminator, 0xaaaa);
    }
}

#[test]
fn zero_your_discriminator_down_bootstrap_remains_valid() {
    let mut session = BfdSession::new(0x1001, 100_000);
    let packet = BfdControlPacket::build_control(BfdState::Down, 0x2002, 0, 100_000);

    let response = session.process_packet(&packet).unwrap();
    assert_eq!(session.state, BfdState::Init);
    assert_eq!(session.remote_discriminator, 0x2002);
    assert_eq!(response.state, BfdState::Init);
    assert_eq!(response.your_discriminator, 0x2002);
}

#[test]
fn matching_nonzero_your_discriminator_allows_established_handshake() {
    let mut session = BfdSession::new(0x1001, 100_000);
    session.state = BfdState::Init;

    let packet = BfdControlPacket::build_control(BfdState::Init, 0x2002, 0x1001, 100_000);
    let response = session.process_packet(&packet).unwrap();

    assert_eq!(session.state, BfdState::Up);
    assert_eq!(session.remote_discriminator, 0x2002);
    assert_eq!(response.state, BfdState::Up);
}
''')
