//! Multi-Hop BFD & IPv6 BFD (RFC 5881 / RFC 5883).
//!
//! Provides sub-second path liveness monitoring for IPv6 Single-Hop (UDP 3784) and Multi-Hop (UDP 4784) sessions.

pub use crate::bfd::{BFD_CONTROL_PORT, BfdControlPacket, BfdState};
use crate::ipv6::Ipv6Address;
use std::collections::HashMap;

pub const BFD_MULTIHOP_PORT: u16 = 4784;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdV6Session {
    pub peer_ip: Ipv6Address,
    pub my_discriminator: u32,
    pub your_discriminator: u32,
    pub state: BfdState,
    pub desired_min_tx_us: u32,
    pub required_min_rx_us: u32,
    pub detect_mult: u8,
    pub is_multihop: bool,
}

impl BfdV6Session {
    pub fn new(peer_ip: Ipv6Address, my_discriminator: u32, is_multihop: bool) -> Self {
        BfdV6Session {
            peer_ip,
            my_discriminator,
            your_discriminator: 0,
            state: BfdState::Down,
            desired_min_tx_us: 50_000,  // 50ms
            required_min_rx_us: 50_000, // 50ms
            detect_mult: 3,
            is_multihop,
        }
    }

    pub fn build_outbound_packet(&self, poll: bool) -> BfdControlPacket {
        let mut pkt = BfdControlPacket::build_control(
            self.state,
            self.my_discriminator,
            self.your_discriminator,
            self.desired_min_tx_us,
        );
        pkt.poll = poll;
        pkt.detect_mult = self.detect_mult;
        pkt.required_min_rx_interval_us = self.required_min_rx_us;
        pkt
    }

    pub fn process_inbound_packet(&mut self, pkt: &BfdControlPacket) -> Option<BfdControlPacket> {
        if pkt.your_discriminator != 0 && pkt.your_discriminator != self.my_discriminator {
            return None;
        }
        if pkt.your_discriminator == 0 && !matches!(pkt.state, BfdState::Down | BfdState::AdminDown)
        {
            return None;
        }

        self.your_discriminator = pkt.my_discriminator;

        match (self.state, pkt.state) {
            (BfdState::Down, BfdState::Down) => {
                self.state = BfdState::Init;
                Some(self.build_outbound_packet(false))
            }
            (BfdState::Down, BfdState::Init)
            | (BfdState::Init, BfdState::Init)
            | (BfdState::Init, BfdState::Up) => {
                self.state = BfdState::Up;
                Some(self.build_outbound_packet(false))
            }
            (BfdState::Up, BfdState::Down)
            | (BfdState::Init | BfdState::Up, BfdState::AdminDown) => {
                self.state = BfdState::Down;
                Some(self.build_outbound_packet(false))
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct BfdV6Manager {
    pub sessions: HashMap<Ipv6Address, BfdV6Session>,
}

impl BfdV6Manager {
    pub fn new() -> Self {
        BfdV6Manager {
            sessions: HashMap::new(),
        }
    }

    pub fn add_session(&mut self, session: BfdV6Session) {
        self.sessions.insert(session.peer_ip, session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_bfd_v6_multihop_and_state_transition() {
        let peer_v6 = Ipv6Address::from_str("2001:db8:bfd:1::2").unwrap();
        let mut session = BfdV6Session::new(peer_v6, 0x11223344, true);
        assert_eq!(session.state, BfdState::Down);
        assert!(session.is_multihop);

        // Peer sends Down packet -> transitions to Init
        let incoming_down = BfdControlPacket::build_control(BfdState::Down, 0x99887766, 0, 50_000);
        let resp1 = session.process_inbound_packet(&incoming_down).unwrap();
        assert_eq!(session.state, BfdState::Init);
        assert_eq!(resp1.state, BfdState::Init);
        assert_eq!(session.your_discriminator, 0x99887766);

        // Peer sends Init packet -> transitions to Up
        let incoming_init =
            BfdControlPacket::build_control(BfdState::Init, 0x99887766, 0x11223344, 50_000);
        let resp2 = session.process_inbound_packet(&incoming_init).unwrap();
        assert_eq!(session.state, BfdState::Up);
        assert_eq!(resp2.state, BfdState::Up);
    }

    #[test]
    fn test_bfd_v6_rejects_mismatched_discriminator_without_mutating_session() {
        let peer_v6 = Ipv6Address::from_str("2001:db8:bfd:1::2").unwrap();
        let mut session = BfdV6Session::new(peer_v6, 0x11223344, true);
        session.state = BfdState::Up;
        session.your_discriminator = 0x99887766;

        let incoming =
            BfdControlPacket::build_control(BfdState::Down, 0xaabbccdd, 0x55667788, 50_000);

        assert!(session.process_inbound_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Up);
        assert_eq!(session.your_discriminator, 0x99887766);
    }

    #[test]
    fn test_bfd_v6_rejects_zero_discriminator_from_init_without_learning_peer() {
        let peer_v6 = Ipv6Address::from_str("2001:db8:bfd:1::2").unwrap();
        let mut session = BfdV6Session::new(peer_v6, 0x11223344, false);
        session.your_discriminator = 0x99887766;

        let incoming = BfdControlPacket::build_control(BfdState::Init, 0xaabbccdd, 0, 50_000);

        assert!(session.process_inbound_packet(&incoming).is_none());
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.your_discriminator, 0x99887766);
    }

    #[test]
    fn test_bfd_v6_init_transitions_down_when_remote_signals_admin_down() {
        let peer_v6 = Ipv6Address::from_str("2001:db8:bfd:1::2").unwrap();
        let mut session = BfdV6Session::new(peer_v6, 0x11223344, true);
        session.state = BfdState::Init;
        session.your_discriminator = 0x99887766;

        let incoming = BfdControlPacket::build_control(
            BfdState::AdminDown,
            0xaabbccdd,
            session.my_discriminator,
            50_000,
        );

        let response = session.process_inbound_packet(&incoming).unwrap();
        assert_eq!(session.state, BfdState::Down);
        assert_eq!(session.your_discriminator, 0xaabbccdd);
        assert_eq!(response.state, BfdState::Down);
        assert_eq!(response.your_discriminator, 0xaabbccdd);
    }
}
