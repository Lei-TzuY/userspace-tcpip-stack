//! RFC 7323 timestamp behaviour: option negotiation, the TS.Recent update rule,
//! and PAWS (Protection Against Wrapped Sequence numbers).

use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::tcp::*;

const SERVER_IP: Ipv4Address = Ipv4Address([192, 168, 10, 1]);
const CLIENT_IP: Ipv4Address = Ipv4Address([192, 168, 10, 2]);
const SERVER_PORT: u16 = 80;
const CLIENT_PORT: u16 = 40000;
const SERVER_ISN: u32 = 7_000_000;

fn server() -> TcpConnection {
    TcpConnection::new_server(
        SocketAddrV4 {
            ip: SERVER_IP,
            port: SERVER_PORT,
        },
        SocketAddrV4 {
            ip: CLIENT_IP,
            port: CLIENT_PORT,
        },
        SERVER_ISN,
    )
}

/// Builds a client -> server segment the way the wire would carry it.
fn from_client(
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    options: &[TcpOption],
    payload: &[u8],
) -> Vec<u8> {
    TcpSegment::serialize_with_options(
        CLIENT_IP,
        SERVER_IP,
        CLIENT_PORT,
        SERVER_PORT,
        seq,
        ack,
        flags,
        65535,
        options,
        payload,
    )
}

fn feed(conn: &mut TcpConnection, raw: &[u8], now_ms: u64) -> Option<Vec<u8>> {
    let seg = TcpSegment::parse(CLIENT_IP, SERVER_IP, raw, true).expect("segment parses");
    conn.handle_segment_at(&seg, now_ms)
}

fn ts(val: u32, ecr: u32) -> TcpOption {
    TcpOption::Timestamp { val, ecr }
}

/// Extracts the Timestamp option from a segment the server just emitted.
fn echoed_timestamp(raw: &[u8]) -> Option<(u32, u32)> {
    TcpSegment::parse(SERVER_IP, CLIENT_IP, raw, true)
        .expect("reply parses")
        .options
        .into_iter()
        .find_map(|o| match o {
            TcpOption::Timestamp { val, ecr } => Some((val, ecr)),
            _ => None,
        })
}

/// Drives a handshake that negotiates timestamps and leaves the server ESTABLISHED with
/// 100 bytes of in-order data received.
fn established_with_timestamps() -> TcpConnection {
    let mut conn = server();

    // SYN carrying TSopt: RFC 7323 section 3.2 negotiation, and the SYN seeds TS.Recent.
    let syn = from_client(5000, 0, TcpFlags::syn(), &[ts(1000, 0)], &[]);
    feed(&mut conn, &syn, 100).expect("SYN-ACK");
    assert!(conn.ts_enabled, "timestamps negotiated on the SYN");
    assert_eq!(conn.ts_recent, 1000, "SYN seeds TS.Recent directly");

    // Final handshake ACK.
    let ack = from_client(
        5001,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(1010, 100)],
        &[],
    );
    feed(&mut conn, &ack, 110);
    assert_eq!(conn.state, TcpState::Established);
    assert_eq!(conn.ts_recent, 1010, "in-window ACK advances TS.Recent");

    // 100 bytes of in-order data.
    let data = from_client(
        5001,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(1020, 110)],
        &[0xAA; 100],
    );
    feed(&mut conn, &data, 120).expect("ACK for data");
    assert_eq!(conn.rcv_nxt, 5101);
    assert_eq!(conn.ts_recent, 1020);
    assert_eq!(conn.rx_buffer.len(), 100);

    conn
}

/// RFC 7323 section 5.3. An old duplicate whose sequence number has wrapped back into the
/// current receive window is rejected on its stale timestamp alone. Without PAWS the
/// segment looks perfectly in-order and silently corrupts the byte stream.
#[test]
fn test_paws_discards_old_duplicate_inside_the_window() {
    let mut conn = established_with_timestamps();

    let stale = from_client(
        5101, // exactly rcv_nxt: indistinguishable from fresh data by sequence alone
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(900, 110)], // but its timestamp predates TS.Recent (1020)
        &[0xBB; 100],
    );
    let reply = feed(&mut conn, &stale, 130).expect("PAWS still acknowledges");

    assert_eq!(
        conn.stats.paws_discards, 1,
        "segment counted as a PAWS drop"
    );
    assert_eq!(conn.rcv_nxt, 5101, "receive sequence did not advance");
    assert_eq!(conn.rx_buffer.len(), 100, "stale payload was not delivered");
    assert!(
        conn.rx_buffer.iter().all(|&b| b == 0xAA),
        "byte stream is uncorrupted"
    );
    assert_eq!(
        echoed_timestamp(&reply).map(|(_, ecr)| ecr),
        Some(1020),
        "the ACK still echoes the last valid TS.Recent"
    );
}

/// A RST must never be swallowed by PAWS, or a peer that has genuinely gone away could
/// not tear the connection down.
#[test]
fn test_paws_does_not_swallow_reset() {
    let mut conn = established_with_timestamps();

    let mut flags = TcpFlags::ack();
    flags.rst = true;
    let rst = from_client(
        5101,
        SERVER_ISN.wrapping_add(1),
        flags,
        &[ts(900, 110)], // stale timestamp, yet still a legitimate reset
        &[],
    );
    feed(&mut conn, &rst, 130);

    assert_eq!(conn.stats.paws_discards, 0, "RST is exempt from PAWS");
    assert_eq!(conn.state, TcpState::Closed);
}

/// RFC 7323 section 4.3. TS.Recent only advances on a segment that covers the last byte
/// we acknowledged. A segment sent ahead of a hole must not move it, otherwise the value
/// echoed back describes data the peer has not had acknowledged and its RTT estimate is
/// wrecked.
#[test]
fn test_ts_recent_ignores_segment_ahead_of_last_ack_sent() {
    let mut conn = established_with_timestamps();
    assert_eq!(conn.last_ack_sent, 5101);

    // Out-of-order: sits beyond rcv_nxt, leaving a hole at 5101..5201.
    let ahead = from_client(
        5201,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(1030, 120)],
        &[0xCC; 100],
    );
    let reply = feed(&mut conn, &ahead, 140).expect("duplicate ACK for the hole");

    assert_eq!(
        conn.ts_recent, 1020,
        "TS.Recent must not follow a segment past Last.ACK.sent"
    );
    assert_eq!(
        echoed_timestamp(&reply).map(|(_, ecr)| ecr),
        Some(1020),
        "the ACK echoes the timestamp of the data actually acknowledged"
    );
    assert_eq!(conn.rcv_nxt, 5101, "the hole is still open");
}

/// TS.Recent must not be dragged backwards by a reordered segment either.
#[test]
fn test_ts_recent_never_moves_backwards() {
    let mut conn = established_with_timestamps();

    // A retransmission of already-acknowledged data carrying an older timestamp.
    let old = from_client(
        4901,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(1005, 110)],
        &[0xDD; 100],
    );
    feed(&mut conn, &old, 150);

    assert_eq!(conn.ts_recent, 1020, "TS.Recent is monotonic");
}

/// RFC 7323 section 3.2. Timestamps are enabled by the SYN exchange alone. A peer that
/// omitted the option on its SYN cannot switch it on mid-connection, and the stack must
/// not start emitting a TSopt the peer never agreed to.
#[test]
fn test_timestamp_option_is_ignored_when_not_negotiated() {
    let mut conn = server();

    // SYN without TSopt.
    let syn = from_client(5000, 0, TcpFlags::syn(), &[TcpOption::Mss(1460)], &[]);
    let syn_ack = feed(&mut conn, &syn, 100).expect("SYN-ACK");
    assert!(!conn.ts_enabled, "timestamps were never negotiated");
    assert!(
        echoed_timestamp(&syn_ack).is_none(),
        "SYN-ACK must not offer timestamps the client did not request"
    );

    let ack = from_client(5001, SERVER_ISN.wrapping_add(1), TcpFlags::ack(), &[], &[]);
    feed(&mut conn, &ack, 110);
    assert_eq!(conn.state, TcpState::Established);

    // Data that suddenly carries a TSopt anyway.
    let data = from_client(
        5001,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(9999, 0)],
        &[0xEE; 50],
    );
    let reply = feed(&mut conn, &data, 120).expect("ACK for data");

    assert!(!conn.ts_enabled, "a mid-stream TSopt must not enable them");
    assert_eq!(conn.ts_recent, 0, "TS.Recent was never seeded");
    assert!(
        echoed_timestamp(&reply).is_none(),
        "our ACK must not carry an unnegotiated TSopt"
    );
    // The data itself is still perfectly valid and must be delivered.
    assert_eq!(conn.rx_buffer.len(), 50);
}

/// PAWS compares timestamps with RFC 1982 serial arithmetic, so a peer whose 32-bit
/// timestamp clock wraps past zero keeps working instead of having every segment
/// rejected as ancient.
#[test]
fn test_paws_accepts_timestamps_across_the_32_bit_wrap() {
    let mut conn = server();

    let syn = from_client(
        5000,
        0,
        TcpFlags::syn(),
        &[ts(0xFFFF_FF00, 0)], // clock is about to wrap
        &[],
    );
    feed(&mut conn, &syn, 100).expect("SYN-ACK");
    let ack = from_client(
        5001,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(0xFFFF_FF10, 100)],
        &[],
    );
    feed(&mut conn, &ack, 110);
    assert_eq!(conn.state, TcpState::Established);

    // The clock wraps: 0x0000_0040 is *newer* than 0xFFFF_FF10 in serial arithmetic.
    let wrapped = from_client(
        5001,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(0x0000_0040, 110)],
        &[0x11; 20],
    );
    feed(&mut conn, &wrapped, 120).expect("ACK");

    assert_eq!(conn.stats.paws_discards, 0, "a wrapped clock is not stale");
    assert_eq!(
        conn.rx_buffer.len(),
        20,
        "data across the wrap is delivered"
    );
    assert_eq!(conn.ts_recent, 0x0000_0040);
}

/// Negotiation belongs to the handshake alone. A spurious SYN injected into an
/// established connection must not switch timestamps off or reseed TS.Recent -- that
/// would be a way to disarm PAWS from off-path and then replay old duplicates.
#[test]
fn test_spurious_syn_cannot_renegotiate_timestamps() {
    let mut conn = established_with_timestamps();

    // A bare SYN with no TSopt, as an off-path attacker would inject it.
    let bare_syn = from_client(5101, SERVER_ISN.wrapping_add(1), TcpFlags::syn(), &[], &[]);
    feed(&mut conn, &bare_syn, 130);

    assert!(conn.ts_enabled, "timestamps stay negotiated");
    assert_eq!(conn.ts_recent, 1020, "TS.Recent was not reseeded");

    // PAWS is therefore still armed against the old duplicate that would follow.
    let stale = from_client(
        5101,
        SERVER_ISN.wrapping_add(1),
        TcpFlags::ack(),
        &[ts(900, 110)],
        &[0xBB; 100],
    );
    feed(&mut conn, &stale, 140);

    assert_eq!(conn.stats.paws_discards, 1, "PAWS still rejects the replay");
    assert!(
        conn.rx_buffer.iter().all(|&b| b == 0xAA),
        "byte stream is uncorrupted"
    );
}
