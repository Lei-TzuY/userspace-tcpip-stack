//! QUIC DATAGRAM Extension (RFC 9221) & WebTransport Datagram Framing (RFC 9297).
//!
//! Enables unreliable, low-latency datagram transmission alongside reliable QUIC streams.
//! Widely used for real-time gaming, audio/video media (RTP over QUIC), MASQUE proxying,
//! and WebTransport HTTP/3 applications.
//!
//! Features:
//! - Frame 0x30: `DATAGRAM` (Implicit length, spans to end of packet)
//! - Frame 0x31: `DATAGRAM with Length` (Explicit VINT length prefix)
//! - Transport Parameter `max_datagram_frame_size` (0x20) negotiation
//! - WebTransport RFC 9297 Quarter-Stream ID / Context ID multiplexing
//! - Congestion backpressure queues with configurable drop policies (`DropOldest`, `DropNewest`).

use crate::quic::{QuicError, decode_vint, encode_vint};
use std::collections::{HashMap, VecDeque};
use std::fmt;

pub const QUIC_FRAME_DATAGRAM: u64 = 0x30;
pub const QUIC_FRAME_DATAGRAM_LEN: u64 = 0x31;
pub const QUIC_TP_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicDatagramFrame {
    pub has_length: bool,
    pub payload: Vec<u8>,
}

impl QuicDatagramFrame {
    pub fn new(payload: Vec<u8>, has_length: bool) -> Self {
        QuicDatagramFrame {
            has_length,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        let frame_type = if self.has_length {
            QUIC_FRAME_DATAGRAM_LEN
        } else {
            QUIC_FRAME_DATAGRAM
        };

        buf.extend_from_slice(&encode_vint(frame_type));
        if self.has_length {
            buf.extend_from_slice(&encode_vint(self.payload.len() as u64));
        }
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<(Self, usize), QuicError> {
        let (frame_type, consumed_type) = decode_vint(data)?;
        if frame_type != QUIC_FRAME_DATAGRAM && frame_type != QUIC_FRAME_DATAGRAM_LEN {
            return Err(QuicError::InvalidVint);
        }

        let mut offset = consumed_type;
        let has_length = frame_type == QUIC_FRAME_DATAGRAM_LEN;

        if has_length {
            let (len, consumed_len) = decode_vint(&data[offset..])?;
            offset += consumed_len;
            let len_usize = len as usize;

            if offset + len_usize > data.len() {
                return Err(QuicError::PacketTooShort(data.len()));
            }

            let payload = data[offset..offset + len_usize].to_vec();
            offset += len_usize;

            Ok((
                QuicDatagramFrame {
                    has_length,
                    payload,
                },
                offset,
            ))
        } else {
            // Implicit length: consumes remainder of buffer
            let payload = data[offset..].to_vec();
            let total_len = data.len();
            Ok((
                QuicDatagramFrame {
                    has_length,
                    payload,
                },
                total_len,
            ))
        }
    }
}

/// WebTransport RFC 9297 Datagram Format.
///
/// Prepends a VINT `quarter_stream_id` (or Session/Context ID) to the datagram payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebTransportDatagram {
    pub session_id: u64,
    pub payload: Vec<u8>,
}

impl WebTransportDatagram {
    pub fn new(session_id: u64, payload: Vec<u8>) -> Self {
        WebTransportDatagram {
            session_id,
            payload,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = encode_vint(self.session_id);
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, QuicError> {
        let (session_id, consumed) = decode_vint(data)?;
        let payload = data[consumed..].to_vec();
        Ok(WebTransportDatagram {
            session_id,
            payload,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatagramDropPolicy {
    DropOldest,
    DropNewest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramQueueError {
    ExceedsMaxDatagramSize(usize, usize),
    QueueFull,
}

impl fmt::Display for DatagramQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DatagramQueueError::ExceedsMaxDatagramSize(sz, max) => {
                write!(
                    f,
                    "Datagram size ({} bytes) exceeds max allowed ({} bytes)",
                    sz, max
                )
            }
            DatagramQueueError::QueueFull => write!(f, "Datagram queue is full"),
        }
    }
}

impl std::error::Error for DatagramQueueError {}

#[derive(Debug, Clone, Default)]
pub struct DatagramStats {
    pub enqueued: u64,
    pub dequeued: u64,
    pub dropped: u64,
}

#[derive(Debug, Clone)]
pub struct QuicDatagramQueue {
    pub max_capacity: usize,
    pub max_datagram_size: usize,
    pub drop_policy: DatagramDropPolicy,
    pub queue: VecDeque<Vec<u8>>,
    pub stats: DatagramStats,
}

impl QuicDatagramQueue {
    pub fn new(
        max_capacity: usize,
        max_datagram_size: usize,
        drop_policy: DatagramDropPolicy,
    ) -> Self {
        QuicDatagramQueue {
            max_capacity,
            max_datagram_size,
            drop_policy,
            queue: VecDeque::with_capacity(max_capacity),
            stats: DatagramStats::default(),
        }
    }

    pub fn push(&mut self, datagram: Vec<u8>) -> Result<(), DatagramQueueError> {
        if datagram.len() > self.max_datagram_size {
            return Err(DatagramQueueError::ExceedsMaxDatagramSize(
                datagram.len(),
                self.max_datagram_size,
            ));
        }

        if self.queue.len() >= self.max_capacity {
            match self.drop_policy {
                DatagramDropPolicy::DropOldest => {
                    self.queue.pop_front();
                    self.stats.dropped += 1;
                }
                DatagramDropPolicy::DropNewest => {
                    self.stats.dropped += 1;
                    return Err(DatagramQueueError::QueueFull);
                }
            }
        }

        self.queue.push_back(datagram);
        self.stats.enqueued += 1;
        Ok(())
    }

    pub fn pop(&mut self) -> Option<Vec<u8>> {
        if let Some(d) = self.queue.pop_front() {
            self.stats.dequeued += 1;
            Some(d)
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct QuicDatagramEngine {
    pub local_max_datagram_size: usize,
    pub peer_max_datagram_size: Option<usize>,
    pub tx_queue: QuicDatagramQueue,
    pub rx_queue: QuicDatagramQueue,
}

impl QuicDatagramEngine {
    pub fn new(local_max_datagram_size: usize, queue_capacity: usize) -> Self {
        QuicDatagramEngine {
            local_max_datagram_size,
            peer_max_datagram_size: None,
            tx_queue: QuicDatagramQueue::new(
                queue_capacity,
                local_max_datagram_size,
                DatagramDropPolicy::DropOldest,
            ),
            rx_queue: QuicDatagramQueue::new(
                queue_capacity,
                local_max_datagram_size,
                DatagramDropPolicy::DropOldest,
            ),
        }
    }

    pub fn on_peer_transport_parameters(&mut self, peer_max_datagram_size: usize) {
        self.peer_max_datagram_size = Some(peer_max_datagram_size);
        self.tx_queue.max_datagram_size = peer_max_datagram_size;
    }

    pub fn send_datagram(&mut self, payload: Vec<u8>) -> Result<(), DatagramQueueError> {
        self.tx_queue.push(payload)
    }

    pub fn receive_frame(&mut self, frame: &QuicDatagramFrame) -> Result<(), DatagramQueueError> {
        self.rx_queue.push(frame.payload.clone())
    }

    pub fn create_outgoing_frame(&mut self, has_length: bool) -> Option<QuicDatagramFrame> {
        let payload = self.tx_queue.pop()?;
        Some(QuicDatagramFrame::new(payload, has_length))
    }
}

/// WebTransport RFC 9297 Session Datagram Multiplexer / Demultiplexer.
#[derive(Debug, Clone)]
pub struct WebTransportDatagramEngine {
    pub max_datagram_size: usize,
    pub session_capacity: usize,
    pub drop_policy: DatagramDropPolicy,
    /// Outgoing QUIC datagrams ready to be serialized into DATAGRAM frames
    pub tx_queue: QuicDatagramQueue,
    /// Incoming demultiplexed queues: session_id -> queue
    pub session_rx_queues: HashMap<u64, QuicDatagramQueue>,
}

impl WebTransportDatagramEngine {
    pub fn new(
        max_datagram_size: usize,
        session_capacity: usize,
        drop_policy: DatagramDropPolicy,
    ) -> Self {
        Self {
            max_datagram_size,
            session_capacity,
            drop_policy,
            tx_queue: QuicDatagramQueue::new(session_capacity * 4, max_datagram_size, drop_policy),
            session_rx_queues: HashMap::new(),
        }
    }

    /// Sends an unreliable WebTransport datagram for a specific session ID (RFC 9297 Section 3).
    pub fn send_session_datagram(
        &mut self,
        session_id: u64,
        payload: Vec<u8>,
    ) -> Result<(), DatagramQueueError> {
        let wt_dgram = WebTransportDatagram::new(session_id, payload);
        let serialized = wt_dgram.serialize();
        self.tx_queue.push(serialized)
    }

    /// Pulls an outgoing QUIC DATAGRAM frame (0x30 or 0x31) to send across the network.
    pub fn create_outgoing_frame(&mut self, has_length: bool) -> Option<QuicDatagramFrame> {
        let payload = self.tx_queue.pop()?;
        Some(QuicDatagramFrame::new(payload, has_length))
    }

    /// Processes an incoming raw QUIC DATAGRAM frame, demultiplexing it into the session queue.
    pub fn receive_and_demux(
        &mut self,
        frame: &QuicDatagramFrame,
    ) -> Result<WebTransportDatagram, QuicError> {
        let wt = WebTransportDatagram::parse(&frame.payload)?;
        let queue = self
            .session_rx_queues
            .entry(wt.session_id)
            .or_insert_with(|| {
                QuicDatagramQueue::new(
                    self.session_capacity,
                    self.max_datagram_size,
                    self.drop_policy,
                )
            });
        let _ = queue.push(wt.payload.clone());
        Ok(wt)
    }

    /// Pops a demultiplexed payload for a specific WebTransport session.
    pub fn pop_session_datagram(&mut self, session_id: u64) -> Option<Vec<u8>> {
        self.session_rx_queues.get_mut(&session_id)?.pop()
    }

    /// Returns the number of queued datagrams for a session.
    pub fn session_queue_len(&self, session_id: u64) -> usize {
        self.session_rx_queues
            .get(&session_id)
            .map(|q| q.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quic_datagram_frame_codec() {
        // Frame with explicit length
        let original_payload = b"unreliable real-time audio sample";
        let frame = QuicDatagramFrame::new(original_payload.to_vec(), true);
        let serialized = frame.serialize();

        let (parsed, consumed) = QuicDatagramFrame::parse(&serialized).unwrap();
        assert_eq!(consumed, serialized.len());
        assert!(parsed.has_length);
        assert_eq!(parsed.payload, original_payload);

        // Frame with implicit length (no length field)
        let frame_no_len = QuicDatagramFrame::new(b"end-of-packet datagram".to_vec(), false);
        let ser_no_len = frame_no_len.serialize();
        let (parsed_no_len, consumed_no_len) = QuicDatagramFrame::parse(&ser_no_len).unwrap();
        assert_eq!(consumed_no_len, ser_no_len.len());
        assert!(!parsed_no_len.has_length);
        assert_eq!(parsed_no_len.payload, b"end-of-packet datagram");
    }

    #[test]
    fn test_webtransport_datagram_codec() {
        let wt = WebTransportDatagram::new(42, b"game position x=10 y=20".to_vec());
        let ser = wt.serialize();
        let parsed = WebTransportDatagram::parse(&ser).unwrap();

        assert_eq!(parsed.session_id, 42);
        assert_eq!(parsed.payload, b"game position x=10 y=20");
    }

    #[test]
    fn test_quic_datagram_queue_drop_policies() {
        // Drop Oldest
        let mut q_oldest = QuicDatagramQueue::new(2, 1200, DatagramDropPolicy::DropOldest);
        q_oldest.push(b"first".to_vec()).unwrap();
        q_oldest.push(b"second".to_vec()).unwrap();
        q_oldest.push(b"third".to_vec()).unwrap(); // pushes out "first"

        assert_eq!(q_oldest.len(), 2);
        assert_eq!(q_oldest.stats.dropped, 1);
        assert_eq!(q_oldest.pop().unwrap(), b"second");
        assert_eq!(q_oldest.pop().unwrap(), b"third");

        // Drop Newest
        let mut q_newest = QuicDatagramQueue::new(2, 1200, DatagramDropPolicy::DropNewest);
        q_newest.push(b"first".to_vec()).unwrap();
        q_newest.push(b"second".to_vec()).unwrap();
        let err = q_newest.push(b"third".to_vec()).unwrap_err();
        assert_eq!(err, DatagramQueueError::QueueFull);
        assert_eq!(q_newest.stats.dropped, 1);
        assert_eq!(q_newest.pop().unwrap(), b"first");
    }
}
