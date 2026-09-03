//! Application Socket Layer (Layer 4 Socket Runtime & API).
//!
//! Provides application-facing UDP and TCP socket abstractions:
//! - UDP Sockets: `udp_bind`, `send_to`, `recv_from`, ephemeral port allocation, rx queues.
//! - TCP Listeners: `tcp_listen`, `tcp_accept`, multi-connection accept queues.
//! - TCP Streams: `tcp_connect`, `tcp_write`, `tcp_read`, `tcp_shutdown`, `tcp_close`.
//! - Ephemeral port management (49152..65535) and bind conflict resolution.
//! - Full integration with the underlying deterministic transport engine.
//!
//! The runtime owns every byte it puts on the wire: application code calls `tcp_write`
//! or `udp_send_to` and the runtime queues the resulting transport PDUs, which the
//! `NetStack` then encapsulates in IPv4 and Ethernet. Applications never construct
//! segments, datagrams, packets, or frames themselves.

use crate::congestion::CongestionState;
use crate::ipv4::{IP_PROTO_TCP, IP_PROTO_UDP, Ipv4Address};
use crate::tcp::{SocketAddrV4, TcpConnection, TcpConnectionKey, TcpSegment, TcpState, TcpStats};
use crate::udp::UdpDatagram;
use std::collections::{HashMap, VecDeque};
use std::fmt;

/// Upper bound on finished streams kept for post-mortem `tcp_read` / `tcp_stats` calls.
/// Beyond this the oldest are evicted, so connection history cannot grow without limit.
pub const MAX_CLOSED_STREAM_HISTORY: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UdpSocketHandle(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpListenerHandle(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpStreamHandle(pub u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketError {
    AddressInUse,
    AddressNotAvailable,
    NotConnected,
    ConnectionRefused,
    ConnectionReset,
    ConnectionAborted,
    TimedOut,
    InvalidSocket,
    WouldBlock,
    BufferOverflow,
    InvalidInput(String),
}

impl fmt::Display for SocketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketError::AddressInUse => write!(f, "Address already in use (EADDRINUSE)"),
            SocketError::AddressNotAvailable => {
                write!(f, "Address not available (EADDRNOTAVAIL)")
            }
            SocketError::NotConnected => write!(f, "Socket is not connected (ENOTCONN)"),
            SocketError::ConnectionRefused => write!(f, "Connection refused (ECONNREFUSED)"),
            SocketError::ConnectionReset => write!(f, "Connection reset by peer (ECONNRESET)"),
            SocketError::ConnectionAborted => write!(f, "Connection aborted (ECONNABORTED)"),
            SocketError::TimedOut => write!(f, "Operation timed out (ETIMEDOUT)"),
            SocketError::InvalidSocket => write!(f, "Invalid socket descriptor (EBADF)"),
            SocketError::WouldBlock => write!(f, "Resource temporarily unavailable (EWOULDBLOCK)"),
            SocketError::BufferOverflow => write!(f, "Buffer capacity overflow"),
            SocketError::InvalidInput(msg) => write!(f, "Invalid argument: {}", msg),
        }
    }
}

impl std::error::Error for SocketError {}

/// Internal UDP Socket representation
#[derive(Debug)]
pub struct UdpSocketEntry {
    pub handle: UdpSocketHandle,
    pub local_addr: SocketAddrV4,
    pub rx_queue: VecDeque<(Vec<u8>, SocketAddrV4)>,
}

/// Internal TCP Listener representation
#[derive(Debug)]
pub struct TcpListenerEntry {
    pub handle: TcpListenerHandle,
    pub local_addr: SocketAddrV4,
    pub backlog: usize,
    pub next_isn: u32,
    pub accept_queue: VecDeque<TcpStreamHandle>,
}

/// Internal TCP Stream representation
#[derive(Debug)]
pub struct TcpStreamEntry {
    pub handle: TcpStreamHandle,
    pub connection_key: TcpConnectionKey,
}

/// Standard Socket Options for TCP streams (RFC 9293 / POSIX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSocketOptions {
    pub nodelay: bool,
    pub keepalive: bool,
    pub nonblocking: bool,
    pub read_timeout_ms: Option<u64>,
    pub write_timeout_ms: Option<u64>,
}

impl Default for TcpSocketOptions {
    fn default() -> Self {
        TcpSocketOptions {
            nodelay: false,
            keepalive: false,
            nonblocking: false,
            read_timeout_ms: None,
            write_timeout_ms: None,
        }
    }
}

/// Standard Socket Options for UDP sockets (POSIX).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketOptions {
    pub broadcast: bool,
    pub nonblocking: bool,
    pub multicast_ttl: u8,
    pub multicast_loopback: bool,
}

impl Default for UdpSocketOptions {
    fn default() -> Self {
        UdpSocketOptions {
            broadcast: false,
            nonblocking: false,
            multicast_ttl: 1,
            multicast_loopback: true,
        }
    }
}

/// One transport PDU handed up from the socket runtime for IPv4 encapsulation.
#[derive(Debug, Clone)]
pub struct SocketTx {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    /// IPv4 protocol number (`IP_PROTO_TCP` or `IP_PROTO_UDP`).
    pub protocol: u8,
    /// Fully serialized transport PDU including its header and checksum.
    pub payload: Vec<u8>,
}

/// Per-connection diagnostic snapshot. Values are copied out of the owning connection, so
/// callers observe transport telemetry without any globally mutable state.
#[derive(Debug, Clone)]
pub struct TcpDiagnostics {
    pub local: SocketAddrV4,
    pub remote: SocketAddrV4,
    pub state: TcpState,
    pub stats: TcpStats,
    pub cwnd: u32,
    pub ssthresh: u32,
    pub congestion_state: CongestionState,
    pub bytes_in_flight: u32,
    pub srtt_ms: Option<f64>,
    pub rttvar_ms: Option<f64>,
    pub rto_ms: f64,
    pub send_window: u16,
    pub receive_window: u16,
    pub unacked_segments: usize,
    pub ooo_bytes: usize,
    pub tx_pending: usize,
    pub rx_pending: usize,
}

impl fmt::Display for TcpDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} -> {}  [{}]", self.local, self.remote, self.state)?;
        writeln!(
            f,
            "  bytes    sent={} recv={}   segments sent={} recv={}",
            self.stats.bytes_sent,
            self.stats.bytes_received,
            self.stats.segments_sent,
            self.stats.segments_received
        )?;
        writeln!(
            f,
            "  recovery retransmits={} (fast={}) timeouts={} dup-acks={}",
            self.stats.retransmissions,
            self.stats.fast_retransmits,
            self.stats.timeouts,
            self.stats.duplicate_acks
        )?;
        writeln!(
            f,
            "  window   cwnd={}B ssthresh={}B [{}] in-flight={}B",
            self.cwnd, self.ssthresh, self.congestion_state, self.bytes_in_flight
        )?;
        writeln!(
            f,
            "  rtt      srtt={} rttvar={} rto={:.0}ms",
            self.srtt_ms
                .map(|v| format!("{:.1}ms", v))
                .unwrap_or_else(|| "n/a".to_string()),
            self.rttvar_ms
                .map(|v| format!("{:.1}ms", v))
                .unwrap_or_else(|| "n/a".to_string()),
            self.rto_ms
        )?;
        write!(
            f,
            "  buffers  snd_wnd={}B rcv_wnd={}B unacked={} ooo={}B tx-pending={}B rx-pending={}B",
            self.send_window,
            self.receive_window,
            self.unacked_segments,
            self.ooo_bytes,
            self.tx_pending,
            self.rx_pending
        )
    }
}

/// Central Socket Runtime managing transport endpoint tables, port allocation,
/// timer advancement, and packet dispatching.
pub struct SocketRuntime {
    pub default_ip: Ipv4Address,
    pub next_socket_id: u32,
    pub next_ephemeral_port: u16,
    pub udp_sockets: HashMap<UdpSocketHandle, UdpSocketEntry>,
    pub udp_port_map: HashMap<u16, UdpSocketHandle>,
    pub tcp_listeners: HashMap<TcpListenerHandle, TcpListenerEntry>,
    pub tcp_listener_ports: HashMap<u16, TcpListenerHandle>,
    pub tcp_streams: HashMap<TcpStreamHandle, TcpStreamEntry>,
    pub tcp_connections: HashMap<TcpConnectionKey, (TcpStreamHandle, TcpConnection)>,
    pub current_time_ms: u64,
    /// Transport PDUs produced by the runtime and awaiting IPv4/Ethernet encapsulation.
    tcp_tx: VecDeque<(SocketAddrV4, SocketAddrV4, Vec<u8>)>,
    udp_tx: VecDeque<(SocketAddrV4, SocketAddrV4, Vec<u8>)>,
    /// Streams whose connection has been reaped, retained so `tcp_read` can still report
    /// their final state and any bytes that arrived before teardown.
    closed_streams: HashMap<TcpStreamHandle, (TcpState, TcpStats, Vec<u8>)>,
    /// Insertion order of `closed_streams`, used to evict the oldest entries so a long-lived
    /// host that opens many connections does not accumulate them without bound.
    closed_order: VecDeque<TcpStreamHandle>,
    /// MSS advertised by newly created connections on this host.
    pub default_mss: u16,
    /// Rolling initial-sequence-number source for actively opened connections.
    isn_counter: u32,
    pub tcp_options: HashMap<TcpStreamHandle, TcpSocketOptions>,
    pub udp_options: HashMap<UdpSocketHandle, UdpSocketOptions>,
}

impl SocketRuntime {
    pub fn new(default_ip: Ipv4Address) -> Self {
        SocketRuntime {
            default_ip,
            next_socket_id: 1,
            next_ephemeral_port: 49152,
            udp_sockets: HashMap::new(),
            udp_port_map: HashMap::new(),
            tcp_listeners: HashMap::new(),
            tcp_listener_ports: HashMap::new(),
            tcp_streams: HashMap::new(),
            tcp_connections: HashMap::new(),
            current_time_ms: 0,
            tcp_tx: VecDeque::new(),
            udp_tx: VecDeque::new(),
            closed_streams: HashMap::new(),
            closed_order: VecDeque::new(),
            default_mss: 1460,
            isn_counter: 1_000,
            tcp_options: HashMap::new(),
            udp_options: HashMap::new(),
        }
    }

    /// Sets the MSS advertised by connections created after this call. Used by the lab to
    /// force multi-segment transfers over a small effective path MTU.
    pub fn set_default_mss(&mut self, mss: u16) {
        self.default_mss = mss.clamp(88, 1460);
    }

    fn next_id(&mut self) -> u32 {
        let id = self.next_socket_id;
        self.next_socket_id = self.next_socket_id.wrapping_add(1);
        id
    }

    /// Allocates an unused ephemeral port in the range 49152..=65535.
    pub fn allocate_ephemeral_port(&mut self) -> Result<u16, SocketError> {
        let start = self.next_ephemeral_port;
        loop {
            let port = self.next_ephemeral_port;
            if self.next_ephemeral_port == 65535 {
                self.next_ephemeral_port = 49152;
            } else {
                self.next_ephemeral_port += 1;
            }

            let udp_used = self.udp_port_map.contains_key(&port);
            let tcp_listen_used = self.tcp_listener_ports.contains_key(&port);
            let tcp_conn_used = self.tcp_connections.keys().any(|k| k.local.port == port);

            if !udp_used && !tcp_listen_used && !tcp_conn_used {
                return Ok(port);
            }

            if self.next_ephemeral_port == start {
                return Err(SocketError::AddressNotAvailable);
            }
        }
    }

    // ==========================================
    // UDP Socket API
    // ==========================================

    pub fn udp_bind(
        &mut self,
        mut local_addr: SocketAddrV4,
    ) -> Result<UdpSocketHandle, SocketError> {
        if local_addr.ip.is_unspecified() {
            local_addr.ip = self.default_ip;
        }

        if local_addr.port == 0 {
            local_addr.port = self.allocate_ephemeral_port()?;
        } else if self.udp_port_map.contains_key(&local_addr.port) {
            return Err(SocketError::AddressInUse);
        }

        let handle = UdpSocketHandle(self.next_id());
        let entry = UdpSocketEntry {
            handle,
            local_addr,
            rx_queue: VecDeque::new(),
        };

        self.udp_port_map.insert(local_addr.port, handle);
        self.udp_sockets.insert(handle, entry);

        Ok(handle)
    }

    /// Queues a datagram for transmission. The runtime builds the UDP header and checksum;
    /// the `NetStack` supplies IPv4 and Ethernet encapsulation on the way out.
    pub fn udp_send_to(
        &mut self,
        handle: UdpSocketHandle,
        data: &[u8],
        remote_addr: SocketAddrV4,
    ) -> Result<usize, SocketError> {
        let entry = self
            .udp_sockets
            .get(&handle)
            .ok_or(SocketError::InvalidSocket)?;
        let local_addr = entry.local_addr;

        if data.len() > 65_507 {
            return Err(SocketError::InvalidInput(
                "datagram exceeds maximum UDP payload".to_string(),
            ));
        }

        let datagram = UdpDatagram::serialize(
            local_addr.ip,
            remote_addr.ip,
            local_addr.port,
            remote_addr.port,
            data,
        );
        self.udp_tx.push_back((local_addr, remote_addr, datagram));
        Ok(data.len())
    }

    pub fn udp_recv_from(
        &mut self,
        handle: UdpSocketHandle,
    ) -> Result<(Vec<u8>, SocketAddrV4), SocketError> {
        let entry = self
            .udp_sockets
            .get_mut(&handle)
            .ok_or(SocketError::InvalidSocket)?;
        entry.rx_queue.pop_front().ok_or(SocketError::WouldBlock)
    }

    pub fn udp_close(&mut self, handle: UdpSocketHandle) -> Result<(), SocketError> {
        if let Some(entry) = self.udp_sockets.remove(&handle) {
            self.udp_port_map.remove(&entry.local_addr.port);
            self.udp_options.remove(&handle);
            Ok(())
        } else {
            Err(SocketError::InvalidSocket)
        }
    }

    // ==========================================
    // TCP Listener API
    // ==========================================

    pub fn tcp_listen(
        &mut self,
        mut local_addr: SocketAddrV4,
    ) -> Result<TcpListenerHandle, SocketError> {
        if local_addr.ip.is_unspecified() {
            local_addr.ip = self.default_ip;
        }

        if local_addr.port == 0 {
            local_addr.port = self.allocate_ephemeral_port()?;
        } else if self.tcp_listener_ports.contains_key(&local_addr.port) {
            return Err(SocketError::AddressInUse);
        }

        let handle = TcpListenerHandle(self.next_id());
        let entry = TcpListenerEntry {
            handle,
            local_addr,
            backlog: 128,
            next_isn: 1000,
            accept_queue: VecDeque::new(),
        };

        self.tcp_listener_ports.insert(local_addr.port, handle);
        self.tcp_listeners.insert(handle, entry);

        Ok(handle)
    }

    /// Listens on every local address (`0.0.0.0:port`).
    ///
    /// A multi-interface node such as a router cannot know in advance which of its
    /// addresses a peer will connect to, so a wildcard bind is the only correct one.
    /// `dispatch_tcp_segment` builds each accepted connection from the segment's actual
    /// destination address, so the resulting connections are still per-interface.
    pub fn tcp_listen_any(&mut self, port: u16) -> Result<TcpListenerHandle, SocketError> {
        if port == 0 {
            return Err(SocketError::InvalidInput(
                "wildcard listen requires an explicit port".to_string(),
            ));
        }
        if self.tcp_listener_ports.contains_key(&port) {
            return Err(SocketError::AddressInUse);
        }

        let local_addr = SocketAddrV4 {
            ip: Ipv4Address::UNSPECIFIED,
            port,
        };
        let handle = TcpListenerHandle(self.next_id());
        let entry = TcpListenerEntry {
            handle,
            local_addr,
            backlog: 128,
            next_isn: 1000,
            accept_queue: VecDeque::new(),
        };

        self.tcp_listener_ports.insert(port, handle);
        self.tcp_listeners.insert(handle, entry);

        Ok(handle)
    }

    pub fn tcp_accept(
        &mut self,
        listener_handle: TcpListenerHandle,
    ) -> Result<(TcpStreamHandle, SocketAddrV4), SocketError> {
        let listener = self
            .tcp_listeners
            .get_mut(&listener_handle)
            .ok_or(SocketError::InvalidSocket)?;

        while let Some(stream_handle) = listener.accept_queue.pop_front() {
            if let Some(stream) = self.tcp_streams.get(&stream_handle) {
                let remote_addr = stream.connection_key.remote;
                return Ok((stream_handle, remote_addr));
            }
        }

        Err(SocketError::WouldBlock)
    }

    /// Stops listening, releases the port, and abandons any connections still sitting in
    /// the backlog so they do not linger unreachable in the connection table.
    pub fn tcp_listener_close(&mut self, handle: TcpListenerHandle) -> Result<(), SocketError> {
        let Some(entry) = self.tcp_listeners.remove(&handle) else {
            return Err(SocketError::InvalidSocket);
        };
        self.tcp_listener_ports.remove(&entry.local_addr.port);

        for pending in entry.accept_queue {
            if let Some(key) = self.tcp_streams.get(&pending).map(|s| s.connection_key) {
                self.tcp_connections.remove(&key);
            }
            self.tcp_streams.remove(&pending);
        }
        Ok(())
    }

    // ==========================================
    // TCP Stream API
    // ==========================================

    /// Opens an active connection from an automatically allocated ephemeral port.
    /// The SYN is queued internally; the caller never sees or forwards raw bytes.
    pub fn tcp_connect(
        &mut self,
        remote_addr: SocketAddrV4,
    ) -> Result<TcpStreamHandle, SocketError> {
        let local_port = self.allocate_ephemeral_port()?;
        let local_addr = SocketAddrV4 {
            ip: self.default_ip,
            port: local_port,
        };
        let isn = self.next_isn();
        self.tcp_connect_from(local_addr, remote_addr, isn)
    }

    /// Derives a per-connection initial sequence number. Deterministic so simulations stay
    /// reproducible, but distinct per connection so old segments cannot be misattributed.
    fn next_isn(&mut self) -> u32 {
        self.isn_counter = self.isn_counter.wrapping_add(64_000);
        self.isn_counter
    }

    pub fn tcp_connect_from(
        &mut self,
        local_addr: SocketAddrV4,
        remote_addr: SocketAddrV4,
        isn: u32,
    ) -> Result<TcpStreamHandle, SocketError> {
        let mut local_addr = local_addr;
        if local_addr.ip.is_unspecified() {
            local_addr.ip = self.default_ip;
        }
        if local_addr.port == 0 {
            local_addr.port = self.allocate_ephemeral_port()?;
        }

        let key = TcpConnectionKey {
            local: local_addr,
            remote: remote_addr,
        };

        if self.tcp_connections.contains_key(&key) {
            return Err(SocketError::AddressInUse);
        }

        let handle = TcpStreamHandle(self.next_id());
        let mut conn = TcpConnection::new_client(local_addr, remote_addr, isn);
        conn.local_mss = self.default_mss;
        conn.congestion.mss = self.default_mss as u32;
        let syn_packet = conn.initiate_syn_at(self.current_time_ms);

        self.tcp_connections.insert(key, (handle, conn));
        self.tcp_streams.insert(
            handle,
            TcpStreamEntry {
                handle,
                connection_key: key,
            },
        );
        self.tcp_tx.push_back((local_addr, remote_addr, syn_packet));

        Ok(handle)
    }

    pub fn tcp_write(
        &mut self,
        handle: TcpStreamHandle,
        data: &[u8],
    ) -> Result<usize, SocketError> {
        let stream = self
            .tcp_streams
            .get(&handle)
            .ok_or(SocketError::InvalidSocket)?;
        let key = stream.connection_key;
        let (_, conn) = self
            .tcp_connections
            .get_mut(&key)
            .ok_or(SocketError::InvalidSocket)?;

        if !matches!(conn.state, TcpState::Established | TcpState::CloseWait) {
            return Err(SocketError::NotConnected);
        }
        if conn.close_requested {
            return Err(SocketError::NotConnected);
        }

        let accepted = conn.write(data);
        if accepted == 0 && !data.is_empty() {
            // The send buffer is full; the caller should retry once the network drains.
            return Err(SocketError::WouldBlock);
        }
        Ok(accepted)
    }

    /// Unused send-buffer capacity on a stream, in bytes.
    pub fn tcp_writable(&self, handle: TcpStreamHandle) -> usize {
        let Ok(key) = self.key_of(handle) else {
            return 0;
        };
        self.tcp_connections
            .get(&key)
            .map(|(_, c)| c.send_buffer_available())
            .unwrap_or(0)
    }

    /// Drains received stream bytes. Returns `Ok(0)` at end of stream (the peer's FIN has
    /// been received and all data delivered) and `WouldBlock` when nothing is available yet.
    pub fn tcp_read(
        &mut self,
        handle: TcpStreamHandle,
        buf: &mut [u8],
    ) -> Result<usize, SocketError> {
        let key = self.key_of(handle)?;

        // The connection may already have been reaped; its residual data is still readable.
        if !self.tcp_connections.contains_key(&key) {
            if let Some((_, _, residual)) = self.closed_streams.get_mut(&handle) {
                if residual.is_empty() {
                    return Ok(0);
                }
                let n = buf.len().min(residual.len());
                buf[..n].copy_from_slice(&residual[..n]);
                residual.drain(..n);
                return Ok(n);
            }
            return Err(SocketError::InvalidSocket);
        }

        let (_, conn) = self.tcp_connections.get_mut(&key).unwrap();
        let n = conn.read(buf);
        if n > 0 {
            return Ok(n);
        }
        if conn.aborted {
            return Err(SocketError::ConnectionReset);
        }
        if conn.fin_received
            || matches!(
                conn.state,
                TcpState::Closed | TcpState::TimeWait | TcpState::LastAck | TcpState::CloseWait
            )
        {
            Ok(0) // EOF
        } else {
            Err(SocketError::WouldBlock)
        }
    }

    /// Bytes currently readable on a stream without blocking.
    pub fn tcp_readable(&self, handle: TcpStreamHandle) -> usize {
        let Ok(key) = self.key_of(handle) else {
            return 0;
        };
        if let Some((_, conn)) = self.tcp_connections.get(&key) {
            conn.rx_buffer.len()
        } else {
            self.closed_streams
                .get(&handle)
                .map(|(_, _, r)| r.len())
                .unwrap_or(0)
        }
    }

    /// Half-closes the sending direction. Any FIN produced is queued for transmission;
    /// if application data is still buffered the FIN follows it automatically.
    pub fn tcp_shutdown(&mut self, handle: TcpStreamHandle) -> Result<(), SocketError> {
        let key = self.key_of(handle)?;
        let now = self.current_time_ms;
        let (_, conn) = self
            .tcp_connections
            .get_mut(&key)
            .ok_or(SocketError::NotConnected)?;

        if let Some(fin) = conn.initiate_close_at(now) {
            self.tcp_tx.push_back((key.local, key.remote, fin));
        }
        Ok(())
    }

    /// Closes the stream. Equivalent to `tcp_shutdown` here: the connection is torn down
    /// gracefully and its resources are reclaimed once TIME_WAIT expires.
    pub fn tcp_close(&mut self, handle: TcpStreamHandle) -> Result<(), SocketError> {
        self.tcp_shutdown(handle)
    }

    /// Aborts a connection immediately and releases the handle.
    ///
    /// Anything still in the send buffer is flushed first, because a protocol that has
    /// just written a shutdown message needs it to reach the peer, and then the
    /// connection is removed and a RST is queued.
    ///
    /// This is what `tcp_close` cannot do. A graceful close is a no-op on a connection
    /// that never finished its handshake: `initiate_close_at` only acts in ESTABLISHED
    /// or CLOSE_WAIT, so a SYN_SENT connection would stay in the table retransmitting
    /// forever once its handle was released. A long-lived session that reconnects on a
    /// timer would accumulate one such connection per attempt. Aborting reclaims the
    /// 4-tuple and the ephemeral port there and then.
    pub fn tcp_abort(&mut self, handle: TcpStreamHandle, now_ms: u64) {
        let Ok(key) = self.key_of(handle) else {
            self.tcp_release(handle);
            return;
        };

        if let Some((_, mut conn)) = self.tcp_connections.remove(&key) {
            for payload in conn.poll_output(now_ms) {
                self.tcp_tx.push_back((key.local, key.remote, payload));
            }
            // Tell a peer that may still hold state for this 4-tuple to drop it. There is
            // nothing to reset if the connection never left CLOSED.
            if !conn.aborted && conn.state != TcpState::Closed {
                let mut flags = crate::tcp::TcpFlags::rst();
                flags.ack = true;
                let rst = TcpSegment::serialize(
                    key.local.ip,
                    key.remote.ip,
                    key.local.port,
                    key.remote.port,
                    conn.snd_nxt,
                    conn.rcv_nxt,
                    flags,
                    0,
                    &[],
                );
                self.tcp_tx.push_back((key.local, key.remote, rst));
            }
        }

        self.tcp_release(handle);
    }

    /// Resolves a stream handle to its 4-tuple.
    fn key_of(&self, handle: TcpStreamHandle) -> Result<TcpConnectionKey, SocketError> {
        self.tcp_streams
            .get(&handle)
            .map(|s| s.connection_key)
            .ok_or(SocketError::InvalidSocket)
    }

    pub fn tcp_state(&self, handle: TcpStreamHandle) -> Result<TcpState, SocketError> {
        let key = self.key_of(handle)?;
        if let Some((_, conn)) = self.tcp_connections.get(&key) {
            return Ok(conn.state);
        }
        self.closed_streams
            .get(&handle)
            .map(|(st, _, _)| *st)
            .ok_or(SocketError::InvalidSocket)
    }

    /// True while the stream still owns a usable connection.
    ///
    /// Goes false as soon as the connection is aborted (retransmission limit reached, so
    /// the peer is unreachable), reaches CLOSED, or has been reaped altogether. Long-lived
    /// protocol sessions poll this to notice a dead transport without inspecting
    /// `TcpConnection` directly.
    pub fn tcp_is_live(&self, handle: TcpStreamHandle) -> bool {
        let Ok(key) = self.key_of(handle) else {
            return false;
        };
        match self.tcp_connections.get(&key) {
            Some((_, conn)) => !conn.aborted && conn.state != TcpState::Closed,
            None => false,
        }
    }

    pub fn tcp_stats(&self, handle: TcpStreamHandle) -> Result<TcpStats, SocketError> {
        let key = self.key_of(handle)?;
        if let Some((_, conn)) = self.tcp_connections.get(&key) {
            return Ok(conn.stats.clone());
        }
        self.closed_streams
            .get(&handle)
            .map(|(_, st, _)| st.clone())
            .ok_or(SocketError::InvalidSocket)
    }

    /// Full diagnostic snapshot of a live connection: state machine, byte and segment
    /// counters, congestion state, RTT estimate, and window occupancy.
    pub fn tcp_diagnostics(&self, handle: TcpStreamHandle) -> Result<TcpDiagnostics, SocketError> {
        let key = self.key_of(handle)?;
        let (_, conn) = self
            .tcp_connections
            .get(&key)
            .ok_or(SocketError::InvalidSocket)?;
        Ok(TcpDiagnostics {
            local: conn.local,
            remote: conn.remote,
            state: conn.state,
            stats: conn.stats.clone(),
            cwnd: conn.congestion.cwnd,
            ssthresh: conn.congestion.ssthresh,
            congestion_state: conn.congestion.state,
            bytes_in_flight: conn.bytes_in_flight(),
            srtt_ms: conn.rtt.srtt,
            rttvar_ms: conn.rtt.rttvar,
            rto_ms: conn.rtt.rto,
            send_window: conn.snd_wnd,
            receive_window: conn.current_rcv_wnd(),
            unacked_segments: conn.retransmit_queue.len(),
            ooo_bytes: conn.ooo_bytes(),
            tx_pending: conn.tx_buffer.len(),
            rx_pending: conn.rx_buffer.len(),
        })
    }

    /// Diagnostics for every live connection, ordered by local then remote address so the
    /// output is stable across runs.
    pub fn all_tcp_diagnostics(&self) -> Vec<TcpDiagnostics> {
        let mut out: Vec<TcpDiagnostics> = self
            .tcp_streams
            .keys()
            .filter_map(|h| self.tcp_diagnostics(*h).ok())
            .collect();
        out.sort_by_key(|d| (d.local.ip.0, d.local.port, d.remote.ip.0, d.remote.port));
        out
    }

    /// Returns the local address of a TCP stream.
    pub fn tcp_local_addr(&self, handle: TcpStreamHandle) -> Result<SocketAddrV4, SocketError> {
        self.key_of(handle).map(|k| k.local)
    }

    /// Returns the remote peer address of a TCP stream.
    pub fn tcp_peer_addr(&self, handle: TcpStreamHandle) -> Result<SocketAddrV4, SocketError> {
        self.key_of(handle).map(|k| k.remote)
    }

    /// Sets TCP_NODELAY option to disable Nagle's algorithm.
    pub fn tcp_set_nodelay(
        &mut self,
        handle: TcpStreamHandle,
        nodelay: bool,
    ) -> Result<(), SocketError> {
        self.key_of(handle)?;
        self.tcp_options.entry(handle).or_default().nodelay = nodelay;
        Ok(())
    }

    /// Reads TCP_NODELAY setting.
    pub fn tcp_nodelay(&self, handle: TcpStreamHandle) -> Result<bool, SocketError> {
        self.key_of(handle)?;
        Ok(self
            .tcp_options
            .get(&handle)
            .map(|o| o.nodelay)
            .unwrap_or(false))
    }

    /// Sets non-blocking I/O mode for a TCP stream.
    pub fn tcp_set_nonblocking(
        &mut self,
        handle: TcpStreamHandle,
        nonblocking: bool,
    ) -> Result<(), SocketError> {
        self.key_of(handle)?;
        self.tcp_options.entry(handle).or_default().nonblocking = nonblocking;
        Ok(())
    }

    /// Reads non-blocking I/O setting.
    pub fn tcp_nonblocking(&self, handle: TcpStreamHandle) -> Result<bool, SocketError> {
        self.key_of(handle)?;
        Ok(self
            .tcp_options
            .get(&handle)
            .map(|o| o.nonblocking)
            .unwrap_or(false))
    }

    /// Sets read timeout in milliseconds for a TCP stream.
    pub fn tcp_set_read_timeout(
        &mut self,
        handle: TcpStreamHandle,
        timeout_ms: Option<u64>,
    ) -> Result<(), SocketError> {
        self.key_of(handle)?;
        self.tcp_options.entry(handle).or_default().read_timeout_ms = timeout_ms;
        Ok(())
    }

    /// Reads read timeout setting.
    pub fn tcp_read_timeout(&self, handle: TcpStreamHandle) -> Result<Option<u64>, SocketError> {
        self.key_of(handle)?;
        Ok(self
            .tcp_options
            .get(&handle)
            .and_then(|o| o.read_timeout_ms))
    }

    /// Returns the bound local address of a UDP socket.
    pub fn udp_local_addr(&self, handle: UdpSocketHandle) -> Result<SocketAddrV4, SocketError> {
        self.udp_sockets
            .get(&handle)
            .map(|s| s.local_addr)
            .ok_or(SocketError::InvalidSocket)
    }

    /// Sets SO_BROADCAST option on a UDP socket.
    pub fn udp_set_broadcast(
        &mut self,
        handle: UdpSocketHandle,
        broadcast: bool,
    ) -> Result<(), SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        self.udp_options.entry(handle).or_default().broadcast = broadcast;
        Ok(())
    }

    /// Reads SO_BROADCAST option.
    pub fn udp_broadcast(&self, handle: UdpSocketHandle) -> Result<bool, SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        Ok(self
            .udp_options
            .get(&handle)
            .map(|o| o.broadcast)
            .unwrap_or(false))
    }

    /// Sets non-blocking mode on a UDP socket.
    pub fn udp_set_nonblocking(
        &mut self,
        handle: UdpSocketHandle,
        nonblocking: bool,
    ) -> Result<(), SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        self.udp_options.entry(handle).or_default().nonblocking = nonblocking;
        Ok(())
    }

    /// Reads non-blocking mode on a UDP socket.
    pub fn udp_nonblocking(&self, handle: UdpSocketHandle) -> Result<bool, SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        Ok(self
            .udp_options
            .get(&handle)
            .map(|o| o.nonblocking)
            .unwrap_or(false))
    }

    /// Sets IP_MULTICAST_TTL on a UDP socket.
    pub fn udp_set_multicast_ttl(
        &mut self,
        handle: UdpSocketHandle,
        ttl: u8,
    ) -> Result<(), SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        self.udp_options.entry(handle).or_default().multicast_ttl = ttl;
        Ok(())
    }

    /// Reads IP_MULTICAST_TTL on a UDP socket.
    pub fn udp_multicast_ttl(&self, handle: UdpSocketHandle) -> Result<u8, SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        Ok(self
            .udp_options
            .get(&handle)
            .map(|o| o.multicast_ttl)
            .unwrap_or(1))
    }

    /// Sets IP_MULTICAST_LOOP on a UDP socket.
    pub fn udp_set_multicast_loop_v4(
        &mut self,
        handle: UdpSocketHandle,
        loopback: bool,
    ) -> Result<(), SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        self.udp_options
            .entry(handle)
            .or_default()
            .multicast_loopback = loopback;
        Ok(())
    }

    /// Reads IP_MULTICAST_LOOP on a UDP socket.
    pub fn udp_multicast_loop_v4(&self, handle: UdpSocketHandle) -> Result<bool, SocketError> {
        if !self.udp_sockets.contains_key(&handle) {
            return Err(SocketError::InvalidSocket);
        }
        Ok(self
            .udp_options
            .get(&handle)
            .map(|o| o.multicast_loopback)
            .unwrap_or(true))
    }

    pub fn get_tcp_connection(&self, key: &TcpConnectionKey) -> Option<&TcpConnection> {
        self.tcp_connections.get(key).map(|(_, c)| c)
    }

    pub fn get_tcp_connection_mut(&mut self, key: &TcpConnectionKey) -> Option<&mut TcpConnection> {
        self.tcp_connections.get_mut(key).map(|(_, c)| c)
    }

    pub fn has_endpoint(
        &self,
        local_ip: Ipv4Address,
        local_port: u16,
        remote_ip: Ipv4Address,
        remote_port: u16,
    ) -> bool {
        let key = TcpConnectionKey {
            local: SocketAddrV4 {
                ip: local_ip,
                port: local_port,
            },
            remote: SocketAddrV4 {
                ip: remote_ip,
                port: remote_port,
            },
        };
        if self.tcp_connections.contains_key(&key) {
            return true;
        }
        // A listener also owns the port, but only for addresses this host actually holds:
        // matching on the port alone would claim traffic addressed elsewhere.
        self.tcp_listener_ports
            .get(&local_port)
            .and_then(|h| self.tcp_listeners.get(h))
            .is_some_and(|l| l.local_addr.ip == local_ip || l.local_addr.ip.is_unspecified())
    }

    // ==========================================
    // Inbound Packet Processing & Timers
    // ==========================================

    pub fn dispatch_udp(&mut self, src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> bool {
        if let Some(&handle) = self.udp_port_map.get(&dst.port)
            && let Some(sock) = self.udp_sockets.get_mut(&handle)
        {
            sock.rx_queue.push_back((payload.to_vec(), src));
            return true;
        }
        false
    }

    /// Feeds an inbound TCP segment to the owning connection, a matching listener, or the
    /// RST path when nothing is listening. Returns the segments to transmit in reply.
    pub fn dispatch_tcp_segment(
        &mut self,
        src_ip: Ipv4Address,
        dst_ip: Ipv4Address,
        seg: &TcpSegment<'_>,
        now_ms: u64,
    ) -> Vec<Vec<u8>> {
        self.current_time_ms = now_ms;
        let key = TcpConnectionKey {
            local: SocketAddrV4 {
                ip: dst_ip,
                port: seg.dst_port,
            },
            remote: SocketAddrV4 {
                ip: src_ip,
                port: seg.src_port,
            },
        };

        // 1. An existing connection owns this 4-tuple.
        if let Some((_, conn)) = self.tcp_connections.get_mut(&key) {
            let mut out = Vec::new();
            if let Some(reply) = conn.handle_segment_at(seg, now_ms) {
                out.push(reply);
            }
            // Pump anything the state change just unblocked (data, a deferred FIN).
            out.extend(conn.poll_output(now_ms));
            return out;
        }

        // 2. A listener accepts an inbound SYN, creating a new connection for this 4-tuple.
        //    Several clients may share one listening port; they are kept apart by 4-tuple.
        if seg.flags.syn
            && !seg.flags.ack
            && let Some(&listener_handle) = self.tcp_listener_ports.get(&seg.dst_port)
        {
            let backlog_full = self
                .tcp_listeners
                .get(&listener_handle)
                .map(|l| l.accept_queue.len() >= l.backlog)
                .unwrap_or(true);
            if backlog_full {
                // Backlog exhausted: drop the SYN and let the peer retransmit.
                return Vec::new();
            }

            let isn = {
                let listener = self.tcp_listeners.get_mut(&listener_handle).unwrap();
                let isn = listener.next_isn;
                listener.next_isn = listener.next_isn.wrapping_add(64_000);
                isn
            };

            let mut conn = TcpConnection::new_server(key.local, key.remote, isn);
            conn.local_mss = self.default_mss;
            conn.congestion.mss = self.default_mss as u32;
            let resp = conn.handle_segment_at(seg, now_ms);

            let stream_handle = TcpStreamHandle(self.next_id());
            self.tcp_streams.insert(
                stream_handle,
                TcpStreamEntry {
                    handle: stream_handle,
                    connection_key: key,
                },
            );
            if let Some(listener) = self.tcp_listeners.get_mut(&listener_handle) {
                listener.accept_queue.push_back(stream_handle);
            }
            self.tcp_connections.insert(key, (stream_handle, conn));

            return resp.into_iter().collect();
        }

        // 3. Nothing owns the destination port: reset the peer (never reset a reset).
        if !seg.flags.rst {
            return vec![Self::build_reset(src_ip, dst_ip, seg)];
        }

        Vec::new()
    }

    /// Builds the RST answering a segment addressed to a port with no endpoint.
    fn build_reset(src_ip: Ipv4Address, dst_ip: Ipv4Address, seg: &TcpSegment<'_>) -> Vec<u8> {
        let rst_seq = if seg.flags.ack { seg.ack_num } else { 0 };
        let rst_ack = seg
            .seq_num
            .wrapping_add(if seg.flags.syn { 1 } else { 0 })
            .wrapping_add(if seg.flags.fin { 1 } else { 0 })
            .wrapping_add(seg.payload.len() as u32);
        let mut flags = crate::tcp::TcpFlags::rst();
        if !seg.flags.ack {
            flags.ack = true;
        }
        TcpSegment::serialize(
            dst_ip,
            src_ip,
            seg.dst_port,
            seg.src_port,
            rst_seq,
            rst_ack,
            flags,
            0,
            &[],
        )
    }

    /// Advances every connection's timers at simulated time `now_ms` and returns all
    /// transport PDUs to transmit: freshly segmented application data, retransmissions,
    /// deferred FINs, zero-window probes, and any queued UDP datagrams.
    ///
    /// This is the single transmission path. Nothing else in the runtime puts bytes on
    /// the wire, and no wall-clock time is consulted anywhere.
    pub fn step_timers(&mut self, now_ms: u64) -> Vec<SocketTx> {
        self.current_time_ms = now_ms;
        let mut outgoing: Vec<SocketTx> = Vec::new();

        for (local, remote, payload) in self.udp_tx.drain(..) {
            outgoing.push(SocketTx {
                local,
                remote,
                protocol: IP_PROTO_UDP,
                payload,
            });
        }
        for (local, remote, payload) in self.tcp_tx.drain(..) {
            outgoing.push(SocketTx {
                local,
                remote,
                protocol: IP_PROTO_TCP,
                payload,
            });
        }

        let mut keys: Vec<TcpConnectionKey> = self.tcp_connections.keys().copied().collect();
        keys.sort_by_key(|k| (k.local.ip.0, k.local.port, k.remote.ip.0, k.remote.port));

        for key in keys {
            if let Some((_, conn)) = self.tcp_connections.get_mut(&key) {
                for payload in conn.poll_output(now_ms) {
                    outgoing.push(SocketTx {
                        local: key.local,
                        remote: key.remote,
                        protocol: IP_PROTO_TCP,
                        payload,
                    });
                }
            }
        }

        self.reap_closed(now_ms);
        outgoing
    }

    /// Reclaims connections that have reached CLOSED or whose TIME_WAIT has expired,
    /// preserving their final state, stats, and undelivered bytes for the owning stream so
    /// neither connection table entries nor ephemeral ports leak.
    fn reap_closed(&mut self, now_ms: u64) {
        let done: Vec<TcpConnectionKey> = self
            .tcp_connections
            .iter()
            .filter(|(_, (_, conn))| conn.is_reapable(now_ms))
            .map(|(k, _)| *k)
            .collect();

        for key in done {
            if let Some((handle, conn)) = self.tcp_connections.remove(&key)
                && self
                    .closed_streams
                    .insert(handle, (conn.state, conn.stats.clone(), conn.rx_buffer))
                    .is_none()
            {
                self.closed_order.push_back(handle);
            }
        }

        // Evict the oldest finished streams once the history exceeds its cap.
        while self.closed_order.len() > MAX_CLOSED_STREAM_HISTORY {
            if let Some(old) = self.closed_order.pop_front() {
                self.closed_streams.remove(&old);
                self.tcp_streams.remove(&old);
            }
        }
    }

    /// Number of live (unreaped) TCP connections.
    pub fn connection_count(&self) -> usize {
        self.tcp_connections.len()
    }

    /// Releases a fully finished stream handle. After this the handle is invalid.
    pub fn tcp_release(&mut self, handle: TcpStreamHandle) {
        self.closed_streams.remove(&handle);
        self.closed_order.retain(|h| *h != handle);
        self.tcp_streams.remove(&handle);
        self.tcp_options.remove(&handle);
    }

    /// Number of finished streams still retained for post-mortem reads.
    pub fn closed_stream_count(&self) -> usize {
        self.closed_streams.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_runtime_udp_flow() {
        let mut runtime = SocketRuntime::new(Ipv4Address::new(192, 168, 1, 10));

        let local_addr = SocketAddrV4 {
            ip: Ipv4Address::new(192, 168, 1, 10),
            port: 9000,
        };
        let handle = runtime.udp_bind(local_addr).unwrap();

        let peer_addr = SocketAddrV4 {
            ip: Ipv4Address::new(192, 168, 1, 20),
            port: 45000,
        };

        // Incoming datagram dispatch
        assert!(runtime.dispatch_udp(peer_addr, local_addr, b"Hello UDP"));

        // Receive from queue
        let (data, sender) = runtime.udp_recv_from(handle).unwrap();
        assert_eq!(data, b"Hello UDP");
        assert_eq!(sender, peer_addr);

        // Conflict check
        assert_eq!(
            runtime.udp_bind(local_addr).unwrap_err(),
            SocketError::AddressInUse
        );
    }

    #[test]
    fn test_tcp_abort_reclaims_a_connection_a_graceful_close_cannot() {
        let client_ip = Ipv4Address::new(10, 0, 0, 1);
        let server_ip = Ipv4Address::new(10, 0, 0, 2);
        let mut rt = SocketRuntime::new(client_ip);

        let stream = rt
            .tcp_connect_from(
                SocketAddrV4 {
                    ip: client_ip,
                    port: 40_000,
                },
                SocketAddrV4 {
                    ip: server_ip,
                    port: 179,
                },
                100,
            )
            .unwrap();
        let _ = rt.step_timers(0);
        assert_eq!(rt.connection_count(), 1);

        // The peer never answers, so the connection is stuck in SYN_SENT. A graceful
        // close does nothing there and releasing the handle would orphan it.
        assert_eq!(rt.tcp_state(stream), Ok(TcpState::SynSent));
        rt.tcp_close(stream).unwrap();
        assert_eq!(
            rt.connection_count(),
            1,
            "a graceful close should be a no-op in SYN_SENT"
        );

        rt.tcp_abort(stream, 10);
        assert_eq!(rt.connection_count(), 0, "abort left the connection behind");
        assert!(!rt.tcp_is_live(stream));
        // The port is free again, so a reconnect loop cannot exhaust the range.
        assert!(
            rt.tcp_connect_from(
                SocketAddrV4 {
                    ip: client_ip,
                    port: 40_000,
                },
                SocketAddrV4 {
                    ip: server_ip,
                    port: 179,
                },
                200,
            )
            .is_ok()
        );
    }

    #[test]
    fn test_tcp_abort_flushes_buffered_data_before_resetting() {
        let client_ip = Ipv4Address::new(10, 0, 0, 1);
        let server_ip = Ipv4Address::new(10, 0, 0, 2);
        let mut client = SocketRuntime::new(client_ip);
        let mut server = SocketRuntime::new(server_ip);

        let srv_addr = SocketAddrV4 {
            ip: server_ip,
            port: 179,
        };
        let listener = server.tcp_listen_any(179).unwrap();
        let cs = client
            .tcp_connect_from(
                SocketAddrV4 {
                    ip: client_ip,
                    port: 40_000,
                },
                srv_addr,
                100,
            )
            .unwrap();

        // Three-way handshake.
        let syn = client.step_timers(0).remove(0).payload;
        let seg = TcpSegment::parse(client_ip, server_ip, &syn, true).unwrap();
        let syn_ack = server
            .dispatch_tcp_segment(client_ip, server_ip, &seg, 1)
            .remove(0);
        let seg = TcpSegment::parse(server_ip, client_ip, &syn_ack, true).unwrap();
        let ack = client
            .dispatch_tcp_segment(server_ip, client_ip, &seg, 2)
            .remove(0);
        let seg = TcpSegment::parse(client_ip, server_ip, &ack, true).unwrap();
        let _ = server.dispatch_tcp_segment(client_ip, server_ip, &seg, 3);
        let (ss, _) = server.tcp_accept(listener).unwrap();
        assert_eq!(client.tcp_state(cs), Ok(TcpState::Established));

        // A last message, then an immediate abort. The message must still go out, ahead
        // of the RST, because that is how a NOTIFICATION reaches its peer.
        client.tcp_write(cs, b"FINAL-WORD").unwrap();
        client.tcp_abort(cs, 4);

        let out = client.step_timers(5);
        assert!(out.len() >= 2, "expected the data and then a reset");
        let data = TcpSegment::parse(client_ip, server_ip, &out[0].payload, true).unwrap();
        assert_eq!(data.payload, b"FINAL-WORD");
        assert!(!data.flags.rst);
        let rst = TcpSegment::parse(client_ip, server_ip, &out[1].payload, true).unwrap();
        assert!(rst.flags.rst, "no RST followed the flushed data");

        // The server sees the data, then the reset.
        let _ = server.dispatch_tcp_segment(client_ip, server_ip, &data, 6);
        let mut buf = [0u8; 32];
        assert_eq!(server.tcp_read(ss, &mut buf), Ok(10));
        assert_eq!(&buf[..10], b"FINAL-WORD");
        let _ = server.dispatch_tcp_segment(client_ip, server_ip, &rst, 7);
        assert_eq!(client.connection_count(), 0);
    }

    #[test]
    fn test_wildcard_listener_accepts_on_any_local_address() {
        let mut rt = SocketRuntime::new(Ipv4Address::new(10, 0, 0, 1));
        rt.tcp_listen_any(179).unwrap();

        // A multi-interface node must answer on an address that is not its default one.
        assert!(rt.has_endpoint(
            Ipv4Address::new(192, 168, 5, 1),
            179,
            Ipv4Address::new(192, 168, 5, 2),
            50_000
        ));
        assert!(!rt.has_endpoint(
            Ipv4Address::new(192, 168, 5, 1),
            180,
            Ipv4Address::new(192, 168, 5, 2),
            50_000
        ));
        assert_eq!(
            rt.tcp_listen_any(179).unwrap_err(),
            SocketError::AddressInUse
        );
        assert!(rt.tcp_listen_any(0).is_err());
    }

    #[test]
    fn test_socket_runtime_tcp_connect_and_listen() {
        let client_ip = Ipv4Address::new(10, 0, 0, 1);
        let server_ip = Ipv4Address::new(10, 0, 0, 2);

        let mut client_rt = SocketRuntime::new(client_ip);
        let mut server_rt = SocketRuntime::new(server_ip);

        let srv_listen_addr = SocketAddrV4 {
            ip: server_ip,
            port: 8080,
        };
        let listener = server_rt.tcp_listen(srv_listen_addr).unwrap();

        // 1. Client connects. The SYN is queued inside the runtime; draining the pump is
        //    what the NetStack does before encapsulating in IPv4 and Ethernet.
        let client_stream = client_rt
            .tcp_connect_from(
                SocketAddrV4 {
                    ip: client_ip,
                    port: 50000,
                },
                srv_listen_addr,
                100,
            )
            .unwrap();
        let mut pending = client_rt.step_timers(0);
        assert_eq!(
            pending.len(),
            1,
            "connect should have queued exactly one SYN"
        );
        let syn_raw = pending.remove(0).payload;

        // 2. Server receives SYN -> sends SYN-ACK
        let syn_seg = TcpSegment::parse(client_ip, server_ip, &syn_raw, true).unwrap();
        let mut syn_ack_list = server_rt.dispatch_tcp_segment(client_ip, server_ip, &syn_seg, 10);
        assert_eq!(syn_ack_list.len(), 1);
        let syn_ack_raw = syn_ack_list.remove(0);

        // 3. Server accept queue now holds accepted connection
        let (server_stream, client_peer) = server_rt.tcp_accept(listener).unwrap();
        assert_eq!(client_peer.port, 50000);

        // 4. Client receives SYN-ACK -> sends ACK
        let syn_ack_seg = TcpSegment::parse(server_ip, client_ip, &syn_ack_raw, true).unwrap();
        let mut ack_list = client_rt.dispatch_tcp_segment(server_ip, client_ip, &syn_ack_seg, 20);
        assert_eq!(ack_list.len(), 1);
        let ack_raw = ack_list.remove(0);

        // 5. Server receives ACK
        let ack_seg = TcpSegment::parse(client_ip, server_ip, &ack_raw, true).unwrap();
        let _ = server_rt.dispatch_tcp_segment(client_ip, server_ip, &ack_seg, 30);

        assert_eq!(
            client_rt.tcp_state(client_stream).unwrap(),
            TcpState::Established
        );
        assert_eq!(
            server_rt.tcp_state(server_stream).unwrap(),
            TcpState::Established
        );
    }
}
