//! Socket runtime integration tests.
//!
//! Exercises the application-facing socket API end to end over the deterministic virtual
//! lab: UDP bind / send_to / recv_from with port demultiplexing and ephemeral allocation,
//! and TCP listen / connect / accept / write / read / close with several simultaneous
//! connections sharing one listening port.
//!
//! Every test here drives the real stack. Nothing constructs a packet by hand.

mod common;

use common::{CLIENT_IP, Fixture, SERVER_IP};
use toy_tcpip::socket::SocketError;
use toy_tcpip::tcp::{SocketAddrV4, TcpState};

#[test]
fn test_udp_bind_ephemeral_ports_and_conflicts() {
    let mut fx = Fixture::new("lan_udp_bind", 1460);

    // An explicit bind takes the requested port.
    let named = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_bind(9000)
        .unwrap();
    assert_eq!(
        fx.lab
            .host("server")
            .unwrap()
            .stack
            .sockets
            .udp_sockets
            .get(&named)
            .unwrap()
            .local_addr
            .port,
        9000
    );

    // Port 0 allocates from the ephemeral range.
    let ephemeral = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_bind(0)
        .unwrap();
    let ephemeral_port = fx
        .lab
        .host("server")
        .unwrap()
        .stack
        .sockets
        .udp_sockets
        .get(&ephemeral)
        .unwrap()
        .local_addr
        .port;
    assert!(
        (49152..=65535).contains(&ephemeral_port),
        "ephemeral port {} outside 49152..=65535",
        ephemeral_port
    );

    // Re-binding an occupied port is refused.
    assert_eq!(
        fx.lab
            .host_mut("server")
            .unwrap()
            .stack
            .udp_bind(9000)
            .unwrap_err(),
        SocketError::AddressInUse
    );

    // Closing frees the port for reuse.
    fx.lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_close(named)
        .unwrap();
    assert!(
        fx.lab
            .host_mut("server")
            .unwrap()
            .stack
            .udp_bind(9000)
            .is_ok()
    );
}

#[test]
fn test_udp_send_recv_over_the_wire_with_port_demultiplexing() {
    let mut fx = Fixture::new("lan_udp_wire", 1460);

    // Two server sockets on different ports must receive only their own traffic.
    let sock_a = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_bind(7001)
        .unwrap();
    let sock_b = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_bind(7002)
        .unwrap();
    let client = fx
        .lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_bind(41000)
        .unwrap();

    fx.lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_send_to(
            client,
            b"for port 7001",
            SocketAddrV4 {
                ip: SERVER_IP,
                port: 7001,
            },
        )
        .unwrap();
    fx.lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_send_to(
            client,
            b"for port 7002",
            SocketAddrV4 {
                ip: SERVER_IP,
                port: 7002,
            },
        )
        .unwrap();

    fx.settle();

    let (data_a, from_a) = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_recv_from(sock_a)
        .expect("socket A should have a datagram");
    assert_eq!(data_a, b"for port 7001");
    assert_eq!(
        from_a,
        SocketAddrV4 {
            ip: CLIENT_IP,
            port: 41000
        }
    );

    let (data_b, from_b) = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .udp_recv_from(sock_b)
        .expect("socket B should have a datagram");
    assert_eq!(data_b, b"for port 7002");
    assert_eq!(
        from_b,
        SocketAddrV4 {
            ip: CLIENT_IP,
            port: 41000
        }
    );

    // Queues are now empty.
    assert_eq!(
        fx.lab
            .host_mut("server")
            .unwrap()
            .stack
            .udp_recv_from(sock_a)
            .unwrap_err(),
        SocketError::WouldBlock
    );
}

#[test]
fn test_udp_datagram_to_unbound_port_is_discarded_without_panic() {
    let mut fx = Fixture::new("lan_udp_closed", 1460);
    let client = fx
        .lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_bind(41100)
        .unwrap();

    fx.lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_send_to(
            client,
            b"nobody is listening",
            SocketAddrV4 {
                ip: SERVER_IP,
                port: 9999,
            },
        )
        .unwrap();

    fx.settle();
    // The stack stays healthy and the client has nothing to read.
    assert_eq!(
        fx.lab
            .host_mut("client")
            .unwrap()
            .stack
            .udp_recv_from(client)
            .unwrap_err(),
        SocketError::WouldBlock
    );
}

#[test]
fn test_tcp_three_way_handshake_through_socket_api() {
    let mut fx = Fixture::new("lan_handshake", 1460);
    let listener = fx.listen(80);
    let (client, server) = fx.establish(listener, 80);

    assert_eq!(fx.state("client", client), TcpState::Established);
    assert_eq!(fx.state("server", server), TcpState::Established);

    // The client's local port came from the ephemeral range.
    let diag = fx
        .lab
        .host("client")
        .unwrap()
        .stack
        .tcp_diagnostics(client)
        .unwrap();
    assert!((49152..=65535).contains(&diag.local.port));
    assert_eq!(
        diag.remote,
        SocketAddrV4 {
            ip: SERVER_IP,
            port: 80
        }
    );
}

#[test]
fn test_tcp_multiple_simultaneous_connections_share_one_listening_port() {
    let mut fx = Fixture::new("lan_multi", 512);
    let listener = fx.listen(8080);

    // Three clients connect to the same listening port from distinct local ports.
    let c1 = fx.connect_from(41001, 8080, 10_000);
    let c2 = fx.connect_from(41002, 8080, 20_000);
    let c3 = fx.connect_from(41003, 8080, 30_000);

    assert!(fx.run_until(25, 60_000, |lab| {
        [c1, c2, c3].iter().all(|h| {
            lab.host("client")
                .unwrap()
                .stack
                .tcp_state(*h)
                .map(|s| s == TcpState::Established)
                .unwrap_or(false)
        })
    }));

    // The listener hands back three distinct streams, each keyed by its own 4-tuple.
    let mut accepted = Vec::new();
    while let Ok((stream, peer)) = fx
        .lab
        .host_mut("server")
        .unwrap()
        .stack
        .tcp_accept(listener)
    {
        accepted.push((stream, peer));
    }
    assert_eq!(accepted.len(), 3, "expected three accepted connections");

    let mut peer_ports: Vec<u16> = accepted.iter().map(|(_, p)| p.port).collect();
    peer_ports.sort_unstable();
    assert_eq!(peer_ports, vec![41001, 41002, 41003]);

    // Each connection carries its own independent byte stream.
    let messages: [&[u8]; 3] = [b"stream one", b"stream two", b"stream three"];
    for (client, msg) in [c1, c2, c3].iter().zip(messages.iter()) {
        fx.write("client", *client, msg);
    }

    assert!(fx.run_until(25, 60_000, |lab| {
        accepted.iter().enumerate().all(|(i, (s, _))| {
            lab.host("server")
                .unwrap()
                .stack
                .tcp_stats(*s)
                .map(|st| st.bytes_received as usize >= messages[i].len())
                .unwrap_or(false)
        })
    }));

    // Demultiplex by peer port so the assertion does not depend on accept order.
    for (stream, peer) in &accepted {
        let got = fx.drain("server", *stream);
        let expected: &[u8] = match peer.port {
            41001 => messages[0],
            41002 => messages[1],
            41003 => messages[2],
            other => panic!("unexpected peer port {}", other),
        };
        assert_eq!(
            got, expected,
            "stream from :{} carried wrong bytes",
            peer.port
        );
    }
}

#[test]
fn test_tcp_bidirectional_stream_and_graceful_close() {
    let mut fx = Fixture::new("lan_bidi", 512);
    let listener = fx.listen(80);
    let (client, server) = fx.establish(listener, 80);

    let request = b"ping from the client".to_vec();
    let got = fx.transfer("client", client, "server", server, &request);
    assert_eq!(got, request);

    let reply = b"pong from the server".to_vec();
    let got_back = fx.transfer("server", server, "client", client, &reply);
    assert_eq!(got_back, reply);

    // Client closes; the server observes end of stream.
    fx.close("client", client);
    assert!(fx.run_until(25, 60_000, |lab| {
        lab.host("server")
            .unwrap()
            .stack
            .tcp_state(server)
            .map(|s| {
                matches!(
                    s,
                    TcpState::CloseWait | TcpState::LastAck | TcpState::Closed
                )
            })
            .unwrap_or(false)
    }));

    let mut buf = [0u8; 64];
    assert_eq!(
        fx.lab
            .host_mut("server")
            .unwrap()
            .stack
            .tcp_read(server, &mut buf)
            .unwrap(),
        0,
        "server should see EOF after the client's FIN"
    );

    // Server closes in turn; both sides finish cleanly.
    fx.close("server", server);
    assert!(fx.run_until(250, 60_000, |lab| {
        lab.host("client")
            .unwrap()
            .stack
            .tcp_state(client)
            .map(|s| matches!(s, TcpState::TimeWait | TcpState::Closed))
            .unwrap_or(false)
    }));
}

#[test]
fn test_tcp_close_flushes_queued_data_before_the_fin() {
    // A close issued immediately after a large write must not truncate the stream: the
    // FIN is deferred until the send buffer has drained.
    let mut fx = Fixture::new("lan_close_flush", 256);
    let listener = fx.listen(80);
    let (client, server) = fx.establish(listener, 80);

    let data = common::payload(8_192);
    fx.write("client", client, &data);
    fx.close("client", client); // close before a single segment has left

    assert!(fx.run_until(25, 120_000, |lab| {
        lab.host("server")
            .unwrap()
            .stack
            .tcp_stats(server)
            .map(|s| s.bytes_received as usize >= data.len())
            .unwrap_or(false)
    }));

    let got = fx.drain("server", server);
    assert_eq!(got.len(), data.len(), "close truncated the stream");
    assert_eq!(got, data);
}

#[test]
fn test_connection_to_closed_port_is_refused_with_reset() {
    let mut fx = Fixture::new("lan_refused", 1460);
    // No listener on :9. The SYN must draw a RST rather than hanging or panicking.
    let client = fx.connect(9);

    assert!(fx.run_until(25, 20_000, |lab| {
        lab.host("client")
            .unwrap()
            .stack
            .tcp_state(client)
            .map(|s| s == TcpState::Closed)
            .unwrap_or(false)
    }));
    assert_eq!(fx.state("client", client), TcpState::Closed);
}

#[test]
fn test_finished_connections_are_reaped_so_the_table_does_not_leak() {
    let mut fx = Fixture::new("lan_reap", 512);
    let listener = fx.listen(80);

    // Open, use, and close ten connections in sequence.
    for i in 0..10u16 {
        let (client, server) = fx.establish(listener, 80);
        let msg = format!("connection {}", i).into_bytes();
        let got = fx.transfer("client", client, "server", server, &msg);
        assert_eq!(got, msg);
        fx.close("client", client);
        fx.close("server", server);

        // Both sides must fall out of TIME_WAIT (2 * MSL) and be reclaimed on their own.
        let reaped = fx.run_until(500, 30_000, |lab| {
            lab.host("client").unwrap().stack.sockets.connection_count() == 0
                && lab.host("server").unwrap().stack.sockets.connection_count() == 0
        });
        assert!(reaped, "connection {} was never reclaimed after close", i);
    }

    let client_live = fx
        .lab
        .host("client")
        .unwrap()
        .stack
        .sockets
        .connection_count();
    let server_live = fx
        .lab
        .host("server")
        .unwrap()
        .stack
        .sockets
        .connection_count();

    assert_eq!(
        client_live, 0,
        "client connection table leaked {} entries",
        client_live
    );
    assert_eq!(
        server_live, 0,
        "server connection table leaked {} entries",
        server_live
    );
}

#[test]
fn test_ephemeral_ports_do_not_collide_across_many_connections() {
    let mut fx = Fixture::new("lan_ephemeral", 512);
    let listener = fx.listen(80);

    let mut ports = Vec::new();
    for _ in 0..32 {
        let client = fx.connect(80);
        let diag = fx
            .lab
            .host("client")
            .unwrap()
            .stack
            .tcp_diagnostics(client)
            .unwrap();
        ports.push(diag.local.port);
        let _ = fx.establish_existing(listener, client);
    }

    let mut sorted = ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        ports.len(),
        "ephemeral port allocator handed out a duplicate while connections were live"
    );
}

#[test]
fn test_closed_stream_history_is_bounded() {
    // A long-lived host that opens and closes many connections must not accumulate
    // finished-stream records without limit.
    let mut fx = Fixture::new("lan_history", 512);
    let listener = fx.listen(80);

    for _ in 0..(toy_tcpip::socket::MAX_CLOSED_STREAM_HISTORY + 40) {
        let (client, server) = fx.establish(listener, 80);
        fx.close("client", client);
        fx.close("server", server);
        fx.run_until(500, 30_000, |lab| {
            lab.host("client").unwrap().stack.sockets.connection_count() == 0
        });
    }

    let history = fx
        .lab
        .host("client")
        .unwrap()
        .stack
        .sockets
        .closed_stream_count();
    assert!(
        history <= toy_tcpip::socket::MAX_CLOSED_STREAM_HISTORY,
        "closed-stream history grew to {}, past the {} cap",
        history,
        toy_tcpip::socket::MAX_CLOSED_STREAM_HISTORY
    );
    assert_eq!(
        fx.lab
            .host("client")
            .unwrap()
            .stack
            .sockets
            .connection_count(),
        0
    );
}

#[test]
fn test_closing_a_listener_releases_its_backlog() {
    let mut fx = Fixture::new("lan_listener_close", 512);
    let listener = fx.listen(80);

    // Three connections arrive but are never accepted.
    for port in [42001u16, 42002, 42003] {
        fx.connect_from(port, 80, 5_000 + port as u32);
    }
    fx.run_until(25, 30_000, |lab| {
        lab.host("server").unwrap().stack.sockets.connection_count() >= 3
    });
    assert!(
        fx.lab
            .host("server")
            .unwrap()
            .stack
            .sockets
            .connection_count()
            >= 3
    );

    // Closing the listener abandons the unaccepted backlog and frees the port.
    fx.lab
        .host_mut("server")
        .unwrap()
        .stack
        .tcp_listener_close(listener)
        .unwrap();
    assert_eq!(
        fx.lab
            .host("server")
            .unwrap()
            .stack
            .sockets
            .connection_count(),
        0,
        "backlogged connections outlived their listener"
    );
    assert!(
        fx.lab
            .host_mut("server")
            .unwrap()
            .stack
            .tcp_listen(80)
            .is_ok(),
        "the listening port was not released"
    );
}

#[test]
fn test_socket_options_and_address_inspection() {
    let mut fx = Fixture::new("socket_opts_lan", 1460);

    // 1. Test UDP socket options & local address inspection
    let udp_sock = fx
        .lab
        .host_mut("client")
        .unwrap()
        .stack
        .udp_bind(7777)
        .unwrap();

    let client_stack = &mut fx.lab.host_mut("client").unwrap().stack;
    let udp_local = client_stack.sockets.udp_local_addr(udp_sock).unwrap();
    assert_eq!(udp_local.port, 7777);

    // Default UDP options
    assert!(!client_stack.sockets.udp_broadcast(udp_sock).unwrap());
    assert_eq!(client_stack.sockets.udp_multicast_ttl(udp_sock).unwrap(), 1);
    assert!(
        client_stack
            .sockets
            .udp_multicast_loop_v4(udp_sock)
            .unwrap()
    );

    // Modify UDP options
    client_stack
        .sockets
        .udp_set_broadcast(udp_sock, true)
        .unwrap();
    client_stack
        .sockets
        .udp_set_multicast_ttl(udp_sock, 32)
        .unwrap();
    client_stack
        .sockets
        .udp_set_multicast_loop_v4(udp_sock, false)
        .unwrap();
    client_stack
        .sockets
        .udp_set_nonblocking(udp_sock, true)
        .unwrap();

    assert!(client_stack.sockets.udp_broadcast(udp_sock).unwrap());
    assert_eq!(
        client_stack.sockets.udp_multicast_ttl(udp_sock).unwrap(),
        32
    );
    assert!(
        !client_stack
            .sockets
            .udp_multicast_loop_v4(udp_sock)
            .unwrap()
    );
    assert!(client_stack.sockets.udp_nonblocking(udp_sock).unwrap());

    // 2. Test TCP socket options & 4-tuple inspection
    let listener = fx.listen(8080);
    let (client_stream, _server_stream) = fx.establish(listener, 8080);

    let client_stack = &mut fx.lab.host_mut("client").unwrap().stack;
    let local = client_stack.sockets.tcp_local_addr(client_stream).unwrap();
    let peer = client_stack.sockets.tcp_peer_addr(client_stream).unwrap();
    assert_eq!(peer.ip, SERVER_IP);
    assert_eq!(peer.port, 8080);
    assert_eq!(local.ip, CLIENT_IP);

    // Default TCP options
    assert!(!client_stack.sockets.tcp_nodelay(client_stream).unwrap());
    assert!(!client_stack.sockets.tcp_nonblocking(client_stream).unwrap());
    assert_eq!(
        client_stack
            .sockets
            .tcp_read_timeout(client_stream)
            .unwrap(),
        None
    );

    // Set TCP options
    client_stack
        .sockets
        .tcp_set_nodelay(client_stream, true)
        .unwrap();
    client_stack
        .sockets
        .tcp_set_nonblocking(client_stream, true)
        .unwrap();
    client_stack
        .sockets
        .tcp_set_read_timeout(client_stream, Some(2500))
        .unwrap();

    assert!(client_stack.sockets.tcp_nodelay(client_stream).unwrap());
    assert!(client_stack.sockets.tcp_nonblocking(client_stream).unwrap());
    assert_eq!(
        client_stack
            .sockets
            .tcp_read_timeout(client_stream)
            .unwrap(),
        Some(2500)
    );

    // Cleanup on UDP close
    client_stack.sockets.udp_close(udp_sock).unwrap();
    assert!(client_stack.sockets.udp_broadcast(udp_sock).is_err());

    // Cleanup on TCP release
    client_stack.sockets.tcp_release(client_stream);
    assert!(client_stack.sockets.tcp_nodelay(client_stream).is_err());
}
