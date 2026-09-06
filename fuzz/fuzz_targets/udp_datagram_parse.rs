#![no_main]

use libfuzzer_sys::fuzz_target;
use toy_tcpip::ipv4::Ipv4Address;
use toy_tcpip::udp::{UdpDatagram, UDP_HEADER_LEN};

fuzz_target!(|data: &[u8]| {
    let src_ip = Ipv4Address::new(192, 0, 2, 1);
    let dst_ip = Ipv4Address::new(198, 51, 100, 1);

    let _ = UdpDatagram::parse(src_ip, dst_ip, data, true);

    if let Ok(datagram) = UdpDatagram::parse(src_ip, dst_ip, data, false) {
        let encoded = UdpDatagram::try_serialize(
            src_ip,
            dst_ip,
            datagram.src_port,
            datagram.dst_port,
            datagram.payload,
        )
        .expect("parsed UDP payload must fit the UDP length field");

        let reparsed = UdpDatagram::parse(src_ip, dst_ip, &encoded, true)
            .expect("serialized UDP datagram must parse with checksum verification");
        assert_eq!(reparsed.src_port, datagram.src_port);
        assert_eq!(reparsed.dst_port, datagram.dst_port);
        assert_eq!(reparsed.payload, datagram.payload);
        assert_eq!(reparsed.length as usize, encoded.len());

        if encoded.len() > UDP_HEADER_LEN {
            assert!(UdpDatagram::parse(src_ip, dst_ip, &encoded[..encoded.len() - 1], false).is_err());
        }

        let mut with_trailing = encoded.clone();
        with_trailing.push(0xa5);
        let reparsed_with_trailing = UdpDatagram::parse(src_ip, dst_ip, &with_trailing, true)
            .expect("transport bytes beyond declared UDP length must be ignored");
        assert_eq!(reparsed_with_trailing.payload, datagram.payload);
        assert_eq!(reparsed_with_trailing.length as usize, encoded.len());
    }
});
