use toy_tcpip::bgp::{AsPath, Ipv4Prefix};
use toy_tcpip::bgp_add_path::{
    AddPathMode, AddPathNlri, AddPathRib, AddPathRibEntry, BgpAddPathCapability,
};
use toy_tcpip::bgp_caps::AfiSafi;
use toy_tcpip::ipv4::Ipv4Address;

#[test]
fn test_bgp_add_path_capability_codec_and_negotiation() {
    let mut local_cap = BgpAddPathCapability::new();
    local_cap = local_cap.with_family(AfiSafi::IPV4_UNICAST, AddPathMode::Both);
    local_cap = local_cap.with_family(AfiSafi::L2VPN_EVPN, AddPathMode::Send);

    let bytes = local_cap.encode_value();
    assert_eq!(bytes.len(), 8);

    let decoded = BgpAddPathCapability::decode_value(&bytes).unwrap();
    assert_eq!(decoded, local_cap);

    // Test negotiation logic
    let mut peer_cap = BgpAddPathCapability::new();
    peer_cap = peer_cap.with_family(AfiSafi::IPV4_UNICAST, AddPathMode::Both);
    peer_cap = peer_cap.with_family(AfiSafi::L2VPN_EVPN, AddPathMode::Receive);

    let (v4_send, v4_recv) = local_cap.negotiate(&peer_cap, AfiSafi::IPV4_UNICAST);
    assert!(v4_send);
    assert!(v4_recv);

    let (evpn_send, evpn_recv) = local_cap.negotiate(&peer_cap, AfiSafi::L2VPN_EVPN);
    assert!(evpn_send); // Local can Send, Peer can Receive -> true
    assert!(!evpn_recv); // Local can Send only, cannot Receive -> false
}

#[test]
fn test_add_path_nlri_encode_decode() {
    let prefix = Ipv4Prefix::new(Ipv4Address::new(10, 20, 0, 0), 16);
    let nlri = AddPathNlri::new(0x0000_1234, prefix);

    let wire = nlri.encode();
    assert_eq!(wire.len(), 4 + 1 + 2); // 4 bytes path_id + 1 byte len + 2 bytes IP
    assert_eq!(&wire[0..4], &[0x00, 0x00, 0x12, 0x34]);
    assert_eq!(wire[4], 16);
    assert_eq!(&wire[5..7], &[10, 20]);

    let (parsed, consumed) = AddPathNlri::decode(&wire).unwrap();
    assert_eq!(consumed, wire.len());
    assert_eq!(parsed, nlri);
}

#[test]
fn test_add_path_rib_multi_path_and_pic_failover() {
    let mut rib = AddPathRib::new(4);
    let prefix = Ipv4Prefix::new(Ipv4Address::new(172, 16, 0, 0), 12);

    let peer1 = Ipv4Address::new(192, 0, 2, 1);
    let peer2 = Ipv4Address::new(192, 0, 2, 2);
    let peer3 = Ipv4Address::new(192, 0, 2, 3);

    let mut path1 = AddPathRibEntry::new(
        1,
        peer1,
        peer1,
        AsPath::sequence(vec![65001, 65100]),
    );
    path1.local_pref = Some(200);

    let mut path2 = AddPathRibEntry::new(
        2,
        peer2,
        peer2,
        AsPath::sequence(vec![65002, 65100]),
    );
    path2.local_pref = Some(150);

    let mut path3 = AddPathRibEntry::new(
        3,
        peer3,
        peer3,
        AsPath::sequence(vec![65003, 65100]),
    );
    path3.local_pref = Some(100);

    rib.insert_path(prefix, path1);
    rib.insert_path(prefix, path2);
    rib.insert_path(prefix, path3);

    // Verify multi-path storage
    let advertised = rib.get_advertised_paths(&prefix);
    assert_eq!(advertised.len(), 3);
    assert_eq!(advertised[0].peer_ip, peer1);
    assert!(advertised[0].is_best);
    assert_eq!(advertised[1].peer_ip, peer2);
    assert!(advertised[1].is_backup);

    // Verify PIC forwarding (Primary = Peer1, Backup = Peer2)
    let (primary, backup) = rib.get_pic_forwarding(&prefix).unwrap();
    assert_eq!(primary, peer1);
    assert_eq!(backup, Some(peer2));

    // Simulate primary failure / withdrawal
    assert!(rib.withdraw_path(&prefix, peer1, 1));
    let (new_primary, new_backup) = rib.get_pic_forwarding(&prefix).unwrap();
    assert_eq!(new_primary, peer2);
    assert_eq!(new_backup, Some(peer3));
}
