use toy_tcpip::bfd::{BFD_AUTH_KEYED_MD5, BfdAuthHeader};

#[test]
fn keyed_md5_receiver_ignores_nonzero_reserved_octet() {
    let mut auth = vec![0u8; 24];
    auth[0] = BFD_AUTH_KEYED_MD5;
    auth[1] = 24;
    auth[2] = 7;
    auth[3] = 0xa5;
    auth[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
    auth[8..24].fill(0x5a);

    let parsed = BfdAuthHeader::parse(&auth).expect("nonzero reserved octet must be ignored");
    assert_eq!(
        parsed,
        BfdAuthHeader::KeyedMd5 {
            meticulous: false,
            key_id: 7,
            sequence_number: 0x1122_3344,
            auth_key_hash: [0x5a; 16],
        }
    );
}
