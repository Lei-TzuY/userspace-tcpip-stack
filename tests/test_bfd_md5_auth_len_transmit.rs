use toy_tcpip::bfd::{BFD_AUTH_KEYED_MD5, BFD_AUTH_METICULOUS_KEYED_MD5, BfdAuthHeader};

#[test]
fn keyed_md5_serialization_uses_exact_rfc_auth_len() {
    for meticulous in [false, true] {
        let auth = BfdAuthHeader::KeyedMd5 {
            meticulous,
            key_id: 7,
            sequence_number: 0x0102_0304,
            auth_key_hash: [0x5a; 16],
        };

        let raw = auth.serialize();
        assert_eq!(raw.len(), 24);
        assert_eq!(raw[1], 24);
        assert_eq!(
            raw[0],
            if meticulous {
                BFD_AUTH_METICULOUS_KEYED_MD5
            } else {
                BFD_AUTH_KEYED_MD5
            }
        );
    }
}
